// The control for the class: same size, same window, one conjunct at a time.
//
// `analyzability --by-class` compares quarantine-no-genome against
// watcher-threshold and finds the first far more legible than the second. The
// comparison cannot support that reading, and the reason is arithmetic rather
// than statistical: the class is DEFINED as under 100KB, and a binary, a WASM
// module, a V8 bytecode cache and a webpack bundle do not fit in 100KB. The
// other segment is selected on a high score, which is enriched for exactly those
// things. The module table has the same defect — that cut reports child_process
// LESS often inside the class than outside it, which is what you would expect if
// the comparison group were simply bigger software.
//
// So this holds size fixed and varies the class definition itself. The class is
// four conjuncts:
//
//     no genome  AND  name under 7 days  AND  under 100KB  AND  no repository
//
// Every group here is under 100KB and drawn from the same window. What changes
// between them is ONE of the other three conjuncts:
//
//   class        no genome, young name, no repository        (the class itself)
//   +repository  no genome, young name, HAS a repository     (one conjunct)
//   +age         no genome, name >= 7 days, no repository    (one conjunct)
//   maintained   has a genome, old name, has a repository    (the far corner)
//
// The third row cannot be a single conjunct and this is a fact about the
// definitions rather than a compromise: a genome needs ten versions and ninety
// days of them, so a package WITH a genome always has an old name. There is no
// young-with-genome cell to draw from, and reporting one would be inventing it.
//
// Two acquisition paths, because they answer different questions:
//
//   from disk      the captures the watcher already took. Group A this way is a
//                  census of the class in the window, not a sample of it.
//   from the       drawn from changes-log.ndjson, which records the class
//   registry       markers for EVERY publication the watcher scored, and fetched
//                  from npm now. Nothing selected these but their cell, their
//                  size and the window.
//
// The class is measured BOTH ways on purpose. A package npm has since removed
// cannot be fetched, and the class is the population npm removes; running it
// through the registry path as well is what measures how much that costs,
// instead of leaving it as a caveat nobody can size.
//
// Descriptive, like the rest of the analyzability family. Nothing here scores. A
// rate that separates two populations is a fact about the populations, and this
// file's whole subject is how easily such a fact turns out to be a fact about
// the sampling instead.

import { existsSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { loadCorpus, type CorpusSample } from './corpus.js'
import { readChangeLogs } from './field-recall.js'
import { classifyPublication, TINY_PACKAGE_BYTES, YOUNG_NAME_DAYS, type ClassMarkers } from './observed-class.js'
import { normalizePackument, type Packument, type VersionMeta } from './packument.js'
import { readTar, DEFAULT_TAR_LIMITS, type TarLimits } from './tarball.js'
import { defaultSource, downloadTarball, type PackageSource } from './source.js'
import { NgpackSource } from './ngpack.js'
import {
  analyzeArchive,
  reachableModulesOf,
  summariseCorpus,
  canonicalModule,
  type CoverageBucket,
  type ModulePrevalence,
  type ReasonPrevalence,
} from './analyzability-run.js'
import type { CaptureAnalyzability, LegibilityThreshold } from './analyzability.js'
import {
  differenceWithCI, rateWithCI, zForFamily,
  type DifferenceWithCI, type RateWithCI,
} from './stats.js'

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

export interface ClassCell {
  key: string
  name: string
  definition: string
  // null means "either", which no cell needs today and the type allows so that
  // a wider cell can be added without changing the matcher.
  noGenome: boolean | null
  young: boolean | null
  repository: boolean | null
}

export const CLASS_CELL = 'class'

export const CELLS: ClassCell[] = [
  {
    key: CLASS_CELL,
    name: 'class',
    definition: `no genome, name under ${YOUNG_NAME_DAYS} days, no repository`,
    noGenome: true, young: true, repository: false,
  },
  {
    key: 'repository',
    name: 'class +repository',
    definition: `no genome, name under ${YOUNG_NAME_DAYS} days, HAS a repository — one conjunct away from the class`,
    noGenome: true, young: true, repository: true,
  },
  {
    key: 'age',
    name: 'class +age',
    definition: `no genome, name ${YOUNG_NAME_DAYS} days or older, no repository — one conjunct away from the class`,
    noGenome: true, young: false, repository: false,
  },
  {
    key: 'maintained',
    name: 'maintained',
    definition: 'has a genome, old name, has a repository — the far corner, and the closest thing here to ordinary small software',
    noGenome: false, young: false, repository: true,
  },
]

export interface CellMarkers {
  noGenome: boolean
  young: boolean
  repository: boolean
  tiny: boolean
}

export function cellOf(m: CellMarkers): ClassCell | null {
  if (!m.tiny) return null
  return CELLS.find(c =>
    (c.noGenome === null || c.noGenome === m.noGenome) &&
    (c.young === null || c.young === m.young) &&
    (c.repository === null || c.repository === m.repository)
  ) ?? null
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

export interface ControlMember {
  package: string
  version: string
  // When the watcher saw it. capturedAt for a capture, seenAt for a log row: the
  // same process wrote both within a second of each other, so one window covers
  // both.
  at: string
  origin: 'capture' | 'registry'
  ngpackPath: string | null
  unpackedSize: number
  hasRepository: boolean
  nameAgeDays: number | null
  // The watcher's own decision at publication, recorded. Never recomputed: the
  // packument on npm today holds versions that did not exist then, and the
  // regime is a function of how many there were.
  regime: string | null
  cell: string
  // The registry no longer holds the version the log row was written about, so
  // a later one was measured. Excluded from the rates and counted, because its
  // bytes are not the bytes the window saw.
  versionAfterSighting?: boolean
}

// The packument a capture holds, without its tarballs. NgpackSource loads the
// bytes too, which is right for analysis and wrong for classification: deciding
// which cell 2,000 captures belong to would read gigabytes to answer a question
// that lives entirely in the JSON. The hash is still checked, because that is
// what makes a capture evidence rather than a file.
export function capturePackument(ngpackPath: string): Packument | null {
  const manifestPath = join(ngpackPath, 'manifest.json')
  const packumentPath = join(ngpackPath, 'packument.json')
  if (!existsSync(manifestPath) || !existsSync(packumentPath)) return null

  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as {
      hashes?: Record<string, string>
    }
    const raw = readFileSync(packumentPath, 'utf-8')
    const declared = manifest.hashes?.['packument.json']
    if (declared) {
      const actual = createHash('sha256').update(Buffer.from(raw)).digest('hex')
      if (actual !== declared) return null
    }
    return JSON.parse(raw) as Packument
  } catch {
    return null
  }
}

// The class markers as they stood when the capture was taken. `now` is the
// capture time and not today: "the name is under seven days old" is a statement
// about the moment the watcher saw it, and re-asking it today would move every
// capture out of the class as the corpus ages.
export function markersOfCapture(sample: CorpusSample): ClassMarkers | null {
  const packument = capturePackument(sample.ngpackPath)
  if (!packument) return null

  const meta = packument.versions[sample.version]
  if (!meta) return null

  return classifyPublication(
    packument,
    meta,
    sample.composition?.regime ?? 'unknown',
    new Date(sample.capturedAt).getTime()
  )
}

function memberFromCapture(sample: CorpusSample, markers: ClassMarkers, cell: string): ControlMember {
  return {
    package: sample.package,
    version: sample.version,
    at: sample.capturedAt,
    origin: 'capture',
    ngpackPath: sample.ngpackPath,
    unpackedSize: markers.unpackedSize,
    hasRepository: markers.hasRepository,
    nameAgeDays: markers.nameAgeDays,
    regime: sample.composition?.regime ?? null,
    cell,
  }
}

// ---------------------------------------------------------------------------
// The pool every registry group is drawn from
// ---------------------------------------------------------------------------

export interface ChangeRow {
  package: string
  outcome?: string
  regime?: string
  seenAt?: string
  class?: {
    inClass?: boolean
    young?: boolean
    tiny?: boolean
    repo?: boolean
    ageDays?: number | null
    bytes?: number
  }
}

export interface PoolCandidate {
  package: string
  seenAt: string
  regime: string | null
  bytes: number
  cell: string
}

export interface Pool {
  candidates: PoolCandidate[]
  rowsScanned: number
  analysedInWindow: number
  tinyInWindow: number
  // Under 100KB and in none of the four cells. Today this is empty by
  // construction — the cells cover every combination that can exist — and it is
  // counted anyway, because "by construction" is what this whole file is about.
  tinyOutsideEveryCell: number
  byCell: Array<{ cell: string; packages: number }>
}

// Every publication the watcher scored in the window that is under 100KB, one
// row per package, tagged with the cell it belongs to.
//
// The markers on these rows were computed by classifyPublication AT
// PUBLICATION, which is the same function, on the same clock, that decided
// whether each capture on disk belonged to the class. That is what makes the
// groups comparable: membership on both sides is one decision made once, not a
// reconstruction made now.
export function buildPool(
  outputDir: string,
  window: { since: string; until?: string }
): Pool {
  const byPackage = new Map<string, PoolCandidate>()
  let rowsScanned = 0, analysedInWindow = 0, tinyInWindow = 0, tinyOutsideEveryCell = 0

  for (const text of readChangeLogs(outputDir)) {
    for (const line of text.split('\n')) {
      if (!line) continue
      let row: ChangeRow
      try { row = JSON.parse(line) as ChangeRow } catch { continue }
      rowsScanned++

      const seenAt = row.seenAt ?? ''
      if (row.outcome !== 'analyzed' || !row.class || !seenAt) continue
      if (seenAt < window.since) continue
      if (window.until && seenAt > window.until) continue
      analysedInWindow++
      if (!row.class.tiny) continue
      tinyInWindow++

      const cell = cellOf({
        noGenome: row.regime === 'no-genome',
        young: Boolean(row.class.young),
        repository: Boolean(row.class.repo),
        tiny: true,
      })
      if (!cell) { tinyOutsideEveryCell++; continue }

      // The earliest sighting in the window. A name republished four times in a
      // day is one package, and counting it four times would weight the pool by
      // publishing frequency.
      const existing = byPackage.get(row.package)
      if (existing && existing.seenAt <= seenAt) continue

      byPackage.set(row.package, {
        package: row.package,
        seenAt,
        regime: row.regime ?? null,
        bytes: row.class.bytes ?? 0,
        cell: cell.key,
      })
    }
  }

  const candidates = [...byPackage.values()].sort((a, b) => a.seenAt.localeCompare(b.seenAt))

  return {
    candidates,
    rowsScanned, analysedInWindow, tinyInWindow, tinyOutsideEveryCell,
    byCell: CELLS.map(c => ({
      cell: c.key,
      packages: candidates.filter(x => x.cell === c.key).length,
    })),
  }
}

// ---------------------------------------------------------------------------
// Matching on size
// ---------------------------------------------------------------------------

export interface SizeBucket {
  label: string
  low: number
  high: number
}

// Buckets from the class's own size distribution, so the match is against the
// thing being controlled for rather than against round numbers. Deciles: fewer
// would let a bucket hide a real difference in shape, more would leave buckets
// the pool cannot fill.
export function sizeBuckets(sizes: number[], count = 10): SizeBucket[] {
  const sorted = [...sizes].sort((a, b) => a - b)
  if (sorted.length === 0) return [{ label: 'everything', low: 0, high: Infinity }]

  const edges: number[] = []
  for (let i = 1; i < count; i++) {
    const at = sorted[Math.floor((i / count) * sorted.length)]
    if (at !== undefined && (edges.length === 0 || at > edges[edges.length - 1]!)) edges.push(at)
  }

  const buckets: SizeBucket[] = []
  let low = 0
  for (const edge of edges) {
    buckets.push({ label: `${bytes(low)}-${bytes(edge)}`, low, high: edge })
    low = edge
  }
  buckets.push({ label: `${bytes(low)}+`, low, high: Infinity })
  return buckets
}

// Adjacent deciles of this class are hundreds of bytes apart, and rounding them
// to whole KB collapses them into rows labelled "1KB-1KB".
function bytes(n: number): string {
  if (n === 0) return '0'
  if (n < 10_000) return `${n}B`
  return `${(n / 1000).toFixed(1)}KB`
}

export function bucketOf(buckets: SizeBucket[], size: number): number {
  for (let i = 0; i < buckets.length; i++) {
    if (size >= buckets[i]!.low && size < buckets[i]!.high) return i
  }
  return buckets.length - 1
}

export interface Draw<T> {
  picked: T[]
  // Buckets the pool could not fill, with how short each one came. Reported
  // rather than silently absorbed: a match that failed in the top decile is a
  // match that did not control for size at the end that matters.
  shortfall: Array<{ bucket: string; wanted: number; got: number }>
}

// A deterministic draw matched to a target size distribution. Not random: a run
// that cannot be reproduced cannot be compared against the next one, which is
// the same reason stratifiedSample is a stride rather than a shuffle.
export function sizeMatchedDraw<T>(
  pool: T[],
  sizeOf: (item: T) => number,
  targetSizes: number[],
  drawSize: number,
  buckets: SizeBucket[]
): Draw<T> {
  const wanted = new Array(buckets.length).fill(0) as number[]
  for (const size of targetSizes) wanted[bucketOf(buckets, size)]!++

  const scale = targetSizes.length > 0 ? drawSize / targetSizes.length : 0
  const byBucket: T[][] = buckets.map(() => [])
  for (const item of pool) byBucket[bucketOf(buckets, sizeOf(item))]!.push(item)

  const picked: T[] = []
  const shortfall: Draw<T>['shortfall'] = []

  for (let i = 0; i < buckets.length; i++) {
    const target = Math.round(wanted[i]! * scale)
    const available = byBucket[i]!
    const take = Math.min(target, available.length)

    if (take < target) shortfall.push({ bucket: buckets[i]!.label, wanted: target, got: take })
    if (take === 0) continue

    // A stride across the bucket rather than its first N: the pool is ordered by
    // time, and the first N would be the first hours of the window.
    const step = available.length / take
    for (let k = 0; k < take; k++) picked.push(available[Math.floor(k * step)]!)
  }

  return { picked, shortfall }
}

export function sizeProfile(
  sizes: number[],
  buckets: SizeBucket[]
): Array<{ label: string; members: number; share: number }> {
  const counts = new Array(buckets.length).fill(0) as number[]
  for (const size of sizes) counts[bucketOf(buckets, size)]!++
  return buckets.map((b, i) => ({
    label: b.label,
    members: counts[i]!,
    share: sizes.length > 0 ? counts[i]! / sizes.length : 0,
  }))
}

// ---------------------------------------------------------------------------
// Measuring a group
// ---------------------------------------------------------------------------

export interface MemberResult {
  member: ControlMember
  analysis: CaptureAnalyzability
  modules: string[] | null
  lostTrails: number
  // sha256 of the tarball measured, so a registry-fetched member can be
  // re-measured against the same bytes even after npm removes it.
  tarballSha256: string
}

export interface GroupReport {
  name: string
  cell: string
  definition: string
  source: 'capture' | 'registry'
  // Whether this group was drawn to match the class's size distribution. A
  // group that was not is not evidence about size and must not be described as
  // if it were.
  sizeMatched: boolean

  members: number
  analysed: number
  failures: Array<{ package: string; reason: string }>
  shortfall: Array<{ bucket: string; wanted: number; got: number }>

  medianUnpackedSize: number | null
  // Always in the class's buckets, never in the group's own: a table where every
  // group is profiled in its own deciles reads as a perfect match whatever the
  // sizes are, and that table is the only check that the control worked.
  sizeProfile: Array<{ label: string; members: number; share: number }>
  byDay: Array<{ day: string; members: number }>

  // The archive could not be opened at all. Distinct from a package with
  // nothing executable in it: one is an acquisition defect and the other is a
  // finding about the package.
  unreadable: number
  nothingExecutable: number
  // The denominator for both rates below: opened, and with at least one
  // executable byte.
  scored: number
  fullyLegible: RateWithCI
  shipsOpaqueExecutable: RateWithCI
  byteCoverage: number | null
  medianCaptureCoverage: number | null
  distribution: CoverageBucket[]
  reasons: ReasonPrevalence[]

  reachabilityAnalysed: number
  modules: ModulePrevalence[]
  lostTrails: number
}

const OPAQUE_REASONS = ['native-binary', 'wasm', 'bytecode', 'minified'] as const

export function summariseGroup(input: {
  name: string
  cell: string
  definition: string
  source: 'capture' | 'registry'
  sizeMatched: boolean
  results: MemberResult[]
  failures: Array<{ package: string; reason: string }>
  shortfall?: Array<{ bucket: string; wanted: number; got: number }>
  buckets: SizeBucket[]
  members: number
  threshold: LegibilityThreshold
}): GroupReport {
  const { results } = input
  const summary = summariseCorpus(results.map(r => r.analysis), {
    threshold: input.threshold,
    engineVersion: '',
    ranAt: '',
    confirmedPackages: new Set<string>(),
  })

  // Both rates over ONE denominator, named in the type. summariseCorpus computes
  // its opaque rate over every capture it could open, including the ones with
  // nothing executable in them; putting that on the same line as a coverage rate
  // computed over the captures that do have something executable would be two
  // denominators under one heading.
  const scored = results.filter(r => r.analysis.coverage !== null && !unreadable(r.analysis))
  const legible = scored.filter(r => (r.analysis.coverage ?? 0) >= 0.999).length
  const opaque = scored.filter(r =>
    OPAQUE_REASONS.some(reason => r.analysis.byReason[reason])
  ).length

  const byDay = new Map<string, number>()
  for (const r of results) {
    const day = r.member.at.slice(0, 10)
    byDay.set(day, (byDay.get(day) ?? 0) + 1)
  }

  const withReach = results.filter(r => r.modules !== null)
  const moduleCaptures = new Map<string, number>()
  for (const r of withReach) {
    for (const module of new Set(r.modules!)) {
      moduleCaptures.set(module, (moduleCaptures.get(module) ?? 0) + 1)
    }
  }

  return {
    name: input.name,
    cell: input.cell,
    definition: input.definition,
    source: input.source,
    sizeMatched: input.sizeMatched,
    members: input.members,
    analysed: results.length,
    failures: input.failures,
    shortfall: input.shortfall ?? [],
    medianUnpackedSize: median(results.map(r => r.member.unpackedSize)),
    sizeProfile: sizeProfile(results.map(r => r.member.unpackedSize), input.buckets),
    byDay: [...byDay.entries()].map(([day, members]) => ({ day, members }))
      .sort((a, b) => a.day.localeCompare(b.day)),
    unreadable: results.filter(r => unreadable(r.analysis)).length,
    nothingExecutable: summary.nothingExecutable,
    scored: scored.length,
    fullyLegible: rateWithCI(legible, scored.length),
    shipsOpaqueExecutable: rateWithCI(opaque, scored.length),
    byteCoverage: summary.byteCoverage,
    medianCaptureCoverage: summary.medianCaptureCoverage,
    distribution: summary.distribution,
    reasons: summary.reasons,
    reachabilityAnalysed: withReach.length,
    lostTrails: withReach.reduce((s, r) => s + r.lostTrails, 0),
    modules: [...moduleCaptures.entries()]
      .map(([module, captures]) => ({
        module, captures, rate: rateWithCI(captures, withReach.length),
      }))
      .sort((a, b) => b.captures - a.captures),
  }
}

function unreadable(a: CaptureAnalyzability): boolean {
  return Boolean(a.error) && a.executableFiles === 0
}

function median(values: number[]): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.floor(sorted.length / 2)]!
}

// One member, measured exactly as a corpus capture is measured: same reader,
// same limits, same threshold, and the same two questions asked of one read of
// the bytes.
export function measureMember(
  member: ControlMember,
  tarball: Buffer,
  threshold: LegibilityThreshold,
  limits: TarLimits = DEFAULT_TAR_LIMITS
): MemberResult {
  const archive = readTar(tarball, limits)
  const sample = {
    package: member.package,
    version: member.version,
    capturedAt: member.at,
    ngpackPath: member.ngpackPath ?? `registry:${member.package}@${member.version}`,
    label: 'unconfirmed' as const,
  }

  // An archive with no members at all is an unreadable archive, not a package
  // with nothing in it. The distinction matters here more than over the corpus:
  // anything the registry hands back that is not a tarball would otherwise be
  // counted as a package with nothing executable and quietly improve the group
  // it landed in. A genuinely empty tarball would be misfiled by this, and npm
  // does not accept one.
  const analysis = archive.entries.length === 0
    ? {
        ...sample,
        executableBytes: 0, executableFiles: 0, coveredBytes: 0, coveredFiles: 0,
        coverage: null, byReason: {}, heldOut: {}, files: [],
        error: `archive unreadable: ${archive.truncationReason ?? 'it holds no members'}`,
      }
    : analyzeArchive(sample as unknown as CorpusSample, archive, threshold)

  const reach = archive.entries.length > 0 ? reachableModulesOf(archive) : null

  return {
    member,
    analysis,
    modules: reach ? [...reach.modules].map(canonicalModule) : null,
    lostTrails: reach?.lost ?? 0,
    tarballSha256: createHash('sha256').update(tarball).digest('hex'),
  }
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

// How large a difference has to be before "no difference" is a claim rather than
// a shrug. Declared here, before any run, because an equivalence bound chosen
// after seeing the interval is not a bound.
//
// Ten points: the finding under test is a gap of tens of points in byte
// coverage, so an interval that excludes ten would have excluded the effect that
// prompted the question.
export const EQUIVALENCE_MARGIN = 0.10

export interface EndpointComparison {
  endpoint: string
  meaning: string
  difference: DifferenceWithCI
  // The same difference with the interval widened for every endpoint in every
  // comparison this run printed. Filled in once the run knows how many there
  // were, because a family cannot be counted from inside one of its members.
  familyAdjusted?: DifferenceWithCI
}

export interface ModuleComparison {
  module: string
  difference: DifferenceWithCI
}

export interface ControlComparison {
  a: string
  b: string
  sizeMatched: boolean
  endpoints: EndpointComparison[]
  // How many endpoint comparisons the whole run printed, so the widening above
  // can be checked rather than trusted.
  endpointFamily?: number
  endpointZ?: number
  // Family-wide, not per row. The z is widened for the number of modules in the
  // table, because selecting the largest row of forty and reading a 95%
  // interval off it is how the last module finding was made.
  moduleComparisons: number
  moduleZ: number
  modules: ModuleComparison[]
  verdict: string
  caveat: string
}

export function compareGroups(a: GroupReport, b: GroupReport): ControlComparison {
  const legible = differenceWithCI(
    a.fullyLegible.successes, a.fullyLegible.n,
    b.fullyLegible.successes, b.fullyLegible.n
  )
  const opaque = differenceWithCI(
    a.shipsOpaqueExecutable.successes, a.shipsOpaqueExecutable.n,
    b.shipsOpaqueExecutable.successes, b.shipsOpaqueExecutable.n
  )

  const endpoints: EndpointComparison[] = [
    {
      endpoint: 'fully legible',
      meaning: 'every executable byte in the package parses, is legible, and holds no construct that moves behaviour out of the parser\'s reach',
      difference: legible,
    },
    {
      endpoint: 'ships opaque executable',
      meaning: 'at least one native binary, WASM module, bytecode cache or unreadable minified file',
      difference: opaque,
    },
  ]

  // Every module either group reaches, so a module present in one and absent
  // from the other is visible as a difference rather than as an absence.
  const names = new Set([...a.modules.map(m => m.module), ...b.modules.map(m => m.module)])
  const z = zForFamily(names.size)
  const modules: ModuleComparison[] = [...names]
    .map(module => {
      const inA = a.modules.find(m => m.module === module)
      const inB = b.modules.find(m => m.module === module)
      return {
        module,
        difference: differenceWithCI(
          inA?.captures ?? 0, a.reachabilityAnalysed,
          inB?.captures ?? 0, b.reachabilityAnalysed,
          z
        ),
      }
    })
    .sort((x, y) => Math.abs(y.difference.difference ?? 0) - Math.abs(x.difference.difference ?? 0))

  return {
    a: a.name,
    b: b.name,
    sizeMatched: a.sizeMatched && b.sizeMatched,
    endpoints,
    moduleComparisons: names.size,
    moduleZ: z,
    modules,
    verdict: verdictFor(a, b, legible),
    caveat: caveatFor(a, b),
  }
}

// The rule, stated before the run, applied to the number the run produced.
export function verdictFor(a: GroupReport, b: GroupReport, legible: DifferenceWithCI): string {
  if (legible.difference === null || legible.low === null || legible.high === null) {
    return `Not calculable: ${a.name} scored ${a.scored} packages and ${b.name} scored ${b.scored}.`
  }

  const pp = (x: number) => `${(x * 100).toFixed(1)}pp`
  const held = a.sizeMatched && b.sizeMatched
    ? `Both groups were drawn to the class's size distribution, decile by decile`
    : `These two were NOT size-matched — both are simply under 100KB, and the size table above is where to check how far apart they still are`

  if (legible.separated && legible.difference > 0) {
    return (
      `THE GAP SURVIVES. ${a.name} is more legible than ${b.name} by ${pp(legible.difference)} ` +
      `(95% CI ${pp(legible.low)} to ${pp(legible.high)}, excludes zero). ${held}, so this is not ` +
      `the <100KB cut reading itself back. It remains descriptive: a rate that separates two ` +
      `populations is not a detector, and nothing here scores.`
    )
  }

  if (legible.separated && legible.difference < 0) {
    return (
      `IT RUNS THE OTHER WAY. ${b.name} is MORE legible than ${a.name} by ${pp(-legible.difference)} ` +
      `(95% CI ${pp(-legible.high)} to ${pp(-legible.low)}). ${held}.`
    )
  }

  const halfWidth = (legible.high - legible.low) / 2
  const withinMargin = legible.high < EQUIVALENCE_MARGIN && legible.low > -EQUIVALENCE_MARGIN

  if (withinMargin) {
    return (
      `NO DIFFERENCE WORTH THE NAME. The gap is ${pp(legible.difference)} and the whole interval ` +
      `(${pp(legible.low)} to ${pp(legible.high)}) lies inside the ${pp(EQUIVALENCE_MARGIN)} margin ` +
      `declared before the run. ${held}. Whatever separated these two populations in the by-class ` +
      `run, it was not this.`
    )
  }

  return (
    `INCONCLUSIVE at this n. The gap is ${pp(legible.difference)} with an interval ${pp(legible.low)} ` +
    `to ${pp(legible.high)} — half-width ${pp(halfWidth)}, wider than the ${pp(EQUIVALENCE_MARGIN)} ` +
    `margin, over ${a.scored} and ${b.scored} packages. This neither shows a gap nor rules one out, ` +
    `and reading it as "no difference" would be affirming the null from a sample too small to have ` +
    `found one.`
  )
}

function caveatFor(a: GroupReport, b: GroupReport): string {
  const parts: string[] = []

  if (a.source !== b.source) {
    parts.push(
      `these two were acquired differently — ${a.name} ${a.source === 'capture' ? 'from captures taken at publication' : 'fetched from npm now'} ` +
      `and ${b.name} the other way — so anything npm removed in between is missing from the fetched side`
    )
  }

  parts.push(
    `neither group is a set of independent draws: this class arrives in campaigns, a family of names ` +
    `published minutes apart by one operator, and the class side is affected more than the control ` +
    `side because the control is drawn one row per name across the whole window. Both intervals are ` +
    `therefore narrower than the truth, and the class's more so`
  )

  if (!a.sizeMatched || !b.sizeMatched) {
    parts.push(`one of these two was not size-matched, so size is bounded here only by "under 100KB"`)
  }

  return parts.join('; ')
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface SizeControlOptions {
  roots?: string[]
  outputDir: string
  threshold: LegibilityThreshold
  engineVersion: string
  since: string
  until?: string
  // How many packages to draw and fetch per cell. Zero skips every registry
  // group and leaves the on-disk comparison as the only one.
  drawPerCell: number
  source?: PackageSource
  limits?: TarLimits
  onProgress?: (stage: string, done: number, total: number) => void
  now?: () => string
  // Milliseconds between registry requests, applied whatever the outcome. The
  // watcher makes two per package name at a much higher rate than this; the
  // delay is here so a control run cannot become a load generator by being
  // pointed at a large draw.
  fetchDelayMs?: number
}

export interface SizeControlReport {
  ranAt: string
  engineVersion: string
  threshold: LegibilityThreshold
  window: { since: string; until: string | null }
  maxBytes: number
  equivalenceMargin: number
  buckets: SizeBucket[]
  // What the disk held before anything was measured, so the funnel is visible.
  corpus: {
    // Uncontaminated captures in the window, before anything is measured.
    inWindow: number
    // Excluded for being over the size band. Not a defect: the study is about
    // packages under 100KB and these are not in it.
    overTheSizeBand: number
    withBytes: number
    unclassifiable: number
    byCell: Array<{ cell: string; captures: number; packages: number }>
    // Under 100KB and in none of the four cells, which is a real place to be:
    // the cells are the class and the three comparisons, not a partition.
    tinyOutsideEveryCell: number
  }
  pool: Pool
  groups: GroupReport[]
  comparisons: ControlComparison[]
  caveats: string[]
}

export async function runSizeControl(options: SizeControlOptions): Promise<SizeControlReport> {
  const corpus = loadCorpus(options.roots)
  const inWindow = corpus.samples.filter(s =>
    !s.contaminated &&
    s.capturedAt >= options.since &&
    (!options.until || s.capturedAt <= options.until)
  )

  // Classified first and filtered for bytes afterwards, so the loss is a
  // reported number rather than an invisible one. Two thirds of this corpus has
  // no tarball left and the loss is not spread evenly across the classes.
  // Every tiny capture is kept, cell or no cell. The four cells do NOT cover
  // every combination — no-genome/old/with-repository and genome/old/without
  // one are both real and neither is one conjunct from the class — and dropping
  // them here would quietly shrink the off-class group to the cells that
  // happened to be named.
  const classified: Array<{ sample: CorpusSample; markers: ClassMarkers; cell: ClassCell | null }> = []
  let unclassifiable = 0
  let notTiny = 0

  for (const sample of inWindow) {
    const markers = markersOfCapture(sample)
    if (!markers) { unclassifiable++; continue }
    if (!markers.tiny) { notTiny++; continue }
    classified.push({
      sample,
      markers,
      cell: cellOf({
        noGenome: markers.noGenome,
        young: markers.young,
        repository: markers.hasRepository,
        tiny: markers.tiny,
      }),
    })
  }

  const withBytes = classified.filter(c => c.sample.tarballPresent)

  // Deduplicated BEFORE the buckets are cut, because the buckets are the target
  // the control is matched to: cutting them over captures would weight the
  // target by publishing frequency, which is the weighting dedupeByPackage
  // exists to remove.
  const classMembers = dedupeByPackage(
    withBytes.filter(c => c.cell?.key === CLASS_CELL)
      .map(c => memberFromCapture(c.sample, c.markers, CLASS_CELL))
  )
  const offClassMembers = dedupeByPackage(
    withBytes.filter(c => c.cell?.key !== CLASS_CELL)
      .map(c => memberFromCapture(c.sample, c.markers, c.cell?.key ?? 'outside every cell'))
  )

  const targetSizes = classMembers.map(m => m.unpackedSize)
  const buckets = sizeBuckets(targetSizes)

  const groups: GroupReport[] = []

  groups.push(await measureCaptureGroup({
    name: 'class, from disk',
    cell: CLASS_CELL,
    definition: `${CELLS[0]!.definition} — every capture of the class in the window, which is a census of it and not a sample`,
    sizeMatched: true,          // it IS the target distribution
    members: classMembers,
    buckets, options,
  }))

  groups.push(await measureCaptureGroup({
    name: 'off-class, from disk',
    cell: 'off-class',
    definition: 'captures in the same window, under 100KB, outside the class — every one of them kept because it scored high enough for the watcher to snapshot it, which is a second filter and not the background',
    sizeMatched: false,
    members: offClassMembers,
    buckets, options,
  }))

  const pool = buildPool(options.outputDir, { since: options.since, until: options.until })

  if (options.drawPerCell > 0) {
    for (const cell of CELLS) {
      const candidates = pool.candidates.filter(c => c.cell === cell.key)
      const draw = sizeMatchedDraw(candidates, c => c.bytes, targetSizes, options.drawPerCell, buckets)

      groups.push(await measureRegistryGroup({
        name: `${cell.name}, from the registry`,
        cell: cell.key,
        definition: `${cell.definition}; drawn from the publish stream to match the class's size distribution decile by decile, and fetched from npm now`,
        candidates: draw.picked,
        shortfall: draw.shortfall,
        buckets, options,
      }))
    }
  }

  const fromDisk = groups.find(g => g.name === 'class, from disk')!
  const comparisons: ControlComparison[] = []
  for (const g of groups) {
    if (g === fromDisk) continue
    if (g.scored === 0) continue
    comparisons.push(compareGroups(fromDisk, g))
  }

  // The endpoints are a family too. The module table is widened for its own
  // size inside compareGroups; leaving the headline rows at a bare 95% each
  // would mean the only unadjusted numbers in the report are the ones somebody
  // is going to quote.
  const endpointFamily = comparisons.reduce((n, c) => n + c.endpoints.length, 0)
  const z = zForFamily(endpointFamily)
  for (const c of comparisons) {
    c.endpointFamily = endpointFamily
    c.endpointZ = z
    for (const e of c.endpoints) {
      e.familyAdjusted = differenceWithCI(
        e.difference.a.successes, e.difference.a.n,
        e.difference.b.successes, e.difference.b.n,
        z
      )
    }
  }

  return {
    ranAt: options.now ? options.now() : new Date().toISOString(),
    engineVersion: options.engineVersion,
    threshold: options.threshold,
    window: { since: options.since, until: options.until ?? null },
    maxBytes: TINY_PACKAGE_BYTES,
    equivalenceMargin: EQUIVALENCE_MARGIN,
    buckets,
    corpus: {
      inWindow: inWindow.length,
      overTheSizeBand: notTiny,
      withBytes: withBytes.length,
      unclassifiable,
      byCell: [
        ...CELLS.map(c => ({
          cell: c.key,
          captures: withBytes.filter(x => x.cell?.key === c.key).length,
          packages: new Set(withBytes.filter(x => x.cell?.key === c.key).map(x => x.sample.package)).size,
        })),
        {
          cell: 'outside every cell',
          captures: withBytes.filter(x => x.cell === null).length,
          packages: new Set(withBytes.filter(x => x.cell === null).map(x => x.sample.package)).size,
        },
      ],
      tinyOutsideEveryCell: withBytes.filter(x => x.cell === null).length,
    },
    pool,
    groups,
    comparisons,
    caveats: caveatsFor(groups),
  }
}

// One capture per package name. The same name is captured again on every
// publication, and a legibility rate over captures weights whoever publishes
// most — which in this window is a handful of campaign families.
export function dedupeByPackage(members: ControlMember[]): ControlMember[] {
  const first = new Map<string, ControlMember>()
  for (const m of members) {
    const seen = first.get(m.package)
    if (!seen || m.at < seen.at) first.set(m.package, m)
  }
  return [...first.values()].sort((a, b) => a.at.localeCompare(b.at))
}

async function measureCaptureGroup(input: {
  name: string
  cell: string
  definition: string
  sizeMatched: boolean
  members: ControlMember[]
  buckets: SizeBucket[]
  options: SizeControlOptions
}): Promise<GroupReport> {
  const results: MemberResult[] = []
  const failures: Array<{ package: string; reason: string }> = []
  let done = 0

  for (const member of input.members) {
    done++
    input.options.onProgress?.(input.name, done, input.members.length)

    const tarball = tarballOfCapture(member)
    if (typeof tarball === 'string') {
      failures.push({ package: `${member.package}@${member.version}`, reason: tarball })
      continue
    }
    results.push(measureMember(member, tarball, input.options.threshold, input.options.limits))
  }

  return summariseGroup({
    name: input.name, cell: input.cell, definition: input.definition,
    source: 'capture', sizeMatched: input.sizeMatched,
    results, failures, buckets: input.buckets,
    members: input.members.length, threshold: input.options.threshold,
  })
}

function tarballOfCapture(member: ControlMember): Buffer | string {
  if (!member.ngpackPath) return 'no snapshot path'
  try {
    const source = new NgpackSource(member.ngpackPath)
    if (source.missingTarballs.includes(member.version)) {
      return 'tarball bytes are no longer in the object store'
    }
    return source.tarballSync(member.version) ?? source.tarballSync() ?? 'no tarball in the snapshot'
  } catch (e) {
    return `unreadable snapshot: ${e instanceof Error ? e.message : String(e)}`
  }
}

// A registry group, fetched. Every failure is recorded with its reason: a
// package npm removed between publication and now cannot be measured, and a
// control group that silently drops those is a control group of survivors.
async function measureRegistryGroup(input: {
  name: string
  cell: string
  definition: string
  candidates: PoolCandidate[]
  shortfall: Draw<PoolCandidate>['shortfall']
  buckets: SizeBucket[]
  options: SizeControlOptions
}): Promise<GroupReport> {
  const { options } = input
  const source = options.source ?? defaultSource
  const delay = options.fetchDelayMs ?? 100

  const results: MemberResult[] = []
  const failures: Array<{ package: string; reason: string }> = []
  let done = 0

  for (const candidate of input.candidates) {
    done++
    options.onProgress?.(input.name, done, input.candidates.length)

    try {
      let packument: Packument
      try {
        packument = normalizePackument(await source.fetchPackument(candidate.package))
      } catch (e) {
        failures.push({ package: candidate.package, reason: `packument: ${short(e)}` })
        continue
      }

      const chosen = versionAt(packument, candidate.seenAt)
      if (!chosen) {
        failures.push({ package: candidate.package, reason: 'the packument holds no versions at all' })
        continue
      }

      // The version the log row was about is gone and a later one is what npm
      // still serves. Measuring it would put bytes in the group that the window
      // never saw.
      if (chosen.publishedAt && new Date(chosen.publishedAt).getTime() > new Date(candidate.seenAt).getTime()) {
        failures.push({
          package: candidate.package,
          reason: `the version published at the sighting is gone; the earliest survivor is ${chosen.version} from ${chosen.publishedAt.slice(0, 10)}`,
        })
        continue
      }

      // Re-derived here rather than trusted from the log, because the row and
      // the packument are two records of the same moment and a disagreement
      // means the version being measured is not the one the row described.
      const markers = classifyPublication(
        packument, chosen, candidate.regime ?? 'unknown',
        new Date(candidate.seenAt).getTime()
      )
      const cell = cellOf({
        noGenome: markers.noGenome,
        young: markers.young,
        repository: markers.hasRepository,
        tiny: markers.tiny,
      })
      if (cell?.key !== input.cell) {
        failures.push({
          package: candidate.package,
          reason: `re-derives into ${cell?.key ?? 'no cell'} rather than ${input.cell} (bytes=${markers.unpackedSize}, repo=${markers.hasRepository}, young=${markers.young})`,
        })
        continue
      }

      let tarball: Buffer
      try {
        // By URL, from the packument already in hand. Going through
        // fetchTarball would fetch the packument a second time, and the two
        // copies can disagree.
        tarball = await downloadTarball(chosen.dist.tarball)
      } catch (e) {
        failures.push({ package: `${candidate.package}@${chosen.version}`, reason: `tarball: ${short(e)}` })
        continue
      }

      results.push(measureMember({
        package: candidate.package,
        version: chosen.version,
        at: candidate.seenAt,
        origin: 'registry',
        ngpackPath: null,
        unpackedSize: markers.unpackedSize,
        hasRepository: markers.hasRepository,
        nameAgeDays: markers.nameAgeDays,
        regime: candidate.regime,
        cell: input.cell,
      }, tarball, options.threshold, options.limits))
    } finally {
      // Whatever the outcome. Skipping the wait on the failure paths would make
      // the request rate highest exactly when a cell is being taken down.
      if (delay > 0) await sleep(delay)
    }
  }

  return summariseGroup({
    name: input.name, cell: input.cell, definition: input.definition,
    source: 'registry', sizeMatched: true,
    results, failures, shortfall: input.shortfall, buckets: input.buckets,
    members: input.candidates.length, threshold: options.threshold,
  })
}

// The version the log row was written about: the last one published at or
// before the sighting. Null only when the packument holds nothing at all; the
// caller decides what to do when the survivor is later than the sighting,
// because that is a different fact from "not found".
export function versionAt(packument: Packument, at: string): VersionMeta | null {
  const atMs = new Date(at).getTime()
  const published = Object.values(packument.versions)
    .filter(v => v.publishedAt)
    .sort((x, y) => new Date(x.publishedAt).getTime() - new Date(y.publishedAt).getTime())

  if (published.length === 0) return Object.values(packument.versions)[0] ?? null

  let chosen: VersionMeta | null = null
  for (const v of published) {
    if (new Date(v.publishedAt).getTime() <= atMs) chosen = v
    else break
  }
  return chosen ?? published[0]!
}

function caveatsFor(groups: GroupReport[]): string[] {
  const caveats: string[] = []
  const registry = groups.filter(g => g.source === 'registry')

  if (registry.length > 0) {
    const lost = registry.reduce((s, g) => s + g.failures.length, 0)
    const asked = registry.reduce((s, g) => s + g.members, 0)
    caveats.push(
      `${lost} of the ${asked} packages drawn for the registry groups could not be measured — removed, ` +
      `renamed, re-derived into another cell, or their version at the sighting is gone. Every one is in ` +
      `the artifact with its reason, because npm removing a package between publication and now is not ` +
      `random and the class is the population npm removes.`
    )
    caveats.push(
      `The class is measured twice on purpose. "class, from disk" is a census of the class in the ` +
      `window; "class, from the registry" is what is left of it today. The gap between those two rows ` +
      `is the size of the survivorship problem, measured rather than assumed.`
    )
  }

  caveats.push(
    `Size is controlled. What is NOT controlled is whether a package was built by a toolchain — and ` +
    `two of the three conjuncts being varied (a repository, a publication history) are close proxies ` +
    `for exactly that. A package with a repo and ten versions is usually bundled, transpiled or ` +
    `minified; one published an hour ago under a new name usually is not. So a surviving gap says the ` +
    `class ships flat readable JavaScript more often than software of the same size that has a ` +
    `history — it does not say the class is unusual in any way its own definition does not already ` +
    `state.`
  )

  caveats.push(
    `Module rates are over the captures whose entry points could be resolved and followed, which is a ` +
    `different subset in each group, and a package whose payload is a native binary reaches whatever ` +
    `it likes and appears in none of them.`
  )

  return caveats
}

function short(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e)
  return message.length > 120 ? `${message.slice(0, 117)}...` : message
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
