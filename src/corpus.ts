// The malicious corpus is whatever exists on disk as .ngpack snapshots. The
// Shai-Hulud and AsyncAPI versions were purged from npm within the hour, so a
// corpus defined as a list of names cannot be run at all.
//
// Promotion out of 'unconfirmed' needs an external source: an npm advisory, a
// public report, or content analysis. A high score is why a capture was kept,
// not evidence of what it is, since an attack nobody detected also sits quiet.
// Recall is computed over confirmed_malicious and nothing else.

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { objectPath } from './object-store.js'
import { writeFileSync } from 'node:fs'
import { rateWithCI, type RateWithCI } from './stats.js'
import { EXPIRY_LOG as EXPIRY_LOG_NAME } from './capture-budget.js'
import type { CaptureComposition, CaptureLabel, CaptureMetadata, NgpackManifest, TarballRefusal } from './ngpack.js'

export interface CorpusSample {
  package: string
  version: string
  label: CaptureLabel
  ngpackPath: string
  capturedAt: string
  captureScore?: number
  labelSource?: string
  labeledAt?: string
  notes?: string
  // The manifest DECLARES a captured version. It is not a statement that the
  // bytes are on disk, and it was read as one for long enough to matter: 3,261
  // of 4,884 captures — 66.8%, including six of the eight confirmed_malicious —
  // have no tarball left, and nothing reported it because layer 1 analyses the
  // packument and never asks for the artifact.
  hasTarball: boolean
  // Whether the bytes are actually there, checked. Anything that needs to read
  // a package's contents has to filter on this one.
  tarballPresent: boolean
  // No capture-metadata.json, so 'unconfirmed' is this loader's default rather
  // than a recorded decision.
  labelAssumed: boolean
  captureReason?: string
  engineVersion?: string
  // The weekly download count as it stood at capture, when the watcher recorded
  // it. This is the fifth conjunct of the fabricated-profile rule, and the only
  // copy of it that will ever exist: npm serves one complete week at a time, so
  // a snapshot taken without it can never be re-judged by the rule. Undefined
  // means it was never recorded, which is not the same as zero.
  weeklyDownloads?: number | null
  downloadWindowEnd?: string | null
  // Whether that week overlapped the package's life. A zero without it cannot be
  // told from npm's 404 for a name it never had, and npm answers 404 for almost
  // every package of this class.
  downloadWindowCovers?: boolean | null
  composition?: CaptureComposition
  // The tarball was refused by policy rather than lost. Held apart from
  // `tarballPresent` on purpose: both are captures with no bytes, and only one
  // of them is a defect. A denominator can be corrected for a refusal, because
  // the refusal states the size that caused it.
  tarballRefused?: TarballRefusal
  // Known-biased selection, or unknown provenance. A corpus assembled by a
  // detector with a known bug is a draw from what that bug flagged, not from the
  // ecosystem, so it stays out of every denominator.
  contaminated: boolean
  contaminationReason?: string
}

export interface LabeledCorpus {
  roots: string[]
  samples: CorpusSample[]
  // Usable only. Contaminated samples are held apart deliberately.
  confirmedMalicious: CorpusSample[]
  confirmedBenign: CorpusSample[]
  unconfirmed: CorpusSample[]
  contaminated: CorpusSample[]
  confirmedMaliciousContaminated: CorpusSample[]
  unlabeled: number
  firstCaptureAt: string | null
  lastCaptureAt: string | null
}

// The era when the gate scored packages against a genome they did not have.
export const PRE_FIX_REASON = 'pre-fix-gate-bug'

export function classifyContamination(
  captureReason: string | undefined,
  labelAssumed: boolean
): { contaminated: boolean; contaminationReason?: string } {
  if (captureReason?.includes('pre-fix')) {
    return {
      contaminated: true,
      contaminationReason: 'captured while the gate was broken: it scored packages with no genome under genome rules',
    }
  }
  if (labelAssumed || !captureReason) {
    return {
      contaminated: true,
      contaminationReason: 'no provenance recorded: neither which engine selected it nor why',
    }
  }
  return { contaminated: false }
}

export const DEFAULT_CORPUS_ROOTS = [
  './norte-guard-captures/captures',
  './captures',
]

function corpusRoots(explicit?: string[]): string[] {
  if (explicit && explicit.length > 0) return explicit
  const fromEnv = process.env['NORTE_GUARD_CORPUS']
  if (fromEnv) return fromEnv.split(':').filter(Boolean)
  return DEFAULT_CORPUS_ROOTS
}

// Name and version come from the manifest: the directory encodes "@scope/pkg"
// as "_scope_pkg", which cannot be reversed without guessing.
function readSample(dir: string): CorpusSample | null {
  const manifestPath = join(dir, 'manifest.json')
  if (!existsSync(manifestPath)) return null

  let manifest: NgpackManifest
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as NgpackManifest
  } catch {
    return null
  }

  const version = manifest.versionsIncluded[0] ?? ''
  const metaPath = join(dir, 'capture-metadata.json')

  const withoutMetadata = (): CorpusSample => ({
    package: manifest.package,
    version,
    label: 'unconfirmed',
    ngpackPath: dir,
    capturedAt: manifest.capturedAt,
    hasTarball: manifest.versionsIncluded.length > 0,
    tarballPresent: tarballPresent(dir, manifest, version),
    labelAssumed: true,
    ...classifyContamination(undefined, true),
  })

  if (!existsSync(metaPath)) return withoutMetadata()

  let meta: CaptureMetadata
  try {
    meta = JSON.parse(readFileSync(metaPath, 'utf-8')) as CaptureMetadata
  } catch {
    return withoutMetadata()
  }

  // Corruption degrades to unconfirmed. Promotion is always an explicit act.
  const label: CaptureLabel =
    meta.label === 'confirmed_malicious' || meta.label === 'confirmed_benign'
      ? meta.label
      : 'unconfirmed'

  // A confirmed label with no source behind it is what this corpus exists to
  // prevent.
  const confirmedWithoutSource =
    label !== 'unconfirmed' && !meta.labelSource

  return {
    package: meta.package || manifest.package,
    version: meta.version || version,
    label: confirmedWithoutSource ? 'unconfirmed' : label,
    ngpackPath: dir,
    capturedAt: meta.capturedAt || manifest.capturedAt,
    captureScore: meta.score,
    labelSource: meta.labelSource,
    labeledAt: meta.labeledAt,
    notes: confirmedWithoutSource
      ? `label "${meta.label}" ignored: no labelSource. ${meta.notes ?? ''}`.trim()
      : meta.notes,
    hasTarball: manifest.versionsIncluded.length > 0,
    tarballPresent: tarballPresent(dir, manifest, meta.version || version),
    labelAssumed: false,
    captureReason: meta.captureReason,
    engineVersion: meta.engineVersion,
    weeklyDownloads: meta.weeklyDownloads,
    downloadWindowEnd: meta.downloadWindowEnd,
    downloadWindowCovers: meta.downloadWindowCovers,
    composition: meta.composition ?? compositionFromNotes(meta.notes),
    tarballRefused: meta.tarballRefused,
    ...classifyContamination(meta.captureReason, false),
  }
}

// Whether the bytes a capture declares are still where it left them. Both
// layouts have to be checked: older captures hold the tarball inline, newer ones
// name an object in the shared store, and the store is what rotation prunes.
//
// Cheap enough to run on every load — one stat per capture — and the alternative
// is what happened: a corpus that reported 4,884 samples when two thirds of them
// were a manifest and a packument with nothing behind them.
function tarballPresent(dir: string, manifest: NgpackManifest, version: string): boolean {
  if (!version) return false

  const hash = manifest.objects?.[version]
  if (hash && manifest.objectStore) {
    // Resolved against the capture's own parent, never against the recorded
    // objectStore string: that is a path relative to wherever the watcher
    // happened to be running, and following it points at whatever store sits
    // under the current shell's cwd.
    return existsSync(objectPath(join(dir, '..'), hash))
  }

  return existsSync(join(dir, 'tarballs', `${version}.tgz`))
}

// Captures written before composition was recorded still carry the same facts in
// their notes string. Parsing it back is ugly, but the alternative is a corpus
// whose older half cannot be broken down at all.
export function compositionFromNotes(notes?: string): CaptureComposition | undefined {
  if (!notes) return undefined

  const regime = /regime ([a-z-]+)/.exec(notes)?.[1]
  const signalList = /signals: (.+?)(?:;|$)/.exec(notes)?.[1]
  if (!regime && !signalList) return undefined

  const signals = signalList && signalList !== 'ninguna'
    ? signalList.split(',').map(s => s.trim().replace(/[+-]\d+$/, ''))
    : []

  const ghost = /recent ghost (\S+)/.exec(notes)?.[1] ?? null

  return {
    regime: regime ?? 'unknown',
    signals,
    firstPublication: regime === 'no-genome',
    ghost,
    ghostKind: ghost ? (/recent ghost \S+ \((\w+)\)/.exec(notes)?.[1] ?? null) : null,
    newInstallScript: signals.some(s => s === 'new_install_script' || s === 'absolute_install_script'),
    platformFamily: null,
  }
}

export interface CorpusComposition {
  total: number
  withComposition: number
  platformFamilyMembers: number
  platformFamilies: number
  firstPublications: number
  withGhost: number
  ghostByKind: Record<string, number>
  withNewInstallScript: number
  byRegime: Record<string, number>
  topSignals: Array<{ signal: string; count: number }>
}

// A count of captures says nothing about whether the disk holds a corpus. This
// says what it holds, which is what decides whether the budget is buying
// anything.
export function describeComposition(samples: CorpusSample[]): CorpusComposition {
  const withComposition = samples.filter(s => s.composition)
  const families = new Set<string>()
  const ghostByKind: Record<string, number> = {}
  const byRegime: Record<string, number> = {}
  const signalCounts: Record<string, number> = {}

  let platformFamilyMembers = 0
  let firstPublications = 0
  let withGhost = 0
  let withNewInstallScript = 0

  for (const s of withComposition) {
    const c = s.composition!
    if (c.platformFamily) { platformFamilyMembers++; families.add(c.platformFamily) }
    else if (isPlatformSuffixed(s.package)) { platformFamilyMembers++; families.add(baseName(s.package)) }
    if (c.firstPublication) firstPublications++
    if (c.ghost) {
      withGhost++
      const kind = c.ghostKind ?? 'unknown'
      ghostByKind[kind] = (ghostByKind[kind] ?? 0) + 1
    }
    if (c.newInstallScript) withNewInstallScript++
    byRegime[c.regime] = (byRegime[c.regime] ?? 0) + 1
    for (const sig of new Set(c.signals)) signalCounts[sig] = (signalCounts[sig] ?? 0) + 1
  }

  return {
    total: samples.length,
    withComposition: withComposition.length,
    platformFamilyMembers,
    platformFamilies: families.size,
    firstPublications,
    withGhost,
    ghostByKind,
    withNewInstallScript,
    byRegime,
    topSignals: Object.entries(signalCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([signal, count]) => ({ signal, count })),
  }
}

// The denominator. Without it the corpus can report eight confirmed removals and
// nothing at all about what they were eight out of, and eight out of fifty and
// eight out of fifteen hundred are opposite conclusions about the same rule.
//
// The unit is the PACKAGE, not the capture. The same name is captured again on
// every publication, so counting captures multiplies whichever packages publish
// most and turns a precision into a publishing-frequency artifact. Captures are
// reported alongside because they are what the disk cost is measured in.
export interface ClassPrecision {
  // Everything the capture filter marked, whatever became of it.
  markedCaptures: number
  markedPackages: number
  // npm published 0.0.1-security over it. Known from the takedown log the
  // watcher writes live and from any sweep on disk, which is the same authority
  // the labels come from.
  removed: number
  // Alive at the last check and installed by somebody. Only knowable for
  // packages the tracker has actually queried, so it is reported over its own
  // denominator and never over the marked total.
  observedAlive: number
  observedAliveWithUsage: number
  precision: RateWithCI | null
  // The same fraction over packages old enough for the verdict to mean
  // something. A package marked yesterday is neither a hit nor a miss yet, and
  // folding it into the denominator understates precision by however much of the
  // corpus is too young to have resolved.
  matureDays: number
  maturePackages: number
  matureRemoved: number
  maturePrecision: RateWithCI | null
  // Names counted from the expiry log because their artifacts are gone.
  expiredPackages: number
  oldestMarkedDays: number | null
  medianMarkedDays: number | null
  // What the number cannot say, in the same object as the number.
  caveats: string[]
}

export function classPrecision(input: {
  samples: CorpusSample[]
  captureReason: string
  // Every package known to have been removed, from whichever source knows it.
  removedPackages: Set<string>
  // Names the filter marked whose artifacts have since been deleted by retention
  // or by the disk cap. They belong in the denominator: the package was marked,
  // and the deleter is not evidence about it either way. Leaving them out would
  // let precision climb as the corpus aged, because both deleters protect
  // labelled captures and take unlabelled ones oldest-first — the numerator is
  // safe and the denominator is not.
  expired?: Array<{ package: string; capturedAt: string; captureReason?: string }>
  // package -> the highest weekly download count the tracker has seen for it.
  observedDownloads?: Map<string, number>
  realUsageDownloads: number
  matureDays: number
  // How long an unconfirmed capture of this class is kept. When it is shorter
  // than matureDays the mature fraction can never be rebuilt from surviving
  // directories, and saying "not yet" would be wrong in a way that never
  // corrects itself.
  retentionDays?: number
  now?: number
}): ClassPrecision {
  const now = input.now ?? Date.now()

  // Earliest capture per package: the clock starts when the filter first marked
  // it, not when it was last re-captured.
  const firstMarked = new Map<string, string>()
  let markedCaptures = 0
  for (const s of input.samples) {
    if (s.captureReason !== input.captureReason) continue
    markedCaptures++
    const seen = firstMarked.get(s.package)
    if (seen === undefined || s.capturedAt < seen) firstMarked.set(s.package, s.capturedAt)
  }

  let expiredPackages = 0
  for (const e of input.expired ?? []) {
    if (e.captureReason !== input.captureReason) continue
    // A name that was re-captured after the old artifact expired is already
    // counted, and the earlier date is the one the clock should run from.
    const seen = firstMarked.get(e.package)
    if (seen === undefined) expiredPackages++
    if (seen === undefined || e.capturedAt < seen) firstMarked.set(e.package, e.capturedAt)
  }

  const ages = [...firstMarked.values()]
    .map(at => (now - new Date(at).getTime()) / 86_400_000)
    .filter(d => Number.isFinite(d))
    .sort((a, b) => a - b)

  const markedPackages = firstMarked.size
  const removed = [...firstMarked.keys()].filter(p => input.removedPackages.has(p)).length

  const mature = [...firstMarked.entries()].filter(
    ([, at]) => (now - new Date(at).getTime()) / 86_400_000 >= input.matureDays
  )
  const matureRemoved = mature.filter(([p]) => input.removedPackages.has(p)).length

  const tracked = [...firstMarked.keys()].filter(p => input.observedDownloads?.has(p))
  const observedAliveWithUsage = tracked.filter(
    p => (input.observedDownloads!.get(p) ?? 0) >= input.realUsageDownloads
  ).length

  const caveats: string[] = []
  if (mature.length === 0) {
    // A LOWER bound, and the direction matters. Every marked name is in the
    // denominator from the moment it was marked, whatever becomes of it, so the
    // denominator is already complete for this cohort and only the numerator can
    // still move — upward, as removals that have not happened yet arrive. The
    // first version of this line said "upper bound" and had the arithmetic
    // backwards.
    caveats.push(
      `no marked package has reached ${input.matureDays} days yet (oldest ${ages[ages.length - 1]?.toFixed(1) ?? '0'} days), ` +
      `so nothing in this denominator has resolved. The denominator is complete for this cohort and ` +
      `the numerator is not, so this is a LOWER bound: it can only rise as removals arrive.`
    )
  }
  if (input.retentionDays !== undefined && input.retentionDays < input.matureDays) {
    caveats.push(
      `the mature fraction cannot be rebuilt from surviving captures at all: quarantine retention is ` +
      `${input.retentionDays} days and a verdict takes ${input.matureDays}, so no unconfirmed capture ` +
      `of this class ever reaches the age its answer needs. It is calculable only because the names ` +
      `outlive the artifacts in ${EXPIRY_LOG_NAME}.`
    )
  }
  if (expiredPackages > 0) {
    caveats.push(
      `${expiredPackages} marked packages are counted from the expiry log: their artifacts were ` +
      `deleted by retention or the disk cap. Both deleters keep labelled captures and take unlabelled ` +
      `ones oldest-first, so without that log this fraction would climb on its own as the corpus aged.`
    )
  }
  // Wilson assumes independent trials, and these are not. The removals arrive in
  // campaigns: one operator publishes a family of names within minutes and npm
  // removes the family within seconds of each other. The interval is reported
  // because a bare rate invites more precision than any n supports, but its
  // width is the width for independent draws and the true one is wider.
  if (removed > 1) {
    caveats.push(
      `the ${removed} removals are not ${removed} independent events: this class arrives in campaigns, ` +
      `several names published minutes apart and removed together. The Wilson interval assumes ` +
      `independent trials, so read it as narrower than the truth.`
    )
  }
  if (tracked.length > 0 && observedAliveWithUsage > 0) {
    caveats.push(
      `${observedAliveWithUsage} of the ${tracked.length} marked packages the tracker has queried are alive with ` +
      `>=${input.realUsageDownloads} weekly downloads. On that sample the class contains more packages ` +
      `somebody installs than packages npm removed.`
    )
  }
  if (tracked.length < markedPackages) {
    caveats.push(
      `${markedPackages - tracked.length} of ${markedPackages} marked packages have never been queried, so ` +
      `"alive" is measured on ${tracked.length} and must not be scaled up to the rest.`
    )
  }

  return {
    markedCaptures,
    markedPackages,
    removed,
    observedAlive: tracked.length,
    observedAliveWithUsage,
    precision: markedPackages > 0 ? rateWithCI(removed, markedPackages) : null,
    matureDays: input.matureDays,
    maturePackages: mature.length,
    matureRemoved,
    maturePrecision: mature.length > 0 ? rateWithCI(matureRemoved, mature.length) : null,
    expiredPackages,
    oldestMarkedDays: ages.length > 0 ? Math.round(ages[ages.length - 1]! * 10) / 10 : null,
    medianMarkedDays: ages.length > 0 ? Math.round(ages[Math.floor(ages.length / 2)]! * 10) / 10 : null,
    caveats,
  }
}

const PLATFORM_SUFFIX =
  /-(darwin|linux|win32|freebsd|openbsd|sunos|android|universal)(-(arm64|x64|ia32|arm|riscv64|ppc64|s390x|loong64))?(-(gnu|musl|msvc|eabi|eabihf|baseline))?$/

function isPlatformSuffixed(name: string): boolean {
  return PLATFORM_SUFFIX.test(name)
}

function baseName(name: string): string {
  return name.replace(PLATFORM_SUFFIX, '')
}

export function loadCorpus(explicitRoots?: string[]): LabeledCorpus {
  const roots = corpusRoots(explicitRoots)
  const samples: CorpusSample[] = []

  for (const root of roots) {
    if (!existsSync(root)) continue
    for (const name of readdirSync(root)) {
      const dir = join(root, name)
      try {
        if (!statSync(dir).isDirectory()) continue
      } catch { continue }

      const sample = readSample(dir)
      if (sample) samples.push(sample)
    }
  }

  samples.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))

  const usable = samples.filter(s => !s.contaminated)

  return {
    roots,
    samples,
    // Excluded here rather than downstream, so a caller cannot use the corpus
    // for a benchmark without passing the split deliberately.
    confirmedMalicious: usable.filter(s => s.label === 'confirmed_malicious'),
    confirmedBenign: usable.filter(s => s.label === 'confirmed_benign'),
    unconfirmed: usable.filter(s => s.label === 'unconfirmed'),
    contaminated: samples.filter(s => s.contaminated),
    confirmedMaliciousContaminated: samples.filter(
      s => s.contaminated && s.label === 'confirmed_malicious'
    ),
    unlabeled: samples.filter(s => s.labelAssumed).length,
    firstCaptureAt: samples[0]?.capturedAt ?? null,
    lastCaptureAt: samples[samples.length - 1]?.capturedAt ?? null,
  }
}

// Printed under every recall line, calculable or not: the size and age of the
// corpus is what makes the number readable, or its absence defensible.
export function describeCorpusProgress(corpus: LabeledCorpus): string {
  const since = corpus.firstCaptureAt
    ? corpus.firstCaptureAt.slice(0, 10)
    : '(no captures)'

  // The artifact count belongs on the same line as the capture count, because
  // for two days they were the same number in everyone's head and they are not
  // the same number on disk. Layer 1 reads the packument, so a capture whose
  // tarball is gone analyses exactly like one that still has it, and nothing
  // downstream had any reason to notice — `norte-guard analyzability` was the
  // first thing to ask.
  const withBytes = corpus.samples.filter(s => s.tarballPresent).length
  const confirmedWithBytes = corpus.confirmedMalicious.filter(s => s.tarballPresent).length
  const missing = corpus.samples.length - withBytes

  return (
    `corpus building since ${since}: ` +
    `${corpus.samples.length} captures, ${corpus.confirmedMalicious.length} confirmed` +
    (missing > 0
      ? `; ${withBytes} still hold their tarball (${confirmedWithBytes} of the confirmed ones), ` +
        `the other ${missing} are a manifest and a packument with nothing behind them`
      : '')
  )
}

// Printed whenever anything is held back, so "the corpus is small" and "part of
// it is unusable" never have to be told apart by inference.
export function describeContamination(corpus: LabeledCorpus): string | null {
  if (corpus.contaminated.length === 0) return null

  const preFix = corpus.contaminated.filter(s => s.captureReason?.includes('pre-fix')).length
  const unknown = corpus.contaminated.length - preFix

  const parts: string[] = []
  if (preFix > 0) parts.push(`${preFix} captured while the gate was broken`)
  if (unknown > 0) parts.push(`${unknown} with no provenance`)

  return (
    `${corpus.contaminated.length} captures excluded from every benchmark (${parts.join(', ')})` +
    (corpus.confirmedMaliciousContaminated.length > 0
      ? `, of which ${corpus.confirmedMaliciousContaminated.length} are labelled confirmed_malicious and still excluded from recall`
      : '')
  )
}

// The public record of attacks this tool is meant to catch. None of them can be
// fetched any more, which is why NgpackSource exists.
//
// These are not samples. A version that cannot be analysed cannot be detected or
// missed, so none of them enters the recall denominator. The list is work: each
// entry is a snapshot somebody still has to find in a mirror or artifact cache.
export interface AttackReference {
  package: string
  version: string
  campaign: string
  source: string
  publishedAt?: string
  detectedAt?: string
  note?: string
}

export const KNOWN_ATTACK_REFERENCES: AttackReference[] = [
  { package: 'keyv',              version: '6.0.0',   campaign: 'Shai-Hulud', source: 'Aikido/Socket', publishedAt: '2026-08-04T09:00:00Z', detectedAt: '2026-08-04T11:00:00Z' },
  { package: 'flat-cache',        version: '6.1.24',  campaign: 'Shai-Hulud', source: 'Aikido/Socket' },
  { package: 'file-entry-cache',  version: '11.1.6',  campaign: 'Shai-Hulud', source: 'Aikido/Socket' },
  { package: 'cache-manager',     version: '7.2.10',  campaign: 'Shai-Hulud', source: 'Aikido/Socket' },
  { package: 'cacheable-request', version: '13.0.20', campaign: 'Shai-Hulud', source: 'Aikido/Socket' },

  // Import-time payloads. The packument layer cannot see these even with a
  // snapshot in hand — kept on the list because a benchmark that quietly drops
  // its known blind spots stops measuring anything.
  { package: '@asyncapi/specs',             version: '6.11.2', campaign: 'AsyncAPI/Miasma', source: 'Microsoft/Socket', publishedAt: '2026-07-14T07:10:00Z', note: 'import-time, outside the reach of layer 1' },
  { package: '@asyncapi/generator',         version: '3.3.1',  campaign: 'AsyncAPI/Miasma', source: 'Microsoft/Socket', note: 'import-time — fuera del alcance de la capa 1' },
  { package: '@asyncapi/generator-helpers', version: '1.1.1',  campaign: 'AsyncAPI/Miasma', source: 'Microsoft/Socket', note: 'import-time — fuera del alcance de la capa 1' },

  // Slow poison: the payload landed long after the maintainer handover, so a
  // capability delta against the previous version cannot see it.
  { package: 'event-stream', version: '3.3.6', campaign: 'event-stream-2018', source: 'npm advisory', publishedAt: '2018-09-01T00:00:00Z', detectedAt: '2018-11-26T00:00:00Z', note: 'capability delta does not apply: the payload arrived months after the handover' },
]

export interface BackfillResult {
  ngpackPath: string
  package: string
  version: string
  action: 'marked' | 'skipped-has-metadata' | 'skipped-after-cutoff'
}

// Writes provenance retroactively for captures taken before the watcher started
// recording it. The discriminator is exact rather than inferred: the pre-fix
// watcher never wrote capture-metadata.json at all, so "no metadata" and
// "pre-fix" are the same set. `before` narrows it further.
export function backfillCaptureProvenance(input: {
  roots?: string[]
  reason: string
  engineVersion: string
  before?: string
  dryRun?: boolean
}): BackfillResult[] {
  const roots = corpusRoots(input.roots)
  const results: BackfillResult[] = []

  for (const root of roots) {
    if (!existsSync(root)) continue

    for (const name of readdirSync(root)) {
      const dir = join(root, name)
      try {
        if (!statSync(dir).isDirectory()) continue
      } catch { continue }

      const manifestPath = join(dir, 'manifest.json')
      if (!existsSync(manifestPath)) continue

      let manifest: NgpackManifest
      try {
        manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as NgpackManifest
      } catch { continue }

      const version = manifest.versionsIncluded[0] ?? ''
      const base = { ngpackPath: dir, package: manifest.package, version }

      // Never overwrites: a capture that already declares its provenance has
      // been decided about.
      if (existsSync(join(dir, 'capture-metadata.json'))) {
        results.push({ ...base, action: 'skipped-has-metadata' })
        continue
      }

      if (input.before && manifest.capturedAt >= input.before) {
        results.push({ ...base, action: 'skipped-after-cutoff' })
        continue
      }

      if (!input.dryRun) {
        const metadata: CaptureMetadata = {
          package: manifest.package,
          version,
          capturedAt: manifest.capturedAt,
          // The pre-fix watcher never recorded it; zero means unknown, and the
          // note says so.
          score: 0,
          label: 'unconfirmed',
          captureReason: input.reason,
          engineVersion: input.engineVersion,
          notes:
            'provenance reconstructed: this capture predates the watcher writing ' +
            'capture-metadata.json. The capture score was never recorded (0 = unknown).',
          doNotExtract: true,
        }
        writeFileSync(join(dir, 'capture-metadata.json'), JSON.stringify(metadata, null, 2))
      }

      results.push({ ...base, action: 'marked' })
    }
  }

  return results
}

export interface ReferenceStatus extends AttackReference {
  sample: CorpusSample | null
}

// Everything without a sample is reported as missing, never as a miss.
export function resolveReferences(
  corpus: LabeledCorpus,
  references: AttackReference[] = KNOWN_ATTACK_REFERENCES
): ReferenceStatus[] {
  return references.map(ref => ({
    ...ref,
    sample: corpus.samples.find(
      s => s.package === ref.package && s.version === ref.version
    ) ?? null,
  }))
}
