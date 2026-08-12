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
import { writeFileSync } from 'node:fs'
import type { CaptureComposition, CaptureLabel, CaptureMetadata, NgpackManifest } from './ngpack.js'

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
  hasTarball: boolean
  // No capture-metadata.json, so 'unconfirmed' is this loader's default rather
  // than a recorded decision.
  labelAssumed: boolean
  captureReason?: string
  engineVersion?: string
  composition?: CaptureComposition
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
    labelAssumed: false,
    captureReason: meta.captureReason,
    engineVersion: meta.engineVersion,
    composition: meta.composition ?? compositionFromNotes(meta.notes),
    ...classifyContamination(meta.captureReason, false),
  }
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

  return (
    `corpus building since ${since}: ` +
    `${corpus.samples.length} captures, ${corpus.confirmedMalicious.length} confirmed`
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
