// Running the reach measurement over the corpus on disk.
//
// Kept apart from analyzability.ts so that file stays pure: bytes in, verdict
// out, no filesystem and no corpus loader. This one knows where the captures
// live and how long a full pass takes.

import { NgpackSource } from './ngpack.js'
import { loadCorpus, type CorpusSample } from './corpus.js'
import { readTar, DEFAULT_TAR_LIMITS, type TarLimits } from './tarball.js'
import { rateWithCI, type RateWithCI } from './stats.js'
import {
  analyzeFile,
  summariseFiles,
  packageTypeOf,
  NON_COVERAGE_REASONS,
  type CaptureAnalyzability,
  type FileAnalysis,
  type KindTotals,
  type LegibilityMetrics,
  type LegibilityThreshold,
  type NonCoverageReason,
} from './analyzability.js'
import type { FileKind } from './file-kind.js'

export interface AnalyzeCaptureOptions {
  threshold?: LegibilityThreshold
  limits?: TarLimits
  // Files kept on the result. A full corpus pass holds tens of thousands of
  // captures at once and the per-file list is the bulk of it; the aggregate does
  // not need them and a single-capture inspection does.
  keepFiles?: boolean
}

export function analyzeCapture(
  sample: CorpusSample,
  options: AnalyzeCaptureOptions = {}
): CaptureAnalyzability {
  const base = {
    package: sample.package,
    version: sample.version,
    capturedAt: sample.capturedAt,
    ngpackPath: sample.ngpackPath,
    label: sample.label,
  }

  const empty = (error: string): CaptureAnalyzability => ({
    ...base,
    executableBytes: 0, executableFiles: 0, coveredBytes: 0, coveredFiles: 0,
    coverage: null, byReason: {}, heldOut: {}, files: [], error,
  })

  const tarball = readTarballOf(sample)
  if (typeof tarball === 'string') return empty(tarball)

  const archive = readTar(tarball, options.limits ?? DEFAULT_TAR_LIMITS)
  if (archive.truncated && archive.entries.length === 0) {
    return empty(`archive unreadable: ${archive.truncationReason}`)
  }

  const packageType = packageTypeOf(archive.entries)

  const files: FileAnalysis[] = archive.entries.map(entry =>
    analyzeFile({
      name: entry.name,
      data: entry.data,
      packageType,
      threshold: options.threshold,
    })
  )

  // A member the reader refused is a member nobody analysed, and it is counted
  // as exactly that rather than dropped: this whole file exists because
  // unlooked-at code was being reported as clean.
  for (const skipped of archive.skipped) {
    files.push({
      name: skipped.name,
      bytes: skipped.size,
      kind: 'other',
      classifiedBy: 'skipped by the tar reader',
      covered: false,
      reasons: ['too-large'],
    })
  }

  const summary = summariseFiles(files)

  return {
    ...base,
    ...summary,
    files: options.keepFiles ? files : [],
    error: archive.truncated ? `archive truncated: ${archive.truncationReason}` : undefined,
  }
}

// The tarball, or the sentence explaining why there isn't one. A string return
// is the error case on purpose: every one of these is a corpus defect that has
// to land outside the coverage denominator, and a thrown exception here would
// have to be caught and re-described by every caller.
function readTarballOf(sample: CorpusSample): Buffer | string {
  let source: NgpackSource
  try {
    source = new NgpackSource(sample.ngpackPath)
  } catch (e) {
    return `unreadable snapshot: ${e instanceof Error ? e.message : String(e)}`
  }

  const version = sample.version || source.manifest.versionsIncluded[0] || ''
  if (source.missingTarballs.includes(version)) {
    // The bytes were captured and are gone from the shared store. A snapshot
    // with less in it than it once had, not a package with nothing to read.
    return 'tarball bytes are no longer in the object store'
  }

  return source.tarballSync(version) ?? source.tarballSync() ?? 'no tarball in the snapshot'
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

export interface ReasonPrevalence {
  reason: NonCoverageReason
  // Captures with at least one file carrying this reason. The headline
  // prevalence: "what fraction of packages ship one of these at all".
  captures: number
  captureRate: RateWithCI
  files: number
  bytes: number
}

export interface CoverageBucket {
  label: string
  captures: number
}

export interface CorpusAnalyzability {
  ranAt: string
  engineVersion: string
  threshold: LegibilityThreshold
  // Captures the pass looked at, and the ones it could not open.
  analysed: number
  unreadable: number
  // Captures excluded before the pass began because their bytes are gone. Not a
  // coverage figure and never folded into one: it is a fact about the corpus,
  // and it is the largest single fact about this one.
  withoutBytes: number
  corpusTotal: number
  // The same fact for the confirmed samples specifically, because "1 of 2 fully
  // analysable" is a sentence somebody quotes and 6 of the 8 are not in the 2.
  confirmedWithoutBytes: number
  confirmedTotal: number
  // With nothing executable in them at all. Held apart from 0% coverage.
  nothingExecutable: number
  totalExecutableBytes: number
  totalCoveredBytes: number
  // Two coverage figures, because they answer different questions and a single
  // one gets quoted for both. Byte coverage is dominated by a handful of
  // enormous binaries; capture coverage is one vote per package.
  byteCoverage: number | null
  medianCaptureCoverage: number | null
  fullyCovered: number
  fullyOpaque: number
  distribution: CoverageBucket[]
  reasons: ReasonPrevalence[]
  heldOut: Partial<Record<FileKind, KindTotals>>
  // The two questions this run exists to answer, computed rather than left to
  // the reader.
  shipsOpaqueExecutable: RateWithCI
  confirmedMalicious: CaptureAnalyzability[]
}

export interface RunOptions {
  roots?: string[]
  threshold: LegibilityThreshold
  // A full pass over 4,800 captures and 2GB of gzip is minutes, not seconds.
  // A sample makes the run practical; the confirmed_malicious captures are
  // always analysed whatever the sample says, because one of the two questions
  // asked is specifically about them and eight samples cost nothing.
  sample?: number
  limits?: TarLimits
  onProgress?: (done: number, total: number) => void
  engineVersion: string
  now?: () => string
}

export function runCorpusAnalyzability(options: RunOptions): CorpusAnalyzability {
  const corpus = loadCorpus(options.roots)

  // Contaminated captures are held out of every benchmark by policy and this is
  // a benchmark. Letting them in would put samples the recall denominator
  // refuses into the coverage denominator.
  // tarballPresent, not hasTarball: the second says the manifest declared a
  // version and two thirds of this corpus declares one it no longer holds.
  const uncontaminated = corpus.samples.filter(s => !s.contaminated)
  const usable = uncontaminated.filter(s => s.tarballPresent)
  const allConfirmed = uncontaminated.filter(s => s.label === 'confirmed_malicious')
  const confirmed = usable.filter(s => s.label === 'confirmed_malicious')

  const selected = options.sample && options.sample < usable.length
    ? stratifiedSample(usable, options.sample, confirmed)
    : usable

  const results: CaptureAnalyzability[] = []
  let done = 0
  for (const sample of selected) {
    results.push(analyzeCapture(sample, {
      threshold: options.threshold,
      limits: options.limits,
      keepFiles: false,
    }))
    done++
    options.onProgress?.(done, selected.length)
  }

  return summariseCorpus(results, {
    threshold: options.threshold,
    engineVersion: options.engineVersion,
    ranAt: options.now ? options.now() : new Date().toISOString(),
    confirmedPackages: new Set(confirmed.map(c => `${c.package}@${c.version}`)),
    withoutBytes: uncontaminated.length - usable.length,
    corpusTotal: uncontaminated.length,
    confirmedWithoutBytes: allConfirmed.length - confirmed.length,
    confirmedTotal: allConfirmed.length,
  })
}

// Every confirmed sample, then a deterministic spread over the rest. Not random:
// a run that cannot be reproduced cannot be compared against the next one, and
// comparison is the only reason to save an artifact.
export function stratifiedSample(
  all: CorpusSample[],
  size: number,
  always: CorpusSample[]
): CorpusSample[] {
  const forced = new Set(always.map(s => s.ngpackPath))
  const rest = all.filter(s => !forced.has(s.ngpackPath))
  const room = Math.max(0, size - forced.size)

  if (room >= rest.length) return [...always, ...rest]

  const step = rest.length / room
  const picked: CorpusSample[] = []
  for (let i = 0; i < room; i++) picked.push(rest[Math.floor(i * step)]!)

  return [...always, ...picked]
}

export function summariseCorpus(
  results: CaptureAnalyzability[],
  meta: {
    threshold: LegibilityThreshold
    engineVersion: string
    ranAt: string
    confirmedPackages: Set<string>
    withoutBytes?: number
    corpusTotal?: number
    confirmedWithoutBytes?: number
    confirmedTotal?: number
  }
): CorpusAnalyzability {
  const unreadable = results.filter(r => r.error && r.executableFiles === 0).length
  const readable = results.filter(r => !(r.error && r.executableFiles === 0))
  const nothingExecutable = readable.filter(r => r.coverage === null).length
  const scored = readable.filter(r => r.coverage !== null)

  const totalExecutableBytes = scored.reduce((s, r) => s + r.executableBytes, 0)
  const totalCoveredBytes = scored.reduce((s, r) => s + r.coveredBytes, 0)

  const coverages = scored.map(r => r.coverage!).sort((a, b) => a - b)

  const buckets: CoverageBucket[] = [
    { label: '0%', captures: coverages.filter(c => c === 0).length },
    { label: '0-50%', captures: coverages.filter(c => c > 0 && c < 0.5).length },
    { label: '50-90%', captures: coverages.filter(c => c >= 0.5 && c < 0.9).length },
    { label: '90-99.9%', captures: coverages.filter(c => c >= 0.9 && c < 0.999).length },
    { label: '100%', captures: coverages.filter(c => c >= 0.999).length },
  ]

  const reasons: ReasonPrevalence[] = NON_COVERAGE_REASONS.map(reason => {
    const withIt = readable.filter(r => r.byReason[reason])
    return {
      reason,
      captures: withIt.length,
      captureRate: rateWithCI(withIt.length, readable.length),
      files: withIt.reduce((s, r) => s + (r.byReason[reason]?.files ?? 0), 0),
      bytes: withIt.reduce((s, r) => s + (r.byReason[reason]?.bytes ?? 0), 0),
    }
  }).sort((a, b) => b.captures - a.captures)

  const heldOut: Partial<Record<FileKind, KindTotals>> = {}
  for (const r of readable) {
    for (const [kind, totals] of Object.entries(r.heldOut) as Array<[FileKind, KindTotals]>) {
      const entry = heldOut[kind] ?? { files: 0, bytes: 0 }
      entry.files += totals.files
      entry.bytes += totals.bytes
      heldOut[kind] = entry
    }
  }

  // The question as asked: what fraction of new npm packages ship a binary, WASM
  // or unreadable minified code. One capture counts once however many such files
  // it holds.
  const opaqueKinds: NonCoverageReason[] = ['native-binary', 'wasm', 'bytecode', 'minified']
  const withOpaque = readable.filter(r => opaqueKinds.some(k => r.byReason[k])).length

  return {
    ranAt: meta.ranAt,
    engineVersion: meta.engineVersion,
    threshold: meta.threshold,
    analysed: results.length,
    unreadable,
    withoutBytes: meta.withoutBytes ?? 0,
    corpusTotal: meta.corpusTotal ?? results.length,
    confirmedWithoutBytes: meta.confirmedWithoutBytes ?? 0,
    confirmedTotal: meta.confirmedTotal ?? meta.confirmedPackages.size,
    nothingExecutable,
    totalExecutableBytes,
    totalCoveredBytes,
    byteCoverage: totalExecutableBytes > 0 ? totalCoveredBytes / totalExecutableBytes : null,
    medianCaptureCoverage: coverages.length > 0
      ? coverages[Math.floor(coverages.length / 2)]!
      : null,
    fullyCovered: coverages.filter(c => c >= 0.999).length,
    fullyOpaque: coverages.filter(c => c === 0).length,
    distribution: buckets,
    reasons,
    heldOut,
    shipsOpaqueExecutable: rateWithCI(withOpaque, readable.length),
    confirmedMalicious: results.filter(r =>
      meta.confirmedPackages.has(`${r.package}@${r.version}`)
    ),
  }
}

// ---------------------------------------------------------------------------
// Deriving the threshold
// ---------------------------------------------------------------------------

export interface MetricRow {
  package: string
  file: string
  bytes: number
  bytesPerLine: number
  maxLineLength: number
  bytesPerNode: number
  meanIdentifierLength: number
  shortIdentifierRatio: number
  // Self-labelled: a file named *.min.js, or one carrying a sourceMappingURL,
  // says what it is without anybody deciding. This is the only ground truth
  // available at this scale and its bias is stated where it is used.
  selfLabelledMinified: boolean
}

export function selfLabelledMinified(name: string, source: string): boolean {
  if (/\.min\.[cm]?js$/i.test(name)) return true
  // A build that emitted a source map emitted it because the output is not meant
  // to be read. The marker is at the end of the file by convention.
  return /\/\/[#@]\s*sourceMappingURL=/.test(source.slice(-2048))
}

// Every parsed JavaScript file in the sampled captures, with every candidate
// metric. This is what the threshold is derived from, and it is a separate mode
// rather than a side effect of the main run so the derivation can be re-done
// against a fresh corpus without re-deciding anything else.
export function collectMetrics(options: {
  roots?: string[]
  sample: number
  limits?: TarLimits
  onProgress?: (done: number, total: number) => void
}): MetricRow[] {
  const corpus = loadCorpus(options.roots)
  const usable = corpus.samples.filter(s => !s.contaminated && s.tarballPresent)
  const confirmed = usable.filter(s => s.label === 'confirmed_malicious')
  const selected = options.sample < usable.length
    ? stratifiedSample(usable, options.sample, confirmed)
    : usable

  const rows: MetricRow[] = []
  let done = 0

  for (const sample of selected) {
    done++
    options.onProgress?.(done, selected.length)

    const tarball = readTarballOf(sample)
    if (typeof tarball === 'string') continue

    const archive = readTar(tarball, options.limits ?? DEFAULT_TAR_LIMITS)
    const packageType = packageTypeOf(archive.entries)

    for (const entry of archive.entries) {
      const analysis = analyzeFile({ name: entry.name, data: entry.data, packageType })
      if (!analysis.metrics) continue

      rows.push({
        package: sample.package,
        file: entry.name,
        bytes: analysis.metrics.bytes,
        bytesPerLine: analysis.metrics.bytesPerLine,
        maxLineLength: analysis.metrics.maxLineLength,
        bytesPerNode: analysis.metrics.bytesPerNode,
        meanIdentifierLength: analysis.metrics.meanIdentifierLength,
        shortIdentifierRatio: analysis.metrics.shortIdentifierRatio,
        selfLabelledMinified: selfLabelledMinified(entry.name, entry.data.toString('utf-8')),
      })
    }
  }

  return rows
}

// How well a candidate cut separates the self-labelled set from everything else.
//
// Reported as both error rates rather than as one accuracy number: for a REACH
// measurement the two are not interchangeable. A false positive marks readable
// code unreadable and understates coverage, which is the safe direction. A false
// negative marks minified code readable and overstates it, which is the failure
// this phase exists to prevent.
export interface ThresholdCheck {
  threshold: LegibilityThreshold
  labelled: number
  unlabelled: number
  // Self-labelled minified files the cut catches.
  truePositiveRate: number | null
  // Files with no minified label that the cut catches anyway. Some of these are
  // genuinely minified and simply unlabelled, so this is an upper bound on the
  // error and not a measurement of it.
  falsePositiveRate: number | null
}

export function checkThreshold(rows: MetricRow[], threshold: LegibilityThreshold): ThresholdCheck {
  const hits = (r: MetricRow) =>
    r.bytesPerLine >= threshold.bytesPerLine &&
    r.shortIdentifierRatio >= threshold.shortIdentifierRatio

  const labelled = rows.filter(r => r.selfLabelledMinified)
  const unlabelled = rows.filter(r => !r.selfLabelledMinified)

  return {
    threshold,
    labelled: labelled.length,
    unlabelled: unlabelled.length,
    truePositiveRate: labelled.length > 0 ? labelled.filter(hits).length / labelled.length : null,
    falsePositiveRate: unlabelled.length > 0 ? unlabelled.filter(hits).length / unlabelled.length : null,
  }
}
