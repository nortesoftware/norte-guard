// Every fp-bench run is written to disk before anything is printed, because
// calibration is a sequence of deltas and a delta needs the previous run to
// still exist. The file carries the keyword pool, sample size, engine version
// and thresholds alongside the results: a rate measured with different keywords,
// a different n or different thresholds is a different measurement, not a
// movement.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ThresholdConfig } from './types.js'
import type { SignalRef } from './signal-report.js'
import type { ScoreDistribution } from './stats.js'

export const FP_BENCH_RESULTS_DIR = 'fp-bench-results'

export interface FpBenchPackageResult {
  package: string
  downloads: number
  // 1 = most downloaded. Absent in --top mode, where the sample is the head of
  // the distribution by construction.
  decile?: number
  gate: ModeResult
  audit: ModeResult
  // The conjunction, evaluated on every package whether or not the rule was
  // switched on. Kept in the artifact rather than only printed: a run saved
  // before the rule went default-on cannot be told apart from one saved after
  // unless the file carries both the config it ran under and what the rule saw.
  fabricatedProfile?: {
    matches: boolean
    localConjuncts: boolean
    conjuncts: Record<string, boolean>
  }
  error?: string
}

export interface ModeResult {
  verdict: string
  score: number
  regime: string
  signals: SignalRef[]
}

export interface DecileResult {
  decile: number
  n: number
  blocked: number
  rate: number | null
  low: number | null
  high: number | null
  minDownloads: number
  maxDownloads: number
}

export interface FpBenchArtifact {
  schema: 1
  generatedAt: string
  engineVersion: string
  sampling: {
    mode: 'top' | 'stratified'
    harvestQueries: string[]
    poolSize: number
    // The difference against poolSize is what was dropped rather than ranked at
    // zero.
    measuredPoolSize?: number
    unresolvedDownloads?: number
    top?: number
    perDecile?: number
    n: number
  }
  thresholds: Record<'gate' | 'audit', ThresholdConfig>
  rates: Record<'gate' | 'audit', {
    blocked: number
    warned?: number
    insufficientHistory?: number
    passed?: number
    // BLOCK + WARN. INSUFFICIENT_HISTORY is counted separately in `unevaluated`:
    // it no longer fails the build, so it is coverage rather than usability.
    nonPass?: number
    unevaluated?: number
    n: number
    rate: number | null
    low: number | null
    high: number | null
    nonPassRate?: number | null
    nonPassLow?: number | null
    nonPassHigh?: number | null
  }>
  byDecile?: Record<'gate' | 'audit', DecileResult[]>
  scoreDistribution?: Record<'gate' | 'audit', {
    noGenome: ScoreDistribution | null
    genome: ScoreDistribution | null
    all: ScoreDistribution | null
  }>
  proposedThresholds?: {
    captureFromNoGenomeP99: number | null
  }
  bySignal: Record<'gate' | 'audit', {
    amongBlocked: Record<string, { count: number; totalScore: number }>
    overall: Record<string, { count: number; totalScore: number }>
  }>
  regimes: Record<'gate' | 'audit', Record<string, Record<string, number>>>
  // Watched conditions that are not errors, such as a BLOCK rate of zero.
  alerts?: string[]
  assumptions: string[]
  packages: FpBenchPackageResult[]
}

export function engineVersion(): string {
  try {
    const raw = readFileSync(new URL('../package.json', import.meta.url), 'utf-8')
    return (JSON.parse(raw) as { version?: string }).version ?? '0.0.0'
  } catch {
    return '0.0.0'
  }
}

// Suffixed when a day holds more than one run: overwriting would destroy the
// baseline of the comparison being made.
export function artifactPath(artifact: FpBenchArtifact, dir = FP_BENCH_RESULTS_DIR): string {
  const date = artifact.generatedAt.slice(0, 10)
  const base = `${date}-v${artifact.engineVersion}`

  let candidate = join(dir, `${base}.json`)
  for (let i = 2; existsSync(candidate); i++) {
    candidate = join(dir, `${base}-${i}.json`)
  }
  return candidate
}

export function saveArtifact(artifact: FpBenchArtifact, dir = FP_BENCH_RESULTS_DIR): string {
  mkdirSync(dir, { recursive: true })
  const path = artifactPath(artifact, dir)
  writeFileSync(path, JSON.stringify(artifact, null, 2))
  return path
}

export interface LoadedArtifact {
  path: string
  artifact: FpBenchArtifact
}

export function loadArtifacts(dir = FP_BENCH_RESULTS_DIR): LoadedArtifact[] {
  if (!existsSync(dir)) return []

  const loaded: LoadedArtifact[] = []
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue
    try {
      const artifact = JSON.parse(readFileSync(join(dir, name), 'utf-8')) as FpBenchArtifact
      if (artifact.schema !== 1) continue
      loaded.push({ path: join(dir, name), artifact })
    } catch {
      // A corrupt artifact is not a reason to lose the rest of the history.
    }
  }

  return loaded.sort((a, b) => b.artifact.generatedAt.localeCompare(a.artifact.generatedAt))
}

// There was a loadLatestArtifact() here and its removal is the point. "Newest
// wins" is a selection rule that cannot see whether the run it picks measured
// the engine asking, and it picked an ablation run saved an hour after the one
// that matched. Callers take the sorted list and choose on the config they need;
// bench.ts does exactly that.

// In the artifact rather than only printed, so the caveat cannot be dropped when
// the number is quoted elsewhere.
export function cleanSampleAssumptions(n: number): string[] {
  if (n === 0) {
    return ['No clean package was analysed in this run: there is no false-positive rate to declare.']
  }
  return [
    `The ${n} packages analysed are assumed clean. Not verified.`,
    'A compromised package inside the sample would count as a false positive while being a hit.',
    'The reported rate is therefore an upper bound on the error, not a measurement of it.',
  ]
}
