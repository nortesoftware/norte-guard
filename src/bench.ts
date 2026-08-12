// The benchmark is built first: without a number there is nothing to falsify.
//
// Two rules decide the rest. The malicious corpus is .ngpack snapshots on disk,
// never a list of names, because keyv@6.0.0 and the rest were purged from npm
// within two hours of publication. And recall is computed over
// confirmed_malicious samples only, so with none of them it is not calculable —
// which is not the same claim as 0%, and printing the second when the first is
// true would be the most misleading thing this file could do.

import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { inspect } from './inspect.js'
import { NgpackSource } from './ngpack.js'
import {
  loadCorpus,
  describeCorpusProgress,
  describeContamination,
  resolveReferences,
  KNOWN_ATTACK_REFERENCES,
  type CorpusSample,
  type LabeledCorpus,
  type ReferenceStatus,
} from './corpus.js'
import { formatRateWithCI, rateWithCI, pct, type RateWithCI } from './stats.js'
import { tallySignals, renderPartition, type SignalPartition, type SignalRef } from './signal-report.js'
import {
  loadLatestArtifact,
  engineVersion,
  cleanSampleAssumptions,
  type FpBenchArtifact,
  type FpBenchPackageResult,
} from './fp-bench-store.js'
import { computeFieldRecall, type FieldRecallReport } from './field-recall.js'
import type { InspectResult } from './types.js'

export interface CleanEntry {
  package: string
  version: string
  source: string
}

export interface SampleResult {
  package: string
  version: string
  ngpackPath?: string
  result: InspectResult | null
  error?: string
  // `prediction` collapses this to the binary the recall arithmetic needs.
  // INSUFFICIENT_HISTORY and PASS are the same non-detection and very different
  // events for whoever is waiting on the build, so the verdict is kept too.
  verdict: InspectResult['verdict'] | 'ERROR'
  prediction: 'BLOCK' | 'PASS'
  detected: boolean
}

export interface RecallReport {
  calculable: boolean
  // null, never 0, when there is nothing to measure.
  value: number | null
  confirmedInCorpus: number
  analyzed: number
  truePositives: number
  falseNegatives: number
  unreadable: number
  // Errors counted as misses, printed whenever it differs, so an unreadable
  // snapshot cannot quietly raise recall.
  conservativeValue: number | null
  statement: string
  detail: string
}

export interface FalsePositiveReport {
  source: 'fp-bench' | 'corpus-limpio-local' | 'no-medido'
  sourceDetail: string
  // BLOCK + WARN: findings about the package. The cost of adopting the gate.
  nonPass: number
  blocked: number
  warned: number
  // A coverage number since it stopped failing the build. Folding it into
  // no-PASS and hiding it are opposite errors, so it gets its own line.
  insufficientHistory: number
  n: number
  rate: RateWithCI | null
  unevaluatedRate: RateWithCI | null
  statement: string
  unevaluatedStatement: string | null
  breakdown: string | null
}

export interface BenchSummary {
  mode: 'gate' | 'audit'
  engineVersion: string
  corpus: {
    roots: string[]
    total: number
    confirmedMalicious: number
    confirmedBenign: number
    unconfirmed: number
    unlabeled: number
    contaminated: number
    contaminatedConfirmedMalicious: number
    since: string | null
    progress: string
    contamination: string | null
  }
  recall: RecallReport
  falsePositives: FalsePositiveReport
  references: {
    total: number
    withSnapshot: number
    missing: ReferenceStatus[]
  }
  bySignal: SignalPartition
  // Recall over packages npm removed after the collector had already scored
  // them. The label is the registry's, the verdict is the one issued before the
  // removal existed.
  fieldRecall: FieldRecallReport
  sampleResults: SampleResult[]
  assumptions: string[]
  survivorshipBias: string
}

// A smoke test at n=11. The number that means anything comes from fp-bench,
// which is why a saved run is preferred over this list below.
export const CLEAN_CORPUS: CleanEntry[] = [
  { package: 'lodash',   version: '4.17.21', source: 'npm-top-1000' },
  { package: 'chalk',    version: '5.3.0',   source: 'npm-top-1000' },
  { package: 'axios',    version: '1.6.0',   source: 'npm-top-1000' },
  { package: 'express',  version: '4.18.2',  source: 'npm-top-1000' },
  { package: 'react',    version: '18.2.0',  source: 'npm-top-1000' },

  // Legitimate install scripts — the packages a naive detector blocks first.
  { package: 'esbuild',        version: '0.20.0', source: 'legitimate-native' },
  { package: 'sharp',          version: '0.33.0', source: 'legitimate-native' },
  { package: 'better-sqlite3', version: '9.4.3',  source: 'legitimate-native' },

  // Small and irregular release histories, where the genome is thinnest and
  // false positives are hardest to avoid.
  { package: 'tslib',  version: '2.6.2', source: 'npm-long-tail' },
  { package: 'ms',     version: '2.1.3', source: 'npm-long-tail' },
  { package: 'semver', version: '7.6.0', source: 'npm-long-tail' },
]

export interface BenchOptions {
  mode?: 'gate' | 'audit'
  corpusRoots?: string[]
  cleanCorpus?: CleanEntry[]
  fpResultsDir?: string
  captureDir?: string
  offline?: boolean
  verbose?: boolean
}

export async function runBench(options: BenchOptions = {}): Promise<BenchSummary> {
  const mode = options.mode ?? 'gate'
  const clean = options.cleanCorpus ?? CLEAN_CORPUS
  const offline = options.offline ?? Boolean(process.env['NORTE_GUARD_OFFLINE'])

  const corpus = loadCorpus(options.corpusRoots)

  console.log(`\nnorte-guard bench, mode: ${mode}`)
  console.log(`Corpus: ${corpus.roots.join(', ')}`)
  console.log(
    `  ${corpus.samples.length} captures - ` +
    `${corpus.confirmedMalicious.length} confirmed_malicious - ` +
    `${corpus.confirmedBenign.length} confirmed_benign - ` +
    `${corpus.unconfirmed.length} unconfirmed` +
    (corpus.unlabeled > 0 ? ` (${corpus.unlabeled} with no capture-metadata.json, unconfirmed by default)` : '')
  )

  const contamination = describeContamination(corpus)
  if (contamination) console.log(`  WARNING: ${contamination}`)
  console.log()

  const sampleResults = await analyzeConfirmedMalicious(corpus.confirmedMalicious, mode)
  const recall = buildRecallReport(corpus, sampleResults)

  const cleanResults = offline
    ? []
    : await analyzeCleanCorpus(clean, mode)

  const falsePositives = buildFalsePositiveReport({
    mode,
    cleanResults,
    cleanTotal: clean.length,
    offline,
    fpResultsDir: options.fpResultsDir,
  })

  // Detections only. A signal that fired on something the gate missed did not
  // carry the number, and crediting it would misattribute the recall.
  const bySignal = tallySignals(
    sampleResults
      .filter(r => r.detected && r.result)
      .map(r => r.result!.signals.map(s => ({ type: s.type, score: s.score }) as SignalRef))
  )

  const references = resolveReferences(corpus, KNOWN_ATTACK_REFERENCES)

  const summary: BenchSummary = {
    mode,
    engineVersion: engineVersion(),
    corpus: {
      roots: corpus.roots,
      total: corpus.samples.length,
      confirmedMalicious: corpus.confirmedMalicious.length,
      confirmedBenign: corpus.confirmedBenign.length,
      unconfirmed: corpus.unconfirmed.length,
      unlabeled: corpus.unlabeled,
      contaminated: corpus.contaminated.length,
      contaminatedConfirmedMalicious: corpus.confirmedMaliciousContaminated.length,
      since: corpus.firstCaptureAt,
      progress: describeCorpusProgress(corpus),
      contamination: describeContamination(corpus),
    },
    recall,
    falsePositives,
    references: {
      total: references.length,
      withSnapshot: references.filter(r => r.sample !== null).length,
      missing: references.filter(r => r.sample === null),
    },
    bySignal,
    fieldRecall: computeFieldRecall(options.captureDir ?? './norte-guard-captures'),
    sampleResults,
    assumptions: cleanSampleAssumptions(falsePositives.n),
    // In the object, not only printed, so the caveat survives being quoted.
    survivorshipBias:
      'NOTE: only attacks somebody detected publicly can be confirmed. Recall against ' +
      'undetected attacks is unknown and not estimable from this corpus, so any number ' +
      'out of it is a ceiling, not a coverage figure.',
  }

  renderBenchSummary(summary)
  return summary
}

// Each sample reads from its own .ngpack, which is what keeps a purged version
// analysable and the verdict reproducible.
async function analyzeConfirmedMalicious(
  samples: CorpusSample[],
  mode: 'gate' | 'audit'
): Promise<SampleResult[]> {
  if (samples.length === 0) return []

  const results: SampleResult[] = []

  for (const sample of samples) {
    process.stdout.write(`  Analysing ${sample.package}@${sample.version} [.ngpack]... `)
    try {
      const source = new NgpackSource(sample.ngpackPath)
      const result = await inspect(`${sample.package}@${sample.version}`, { mode, source })
      const prediction = result.verdict === 'BLOCK' ? 'BLOCK' : 'PASS'

      results.push({
        package: sample.package,
        version: sample.version,
        ngpackPath: sample.ngpackPath,
        result,
        verdict: result.verdict,
        prediction,
        detected: prediction === 'BLOCK',
      })
      console.log(prediction === 'BLOCK' ? 'detected' : `missed (score ${result.totalScore}, ${result.verdict})`)
    } catch (e) {
      // A snapshot that cannot be read is a corpus defect, not a detector miss.
      // Both readings are reported below rather than chosen between here.
      results.push({
        package: sample.package,
        version: sample.version,
        ngpackPath: sample.ngpackPath,
        result: null,
        error: String(e),
        verdict: 'ERROR',
        prediction: 'PASS',
        detected: false,
      })
      console.log(`UNREADABLE: ${e}`)
    }
  }

  console.log()
  return results
}

async function analyzeCleanCorpus(
  clean: CleanEntry[],
  mode: 'gate' | 'audit'
): Promise<SampleResult[]> {
  const results: SampleResult[] = []

  for (const entry of clean) {
    process.stdout.write(`  Analysing ${entry.package}@${entry.version} [${entry.source}]... `)
    try {
      const result = await inspect(`${entry.package}@${entry.version}`, { mode })
      const prediction = result.verdict === 'BLOCK' ? 'BLOCK' : 'PASS'

      results.push({
        package: entry.package,
        version: entry.version,
        result,
        verdict: result.verdict,
        prediction,
        detected: prediction === 'BLOCK',
      })
      console.log(
        result.verdict === 'PASS' ? 'pass'
        : result.verdict === 'BLOCK' ? `FALSE POSITIVE (score ${result.totalScore})`
        : `NON-PASS: ${result.verdict} (score ${result.totalScore})`
      )
    } catch (e) {
      // Never judged, so it must not enter the denominator either way.
      results.push({
        package: entry.package,
        version: entry.version,
        result: null,
        error: String(e),
        verdict: 'ERROR',
        prediction: 'PASS',
        detected: false,
      })
      console.log(`SKIPPED: ${e}`)
    }
  }

  console.log()
  return results
}

export function buildRecallReport(
  corpus: LabeledCorpus,
  results: SampleResult[]
): RecallReport {
  const confirmed = corpus.confirmedMalicious.length
  const unreadable = results.filter(r => r.error).length
  const analyzed = results.length - unreadable
  const tp = results.filter(r => r.detected).length
  const fn = analyzed - tp

  if (confirmed === 0) {
    return {
      calculable: false,
      value: null,
      confirmedInCorpus: 0,
      analyzed: 0,
      truePositives: 0,
      falseNegatives: 0,
      unreadable: 0,
      conservativeValue: null,
      // The line that must never read "0%".
      statement: 'not calculable, 0 confirmed_malicious samples',
      detail: describeCorpusProgress(corpus),
    }
  }

  if (analyzed === 0) {
    return {
      calculable: false,
      value: null,
      confirmedInCorpus: confirmed,
      analyzed: 0,
      truePositives: 0,
      falseNegatives: 0,
      unreadable,
      conservativeValue: null,
      statement: `not calculable: ${confirmed} confirmed, none readable`,
      detail: `${unreadable} unreadable .ngpack files: the corpus is broken, not the detector`,
    }
  }

  return {
    calculable: true,
    value: tp / analyzed,
    confirmedInCorpus: confirmed,
    analyzed,
    truePositives: tp,
    falseNegatives: fn,
    unreadable,
    conservativeValue: tp / (analyzed + unreadable),
    statement: `${formatRateWithCI(tp, analyzed)} - ${tp}/${analyzed} confirmed_malicious`,
    detail: describeCorpusProgress(corpus),
  }
}

// Prefers a saved fp-bench run over the smoke corpus: n=11 gives a Wilson
// interval of roughly 0%–26%, which is true and useless.
export function buildFalsePositiveReport(input: {
  mode: 'gate' | 'audit'
  cleanResults: SampleResult[]
  cleanTotal: number
  offline: boolean
  fpResultsDir?: string
}): FalsePositiveReport {
  const latest = loadLatestArtifact(input.fpResultsDir)

  if (latest) {
    // Counted from the per-package verdicts so artifacts saved before these
    // rates existed still produce the right number.
    const counts = countVerdicts(latest.artifact, input.mode)

    return {
      source: 'fp-bench',
      sourceDetail:
        `${latest.path} (sampling: ${latest.artifact.sampling.mode}, engine v${latest.artifact.engineVersion})`,
      nonPass: counts.nonPass,
      blocked: counts.blocked,
      warned: counts.warned,
      insufficientHistory: counts.insufficientHistory,
      n: counts.n,
      rate: rateWithCI(counts.nonPass, counts.n),
      unevaluatedRate: rateWithCI(counts.insufficientHistory, counts.n),
      statement: formatRateWithCI(counts.nonPass, counts.n),
      unevaluatedStatement: formatRateWithCI(counts.insufficientHistory, counts.n),
      breakdown:
        `BLOCK ${counts.blocked} (${pct(counts.blocked / (counts.n || 1))}, exit 1) - ` +
        `WARN ${counts.warned} (${pct(counts.warned / (counts.n || 1))}, exit 0)`,
    }
  }

  if (input.offline) {
    return {
      source: 'no-medido',
      sourceDetail: 'offline and no fp-bench-results/: nothing was measured',
      nonPass: 0, blocked: 0, warned: 0, insufficientHistory: 0,
      n: 0,
      rate: null,
      unevaluatedRate: null,
      statement: 'not measured. Run `npm run fp-bench` (offline: no network and no saved runs)',
      unevaluatedStatement: null,
      breakdown: null,
    }
  }

  const judged = input.cleanResults.filter(r => !r.error)
  const blocked = judged.filter(r => r.verdict === 'BLOCK').length
  const warned = judged.filter(r => r.verdict === 'WARN').length
  const insufficient = judged.filter(r => r.verdict === 'INSUFFICIENT_HISTORY').length

  return {
    source: 'corpus-limpio-local',
    sourceDetail:
      `local clean corpus, ${judged.length}/${input.cleanTotal} reachable. ` +
      'n is low: use fp-bench for a comparable number',
    nonPass: blocked + warned, blocked, warned, insufficientHistory: insufficient,
    n: judged.length,
    rate: rateWithCI(blocked + warned, judged.length),
    unevaluatedRate: rateWithCI(insufficient, judged.length),
    statement: formatRateWithCI(blocked + warned, judged.length),
    unevaluatedStatement: formatRateWithCI(insufficient, judged.length),
    breakdown: `BLOCK ${blocked} (exit 1) - WARN ${warned} (exit 0)`,
  }
}

function countVerdicts(artifact: FpBenchArtifact, mode: 'gate' | 'audit') {
  const usable = artifact.packages.filter(p => !p.error)
  const verdictOf = (p: FpBenchPackageResult) => (mode === 'gate' ? p.gate : p.audit).verdict

  const n = usable.length
  const passed = usable.filter(p => verdictOf(p) === 'PASS').length
  const blocked = usable.filter(p => verdictOf(p) === 'BLOCK').length
  const warned = usable.filter(p => verdictOf(p) === 'WARN').length

  return {
    n,
    passed,
    // BLOCK + WARN, not "everything that is not PASS". Folding
    // INSUFFICIENT_HISTORY in here would report a coverage gap as a
    // false-positive rate; it is returned separately instead.
    nonPass: blocked + warned,
    blocked,
    warned,
    insufficientHistory: usable.filter(p => verdictOf(p) === 'INSUFFICIENT_HISTORY').length,
  }
}

const BOLD  = '\x1b[1m'
const GREEN = '\x1b[32m'
const RED   = '\x1b[31m'
const CYAN  = '\x1b[36m'
const YELLOW = '\x1b[33m'
const DIM   = '\x1b[2m'
const RESET = '\x1b[0m'

// Fixed width so the headline numbers and their qualifiers line up. A recall
// that cannot be computed still occupies its row: hiding it would read as if it
// had not been asked for.
const LABEL_WIDTH = 14
const INDENT = ' '.repeat(LABEL_WIDTH)

// Kept apart from the .ngpack recall above because the two rest on different
// evidence: this one has npm's verdict and the score the collector issued before
// it, and no artifact.
function renderFieldRecall(f: FieldRecallReport): void {
  if (f.takedownsFound === 0 && f.preTakedownObservations === 0) return

  const color = f.calculable ? GREEN : YELLOW
  console.log(
    `${color}${'Field recall'.padEnd(LABEL_WIDTH)}${f.calculable ? f.statement : f.statement}${RESET}`
  )
  // Reported on its own line because it answers a different question from
  // recall: whether the collector is there in time at all.
  const cov = f.takedownCoverage
  console.log(
    `${CYAN}${'Coverage'.padEnd(LABEL_WIDTH)}` +
    `${cov?.rate != null ? formatRateWithCI(f.preTakedownObservations, f.takedownsFound) : 'not calculable'}` +
    ` of removals were observed beforehand${RESET}`
  )
  console.log(
    `${INDENT}${DIM}${f.takedownsFound} removed by npm - ` +
    `${f.preTakedownObservations} observed beforehand - ` +
    `${f.scored.length} scored at publication${RESET}`
  )

  for (const sample of f.scored) {
    const mark = sample.gateBlocked ? '[blocked]' : '[missed] '
    console.log(
      `${INDENT}${mark} ${`${sample.package}@${sample.version}`.padEnd(38)} ` +
      `score=${String(sample.score).padStart(3)} ${DIM}${sample.regime}, audit ${sample.auditVerdict}${RESET}`
    )
  }
  for (const sample of f.unscored) {
    console.log(
      `${INDENT}[unscored] ${`${sample.package}@${sample.version}`.padEnd(38)} ` +
      `${DIM}observed without a score: cannot be graded${RESET}`
    )
  }
}

function renderBenchSummary(s: BenchSummary): void {
  console.log('-'.repeat(66))
  console.log(`${BOLD}BENCHMARK  norte-guard v${s.engineVersion}  mode: ${s.mode}${RESET}`)
  console.log('-'.repeat(66))

  // Two lines, never one: no-PASS is what the gate says about packages, sin
  // evaluar is what it cannot say anything about. Different failures, fixed by
  // different work.
  const fpColor = s.falsePositives.rate?.rate != null && s.falsePositives.rate.rate > 0.05 ? RED : GREEN
  console.log(`${fpColor}${`non-PASS ${s.mode}`.padEnd(LABEL_WIDTH)}${s.falsePositives.statement}${RESET}`)
  if (s.falsePositives.breakdown) {
    console.log(`${INDENT}${DIM}${s.falsePositives.breakdown}${RESET}`)
  }
  if (s.falsePositives.unevaluatedStatement) {
    console.log(`${CYAN}${'unevaluated'.padEnd(LABEL_WIDTH)}${s.falsePositives.unevaluatedStatement}${RESET}`)
    console.log(`${INDENT}${DIM}INSUFFICIENT_HISTORY: informational, exit 0, does not fail the build${RESET}`)
  }
  console.log(`${INDENT}${DIM}source: ${s.falsePositives.sourceDetail}${RESET}`)

  const recallColor = s.recall.calculable ? GREEN : YELLOW
  console.log(`${recallColor}${'Recall'.padEnd(LABEL_WIDTH)}${s.recall.statement}${RESET}`)
  console.log(`${INDENT}${DIM}${s.recall.detail}${RESET}`)

  if (s.corpus.contamination) {
    console.log(`${INDENT}${YELLOW}${s.corpus.contamination}${RESET}`)
  }

  if (s.recall.unreadable > 0 && s.recall.conservativeValue !== null) {
    console.log(
      `${INDENT}${RED}${s.recall.unreadable} unreadable snapshots excluded. ` +
      `Counting them as misses: ${pct(s.recall.conservativeValue)}${RESET}`
    )
  }

  renderFieldRecall(s.fieldRecall)

  console.log('-'.repeat(66))

  console.log(`\n${BOLD}Signal attribution, detections only${RESET}`)
  if (s.bySignal.positive.length === 0 &&
      s.bySignal.negative.length === 0 &&
      s.bySignal.informational.length === 0) {
    console.log(`  ${DIM}(no detections to attribute)${RESET}`)
  } else {
    for (const line of renderPartition(s.bySignal, '  ')) console.log(line)
  }

  console.log(`\n${BOLD}Known public attacks with no snapshot${RESET}`)
  console.log(
    `  ${s.references.withSnapshot}/${s.references.total} have an .ngpack. ` +
    `The rest count as neither hit nor miss: they cannot be analysed.`
  )
  for (const ref of s.references.missing) {
    console.log(
      `  ${DIM}  ${`${ref.package}@${ref.version}`.padEnd(38)} ${ref.campaign} ` +
      `(${ref.source})${ref.note ? `: ${ref.note}` : ''}${RESET}`
    )
  }

  console.log(`\n${BOLD}Declared assumptions${RESET}`)
  for (const a of s.assumptions) console.log(`  ${DIM}${a}${RESET}`)
  console.log(`  ${DIM}${s.survivorshipBias}${RESET}`)
  console.log()
}

// Without this `npm run bench` exits silently having measured nothing, which
// reads exactly like a benchmark that found no problems.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const mode = process.argv.includes('--mode=audit') ? 'audit' : 'gate'

  runBench({
    mode,
    offline: process.argv.includes('--offline') || Boolean(process.env['NORTE_GUARD_OFFLINE']),
    verbose: process.argv.includes('--verbose'),
  }).catch(e => {
    console.error(e)
    process.exit(2)
  })
}
