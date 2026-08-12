// False-positive benchmark against the packages people actually install.
//
// bench.ts measures recall on a corpus of confirmed attacks; this measures how
// often norte-guard flags something that was never malicious. A gate nobody can
// leave switched on has no recall, so the two modes are reported separately
// rather than averaged.
//
// Rates always carry their Wilson interval, since 2/500 and 20/5000 are the same
// point estimate and very different claims. Negative signals never appear among
// the causes of a BLOCK. And --stratified exists because the top of the download
// distribution is the best-maintained part of the ecosystem, while the false
// positives live in the tail.

import https from 'node:https'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { fetchPackument } from './packument.js'
import { buildGenomeFromPackument } from './genome.js'
import { scoreWithRegime } from './scorer.js'
import { DEFAULT_THRESHOLDS } from './types.js'
import { formatRateWithCI, rateWithCI, scoreDistribution, pct, type RateWithCI, type ScoreDistribution } from './stats.js'
import { tallySignals, renderPartition, reportBugs, type SignalRef } from './signal-report.js'
import { fabricatedProfile } from './fabricated-profile.js'
import {
  saveArtifact,
  engineVersion,
  cleanSampleAssumptions,
  type FpBenchArtifact,
  type FpBenchPackageResult,
  type DecileResult,
} from './fp-bench-store.js'

const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search'
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'

// npm's search API rejects an empty query, so there is no "global top N" call to
// make. The pool comes from broad keyword queries, then gets ranked by real
// weekly downloads. These keywords are the sampling bias, so they are printed
// with the results and saved into every artifact rather than buried here.
const HARVEST_QUERIES = [
  'keywords:javascript',
  'keywords:typescript',
  'keywords:nodejs',
  'keywords:react',
  'keywords:cli',
  'keywords:util',
  'keywords:testing',
  'keywords:build',
  'keywords:http',
  'keywords:css',
  'keywords:parser',
  'keywords:async',
]

const DECILES = 10

export interface ModeOutcome {
  verdict: string
  score: number
  regime: string
  signals: SignalRef[]
  versions: number
}

export interface FpBenchRow {
  package: string
  downloads: number
  decile?: number
  gate: ModeOutcome
  audit: ModeOutcome
  // Measured on every package whether or not the rule is switched on. Turning it
  // on without this number is what the measurement exists to prevent.
  fabricatedProfile?: {
    matches: boolean
    localConjuncts: boolean
    conjuncts: Record<string, boolean>
  }
  error?: string
}

export interface RegimeReport {
  // In gate mode every one of these must come back INSUFFICIENT_HISTORY.
  noGenome: number
  noGenomeByVerdict: Record<string, number>
  withGenome: number
  // ≤ 20 versions, so no long_history discount. Wider than no-genome: a package
  // with 15 versions over two years has a genome and legitimately passes.
  withoutLongHistory: number
  withoutLongHistoryByVerdict: Record<string, number>
  // Non-zero in gate mode is a broken gate, not a tuning issue.
  gateEscapes: number
}

export interface ModeSummary {
  mode: 'gate' | 'audit'
  analyzed: number
  blocked: number
  warned: number
  passed: number
  insufficientHistory: number
  blockRate: RateWithCI
  warnRate: RateWithCI
  insufficientRate: RateWithCI
  // BLOCK + WARN: findings about the package, and the number that decides
  // whether the gate can be left switched on in CI.
  nonPassRate: RateWithCI
  // The share of the ecosystem the tool cannot judge. Since it stopped failing
  // the build it is a coverage number rather than a usability one, but it does
  // not disappear: it keeps its own name and its own line.
  unevaluatedRate: RateWithCI
  // What actually exits non-zero, under the default (non-strict) policy.
  buildBreakingRate: RateWithCI
  regimes: RegimeReport
  byDecile: DecileResult[]
  // What clean packages actually score, split by regime, so a threshold can come
  // out of a measured distribution rather than a round number.
  scores: {
    noGenome: ScoreDistribution | null
    genome: ScoreDistribution | null
    all: ScoreDistribution | null
  }
}

function getJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'norte-guard-fp-bench/0.1.0',
      },
      timeout: 20_000,
    }, res => {
      if ((res.statusCode ?? 0) >= 400) {
        reject(new Error(`HTTP ${res.statusCode}: ${url}`))
        res.resume()
        return
      }
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8')))
        } catch (e) {
          reject(e)
        }
      })
      res.on('error', reject)
    })
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy()
      reject(new Error(`Timeout: ${url}`))
    })
  })
}

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms))

// The search endpoint rate-limits bursts. A dropped query silently shrinks the
// pool and changes what the benchmark measured, so pacing beats accepting it.
async function getJsonWithRetry(url: string, attempts = 3): Promise<unknown> {
  let lastError: unknown
  for (let i = 0; i < attempts; i++) {
    try {
      return await getJson(url)
    } catch (e) {
      lastError = e
      if (!String(e).includes('HTTP 429')) throw e
      await sleep(2_000 * (i + 1))
    }
  }
  throw lastError
}

async function harvestCandidates(): Promise<string[]> {
  const names = new Set<string>()
  let dropped = 0

  for (const query of HARVEST_QUERIES) {
    // Weighted on popularity alone, so the pool reflects what gets installed
    // rather than what scores well.
    const url = `${SEARCH_URL}?text=${encodeURIComponent(query)}&size=250&popularity=1.0&quality=0.0&maintenance=0.0`
    try {
      for (const name of getSearchObjects(await getJsonWithRetry(url))) names.add(name)
    } catch (e) {
      dropped++
      console.error(`  warning: query "${query}" failed (${e})`)
    }
    await sleep(400)
  }

  // A smaller pool is a different benchmark, not a noisier one, so two runs
  // with different pools cannot be compared.
  if (dropped > 0) {
    console.error(`  WARNING: ${dropped}/${HARVEST_QUERIES.length} queries failed. The pool is not comparable with other runs`)
  }

  return [...names]
}

function getSearchObjects(body: unknown): string[] {
  const objects = (body as { objects?: Array<{ package?: { name?: string } }> }).objects ?? []
  return objects.map(o => o.package?.name).filter((n): n is string => typeof n === 'string')
}

export interface RankedPackage {
  name: string
  downloads: number
  // A failed lookup is not zero downloads. Recording it as zero pushed whole
  // batches into the bottom deciles, so the "tail" was partly a bucket of
  // packages nobody measured.
  resolved: boolean
}

// The bulk downloads endpoint takes up to 128 names and does not accept scoped
// packages, so scoped names are counted one at a time.
async function rankByDownloads(names: string[]): Promise<RankedPackage[]> {
  const counts = new Map<string, number>()

  const unscoped = names.filter(n => !n.startsWith('@'))
  const scoped = names.filter(n => n.startsWith('@'))

  for (let i = 0; i < unscoped.length; i += 128) {
    const batch = unscoped.slice(i, i + 128)
    try {
      const body = await getJson(`${DOWNLOADS_URL}/${batch.join(',')}`) as Record<string, { downloads?: number } | null>
      // A single-name batch returns the record directly rather than a map keyed
      // by name, which would otherwise produce silent zeros.
      if (batch.length === 1) {
        const one = body as unknown as { downloads?: number }
        if (typeof one?.downloads === 'number') counts.set(batch[0]!, one.downloads)
      } else {
        for (const [name, rec] of Object.entries(body)) {
          // npm returns a literal null for names it has no data for: absence,
          // not zero.
          if (rec && typeof rec.downloads === 'number') counts.set(name, rec.downloads)
        }
      }
    } catch {
      // Left unresolved, so the batch is excluded below rather than sunk to the
      // bottom of the ranking.
    }
  }

  for (const name of scoped) {
    try {
      const body = await getJson(`${DOWNLOADS_URL}/${name}`) as { downloads?: number }
      if (typeof body?.downloads === 'number') counts.set(name, body.downloads)
    } catch {
      // Same: unresolved, not zero.
    }
  }

  return names
    .map(name => ({
      name,
      downloads: counts.get(name) ?? 0,
      resolved: counts.has(name),
    }))
    .sort((a, b) => b.downloads - a.downloads)
}

export interface Selected {
  name: string
  downloads: number
  decile?: number
}

// Evenly spaced and deliberately not random: two calibration runs have to sample
// the same packages, or the delta between them measures the sample.
export function sampleEvenly<T>(items: T[], k: number): T[] {
  if (k >= items.length) return [...items]
  const out: T[] = []
  for (let i = 0; i < k; i++) {
    out.push(items[Math.floor((i * items.length) / k)]!)
  }
  return out
}

// The top by downloads is where the genome works best and false positives are
// rarest. Sampling per decile puts the tail in the denominator, where short
// histories and hand-published releases live.
export function stratifyByDecile(
  ranked: Array<{ name: string; downloads: number }>,
  perDecile: number
): Selected[] {
  const selected: Selected[] = []
  const size = Math.ceil(ranked.length / DECILES)

  for (let d = 0; d < DECILES; d++) {
    const slice = ranked.slice(d * size, (d + 1) * size)
    if (slice.length === 0) continue
    for (const item of sampleEvenly(slice, perDecile)) {
      selected.push({ ...item, decile: d + 1 })
    }
  }

  return selected
}

async function analyzeOne(name: string, downloads: number, decile?: number): Promise<FpBenchRow> {
  const emptyMode = (): ModeOutcome => ({ verdict: 'ERROR', score: 0, regime: 'unknown', signals: [], versions: 0 })
  const empty: FpBenchRow = {
    package: name,
    downloads,
    decile,
    gate: emptyMode(),
    audit: emptyMode(),
  }

  try {
    const packument = await fetchPackument(name)
    const latest = packument.distTags['latest']
    if (!latest) return { ...empty, error: 'no latest dist-tag' }

    const currentMeta = packument.versions[latest]
    if (!currentMeta) return { ...empty, error: `version ${latest} missing` }

    // One fetch, one genome, two verdicts. Re-fetching doubled the load on a
    // public service for bytes already in hand.
    const genome = buildGenomeFromPackument(name, packument)

    // scoreWithRegime, not score: calling score() directly made
    // INSUFFICIENT_HISTORY unreachable, so packages with no baseline produced no
    // deltas and came back PASS from a gate that never examined them.
    const toOutcome = (r: ReturnType<typeof scoreWithRegime>): ModeOutcome => ({
      verdict: r.verdict,
      score: r.totalScore,
      regime: r.regime,
      signals: r.signals.map(s => ({ type: s.type, score: s.score })),
      versions: genome.versionsAnalyzed,
    })

    // The download count is already in hand from the ranking step, so the
    // conjunction can be evaluated for free on every package in the sample.
    const gate = scoreWithRegime({
      packument, version: latest, currentMeta, genome,
      weeklyDownloads: downloads,
      config: DEFAULT_THRESHOLDS.gate,
    })
    const audit = scoreWithRegime({
      packument, version: latest, currentMeta, genome,
      weeklyDownloads: downloads,
      config: DEFAULT_THRESHOLDS.audit,
    })

    const profile = fabricatedProfile({ packument, currentMeta, regime: gate.regime, weeklyDownloads: downloads })

    return {
      package: name,
      downloads,
      decile,
      gate: toOutcome(gate),
      audit: toOutcome(audit),
      fabricatedProfile: {
        matches: profile.matches,
        localConjuncts:
          profile.conjuncts.noGenome && profile.conjuncts.youngName &&
          profile.conjuncts.tiny && profile.conjuncts.noRepository,
        conjuncts: profile.conjuncts,
      },
    }
  } catch (e) {
    return { ...empty, error: String(e) }
  }
}

// 500 packages at one registry request each is already a lot to ask of a public
// service; unbounded parallelism would make this a load test.
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0

  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++
      if (i >= items.length) return
      results[i] = await fn(items[i]!, i)
    }
  })

  await Promise.all(workers)
  return results
}

const outcomeOf = (r: FpBenchRow, mode: 'gate' | 'audit') => mode === 'gate' ? r.gate : r.audit

function countByVerdict(rows: FpBenchRow[], mode: 'gate' | 'audit'): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const r of rows) {
    const v = outcomeOf(r, mode).verdict
    counts[v] = (counts[v] ?? 0) + 1
  }
  return counts
}

export function summarize(rows: FpBenchRow[], mode: 'gate' | 'audit'): ModeSummary {
  const usable = rows.filter(r => !r.error)
  const blockedRows = usable.filter(r => outcomeOf(r, mode).verdict === 'BLOCK')

  const noGenomeRows = usable.filter(r => outcomeOf(r, mode).regime === 'no-genome')
  const withoutLongHistory = usable.filter(
    r => !outcomeOf(r, mode).signals.some(s => s.type === 'long_history')
  )

  // A package with no genome has exactly one correct gate verdict. Anything else
  // escaped the regime check, which this exists to catch before CI does.
  const gateEscapes = mode === 'gate'
    ? noGenomeRows.filter(r => outcomeOf(r, mode).verdict !== 'INSUFFICIENT_HISTORY').length
    : 0

  const warned = usable.filter(r => outcomeOf(r, mode).verdict === 'WARN').length
  const passed = usable.filter(r => outcomeOf(r, mode).verdict === 'PASS').length
  const insufficient = usable.filter(r => outcomeOf(r, mode).verdict === 'INSUFFICIENT_HISTORY').length

  return {
    mode,
    analyzed: usable.length,
    blocked: blockedRows.length,
    warned,
    passed,
    insufficientHistory: insufficient,
    blockRate: rateWithCI(blockedRows.length, usable.length),
    warnRate: rateWithCI(warned, usable.length),
    insufficientRate: rateWithCI(insufficient, usable.length),
    nonPassRate: rateWithCI(blockedRows.length + warned, usable.length),
    unevaluatedRate: rateWithCI(insufficient, usable.length),
    buildBreakingRate: rateWithCI(blockedRows.length, usable.length),
    regimes: {
      noGenome: noGenomeRows.length,
      noGenomeByVerdict: countByVerdict(noGenomeRows, mode),
      withGenome: usable.length - noGenomeRows.length,
      withoutLongHistory: withoutLongHistory.length,
      withoutLongHistoryByVerdict: countByVerdict(withoutLongHistory, mode),
      gateEscapes,
    },
    byDecile: summarizeByDecile(usable, mode),
    scores: {
      noGenome: scoreDistribution(noGenomeRows.map(r => outcomeOf(r, mode).score)),
      genome: scoreDistribution(
        usable.filter(r => outcomeOf(r, mode).regime === 'genome').map(r => outcomeOf(r, mode).score)
      ),
      all: scoreDistribution(usable.map(r => outcomeOf(r, mode).score)),
    },
  }
}

function summarizeByDecile(usable: FpBenchRow[], mode: 'gate' | 'audit'): DecileResult[] {
  const withDecile = usable.filter(r => r.decile !== undefined)
  if (withDecile.length === 0) return []

  const out: DecileResult[] = []
  for (let d = 1; d <= DECILES; d++) {
    const rows = withDecile.filter(r => r.decile === d)
    if (rows.length === 0) continue

    const blocked = rows.filter(r => outcomeOf(r, mode).verdict === 'BLOCK').length
    const rate = rateWithCI(blocked, rows.length)
    const downloads = rows.map(r => r.downloads)

    out.push({
      decile: d,
      n: rows.length,
      blocked,
      rate: rate.rate,
      low: rate.low,
      high: rate.high,
      minDownloads: Math.min(...downloads),
      maxDownloads: Math.max(...downloads),
    })
  }
  return out
}

const BOLD  = '\x1b[1m'
const RED   = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const DIM   = '\x1b[2m'
const RESET = '\x1b[0m'

export const BLOCK_ZERO_ALERT =
  'BLOCK=0: the gate blocked nothing. This may be drift toward passing everything. ' +
  'Verify with the synthetic sample.'

// Zero blocks on a clean sample is the outcome this benchmark is designed to
// reward, and also what a detector that stopped detecting looks like from here.
// Not an error: the alert exists so the reader does not have to infer which.
export function blockZeroAlert(s: ModeSummary): string[] {
  if (s.blocked > 0 || s.analyzed === 0) return []

  return [
    '',
    `  ${YELLOW}${BOLD}${BLOCK_ZERO_ALERT}${RESET}`,
    `  ${DIM}npx vitest run test/gate-drift.test.ts  keyv@6.0.0: new install script + 25x size.${RESET}`,
    `  ${DIM}This sample is assumed clean, so it cannot tell "nothing to block" from${RESET}`,
    `  ${DIM}"no longer blocking". Only the synthetic sample can.${RESET}`,
  ]
}

function renderSummary(s: ModeSummary, rows: FpBenchRow[]): void {
  const label = s.mode === 'gate' ? 'GATE (the number that decides whether this ships in CI)' : 'AUDIT (forensic)'
  const usable = rows.filter(r => !r.error)

  console.log('\n' + '-'.repeat(70))
  console.log(`${BOLD}FALSE POSITIVES  ${label}${RESET}`)
  console.log('-'.repeat(70))
  console.log(`Analysed           ${s.analyzed}`)

  // Two headline numbers: the cost of adopting the gate, and the share of the
  // ecosystem it cannot judge. Collapsing them made a coverage gap look like a
  // false-positive rate; dropping the second would hide the gap entirely.
  const nonPass = s.blocked + s.warned
  const nonPassColor = (s.nonPassRate.rate ?? 0) > 0.05 ? RED : GREEN
  console.log(
    `${nonPassColor}${BOLD}${'non-PASS'.padEnd(19)}${formatRateWithCI(nonPass, s.analyzed)}${RESET}`
  )
  console.log(`${DIM}                   findings about the package: BLOCK + WARN${RESET}`)
  console.log(
    `${BOLD}${'unevaluated'.padEnd(19)}${formatRateWithCI(s.insufficientHistory, s.analyzed)}${RESET}`
  )
  console.log(`${DIM}                   INSUFFICIENT_HISTORY: informational, exit 0, does not fail the build${RESET}`)
  console.log()
  console.log(`  BLOCK              ${String(s.blocked).padStart(4)}   ${formatRateWithCI(s.blocked, s.analyzed)}   ${DIM}exit 1${RESET}`)
  console.log(`  WARN               ${String(s.warned).padStart(4)}   ${formatRateWithCI(s.warned, s.analyzed)}   ${DIM}exit 0${RESET}`)
  console.log(`  INSUFFICIENT_HIST  ${String(s.insufficientHistory).padStart(4)}   ${formatRateWithCI(s.insufficientHistory, s.analyzed)}   ${DIM}exit 0 (exit 1 with --strict-new-packages)${RESET}`)
  console.log(`  PASS               ${String(s.passed).padStart(4)}`)
  console.log(
    `\n  ${DIM}Fails the build by default: ${formatRateWithCI(s.blocked, s.analyzed)}. ` +
    `With --strict-new-packages: ${formatRateWithCI(s.blocked + s.insufficientHistory, s.analyzed)}.${RESET}`
  )

  // A clean sample cannot tell "nothing to block" from "no longer blocking".
  for (const line of blockZeroAlert(s)) console.log(line)

  renderFabricatedProfile(rows, usable.length)

  // Catches a gate scoring packages it has no baseline for.
  console.log(`\n${BOLD}Scoring regime${RESET}`)
  console.log(`  with genome (>=10 versions, >=90 days)  ${s.regimes.withGenome}`)
  console.log(`  without genome                          ${s.regimes.noGenome}`)
  for (const [verdict, n] of Object.entries(s.regimes.noGenomeByVerdict).sort(([, a], [, b]) => b - a)) {
    console.log(`    ${DIM}${verdict.padEnd(22)} ${n}${RESET}`)
  }

  if (s.mode === 'gate') {
    if (s.regimes.gateEscapes > 0) {
      console.log(
        `\n  ${RED}${BOLD}BROKEN GATE: ${s.regimes.gateEscapes} packages with no genome got a ` +
        `gate verdict instead of INSUFFICIENT_HISTORY.${RESET}`
      )
      console.log(`  ${RED}A PASS there is a package the gate never examined, reported as approved.${RESET}`)
    } else {
      console.log(`  ${GREEN}invariant holds: 0 packages without a genome got a gate verdict${RESET}`)
    }
  }

  console.log(`\n${BOLD}Where packages without long_history land (<=20 versions): ${s.regimes.withoutLongHistory}${RESET}`)
  for (const [verdict, n] of Object.entries(s.regimes.withoutLongHistoryByVerdict).sort(([, a], [, b]) => b - a)) {
    const note = verdict === 'PASS'
      ? '  <- with a valid genome this is a legitimate PASS; without one it is the bug above'
      : ''
    console.log(`  ${verdict.padEnd(22)} ${n}${DIM}${note}${RESET}`)
  }

  // A discount listed as a cause of BLOCK is a reporting bug, and gets named as
  // one rather than quietly rendered.
  const blockedRows = usable.filter(r => outcomeOf(r, s.mode).verdict === 'BLOCK')
  const blockedPartition = tallySignals(blockedRows.map(r => outcomeOf(r, s.mode).signals))

  console.log(`\n${BOLD}Signals on BLOCKED packages${RESET}`)
  if (blockedRows.length === 0) {
    console.log(`  ${DIM}(none)${RESET}`)
  } else {
    for (const line of renderPartition(blockedPartition, '  ')) console.log(line)
    for (const bug of reportBugs(blockedPartition)) {
      console.log(`  ${YELLOW}${bug}${RESET}`)
    }
  }

  console.log(`\n${BOLD}Prevalence of each signal, all analysed${RESET}`)
  for (const line of renderPartition(tallySignals(usable.map(r => outcomeOf(r, s.mode).signals)), '  ')) {
    console.log(line)
  }

  const worst = blockedRows
    .sort((a, b) => outcomeOf(b, s.mode).score - outcomeOf(a, s.mode).score)
    .slice(0, 10)

  if (worst.length > 0) {
    console.log(`\n${BOLD}Worst false positives${RESET}`)
    for (const r of worst) {
      const o = outcomeOf(r, s.mode)
      // Only what pushed it over: printing discounts here made long_history look
      // like a cause of the block.
      const causes = o.signals.filter(sig => sig.score > 0).map(sig => `${sig.type}+${sig.score}`).join(', ')
      console.log(`  ${r.package.padEnd(34)} score=${String(o.score).padEnd(5)} ${DIM}${causes}${RESET}`)
    }
  }

  // Both regimes: a no-genome package is scored on absolute risk and tops out
  // far lower than one with a baseline to diff against.
  console.log(`\n${BOLD}Score distribution, sample assumed clean${RESET}`)
  const distRow = (label: string, d: ScoreDistribution | null) => {
    if (!d) return console.log(`  ${label.padEnd(12)} ${DIM}(no data)${RESET}`)
    console.log(
      `  ${label.padEnd(12)} n=${String(d.n).padEnd(5)} ` +
      `p50=${String(d.p50).padEnd(5)} p90=${String(d.p90).padEnd(5)} ` +
      `p95=${String(d.p95).padEnd(5)} p99=${String(d.p99).padEnd(5)} max=${d.max}`
    )
  }
  distRow('no-genome', s.scores.noGenome)
  distRow('genome', s.scores.genome)
  distRow('all', s.scores.all)

  const ng = s.scores.noGenome
  if (ng) {
    console.log(`\n  ${BOLD}Proposed threshold (p99 of clean no-genome scores): ${ng.p99}${RESET}`)

    console.log(`  ${DIM}no-genome score histogram:${RESET}`)
    for (const bin of ng.histogram) {
      console.log(
        `    ${DIM}score=${String(bin.score).padStart(4)}  ${String(bin.count).padStart(5)} paquetes` +
        `   at or above: ${bin.atOrAbove} (${pct(bin.atOrAbove / ng.n, 1)})${RESET}`
      )
    }

    // With a handful of distinct values p99 is not a 1-in-100 cut point, just
    // the top bucket, and the threshold it produces captures whatever that
    // bucket holds.
    if (ng.distinct <= 3) {
      const top = ng.histogram[ng.histogram.length - 1]
      const plural = ng.distinct === 1 ? 'a single distinct value' : `only ${ng.distinct} distinct values`
      console.log(`\n  ${YELLOW}${BOLD}CAUTION: the no-genome score takes ${plural}.${RESET}`)
      console.log(
        `  ${YELLOW}A p99 rule assumes the distribution is fine-grained enough for the\n` +
        `  99th percentile to name a cut point. It is not: a threshold of ${ng.p99}\n` +
        `  captures ${top ? pct(top.atOrAbove / ng.n, 1) : '?'} of new packages, not 1%. One of ${ng.p99 + 1} captures 0%.${RESET}`
      )
      console.log(
        `  ${YELLOW}No intermediate threshold separates anything, so the lever is not the\n` +
        `  threshold: it is the scorer's absolute-risk branch, which only emits\n` +
        `  absolute_install_script (+20) and absolute_large_size (+15). Until that\n` +
        `  branch discriminates further, any no-genome threshold is all or nothing.${RESET}`
      )
    } else {
      console.log(
        `  ${DIM}One in a hundred ordinary new packages reaches that score. It comes ` +
        `from the measured\n  distribution, not from a round number.${RESET}`
      )
    }
  }

  if (s.byDecile.length > 0) {
    console.log(`\n${BOLD}False positives by download decile (1 = most downloaded)${RESET}`)
    for (const d of s.byDecile) {
      const bar = d.rate === null ? '' : formatRateWithCI(d.blocked, d.n)
      console.log(
        `  decile ${String(d.decile).padStart(2)}  n=${String(d.n).padEnd(4)} ` +
        `${bar.padEnd(44)} ${DIM}${d.maxDownloads.toLocaleString()}-${d.minDownloads.toLocaleString()} downloads/week${RESET}`
      )
    }
  }
}

// The number that decides whether the conjunction can be on by default. It is
// evaluated on every package in the clean sample regardless of whether the rule
// is enabled, so the cost is known before the switch is thrown.
export function renderFabricatedProfile(rows: FpBenchRow[], analyzed: number): void {
  const usable = rows.filter(r => !r.error && r.fabricatedProfile)
  if (usable.length === 0) return

  const matches = usable.filter(r => r.fabricatedProfile!.matches)
  const local = usable.filter(r => r.fabricatedProfile!.localConjuncts)

  console.log(`\n${BOLD}Fabricated-profile rule: false positives on the clean sample${RESET}`)
  console.log(
    `  full conjunction (5 conditions)      ${matches.length}/${usable.length}   ` +
    formatRateWithCI(matches.length, usable.length)
  )
  console.log(
    `  ${DIM}the 4 local ones (no downloads)      ${local.length}/${usable.length}   ` +
    formatRateWithCI(local.length, usable.length) + RESET
  )

  for (const r of matches) {
    console.log(`  ${RED}${r.package}: would block a clean package${RESET}`)
  }

  // The sample is ranked by downloads, so the fifth conjunct is close to
  // impossible in it by construction. The four-way count is the number that
  // carries information here, and it bounds the five-way from above.
  console.log(
    `\n  ${DIM}The sample is ranked by downloads, so "zero downloads" can barely occur\n` +
    `  in it. The informative number is the four local conditions, which bounds\n` +
    `  the full conjunction from above.${RESET}`
  )

  const verdict = matches.length === 0 && local.length === 0
    ? `${GREEN}0 of ${usable.length} clean packages blocked: the rule can be on by default${RESET}`
    : matches.length === 0
      ? `${YELLOW}0 blocked, but ${local.length} meet the four local conditions: opt-in until measured against a sample of legitimate new packages${RESET}`
      : `${RED}${matches.length} clean packages blocked: opt-in, not default${RESET}`

  console.log(`\n  ${verdict}`)
}

export interface FpBenchOptions {
  top?: number
  concurrency?: number
  stratified?: boolean
  perDecile?: number
  resultsDir?: string
  save?: boolean
}

export async function runFalsePositiveBench(options: FpBenchOptions = {}): Promise<{
  rows: FpBenchRow[]
  gate: ModeSummary
  audit: ModeSummary
  artifact: FpBenchArtifact
  artifactPath: string | null
}> {
  const stratified = options.stratified ?? false
  const top = options.top ?? 500
  const perDecile = options.perDecile ?? 50
  const concurrency = options.concurrency ?? 8

  console.log(
    `\nnorte-guard fp-bench: ` +
    (stratified ? `stratified, ${perDecile} per decile` : `top ${top}`) +
    `, concurrency ${concurrency}\n`
  )

  console.log('Harvesting candidates...')
  const candidates = await harvestCandidates()
  console.log(`  ${candidates.length} unique packages in the pool`)

  console.log('Ranking by real last-week downloads...')
  const ranked = await rankByDownloads(candidates)

  // Excluded, not sunk to the bottom. Counting an unresolved lookup as zero
  // downloads fabricates a tail, and the tail is exactly what --stratified is
  // supposed to be measuring.
  const measured = ranked.filter(r => r.resolved)
  const unresolved = ranked.length - measured.length
  if (unresolved > 0) {
    console.log(
      `  ${unresolved}/${ranked.length} with no download data, excluded from the sample ` +
      `(a failed lookup is not a package with 0 downloads)`
    )
  }

  const selected: Selected[] = stratified
    ? stratifyByDecile(measured, perDecile)
    : measured.slice(0, top).map(r => ({ name: r.name, downloads: r.downloads }))

  console.log(
    `  selected ${selected.length} ` +
    `(measured pool: ${measured.length}, from ${measured[0]?.downloads.toLocaleString()} to ` +
    `${measured[measured.length - 1]?.downloads.toLocaleString()} downloads/week)\n`
  )

  let done = 0
  const rows = await mapWithConcurrency(selected, concurrency, async ({ name, downloads, decile }) => {
    const row = await analyzeOne(name, downloads, decile)
    done++
    if (done % 25 === 0) console.log(`  ${done}/${selected.length}...`)
    return row
  })

  const failed = rows.filter(r => r.error)
  if (failed.length > 0) {
    console.log(`\n${failed.length} packages could not be analysed (excluded from the denominator)`)
  }

  const gate = summarize(rows, 'gate')
  const audit = summarize(rows, 'audit')

  const artifact = buildArtifact({
    rows, gate, audit,
    sampling: {
      mode: stratified ? 'stratified' : 'top',
      harvestQueries: HARVEST_QUERIES,
      poolSize: ranked.length,
      measuredPoolSize: measured.length,
      unresolvedDownloads: unresolved,
      top: stratified ? undefined : top,
      perDecile: stratified ? perDecile : undefined,
      n: gate.analyzed,
    },
  })

  renderSummary(gate, rows)
  renderSummary(audit, rows)

  console.log('\n' + '-'.repeat(70))
  console.log(
    'SAMPLING BIAS: npm exposes no global top N, since the search API requires a\n' +
    'term. The pool comes from these keyword queries and is then ranked by real\n' +
    'downloads:\n  ' + HARVEST_QUERIES.join(', ') + '\n' +
    'Popular packages carrying none of these keywords never enter. The number is not\n' +
    `"npm's top ${top}", it is "${stratified ? 'a stratified sample' : `the ${top} most downloaded`} of this pool".`
  )
  if (!stratified) {
    console.log(
      '\nThe top N is also biased toward well-maintained packages: long histories,\n' +
      'automated releases, dense genomes. False positives live in the tail.\n' +
      'Run with --stratified to measure by download decile.'
    )
  }

  console.log('\n' + '-'.repeat(70))
  console.log(`${BOLD}DECLARED ASSUMPTIONS${RESET}`)
  for (const a of artifact.assumptions) console.log(`  ${a}`)
  console.log('-'.repeat(70))

  let savedPath: string | null = null
  if (options.save ?? true) {
    savedPath = saveArtifact(artifact, options.resultsDir)
    console.log(`\nResults saved to ${savedPath}`)
    console.log(`${DIM}Compare against earlier runs to measure the delta of a calibration.${RESET}\n`)
  }

  return { rows, gate, audit, artifact, artifactPath: savedPath }
}

function modeRates(s: ModeSummary): FpBenchArtifact['rates']['gate'] {
  return {
    blocked: s.blocked,
    warned: s.warned,
    insufficientHistory: s.insufficientHistory,
    passed: s.passed,
    nonPass: s.blocked + s.warned,
    unevaluated: s.insufficientHistory,
    n: s.analyzed,
    rate: s.blockRate.rate,
    low: s.blockRate.low,
    high: s.blockRate.high,
    nonPassRate: s.nonPassRate.rate,
    nonPassLow: s.nonPassRate.low,
    nonPassHigh: s.nonPassRate.high,
  }
}

export function buildArtifact(input: {
  rows: FpBenchRow[]
  gate: ModeSummary
  audit: ModeSummary
  sampling: FpBenchArtifact['sampling']
  generatedAt?: string
}): FpBenchArtifact {
  const { rows, gate, audit, sampling } = input

  const signalMap = (mode: 'gate' | 'audit', subset: FpBenchRow[]) => {
    const partition = tallySignals(subset.map(r => outcomeOf(r, mode).signals))
    const out: Record<string, { count: number; totalScore: number }> = {}
    for (const t of [...partition.positive, ...partition.negative, ...partition.informational]) {
      out[t.type] = { count: t.count, totalScore: t.totalScore }
    }
    return out
  }

  const usable = rows.filter(r => !r.error)
  const packages: FpBenchPackageResult[] = rows.map(r => ({
    package: r.package,
    downloads: r.downloads,
    decile: r.decile,
    gate: { verdict: r.gate.verdict, score: r.gate.score, regime: r.gate.regime, signals: r.gate.signals },
    audit: { verdict: r.audit.verdict, score: r.audit.score, regime: r.audit.regime, signals: r.audit.signals },
    error: r.error,
  }))

  return {
    schema: 1,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    engineVersion: engineVersion(),
    sampling,
    thresholds: DEFAULT_THRESHOLDS,
    rates: {
      gate: modeRates(gate),
      audit: modeRates(audit),
    },
    byDecile: gate.byDecile.length > 0 ? { gate: gate.byDecile, audit: audit.byDecile } : undefined,
    scoreDistribution: { gate: gate.scores, audit: audit.scores },
    proposedThresholds: {
      // p99 of clean no-genome scores.
      captureFromNoGenomeP99: gate.scores.noGenome?.p99 ?? null,
    },
    bySignal: {
      gate: {
        amongBlocked: signalMap('gate', usable.filter(r => r.gate.verdict === 'BLOCK')),
        overall: signalMap('gate', usable),
      },
      audit: {
        amongBlocked: signalMap('audit', usable.filter(r => r.audit.verdict === 'BLOCK')),
        overall: signalMap('audit', usable),
      },
    },
    regimes: {
      gate: { noGenome: gate.regimes.noGenomeByVerdict, sinLongHistory: gate.regimes.withoutLongHistoryByVerdict },
      audit: { noGenome: audit.regimes.noGenomeByVerdict, sinLongHistory: audit.regimes.withoutLongHistoryByVerdict },
    },
    // An alert that only ever existed in a terminal cannot be compared against
    // the next run.
    alerts: [
      ...(gate.blocked === 0 && gate.analyzed > 0 ? [`gate: ${BLOCK_ZERO_ALERT}`] : []),
      ...(audit.blocked === 0 && audit.analyzed > 0 ? [`audit: ${BLOCK_ZERO_ALERT}`] : []),
    ],
    assumptions: cleanSampleAssumptions(gate.analyzed),
    packages,
  }
}

// Only when invoked directly, so importing the module for its types does not
// kick off a thousand registry requests.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const arg = (flag: string) => process.argv.find(a => a.startsWith(`--${flag}=`))?.split('=')[1]

  runFalsePositiveBench({
    top: Number(arg('top') ?? 500),
    concurrency: Number(arg('concurrency') ?? 8),
    stratified: process.argv.includes('--stratified'),
    perDecile: Number(arg('per-decile') ?? 50),
    resultsDir: arg('results-dir'),
    save: !process.argv.includes('--no-save'),
  }).catch(e => {
    console.error(e)
    process.exit(2)
  })
}
