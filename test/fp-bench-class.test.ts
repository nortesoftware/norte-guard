/**
 * The class-matched false-positive arm.
 *
 * The defect this arm exists for is not a bug in any signal: it is that the
 * popularity-ranked corpus cannot express the observed class at all. A popular
 * package is not seven days old, is not under 100KB, and has a repository — so a
 * signal gated on those three scores 0.0% false positives there whatever it
 * does, and the benchmark approves it by declining to answer.
 *
 * Measured on shipped code rather than argued: `fabricatedProfile` reports
 * 0.00% on seven saved popularity runs (v0.2.0 through v1.2.0, n=500 each) and
 * 82.66% on the class arm (n=1,505). The first test below is that invariant, so
 * a future change to the conjuncts cannot quietly make the popularity arm look
 * capable of measuring them.
 */

import { describe, it, expect } from 'vitest'
import { buildClassArmArtifact, analyzeStoredCapture, CLASS_ARM_REASON, type FpBenchRow, type ModeSummary } from '../src/fp-bench.js'
import { classifyPublication, TINY_PACKAGE_BYTES, YOUNG_NAME_DAYS } from '../src/observed-class.js'
import { normalizePackument } from '../src/packument.js'
import type { CorpusSample } from '../src/corpus.js'

const NOW = Date.UTC(2026, 7, 20)
const daysAgo = (n: number): string => new Date(NOW - n * 86_400_000).toISOString()

function packument(input: { name: string; at: string; size: number; repository?: unknown }) {
  return normalizePackument({
    name: input.name,
    time: { created: input.at, modified: input.at, '1.0.0': input.at },
    versions: {
      '1.0.0': {
        dist: { unpackedSize: input.size, tarball: '', integrity: '', shasum: '' },
        repository: input.repository,
        _npmUser: { name: 'someone', email: 'a@b.c' },
      },
    },
    maintainers: [{ name: 'someone', email: 'a@b.c' }],
  })
}

describe('the popularity corpus cannot express the observed class', () => {
  it('a popular package fails all three conjuncts', () => {
    // What the harvest ranks to the top: years old, megabytes, a repository.
    const popular = packument({
      name: 'lodash-like',
      at: daysAgo(900),
      size: 5_000_000,
      repository: { type: 'git', url: 'https://github.com/x/y' },
    })
    const markers = classifyPublication(popular, popular.versions['1.0.0']!, 'genome', NOW)

    expect(markers.young).toBe(false)
    expect(markers.tiny).toBe(false)
    expect(markers.hasRepository).toBe(true)
    // The consequence: a class-gated signal has nothing to fire on, so its false
    // positive rate on this corpus is 0.0% by construction and means nothing.
    expect(markers.inClass).toBe(false)
  })

  it('a class member fails every property the popularity ranking selects on', () => {
    const newborn = packument({ name: 'newborn', at: daysAgo(1), size: 20_000 })
    const markers = classifyPublication(newborn, newborn.versions['1.0.0']!, 'no-genome', NOW)

    expect(markers.inClass).toBe(true)
    expect(markers.nameAgeDays).toBeLessThan(YOUNG_NAME_DAYS)
    expect(markers.unpackedSize).toBeLessThan(TINY_PACKAGE_BYTES)
  })

  it('draws its pool from the capture reason that IS the class', () => {
    // Not a preference. `watcher-threshold` keeps whatever scored high, which is
    // a different population; `quarantine-no-genome` keeps what matched the
    // three conjuncts, which is the one a class-gated signal fires in.
    expect(CLASS_ARM_REASON).toBe('quarantine-no-genome')
  })
})

describe('scoring a stored capture', () => {
  const sample = (over: Partial<CorpusSample> = {}): CorpusSample => ({
    package: 'x',
    version: '1.0.0',
    label: 'unconfirmed',
    ngpackPath: '/nonexistent/capture',
    capturedAt: daysAgo(1),
    hasTarball: false,
    tarballPresent: false,
    labelAssumed: true,
    contaminated: false,
    ...over,
  })

  it('reports a capture with no packument as an error rather than a PASS', () => {
    const row = analyzeStoredCapture(sample())
    expect(row.error).toBe('no packument in the capture')
    // An unreadable capture must not land in the denominator as a clean package:
    // that would lower the false-positive rate by failing to look.
    expect(row.gate.verdict).toBe('ERROR')
  })

  it('carries a missing download week as absent rather than as zero', () => {
    // npm serves one complete week at a time, so a snapshot without it can never
    // be re-judged, and a zero there is a claim about the package.
    const row = analyzeStoredCapture(sample({ weeklyDownloads: null }))
    expect(row.downloads).toBe(0)
    expect(row.error).toBeDefined()
  })
})

describe('the artifact', () => {
  const mode = (over: Partial<ModeSummary> = {}): ModeSummary => ({
    mode: 'gate', analyzed: 3, blocked: 1, warned: 0, passed: 2, insufficientHistory: 0,
    blockRate: { successes: 1, n: 3, rate: 1 / 3, low: 0, high: 1 },
    warnRate: { successes: 0, n: 3, rate: 0, low: 0, high: 1 },
    insufficientRate: { successes: 0, n: 3, rate: 0, low: 0, high: 1 },
    nonPassRate: { successes: 1, n: 3, rate: 1 / 3, low: 0, high: 1 },
    unevaluatedRate: { successes: 0, n: 3, rate: 0, low: 0, high: 1 },
    buildBreakingRate: { successes: 1, n: 3, rate: 1 / 3, low: 0, high: 1 },
    regimes: {
      noGenome: 0, noGenomeByVerdict: {}, withGenome: 3,
      withoutLongHistory: 0, withoutLongHistoryByVerdict: {}, gateEscapes: 0,
    },
    byDecile: [],
    scores: { noGenome: null, genome: null, all: null },
    ...over,
  })

  const row = (name: string, matches: boolean, error?: string): FpBenchRow => ({
    package: name,
    downloads: 0,
    gate: { verdict: 'PASS', score: 0, regime: 'no-genome', signals: [], versions: 1 },
    audit: { verdict: 'PASS', score: 0, regime: 'no-genome', signals: [], versions: 1 },
    fabricatedProfile: { matches, localConjuncts: matches, conjuncts: {} },
    error,
  })

  it('rates the fabricated profile over usable rows only', () => {
    const artifact = buildClassArmArtifact({
      rows: [row('a', true), row('b', false), row('c', true), row('d', true, 'unreadable')],
      gate: mode(), audit: mode({ mode: 'audit' }),
      pool: { scored: [], inReason: 10, withdrawnRemoved: 2, confirmedRemoved: 1, noDownloadsRecorded: 0 },
      captureReason: CLASS_ARM_REASON,
    })

    // The errored row is out of both halves. Counting it as a non-match would
    // report a package nobody could read as one the rule cleared.
    expect(artifact.fabricatedProfile.fullConjunction.successes).toBe(2)
    expect(artifact.fabricatedProfile.fullConjunction.n).toBe(3)
    expect(artifact.packages).toHaveLength(3)
  })

  it('records what the pool excluded, not only what it kept', () => {
    const artifact = buildClassArmArtifact({
      rows: [row('a', false)],
      gate: mode(), audit: mode({ mode: 'audit' }),
      pool: { scored: [], inReason: 10, withdrawnRemoved: 2, confirmedRemoved: 1, noDownloadsRecorded: 4 },
      captureReason: CLASS_ARM_REASON,
    })

    // "Not withdrawn" is the whole basis for calling this arm clean, so the
    // count that was withdrawn has to travel with the rate.
    expect(artifact.pool.withdrawnRemoved).toBe(2)
    expect(artifact.pool.confirmedRemoved).toBe(1)
    expect(artifact.pool.noDownloadsRecorded).toBe(4)
    expect(artifact.arm).toBe('class-matched')
  })
})
