/**
 * Benchmark tests. Each one pins a specific correction:
 *
 *   Wilson, not the normal approximation: at low n the normal gives a negative
 *   lower bound.
 *   "not calculable" is never printed as "0%". They are different things.
 *   The corpus separates by label: recall ONLY over confirmed_malicious.
 *   NgpackSource as the malicious corpus source, since the versions were purged
 *   and cannot be downloaded.
 *   INSUFFICIENT_HISTORY exists at runtime: a package with no genome cannot
 *   receive a gate verdict.
 *   long_history is a discount, never a cause of BLOCK.
 *   entrypoint_changed is worth 0 points in layer 1.
 */

import { describe, it, expect, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'

import { wilsonInterval, rateWithCI, formatRateWithCI, pct } from '../src/stats.js'
import { tallySignals, reportBugs } from '../src/signal-report.js'
import {
  loadCorpus,
  describeCorpusProgress,
  describeContamination,
  classifyContamination,
  backfillCaptureProvenance,
  resolveReferences,
  KNOWN_ATTACK_REFERENCES,
  PRE_FIX_REASON,
} from '../src/corpus.js'
import { runBench, buildRecallReport, buildFalsePositiveReport, artifactStaleness, artifactBlindSpots } from '../src/bench.js'
import { computeFieldRecall, regradeWithCurrentEngine } from '../src/field-recall.js'
import { summarize, sampleEvenly, stratifyByDecile, buildArtifact, blockZeroAlert, BLOCK_ZERO_ALERT, type FpBenchRow } from '../src/fp-bench.js'
import { saveArtifact, loadArtifacts, artifactPath, engineVersion, type FpBenchArtifact } from '../src/fp-bench-store.js'
import { scoreWithRegime, score } from '../src/scorer.js'
import { inspect } from '../src/inspect.js'
import { NgpackSource } from '../src/ngpack.js'
import { buildGenomeFromPackument } from '../src/genome.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'
import type { Packument, VersionMeta } from '../src/packument.js'

const tempDirs: string[] = []

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

describe('wilsonInterval', () => {
  it('reproduces the reported case: 2/500 gives 0.11%-1.45%', () => {
    const { low, high } = wilsonInterval(2, 500)
    expect(pct(2 / 500)).toBe('0.40%')
    expect(pct(low)).toBe('0.11%')
    expect(pct(high)).toBe('1.45%')
  })

  it('n=0 neither throws nor invents a rate', () => {
    expect(wilsonInterval(0, 0)).toEqual({ low: 0, high: 0 })
  })

  it('with 0 successes the lower bound is 0: the normal would give a negative', () => {
    const { low, high } = wilsonInterval(0, 500)
    expect(low).toBe(0)
    expect(high).toBeGreaterThan(0)

    // The reason to use Wilson: at this point the normal approximation claims
    // "fewer than zero false positives".
    const p = 0 / 500
    const normalLow = p - 1.96 * Math.sqrt(p * (1 - p) / 500)
    expect(normalLow).toBe(0)   // degenerate: zero-width interval, equally useless

    // And at 1/500 it does go below zero.
    const p1 = 1 / 500
    expect(p1 - 1.96 * Math.sqrt(p1 * (1 - p1) / 500)).toBeLessThan(0)
    expect(wilsonInterval(1, 500).low).toBeGreaterThan(0)
  })

  it('the interval always falls inside [0,1]', () => {
    for (const [k, n] of [[0, 1], [1, 1], [3, 7], [499, 500], [500, 500]] as const) {
      const { low, high } = wilsonInterval(k, n)
      expect(low).toBeGreaterThanOrEqual(0)
      expect(high).toBeLessThanOrEqual(1)
      expect(low).toBeLessThanOrEqual(high)
    }
  })

  it('formatRateWithCI produces the report line', () => {
    expect(formatRateWithCI(2, 500)).toBe('0.40% (95% Wilson CI: 0.11%-1.45%, n=500)')
  })

  it('rateWithCI returns null at n=0: a rate over nothing is not zero', () => {
    const r = rateWithCI(0, 0)
    expect(r.rate).toBeNull()
    expect(r.low).toBeNull()
    expect(r.high).toBeNull()
  })
})

describe('tallySignals: separates what adds from what subtracts', () => {
  it('long_history lands in discounts, never in positives', () => {
    const partition = tallySignals([
      [{ type: 'new_install_script', score: 45 }, { type: 'long_history', score: -15 }],
      [{ type: 'new_install_script', score: 45 }, { type: 'long_history', score: -15 }],
    ])

    expect(partition.positive.map(t => t.type)).toEqual(['new_install_script'])
    expect(partition.negative.map(t => t.type)).toEqual(['long_history'])
    expect(partition.positive.find(t => t.type === 'long_history')).toBeUndefined()
    expect(partition.negative[0]!.totalScore).toBe(-30)
    expect(partition.negative[0]!.count).toBe(2)
  })

  it('a 0-point signal is informational, not positive', () => {
    const partition = tallySignals([[{ type: 'entrypoint_changed', score: 0 }]])
    expect(partition.informational.map(t => t.type)).toEqual(['entrypoint_changed'])
    expect(partition.positive).toHaveLength(0)
  })

  it('reportBugs names the discount present on blocked packages', () => {
    const partition = tallySignals([[{ type: 'long_history', score: -15 }]])
    const bugs = reportBugs(partition)
    expect(bugs).toHaveLength(1)
    expect(bugs[0]).toContain('long_history')
    expect(bugs[0]).toContain('discount')
  })
})

describe('entrypoint_changed — desactivado en capa 1', () => {
  function twoVersions(prev: Partial<VersionMeta>, next: Partial<VersionMeta>): Packument {
    const base = (o: Partial<VersionMeta>): VersionMeta => ({
      version: '1.0.0', publishedAt: '2024-01-01T00:00:00Z', publishedBy: 'x',
      unpackedSize: 100_000, hasInstallScript: false, scripts: {},
      dependencies: {}, devDependencies: {}, dist: { tarball: '', integrity: '' }, ...o,
    })
    const a = base({ version: '1.0.0', publishedAt: '2024-01-01T00:00:00Z', ...prev })
    const b = base({ version: '1.1.0', publishedAt: '2024-06-01T00:00:00Z', ...next })
    return {
      name: 'pkg', distTags: { latest: '1.1.0' },
      versions: { '1.0.0': a, '1.1.0': b },
      time: { '1.0.0': a.publishedAt, '1.1.0': b.publishedAt },
      maintainers: [],
    }
  }

  it('it is still detected but adds 0 points', () => {
    const packument = twoVersions(
      { exports: { default: './index.js' } },
      { exports: { default: './payload.js' } },
    )

    const result = score({
      packument, version: '1.1.0', currentMeta: packument.versions['1.1.0']!,
      genome: {
        package: 'pkg', computedAt: '', versionsAnalyzed: 5, stableCapabilities: [],
        capabilityHistory: [], sizeBaseline: 100_000, publishVelocityBaseline: 1,
        isMonorepo: false, batchPeers: [],
      },
      config: DEFAULT_THRESHOLDS.gate,
    })

    const signal = result.signals.find(s => s.type === 'entrypoint_changed')
    expect(signal).toBeDefined()
    expect(signal!.score).toBe(0)
    expect(signal!.informational).toBe(true)

    // What it measured was the migration to ESM: an exports field that moves,
    // and nothing else. On its own it cannot move a verdict.
    expect(result.totalScore).toBe(0)
    expect(result.verdict).toBe('PASS')
  })
})

describe('scoring regime: the gate cannot score without a baseline', () => {
  function freshPackage(): { packument: Packument; meta: VersionMeta } {
    const meta: VersionMeta = {
      version: '1.0.0', publishedAt: new Date().toISOString(), publishedBy: 'nuevo',
      unpackedSize: 6_000_000, hasInstallScript: true, scripts: { postinstall: 'node x.js' },
      dependencies: { axios: '^1.0.0' }, devDependencies: {},
      dist: { tarball: '', integrity: '' },
    }
    return {
      packument: {
        name: 'paquete-nuevo', distTags: { latest: '1.0.0' },
        versions: { '1.0.0': meta }, time: { '1.0.0': meta.publishedAt }, maintainers: [],
      },
      meta,
    }
  }

  it('with no history, gate returns INSUFFICIENT_HISTORY and not PASS', () => {
    const { packument, meta } = freshPackage()
    const genome = buildGenomeFromPackument('paquete-nuevo', packument)

    const gate = scoreWithRegime({
      packument, version: '1.0.0', currentMeta: meta, genome, config: DEFAULT_THRESHOLDS.gate,
    })

    expect(gate.regime).toBe('no-genome')
    expect(gate.verdict).toBe('INSUFFICIENT_HISTORY')
    expect(gate.verdict).not.toBe('PASS')
  })

  it('summarize flags gateEscapes when a no-genome receives a gate verdict', () => {
    const row = (verdict: string, regime: string): FpBenchRow => ({
      package: `p-${verdict}-${regime}`, downloads: 1,
      gate: { verdict, score: 0, regime, signals: [], versions: 1 },
      audit: { verdict, score: 0, regime, signals: [], versions: 1 },
    })

    const healthy = summarize([
      row('INSUFFICIENT_HISTORY', 'no-genome'),
      row('PASS', 'genome'),
    ], 'gate')
    expect(healthy.regimes.gateEscapes).toBe(0)
    expect(healthy.insufficientHistory).toBe(1)

    // The bug behind correction 5: no genome, yet reported as PASS.
    const broken = summarize([row('PASS', 'no-genome')], 'gate')
    expect(broken.regimes.gateEscapes).toBe(1)
  })

  it('counts where packages without long_history land', () => {
    const withLong: FpBenchRow = {
      package: 'old', downloads: 1,
      gate: { verdict: 'PASS', score: -15, regime: 'genome', signals: [{ type: 'long_history', score: -15 }], versions: 40 },
      audit: { verdict: 'PASS', score: -15, regime: 'genome', signals: [{ type: 'long_history', score: -15 }], versions: 40 },
    }
    const withoutLong: FpBenchRow = {
      package: 'joven', downloads: 1,
      gate: { verdict: 'PASS', score: 0, regime: 'genome', signals: [], versions: 12 },
      audit: { verdict: 'PASS', score: 0, regime: 'genome', signals: [], versions: 12 },
    }

    const s = summarize([withLong, withoutLong], 'gate')
    expect(s.regimes.withoutLongHistory).toBe(1)
    expect(s.regimes.withoutLongHistoryByVerdict['PASS']).toBe(1)
  })
})

describe('decile sampling', () => {
  it('sampleEvenly is deterministic and covers the whole range', () => {
    const items = Array.from({ length: 100 }, (_, i) => i)
    const a = sampleEvenly(items, 10)
    const b = sampleEvenly(items, 10)
    expect(a).toEqual(b)
    expect(a).toEqual([0, 10, 20, 30, 40, 50, 60, 70, 80, 90])
  })

  it('returns everything when asked for more than exists', () => {
    expect(sampleEvenly([1, 2, 3], 50)).toEqual([1, 2, 3])
  })

  it('stratifies into 10 deciles and labels each sample', () => {
    const ranked = Array.from({ length: 1000 }, (_, i) => ({ name: `p${i}`, downloads: 1000 - i }))
    const selected = stratifyByDecile(ranked, 50)

    expect(selected).toHaveLength(500)
    expect(new Set(selected.map(s => s.decile))).toEqual(new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))

    // Decile 1 is the most downloaded and 10 is the tail: that is what a top-N
    // sample never measures.
    const d1 = selected.filter(s => s.decile === 1)
    const d10 = selected.filter(s => s.decile === 10)
    expect(Math.min(...d1.map(s => s.downloads))).toBeGreaterThan(Math.max(...d10.map(s => s.downloads)))
  })
})

function writeCapture(root: string, opts: {
  pkg: string
  version: string
  packument: Packument
  metadata?: Record<string, unknown> | null
}): string {
  const dir = join(root, `${opts.pkg.replace(/[@/]/g, '_')}@${opts.version}_1`)
  mkdirSync(join(dir, 'tarballs'), { recursive: true })

  const raw = JSON.stringify(opts.packument)
  writeFileSync(join(dir, 'packument.json'), raw)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
    version: 1,
    package: opts.pkg,
    capturedAt: '2026-08-12T02:46:45.791Z',
    capturedFrom: 'https://registry.npmjs.org',
    versionsIncluded: [opts.version],
    hashes: { 'packument.json': createHash('sha256').update(Buffer.from(raw)).digest('hex') },
  }, null, 2))

  if (opts.metadata !== null) {
    writeFileSync(join(dir, 'capture-metadata.json'), JSON.stringify({
      package: opts.pkg,
      version: opts.version,
      capturedAt: '2026-08-12T02:46:45.791Z',
      score: 80,
      label: 'unconfirmed',
      // Procedencia por defecto: capturada por el watcher ya arreglado. Los
      // tests que necesitan una captura contaminada la sobreescriben.
      captureReason: 'watcher-threshold',
      engineVersion: '0.3.0',
      doNotExtract: true,
      ...opts.metadata,
    }, null, 2))
  }

  return dir
}

// keyv reconstructed from public reports: a long clean history and a v6.0.0
// that gains preinstall and 24x the size. The .ngpack is the only way to analyse
// it, since npm purged the version.
function makeKeyvPackument(): Packument {
  const versions: Record<string, VersionMeta> = {}
  const time: Record<string, string> = {}

  for (let i = 0; i < 33; i++) {
    const ver = `5.${i}.0`
    const ts = new Date(Date.UTC(2020, 0, 1 + i * 20)).toISOString()
    versions[ver] = {
      version: ver, publishedAt: ts, publishedBy: 'jaredwray',
      unpackedSize: 185_000, hasInstallScript: false, scripts: {},
      dependencies: {}, devDependencies: {}, dist: { tarball: '', integrity: `sha512-${i}` },
    }
    time[ver] = ts
  }

  const maliciousTs = '2026-08-04T09:08:00Z'
  versions['6.0.0'] = {
    version: '6.0.0', publishedAt: maliciousTs, publishedBy: 'jaredwray',
    unpackedSize: 4_500_000, hasInstallScript: true,
    scripts: { preinstall: 'node setup.mjs' },
    dependencies: {}, devDependencies: {}, dist: { tarball: '', integrity: 'sha512-mal' },
  }
  time['6.0.0'] = maliciousTs

  return { name: 'keyv', distTags: { latest: '6.0.0' }, versions, time, maintainers: [] }
}

describe('corpus etiquetado', () => {
  it('a capture with no capture-metadata.json is unconfirmed, not malicious', () => {
    const root = makeTempDir('ng-corpus-a-')
    writeCapture(root, { pkg: 'pisper', version: '0.5.1', packument: makeKeyvPackument(), metadata: null })

    const corpus = loadCorpus([root])
    expect(corpus.samples).toHaveLength(1)
    expect(corpus.samples[0]!.label).toBe('unconfirmed')
    expect(corpus.samples[0]!.labelAssumed).toBe(true)
    expect(corpus.confirmedMalicious).toHaveLength(0)
    expect(corpus.unlabeled).toBe(1)
  })

  it('confirmed_malicious with no labelSource degrades to unconfirmed', () => {
    const root = makeTempDir('ng-corpus-b-')
    writeCapture(root, {
      pkg: 'fantasma', version: '1.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious' },   // sin fuente externa
    })

    const corpus = loadCorpus([root])
    expect(corpus.confirmedMalicious).toHaveLength(0)
    expect(corpus.unconfirmed).toHaveLength(1)
    expect(corpus.unconfirmed[0]!.notes).toContain('no labelSource')
  })

  it('describeCorpusProgress counts captures and confirmed samples separately', () => {
    const root = makeTempDir('ng-corpus-c-')
    writeCapture(root, { pkg: 'a', version: '1.0.0', packument: makeKeyvPackument(), metadata: null })
    writeCapture(root, { pkg: 'b', version: '1.0.0', packument: makeKeyvPackument(), metadata: null })

    expect(describeCorpusProgress(loadCorpus([root])))
      .toBe('corpus building since 2026-08-12: 2 captures, 0 confirmed')
  })

  it('public references without a snapshot are not samples', () => {
    const corpus = loadCorpus([makeTempDir('ng-corpus-d-')])
    const refs = resolveReferences(corpus, KNOWN_ATTACK_REFERENCES)

    expect(refs.length).toBeGreaterThan(0)
    expect(refs.every(r => r.sample === null)).toBe(true)
    // Y no entran en el corpus: un ataque que no se puede analizar no es una
    // muestra que se pueda fallar.
    expect(corpus.confirmedMalicious).toHaveLength(0)
  })
})

describe('capture provenance', () => {
  it('with no captureReason the provenance is unknown, so contaminated', () => {
    expect(classifyContamination(undefined, true).contaminated).toBe(true)
    expect(classifyContamination(undefined, false).contaminated).toBe(true)
    expect(classifyContamination(undefined, false).contaminationReason).toContain('no provenance')
  })

  it('pre-fix-gate-bug marks contamination with its reason', () => {
    const c = classifyContamination(PRE_FIX_REASON, false)
    expect(c.contaminated).toBe(true)
    expect(c.contaminationReason).toContain('gate was broken')
  })

  it('a capture from the fixed watcher is usable', () => {
    expect(classifyContamination('watcher-threshold', false).contaminated).toBe(false)
  })

  it('a confirmed_malicious captured with the broken gate does NOT enter recall', () => {
    const root = makeTempDir('ng-contam-')
    writeCapture(root, {
      pkg: 'captured-by-the-bug', version: '1.0.0', packument: makeKeyvPackument(),
      metadata: {
        label: 'confirmed_malicious',
        labelSource: 'npm advisory real',
        captureReason: PRE_FIX_REASON,
        engineVersion: '0.2.0',
      },
    })
    writeCapture(root, {
      pkg: 'captured-clean', version: '2.0.0', packument: makeKeyvPackument(),
      metadata: {
        label: 'confirmed_malicious',
        labelSource: 'npm advisory real',
        captureReason: 'watcher-threshold',
        engineVersion: '0.3.0',
      },
    })

    const corpus = loadCorpus([root])

    // The label is legitimate in both; what separates them is how they were
    // selected.
    expect(corpus.confirmedMalicious.map(s => s.package)).toEqual(['captured-clean'])
    expect(corpus.confirmedMaliciousContaminated.map(s => s.package)).toEqual(['captured-by-the-bug'])
    expect(corpus.contaminated).toHaveLength(1)

    const report = buildRecallReport(corpus, [
      { package: 'captured-clean', version: '2.0.0', result: null, prediction: 'BLOCK', detected: true },
    ])
    expect(report.confirmedInCorpus).toBe(1)   // no 2
    expect(report.value).toBe(1)

    const contamination = describeContamination(corpus)!
    expect(contamination).toContain('gate was broken')
    expect(contamination).toContain('excluded from recall')
  })

  it('backfill writes provenance only where it is missing, and --dry-run writes nothing', () => {
    const root = makeTempDir('ng-backfill-')
    writeCapture(root, { pkg: 'vieja', version: '1.0.0', packument: makeKeyvPackument(), metadata: null })
    writeCapture(root, {
      pkg: 'ya-marcada', version: '1.0.0', packument: makeKeyvPackument(),
      metadata: { captureReason: 'watcher-threshold', engineVersion: '0.3.0' },
    })

    const dry = backfillCaptureProvenance({
      roots: [root], reason: PRE_FIX_REASON, engineVersion: '0.2.0', dryRun: true,
    })
    expect(dry.filter(r => r.action === 'marked').map(r => r.package)).toEqual(['vieja'])
    expect(dry.filter(r => r.action === 'skipped-has-metadata').map(r => r.package)).toEqual(['ya-marcada'])
    expect(loadCorpus([root]).samples.find(s => s.package === 'vieja')!.captureReason).toBeUndefined()

    backfillCaptureProvenance({ roots: [root], reason: PRE_FIX_REASON, engineVersion: '0.2.0' })

    const corpus = loadCorpus([root])
    const vieja = corpus.samples.find(s => s.package === 'vieja')!
    expect(vieja.captureReason).toBe(PRE_FIX_REASON)
    expect(vieja.engineVersion).toBe('0.2.0')
    expect(vieja.contaminated).toBe(true)

    // Nunca pisa una procedencia ya declarada.
    expect(corpus.samples.find(s => s.package === 'ya-marcada')!.captureReason).toBe('watcher-threshold')
  })

  it('--before excludes what was captured after the cutoff', () => {
    const root = makeTempDir('ng-backfill-cut-')
    writeCapture(root, { pkg: 'antes', version: '1.0.0', packument: makeKeyvPackument(), metadata: null })

    const results = backfillCaptureProvenance({
      roots: [root], reason: PRE_FIX_REASON, engineVersion: '0.2.0',
      before: '2026-08-01T00:00:00.000Z', dryRun: true,
    })
    expect(results[0]!.action).toBe('skipped-after-cutoff')
  })
})

describe('recall', () => {
  it('with 0 confirmed samples it says "not calculable", never "0%"', () => {
    const corpus = loadCorpus([makeTempDir('ng-recall-a-')])
    const report = buildRecallReport(corpus, [])

    expect(report.calculable).toBe(false)
    expect(report.value).toBeNull()
    expect(report.statement).toBe('not calculable, 0 confirmed_malicious samples')
    expect(report.statement).not.toMatch(/\d+([.,]\d+)?\s*%/)
    expect(report.detail).toContain('corpus building since')
  })

  it('with analysed confirmed samples it does calculate, with its interval', () => {
    const root = makeTempDir('ng-recall-b-')
    writeCapture(root, {
      pkg: 'keyv', version: '6.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'npm advisory + Aikido 2026-08-04' },
    })

    const corpus = loadCorpus([root])
    const report = buildRecallReport(corpus, [
      { package: 'keyv', version: '6.0.0', result: null, prediction: 'BLOCK', detected: true },
    ])

    expect(report.calculable).toBe(true)
    expect(report.value).toBe(1)
    expect(report.statement).toContain('1/1 confirmed_malicious')
    expect(report.statement).toContain('95% Wilson CI')
  })

  it('an unreadable snapshot is reported separately, it does not silently raise recall', () => {
    const root = makeTempDir('ng-recall-c-')
    writeCapture(root, {
      pkg: 'keyv', version: '6.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'advisory' },
    })
    writeCapture(root, {
      pkg: 'broken', version: '1.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'advisory' },
    })

    const report = buildRecallReport(loadCorpus([root]), [
      { package: 'keyv', version: '6.0.0', result: null, prediction: 'BLOCK', detected: true },
      { package: 'broken', version: '1.0.0', result: null, error: 'hash no coincide', prediction: 'PASS', detected: false },
    ])

    expect(report.value).toBe(1)              // over what could actually be analysed
    expect(report.conservativeValue).toBe(0.5) // contando el ilegible como fallo
    expect(report.unreadable).toBe(1)
  })

  // With the rule opt-in, every sample of its class is a real miss and recall is
  // a real 0%. That number reads as "the detector does not work" unless it says
  // that the rule it needed was switched off — and that turning it on would not
  // raise it either, because the snapshots cannot feed it.
  it('a 0% measured with the rule off says so, and says what turning it on would not fix', () => {
    const root = makeTempDir('ng-recall-ruleoff-')
    writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0', packument: makeFabricatedPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'npm-takedown: 0.0.1-security' },
    })

    const results = [
      { package: 'fabricado', version: '1.0.0', result: null, prediction: 'PASS' as const, detected: false },
    ]

    const off = buildRecallReport(loadCorpus([root]), results, false)
    expect(off.calculable).toBe(true)
    expect(off.value).toBe(0)
    expect(off.detail).toContain('opt-in and was off')
    expect(off.detail).toContain('decline to judge')

    const on = buildRecallReport(loadCorpus([root]), results, true)
    expect(on.detail).not.toContain('opt-in and was off')
  })
})

describe('false-positive report', () => {
  // Synthetic rows rather than a hand-built ModeSummary: the test walks
  // summarize() -> buildArtifact() -> buildFalsePositiveReport(), which is the
  // real path the number comes out of.
  function syntheticRows(verdicts: Record<string, number>): FpBenchRow[] {
    const rows: FpBenchRow[] = []
    let i = 0
    for (const [verdict, count] of Object.entries(verdicts)) {
      for (let k = 0; k < count; k++) {
        const regime = verdict === 'INSUFFICIENT_HISTORY' ? 'no-genome' : 'genome'
        rows.push({
          package: `p${i++}`, downloads: 1000 - i,
          gate: { verdict, score: 0, regime, signals: [], versions: 30 },
          audit: { verdict, score: 0, regime, signals: [], versions: 30 },
        })
      }
    }
    return rows
  }

  it('prefers a saved fp-bench run over the local corpus', () => {
    const dir = makeTempDir('ng-fp-')
    const rows = syntheticRows({ PASS: 498, BLOCK: 2 })
    const artifact = buildArtifact({
      rows,
      gate: summarize(rows, 'gate'),
      audit: summarize(rows, 'audit'),
      sampling: { mode: 'top', harvestQueries: ['keywords:cli'], poolSize: 2000, top: 500, n: 500 },
      generatedAt: '2026-08-11T10:00:00.000Z',
    })

    // The name carries the engine version: two runs on different engines are
    // not comparable and cannot share a file.
    const version = engineVersion()
    const path = saveArtifact(artifact, dir)
    expect(path).toBe(join(dir, `2026-08-11-v${version}.json`))

    // Second run on the same day: it cannot overwrite the first, or the delta
    // being measured disappears.
    expect(artifactPath(artifact, dir)).toBe(join(dir, `2026-08-11-v${version}-2.json`))

    const saved = JSON.parse(readFileSync(path, 'utf-8'))
    expect(saved.sampling.harvestQueries).toEqual(['keywords:cli'])
    expect(saved.thresholds.gate.blockScore).toBe(70)
    expect(saved.assumptions.join(' ')).toContain('The 500 packages analysed are assumed clean')

    const report = buildFalsePositiveReport({
      mode: 'gate', cleanResults: [], cleanTotal: 11, offline: true, fpResultsDir: dir,
    })

    expect(report.source).toBe('fp-bench')
    expect(report.statement).toBe('0.40% (95% Wilson CI: 0.11%-1.45%, n=500)')
    expect(loadArtifacts(dir)[0]!.artifact.engineVersion).toBeTruthy()
  })

  it('separates "non-PASS" from "unevaluated": distinct categories, neither hidden', () => {
    const dir = makeTempDir('ng-fp-nonpass-')
    // The real shape measured on 2026-08-12: 0 BLOCK, 1 WARN, 130 unjudgeable.
    // INSUFFICIENT_HISTORY no longer breaks the build, so it leaves the cost of
    // adopting the gate. It does not disappear: it is the missing coverage, and
    // it is reported on its own line.
    const rows = syntheticRows({ PASS: 369, BLOCK: 0, WARN: 1, INSUFFICIENT_HISTORY: 130 })
    saveArtifact(buildArtifact({
      rows,
      gate: summarize(rows, 'gate'),
      audit: summarize(rows, 'audit'),
      sampling: { mode: 'stratified', harvestQueries: [], poolSize: 1780, perDecile: 50, n: 500 },
      generatedAt: '2026-08-12T10:00:00.000Z',
    }), dir)

    const report = buildFalsePositiveReport({
      mode: 'gate', cleanResults: [], cleanTotal: 11, offline: true, fpResultsDir: dir,
    })

    expect(report.blocked).toBe(0)
    expect(report.nonPass).toBe(1)              // BLOCK + WARN
    expect(report.insufficientHistory).toBe(130)
    expect(report.n).toBe(500)
    expect(report.statement).toContain('0.20%')
    expect(report.unevaluatedStatement).toContain('26.00%')
    expect(report.breakdown).toContain('BLOCK 0')
    expect(report.breakdown).toContain('exit 1')
    // Lo que rompe el build y lo que no queda escrito en el desglose.
    expect(report.breakdown).toContain('WARN 1 (0.20%, exit 0)')
  })

  it('BLOCK=0 raises a visible alert, not an error', () => {
    // A false-positive benchmark rewards the detector for not firing, so 0
    // blocks reads here as a perfect score, and is indistinguishable from a
    // detector that stopped detecting. The alert exists so nobody has to guess
    // which of the two they are looking at.
    const noBlocks = summarize(syntheticRows({ PASS: 499, WARN: 1 }), 'gate')
    const alert = blockZeroAlert(noBlocks)

    expect(alert.join('\n')).toContain(BLOCK_ZERO_ALERT)
    expect(alert.join('\n')).toContain('gate-drift.test.ts')

    // With a single BLOCK there is no alert.
    expect(blockZeroAlert(summarize(syntheticRows({ PASS: 499, BLOCK: 1 }), 'gate'))).toEqual([])

    // Nor with no sample: 0 of 0 is not drift, it is nothing measured.
    expect(blockZeroAlert(summarize([], 'gate'))).toEqual([])
  })

  it('the alert travels inside the artifact, not only in the terminal', () => {
    const rows = syntheticRows({ PASS: 499, WARN: 1 })
    const artifact = buildArtifact({
      rows,
      gate: summarize(rows, 'gate'),
      audit: summarize(rows, 'audit'),
      sampling: { mode: 'top', harvestQueries: [], poolSize: 1000, top: 500, n: 500 },
      generatedAt: '2026-08-12T10:00:00.000Z',
    })

    expect(artifact.alerts!.some(a => a.startsWith('gate: '))).toBe(true)
    expect(artifact.alerts!.join(' ')).toContain('drift toward passing everything')
  })

  it('summarize reports findings and coverage separately', () => {
    const s = summarize(syntheticRows({ PASS: 369, WARN: 1, INSUFFICIENT_HISTORY: 130 }), 'gate')

    expect(s.blockRate.rate).toBe(0)
    expect(s.warnRate.rate).toBe(1 / 500)
    expect(s.insufficientRate.rate).toBe(130 / 500)

    // no-PASS = hallazgos sobre el paquete (BLOCK + WARN).
    expect(s.nonPassRate.rate).toBe(1 / 500)
    // sin evaluar = lo que el gate no pudo juzgar. Visible, no sumado.
    expect(s.unevaluatedRate.rate).toBe(130 / 500)
    // Y lo que de verdad sale con exit 1 por defecto: solo BLOCK.
    expect(s.buildBreakingRate.rate).toBe(0)

    // El invariante del gate sigue verde: los 130 sin genoma son justamente
    // INSUFFICIENT_HISTORY, no PASS.
    expect(s.regimes.gateEscapes).toBe(0)
  })

  it('with no saved run and no network, it declares that it measured nothing', () => {
    const report = buildFalsePositiveReport({
      mode: 'gate', cleanResults: [], cleanTotal: 11, offline: true,
      fpResultsDir: join(makeTempDir('ng-fp-empty-'), 'does-not-exist'),
    })

    expect(report.source).toBe('no-medido')
    expect(report.rate).toBeNull()
    expect(report.statement).toContain('not measured')
  })
})

describe('runBench offline over the .ngpack corpus', () => {
  it('detects keyv@6.0.0 from the snapshot and reports calculable recall', async () => {
    const root = makeTempDir('ng-bench-')
    writeCapture(root, {
      pkg: 'keyv', version: '6.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'npm advisory + Aikido 2026-08-04' },
    })

    const lines: string[] = []
    const log = console.log
    const write = process.stdout.write
    console.log = (...a: unknown[]) => { lines.push(a.join(' ')) }
    process.stdout.write = ((s: string) => { lines.push(String(s)); return true }) as typeof process.stdout.write

    let summary
    try {
      summary = await runBench({
        mode: 'gate',
        corpusRoots: [root],
        offline: true,
        fpResultsDir: join(root, 'sin-resultados'),
        // Pointed at the temp corpus, not left to default. Otherwise field
        // recall reads the developer's real capture directory — a 22MB log
        // whose contents decide how long this test takes and, in principle,
        // what it asserts.
        captureDir: root,
      })
    } finally {
      console.log = log
      process.stdout.write = write
    }

    expect(summary.recall.calculable).toBe(true)
    expect(summary.recall.value).toBe(1)
    expect(summary.recall.truePositives).toBe(1)

    // Attribution counts only positive signals as a cause.
    expect(summary.bySignal.positive.map(t => t.type).sort())
      .toEqual(['new_install_script', 'size_anomaly'])
    expect(summary.bySignal.negative.map(t => t.type)).toEqual(['long_history'])

    // keyv@6.0.0 is one of the public references and now has a snapshot; the
    // other eight are declared unanalysable, not failures.
    expect(summary.references.withSnapshot).toBe(1)
    expect(summary.references.missing.length).toBe(KNOWN_ATTACK_REFERENCES.length - 1)
    expect(summary.references.missing.map(r => r.package)).not.toContain('keyv')

    const output = lines.join('\n')
    expect(output).toContain('Known public attacks with no snapshot')

    // Offline with no saved runs: no clean package was measured, so the
    // clean-sample assumption does not apply and is not declared as if it did.
    expect(output).toContain('No clean package was analysed')
    expect(output).not.toContain('The 0 packages analysed')

    // Recall at n=1 comes out with an enormous interval, which is exactly what
    // should be visible: one confirmed sample is not a measurement.
    expect(summary.recall.statement).toContain('n=1')
  })

  it('with 0 confirmed samples the output says "not calculable" and prints no recall', async () => {
    const root = makeTempDir('ng-bench-vacio-')
    writeCapture(root, {
      pkg: 'pisper', version: '0.5.1', packument: makeKeyvPackument(), metadata: null,
    })

    const lines: string[] = []
    const log = console.log
    console.log = (...a: unknown[]) => { lines.push(a.join(' ')) }

    let summary
    try {
      summary = await runBench({
        mode: 'gate', corpusRoots: [root], offline: true,
        fpResultsDir: join(root, 'sin-resultados'),
        captureDir: root,
      })
    } finally {
      console.log = log
    }

    expect(summary.recall.calculable).toBe(false)
    expect(summary.recall.value).toBeNull()

    const recallLine = lines.find(l => l.includes('Recall'))!
    expect(recallLine).toContain('not calculable, 0 confirmed_malicious samples')
    expect(recallLine).not.toMatch(/\d+([.,]\d+)?\s*%/)

    expect(lines.join('\n')).toContain('corpus building since 2026-08-12: 1 captures, 0 confirmed')
  })

  it('inspect reads from the .ngpack without touching the network', async () => {
    const root = makeTempDir('ng-inspect-')
    const dir = writeCapture(root, {
      pkg: 'keyv', version: '6.0.0', packument: makeKeyvPackument(),
      metadata: { label: 'confirmed_malicious', labelSource: 'advisory' },
    })

    const result = await inspect('keyv@6.0.0', { mode: 'gate', source: new NgpackSource(dir) })

    expect(result.verdict).toBe('BLOCK')
    expect(result.regime).toBe('genome')
    expect(result.signals.find(s => s.type === 'new_install_script')).toBeDefined()
    expect(result.baselineVersion).toBe('5.32.0')
  })
})

/**
 * Coverage read 4/73 — 5.48% — for two days after four of its own confirmed
 * samples had stopped being in either half of the fraction. Both numbers came
 * from takedowns.json, written by one sweep on 2026-08-12 at 20:43Z; the four
 * packages were captured at 09:27 the next morning, and npm removed them that
 * afternoon. A sweep is a snapshot of an answer, and nothing said when.
 */
describe('takedown coverage counts the evidence that arrived after the sweep', () => {
  function fixture(): string {
    const dir = makeTempDir('ng-coverage-')

    writeFileSync(join(dir, 'takedowns.json'), JSON.stringify({
      sweptAt: '2026-08-12T20:43:58.957Z',
      takenDown: [
        { package: 'vieja-a', observedVersion: '0.0.1-security', observedAt: '2026-08-12T10:00:00Z' },
        { package: 'vieja-b', observedVersion: '1.0.0', observedAt: '2026-08-12T10:00:00Z' },
      ],
      preTakedownObservations: [
        { package: 'vieja-b', observedVersion: '1.0.0', observedAt: '2026-08-12T10:00:00Z' },
      ],
    }))

    // The watcher's own log, written as it saw the removals happen — the day
    // after the sweep ran.
    writeFileSync(join(dir, 'takedown-log.ndjson'),
      [
        { package: 'async-critical-section', seenAt: '2026-08-13T16:19:03Z', purgedVersions: ['1.0.0'] },
        { package: 'mutex-forge', seenAt: '2026-08-13T16:19:27Z', purgedVersions: ['2.0.2'] },
      ].map(r => JSON.stringify(r)).join('\n') + '\n')

    return dir
  }

  const capture = (pkg: string, version: string): CorpusSample => ({
    package: pkg,
    version,
    label: 'confirmed_malicious',
    ngpackPath: `/captures/${pkg}`,
    capturedAt: '2026-08-13T09:27:00Z',
    labelSource: `npm-takedown: 0.0.1-security published over ${pkg}`,
    hasTarball: true,
    labelAssumed: false,
    contaminated: false,
  })

  it('the live log and the labelled captures are in the denominator too', () => {
    const dir = fixture()

    const stale = computeFieldRecall(dir, [])
    // Sweep alone: 2 removals, 1 observed beforehand.
    expect(stale.takedownsFound).toBe(4)   // + the two the watcher logged since
    expect(stale.evidence.sweepTakedowns).toBe(2)
    expect(stale.evidence.liveLogTakedowns).toBe(2)

    const withCaptures = computeFieldRecall(dir, [capture('async-critical-section', '1.0.0')])
    expect(withCaptures.takedownsFound).toBe(4)
    // The capture is an observation of the artifact before the removal, by
    // construction: the bytes are on disk.
    expect(withCaptures.preTakedownObservations).toBe(2)
    expect(withCaptures.evidence.labelledCaptures).toBe(1)
  })

  it('a capture of a package the sweep never saw adds to both halves', () => {
    const dir = fixture()
    const before = computeFieldRecall(dir, [])
    const after = computeFieldRecall(dir, [capture('single-flight-lock', '1.0.0')])

    expect(after.takedownsFound).toBe(before.takedownsFound + 1)
    expect(after.preTakedownObservations).toBe(before.preTakedownObservations + 1)
  })

  it('it says how stale the sweep is instead of presenting it as current', () => {
    const report = computeFieldRecall(fixture(), [])

    expect(report.evidence.sweptAt).toBe('2026-08-12T20:43:58.957Z')
    expect(report.evidence.takedownsAfterSweep).toBe(2)
    expect(report.evidence.staleness).toContain('2026-08-12T20:43:58.957Z')
    expect(report.evidence.staleness).toContain('sweep-takedowns --include-observed')
  })

  it('a capture holding only npm\'s marker is not an observation of anything', () => {
    const dir = fixture()
    const marker: CorpusSample = { ...capture('holder-only', '0.0.1-security') }

    const report = computeFieldRecall(dir, [marker])
    expect(report.evidence.labelledCaptures).toBe(0)
    expect(report.preTakedownObservations).toBe(computeFieldRecall(dir, []).preTakedownObservations)
  })

  it('with no sweep at all it still counts what the watcher saw', () => {
    const dir = makeTempDir('ng-coverage-nosweep-')
    writeFileSync(join(dir, 'takedown-log.ndjson'),
      JSON.stringify({ package: 'algo', seenAt: '2026-08-13T16:19:03Z', purgedVersions: ['1.0.0'] }) + '\n')

    const report = computeFieldRecall(dir, [])
    expect(report.takedownsFound).toBe(1)
    expect(report.evidence.sweptAt).toBe(null)
  })
})

/**
 * A snapshot answers with what it recorded, or it does not answer.
 *
 * The download count is the one input the conjunction needs that an .ngpack
 * cannot reconstruct: npm reports one complete week and that week has moved on.
 * Reading today's count into a verdict about an archived version is bad enough
 * on its own; the packages a snapshot is most often asked about are the ones npm
 * removed, and for those the downloads endpoint answers 404, which the client
 * maps to zero. The fifth condition would hold BECAUSE the package was taken
 * down, and a benchmark whose labels are takedowns would be scoring its own
 * labels.
 */
describe('an .ngpack verdict never reaches for a number it did not capture', () => {
  it('a snapshot with no recorded count reports the rule as unverified, not as cleared', async () => {
    const root = makeTempDir('ng-nodl-')
    const dir = writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0',
      packument: makeFabricatedPackument(),
      metadata: { label: 'unconfirmed' },
    })

    const result = await inspect('fabricado@1.0.0', {
      mode: 'gate',
      source: new NgpackSource(dir),
      config: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: true },
    })

    expect(result.verdict).toBe('INSUFFICIENT_HISTORY')
    expect(result.signals.map(s => s.type)).toContain('fabricated_profile_unverified')
    expect(result.signals.map(s => s.type)).not.toContain('fabricated_package_profile')
  })

  it('a snapshot that recorded the count uses it, and blocks on it', async () => {
    const root = makeTempDir('ng-dl-')
    const dir = writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0',
      packument: makeFabricatedPackument(),
      metadata: {
        label: 'unconfirmed',
        weeklyDownloads: 0,
        downloadWindowEnd: '2026-08-13',
      },
    })

    const result = await inspect('fabricado@1.0.0', {
      mode: 'gate',
      source: new NgpackSource(dir),
      config: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: true },
    })

    expect(result.verdict).toBe('BLOCK')
    expect(result.signals.map(s => s.type)).toContain('fabricated_package_profile')
    // And the verdict is dated to the capture, not to this run.
    expect(result.evaluatedAsOf).toBe(result.source.capturedAt)
  })
})

// The observed class: no history, name minutes old, under 100KB, no repository.
// Published a moment before writeCapture's capturedAt, because the ages are
// measured as of the capture and a version published after it is not young, it
// is impossible.
function makeFabricatedPackument(): Packument {
  const publishedAt = '2026-08-12T02:40:00.000Z'
  return {
    name: 'fabricado',
    distTags: { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        version: '1.0.0',
        publishedAt,
        publishedBy: 'alguien',
        unpackedSize: 3_084,
        hasInstallScript: false,
        scripts: {},
        dependencies: {},
        devDependencies: {},
        dist: { tarball: '', integrity: '' },
      },
    },
    time: { created: publishedAt, '1.0.0': publishedAt },
    maintainers: [{ name: 'alguien', email: 'a@example.com' }],
    createdAt: publishedAt,
    hasReadme: true,
  }
}

/**
 * "Field recall 0/9 blocked by the gate" was produced by a formula that could
 * not return anything else. The collector logs one audit verdict per
 * publication, the gate verdict is reconstructed from it as "BLOCK and a genome
 * existed", and every sample in that list is no-genome — so the fraction was
 * fixed at zero by its own arithmetic, whatever the engine did.
 *
 * The fix is not a better reconstruction. It is a second number, computed by
 * re-running each sample through the engine in this build against the snapshot
 * it was captured from.
 */
describe('field recall is re-graded by the engine that is shipping', () => {
  const sampleOf = (pkg: string, version: string) => ({
    package: pkg,
    version,
    observedAt: '2026-08-12T02:46:45.791Z',
    score: 17,
    regime: 'no-genome' as const,
    auditVerdict: 'PASS',
    auditBlocked: false,
    gateBlocked: false,
  })

  const corpusSample = (pkg: string, version: string, dir: string): CorpusSample => ({
    package: pkg, version, label: 'confirmed_malicious', ngpackPath: dir,
    capturedAt: '2026-08-12T02:46:45.791Z',
    labelSource: 'npm-takedown: 0.0.1-security', hasTarball: true,
    labelAssumed: false, contaminated: false,
  })

  it('a snapshot with no recorded count is held out of the fraction, not counted as a miss', async () => {
    const root = makeTempDir('ng-regrade-nodl-')
    const dir = writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0',
      packument: makeFabricatedPackument(),
      metadata: { label: 'unconfirmed' },
    })

    const r = await regradeWithCurrentEngine(
      [sampleOf('fabricado', '1.0.0')],
      [corpusSample('fabricado', '1.0.0', dir)],
      'gate'
    )

    expect(r.unevaluable).toBe(1)
    expect(r.graded).toBe(0)
    expect(r.blocked).toBe(0)
    expect(r.recall).toBeNull()
    expect(r.statement).toContain('not calculable')
    expect(r.samples[0]!.detail).toContain('download count')
  })

  it('the same sample with the count recorded is blocked by this engine', async () => {
    const root = makeTempDir('ng-regrade-dl-')
    const dir = writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0',
      packument: makeFabricatedPackument(),
      metadata: { label: 'unconfirmed', weeklyDownloads: 0, downloadWindowEnd: '2026-08-13' },
    })

    const r = await regradeWithCurrentEngine(
      [sampleOf('fabricado', '1.0.0')],
      [corpusSample('fabricado', '1.0.0', dir)],
      'gate'
    )

    // Forced on, and it says so. The rule is opt-in, so re-grading under the
    // shipped default could never block anything and the number would say
    // nothing about the rule — which is the only thing it is being asked about.
    expect(r.ruleEnabled).toBe(true)
    expect(DEFAULT_THRESHOLDS.gate.blockFabricatedProfile).toBe(false)

    expect(r.graded).toBe(1)
    expect(r.blocked).toBe(1)
    expect(r.recall!.rate).toBe(1)
    expect(r.statement).toContain('fabricated-profile rule switched on')
    // And the historical verdict survives alongside it: the point is that they
    // disagree, so neither may overwrite the other.
    expect(r.samples[0]!.historicalGateBlocked).toBe(false)
    expect(r.samples[0]!.historicalVerdict).toBe('PASS')
    expect(r.samples[0]!.blocked).toBe(true)
  })

  it('a sample with no snapshot is reported as not re-graded, never as a miss', async () => {
    const r = await regradeWithCurrentEngine([sampleOf('sin-captura', '1.0.0')], [], 'gate')

    expect(r.noSnapshot).toBe(1)
    expect(r.graded).toBe(0)
    expect(r.blocked).toBe(0)
    expect(r.samples[0]!.detail).toContain('no .ngpack')
  })

  it('a contaminated capture is not used to re-grade anything', async () => {
    const root = makeTempDir('ng-regrade-cont-')
    const dir = writeCapture(root, {
      pkg: 'fabricado', version: '1.0.0',
      packument: makeFabricatedPackument(),
      metadata: { label: 'unconfirmed', weeklyDownloads: 0 },
    })

    const r = await regradeWithCurrentEngine(
      [sampleOf('fabricado', '1.0.0')],
      [{ ...corpusSample('fabricado', '1.0.0', dir), contaminated: true }],
      'gate'
    )
    expect(r.noSnapshot).toBe(1)
  })
})

/**
 * bench reported a 0.20% false-positive rate for two days that had been measured
 * on engine v0.3.2 with the fabricated-profile rule switched off, and printed it
 * next to v1.1.0 with the rule on. Nothing in the output said so.
 */
describe('a saved fp-bench run declares how far it is from the engine quoting it', () => {
  const artifact = (over: Partial<FpBenchArtifact> = {}): FpBenchArtifact => ({
    ...buildArtifact({
      rows: [],
      gate: summarize([], 'gate'),
      audit: summarize([], 'audit'),
      sampling: { mode: 'top', harvestQueries: [], poolSize: 0, n: 0 },
      generatedAt: '2026-08-12T00:00:00Z',
    }),
    ...over,
  })

  it('a run from another engine version is called stale by name', () => {
    const lines = artifactStaleness(artifact({ engineVersion: '0.3.2' }), 'gate')
    expect(lines.join(' ')).toContain('v0.3.2')
    expect(lines.join(' ')).toContain(engineVersion())
    expect(lines.join(' ')).toContain('fp-bench')
  })

  // The v0.3.2 artifact records {mode, blockScore} and nothing else. A flag that
  // did not exist cannot have been on, so the run was measured with the rule
  // off — and quoting it beside a build that ships the rule on has to say so.
  it('an artifact that predates the flag is compared against a build that ships the rule on', () => {
    const a = artifact({
      engineVersion: engineVersion(),
      thresholds: {
        gate: { mode: 'gate', blockScore: 70, blockFabricatedProfile: true },
        audit: { mode: 'audit', blockScore: 40, blockFabricatedProfile: true },
      },
    })
    // The saved run had it ON and this build ships it OFF: still a difference,
    // still named.
    expect(artifactStaleness(a, 'gate').join(' ')).toContain('rule ON')

    const predatesFlag = artifact({
      engineVersion: engineVersion(),
      thresholds: {
        gate: { mode: 'gate', blockScore: 70 },
        audit: { mode: 'audit', blockScore: 40 },
      } as unknown as FpBenchArtifact['thresholds'],
    })
    // The shipped default is off, and a run that predates the flag was off too:
    // no difference, so no alarm. The wording is pinned by the ON case above.
    expect(artifactStaleness(predatesFlag, 'gate')).toEqual([])
  })

  it('a change in the block threshold is named too', () => {
    const a = artifact({
      engineVersion: engineVersion(),
      thresholds: {
        ...DEFAULT_THRESHOLDS,
        gate: { ...DEFAULT_THRESHOLDS.gate, blockScore: 50 },
      },
    })
    expect(artifactStaleness(a, 'gate').join(' ')).toContain('blockScore 50')
  })

  it('a run on this engine with this config declares nothing', () => {
    const a = artifact({ engineVersion: engineVersion(), thresholds: DEFAULT_THRESHOLDS })
    expect(artifactStaleness(a, 'gate')).toEqual([])
  })

  // The honest answer to "re-run fp-bench with the rule on": a fresh run is
  // necessary and still cannot measure this rule, because its sampling frame
  // excludes the class the rule fires on.
  it('a download-ranked sample declares that it holds no candidate for the rule', () => {
    const row = (over: Record<string, boolean>) => ({
      package: 'p', downloads: 5000,
      gate: { verdict: 'PASS', score: 0, regime: 'genome', signals: [] },
      audit: { verdict: 'PASS', score: 0, regime: 'genome', signals: [] },
      fabricatedProfile: {
        matches: false,
        localConjuncts: false,
        conjuncts: {
          noGenome: false, youngName: false, tiny: true,
          noRepository: false, zeroDownloads: false, ...over,
        },
      },
    })

    const a = artifact({ engineVersion: engineVersion(), packages: [row({}), row({})] })
    const spots = artifactBlindSpots(a).join(' ')

    expect(spots).toContain('no candidate')
    expect(spots).toContain('0/2 names under seven days old')
    expect(spots).toContain('ranked by')
  })

  it('a sample that does hold candidates declares no blind spot', () => {
    const a = artifact({
      engineVersion: engineVersion(),
      packages: [{
        package: 'p', downloads: 0,
        gate: { verdict: 'PASS', score: 0, regime: 'no-genome', signals: [] },
        audit: { verdict: 'PASS', score: 0, regime: 'no-genome', signals: [] },
        fabricatedProfile: {
          matches: false, localConjuncts: true,
          conjuncts: { noGenome: true, youngName: true, tiny: true, noRepository: true, zeroDownloads: false },
        },
      }],
    })
    expect(artifactBlindSpots(a)).toEqual([])
  })

  it('an artifact with no per-package conjunction says so rather than passing', () => {
    const a = artifact({
      engineVersion: engineVersion(),
      packages: [{
        package: 'p', downloads: 5000,
        gate: { verdict: 'PASS', score: 0, regime: 'genome', signals: [] },
        audit: { verdict: 'PASS', score: 0, regime: 'genome', signals: [] },
      }],
    })
    expect(artifactBlindSpots(a).join(' ')).toContain('does not record the conjunction')
  })
})

/**
 * Two artifacts from the same day and the same engine, one an ablation run: the
 * selection rule was "newest wins", so the ablation saved an hour later took
 * precedence over the run that matched the shipped config, which sat unread on
 * disk beside it. Declaring the mismatch is necessary and is not a substitute
 * for not making it.
 */
describe('bench reads the run that measured this engine, not the newest file', () => {
  const artifactAt = (generatedAt: string, ruleOn: boolean): FpBenchArtifact => ({
    ...buildArtifact({
      rows: [],
      gate: summarize([], 'gate'),
      audit: summarize([], 'audit'),
      sampling: { mode: 'top', harvestQueries: [], poolSize: 0, n: 0 },
      generatedAt,
    }),
    thresholds: {
      gate: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: ruleOn },
      audit: { ...DEFAULT_THRESHOLDS.audit, blockFabricatedProfile: ruleOn },
    },
  })

  const shipped = DEFAULT_THRESHOLDS.gate.blockFabricatedProfile === true

  it('a newer run under a config nobody ships is passed over for one that matches', () => {
    const dir = makeTempDir('ng-fp-select-')
    // The matching run first, the ablation an hour later — the order that broke it.
    writeFileSync(join(dir, 'match.json'), JSON.stringify(artifactAt('2026-08-16T01:15:33Z', shipped)))
    writeFileSync(join(dir, 'ablation.json'), JSON.stringify(artifactAt('2026-08-16T01:49:50Z', !shipped)))

    // Newest by date is the ablation.
    expect(loadArtifacts(dir)[0]!.artifact.generatedAt).toBe('2026-08-16T01:49:50Z')

    const report = buildFalsePositiveReport({
      mode: 'gate', cleanResults: [], cleanTotal: 0, offline: true, fpResultsDir: dir,
    })
    expect(report.sourceDetail).toContain('match.json')
    expect(report.staleness).toEqual([])
  })

  it('with nothing matching it still reports, and says what it is reporting', () => {
    const dir = makeTempDir('ng-fp-select-none-')
    writeFileSync(join(dir, 'only.json'), JSON.stringify(artifactAt('2026-08-16T01:49:50Z', !shipped)))

    const report = buildFalsePositiveReport({
      mode: 'gate', cleanResults: [], cleanTotal: 0, offline: true, fpResultsDir: dir,
    })
    expect(report.source).toBe('fp-bench')
    expect(report.staleness.join(' ')).toContain('fabricated-profile rule')
  })
})
