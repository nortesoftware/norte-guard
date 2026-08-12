/**
 * The absolute-risk branch judges 26% of the ecosystem: the packages with no
 * genome. It used to carry two binary signals, so the score took two values.
 *
 * And the gate liveness proof: BLOCK=0 across 500 packages is an alert, not a
 * victory. What is pinned here is that the gate fires through the real path,
 * with the exit code that fails a build.
 */

import { describe, it, expect } from 'vitest'
import { absoluteRiskSignals, nearestPopularName, osaDistance, provenanceLostSignal } from '../src/absolute-risk.js'
import { POPULAR_PACKAGE_NAMES } from '../src/popular-names.js'
import { score, scoreWithRegime } from '../src/scorer.js'
import { buildGenomeFromPackument } from '../src/genome.js'
import { exitCodeForVerdict } from '../src/output.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'
import type { Packument, VersionMeta } from '../src/packument.js'
import type { PackageGenome } from '../src/types.js'

const NOW = Date.parse('2026-08-12T12:00:00Z')

function meta(overrides: Partial<VersionMeta> = {}): VersionMeta {
  return {
    version: '1.0.0',
    publishedAt: '2026-08-12T11:00:00Z',
    publishedBy: 'alguien',
    unpackedSize: 50_000,
    hasInstallScript: false,
    scripts: {},
    dependencies: {},
    devDependencies: {},
    dist: { tarball: '', integrity: '' },
    ...overrides,
  }
}

function packument(overrides: Partial<Packument> = {}, versionMeta = meta()): Packument {
  return {
    name: 'un-paquete-cualquiera',
    distTags: { latest: versionMeta.version },
    versions: { [versionMeta.version]: versionMeta },
    time: { created: '2026-08-12T11:00:00Z', [versionMeta.version]: versionMeta.publishedAt },
    maintainers: [{ name: 'alguien', email: 'a@b.c' }],
    createdAt: '2026-08-12T11:00:00Z',
    hasReadme: true,
    ...overrides,
  }
}

const typesOf = (signals: { type: string }[]) => signals.map(s => s.type)
const totalOf = (signals: { score: number }[]) => signals.reduce((a, s) => a + s.score, 0)

describe('osaDistance', () => {
  it('counts edits', () => {
    expect(osaDistance('axios', 'axios')).toBe(0)
    expect(osaDistance('axios', 'axio')).toBe(1)
    expect(osaDistance('axios', 'axioss')).toBe(1)
    expect(osaDistance('axios', 'ax1os')).toBe(1)
  })

  it('an adjacent transposition costs 1, not 2: it is the typosquat mistake', () => {
    expect(osaDistance('axios', 'axois')).toBe(1)
    expect(osaDistance('lodash', 'lodahs')).toBe(1)
  })

  it('the bound cuts the computation short without lying about the result', () => {
    expect(osaDistance('abcdefgh', 'zyxwvuts', 2)).toBe(3)   // max + 1
    expect(osaDistance('abc', 'abd', 2)).toBe(1)
  })
})

describe('nearestPopularName', () => {
  const popular = ['express', 'lodash', 'chalk', 'postcss']

  it('a popular package is not a typosquat of itself', () => {
    expect(nearestPopularName('express', popular)).toBeNull()
  })

  it('one edit of distance finds it', () => {
    expect(nearestPopularName('expres', popular)).toEqual({ name: 'express', distance: 1 })
    expect(nearestPopularName('lodahs', popular)).toEqual({ name: 'lodash', distance: 1 })
  })

  it('an unrelated name does not fire', () => {
    expect(nearestPopularName('mi-paquete-privado', popular)).toBeNull()
  })

  it('short names are ignored: they collide with everything', () => {
    expect(nearestPopularName('ms', popular)).toBeNull()
    expect(nearestPopularName('abcd', ['abce'])).toBeNull()
  })

  it('inside a scope the trick is the same', () => {
    expect(nearestPopularName('@malo/postcs', popular)).toEqual({ name: 'postcss', distance: 1 })
    // Pero un scope sobre el nombre exacto no es un typo.
    expect(nearestPopularName('@malo/express', popular)).toBeNull()
  })

  it('works against the real list generated from the artifact', () => {
    expect(POPULAR_PACKAGE_NAMES).toContain('postcss')
    expect(nearestPopularName('postcs')).toEqual({ name: 'postcss', distance: 1 })
  })
})

describe('absoluteRiskSignals', () => {
  it('a well-presented new package barely scores', () => {
    const m = meta({
      repository: { type: 'git', url: 'git+https://github.com/x/y.git' },
      description: 'hace una cosa',
      dist: { tarball: '', integrity: '', attestations: { url: 'https://…' } },
    })
    const p = packument({
      maintainers: [{ name: 'alguien', email: 'a@b.c' }, { name: 'otro', email: 'o@b.c' }],
      createdAt: '2024-01-01T00:00:00Z',
      hasReadme: true,
    }, m)

    const signals = absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })
    const scored = signals.filter(s => s.score !== 0)

    expect(scored).toHaveLength(0)
    // The informational signal is still there: it declares the gap, it does not price it.
    expect(typesOf(signals)).toContain('absolute_account_age_unknown')
    expect(totalOf(signals)).toBe(0)
  })

  it('a new package with no metadata accumulates distinct signals', () => {
    const m = meta()
    const p = packument({ hasReadme: false }, m)

    const signals = absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })
    const types = typesOf(signals)

    expect(types).toContain('absolute_no_repository')
    expect(types).toContain('absolute_no_readme')
    expect(types).toContain('absolute_no_description')
    expect(types).toContain('absolute_package_days_old')
    expect(totalOf(signals)).toBe(7 + 6 + 3 + 10)
  })

  it('the two signals that fire on almost everything score 0 and declare themselves informational', () => {
    // Measured: absolute_no_provenance on 95.6% of packages with no genome and
    // absolute_single_maintainer on 77%. They describe the state of the registry,
    // not the state of this package. No weight makes a near-constant discriminate.
    const m = meta()
    const signals = absoluteRiskSignals({ packument: packument({}, m), currentMeta: m, now: NOW })

    for (const type of ['absolute_no_provenance', 'absolute_single_maintainer']) {
      const signal = signals.find(s => s.type === type)
      expect(signal, type).toBeDefined()
      expect(signal!.score, type).toBe(0)
      expect(signal!.informational, type).toBe(true)
    }
  })

  it('the inverse genome: it had provenance and lost it', () => {
    // Absence of provenance is 95.6% of the registry, so it says nothing.
    // Having had it and lost it means the pipeline that signed stopped signing.
    // An npm credential is enough to publish; the CI that attests is not.
    const signed = meta({
      version: '1.0.0', publishedAt: '2026-01-01T00:00:00Z',
      dist: { tarball: '', integrity: '', attestations: { url: 'https://…' } },
    })
    const unsigned = meta({ version: '1.1.0', publishedAt: '2026-08-12T11:00:00Z' })

    const p: Packument = {
      name: 'perdio-procedencia', distTags: { latest: '1.1.0' },
      versions: { '1.0.0': signed, '1.1.0': unsigned },
      time: { created: '2026-01-01T00:00:00Z', '1.0.0': signed.publishedAt, '1.1.0': unsigned.publishedAt },
      maintainers: [{ name: 'alguien', email: 'a@b.c' }],
      createdAt: '2026-01-01T00:00:00Z', hasReadme: true,
    }

    const signal = provenanceLostSignal(p, '1.1.0')
    expect(signal).not.toBeNull()
    expect(signal!.score).toBe(35)
    expect(signal!.description).toContain('1.0.0')

    // And it replaces the informational signal: the two are not counted together.
    const signals = absoluteRiskSignals({ packument: p, currentMeta: unsigned, now: NOW })
    expect(typesOf(signals)).toContain('provenance_lost')
    expect(typesOf(signals)).not.toContain('absolute_no_provenance')
  })

  it('does not fire if neverSigned never had provenance, nor if stillSigned kept it', () => {
    const base = (o: Partial<VersionMeta>) => meta(o)
    const neverSigned: Packument = {
      name: 'x', distTags: { latest: '1.1.0' },
      versions: {
        '1.0.0': base({ version: '1.0.0', publishedAt: '2026-01-01T00:00:00Z' }),
        '1.1.0': base({ version: '1.1.0', publishedAt: '2026-08-12T11:00:00Z' }),
      },
      time: { '1.0.0': '2026-01-01T00:00:00Z', '1.1.0': '2026-08-12T11:00:00Z' },
      maintainers: [],
    }
    expect(provenanceLostSignal(neverSigned, '1.1.0')).toBeNull()

    const stillSigned: Packument = {
      ...neverSigned,
      versions: {
        '1.0.0': base({ version: '1.0.0', publishedAt: '2026-01-01T00:00:00Z', dist: { tarball: '', integrity: '', attestations: { url: 'u' } } }),
        '1.1.0': base({ version: '1.1.0', publishedAt: '2026-08-12T11:00:00Z', dist: { tarball: '', integrity: '', attestations: { url: 'u' } } }),
      },
    }
    expect(provenanceLostSignal(stillSigned, '1.1.0')).toBeNull()

    // And on the first version there is nothing earlier to compare against.
    expect(provenanceLostSignal(neverSigned, '1.0.0')).toBeNull()
  })

  it('provenance present removes the signal, via attestations or trustedPublisher', () => {
    const withAttestations = meta({ dist: { tarball: '', integrity: '', attestations: { url: 'u' } } })
    const withTrusted = meta({ trustedPublisher: { id: 'github' } })

    for (const m of [withAttestations, withTrusted]) {
      const signals = absoluteRiskSignals({ packument: packument({}, m), currentMeta: m, now: NOW })
      expect(typesOf(signals)).not.toContain('absolute_no_provenance')
    }
  })

  it('publishing from an account that is not a maintainer counts', () => {
    const m = meta({ _npmUser: { name: 'intruso', email: 'i@x.c' } })
    const p = packument({ maintainers: [{ name: 'the-owner', email: 'd@x.c' }] }, m)

    const signal = absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })
      .find(s => s.type === 'absolute_publisher_not_maintainer')

    expect(signal).toBeDefined()
    expect(signal!.score).toBe(18)
    expect(signal!.description).toContain('intruso')
  })

  it('account age is declared as a gap, not approximated', () => {
    const m = meta()
    const signal = absoluteRiskSignals({ packument: packument({}, m), currentMeta: m, now: NOW })
      .find(s => s.type === 'absolute_account_age_unknown')

    expect(signal!.score).toBe(0)
    expect(signal!.informational).toBe(true)
    expect(signal!.description).toContain('401')
  })

  it('dependency age is scored only if the caller paid for it', () => {
    const m = meta({ dependencies: { 'dep-a': '^1', 'dep-b': '^1', 'dep-c': '^1' } })
    const p = packument({}, m)

    const sinDatos = absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })
    expect(typesOf(sinDatos)).toContain('absolute_dep_ages_unchecked')
    expect(sinDatos.find(s => s.type === 'absolute_dep_ages_unchecked')!.score).toBe(0)

    const conDatos = absoluteRiskSignals({
      packument: p, currentMeta: m, now: NOW,
      dependencyAgeDays: { 'dep-a': 2, 'dep-b': 5, 'dep-c': 900 },
    })
    const signal = conDatos.find(s => s.type === 'absolute_deps_mostly_new')
    expect(signal).toBeDefined()
    expect(signal!.description).toContain('2/3')

    // Con dependencias viejas no dispara.
    const viejas = absoluteRiskSignals({
      packument: p, currentMeta: m, now: NOW,
      dependencyAgeDays: { 'dep-a': 900, 'dep-b': 900, 'dep-c': 900 },
    })
    expect(typesOf(viejas)).not.toContain('absolute_deps_mostly_new')
  })

  it('the typosquat enters the score', () => {
    const m = meta()
    const p = packument({ name: 'postcs' }, m)

    const signal = absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })
      .find(s => s.type === 'absolute_typosquat_distance_1')

    expect(signal).toBeDefined()
    expect(signal!.score).toBe(30)
  })

  it('the score is no longer binary: different fixtures give different totals', () => {
    // This was the measured problem: in no-genome the score only took 0 and 20,
    // so no threshold separated anything.
    const fixtures: Array<[string, Packument, VersionMeta]> = []

    const limpio = meta({
      repository: { url: 'git+https://github.com/x/y' }, description: 'd',
      dist: { tarball: '', integrity: '', attestations: { url: 'u' } },
    })
    fixtures.push(['limpio', packument({
      maintainers: [{ name: 'a', email: 'a@x' }, { name: 'b', email: 'b@x' }],
      createdAt: '2020-01-01T00:00:00Z',
    }, limpio), limpio])

    const soloSinRepo = meta({ description: 'd', dist: { tarball: '', integrity: '', attestations: { url: 'u' } } })
    fixtures.push(['sin repo', packument({
      maintainers: [{ name: 'a', email: 'a@x' }, { name: 'b', email: 'b@x' }],
      createdAt: '2020-01-01T00:00:00Z',
    }, soloSinRepo), soloSinRepo])

    const desnudo = meta()
    fixtures.push(['desnudo', packument({ hasReadme: false }, desnudo), desnudo])

    const conScript = meta({ hasInstallScript: true, scripts: { postinstall: 'node x' } })
    fixtures.push(['con script', packument({ hasReadme: false }, conScript), conScript])

    const squat = meta({ hasInstallScript: true, scripts: { postinstall: 'node x' } })
    fixtures.push(['typosquat', packument({ name: 'postcs', hasReadme: false }, squat), squat])

    const totals = fixtures.map(([, p, m]) =>
      totalOf(absoluteRiskSignals({ packument: p, currentMeta: m, now: NOW })))

    expect(new Set(totals).size).toBe(fixtures.length)
    expect(Math.max(...totals)).toBeGreaterThan(Math.min(...totals) + 20)
  })
})

describe('gate liveness proof', () => {
  // 48 versiones limpias y una que gana install script y crece 10x. Es la forma
  // de Shai-Hulud reducida a lo que la capa 1 puede ver.
  function attackedPackument(sizeMultiplier: number): Packument {
    const versions: Record<string, VersionMeta> = {}
    const time: Record<string, string> = { created: '2020-01-01T00:00:00Z' }

    for (let i = 0; i < 15; i++) {
      const ver = `1.${i}.0`
      const ts = new Date(Date.UTC(2020, 0, 1 + i * 30)).toISOString()
      versions[ver] = meta({ version: ver, publishedAt: ts, unpackedSize: 100_000 })
      time[ver] = ts
    }

    const attackTs = '2026-08-04T09:08:00Z'
    versions['2.0.0'] = meta({
      version: '2.0.0',
      publishedAt: attackTs,
      unpackedSize: 100_000 * sizeMultiplier,
      hasInstallScript: true,
      scripts: { preinstall: 'node setup.mjs' },
    })
    time['2.0.0'] = attackTs

    return {
      name: 'paquete-con-historia', distTags: { latest: '2.0.0' },
      versions, time, maintainers: [{ name: 'alguien', email: 'a@b.c' }],
      createdAt: '2020-01-01T00:00:00Z', hasReadme: true,
    }
  }

  const genomeOf = (p: Packument): PackageGenome => ({
    ...buildGenomeFromPackument(p.name, p),
    // The size baseline comes from the history, not from the attacking version.
    sizeBaseline: 100_000,
    publishVelocityBaseline: 1,
  })

  it('EMITS BLOCK: new install script + size anomaly clears the gate threshold', () => {
    // 11x, not 10x: the size threshold is strictly greater than 10, so growth of
    // exactly 10.0x does not fire the signal. That is a decision rather than a
    // bug, but it only becomes visible when the test is written.
    const p = attackedPackument(11)
    const result = scoreWithRegime({
      packument: p, version: '2.0.0', currentMeta: p.versions['2.0.0']!,
      genome: genomeOf(p), config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.regime).toBe('genome')
    expect(result.verdict).toBe('BLOCK')
    expect(result.totalScore).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.gate.blockScore)
    expect(typesOf(result.signals)).toContain('new_install_script')
    expect(typesOf(result.signals)).toContain('size_anomaly')
  })

  it('a BLOCK leaves the process as exit 1, which is what fails the build', () => {
    expect(exitCodeForVerdict('BLOCK')).toBe(1)
    expect(exitCodeForVerdict('WARN')).toBe(0)
    expect(exitCodeForVerdict('PASS')).toBe(0)
  })

  it('INSUFFICIENT_HISTORY does not break the build unless asked to', () => {
    // This was 22.6% of a 500-package sample. A gate that stops one build in
    // five over packages that simply have no baseline is a gate that gets turned
    // off, and its recall is then zero whatever the benchmark says. Lack of
    // context is not evidence of risk.
    expect(exitCodeForVerdict('INSUFFICIENT_HISTORY')).toBe(0)
    expect(exitCodeForVerdict('INSUFFICIENT_HISTORY', {})).toBe(0)

    // Whoever wants the hard behaviour asks for it explicitly.
    expect(exitCodeForVerdict('INSUFFICIENT_HISTORY', { strictNewPackages: true })).toBe(1)

    // And the flag touches nothing else: it does not turn a WARN into a failure.
    expect(exitCodeForVerdict('WARN', { strictNewPackages: true })).toBe(0)
    expect(exitCodeForVerdict('PASS', { strictNewPackages: true })).toBe(0)
    expect(exitCodeForVerdict('BLOCK', { strictNewPackages: true })).toBe(1)
  })

  it('exactlyTen below the threshold is NOT a BLOCK: the gate discriminates rather than always firing', () => {
    // Solo el install script nuevo: 45 pts, por debajo de los 70 del gate.
    const p = attackedPackument(1)
    const result = scoreWithRegime({
      packument: p, version: '2.0.0', currentMeta: p.versions['2.0.0']!,
      genome: genomeOf(p), config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.totalScore).toBe(45)
    expect(result.verdict).toBe('WARN')
    expect(exitCodeForVerdict(result.verdict)).toBe(0)

    // And the exact size boundary: 10.0x is not "> 10".
    const exactlyTen = attackedPackument(10)
    const atTheBoundary = scoreWithRegime({
      packument: exactlyTen, version: '2.0.0', currentMeta: exactlyTen.versions['2.0.0']!,
      genome: genomeOf(exactlyTen), config: DEFAULT_THRESHOLDS.gate,
    })
    expect(typesOf(atTheBoundary.signals)).not.toContain('size_anomaly')
    expect(atTheBoundary.verdict).toBe('WARN')

    // And the same package does block in audit mode: what changes is the
    // threshold, not the evidence.
    const audit = scoreWithRegime({
      packument: p, version: '2.0.0', currentMeta: p.versions['2.0.0']!,
      genome: genomeOf(p), config: DEFAULT_THRESHOLDS.audit,
    })
    expect(audit.verdict).toBe('BLOCK')
  })

  it('with no genome the gate still cannot emit BLOCK, however many signals add up', () => {
    // Un paquete nuevo que dispara casi todo lo absoluto: typosquat, sin
    // metadata, install script. En gate eso es INSUFFICIENT_HISTORY igual.
    const m = meta({
      hasInstallScript: true, scripts: { preinstall: 'node x' },
      unpackedSize: 9_000_000,
      _npmUser: { name: 'intruso', email: 'i@x' },
    })
    const p = packument({ name: 'postcs', hasReadme: false, maintainers: [{ name: 'otro', email: 'o@x' }] }, m)

    const gate = scoreWithRegime({
      packument: p, version: '1.0.0', currentMeta: m,
      genome: buildGenomeFromPackument(p.name, p), config: DEFAULT_THRESHOLDS.gate,
    })

    expect(gate.regime).toBe('no-genome')
    expect(gate.totalScore).toBeGreaterThan(70)
    expect(gate.verdict).toBe('INSUFFICIENT_HISTORY')
    expect(gate.verdict).not.toBe('BLOCK')

    // In audit, which a person reads, the same package does warn.
    const audit = scoreWithRegime({
      packument: p, version: '1.0.0', currentMeta: m,
      genome: buildGenomeFromPackument(p.name, p), config: DEFAULT_THRESHOLDS.audit,
    })
    expect(audit.verdict).toBe('WARN')
  })

  it('score() in the genome regime does not drag in absolute signals', () => {
    const p = attackedPackument(10)
    const result = score({
      packument: p, version: '2.0.0', currentMeta: p.versions['2.0.0']!,
      genome: genomeOf(p), config: DEFAULT_THRESHOLDS.gate,
    })

    expect(typesOf(result.signals).some(t => t.startsWith('absolute_'))).toBe(false)
  })
})
