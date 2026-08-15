/**
 * Tests over REAL samples reconstructed through MockSource.
 *
 * 7/7 green over a circular MockSource proves nothing. Here MockSource emits
 * the DOCUMENTED state of keyv before and after the attack, based on public
 * reports from Aikido, Socket and Chainguard.
 *
 * We do not have the real tarball, it was purged. We have the real packument
 * with the fields that determine the verdict, which is enough for v1.
 *
 * The honest note belongs in the test: this is "reconstructed from public
 * reports", not "captured from the live registry". The .ngpack fixes that as
 * soon as a mirror carrying keyv@6.0.0 turns up.
 */

import { describe, it, expect } from 'vitest'
import { score } from '../src/scorer.js'
import { buildGenome, extractCapabilities } from '../src/genome.js'
import { detectGhostVersions, classifyGhostReversion } from '../src/genome.js'
import {
  detectCampaigns,
  detectFabricatedFamilies,
  publishingEntity,
  mergeCampaign,
  type CampaignSignal,
} from '../src/ecosystem.js'
import {
  parseRssItems,
  selectFreshItems,
  computeWindowOverlap,
  feedItemKey,
  type FeedItem,
} from '../src/watcher.js'
import { MockSource } from '../src/ngpack.js'
import type { Packument } from '../src/packument.js'
import type { VersionMeta } from '../src/packument.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'

// Fixture: reconstructed keyv
// Basado en: Aikido (2026-08-04), Socket, Chainguard, Microsoft
// keyv siempre fue un paquete de cache simple.
// v6.0.0 was the malicious version npm purged on 2026-08-04.

function makeVersionMeta(overrides: Partial<VersionMeta>): VersionMeta {
  return {
    version: '1.0.0',
    publishedAt: '2020-01-01T00:00:00Z',
    publishedBy: 'jaredwray',
    unpackedSize: 185_000,  // ~185KB, keyv's historical size
    hasInstallScript: false,
    scripts: {},
    dependencies: {},
    devDependencies: {},
    dist: { tarball: '', integrity: '' },
    ...overrides,
  }
}

// Clean historical versions of keyv (public packument data)
function makeCleanKeyvPackument(): Packument {
  const versions: Record<string, VersionMeta> = {}
  const time: Record<string, string> = {}

  // ~48 historical versions, none with an install script
  const historicalVersions = [
    '4.0.0', '4.0.1', '4.0.2', '4.1.0', '4.1.1',
    '4.2.0', '4.2.1', '4.2.2', '4.2.3', '4.2.4',
    '5.0.0', '5.0.1', '5.0.2', '5.0.3', '5.0.4',
    '5.1.0', '5.1.1', '5.1.2', '5.1.3', '5.1.4',
    '5.2.0', '5.2.1', '5.2.2', '5.2.3', '5.2.4',
    '5.3.0', '5.3.1', '5.4.0', '5.5.0', '5.5.1',
    '5.5.2', '5.5.3', '5.6.0',  // latest limpio
  ]

  historicalVersions.forEach((ver, i) => {
    const date = new Date(2020, 0, 1)
    date.setMonth(date.getMonth() + Math.floor(i / 3))
    date.setDate(date.getDate() + (i % 3) * 10)
    const ts = date.toISOString()

    versions[ver] = makeVersionMeta({
      version: ver,
      publishedAt: ts,
      unpackedSize: 180_000 + Math.random() * 10_000,
      hasInstallScript: false,
    })
    time[ver] = ts
  })

  return {
    name: 'keyv',
    distTags: { latest: '5.6.0' },
    versions,
    time,
    maintainers: [{ name: 'jaredwray', email: 'jaredwray@gmail.com' }],
  }
}

// The malicious version: keyv@6.0.0. It gained preinstall and 25x the size,
// published 8 minutes after 5.9.0 (reconstructed from public reports).
function makeMaliciousKeyvPackument(): Packument {
  const clean = makeCleanKeyvPackument()

  const maliciousVersion = makeVersionMeta({
    version: '6.0.0',
    publishedAt: '2026-08-04T09:08:00Z',  // 8 min after "5.9.0"
    publishedBy: 'jaredwray',  // cuenta comprometida
    unpackedSize: 4_500_000,   // 25x the history: setup.mjs + Math_Symbol.js
    hasInstallScript: true,
    scripts: {
      preinstall: 'node setup.mjs',  // el vector del ataque
    },
  })

  return {
    ...clean,
    distTags: { latest: '6.0.0' },
    versions: {
      ...clean.versions,
      '6.0.0': maliciousVersion,
    },
    time: {
      ...clean.time,
      '6.0.0': '2026-08-04T09:08:00Z',
    },
  }
}

describe('scorer: clean package', () => {
  it('clean lodash passes with no anomalies', async () => {
    const { fetchPackument } = await import('../src/packument.js')
    // Solo correr si hay red — skipear en CI offline
    if (process.env['NORTE_GUARD_OFFLINE']) return

    const packument = await fetchPackument('lodash')
    const versions = Object.keys(packument.versions)
    const latest = packument.versions[versions[versions.length - 1]]
    const genome = await buildGenome('lodash')

    const result = score({
      packument,
      version: latest.version,
      currentMeta: latest,
      genome,
      config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.verdict).toBe('PASS')
    expect(result.totalScore).toBeLessThan(DEFAULT_THRESHOLDS.gate.blockScore)
  })
})

describe('scorer: keyv@6.0.0 reconstructed (Shai-Hulud)', () => {
  // These tests use data RECONSTRUCTED from public reports. The real tarball
  // was purged from npm. The reconstruction is faithful to the fields that
  // determine the v1 verdict.
  // Sources: Aikido (2026-08-04), Socket, Chainguard, Microsoft.

  it('detects the malicious version with score > 70', () => {
    const packument = makeMaliciousKeyvPackument()
    const maliciousVersion = packument.versions['6.0.0']
    const prevVersion = packument.versions['5.6.0']

    expect(maliciousVersion).toBeDefined()
    expect(prevVersion).toBeDefined()

    // Construir genome desde el packument simulado
    const allVersions = Object.values(packument.versions)
      .sort((a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime())

    const stableCaps = extractCapabilities(prevVersion!)

    const genome = {
      package: 'keyv',
      computedAt: new Date().toISOString(),
      versionsAnalyzed: allVersions.length,
      stableCapabilities: [...stableCaps] as import('../src/types.js').Capability[],
      capabilityHistory: [],
      sizeBaseline: 185_000,
      publishVelocityBaseline: 0.05,  // ~1 version every 3 weeks
      isMonorepo: false,
      batchPeers: [],
    }

    const result = score({
      packument,
      version: '6.0.0',
      currentMeta: maliciousVersion!,
      genome,
      config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.verdict).toBe('BLOCK')
    expect(result.totalScore).toBeGreaterThan(DEFAULT_THRESHOLDS.gate.blockScore)

    // Debe detectar el install script nuevo
    const installSignal = result.signals.find(s => s.type === 'new_install_script')
    expect(installSignal).toBeDefined()
    expect(installSignal!.isHistorical).toBe(false)

    // It must detect the size anomaly (25x)
    const sizeSignal = result.signals.find(s => s.type === 'size_anomaly')
    expect(sizeSignal).toBeDefined()
  })

  it('the clean 5.6.0 passes', () => {
    const packument = makeCleanKeyvPackument()
    const latest = packument.versions['5.6.0']!

    const genome = {
      package: 'keyv',
      computedAt: new Date().toISOString(),
      versionsAnalyzed: Object.keys(packument.versions).length,
      stableCapabilities: [] as import('../src/types.js').Capability[],
      capabilityHistory: [],
      sizeBaseline: 185_000,
      publishVelocityBaseline: 0.05,
      isMonorepo: false,
      batchPeers: [],
    }

    const result = score({
      packument,
      version: '5.6.0',
      currentMeta: latest,
      genome,
      config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.verdict).toBe('PASS')
    expect(result.totalScore).toBeLessThan(DEFAULT_THRESHOLDS.gate.blockScore)
  })
})

describe('campaign detection — genoma invertido', () => {
  it('detects a coordinated campaign with a per-package relative rate', () => {
    // Simula 5 paquetes de mantenedores distintos, cada uno ganando
    // un install script por primera vez en su historia

    function makePackumentWithNewScript(name: string, maintainer: string): Packument {
      const versions: Record<string, VersionMeta> = {}
      const time: Record<string, string> = {}

      // 10 historical versions with no script
      for (let i = 0; i < 10; i++) {
        const ver = `1.${i}.0`
        const ts = new Date(2024, i, 1).toISOString()
        versions[ver] = makeVersionMeta({
          version: ver,
          publishedAt: ts,
          publishedBy: maintainer,
          hasInstallScript: false,
        })
        time[ver] = ts
      }

      // A new version with an install script NOW
      const now = new Date().toISOString()
      versions['2.0.0'] = makeVersionMeta({
        version: '2.0.0',
        publishedAt: now,
        publishedBy: maintainer,
        hasInstallScript: true,
        scripts: { preinstall: 'node setup.js' },
        unpackedSize: 2_000_000,  // 10x the history
      })
      time['2.0.0'] = now

      return {
        name,
        distTags: { latest: '2.0.0' },
        versions,
        time,
        maintainers: [{ name: maintainer, email: `${maintainer}@example.com` }],
      }
    }

    const packuments = [
      makePackumentWithNewScript('pkg-alpha',   'maintainer-a'),
      makePackumentWithNewScript('pkg-beta',    'maintainer-b'),
      makePackumentWithNewScript('pkg-gamma',   'maintainer-c'),
      makePackumentWithNewScript('pkg-delta',   'maintainer-d'),
      makePackumentWithNewScript('pkg-epsilon', 'maintainer-e'),
    ]

    const signals = detectCampaigns(packuments, 60)

    // It must detect a coordinated campaign
    expect(signals.length).toBeGreaterThan(0)

    const campaignSignal = signals.find(s =>
      s.type === 'coordinated_capability_gain' ||
      s.type === 'velocity_burst'
    )
    expect(campaignSignal).toBeDefined()
    expect(campaignSignal!.packages.length).toBeGreaterThanOrEqual(3)
  })

  it('does NOT fire for a legitimate same-maintainer monorepo', () => {
    // TanStack: muchos paquetes del mismo mantenedor
    function makeMonorepoPackage(name: string): Packument {
      const versions: Record<string, VersionMeta> = {}
      const time: Record<string, string> = {}

      for (let i = 0; i < 20; i++) {
        const ver = `1.${i}.0`
        const ts = new Date(2024, Math.floor(i / 2), 1).toISOString()
        versions[ver] = makeVersionMeta({
          version: ver,
          publishedAt: ts,
          publishedBy: 'tanstack',
          hasInstallScript: false,
        })
        time[ver] = ts
      }

      const now = new Date().toISOString()
      versions['2.0.0'] = makeVersionMeta({
        version: '2.0.0',
        publishedAt: now,
        publishedBy: 'tanstack',  // MISMO mantenedor
        hasInstallScript: false,  // sin script nuevo
      })
      time['2.0.0'] = now

      return { name, distTags: { latest: '2.0.0' }, versions, time,
               maintainers: [{ name: 'tanstack', email: 'hi@tanstack.com' }] }
    }

    const packuments = [
      makeMonorepoPackage('@tanstack/query-core'),
      makeMonorepoPackage('@tanstack/react-query'),
      makeMonorepoPackage('@tanstack/vue-query'),
    ]

    const signals = detectCampaigns(packuments, 60)

    // No new capabilities means no campaign signal
    expect(signals.length).toBe(0)
  })
})

// A low versionsAnalyzed and a sizeBaseline equal to makeVersionMeta's, so that
// neither long_history nor size_anomaly sneaks in and dirties the assertion.

function makeQuietGenome(pkg: string) {
  return {
    package: pkg,
    computedAt: new Date().toISOString(),
    versionsAnalyzed: 5,
    stableCapabilities: [] as import('../src/types.js').Capability[],
    capabilityHistory: [],
    sizeBaseline: 185_000,
    publishVelocityBaseline: 0.05,
    isMonorepo: false,
    batchPeers: [],
  }
}

function makeTwoVersionPackument(
  name: string,
  prev: Partial<VersionMeta>,
  next: Partial<VersionMeta>
): Packument {
  const a = makeVersionMeta({ version: '1.0.0', publishedAt: '2024-01-01T00:00:00Z', ...prev })
  const b = makeVersionMeta({ version: '1.1.0', publishedAt: '2024-06-01T00:00:00Z', ...next })

  return {
    name,
    distTags: { latest: '1.1.0' },
    versions: { '1.0.0': a, '1.1.0': b },
    time: { '1.0.0': a.publishedAt, '1.1.0': b.publishedAt },
    maintainers: [{ name: 'someone', email: 'someone@example.com' }],
  }
}

describe('entrypoint_changed signal: the exports/main/browser delta', () => {
  it('fires when exports points at another file', async () => {
    const packument = makeTwoVersionPackument('pkg-entrypoint',
      { exports: { types: './index.d.ts', default: './index.js' } },
      { exports: { types: './index.d.ts', default: './payload.js' } },
    )

    // Through MockSource: the analysis must not touch the network to reach a verdict.
    const source = new MockSource({ 'pkg-entrypoint': packument })
    const fetched = await source.fetchPackument('pkg-entrypoint')

    const result = score({
      packument: fetched,
      version: '1.1.0',
      currentMeta: fetched.versions['1.1.0']!,
      genome: makeQuietGenome('pkg-entrypoint'),
      config: DEFAULT_THRESHOLDS.gate,
    })

    const signal = result.signals.find(s => s.type === 'entrypoint_changed')
    expect(signal).toBeDefined()
    expect(signal!.surface).toBe('import_time')
    expect(signal!.isHistorical).toBe(false)
    expect(signal!.description).toContain('payload.js')
  })

  it('does NOT fire if only the order of the exports keys changes', () => {
    // The regression that matters: key order in a packument depends on the
    // publisher's JSON, so an identical exports reordered is not a change.
    const packument = makeTwoVersionPackument('pkg-reorder',
      { exports: { types: './index.d.ts', default: './index.js' } },
      { exports: { default: './index.js', types: './index.d.ts' } },
    )

    const result = score({
      packument,
      version: '1.1.0',
      currentMeta: packument.versions['1.1.0']!,
      genome: makeQuietGenome('pkg-reorder'),
      config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.signals.find(s => s.type === 'entrypoint_changed')).toBeUndefined()
  })

  it('fires when main appears or disappears', () => {
    const packument = makeTwoVersionPackument('pkg-main',
      { main: './lib/index.js' },
      { main: undefined },
    )

    const result = score({
      packument,
      version: '1.1.0',
      currentMeta: packument.versions['1.1.0']!,
      genome: makeQuietGenome('pkg-main'),
      config: DEFAULT_THRESHOLDS.gate,
    })

    const signal = result.signals.find(s => s.type === 'entrypoint_changed')
    expect(signal).toBeDefined()
    expect(signal!.description).toContain('main')
  })

  it('does NOT fire when the three fields stay the same', () => {
    const packument = makeTwoVersionPackument('pkg-estable',
      { main: './index.js' },
      { main: './index.js' },
    )

    const result = score({
      packument,
      version: '1.1.0',
      currentMeta: packument.versions['1.1.0']!,
      genome: makeQuietGenome('pkg-estable'),
      config: DEFAULT_THRESHOLDS.gate,
    })

    expect(result.signals.find(s => s.type === 'entrypoint_changed')).toBeUndefined()
  })
})

describe('classifyGhostReversion: rollback vs patch', () => {
  // The ghost exists in time{} but not in versions{}: it was published and
  // withdrawn. It cannot be downloaded, so the classification comes from the
  // number of the version that replaced it. The integrity parameters are still
  // here to prove they no longer matter: comparing hashes of two different
  // releases classified 100% of the real cases as "patch".
  function makeGhostPackument(beforeIntegrity: string, afterIntegrity: string): Packument {
    const before = makeVersionMeta({
      version: '1.0.0', publishedAt: '2026-01-01T00:00:00Z',
      dist: { tarball: '', integrity: beforeIntegrity },
    })
    const after = makeVersionMeta({
      version: '1.2.0', publishedAt: '2026-01-03T00:00:00Z',
      dist: { tarball: '', integrity: afterIntegrity },
    })

    return {
      name: 'pkg-ghost',
      distTags: { latest: '1.2.0' },
      versions: { '1.0.0': before, '1.2.0': after },
      time: {
        '1.0.0': '2026-01-01T00:00:00Z',
        '1.1.0': '2026-01-02T00:00:00Z',   // el fantasma: sin entrada en versions{}
        '1.2.0': '2026-01-03T00:00:00Z',
      },
      maintainers: [{ name: 'someone', email: 'someone@example.com' }],
    }
  }

  it('detects the ghost in time{} with no entry in versions{}', () => {
    const ghosts = detectGhostVersions(makeGhostPackument('sha512-AAA', 'sha512-BBB'))
    expect(ghosts.map(g => g.version)).toEqual(['1.1.0'])
  })

  it('the replacement advances the number, so patch, with equal or different integrity', () => {
    // 1.2.0 reemplaza al fantasma 1.1.0: hacia delante. El integrity de los
    // neighbours no longer enters the decision, so both cases give the same.
    for (const [a, b] of [['sha512-IGUAL', 'sha512-IGUAL'], ['sha512-ANTES', 'sha512-DESPUES']]) {
      const rev = classifyGhostReversion(makeGhostPackument(a!, b!), '1.1.0')
      expect(rev.kind).toBe('patch')
      expect(rev.before).toBe('1.0.0')
      expect(rev.after).toBe('1.2.0')
    }
  })

  it('the replacement moves the number back, so rollback', () => {
    const p = makeGhostPackument('sha512-A', 'sha512-B')
    // The publisher withdraws 1.1.0 and returns to 1.0.1: they backed out.
    p.versions['1.0.1'] = makeVersionMeta({
      version: '1.0.1', publishedAt: '2026-01-03T00:00:00Z',
      dist: { tarball: '', integrity: 'sha512-C' },
    })
    p.time['1.0.1'] = '2026-01-03T00:00:00Z'
    delete p.versions['1.2.0']
    delete p.time['1.2.0']

    const rev = classifyGhostReversion(p, '1.1.0')
    expect(rev.kind).toBe('rollback')
    expect(rev.after).toBe('1.0.1')
  })

  it('skips neighbours that are also ghosts', () => {
    const p = makeGhostPackument('sha512-A', 'sha512-A')
    // Dos fantasmas consecutivos: 1.1.0 y 1.1.5, ninguno en versions{}.
    p.time['1.1.5'] = '2026-01-02T12:00:00Z'

    const forward = classifyGhostReversion(p, '1.1.0')
    expect(forward.before).toBe('1.0.0')
    expect(forward.after).toBe('1.2.0')

    const backward = classifyGhostReversion(p, '1.1.5')
    expect(backward.before).toBe('1.0.0')
    expect(backward.after).toBe('1.2.0')
    expect(backward.kind).toBe('patch')
  })

  it('with nothing earlier it is still classifiable: only the replacement decides', () => {
    const p = makeGhostPackument('sha512-A', 'sha512-B')
    // The ghost becomes the oldest thing there is. The previous version is
    // context rather than evidence, so its absence does not prevent classifying.
    p.time['0.9.0'] = '2025-01-01T00:00:00Z'
    delete p.time['1.0.0']
    delete p.versions['1.0.0']

    const rev = classifyGhostReversion(p, '0.9.0')
    expect(rev.before).toBeNull()
    expect(rev.after).toBe('1.2.0')
    expect(rev.kind).toBe('patch')
  })

  it('with no replacement it does not classify', () => {
    const p = makeGhostPackument('sha512-A', 'sha512-B')
    // A ghost later than everything that exists: nothing has replaced it yet.
    p.time['9.0.0'] = '2026-06-01T00:00:00Z'

    const rev = classifyGhostReversion(p, '9.0.0')
    expect(rev.kind).toBe('unknown')
    expect(rev.after).toBeNull()
  })

  it('a version absent from time{} is unknown', () => {
    const rev = classifyGhostReversion(makeGhostPackument('a', 'b'), '9.9.9')
    expect(rev.kind).toBe('unknown')
  })
})

describe('watcher coverage: feed parsing and gap detection', () => {
  const RSS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title><![CDATA[@scope/segundo]]></title>
    <pubDate>Tue, 11 Aug 2026 09:52:38 GMT</pubDate>
  </item>
  <item>
    <title><![CDATA[primero]]></title>
    <pubDate>Tue, 11 Aug 2026 09:52:20 GMT</pubDate>
  </item>
</channel></rss>`

  it('extracts names wrapped in CDATA, scoped ones included', () => {
    const items = parseRssItems(RSS)
    expect(items.map(i => i.name)).toEqual(['@scope/segundo', 'primero'])
    expect(items.every(i => i.publishedMs > 0)).toBe(true)
  })

  it('document order is NOT chronological, so it has to be sorted', () => {
    const items = parseRssItems(RSS)
    // As they arrive, the first in the document is the newest.
    expect(items[0]!.publishedMs).toBeGreaterThan(items[1]!.publishedMs)

    const sorted = [...items].sort((a, b) => a.publishedMs - b.publishedMs)
    expect(sorted[0]!.name).toBe('primero')
  })

  it('selectFreshItems discards anything before the watermark', () => {
    const items = parseRssItems(RSS)
    const newest = Math.max(...items.map(i => i.publishedMs))

    const fresh = selectFreshItems(items, newest, new Map())
    expect(fresh.map(i => i.name)).toEqual(['@scope/segundo'])
  })

  it('selectFreshItems discards what is already processed even if it falls in the window', () => {
    const items = parseRssItems(RSS)
    const seen = new Map([[feedItemKey(items[0]!), items[0]!.publishedMs]])

    const fresh = selectFreshItems(items, 0, seen)
    expect(fresh.map(i => i.name)).toEqual(['primero'])
  })

  it('a real republication of the same package is NOT deduplicated', () => {
    const items = parseRssItems(RSS)
    const seen = new Map([[feedItemKey(items[0]!), items[0]!.publishedMs]])

    // Same name, different timestamp: another publication, and it must be analysed.
    const republished: FeedItem = { ...items[0]!, publishedMs: items[0]!.publishedMs + 60_000 }
    const fresh = selectFreshItems([republished], 0, seen)
    expect(fresh).toHaveLength(1)
  })

  it('zero overlap between windows is a coverage gap', () => {
    const previous = new Set(['a', 'b', 'c'])
    const current = new Set(['x', 'y', 'z'])

    const { overlap, rolledOver } = computeWindowOverlap(previous, current)
    expect(overlap).toBe(0)
    expect(rolledOver).toBe(true)
  })

  it('the first poll cannot be a gap: there is no previous window', () => {
    const { overlap, rolledOver } = computeWindowOverlap(new Set(), new Set(['a', 'b']))
    expect(overlap).toBe(0)
    expect(rolledOver).toBe(false)
  })

  it('with partial overlap there is no gap', () => {
    const previous = new Set(['a', 'b', 'c'])
    const current = new Set(['c', 'd', 'e'])

    const { overlap, rolledOver } = computeWindowOverlap(previous, current)
    expect(overlap).toBe(1)
    expect(rolledOver).toBe(false)
  })
})

/**
 * The campaign this collector captured and its own detector could not see.
 *
 * async-critical-section@1.0.0, keyed-mutex-map@2.1.2, resource-lease-pool@1.4.2,
 * single-flight-lock@1.0.0 and try-lock-runner@3.2.1: five first publications
 * from one account inside four minutes, each 3-4KB with no repository, each
 * depending on mutex-forge — published two days earlier and removed alongside
 * them. npm published 0.0.1-security over all six, plus async-lock-queue,
 * lock-deadline-guard and priority-mutex-lane, seven hours after the first.
 *
 * The fields below are the ones on disk in the captures, not invented.
 */
describe('fabricated families — the campaign with no history to be anomalous against', () => {
  const PUBLISHED = '2026-08-13T09:27:00.000Z'
  const NOW = Date.parse('2026-08-13T09:35:00.000Z')

  function newPackage(overrides: {
    name: string
    version?: string
    publishedBy?: string
    minutesAfter?: number
    unpackedSize?: number
    dependencies?: Record<string, string>
    repository?: unknown
  }): Packument {
    const publishedAt = new Date(Date.parse(PUBLISHED) + (overrides.minutesAfter ?? 0) * 60_000).toISOString()
    const version = overrides.version ?? '1.0.0'

    return {
      name: overrides.name,
      distTags: { latest: version },
      versions: {
        [version]: makeVersionMeta({
          version,
          publishedAt,
          publishedBy: overrides.publishedBy ?? 'javonayers999',
          unpackedSize: overrides.unpackedSize ?? 3_084,
          dependencies: overrides.dependencies ?? { 'mutex-forge': '^2.0.2' },
          repository: overrides.repository,
          scripts: { test: 'node test.js' },
        }),
      },
      time: { created: publishedAt, [version]: publishedAt },
      maintainers: [{ name: overrides.publishedBy ?? 'javonayers999', email: 'x@example.com' }],
      createdAt: publishedAt,
      hasReadme: true,
    }
  }

  const lockFamily = () => [
    newPackage({ name: 'async-critical-section', version: '1.0.0', minutesAfter: 0 }),
    newPackage({ name: 'keyed-mutex-map', version: '2.1.2', minutesAfter: 0.4, unpackedSize: 4_010 }),
    newPackage({ name: 'resource-lease-pool', version: '1.4.2', minutesAfter: 2.4, unpackedSize: 3_825 }),
    newPackage({ name: 'single-flight-lock', version: '1.0.0', minutesAfter: 3.9, unpackedSize: 3_578 }),
    newPackage({ name: 'try-lock-runner', version: '3.2.1', minutesAfter: 4.3, unpackedSize: 3_517 }),
  ]

  it('the old detector is blind to it: nothing here has a history to be anomalous against', () => {
    const genomeOnly = detectCampaigns(lockFamily(), 60, NOW)
      .filter(s => s.type !== 'fabricated_family')

    expect(
      genomeOnly,
      'a capability-delta rule fired on packages whose only version IS the delta'
    ).toEqual([])
  })

  it('the no-genome mode catches all five, and names what tied them together', () => {
    const signals = detectFabricatedFamilies(lockFamily(), 60, NOW)

    expect(signals).toHaveLength(1)
    const family = signals[0]!

    expect(family.packages.sort()).toEqual([
      'async-critical-section@1.0.0',
      'keyed-mutex-map@2.1.2',
      'resource-lease-pool@1.4.2',
      'single-flight-lock@1.0.0',
      'try-lock-runner@3.2.1',
    ])
    expect(family.entities).toHaveLength(5)
    // The maintainer and the shared fresh dependency are what carry this case.
    // The five names share no token at all, so a rule built on repeated
    // substrings alone would have linked try-lock-runner to single-flight-lock
    // and missed the other three.
    expect(family.linkedBy).toContain('maintainer')
    expect(family.linkedBy).toContain('dependency')
  })

  it('a shared dependency only links when it is a rare one', () => {
    // The same shape, but the dependency everything in this class depends on:
    // zod is in 10.83% of the captures on disk, mutex-forge in 0.13%.
    const mcpServers = [
      newPackage({ name: 'ascend-mcp', publishedBy: 'a', dependencies: { zod: '^3' } }),
      newPackage({ name: 'mysql-mcp-server', publishedBy: 'b', dependencies: { zod: '^3' } }),
      newPackage({ name: 'hugging-mcp', publishedBy: 'c', dependencies: { zod: '^3' } }),
    ]

    expect(detectFabricatedFamilies(mcpServers, 60, NOW)).toEqual([])
  })

  it('a monorepo publishing new packages in a batch is one party, not seven', () => {
    // fwork-jsts-*: one account, no repository field, six names sharing "fwork"
    // — a token in 6 of 41,356 observed names. Counted as six they cleared every
    // threshold; collapsed by prefix they are one.
    const monorepo = ['common', 'db', 'server', 'browser', 'test', 'react-mui-ext'].map((part, i) =>
      newPackage({
        name: `fwork-${part}`,
        publishedBy: 'joabssilveira',
        minutesAfter: i,
        dependencies: { 'fwork-jsts-common': '^2.0.0' },
      })
    )

    const signals = detectFabricatedFamilies(monorepo, 60, NOW)
    expect(signals, 'a monorepo batch was reported as a campaign').toEqual([])

    const peers = monorepo.map(m => ({ name: m.name, maintainer: 'joabssilveira' }))
    expect(new Set(monorepo.map(p =>
      publishingEntity(p.name, Object.values(p.versions)[0], 'joabssilveira', peers)
    ))).toEqual(new Set(['prefix:fwork']))
  })

  it('a scope is a declared identity and collapses too', () => {
    const scoped = ['a', 'b', 'c', 'd'].map((part, i) =>
      newPackage({ name: `@acme/${part}`, publishedBy: 'acme-bot', minutesAfter: i })
    )
    expect(detectFabricatedFamilies(scoped, 60, NOW)).toEqual([])
  })

  it('a shared repository collapses packages published from different accounts', () => {
    const shared = ['one', 'two', 'three'].map((part, i) =>
      newPackage({
        name: `thing-${part}`,
        publishedBy: `dev-${i}`,
        minutesAfter: i,
        repository: { url: 'git+https://github.com/acme/monorepo.git' },
      })
    )
    // A repository field also takes them out of the class entirely, which is the
    // first thing that should stop this: the conjunction requires its absence.
    expect(detectFabricatedFamilies(shared, 60, NOW)).toEqual([])
    expect(new Set(shared.map(p =>
      publishingEntity(p.name, Object.values(p.versions)[0])
    ))).toEqual(new Set(['repo:acme/monorepo']))
  })

  it('a package outside the window is not part of the family', () => {
    const family = lockFamily()
    const late = detectFabricatedFamilies(family, 60, Date.parse('2026-08-14T09:35:00.000Z'))
    expect(late, 'a day later the whole window has expired').toEqual([])
  })
})

/**
 * The same campaign was written to campaigns.ndjson 19 times, and 163 lines on
 * disk describe 27 campaigns. Detection has no memory and should not: the ledger
 * is what turns a repeated detection into one record.
 */
describe('campaign ledger', () => {
  const signal = (packages: string[]): CampaignSignal => ({
    type: 'fabricated_family',
    certainty: 80,
    packages,
    entities: packages.map(p => `package:${p.split('@')[0]}`),
    windowMinutes: 5,
    description: 'x',
    linkedBy: ['maintainer'],
  })

  it('announces once, then updates in silence', () => {
    const first = mergeCampaign([], signal(['a@1', 'b@1', 'c@1']), '2026-08-13T09:35:00Z')
    expect(first.change).toBe('new')
    expect(first.records).toHaveLength(1)

    let records = first.records
    for (let i = 0; i < 18; i++) {
      const again = mergeCampaign(records, signal(['a@1', 'b@1', 'c@1']), '2026-08-13T09:40:00Z')
      expect(again.change, 'the same campaign was announced twice').toBe(null)
      expect(again.records).toHaveLength(1)
      records = again.records
    }

    expect(records[0]!.sightings).toBe(19)
    expect(records[0]!.firstSeenAt).toBe('2026-08-13T09:35:00Z')
    expect(records[0]!.lastSeenAt).toBe('2026-08-13T09:40:00Z')
  })

  it('a campaign that grows is reported again, with only what is new', () => {
    const first = mergeCampaign([], signal(['a@1', 'b@1', 'c@1']), '2026-08-13T09:35:00Z')
    const grown = mergeCampaign(first.records, signal(['b@1', 'c@1', 'd@1']), '2026-08-13T09:45:00Z')

    expect(grown.change).toBe('grown')
    expect(grown.added).toEqual(['d@1'])
    // Union, not replacement: a@1 aged out of the window and was still part of it.
    expect(grown.record.packages).toEqual(['a@1', 'b@1', 'c@1', 'd@1'])
    expect(grown.records).toHaveLength(1)
  })

  it('two campaigns sharing no member stay two records', () => {
    const first = mergeCampaign([], signal(['a@1', 'b@1', 'c@1']), '2026-08-13T09:35:00Z')
    const other = mergeCampaign(first.records, signal(['x@1', 'y@1', 'z@1']), '2026-08-13T09:36:00Z')

    expect(other.change).toBe('new')
    expect(other.records).toHaveLength(2)
    expect(other.record.id).not.toBe(first.record.id)
  })

  it('the id survives a restart: same first detection, same record', () => {
    const a = mergeCampaign([], signal(['c@1', 'a@1', 'b@1']), '2026-08-13T09:35:00Z')
    const b = mergeCampaign([], signal(['b@1', 'c@1', 'a@1']), '2026-08-13T11:00:00Z')
    expect(a.record.id).toBe(b.record.id)
  })
})
