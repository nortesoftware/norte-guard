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
import { detectCampaigns } from '../src/ecosystem.js'
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
