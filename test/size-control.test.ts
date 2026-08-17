/**
 * The control by size.
 *
 * The by-class run reports the class as far more legible than the segment it is
 * compared against, and it cannot mean what it looks like: the class is DEFINED
 * as under 100KB, and binaries, WASM, bytecode and bundles do not fit in 100KB.
 * These tests pin the machinery that decides whether anything is left once size
 * is held fixed:
 *
 *   The difference between two rates carries its own interval. Reading it off a
 *   pair of overlapping error bars throws away real gaps, and there is a test
 *   here that does exactly that case.
 *   Group membership is recomputed from the capture's own packument, at capture
 *   time — not read off captureReason and not re-asked today.
 *   A capture whose packument does not hash to its manifest is not evidence.
 *   The background is drawn to match group A's size distribution, and a bucket
 *   the pool cannot fill is reported rather than absorbed.
 */

import { describe, it, expect } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

import { differenceWithCI, formatDifference, wilsonInterval, normalQuantile, zForFamily } from '../src/stats.js'
import {
  capturePackument,
  markersOfCapture,
  buildPool,
  cellOf,
  CELLS,
  CLASS_CELL,
  EQUIVALENCE_MARGIN,
  sizeBuckets,
  bucketOf,
  sizeMatchedDraw,
  sizeProfile,
  dedupeByPackage,
  versionAt,
  measureMember,
  summariseGroup,
  compareGroups,
  verdictFor,
  type ControlMember,
  type GroupReport,
} from '../src/size-control.js'
import { MINIFIED_THRESHOLD } from '../src/analyzability.js'
import type { CorpusSample } from '../src/corpus.js'
import { gzipSync } from 'node:zlib'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function tarHeader(name: string, size: number): Buffer {
  const block = Buffer.alloc(512)
  block.write(name.slice(0, 100), 0, 'utf-8')
  block.write('0000644\0', 100)
  block.write('0000000\0', 108)
  block.write('0000000\0', 116)
  block.write(size.toString(8).padStart(11, '0') + '\0', 124)
  block.write('00000000000\0', 136)
  block.write('0', 156)
  block.write('ustar\0', 257)
  block.write('00', 263)
  block.write('        ', 148)
  let sum = 0
  for (const byte of block) sum += byte
  block.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  return block
}

function tarFile(name: string, content: string | Buffer): Buffer {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf-8')
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512)
  return Buffer.concat([tarHeader(name, data.length), data, padding])
}

const TAR_END = Buffer.alloc(1024)

function packumentFixture(input: {
  name?: string
  created: string
  version: string
  publishedAt: string
  unpackedSize: number
  repository?: unknown
  extraVersions?: Array<{ version: string; publishedAt: string }>
}) {
  const versions: Record<string, unknown> = {
    [input.version]: {
      version: input.version,
      publishedAt: input.publishedAt,
      publishedBy: 'someone',
      unpackedSize: input.unpackedSize,
      hasInstallScript: false,
      scripts: {},
      dependencies: {},
      devDependencies: {},
      dist: { tarball: 'https://example/x.tgz', integrity: 'sha512-x', unpackedSize: input.unpackedSize },
      repository: input.repository,
    },
  }
  const time: Record<string, string> = { created: input.created, [input.version]: input.publishedAt }

  for (const extra of input.extraVersions ?? []) {
    versions[extra.version] = {
      version: extra.version,
      publishedAt: extra.publishedAt,
      publishedBy: 'someone',
      unpackedSize: 1000,
      hasInstallScript: false,
      scripts: {}, dependencies: {}, devDependencies: {},
      dist: { tarball: 'https://example/x.tgz', integrity: 'sha512-x', unpackedSize: 1000 },
    }
    time[extra.version] = extra.publishedAt
  }

  return {
    name: input.name ?? 'fixture-pkg',
    distTags: { latest: input.version },
    versions,
    time,
    maintainers: [],
    createdAt: input.created,
  }
}

// A capture directory as the watcher writes one: manifest, packument, and the
// manifest's hash of the packument.
function writeCapture(dir: string, packument: unknown, tamper = false): string {
  mkdirSync(dir, { recursive: true })
  const raw = JSON.stringify(packument)
  writeFileSync(join(dir, 'packument.json'), tamper ? raw.replace('fixture-pkg', 'other-pkg!') : raw)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
    version: 1,
    package: (packument as { name: string }).name,
    capturedAt: '2026-08-15T12:00:00.000Z',
    capturedFrom: 'https://registry.npmjs.org',
    versionsIncluded: ['1.0.0'],
    hashes: { 'packument.json': createHash('sha256').update(Buffer.from(raw)).digest('hex') },
  }))
  return dir
}

function sampleFor(dir: string, overrides: Partial<CorpusSample> = {}): CorpusSample {
  return {
    package: 'fixture-pkg',
    version: '1.0.0',
    label: 'unconfirmed',
    ngpackPath: dir,
    capturedAt: '2026-08-15T12:00:00.000Z',
    hasTarball: true,
    tarballPresent: true,
    labelAssumed: false,
    contaminated: false,
    composition: {
      regime: 'no-genome', signals: [], firstPublication: true,
      ghost: null, ghostKind: null, newInstallScript: false, platformFamily: null,
    },
    ...overrides,
  } as CorpusSample
}

function memberFixture(over: Partial<ControlMember> = {}): ControlMember {
  return {
    package: 'p', version: '1.0.0', at: '2026-08-15T12:00:00.000Z',
    origin: 'capture', ngpackPath: null, unpackedSize: 10_000,
    hasRepository: false, nameAgeDays: 1, regime: 'no-genome', cell: CLASS_CELL,
    ...over,
  }
}

// ---------------------------------------------------------------------------

describe('the quantile the widening needs', () => {
  it('agrees with the published values of the standard normal', () => {
    // The four everybody knows, to nine places. If this drifts, every interval
    // in the report drifts with it.
    expect(normalQuantile(0.975)).toBeCloseTo(1.959963985, 7)
    expect(normalQuantile(0.995)).toBeCloseTo(2.575829304, 7)
    expect(normalQuantile(0.999)).toBeCloseTo(3.090232306, 7)
    expect(normalQuantile(0.5)).toBeCloseTo(0, 12)
    expect(normalQuantile(0.025)).toBeCloseTo(-1.959963985, 7)
  })

  it('is symmetric about the median and monotone', () => {
    for (const p of [0.001, 0.01, 0.1, 0.3, 0.49]) {
      expect(normalQuantile(p)).toBeCloseTo(-normalQuantile(1 - p), 9)
    }
    expect(normalQuantile(0.6)).toBeLessThan(normalQuantile(0.7))
  })

  it('widens with the size of the family and never narrows below 95%', () => {
    expect(zForFamily(1)).toBeCloseTo(1.959963985, 7)
    expect(zForFamily(10)).toBeGreaterThan(zForFamily(1))
    expect(zForFamily(708)).toBeGreaterThan(zForFamily(10))
    // A family of zero or one comparison is still one comparison.
    expect(zForFamily(0)).toBe(zForFamily(1))
  })
})

describe('the interval on a difference', () => {
  it('is not the same question as two intervals side by side', () => {
    // 120/200 against 100/200: the two Wilson intervals overlap, and the
    // difference still excludes zero. Reading "they overlap, so it is nothing"
    // off a pair of error bars is the mistake this function exists to prevent.
    const a = wilsonInterval(120, 200)
    const b = wilsonInterval(100, 200)
    expect(a.low).toBeLessThan(b.high)

    const d = differenceWithCI(120, 200, 100, 200)
    expect(d.difference).toBeCloseTo(0.1, 10)
    expect(d.low!).toBeGreaterThan(0)
    expect(d.separated).toBe(true)
  })

  it('is symmetric: swapping the groups negates the interval', () => {
    const forward = differenceWithCI(99, 100, 23, 100)
    const backward = differenceWithCI(23, 100, 99, 100)

    expect(backward.difference).toBeCloseTo(-forward.difference!, 12)
    expect(backward.low).toBeCloseTo(-forward.high!, 12)
    expect(backward.high).toBeCloseTo(-forward.low!, 12)
  })

  it('contains its own point estimate and stays inside [-1, 1]', () => {
    for (const [sa, na, sb, nb] of [[99, 100, 23, 100], [0, 30, 0, 30], [68, 68, 1, 4], [1, 3, 300, 300]]) {
      const d = differenceWithCI(sa!, na!, sb!, nb!)
      expect(d.low!).toBeLessThanOrEqual(d.difference!)
      expect(d.high!).toBeGreaterThanOrEqual(d.difference!)
      expect(d.low!).toBeGreaterThanOrEqual(-1)
      expect(d.high!).toBeLessThanOrEqual(1)
    }
  })

  it('reports equal rates as inseparable, however large the n', () => {
    const d = differenceWithCI(500, 1000, 50, 100)
    expect(d.difference).toBe(0)
    expect(d.separated).toBe(false)
    expect(d.low!).toBeLessThan(0)
    expect(d.high!).toBeGreaterThan(0)
  })

  it('declines rather than dividing by zero', () => {
    const d = differenceWithCI(0, 0, 10, 20)
    expect(d.difference).toBeNull()
    expect(d.separated).toBe(false)
    expect(formatDifference(d)).toContain('not calculable')
  })

  it('spells the sign out, because +76pp and -76pp are opposite findings', () => {
    expect(formatDifference(differenceWithCI(99, 100, 23, 100))).toMatch(/^\+/)
    expect(formatDifference(differenceWithCI(23, 100, 99, 100))).toMatch(/^-/)
  })
})

describe('membership, recomputed from the capture', () => {
  it('classifies at capture time and not at read time', () => {
    const dir = writeCapture(
      join(mkdtempSync(join(tmpdir(), 'ng-control-')), 'cap'),
      packumentFixture({
        created: '2026-08-14T12:00:00.000Z',   // one day before the capture
        version: '1.0.0',
        publishedAt: '2026-08-15T11:59:00.000Z',
        unpackedSize: 30_000,
      })
    )

    const markers = markersOfCapture(sampleFor(dir))
    expect(markers).not.toBeNull()
    expect(markers!.young).toBe(true)
    expect(markers!.tiny).toBe(true)
    expect(markers!.hasRepository).toBe(false)
    expect(markers!.noGenome).toBe(true)
    expect(markers!.inClass).toBe(true)
    // Read today the name is far older than seven days; the answer must not
    // depend on when the question is asked.
    expect(markers!.nameAgeDays).toBeCloseTo(1, 1)
  })

  it('keeps a repository out of the class at the same size and age', () => {
    const dir = writeCapture(
      join(mkdtempSync(join(tmpdir(), 'ng-control-')), 'cap'),
      packumentFixture({
        created: '2026-08-14T12:00:00.000Z',
        version: '1.0.0',
        publishedAt: '2026-08-15T11:59:00.000Z',
        unpackedSize: 30_000,
        repository: { type: 'git', url: 'git+https://github.com/x/y.git' },
      })
    )

    const markers = markersOfCapture(sampleFor(dir))!
    expect(markers.tiny).toBe(true)
    expect(markers.inClass).toBe(false)
  })

  it('refuses a packument that does not hash to its manifest', () => {
    const dir = writeCapture(
      join(mkdtempSync(join(tmpdir(), 'ng-control-')), 'cap'),
      packumentFixture({
        created: '2026-08-14T12:00:00.000Z',
        version: '1.0.0',
        publishedAt: '2026-08-15T11:59:00.000Z',
        unpackedSize: 30_000,
      }),
      true
    )

    expect(capturePackument(dir)).toBeNull()
    expect(markersOfCapture(sampleFor(dir))).toBeNull()
  })
})

describe('the pool every registry group is drawn from', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-pool-'))
  const row = (o: Record<string, unknown>) => JSON.stringify(o)

  writeFileSync(join(dir, 'changes-log.ndjson'), [
    // in: tiny, not the class
    row({ package: 'keep-me', outcome: 'analyzed', regime: 'genome', seenAt: '2026-08-15T10:00:00.000Z', class: { inClass: false, tiny: true, repo: true, young: false, ageDays: 400, bytes: 20_000 } }),
    // in, and republished later the same day: the earliest sighting wins
    row({ package: 'twice', outcome: 'analyzed', regime: 'genome', seenAt: '2026-08-15T18:00:00.000Z', class: { inClass: false, tiny: true, repo: true, young: false, ageDays: 30, bytes: 9_000 } }),
    row({ package: 'twice', outcome: 'analyzed', regime: 'genome', seenAt: '2026-08-15T09:00:00.000Z', class: { inClass: false, tiny: true, repo: true, young: false, ageDays: 30, bytes: 9_000 } }),
    // out: it is the class
    row({ package: 'the-class', outcome: 'analyzed', regime: 'no-genome', seenAt: '2026-08-15T10:00:00.000Z', class: { inClass: true, tiny: true, repo: false, young: true, ageDays: 0.1, bytes: 20_000 } }),
    // out: too big
    row({ package: 'big', outcome: 'analyzed', regime: 'genome', seenAt: '2026-08-15T10:00:00.000Z', class: { inClass: false, tiny: false, repo: true, young: false, ageDays: 400, bytes: 4_000_000 } }),
    // out: before the window
    row({ package: 'old-news', outcome: 'analyzed', regime: 'genome', seenAt: '2026-08-13T10:00:00.000Z', class: { inClass: false, tiny: true, repo: true, young: false, ageDays: 400, bytes: 20_000 } }),
    // out: never scored, so it has no markers to be in or out by
    row({ package: 'not-a-publication', outcome: 'no-publicacion', seenAt: '2026-08-15T10:00:00.000Z' }),
    '',
  ].join('\n'))

  it('takes every tiny publication in the window, one row per package, tagged by cell', () => {
    const pool = buildPool(dir, { since: '2026-08-15' })
    expect(pool.candidates.map(c => c.package).sort()).toEqual(['keep-me', 'the-class', 'twice'])
    expect(pool.tinyInWindow).toBe(4)        // keep-me, twice x2, the-class
    expect(pool.analysedInWindow).toBe(5)    // every analyzed row on or after the 15th
    expect(pool.candidates.find(c => c.package === 'the-class')!.cell).toBe(CLASS_CELL)
    expect(pool.candidates.find(c => c.package === 'keep-me')!.cell).toBe('maintained')
  })

  it('keeps the earliest sighting of a package that published twice', () => {
    const pool = buildPool(dir, { since: '2026-08-15' })
    expect(pool.candidates.find(c => c.package === 'twice')!.seenAt)
      .toBe('2026-08-15T09:00:00.000Z')
  })

  it('honours the far end of the window', () => {
    const pool = buildPool(dir, { since: '2026-08-15', until: '2026-08-15T09:30:00.000Z' })
    expect(pool.candidates.map(c => c.package)).toEqual(['twice'])
  })
})

describe('the cells, which are the whole design', () => {
  it('puts the class in the class cell and nothing else', () => {
    expect(cellOf({ noGenome: true, young: true, repository: false, tiny: true })!.key).toBe(CLASS_CELL)
    expect(cellOf({ noGenome: true, young: true, repository: true, tiny: true })!.key).toBe('repository')
    expect(cellOf({ noGenome: true, young: false, repository: false, tiny: true })!.key).toBe('age')
    expect(cellOf({ noGenome: false, young: false, repository: true, tiny: true })!.key).toBe('maintained')
  })

  it('refuses anything over the size band, whatever else it is', () => {
    expect(cellOf({ noGenome: true, young: true, repository: false, tiny: false })).toBeNull()
  })

  it('varies exactly one conjunct in the two cells that claim to', () => {
    const cls = CELLS.find(c => c.key === CLASS_CELL)!
    for (const key of ['repository', 'age']) {
      const cell = CELLS.find(c => c.key === key)!
      const differences = [
        cell.noGenome !== cls.noGenome,
        cell.young !== cls.young,
        cell.repository !== cls.repository,
      ].filter(Boolean).length
      expect(differences, `${key} should differ from the class in exactly one conjunct`).toBe(1)
    }
  })
})

describe('matching on size', () => {
  const target = [1_000, 2_000, 3_000, 4_000, 5_000, 6_000, 7_000, 8_000, 9_000, 10_000]
  const buckets = sizeBuckets(target)

  it('cuts buckets at the target distribution and covers everything', () => {
    expect(buckets[0]!.low).toBe(0)
    expect(buckets[buckets.length - 1]!.high).toBe(Infinity)
    for (let i = 1; i < buckets.length; i++) {
      expect(buckets[i]!.low).toBe(buckets[i - 1]!.high)
    }
    expect(bucketOf(buckets, 0)).toBe(0)
    expect(bucketOf(buckets, 10 ** 9)).toBe(buckets.length - 1)
  })

  it('draws a pool skewed large into the shape of the target', () => {
    // A pool shaped like the real one: it covers the whole band, and most of it
    // sits at the top. An unmatched draw would compare the class against
    // packages several times its size, which is the confound being removed.
    const pool: number[] = []
    for (let i = 0; i < 1_000; i++) pool.push(8_000 + i * 4)      // dense at the top
    for (let i = 0; i < 200; i++) pool.push(500 + i * 40)         // thin across the rest

    const draw = sizeMatchedDraw(pool, x => x, target, 100, buckets)
    const drawn = sizeProfile(draw.picked, buckets)
    const wanted = sizeProfile(target, buckets)
    const raw = sizeProfile(pool, buckets)

    expect(draw.shortfall).toEqual([])
    for (let i = 0; i < buckets.length; i++) {
      expect(Math.abs(drawn[i]!.share - wanted[i]!.share)).toBeLessThan(0.05)
    }
    // And the thing being fixed: the raw pool is nowhere near that shape.
    const worstRaw = Math.max(...buckets.map((_, i) => Math.abs(raw[i]!.share - wanted[i]!.share)))
    expect(worstRaw).toBeGreaterThan(0.3)
  })

  it('reports a bucket the pool cannot fill instead of absorbing it', () => {
    const pool = [9_000, 9_100, 9_200]
    const draw = sizeMatchedDraw(pool, x => x, target, 100, buckets)
    expect(draw.shortfall.length).toBeGreaterThan(0)
    expect(draw.shortfall.every(s => s.got < s.wanted)).toBe(true)
  })

  it('is deterministic, so two runs can be compared', () => {
    const pool = Array.from({ length: 500 }, (_, i) => 500 + i * 20)
    const first = sizeMatchedDraw(pool, x => x, target, 50, buckets).picked
    const second = sizeMatchedDraw(pool, x => x, target, 50, buckets).picked
    expect(first).toEqual(second)
  })
})

describe('one package per name', () => {
  it('keeps the earliest capture of a name republished all day', () => {
    const members = [
      memberFixture({ package: 'x', at: '2026-08-15T18:00:00.000Z', version: '1.0.3' }),
      memberFixture({ package: 'x', at: '2026-08-15T08:00:00.000Z', version: '1.0.1' }),
      memberFixture({ package: 'y', at: '2026-08-15T09:00:00.000Z' }),
    ]
    const deduped = dedupeByPackage(members)
    expect(deduped.length).toBe(2)
    expect(deduped.find(m => m.package === 'x')!.version).toBe('1.0.1')
  })
})

describe('the version a log row was written about', () => {
  const packument = packumentFixture({
    created: '2026-01-01T00:00:00.000Z',
    version: '1.0.2',
    publishedAt: '2026-08-15T10:00:00.000Z',
    unpackedSize: 5_000,
    extraVersions: [
      { version: '1.0.1', publishedAt: '2026-08-01T10:00:00.000Z' },
      { version: '1.0.3', publishedAt: '2026-08-16T10:00:00.000Z' },
    ],
  }) as never

  it('is the last one published at or before the sighting', () => {
    expect(versionAt(packument, '2026-08-15T10:30:00.000Z')!.version).toBe('1.0.2')
    expect(versionAt(packument, '2026-08-17T00:00:00.000Z')!.version).toBe('1.0.3')
  })

  it('falls back to the earliest survivor rather than reporting nothing', () => {
    expect(versionAt(packument, '2020-01-01T00:00:00.000Z')!.version).toBe('1.0.1')
  })
})

describe('measuring one member', () => {
  const threshold = MINIFIED_THRESHOLD

  it('reads a small flat package as fully legible and follows its requires', () => {
    const tar = gzipSync(Buffer.concat([
      tarFile('package/package.json', '{"name":"p","version":"1.0.0","main":"index.js"}'),
      tarFile('package/index.js', 'const cp = require("child_process")\nmodule.exports = () => cp.exec("ls")\n'),
      TAR_END,
    ]))

    const result = measureMember(memberFixture(), tar, threshold)
    expect(result.analysis.coverage).toBe(1)
    expect(result.modules).toContain('child_process')
    expect(result.tarballSha256).toMatch(/^[0-9a-f]{64}$/)
  })

  it('counts a native binary as opaque and still reports the package', () => {
    const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(4096)])
    const tar = gzipSync(Buffer.concat([
      tarFile('package/package.json', '{"name":"p","version":"1.0.0","main":"index.js"}'),
      tarFile('package/index.js', 'module.exports = require("./native.node")\n'),
      tarFile('package/native.node', elf),
      TAR_END,
    ]))

    const result = measureMember(memberFixture(), tar, threshold)
    expect(result.analysis.byReason['native-binary']?.files).toBe(1)
    expect(result.analysis.coverage).toBeLessThan(1)
  })

  it('does not take an unreadable archive down with it', () => {
    const result = measureMember(memberFixture(), Buffer.from('not a tarball at all'), threshold)
    expect(result.analysis.error).toBeTruthy()
    expect(result.analysis.coverage).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// The verdict, which is the whole point of the run
// ---------------------------------------------------------------------------

function groupFixture(name: string, legible: number, n: number, sizeMatched = true): GroupReport {
  const base = summariseGroup({
    name, cell: 'fixture', definition: 'fixture', source: 'registry', sizeMatched,
    results: [], failures: [], buckets: sizeBuckets([1000]), members: n,
    threshold: MINIFIED_THRESHOLD,
  })

  // The rates are what the verdict reads; the rest of the summary is exercised
  // by the runs above.
  return {
    ...base,
    scored: n,
    fullyLegible: { successes: legible, n, rate: legible / n, low: 0, high: 1 },
    shipsOpaqueExecutable: { successes: n - legible, n, rate: (n - legible) / n, low: 0, high: 1 },
    reachabilityAnalysed: n,
    modules: [],
  }
}

describe('the rule, declared before the run and applied to what it produced', () => {
  it('calls a gap a gap when the interval excludes zero', () => {
    const verdict = verdictFor(
      groupFixture('A', 99, 100), groupFixture('B', 23, 100),
      differenceWithCI(99, 100, 23, 100)
    )
    expect(verdict).toContain('THE GAP SURVIVES')
  })

  it('says so when the gap runs the other way', () => {
    const verdict = verdictFor(
      groupFixture('A', 23, 100), groupFixture('B', 99, 100),
      differenceWithCI(23, 100, 99, 100)
    )
    expect(verdict).toContain('IT RUNS THE OTHER WAY')
  })

  it('only calls it "no difference" when the whole interval is inside the declared margin', () => {
    // 980/1000 against 970/1000: the interval is narrow enough that a gap the
    // size of the one under test is excluded.
    const d = differenceWithCI(980, 1000, 970, 1000)
    expect(d.high!).toBeLessThan(EQUIVALENCE_MARGIN)
    const verdict = verdictFor(groupFixture('A', 980, 1000), groupFixture('B', 970, 1000), d)
    expect(verdict).toContain('NO DIFFERENCE WORTH THE NAME')
  })

  it('refuses to affirm the null from a sample too small to have found a gap', () => {
    // The shape the on-disk control has: about 68 packages against 800, at rates
    // where a binomial is at its widest. The interval spans more than the
    // margin, so "no difference" is not a claim this n can make — and before the
    // equivalence bound was declared, this case printed as "withdraw the
    // finding".
    const d = differenceWithCI(400, 800, 34, 68)
    expect(d.separated).toBe(false)
    expect(d.high! - d.low!).toBeGreaterThan(2 * EQUIVALENCE_MARGIN)
    const verdict = verdictFor(groupFixture('A', 400, 800), groupFixture('B', 34, 68), d)
    expect(verdict).toContain('INCONCLUSIVE')
    expect(verdict).toContain('affirming the null')
  })

  it('never claims size was controlled when one side was not matched', () => {
    const matched = verdictFor(
      groupFixture('A', 99, 100), groupFixture('B', 23, 100, true),
      differenceWithCI(99, 100, 23, 100)
    )
    const unmatched = verdictFor(
      groupFixture('A', 99, 100), groupFixture('B', 23, 100, false),
      differenceWithCI(99, 100, 23, 100)
    )
    expect(matched).toContain("size distribution")
    expect(unmatched).toContain('NOT size-matched')
  })

  it('widens the module intervals for the size of the table it prints', () => {
    const a = { ...groupFixture('A', 90, 100), modules: [
      { module: 'fs', captures: 50, rate: { successes: 50, n: 100, rate: 0.5, low: 0, high: 1 } },
    ] }
    const b = { ...groupFixture('B', 90, 100), modules: Array.from({ length: 39 }, (_, i) => ({
      module: `m${i}`, captures: 40, rate: { successes: 40, n: 100, rate: 0.4, low: 0, high: 1 },
    })) }

    const comparison = compareGroups(a, b)
    expect(comparison.moduleComparisons).toBe(40)
    expect(comparison.moduleZ).toBeGreaterThan(1.96)
    // Every module either side reaches is in the table, so an absence reads as a
    // difference rather than as nothing.
    expect(comparison.modules.length).toBe(40)
    expect(comparison.modules.some(m => m.module === 'fs')).toBe(true)
  })
})
