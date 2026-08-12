/**
 * The CouchDB feed is the primary source. What is pinned here is what makes it
 * a cursor rather than a window:
 *
 *   a line split across TCP chunks is neither lost nor half-parsed
 *   heartbeats are not changes
 *   last_seq survives the run and keeps its type
 *   a sequence gap is detected and reported
 *
 * RSS rotated every ~60s (17 rollovers in 54 polls) and whatever fell off the
 * window was never seen. That is not recoverable after the fact; this is.
 */

import { describe, it, expect, afterAll } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import {
  parseChangeLine,
  parseChangesPage,
  seqNumber,
  detectSeqGap,
  detectCursorRewind,
  splitLines,
  loadLastSeq,
  saveLastSeq,
  changesUrl,
  pagedChangesUrl,
  type ChangeEvent,
} from '../src/changes-feed.js'
import { isRecentPublish, coalesceByPackage } from '../src/watcher.js'
import type { Packument, VersionMeta } from '../src/packument.js'
import { normalizePackument } from '../src/packument.js'

const dirs: string[] = []
const tempDir = () => {
  const d = mkdtempSync(join(tmpdir(), 'ng-feed-'))
  dirs.push(d)
  return d
}
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }) })

describe('parseChangeLine', () => {
  it('parses a change with a doc', () => {
    const line = JSON.stringify({ seq: 42, id: 'lodash', changes: [{ rev: '1-abc' }], doc: { name: 'lodash' } })
    const parsed = parseChangeLine(line) as ChangeEvent

    expect(parsed.seq).toBe(42)
    expect(parsed.id).toBe('lodash')
    expect(parsed.deleted).toBe(false)
    expect(parsed.doc).toEqual({ name: 'lodash' })
  })

  it('a heartbeat is an empty line, not a change', () => {
    expect(parseChangeLine('')).toBeNull()
    expect(parseChangeLine('   ')).toBeNull()
    expect(parseChangeLine('\n')).toBeNull()
  })

  it('tolerates the trailing comma of the array format', () => {
    const parsed = parseChangeLine('{"seq":7,"id":"x"},') as ChangeEvent
    expect(parsed.seq).toBe(7)
    expect(parsed.id).toBe('x')
  })

  it('flags deletions', () => {
    const parsed = parseChangeLine('{"seq":9,"id":"borrado","deleted":true}') as ChangeEvent
    expect(parsed.deleted).toBe(true)
  })

  it('recognises the last_seq terminator', () => {
    const parsed = parseChangeLine('{"last_seq":12345}')
    expect(parsed).toEqual({ lastSeq: 12345 })
  })

  it('broken JSON does not break the stream', () => {
    expect(parseChangeLine('{"seq":1,"id":')).toBeNull()
    expect(parseChangeLine('basura')).toBeNull()
  })

  it('a change with no id is unusable', () => {
    expect(parseChangeLine('{"seq":1}')).toBeNull()
  })
})

describe('splitLines: TCP chunks cut documents in half', () => {
  it('returns the complete lines and keeps the remainder', () => {
    const { lines, rest } = splitLines('{"a":1}\n{"b":2}\n{"c":')
    expect(lines).toEqual(['{"a":1}', '{"b":2}'])
    expect(rest).toBe('{"c":')
  })

  it('the remainder is completed by the next chunk', () => {
    const first = splitLines('{"seq":1,"id":"par')
    expect(first.lines).toEqual([])

    const second = splitLines(first.rest + 'tido"}\n')
    expect(second.lines).toEqual(['{"seq":1,"id":"partido"}'])
    expect((parseChangeLine(second.lines[0]!) as ChangeEvent).id).toBe('partido')
  })
})

describe('secuencias', () => {
  it('seqNumber accepts an integer and an opaque seq prefix', () => {
    expect(seqNumber(42)).toBe(42)
    expect(seqNumber('8-g1AAAAcalquiercosa')).toBe(8)
    expect(seqNumber('opaco')).toBeNull()
  })

  it('no gap without a previous cursor, and none between consecutive seqs', () => {
    expect(detectSeqGap(null, 10)).toBeNull()
    expect(detectSeqGap(10, 11)).toBeNull()
    expect(detectSeqGap(10, 10)).toBeNull()
  })

  it('detects the gap and how much is missing', () => {
    expect(detectSeqGap(100, 105)).toEqual({ from: 100, to: 105, missing: 4 })
  })

  it('with opaque seqs it does not invent gaps', () => {
    expect(detectSeqGap('a-xyz', 'b-xyz')).toBeNull()
  })
})

describe('cursor persistence', () => {
  it('survives between runs and keeps its type', () => {
    const dir = tempDir()
    expect(loadLastSeq(dir)).toBeNull()

    saveLastSeq(dir, 987654)
    expect(loadLastSeq(dir)).toBe(987654)

    // An opaque seq stored as a number would resume from the beginning of the
    // base de datos: el tipo es parte del cursor.
    saveLastSeq(dir, '8-g1AAAAopaco')
    expect(loadLastSeq(dir)).toBe('8-g1AAAAopaco')
  })

  it('a corrupt file does not break resumption', () => {
    const dir = tempDir()
    saveLastSeq(dir, 1)
    writeFileSync(join(dir, '.last_seq'), 'no es json')
    expect(loadLastSeq(dir)).toBeNull()
  })
})

// replicate.npmjs.com no soporta feed=continuous ni include_docs (probado
// 2026-08-12: HTTP 400 on both). The real path is the page with since=<seq>,
// which gives the same delivery guarantee at one poll of latency.
describe('parseChangesPage: the format the server does return', () => {
  it('extracts the changes and the last_seq', () => {
    const page = parseChangesPage({
      results: [
        { seq: 124525492, id: '@kong-ui-public/entities', changes: [{ rev: '419-abc' }] },
        { seq: 124525494, id: 'otro', changes: [{ rev: '1-def' }], deleted: true },
      ],
      last_seq: 124525494,
    })

    expect(page.results.map(r => r.id)).toEqual(['@kong-ui-public/entities', 'otro'])
    expect(page.results[1]!.deleted).toBe(true)
    expect(page.lastSeq).toBe(124525494)
  })

  it('an empty page is not an error', () => {
    expect(parseChangesPage({ results: [], last_seq: 5 })).toEqual({ results: [], lastSeq: 5 })
    expect(parseChangesPage({})).toEqual({ results: [], lastSeq: null })
  })

  it('drops rows without an id without dropping the page', () => {
    const page = parseChangesPage({ results: [{ seq: 1 }, { seq: 2, id: 'bueno' }] })
    expect(page.results.map(r => r.id)).toEqual(['bueno'])
  })
})

describe('detectCursorRewind: the only way to lose data with a cursor', () => {
  it('no rewind going forward, and none on the first change', () => {
    expect(detectCursorRewind(null, 10)).toBe(false)
    expect(detectCursorRewind(10, 11)).toBe(false)
    expect(detectCursorRewind(10, 10)).toBe(false)
  })

  it('detects the rewind', () => {
    expect(detectCursorRewind(124525494, 124525000)).toBe(true)
  })
})

describe('coalesceByPackage: a monorepo publishes several times per page', () => {
  const change = (seq: number, id: string): ChangeEvent => ({ seq, id, deleted: false })

  it('keeps the last change per package and returns the rest', () => {
    const { kept, superseded } = coalesceByPackage([
      change(1, '@scope/a'),
      change(2, '@scope/b'),
      change(3, '@scope/a'),
      change(4, '@scope/a'),
    ])

    expect(kept.map(e => e.seq)).toEqual([4, 2])
    // The superseded ones are not discarded: they go to the enumeration log.
    expect(superseded.map(e => e.seq)).toEqual([1, 3])
  })

  it('with no repeats it coalesces nothing', () => {
    const { kept, superseded } = coalesceByPackage([change(1, 'a'), change(2, 'b')])
    expect(kept).toHaveLength(2)
    expect(superseded).toHaveLength(0)
  })
})

describe('changesUrl', () => {
  it('asks for a continuous feed, heartbeat, docs and the exact since', () => {
    const url = changesUrl(12345, 10_000, true)
    expect(url).toContain('feed=continuous')
    expect(url).toContain('heartbeat=10000')
    expect(url).toContain('since=12345')
    expect(url).toContain('include_docs=true')
  })

  it('without docs it does not ask for include_docs', () => {
    expect(changesUrl('now', 10_000, false)).not.toContain('include_docs')
  })

  it('the paged URL carries since and limit, with no feed and no heartbeat', () => {
    const url = pagedChangesUrl(124525000, 100, false)
    expect(url).toContain('since=124525000')
    expect(url).toContain('limit=100')
    expect(url).not.toContain('feed=')
    expect(url).not.toContain('heartbeat=')
  })
})

describe('isRecentPublish: the feed carries much more than publications', () => {
  function packumentWithLatest(publishedAt: string): Packument {
    const meta: VersionMeta = {
      version: '1.0.0', publishedAt, publishedBy: 'x', unpackedSize: 1,
      hasInstallScript: false, scripts: {}, dependencies: {}, devDependencies: {},
      dist: { tarball: '', integrity: '' },
    }
    return {
      name: 'p', distTags: { latest: '1.0.0' },
      versions: { '1.0.0': meta }, time: { '1.0.0': publishedAt }, maintainers: [],
    }
  }

  const now = Date.parse('2026-08-12T12:00:00Z')

  it('a freshly published version is analysed', () => {
    expect(isRecentPublish(packumentWithLatest('2026-08-12T11:58:00Z'), 15 * 60_000, now)).toBe(true)
  })

  it('a dist-tag change on an old package is not re-analysed', () => {
    expect(isRecentPublish(packumentWithLatest('2024-01-01T00:00:00Z'), 15 * 60_000, now)).toBe(false)
  })

  it('a document with no versions is not a publication', () => {
    const empty: Packument = { name: 'p', distTags: {}, versions: {}, time: {}, maintainers: [] }
    expect(isRecentPublish(empty, 15 * 60_000, now)).toBe(false)
  })
})

describe('normalizePackument: the feed doc is the same registry document', () => {
  it('normalises a _changes doc without a second request', () => {
    const doc = {
      name: 'ejemplo',
      'dist-tags': { latest: '2.0.0' },
      time: { '1.0.0': '2026-01-01T00:00:00Z', '2.0.0': '2026-08-12T11:00:00Z' },
      versions: {
        '1.0.0': { scripts: {}, dist: { tarball: 't', integrity: 'i' } },
        '2.0.0': { scripts: { postinstall: 'node x.js' }, dist: { tarball: 't2', integrity: 'i2', unpackedSize: 500 } },
      },
      maintainers: [{ name: 'a', email: 'a@b.c' }],
    }

    const p = normalizePackument(doc)
    expect(p.name).toBe('ejemplo')
    expect(p.distTags['latest']).toBe('2.0.0')
    expect(p.versions['2.0.0']!.hasInstallScript).toBe(true)
    expect(p.versions['1.0.0']!.hasInstallScript).toBe(false)
    expect(p.versions['2.0.0']!.publishedAt).toBe('2026-08-12T11:00:00Z')
    expect(p.versions['2.0.0']!.unpackedSize).toBe(500)
  })
})
