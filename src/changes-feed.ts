// The registry's replication feed, primary source with RSS as fallback.
//
// RSS is a fixed 50-entry window polled once a minute. When npm publishes more
// than 50 packages inside a poll interval the window rotates completely and
// whatever fell off was never seen: not delayed, not retried, gone. That
// happened 17 times in one 54-poll run. _changes is a cursor instead, so a
// client that persists its position can be down for an hour and resume with
// nothing missing.
//
// Probed 2026-08-12, replicate.npmjs.com answers 200 only to
// /_changes?since=<seq>&limit=<n>. feed=continuous, include_docs, since=now and
// heartbeat all return 400: the engine there is "npm-replicate", not CouchDB,
// and implements only the paged form. So the default path is a paged cursor,
// with the same delivery guarantee and poll latency instead of push. The
// continuous implementation is kept for hosts that do support it, since the two
// differ in latency rather than in what they promise.
//
// Measured at ~224 seq/min, ~112 changes/min. At that rate the cursor stays
// within one poll interval, and when it does not the backlog is reported.

import https from 'node:https'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const REPLICATE = 'https://replicate.npmjs.com'
const CHANGES_URL = `${REPLICATE}/_changes`

// CouchDB 1.x-style followers return an integer; a clustered CouchDB returns an
// opaque string like "8-g1AAAA...". Both are valid cursors, only the first can
// be compared arithmetically.
export type Seq = string | number

export interface ChangeEvent {
  seq: Seq
  id: string
  deleted: boolean
  doc?: unknown
}

export interface FeedTerminator {
  lastSeq: Seq
}

export interface SeqGap {
  from: Seq
  to: Seq
  missing: number
}

export function parseChangeLine(line: string): ChangeEvent | FeedTerminator | null {
  const trimmed = line.trim()
  // Heartbeats are empty lines, sent to keep the socket alive through proxies.
  if (trimmed === '') return null

  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(trimmed.replace(/,$/, '')) as Record<string, unknown>
  } catch {
    // The caller buffers partial lines, so this only fires on real garbage.
    return null
  }

  return toChangeEvent(parsed)
}

function toChangeEvent(parsed: Record<string, unknown>): ChangeEvent | FeedTerminator | null {
  if (parsed['last_seq'] !== undefined && parsed['id'] === undefined) {
    return { lastSeq: parsed['last_seq'] as Seq }
  }

  if (typeof parsed['id'] !== 'string' || parsed['seq'] === undefined) return null

  return {
    seq: parsed['seq'] as Seq,
    id: parsed['id'] as string,
    deleted: parsed['deleted'] === true,
    doc: parsed['doc'],
  }
}

export function seqNumber(seq: Seq): number | null {
  if (typeof seq === 'number') return Number.isFinite(seq) ? seq : null
  const head = /^(\d+)/.exec(seq)
  return head ? Number(head[1]) : null
}

// Only meaningful where sequence numbers are allocated one per change. npm's
// spends two or more, so wiring this into its feed would warn on almost every
// change and train the reader to ignore it. The watcher reports backlog instead.
export function detectSeqGap(prev: Seq | null, next: Seq): SeqGap | null {
  if (prev === null) return null

  const a = seqNumber(prev)
  const b = seqNumber(next)
  if (a === null || b === null) return null
  if (b <= a + 1) return null

  return { from: prev, to: next, missing: b - a - 1 }
}

// The one way a paged cursor can lose data: a persisted rewind skips everything
// between the two positions. It should be impossible, and is checked anyway.
export function detectCursorRewind(prev: Seq | null, next: Seq): boolean {
  if (prev === null) return false
  const a = seqNumber(prev)
  const b = seqNumber(next)
  if (a === null || b === null) return false
  return b < a
}

// The tail of a TCP chunk is usually half a document, so the remainder is
// returned for the next one to complete.
export function splitLines(buffer: string): { lines: string[]; rest: string } {
  const parts = buffer.split('\n')
  const rest = parts.pop() ?? ''
  return { lines: parts, rest }
}

export interface ChangesPage {
  results: ChangeEvent[]
  lastSeq: Seq | null
}

export function parseChangesPage(body: unknown): ChangesPage {
  const doc = body as { results?: unknown[]; last_seq?: Seq }
  const results: ChangeEvent[] = []

  for (const row of doc.results ?? []) {
    const event = toChangeEvent(row as Record<string, unknown>)
    if (event && 'id' in event) results.push(event)
  }

  return { results, lastSeq: doc.last_seq ?? null }
}

const SEQ_FILE = '.last_seq'

// JSON rather than a bare number: the cursor may be an opaque string, and a run
// that resumes with the wrong type resumes from the start of the database.
export function loadLastSeq(dir: string): Seq | null {
  const path = join(dir, SEQ_FILE)
  if (!existsSync(path)) return null

  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as { seq?: Seq }
    return parsed.seq ?? null
  } catch {
    return null
  }
}

export function saveLastSeq(dir: string, seq: Seq, savedAt = new Date().toISOString()): void {
  writeFileSync(join(dir, SEQ_FILE), JSON.stringify({ seq, savedAt }, null, 2))
}

export interface FeedCapabilities {
  continuous: boolean
  includeDocs: boolean
  updateSeq: Seq | null
  engine: string
  detail: string
}

// Probed rather than assumed, so the monitor does not silently degrade the day
// npm changes what it serves, in either direction.
export async function probeCapabilities(): Promise<FeedCapabilities> {
  let updateSeq: Seq | null = null
  let engine = 'desconocido'

  try {
    const info = await getJson(REPLICATE) as { update_seq?: Seq; engine?: string }
    updateSeq = info.update_seq ?? null
    engine = info.engine ?? 'couchdb'
  } catch { /* the probes below still decide */ }

  const from = updateSeq !== null ? seqNumber(updateSeq) : null
  const since = from !== null ? Math.max(0, from - 5) : 0

  const supports = async (query: string): Promise<boolean> => {
    try {
      await getJson(`${CHANGES_URL}?${query}`)
      return true
    } catch {
      return false
    }
  }

  const [continuous, includeDocs] = await Promise.all([
    supports(`feed=continuous&since=${since}&limit=1&timeout=1000`),
    supports(`since=${since}&limit=1&include_docs=true`),
  ])

  return {
    continuous,
    includeDocs,
    updateSeq,
    engine,
    detail:
      `engine=${engine} - continuous=${continuous ? 'yes' : 'no'} - ` +
      `include_docs=${includeDocs ? 'yes' : 'no'}`,
  }
}

export interface ChangesFeedOptions {
  since: Seq | 'now'
  heartbeatMs?: number
  pollIntervalMs?: number
  pageLimit?: number
  includeDocs?: boolean
  capabilities?: FeedCapabilities
  // Reset by any successful request.
  maxConsecutiveFailures?: number
  onChange: (event: ChangeEvent) => Promise<void>
  // Serial per-change processing tops out near 18 changes a minute against
  // roughly 112 arriving, so a serial consumer falls behind permanently. Handing
  // over the page lets the caller coalesce and parallelise while the cursor
  // still advances in order. It advances only once the page resolves, so a crash
  // mid-page replays it; replaying is safe, skipping would not be.
  onPage?: (events: ChangeEvent[]) => Promise<void>
  onSeq?: (seq: Seq) => void
  onGap?: (gap: SeqGap) => void
  onRewind?: (from: Seq, to: Seq) => void
  // Sequence numbers behind the tip. With a cursor, falling behind is a delay
  // that gets caught up, not a loss — which is what replaces RSS's rollover
  // warning.
  onLag?: (lag: number, tip: Seq) => void
  onConnect?: (since: Seq, mode: 'continuous' | 'paged') => void
  onDisconnect?: (reason: string, attempt: number) => void
  signal?: AbortSignal
}

export function changesUrl(since: Seq, heartbeatMs: number, includeDocs: boolean): string {
  const params = new URLSearchParams({
    feed: 'continuous',
    heartbeat: String(heartbeatMs),
    since: String(since),
  })
  if (includeDocs) params.set('include_docs', 'true')
  return `${CHANGES_URL}?${params.toString()}`
}

export function pagedChangesUrl(since: Seq, limit: number, includeDocs: boolean): string {
  const params = new URLSearchParams({
    since: String(since),
    limit: String(limit),
  })
  if (includeDocs) params.set('include_docs', 'true')
  return `${CHANGES_URL}?${params.toString()}`
}

export class ChangesFeedFailure extends Error {
  constructor(message: string, readonly attempts: number) {
    super(message)
    this.name = 'ChangesFeedFailure'
  }
}

// Throws after maxConsecutiveFailures so the caller can fall back rather than
// sit silent on a dead feed.
export async function streamChanges(options: ChangesFeedOptions): Promise<void> {
  const capabilities = options.capabilities ?? await probeCapabilities()

  // The npm engine has no since=now, so it is resolved client-side. Starting a
  // first run at 0 would replay 124 million changes.
  let since: Seq = options.since === 'now'
    ? (capabilities.updateSeq ?? 0)
    : options.since

  const includeDocs = (options.includeDocs ?? true) && capabilities.includeDocs
  const maxFailures = options.maxConsecutiveFailures ?? 5
  let failures = 0

  for (;;) {
    if (options.signal?.aborted) return

    try {
      options.onConnect?.(since, capabilities.continuous ? 'continuous' : 'paged')

      since = capabilities.continuous
        ? await streamContinuous({ ...options, since, includeDocs })
        : await pollPaged({ ...options, since, includeDocs })

      if (options.signal?.aborted) return
      failures = 0
      options.onDisconnect?.('the server closed the stream', failures)
    } catch (e) {
      failures++
      options.onDisconnect?.(String(e), failures)

      if (failures >= maxFailures) {
        throw new ChangesFeedFailure(`_changes failed ${failures} times in a row: ${e}`, failures)
      }
    }

    // Reconnecting from the persisted cursor means the wait costs latency, not
    // coverage.
    await sleep(Math.min(60_000, 1_000 * 2 ** Math.max(0, failures - 1)), options.signal)
  }
}

// The path npm's engine supports: page forward while pages come back full, then
// idle at the poll interval.
async function pollPaged(
  opts: ChangesFeedOptions & { since: Seq; includeDocs: boolean }
): Promise<Seq> {
  const limit = opts.pageLimit ?? 100
  const pollIntervalMs = opts.pollIntervalMs ?? 10_000

  let since = opts.since
  let prevSeq: Seq | null = null

  for (;;) {
    if (opts.signal?.aborted) return since

    const page = parseChangesPage(await getJson(pagedChangesUrl(since, limit, opts.includeDocs)))

    for (const event of page.results) {
      if (detectCursorRewind(prevSeq, event.seq)) opts.onRewind?.(prevSeq!, event.seq)
      prevSeq = event.seq
    }

    if (opts.onPage) {
      if (page.results.length > 0) {
        await opts.onPage(page.results)

        // One advance per page, after the work. The cursor is the promise that
        // nothing was skipped, so it may only move over changes that have been
        // handed to the consumer in full.
        const last = page.results[page.results.length - 1]!
        since = last.seq
        opts.onSeq?.(last.seq)
      }
    } else {
      for (const event of page.results) {
        if (opts.signal?.aborted) return since
        await opts.onChange(event)
        since = event.seq
        opts.onSeq?.(event.seq)
      }
    }

    // A short page means the cursor caught up. A full one means there is more
    // waiting, so there is no reason to sleep on it.
    if (page.results.length < limit) {
      if (opts.onLag) {
        try {
          const info = await getJson(REPLICATE) as { update_seq?: Seq }
          const tip = info.update_seq
          const a = seqNumber(since)
          const b = tip !== undefined ? seqNumber(tip) : null
          if (a !== null && b !== null) opts.onLag(Math.max(0, b - a), tip!)
        } catch { /* lag is diagnostic; failing to read it must not stop the feed */ }
      }
      await sleep(pollIntervalMs, opts.signal)
    }
  }
}

// Kept for hosts that support it. Resolves with the last sequence seen on a
// clean end, rejects on a connection or watchdog failure.
function streamContinuous(
  opts: ChangesFeedOptions & { since: Seq; includeDocs: boolean }
): Promise<Seq> {
  const heartbeatMs = opts.heartbeatMs ?? 10_000

  return new Promise<Seq>((resolvePromise, reject) => {
    const url = changesUrl(opts.since, heartbeatMs, opts.includeDocs)

    let settled = false
    const settle = (fn: () => void) => { if (!settled) { settled = true; fn() } }

    let buffer = ''
    let lastSeq: Seq = opts.since
    let prevSeq: Seq | null = null

    // The socket is paused while the handler runs: it downloads tarballs, and
    // without backpressure the feed would buffer the firehose into memory while
    // one capture finishes.
    const queue: ChangeEvent[] = []
    let draining = false

    let watchdog: NodeJS.Timeout | undefined
    const armWatchdog = (res?: { destroy: () => void }) => {
      if (watchdog) clearTimeout(watchdog)
      // Silence past two and a half heartbeats means the connection is dead in
      // a way TCP has not noticed yet.
      watchdog = setTimeout(() => {
        res?.destroy()
        settle(() => reject(new Error(`no data for ${(heartbeatMs * 2.5) / 1000}s: dead connection`)))
      }, heartbeatMs * 2.5)
    }

    const req = https.get(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'norte-guard-watcher/0.1.0',
      },
    }, res => {
      if ((res.statusCode ?? 0) >= 400) {
        res.resume()
        settle(() => reject(new Error(`HTTP ${res.statusCode}: ${url}`)))
        return
      }

      res.setEncoding('utf-8')
      armWatchdog(res)

      const drain = async () => {
        if (draining) return
        draining = true
        res.pause()

        try {
          while (queue.length > 0) {
            const event = queue.shift()!
            await opts.onChange(event)
            lastSeq = event.seq
            opts.onSeq?.(event.seq)
          }
        } catch (e) {
          res.destroy()
          settle(() => reject(e))
          return
        } finally {
          draining = false
        }

        if (!res.destroyed) res.resume()
      }

      res.on('data', (chunk: string) => {
        armWatchdog(res)
        buffer += chunk

        const { lines, rest } = splitLines(buffer)
        buffer = rest

        for (const line of lines) {
          const parsed = parseChangeLine(line)
          if (parsed === null) continue

          if ('lastSeq' in parsed) {
            lastSeq = parsed.lastSeq
            continue
          }

          const gap = detectSeqGap(prevSeq, parsed.seq)
          if (gap) opts.onGap?.(gap)
          prevSeq = parsed.seq

          queue.push(parsed)
        }

        if (queue.length > 0) void drain()
      })

      res.on('end', () => {
        if (watchdog) clearTimeout(watchdog)
        settle(() => resolvePromise(lastSeq))
      })

      res.on('error', e => {
        if (watchdog) clearTimeout(watchdog)
        settle(() => reject(e))
      })

      opts.signal?.addEventListener('abort', () => {
        res.destroy()
        if (watchdog) clearTimeout(watchdog)
        settle(() => resolvePromise(lastSeq))
      }, { once: true })
    })

    // Only the connect phase gets a timeout: a quiet feed is not a broken one,
    // which is what the heartbeat watchdog is for.
    req.setTimeout(30_000, () => {
      req.destroy()
      settle(() => reject(new Error(`timeout connecting to ${CHANGES_URL}`)))
    })

    req.on('error', e => {
      if (watchdog) clearTimeout(watchdog)
      settle(() => reject(e))
    })
  })
}

function getJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'norte-guard-watcher/0.1.0',
      },
      timeout: 30_000,
    }, res => {
      if ((res.statusCode ?? 0) >= 400) {
        res.resume()
        reject(new Error(`HTTP ${res.statusCode}: ${url}`))
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

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    if (ms <= 0) return resolve()
    const t = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => { clearTimeout(t); resolve() }, { once: true })
  })
}
