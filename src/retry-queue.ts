// A 404 on the first fetch is not an answer, and until now it was treated as one.
//
// The change feed announces a publication and the watcher fetches the packument
// within about a second. npm's read path is not consistent that fast: for 12,638
// packages the fetch came back 404, and because nothing retried, 6,892 of them
// (54.5%) were never analysed at all. Six of those 6,892 were later removed by
// npm — confirmed attacks that this collector announced to itself and then
// dropped, including `depcruise-wrap-stream-in-html` and
// `eslint-generate-prerelease`, which belong to the same operator as three
// packages already in the corpus.
//
// The window is not tight. `shared-slot-gate` 404ed at 09:30:10 and npm did not
// remove it until 16:19 — nearly seven hours during which one more request would
// have got it. The cost of never asking again was the whole sample.
//
// So: a bounded queue on disk, four attempts on a widening schedule, and a
// permanent-loss record for what is still gone at the end of it. The record
// matters as much as the retry — "we asked five times over two hours and it was
// never there" is a fact about the registry, while a silent drop is a fact about
// us that looks like one about the registry.

import { existsSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'
import type { UnreachableReason } from './watcher.js'

export const RETRY_QUEUE_FILE = 'retry-queue.json'
export const PERMANENT_LOSS_LOG = 'lost-publications.ndjson'

// 30s, 5min, 30min, 2h. Four attempts spanning about two and a half hours,
// chosen against the observed removal times rather than as round numbers: npm's
// median time to remediation is 64 minutes, so a schedule that gives up inside
// an hour would systematically miss the packages that matter most — the ones
// npm is about to remove.
export const RETRY_SCHEDULE_SECONDS = [30, 300, 1800, 7200]

// A registry outage announces thousands of unreachable publications in minutes.
// Without a bound the queue becomes the outage's memory and the watcher spends
// the next day replaying it instead of following the feed. Oldest entries are
// dropped first and the drop is counted, because a queue that silently forgets
// is the defect this module exists to fix, one level up.
export const MAX_QUEUE = 5_000

// Which failures are worth asking about again.
//
// `malformed` is not: the packument parsed badly and will parse badly again, so
// a retry spends a request to reach the same branch. The other three are all
// transient in principle — a 404 from a read replica that has not caught up, a
// timeout, a 5xx — and 404 is the one that carries the corpus.
export const RETRYABLE: UnreachableReason[] = ['404', 'timeout', 'http-error', 'other']

export function isRetryable(reason: UnreachableReason | undefined): boolean {
  return reason !== undefined && RETRYABLE.includes(reason)
}

// Why the package is in the queue, and therefore what a retry should DO with it.
//
// A feed-announced publication is replayed through the ordinary policy. A
// dependency is not: it is in the queue because something already captured
// declares it, and re-running it through the score path would reject it for
// exactly the reasons the dependency rule exists to overrule — `mutex-forge`
// scored 10. Losing the origin would quietly convert the second kind into the
// first, which is the whole defect in miniature.
export type RetryOrigin = 'feed' | 'dependency'

export interface RetryEntry {
  package: string
  origin: RetryOrigin
  // Set only for `dependency` entries: who pointed at it, so a recovery can
  // record the same provenance a first-try capture would have.
  declaredBy?: string
  declaredByVersion?: string
  // The sequence the publication was announced at. Kept so a recovered capture
  // can be tied back to the feed position it came from, which is the only way to
  // tell a recovery from an ordinary later publication. Widened to a string
  // because a CouchDB mirror emits opaque sequences where npm emits integers,
  // and the queue must survive either.
  seq: number | string
  firstSeenAt: string
  reason: UnreachableReason
  attempts: number
  nextAttemptAt: string
}

export interface QueueState {
  entries: RetryEntry[]
  // Counted rather than logged per event: a full queue is one condition, not
  // five thousand.
  dropped: number
}

export function loadQueue(outputDir: string): QueueState {
  const path = join(outputDir, RETRY_QUEUE_FILE)
  if (!existsSync(path)) return { entries: [], dropped: 0 }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as Partial<QueueState>
    return {
      entries: Array.isArray(parsed.entries) ? parsed.entries : [],
      dropped: typeof parsed.dropped === 'number' ? parsed.dropped : 0,
    }
  } catch {
    // A corrupt queue is an empty queue, not a crash. What it holds is a second
    // chance at something already recorded as unreachable; losing it costs a
    // retry, and refusing to start costs the feed.
    return { entries: [], dropped: 0 }
  }
}

export function saveQueue(outputDir: string, state: QueueState): void {
  writeFileSync(join(outputDir, RETRY_QUEUE_FILE), JSON.stringify(state, null, 2))
}

export function enqueue(
  state: QueueState,
  input: {
    package: string
    seq: number | string
    reason: UnreachableReason
    now: number
    origin?: RetryOrigin
    declaredBy?: string
    declaredByVersion?: string
  }
): QueueState {
  if (!isRetryable(input.reason)) return state

  // One entry per package. A package announced three times in a minute is one
  // thing to go back for, and three entries would spend three requests to learn
  // the same fact.
  const existing = state.entries.find(e => e.package === input.package)
  if (existing) return state

  const entry: RetryEntry = {
    package: input.package,
    origin: input.origin ?? 'feed',
    declaredBy: input.declaredBy,
    declaredByVersion: input.declaredByVersion,
    seq: input.seq,
    firstSeenAt: new Date(input.now).toISOString(),
    reason: input.reason,
    attempts: 0,
    nextAttemptAt: new Date(input.now + RETRY_SCHEDULE_SECONDS[0]! * 1000).toISOString(),
  }

  const entries = [...state.entries, entry]
  let dropped = state.dropped
  while (entries.length > MAX_QUEUE) {
    entries.shift()
    dropped += 1
  }
  return { entries, dropped }
}

export function due(state: QueueState, now: number): RetryEntry[] {
  const at = new Date(now).toISOString()
  return state.entries.filter(e => e.nextAttemptAt <= at)
}

export interface AttemptOutcome {
  state: QueueState
  // True when the schedule is exhausted and the package is being given up on.
  // The caller writes the permanent-loss record; this function does not do IO
  // beyond the queue so that a test can drive it.
  exhausted: boolean
}

// Records one attempt. `recovered` removes the entry; a failure either
// reschedules it or exhausts it.
export function recordAttempt(
  state: QueueState,
  packageName: string,
  recovered: boolean,
  now: number
): AttemptOutcome {
  const entry = state.entries.find(e => e.package === packageName)
  if (!entry) return { state, exhausted: false }

  const without = state.entries.filter(e => e.package !== packageName)
  if (recovered) return { state: { ...state, entries: without }, exhausted: false }

  const attempts = entry.attempts + 1
  if (attempts >= RETRY_SCHEDULE_SECONDS.length) {
    return { state: { ...state, entries: without }, exhausted: true }
  }

  const next: RetryEntry = {
    ...entry,
    attempts,
    nextAttemptAt: new Date(now + RETRY_SCHEDULE_SECONDS[attempts]! * 1000).toISOString(),
  }
  return { state: { ...state, entries: [...without, next] }, exhausted: false }
}

// What is still gone after the whole schedule. Appended rather than counted,
// because the interesting question about a permanent loss is which package it
// was — the six confirmed removals hiding in the 6,892 were only findable
// because the name was on disk somewhere.
export function recordPermanentLoss(
  outputDir: string,
  entry: RetryEntry,
  now: number
): void {
  appendFileSync(
    join(outputDir, PERMANENT_LOSS_LOG),
    `${JSON.stringify({
      package: entry.package,
      seq: entry.seq,
      firstSeenAt: entry.firstSeenAt,
      reason: entry.reason,
      origin: entry.origin,
      declaredBy: entry.declaredBy,
      attempts: entry.attempts + 1,
      gaveUpAt: new Date(now).toISOString(),
      // Stated in the record so a reader of the log does not have to find this
      // file to know what it means.
      note: 'announced by the change feed, never fetchable across the full retry schedule',
    })}\n`
  )
}
