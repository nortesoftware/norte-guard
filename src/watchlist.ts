// The experiment that turns seven unconfirmed blocks into seven labels.
//
// The fabricated-profile conjunction fires on packages nothing has confirmed. A
// month of asking the registry what became of them settles it without anyone
// labelling anything by hand: taken down by npm is a confirmed hit, still alive
// with real downloads at thirty days is a confirmed false positive, and anything
// else is still pending.
//
// The promotion criterion lives here rather than in someone's head, because a
// rule that blocks builds should not go on by default on the strength of a
// recollection about how the tracking looked.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export const WATCHLIST_FILE = 'watchlist.json'
export const TRACKING_LOG = 'tracking-log.ndjson'

// Thirty days of being installed by nobody is what makes "alive" mean something.
// Before that, zero downloads is the normal state of a package published last
// week and says nothing either way.
export const VERDICT_AFTER_DAYS = 30

// Below this a package is not meaningfully installed by anyone: npm's own
// tooling, mirrors and scrapers produce a handful of downloads for everything.
export const REAL_USAGE_DOWNLOADS = 10

export interface WatchedPackage {
  package: string
  version: string
  addedAt: string
  // Why it is being tracked, so a watchlist assembled from several rules stays
  // interpretable.
  reason: string
  observedScore?: number
}

export interface TrackingObservation {
  package: string
  checkedAt: string
  exists: boolean
  takenDown: boolean
  weeklyDownloads: number | null
}

export type TrackedStatus = 'confirmed-takedown' | 'confirmed-false-positive' | 'pending' | 'vanished'

export interface TrackedVerdict {
  package: string
  addedAt: string
  daysTracked: number
  status: TrackedStatus
  lastDownloads: number | null
  detail: string
}

export function loadWatchlist(dir: string): WatchedPackage[] {
  const path = join(dir, WATCHLIST_FILE)
  if (!existsSync(path)) return []
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as WatchedPackage[]
  } catch {
    return []
  }
}

export function saveWatchlist(dir: string, list: WatchedPackage[]): void {
  writeFileSync(join(dir, WATCHLIST_FILE), JSON.stringify(list, null, 2))
}

// Idempotent: re-running the collector or the sweep must not restart anyone's
// thirty-day clock.
export function addToWatchlist(dir: string, entries: WatchedPackage[]): number {
  const existing = loadWatchlist(dir)
  const known = new Set(existing.map(e => `${e.package}@${e.version}`))

  let added = 0
  for (const entry of entries) {
    if (known.has(`${entry.package}@${entry.version}`)) continue
    existing.push(entry)
    known.add(`${entry.package}@${entry.version}`)
    added++
  }

  if (added > 0) saveWatchlist(dir, existing)
  return added
}

export function appendObservation(dir: string, observation: TrackingObservation): void {
  try {
    writeFileSync(join(dir, TRACKING_LOG), JSON.stringify(observation) + '\n', { flag: 'a' })
  } catch { /* one lost line does not invalidate the series */ }
}

export function readObservations(dir: string): TrackingObservation[] {
  const path = join(dir, TRACKING_LOG)
  if (!existsSync(path)) return []

  const rows: TrackingObservation[] = []
  for (const line of readFileSync(path, 'utf-8').split('\n')) {
    if (!line) continue
    try { rows.push(JSON.parse(line) as TrackingObservation) } catch { /* skip */ }
  }
  return rows
}

export function verdictFor(
  entry: WatchedPackage,
  observations: TrackingObservation[],
  now = Date.now()
): TrackedVerdict {
  const mine = observations
    .filter(o => o.package === entry.package)
    .sort((a, b) => a.checkedAt.localeCompare(b.checkedAt))

  const last = mine[mine.length - 1]
  const daysTracked = (now - new Date(entry.addedAt).getTime()) / 86_400_000

  const base = {
    package: entry.package,
    addedAt: entry.addedAt,
    daysTracked: Math.round(daysTracked * 10) / 10,
    lastDownloads: last?.weeklyDownloads ?? null,
  }

  // A takedown at any point settles it, whenever it happened.
  if (mine.some(o => o.takenDown)) {
    return { ...base, status: 'confirmed-takedown', detail: 'npm published 0.0.1-security over it' }
  }

  if (last && !last.exists) {
    return { ...base, status: 'vanished', detail: 'the registry no longer answers: neither removed nor alive' }
  }

  if (daysTracked >= VERDICT_AFTER_DAYS) {
    const downloads = last?.weeklyDownloads ?? 0
    if (downloads >= REAL_USAGE_DOWNLOADS) {
      return {
        ...base,
        status: 'confirmed-false-positive',
        detail: `alive at ${Math.round(daysTracked)} days with ${downloads} weekly downloads: somebody uses it`,
      }
    }
    return {
      ...base,
      status: 'pending',
      detail: `${Math.round(daysTracked)} days, alive, ${downloads} downloads: neither removed nor used`,
    }
  }

  return {
    ...base,
    status: 'pending',
    detail: `${Math.round(daysTracked)} of ${VERDICT_AFTER_DAYS} days`,
  }
}

// A dated checkpoint, so waiting cannot quietly become the plan. Reaching it
// with a large corpus and no confirmations is a result in itself: either the
// filter does not catch the class, or the stream does not carry attacks at this
// rate. Both change what the project should be doing.
export const REVIEW_DATE = '2026-08-26'
export const REVIEW_MIN_CAPTURES = 1000
export const REVIEW_MIN_CONFIRMED = 5

export interface ScheduledReview {
  due: boolean
  daysRemaining: number
  captures: number
  confirmed: number
  verdict: string
}

export function scheduledReview(
  captures: number,
  confirmed: number,
  now = new Date()
): ScheduledReview {
  const dueDate = new Date(`${REVIEW_DATE}T00:00:00Z`)
  const daysRemaining = Math.ceil((dueDate.getTime() - now.getTime()) / 86_400_000)
  const due = daysRemaining <= 0

  if (!due) {
    return {
      due, daysRemaining, captures, confirmed,
      verdict: `review on ${REVIEW_DATE}: ${daysRemaining} days to go ` +
        `(${captures} captures, ${confirmed} confirmed)`,
    }
  }

  if (captures >= REVIEW_MIN_CAPTURES && confirmed < REVIEW_MIN_CONFIRMED) {
    return {
      due, daysRemaining, captures, confirmed,
      verdict:
        `REVIEW DUE, AND IT IS A RESULT: ${captures} captures and only ${confirmed} confirmed. ` +
        `Either the filter does not catch the class, or the stream does not carry attacks ` +
        `at this rate. Both change the project. Decide which, do not keep waiting.`,
    }
  }

  return {
    due, daysRemaining, captures, confirmed,
    verdict: `REVIEW DUE: ${captures} captures, ${confirmed} confirmed. Evaluate.`,
  }
}

export interface PromotionAssessment {
  confirmedTakedowns: number
  confirmedFalsePositives: number
  pending: number
  promotable: boolean
  statement: string
}

// The criterion, in code. Three confirmed removals earn the default; a second
// confirmed false positive takes it away again.
export const PROMOTION_MIN_TAKEDOWNS = 3
export const PROMOTION_MAX_FALSE_POSITIVES = 1

export function assessPromotion(verdicts: TrackedVerdict[]): PromotionAssessment {
  const confirmedTakedowns = verdicts.filter(v => v.status === 'confirmed-takedown').length
  const confirmedFalsePositives = verdicts.filter(v => v.status === 'confirmed-false-positive').length
  const pending = verdicts.filter(v => v.status === 'pending').length

  const promotable =
    confirmedTakedowns >= PROMOTION_MIN_TAKEDOWNS &&
    confirmedFalsePositives <= PROMOTION_MAX_FALSE_POSITIVES

  return {
    confirmedTakedowns,
    confirmedFalsePositives,
    pending,
    promotable,
    statement: promotable
      ? `PROMOTABLE to default: ${confirmedTakedowns} confirmed removals, ` +
        `${confirmedFalsePositives} confirmed false positives`
      : `stays opt-in: needs >=${PROMOTION_MIN_TAKEDOWNS} removals ` +
        `(have ${confirmedTakedowns}) and <=${PROMOTION_MAX_FALSE_POSITIVES} false positives ` +
        `(have ${confirmedFalsePositives}) - ${pending} pending`,
  }
}
