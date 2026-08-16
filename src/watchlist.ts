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
//
// It also has to survive being read early. Removals arrive within hours and
// false positives are defined at thirty days, so a criterion that simply counts
// both says PROMOTABLE on day one for any rule at all. What it counts is
// therefore narrower on one side and wider on the other: only removals the rule
// itself would have caused, and false positives that have arrived but not yet
// aged into the definition.

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
  // The weekly count as it stood when the entry was made, when whoever made it
  // had one. Absent from every entry seeded out of changes-log.ndjson: the log
  // records the four free conditions and never the fifth, so an entry from there
  // cannot say whether the rule would have fired.
  weeklyDownloadsAtEntry?: number | null
  // Whether the week that count covered overlapped the package's life. Without
  // it a recorded zero cannot be told from npm's 404 for a name it never had.
  downloadWindowCoversAtEntry?: boolean | null
}

export interface TrackingObservation {
  package: string
  checkedAt: string
  exists: boolean
  takenDown: boolean
  weeklyDownloads: number | null
}

export type TrackedStatus = 'confirmed-takedown' | 'confirmed-false-positive' | 'pending' | 'vanished'

// Which rule a record is evidence about, which is not the same question as what
// happened to the package.
//
// Two criteria in this project are both called "the four free conditions" and
// they are not the same criterion. The capture filter and the watchlist select
// on four — no genome, name under seven days, under 100KB, no repository. The
// rule that fails builds needs a fifth, the weekly download count as it stood at
// publication, and declines to apply without it.
//
// So a removal can be a removal of something the filter kept and the rule would
// never have blocked. Counting those toward promoting the rule is how a record
// of one criterion came to be read as evidence for another.
//
//   rule-matched  the count was zero over a week that overlapped the name's
//                 life: the rule fired on something that could have been
//                 downloaded and was not.
//   vacuous-zero  the count was zero over a week that closed before the name
//                 existed, or over no window at all because npm answered 404 for
//                 a name it had never heard of. The conjunction holds and says
//                 nothing: no download can happen inside a window the package
//                 was not alive for.
//   rule-cleared  the count was not zero: the rule did not fire, so whatever
//                 happened next says nothing about it.
//   unverifiable  no count was recorded. npm serves one complete week at a time,
//                 so this can never be established afterwards — not with more
//                 patience, not with another sweep. The record is permanently
//                 silent about the rule.
//
// The fourth state is not a refinement, it is the difference between a criterion
// and a rubber stamp. npm answers 404 for a package published minutes ago, which
// is what this class is made of, and downloads.ts reads that as zero because for
// a verdict it is one. Grade it as a match and a restarted collector
// manufactures three removals' worth of promotion evidence out of three 404s
// within a day — the same mistake this whole file exists to have caught once.
export type RuleEvidence = 'rule-matched' | 'vacuous-zero' | 'rule-cleared' | 'unverifiable'

// Zero and unknown are different answers, and so are the two kinds of zero. See
// downloads.ts, which returns null for the first distinction and
// synthesizedFrom404 for the second.
export function ruleEvidenceFor(
  weeklyDownloads: number | null | undefined,
  // Whether npm's window overlapped the name's life, as recorded at capture.
  // Undefined means the capture predates the field, and it grades as vacuous
  // rather than as a match nobody established: a build-failing rule does not get
  // the benefit of the doubt from a record that cannot give it.
  windowCovers?: boolean | null
): RuleEvidence {
  if (weeklyDownloads === undefined || weeklyDownloads === null) return 'unverifiable'
  if (weeklyDownloads !== 0) return 'rule-cleared'
  return windowCovers === true ? 'rule-matched' : 'vacuous-zero'
}

export interface TrackedVerdict {
  package: string
  addedAt: string
  daysTracked: number
  status: TrackedStatus
  lastDownloads: number | null
  // What this record can say about the rule that blocks builds, as opposed to
  // the filter that selected the package.
  ruleEvidence: RuleEvidence
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
    // The count observed today is not the one the conjunction asks about. The
    // rule reads the week before publication; tracking reads this week, which is
    // the week the answer is being waited on. Only what was recorded at entry
    // can settle it.
    ruleEvidence: ruleEvidenceFor(entry.weeklyDownloadsAtEntry, entry.downloadWindowCoversAtEntry),
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

// The other half of the evidence, and the half that arrived first.
//
// The watchlist follows names the rule flagged and waits thirty days for the
// registry to settle them. Quarantine takes a different route to the same fact:
// it keeps every publication matching the four free conditions — which is what
// captureReason 'quarantine-no-genome' records — and when npm later publishes
// 0.0.1-security over one, the sweep labels the capture confirmed_malicious with
// npm's own removal as the source.
//
// Those are confirmed removals, established by the same authority as the
// watchlist's. What they are not — and what this comment used to claim they were
// — is removals of exactly the class the rule blocks. The capture filter keeps
// four conditions; the rule needs five. Every capture on disk today is silent
// about the fifth, so these removals confirm the filter and leave the rule
// unmeasured. `ruleEvidence` on each verdict is which of the two a record is,
// and the promotion criterion below counts only the ones that reach the rule.
export interface ClassCapture {
  package: string
  version: string
  capturedAt: string
  label: string
  labelSource?: string
  captureReason?: string
  // The weekly count the watcher recorded alongside the snapshot, which is the
  // only way the fifth conjunct can be answered after the fact. Absent on every
  // capture taken before the watcher started recording it, and absent for good:
  // that week has closed at npm and will not be served again.
  weeklyDownloads?: number | null
  // Whether that count's week overlapped the package's life, as recorded at
  // capture. Absent on every capture that predates the field, and graded
  // conservatively when absent.
  downloadWindowCovers?: boolean | null
  contaminated: boolean
}

export const QUARANTINE_CAPTURE_REASON = 'quarantine-no-genome'

export function verdictsFromCaptures(
  captures: ClassCapture[],
  now = Date.now()
): TrackedVerdict[] {
  // One verdict per PACKAGE, not per capture directory. The same package is
  // captured again on every publication, and counting three snapshots of one
  // removal as three removals would clear the promotion criterion on one event.
  const seen = new Set<string>()

  return captures
    .filter(c =>
      !c.contaminated &&
      c.captureReason === QUARANTINE_CAPTURE_REASON &&
      c.label === 'confirmed_malicious' &&
      // npm's removal, not ours. A capture labelled from anything else is
      // evidence of something, but not of this.
      Boolean(c.labelSource?.includes('npm-takedown'))
    )
    .filter(c => {
      if (seen.has(c.package)) return false
      seen.add(c.package)
      return true
    })
    .map(c => {
      const ruleEvidence = ruleEvidenceFor(c.weeklyDownloads, c.downloadWindowCovers)
      return {
        package: c.package,
        addedAt: c.capturedAt,
        daysTracked: Math.round(((now - new Date(c.capturedAt).getTime()) / 86_400_000) * 10) / 10,
        status: 'confirmed-takedown' as const,
        lastDownloads: null,
        ruleEvidence,
        // The detail used to say "with the four free conditions holding" and
        // stop there, which read as though the rule had fired. Four of them did
        // hold; the rule needs five, and which of the three things that means is
        // the only part a reader needs.
        detail:
          `quarantined by the capture filter (4 conditions), ${c.version} removed by npm` +
          (ruleEvidence === 'rule-matched'
            ? '; 0 downloads over a week the package was alive for, so the 5-condition rule would have blocked it'
            : ruleEvidence === 'vacuous-zero'
              ? '; the recorded 0 covers a week that closed before the name existed, so the conjunction ' +
                'holds vacuously and this removal says nothing about the rule'
              : ruleEvidence === 'rule-cleared'
                ? `; the recorded count was ${c.weeklyDownloads}, so the 5-condition rule would NOT have blocked it`
                : '; no download count in the snapshot, so what the 5-condition rule would have done is unknowable'),
      }
    })
}

export interface PromotionAssessment {
  confirmedTakedowns: number
  // Of those removals, the ones whose record can show the rule actually firing.
  // This is the number the criterion runs on; the one above is the wider class.
  verifiedTakedowns: number
  unverifiableTakedowns: number
  // Removals whose recorded zero came from a week the package had not been
  // published in. The conjunction holds on them and means nothing, and they are
  // counted separately rather than folded into the unverifiable ones because
  // they are the failure mode that arrives on its own: npm answers 404 for a
  // freshly published name, that reads as zero, and the criterion fills up with
  // evidence nobody measured.
  vacuousTakedowns: number
  confirmedFalsePositives: number
  // Packages already alive with real usage whose thirty days have not run out.
  //
  // This exists because the criterion is not symmetric in time and was reading
  // as though it were. npm removes a fabricated package within hours, so every
  // true positive this criterion will ever see has already arrived by day one. A
  // false positive is defined as thirty days alive and installed by somebody, so
  // none of them can arrive before day thirty. Read at day three, the criterion
  // therefore counts every hit and no miss, and says PROMOTABLE whatever the
  // rule does — including for a rule that blocks nothing but ordinary new
  // packages.
  //
  // These are the misses that have already arrived and cannot yet be called
  // misses. Waiting for them to age is the honest thing to do; ignoring them
  // while counting the hits that do not have to wait is not.
  emergingFalsePositives: number
  pending: number
  promotable: boolean
  statement: string
  // Every reason promotion is being withheld, so "not yet" never has to be
  // told apart from "not this rule" by inference.
  blockers: string[]
}

// The criterion, in code. Three confirmed removals earn the default; a second
// confirmed false positive takes it away again.
export const PROMOTION_MIN_TAKEDOWNS = 3
export const PROMOTION_MAX_FALSE_POSITIVES = 1

export function assessPromotion(verdicts: TrackedVerdict[]): PromotionAssessment {
  const takedowns = verdicts.filter(v => v.status === 'confirmed-takedown')
  const confirmedTakedowns = takedowns.length
  const verifiedTakedowns = takedowns.filter(v => v.ruleEvidence === 'rule-matched').length
  const unverifiableTakedowns = takedowns.filter(v => v.ruleEvidence === 'unverifiable').length
  const vacuousTakedowns = takedowns.filter(v => v.ruleEvidence === 'vacuous-zero').length

  const confirmedFalsePositives = verdicts.filter(v => v.status === 'confirmed-false-positive').length
  const pending = verdicts.filter(v => v.status === 'pending').length

  // Counted over the whole tracked class, not only over records the rule can be
  // verified against. The class is a superset of the rule, so a package the
  // class flagged and somebody installs is a candidate false positive for the
  // rule — and for something that fails builds, a candidate is what should stop
  // the switch being thrown, not what should be discounted until proven.
  const emergingFalsePositives = verdicts.filter(
    v => v.status === 'pending' &&
      v.lastDownloads !== null &&
      v.lastDownloads >= REAL_USAGE_DOWNLOADS
  ).length

  const blockers: string[] = []
  if (verifiedTakedowns < PROMOTION_MIN_TAKEDOWNS) {
    blockers.push(
      `${verifiedTakedowns}/${PROMOTION_MIN_TAKEDOWNS} removals can be traced to the rule firing` +
      (unverifiableTakedowns > 0
        ? ` (${unverifiableTakedowns} more were removed but their snapshots carry no download count, ` +
          `so they are evidence for the capture filter and not for the rule)`
        : '')
    )
  }
  if (vacuousTakedowns > 0) {
    blockers.push(
      `${vacuousTakedowns} removals had a zero recorded over a week that closed before the name ` +
      `existed, or over no window at all because npm had never heard of it. That is arithmetic, ` +
      `not a measurement, and it does not count toward promoting anything`
    )
  }
  if (confirmedFalsePositives + emergingFalsePositives > PROMOTION_MAX_FALSE_POSITIVES) {
    blockers.push(
      `${confirmedFalsePositives} confirmed false positives and ${emergingFalsePositives} already ` +
      `alive with >=${REAL_USAGE_DOWNLOADS} weekly downloads before their ${VERDICT_AFTER_DAYS} days ` +
      `are up, against a ceiling of ${PROMOTION_MAX_FALSE_POSITIVES}`
    )
  }

  const promotable = blockers.length === 0

  return {
    confirmedTakedowns,
    verifiedTakedowns,
    unverifiableTakedowns,
    vacuousTakedowns,
    confirmedFalsePositives,
    emergingFalsePositives,
    pending,
    promotable,
    blockers,
    statement: promotable
      ? `PROMOTABLE to default: ${verifiedTakedowns} removals of packages the rule itself would ` +
        `have blocked, ${confirmedFalsePositives} confirmed false positives`
      : `STAYS OPT-IN - ${blockers.join('; ')} - ${pending} pending`,
  }
}
