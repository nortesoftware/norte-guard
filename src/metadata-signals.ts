// IDEA 3 — the endpoints that do not need the tarball.
//
// A5 saturated on four capabilities, and every one of them is answered by
// reading bytes. That is why the corpus outside this collector cannot be used
// for it at all: 0 of 42 confirmed removals gathered elsewhere still has an
// artifact, so 26 publishers' worth of attack is unanalysable by any question
// phrased over contents. The packument survives the takedown, and this module is
// the set of questions that can be asked of it alone.
//
// It survives more completely than expected. @siwatfa/yorn was removed on
// 2026-08-17 and its packument still carries 149 publication timestamps between
// 2026-08-12T10:55 and 2026-08-16T23:28 — the whole release cadence of the
// attack, months after the versions themselves stopped resolving. npm deletes
// the versions and keeps `time`.
//
// WHAT THIS MODULE IS NOT ALLOWED TO FORGET. D11 established that any endpoint
// which is an INPUT to the capture decision separates against the raw pool and
// vanishes against a class-matched one — `has_trusted_publisher` measured
// −44.7pp against every capture reason and exactly 0.0pp against the class,
// because trusted publishing needs a GitHub repository and `!hasRepository` is
// one of the three conjuncts the quarantine filter selects on. A metadata pass
// is where that mistake is easiest to make a second time, because most of what a
// packument says about a young package is downstream of the package being young.
//
// So every endpoint here carries a frozen declaration of its relationship to the
// three conjuncts — `young`, `tiny`, `!hasRepository` — and the report prints it
// beside the number. An endpoint marked `entailed` that separates is not a
// finding; it is the filter measuring itself.

import { nameAgeDays, TINY_PACKAGE_BYTES, YOUNG_NAME_DAYS } from './observed-class.js'
import { hasProvenance, provenanceLostSignal } from './absolute-risk.js'
import type { Packument, VersionMeta } from './packument.js'
import { publisherOf } from './capability-control.js'

// ---------------------------------------------------------------------------
// The publication record, repaired
// ---------------------------------------------------------------------------

// `time.created` is not the package's birth, and reading it as one is a defect
// this module exists downstream of.
//
// After npm removes a package it republishes the name as `0.0.1-security`, and
// that write resets `time.created` to the moment of the takedown. @siwatfa/yorn
// reports `created` = 2026-08-17T10:09:45 with an earliest release of
// 2026-08-12T10:55: five days of life recorded as zero. It is not only a
// takedown artifact — 631 of 24,307 captures in the store have a `created` later
// than their own first release, and `typeguard-ts@2.2.1` reports 2.88 days
// against a true 935.92.
//
// The consequence is not cosmetic. `nameAgeDays` in observed-class.ts prefers
// `createdAt` and falls back to the timestamps, so those packages are scored
// YOUNG when they are old, and `young` is one of the three conjuncts the
// quarantine filter selects on. 133 captures flip the conjunct that way and 17
// enter the observed class on it alone, 5 of them under
// `quarantine-no-genome` — the reason the class-matched control arm is drawn
// from. It admits old packages to a class defined as new ones, so it runs
// AGAINST any difference the case arm shows, which is why it is reported rather
// than treated as invalidating.
//
// Here the first release is taken from the version timestamps and `created` is
// consulted only when there are none.
export function firstReleaseAt(p: Packument): string | null {
  const stamps = releaseTimestamps(p)
  if (stamps.length > 0) return stamps[0]!.at
  return p.createdAt ?? null
}

// True when `time.created` claims the package is younger than its own earliest
// release. Recorded per package so the prevalence can be read off a run rather
// than argued from the two examples above.
export function createdAtIsAfterFirstRelease(p: Packument): boolean {
  const stamps = releaseTimestamps(p)
  const declared = p.createdAt ?? p.time?.['created']
  if (!declared || stamps.length === 0) return false
  return declared > stamps[0]!.at
}

export interface Release {
  version: string
  at: string
}

// Every version npm has a timestamp for, oldest first — INCLUDING versions that
// no longer exist in `versions`. That gap is the whole point: for a removed
// package the timestamps are all that is left, and a function that walked
// `versions` would report a 149-release attack as a single publication.
export function releaseTimestamps(p: Packument): Release[] {
  const out: Release[] = []
  for (const [version, at] of Object.entries(p.time ?? {})) {
    if (version === 'created' || version === 'modified') continue
    if (typeof at !== 'string' || at === '') continue
    out.push({ version, at })
  }
  return out.sort((a, b) => a.at.localeCompare(b.at))
}

// The security placeholder is npm's write, not the publisher's, and counting it
// as a release would credit every removed package with one publication it did
// not make and one interval it did not choose.
export const TAKEDOWN_PLACEHOLDER = '0.0.1-security'

export function authoredReleases(p: Packument): Release[] {
  return releaseTimestamps(p).filter(r => r.version !== TAKEDOWN_PLACEHOLDER)
}

// The registry publishing as itself, which is not a publisher.
//
// When npm removes a package it republishes the name as `0.0.1-security` under
// `_npmUser` = {name: "npm", email: "npm@npmjs.com"} and rewrites `maintainers`
// to npm-support. Read literally that is one account, and it is the account that
// "published" every removed package in the store — so the first family run
// grouped @siwatfa/yorn, gunzip-js and @guildai-services/guildai into one batch
// on the strength of npm having taken all three down within 205 minutes of each
// other.
//
// That is the OIDC bot defect in a second costume: a shared identity standing in
// for many real ones, silently folding unrelated packages into one unit. The
// difference is the direction — the OIDC bot collapsed sixteen control packages
// out of the primary analysis, this one INVENTS coordination among the cases,
// which is the direction that manufactures a finding. Anything grouping by
// account has to reject it, and the check is structural (the reserved account
// and its address) rather than a name match, so an operator calling themselves
// `npm-support` does not disappear from the corpus.
export function isRegistryIdentity(user: { name?: string; email?: string } | undefined): boolean {
  if (!user) return false
  return (
    user.email === 'npm@npmjs.com' ||
    user.email === 'support@npmjs.com' ||
    user.name === 'npm' ||
    user.name === 'npm-support'
  )
}

// True when the captured version IS npm's takedown placeholder. Such a capture
// carries no fact the publisher authored: not a size, not a dependency list, not
// an install script. Its timestamps are still theirs, which is why the packument
// is kept and only the version is disqualified.
export function isTakedownPlaceholder(version: string): boolean {
  return version === TAKEDOWN_PLACEHOLDER
}

// The account a captured version should be attributed to, or null when the
// record does not support attributing it to anyone. The single entry point for
// this question, so the registry guard cannot be applied in one caller and
// forgotten in the next — which is exactly how the OIDC bot survived to v1.3.0.
export function publisherFor(p: Packument, version: string): string | null {
  const meta = p.versions[version]
  const npmUser = meta?._npmUser as
    | { name?: string; email?: string; trustedPublisher?: unknown }
    | undefined
  const maintainers = p.maintainers ?? []
  if (isRegistryIdentity(npmUser) || isRegistryIdentity(maintainers[0])) return null
  return publisherOf(npmUser, maintainers)
}

// ---------------------------------------------------------------------------
// Contamination, declared before the run
// ---------------------------------------------------------------------------

// How an endpoint stands to the three conjuncts of the class the capture filter
// selects on: `young` (name under 7 days), `tiny` (under 100KB), and
// `!hasRepository`.
//
//   entailed     the conjunct forces the answer. A difference against a raw pool
//                is the filter, and against a class-matched pool there is
//                nothing left to see. Measured anyway, and reported as an
//                artifact rather than as a signal.
//   partial      the conjunct bounds the answer without fixing it. `young` caps
//                how many releases a package can have made, but not how fast it
//                made them.
//   independent  nothing in the capture decision constrains it. These are the
//                only rows a finding can come from.
export type Contamination = 'entailed' | 'partial' | 'independent'

export interface EndpointDeclaration {
  key: string
  // What the number means in one line, printed with it.
  reads: string
  contamination: Contamination
  // Why it has that status. Written here so a reader can disagree with the
  // classification without reverse-engineering it from the code.
  because: string
}

// Frozen. Adding a row after seeing a result is the thing this table exists to
// make visible, so it is ordered by contamination and never by outcome.
export const ENDPOINTS: EndpointDeclaration[] = [
  {
    key: 'median_interval_minutes',
    reads: 'median minutes between consecutive publications',
    contamination: 'independent',
    because:
      'A package under seven days old can publish twice or two hundred times. Nothing ' +
      'in young, tiny or !hasRepository decides the spacing.',
  },
  {
    key: 'fastest_interval_minutes',
    reads: 'shortest gap between any two consecutive publications',
    contamination: 'independent',
    because: 'Same argument as the median, and the tail is where a scripted release loop shows.',
  },
  {
    key: 'publisher_is_declared_maintainer',
    reads: 'the account that published the version appears in the maintainer list',
    contamination: 'independent',
    because:
      'Maintainer membership is a registry fact about an account, unconstrained by the ' +
      'age, the size or the repository field of the package it published.',
  },
  {
    key: 'dependency_churn',
    reads: 'dependencies added or removed against the previous version',
    contamination: 'independent',
    because:
      'Needs two versions, which young does not prevent, and the dependency list is not ' +
      'read by the capture filter at all.',
  },
  {
    key: 'multi_maintainer',
    reads: 'more than one account is listed as maintainer',
    contamination: 'independent',
    because: 'Not an input to the class, and it is the metadata form of "somebody else is watching".',
  },
  {
    key: 'releases_per_day',
    reads: 'authored releases divided by the days between the first and the last',
    contamination: 'partial',
    because:
      'young bounds the span this can be measured over — a seven-day-old package cannot ' +
      'show a slow year — so the denominator is squeezed on the case side by the filter.',
  },
  {
    key: 'release_count',
    reads: 'number of authored publications, placeholder excluded',
    contamination: 'partial',
    because:
      'young caps it in practice. Reported because the cap is loose: 149 releases in five ' +
      'days is not something the conjunct forces.',
  },
  {
    key: 'version_ahead_of_releases',
    reads: 'declared semver implies more history than the package has releases',
    contamination: 'partial',
    because:
      'young makes a low release count likely, so half of this ratio is downstream of the ' +
      'filter. The declared version is not.',
  },
  {
    key: 'name_age_days',
    reads: 'days between the first authored release and the capture',
    contamination: 'entailed',
    because:
      'It IS the young conjunct, measured continuously. Against a class-matched control ' +
      'both arms are under seven days by construction. Present to make the entailment ' +
      'visible in the output rather than to test anything.',
  },
  {
    key: 'has_provenance',
    reads: 'npm attestations or a trusted publisher on the captured version',
    contamination: 'entailed',
    because:
      'Trusted publishing needs a GitHub repository and a workflow, and !hasRepository is a ' +
      'conjunct. Measured at full size in D11: 0/10 cases against 0/950 class-matched ' +
      'controls, exactly 0.0pp, against −44.7pp on the raw pool.',
  },
  {
    key: 'provenance_lost',
    reads: 'a previous version was signed and the captured one is not',
    contamination: 'entailed',
    because:
      'Requires a signed predecessor, which requires the repository the conjunct excludes. ' +
      'Cannot fire on either arm of a class-matched comparison, and a 0-versus-0 is not a ' +
      'result.',
  },
]

export function declarationOf(key: string): EndpointDeclaration | null {
  return ENDPOINTS.find(e => e.key === key) ?? null
}

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

export interface DependencyChurn {
  added: number
  removed: number
  kept: number
  previousVersion: string
}

export interface MetadataProfile {
  package: string
  version: string
  capturedAt: string

  // ---- the publication record ---------------------------------------------
  firstReleaseAt: string | null
  releaseCount: number
  releaseSpanHours: number | null
  // Null rather than zero when there is one release: a package that has never
  // published twice has no interval, and a zero there would read as "published
  // twice in the same instant", which is the opposite fact.
  medianIntervalMinutes: number | null
  fastestIntervalMinutes: number | null
  releasesPerDay: number | null

  // ---- the account --------------------------------------------------------
  publisher: string | null
  publisherIsDeclaredMaintainer: boolean | null
  maintainerCount: number

  // ---- the version --------------------------------------------------------
  dependencyChurn: DependencyChurn | null
  declaredMajor: number | null
  versionAheadOfReleases: boolean | null
  publishedAtUTC: string | null
  // The UTC hour, recorded and deliberately NOT turned into an "off hours"
  // endpoint. See the note on hourOfDay below.
  publishHourUTC: number | null

  // ---- the conjuncts, recorded so contamination can be SEEN ----------------
  nameAgeDays: number | null
  unpackedSize: number
  hasRepository: boolean
  hasProvenance: boolean
  provenanceLost: boolean
  // Whether this package's own record carries the `created`-after-first-release
  // defect. Not an endpoint: a property of the data that decides whether
  // nameAgeDays can be read at all.
  createdAtAfterFirstRelease: boolean
}

// The hour of the day was on the list of signals to try and it is recorded
// without being tested, which is a decision and not an omission.
//
// A UTC publish hour is the publisher's LONGITUDE plus their working habits, and
// this cohort has 8 case accounts against controls drawn from the whole
// registry. "Published at 03:00 UTC" separates Jakarta from Berlin far more
// strongly than it separates malice from maintenance, and with 8 accounts the
// case side is one draw from a timezone distribution, not a sample of one.
// Turning it into a rate would produce a number whose mechanism is geography,
// and the run would report it in the same table as the rest.
//
// What the hour IS good for is the family: several packages published inside one
// twenty-minute window is a fact about coordination that needs no timezone at
// all, because it is a difference of timestamps rather than a position on the
// clock. It is used there — see family.ts — and the raw hour is kept here so
// that a future cohort with enough accounts to model the confound can revisit it
// without recollecting anything.
export const HOUR_OF_DAY_IS_RECORDED_NOT_TESTED = true

export function metadataProfileOf(input: {
  packument: Packument
  version: string
  capturedAt: string
}): MetadataProfile | null {
  const { packument, version, capturedAt } = input
  const meta: VersionMeta | undefined = packument.versions[version]

  const releases = authoredReleases(packument)
  const at = new Date(capturedAt).getTime()

  const intervals = intervalMinutes(releases)
  const first = releases[0]?.at ?? firstReleaseAt(packument)
  const last = releases[releases.length - 1]?.at ?? null
  const spanHours =
    first && last && last > first
      ? (new Date(last).getTime() - new Date(first).getTime()) / 3_600_000
      : releases.length > 1 ? 0 : null

  // Ages from the repaired first release, not from `created`. A packument with
  // no timestamps at all yields null and is held out rather than given a zero.
  const ageDays =
    first !== null && Number.isFinite(at)
      ? (at - new Date(first).getTime()) / 86_400_000
      : nameAgeDays(packument, Number.isFinite(at) ? at : undefined)

  const maintainers = packument.maintainers ?? []
  const npmUser = meta?._npmUser as
    | { name?: string; email?: string; trustedPublisher?: unknown }
    | undefined

  // After a takedown BOTH sides of publisherOf's fallback are the registry —
  // `_npmUser` is npm and `maintainers` is npm-support — so the guard has to sit
  // in front of the call rather than inside it, and the answer is null. Not
  // knowing who published a removed package is the truth about the record, and
  // the alternative is attributing it to npm.
  const publisher = publisherFor(packument, version)

  const publishedAt = packument.time?.[version] ?? meta?.publishedAt ?? null
  const stamp = publishedAt ? new Date(publishedAt) : null
  const hour = stamp && Number.isFinite(stamp.getTime()) ? stamp.getUTCHours() : null

  return {
    package: packument.name,
    version,
    capturedAt,

    firstReleaseAt: first,
    releaseCount: releases.length,
    releaseSpanHours: spanHours,
    medianIntervalMinutes: median(intervals),
    fastestIntervalMinutes: intervals.length > 0 ? Math.min(...intervals) : null,
    releasesPerDay:
      spanHours !== null && spanHours > 0 ? releases.length / (spanHours / 24) : null,

    publisher,
    // Null, not false, when there is nothing to compare: an unreadable publisher
    // or an empty maintainer list is "we cannot say", and false would assert the
    // account is an outsider.
    publisherIsDeclaredMaintainer:
      publisher === null || maintainers.length === 0
        ? null
        : maintainers.some(m => m.name === publisher),
    maintainerCount: maintainers.length,

    dependencyChurn: churnAgainstPrevious(packument, version, releases),
    declaredMajor: majorOf(version),
    versionAheadOfReleases: aheadOfReleases(version, releases.length),
    publishedAtUTC: publishedAt,
    publishHourUTC: hour,

    nameAgeDays: ageDays,
    unpackedSize: meta?.unpackedSize ?? 0,
    hasRepository: Boolean(meta?.repository),
    hasProvenance: meta ? hasProvenance(meta) : false,
    provenanceLost: provenanceLostSignal(packument, version) !== null,
    createdAtAfterFirstRelease: createdAtIsAfterFirstRelease(packument),
  }
}

function intervalMinutes(releases: Release[]): number[] {
  const out: number[] = []
  for (let i = 1; i < releases.length; i += 1) {
    const gap =
      new Date(releases[i]!.at).getTime() - new Date(releases[i - 1]!.at).getTime()
    if (Number.isFinite(gap) && gap >= 0) out.push(gap / 60_000)
  }
  return out
}

function median(values: number[]): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  if (sorted.length % 2 === 1) return sorted[mid]!
  return (sorted[mid - 1]! + sorted[mid]!) / 2
}

// The dependency list of the captured version against the version published
// before it. Null when there is no predecessor with a readable list — a first
// publication has not changed anything, and recording that as "0 added, 0
// removed" would put it in the same bucket as a release that deliberately kept
// its dependencies identical.
function churnAgainstPrevious(
  p: Packument,
  version: string,
  releases: Release[]
): DependencyChurn | null {
  const index = releases.findIndex(r => r.version === version)
  if (index <= 0) return null

  const current = p.versions[version]
  // Walk back to the nearest predecessor npm still serves. For a removed package
  // most of them are gone, and stopping at the immediate one would report null
  // for a 149-release attack that has two surviving versions.
  let previous: VersionMeta | undefined
  let previousVersion = ''
  for (let i = index - 1; i >= 0; i -= 1) {
    const candidate = p.versions[releases[i]!.version]
    if (candidate) {
      previous = candidate
      previousVersion = releases[i]!.version
      break
    }
  }
  if (!current || !previous) return null

  const now = new Set(Object.keys(current.dependencies ?? {}))
  const before = new Set(Object.keys(previous.dependencies ?? {}))

  let added = 0
  let kept = 0
  for (const name of now) {
    if (before.has(name)) kept += 1
    else added += 1
  }
  let removed = 0
  for (const name of before) if (!now.has(name)) removed += 1

  return { added, removed, kept, previousVersion }
}

function majorOf(version: string): number | null {
  const major = Number.parseInt(version.split('.')[0] ?? '', 10)
  return Number.isFinite(major) ? major : null
}

// A package declaring 3.x with two releases behind it is claiming a history it
// does not have. Null below 1.0.0: pre-1.0 semver carries no such claim, and
// counting 0.9.4 as "ahead" would fire on every ordinary young package.
function aheadOfReleases(version: string, releaseCount: number): boolean | null {
  const major = majorOf(version)
  if (major === null || major < 1) return null
  return releaseCount < major
}

// ---------------------------------------------------------------------------
// Reading the conjuncts back
// ---------------------------------------------------------------------------

// Whether a profile satisfies the class the capture filter selects on, computed
// from the REPAIRED age. Reported beside the filter's own decision so the two can
// be compared: where they disagree, the capture entered on `time.created`.
export function inObservedClass(profile: MetadataProfile): boolean {
  const young = profile.nameAgeDays !== null && profile.nameAgeDays >= 0 &&
    profile.nameAgeDays < YOUNG_NAME_DAYS
  const tiny = profile.unpackedSize > 0 && profile.unpackedSize < TINY_PACKAGE_BYTES
  return young && tiny && !profile.hasRepository
}
