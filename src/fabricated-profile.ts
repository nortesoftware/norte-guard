// A package cannot be compared against its own history when it has none. It can
// still be compared against the ecosystem it appeared in, and that is a
// different question with a different answer.
//
// This is a boolean conjunction, not a score. Scoring does not work here: the
// ceiling for this shape is around 26 points and raising the weights to reach 70
// would fire on every ordinary new package. The conditions at once are what
// separate 2.65% of the publish stream from the 50.7% that are merely new.
//
//   no genome · name under 7 days · under 100KB · no repository · zero downloads
//
// Four of those are free and are what the prevalence is measured on: 1,116 of
// 42,164 scored publications, re-measured 2026-08-14. The figure this file used
// to carry, 0.75%, was taken on a much shorter run and is no longer what the
// stream does.
//
// The fifth is weaker than it looks and is documented rather than dropped. npm
// reports the last COMPLETE week, which ends about five days back, so for a name
// created yesterday "zero downloads" is a statement about a week in which the
// package did not exist. It does real work at the older end of the seven-day
// range and none at all at the fresh end, and `downloadWindowCovers` below says
// which case a given verdict is.
//
// Why this is defensible in a CI gate at all: this class does not arrive on its
// own. Somebody wrote the name into a package.json. Blocking it is not failing a
// build over a dependency the developer does not control — it is saying that the
// thing they asked for has the profile of a package fabricated today. And
// `norte-guard approve` is a one-line escape when they know better.
//
// It stopped being opt-in on 2026-08-14, on the four free conditions and npm's
// own removals rather than on a reconstructed five-condition match: the packages
// behind the decision were quarantined at publication with those four holding,
// and npm removed every one of them hours later. The fifth cannot be checked
// backwards at all — npm reports one week at a time — so nothing here claims it
// was. The criterion that decided it is in watchlist.ts; the evidence is written
// out in types.ts.
//
// Unknown download counts never match. A gate must not block because it failed
// to check something.

import type { Packument, VersionMeta } from './packument.js'
import { nameAgeDays, YOUNG_NAME_DAYS, TINY_PACKAGE_BYTES } from './observed-class.js'

export interface FabricatedProfileInput {
  packument: Packument
  currentMeta: VersionMeta
  regime: string
  // Weekly downloads. `null` means the count could not be established, which is
  // treated as "not matching" rather than as zero.
  weeklyDownloads?: number | null
  // End of the week npm's count covers, when the caller kept it. Without it the
  // fifth conjunct cannot say whether it measured anything.
  downloadWindowEnd?: string | null
  now?: number
}

export interface FabricatedProfile {
  matches: boolean
  conjuncts: {
    noGenome: boolean
    youngName: boolean
    tiny: boolean
    noRepository: boolean
    zeroDownloads: boolean
  }
  downloadsChecked: boolean
  // The download window overlaps the package's life. False means zeroDownloads
  // held vacuously — the week npm reported on had closed before the name
  // existed — so the verdict rests on four conditions, not five. Null when the
  // window was not recorded.
  downloadWindowCovers: boolean | null
  nameAgeDays: number | null
  reason: string
}

// The four conditions that cost nothing. Callers use this to decide whether the
// download lookup is worth a request: on the measured stream it is true for
// 0.75% of publications, so the fifth condition is only ever paid for on those.
export function matchesLocalConjuncts(input: FabricatedProfileInput): boolean {
  const p = evaluate(input)
  return p.conjuncts.noGenome && p.conjuncts.youngName && p.conjuncts.tiny && p.conjuncts.noRepository
}

export function fabricatedProfile(input: FabricatedProfileInput): FabricatedProfile {
  return evaluate(input)
}

function evaluate(input: FabricatedProfileInput): FabricatedProfile {
  const { packument, currentMeta, regime } = input
  const age = nameAgeDays(packument, input.now ?? Date.now())

  const conjuncts = {
    noGenome: regime === 'no-genome',
    youngName: age !== null && age >= 0 && age < YOUNG_NAME_DAYS,
    tiny: currentMeta.unpackedSize > 0 && currentMeta.unpackedSize < TINY_PACKAGE_BYTES,
    noRepository: !currentMeta.repository,
    zeroDownloads: input.weeklyDownloads === 0,
  }

  const downloadsChecked = input.weeklyDownloads !== undefined && input.weeklyDownloads !== null
  const matches = downloadsChecked && Object.values(conjuncts).every(Boolean)

  const downloadWindowCovers = windowCovers(packument, input.downloadWindowEnd, input.now ?? Date.now())

  const failed = Object.entries(conjuncts)
    .filter(([, held]) => !held)
    .map(([name]) => name)

  return {
    matches,
    conjuncts,
    downloadsChecked,
    downloadWindowCovers,
    nameAgeDays: age,
    reason: matches
      ? `Fabricated-package profile: no history, name ${age?.toFixed(1)} days old, ` +
        `${(currentMeta.unpackedSize / 1024).toFixed(1)}KB, no repository, zero downloads` +
        (downloadWindowCovers === false
          ? ` (over a week that closed ${input.downloadWindowEnd}, before the name existed: ` +
            `that condition carries no information here)`
          : '') +
        `. The four free conditions together describe 2.65% of the publish stream. ` +
        `If you asked for it deliberately: norte-guard approve`
      : !downloadsChecked
        ? 'downloads not verified: the rule does not apply without that fact'
        : `does not match: ${failed.join(', ')}`,
  }
}

// npm's last-week window is the last COMPLETE week, so it lags. A name created
// after the window closed cannot have been downloaded inside it, and its zero is
// arithmetic rather than evidence.
function windowCovers(
  packument: Packument,
  windowEnd: string | null | undefined,
  now: number
): boolean | null {
  if (!windowEnd) return null

  const created = packument.createdAt ?? Object.entries(packument.time ?? {})
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .map(([, ts]) => ts)
    .sort()[0]
  if (!created) return null

  const createdMs = new Date(created).getTime()
  // The window's own end is a date, so it is read as the end of that day.
  const endMs = new Date(`${windowEnd}T23:59:59Z`).getTime()
  if (!Number.isFinite(createdMs) || !Number.isFinite(endMs)) return null

  return createdMs <= endMs && createdMs <= now
}
