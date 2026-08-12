// A package cannot be compared against its own history when it has none. It can
// still be compared against the ecosystem it appeared in, and that is a
// different question with a different answer.
//
// This is a boolean conjunction, not a score. Scoring does not work here: the
// ceiling for this shape is around 26 points and raising the weights to reach 70
// would fire on every ordinary new package. Five conditions at once is what
// separates 0.75% of the publish stream from the 24.6% that are merely new.
//
//   no genome · name under 7 days · under 100KB · no repository · zero downloads
//
// Why this is defensible in a CI gate at all: this class does not arrive on its
// own. Somebody wrote the name into a package.json. Blocking it is not failing a
// build over a dependency the developer does not control — it is saying that the
// thing they asked for has the profile of a package fabricated today. And
// `norte-guard approve` is a one-line escape when they know better.
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

  const failed = Object.entries(conjuncts)
    .filter(([, held]) => !held)
    .map(([name]) => name)

  return {
    matches,
    conjuncts,
    downloadsChecked,
    nameAgeDays: age,
    reason: matches
      ? `Fabricated-package profile: no history, name ${age?.toFixed(1)} days old, ` +
        `${(currentMeta.unpackedSize / 1024).toFixed(1)}KB, no repository, zero downloads. ` +
        `All five at once describe 0.75% of the publish stream. ` +
        `If you asked for it deliberately: norte-guard approve`
      : !downloadsChecked
        ? 'downloads not verified: the rule does not apply without that fact'
        : `does not match: ${failed.join(', ')}`,
  }
}
