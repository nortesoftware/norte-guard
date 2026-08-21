// IDEA 4 — the family as the unit, because an isolated new package is
// indistinguishable and five of them in twenty minutes are not.
//
// Every unit A5 has used so far is a property of one package or one account.
// That is the wrong grain for what this collector keeps seeing: the locks, the
// `-vim` pair, @bikli, @noxzacode, the openrtc trio — attacks arrive in BATCHES,
// and the batch has properties no member has. A package published by a two-day-
// old account with no repository is a description that fits thousands of honest
// packages. Five packages published by that account inside twenty minutes,
// sharing a lexical stem, is a description that fits almost nothing else.
//
// This is also the unit that needs no bytes. A batch is defined by timestamps
// and names, both of which survive the takedown intact, so it is answerable over
// the 42 external removals that kept no tarball and over the 97 placeholder
// captures in this store.
//
// WHAT IT COSTS. Moving to the family shrinks n hard, and it shrinks it on the
// side that is already small: 8 case accounts cannot produce more than 8
// families and will produce fewer. Nothing here should be read as buying power.
// What it buys is a unit whose members are independent EVENTS — one operator
// deciding to publish a batch — where the capture unit counts one operator's
// release loop 36 times.

import { authoredReleases, type MetadataProfile } from './metadata-signals.js'
import type { Packument } from './packument.js'

// ---------------------------------------------------------------------------
// The definition, frozen
// ---------------------------------------------------------------------------

// Two publications by one account belong to the same burst when less than this
// separates them. 60 minutes, taken from `windowMinutes` in ecosystem.ts so the
// two halves of this codebase cut the data the same way — not chosen here after
// looking at a distribution.
export const BURST_GAP_MINUTES = 60

// A family needs at least this many DISTINCT package names. Two, and the
// distinctness is the whole condition.
//
// @siwatfa/yorn is 36 captures of one name and 149 releases of it, and a
// definition counting publications would call that the largest family in the
// corpus. It is one package on a release loop. The batch hypothesis is about an
// operator standing up several names at once, so several names is what the
// definition requires, and a single-name burst is reported as a CADENCE instead
// — a different fact, kept apart rather than dropped.
export const MIN_FAMILY_PACKAGES = 2

export interface Publication {
  package: string
  version: string
  publisher: string
  at: string
}

export interface Family {
  publisher: string
  packages: string[]
  publications: Publication[]
  firstAt: string
  lastAt: string
  spanMinutes: number
  // Distinct names, which is the size that matters. `publications.length` counts
  // versions and would let one name's release loop inflate a batch.
  distinctPackages: number
  packagesPerHour: number | null
  // The token every name in the batch shares, when there is one: `vim` for
  // kit-hydration-vim and svelte-goal-vim, `openrtc-trust` for the three
  // attestation shims. Null when the names have nothing in common, which is
  // itself informative — a batch of unrelated names is a different operator
  // habit from a batch of variations on one theme.
  sharedToken: string | null
  sharedScope: string | null
  // Every member is the first release of its own name.
  allFirstPublications: boolean
}

// A burst of one name. Not a family, and named so it cannot be quietly folded
// into one later.
export interface Cadence {
  publisher: string
  package: string
  publications: Publication[]
  spanMinutes: number
  releasesPerHour: number | null
}

export interface FamilyPartition {
  families: Family[]
  cadences: Cadence[]
  // Publications that belong to neither: a single release standing alone in its
  // window. Counted, because the share of an arm that produces NO batch is the
  // denominator every family rate is over.
  isolated: Publication[]
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

export function partitionIntoFamilies(
  publications: Publication[],
  options: { gapMinutes?: number; firstPublications?: Set<string> } = {}
): FamilyPartition {
  const gap = (options.gapMinutes ?? BURST_GAP_MINUTES) * 60_000
  const byPublisher = new Map<string, Publication[]>()
  for (const p of publications) {
    if (!p.publisher) continue
    const at = new Date(p.at).getTime()
    if (!Number.isFinite(at)) continue
    const list = byPublisher.get(p.publisher) ?? []
    list.push(p)
    byPublisher.set(p.publisher, list)
  }

  const families: Family[] = []
  const cadences: Cadence[] = []
  const isolated: Publication[] = []

  for (const [publisher, all] of byPublisher) {
    const sorted = [...all].sort((a, b) => a.at.localeCompare(b.at))

    let burst: Publication[] = []
    const flush = (): void => {
      if (burst.length === 0) return
      const names = [...new Set(burst.map(p => p.package))]
      if (names.length >= MIN_FAMILY_PACKAGES) {
        families.push(familyOf(publisher, burst, names, options.firstPublications))
      } else if (burst.length > 1) {
        cadences.push(cadenceOf(publisher, burst))
      } else {
        isolated.push(...burst)
      }
      burst = []
    }

    for (const p of sorted) {
      if (burst.length === 0) {
        burst.push(p)
        continue
      }
      const previous = new Date(burst[burst.length - 1]!.at).getTime()
      if (new Date(p.at).getTime() - previous < gap) burst.push(p)
      else {
        flush()
        burst.push(p)
      }
    }
    flush()
  }

  families.sort((a, b) => b.distinctPackages - a.distinctPackages || a.firstAt.localeCompare(b.firstAt))
  return { families, cadences, isolated }
}

function familyOf(
  publisher: string,
  burst: Publication[],
  names: string[],
  firstPublications: Set<string> | undefined
): Family {
  const firstAt = burst[0]!.at
  const lastAt = burst[burst.length - 1]!.at
  const spanMinutes = (new Date(lastAt).getTime() - new Date(firstAt).getTime()) / 60_000

  return {
    publisher,
    packages: names,
    publications: burst,
    firstAt,
    lastAt,
    spanMinutes,
    distinctPackages: names.length,
    // Null rather than a division by zero when a batch lands inside one second.
    // Several packages published simultaneously is the strongest form of the
    // observation, so it must not become a missing number.
    packagesPerHour: spanMinutes > 0 ? names.length / (spanMinutes / 60) : null,
    sharedToken: sharedTokenOf(names),
    sharedScope: sharedScopeOf(names),
    allFirstPublications:
      firstPublications === undefined
        ? false
        : names.every(n => firstPublications.has(n)),
  }
}

function cadenceOf(publisher: string, burst: Publication[]): Cadence {
  const spanMinutes =
    (new Date(burst[burst.length - 1]!.at).getTime() - new Date(burst[0]!.at).getTime()) / 60_000
  return {
    publisher,
    package: burst[0]!.package,
    publications: burst,
    spanMinutes,
    releasesPerHour: spanMinutes > 0 ? burst.length / (spanMinutes / 60) : null,
  }
}

// ---------------------------------------------------------------------------
// The lexical domain
// ---------------------------------------------------------------------------

// Tokens are what remains after the scope and the separators are removed:
// `@noxzacode/lock-file` gives noxzacode, lock, file. The scope is included
// deliberately — an operator who stands up five names under one new scope has
// shared exactly that, and dropping it would report those five as unrelated.
export function tokensOf(name: string): string[] {
  return name
    .toLowerCase()
    .split(/[@/\-_.]+/)
    .filter(t => t.length > 0)
}

// Tokens shared by EVERY name in the batch, longest first, or null. Single
// characters and pure digits are dropped: `v` and `2` are shared by half the
// registry and reporting them as a lexical domain would make the endpoint fire
// on any batch at all.
export function sharedTokenOf(names: string[]): string | null {
  if (names.length < 2) return null

  let common: Set<string> | null = null
  for (const name of names) {
    const tokens = new Set(tokensOf(name).filter(t => t.length > 1 && !/^\d+$/.test(t)))
    if (common === null) common = tokens
    else for (const t of [...common]) if (!tokens.has(t)) common.delete(t)
  }
  if (!common || common.size === 0) return null
  return [...common].sort((a, b) => b.length - a.length || a.localeCompare(b))[0]!
}

export function sharedScopeOf(names: string[]): string | null {
  const scopes = names.map(n => (n.startsWith('@') ? n.slice(0, n.indexOf('/')) : null))
  const first = scopes[0]
  if (first === null || first === undefined) return null
  return scopes.every(s => s === first) ? first : null
}

// ---------------------------------------------------------------------------
// Family-level endpoints
// ---------------------------------------------------------------------------

// The batch properties a family has and a package does not. Every one of them is
// a difference of timestamps or a comparison of names, so every one survives the
// takedown — which is what makes this the unit the external corpus can be read
// at.
export interface FamilyProfile {
  publisher: string
  distinctPackages: number
  spanMinutes: number
  packagesPerHour: number | null
  hasSharedToken: boolean
  sharedToken: string | null
  hasSharedScope: boolean
  allFirstPublications: boolean
  // Three or more names inside one hour. The binary form, for comparison with
  // the capability rates which are also binary.
  isTightBatch: boolean
}

// Three names, one hour. Declared here rather than derived from a distribution:
// two names an hour apart is a maintainer releasing a package and its types, and
// this endpoint is meant to describe the thing that is not that.
export const TIGHT_BATCH_PACKAGES = 3
export const TIGHT_BATCH_MINUTES = 60

export function familyProfileOf(family: Family): FamilyProfile {
  return {
    publisher: family.publisher,
    distinctPackages: family.distinctPackages,
    spanMinutes: family.spanMinutes,
    packagesPerHour: family.packagesPerHour,
    hasSharedToken: family.sharedToken !== null,
    sharedToken: family.sharedToken,
    hasSharedScope: family.sharedScope !== null,
    allFirstPublications: family.allFirstPublications,
    isTightBatch:
      family.distinctPackages >= TIGHT_BATCH_PACKAGES &&
      family.spanMinutes <= TIGHT_BATCH_MINUTES,
  }
}

// ---------------------------------------------------------------------------
// Above the family: the sequence that spans accounts
// ---------------------------------------------------------------------------

// A family is defined by its publisher, and that turned out to be a ceiling
// rather than a floor.
//
// Running the family pass over the store surfaced three accounts —
// node-mini-tools, pkg-utils-lab, tiny-js-helpers — each publishing a tight
// batch of tiny first-publication packages named `<stem>-<NNN>-th`. Read one
// account at a time they are three unremarkable batches. Read together the
// numbers ascend GLOBALLY while the account rotates: 37 node-mini-tools, 38
// pkg-utils-lab, 39 tiny-js-helpers, 41, 44, 45, 47, 48, 49, 51, 53, 54, 56,
// 57, 59, 61, 63 — 17 of 21 adjacent pairs land on a different account, spaced
// about 58 seconds apart. One counter, three accounts, a one-minute timer.
//
// No per-publisher unit can see that, because the coordination is exactly the
// thing the grouping key throws away. What makes it visible is a numeric token
// in the name that increments across the whole set, so that is what is detected:
// not "these accounts look similar" — a similarity judgement over a corpus this
// size will find pairs by chance — but "these names carry one counter", which is
// an ordering fact that a coincidence has to work much harder to produce.
export interface NumberedSequence {
  // The literal shape the names share, with the counter written as N:
  // `<stem>-N-th`. The stem varies inside the campaign, so it is not part of it.
  shape: string
  members: Array<{ package: string; number: number; publisher: string; at: string }>
  publishers: string[]
  // Adjacent-by-number pairs published by different accounts, over the pairs
  // there are. The rotation evidence: one account working alone scores 0.
  crossAccountAdjacency: number
  adjacentPairs: number
  spanMinutes: number
  medianGapSeconds: number | null
}

// Names of the form `word-123-suffix`, which is the shape the observed campaign
// used. Deliberately narrow: a general "find a number in the name" would match
// every platform binary (`cli-darwin-arm64`), every date-stamped nightly and
// every `-v2`, and the point of this detector is that it fires almost nowhere.
const NUMBERED = /^(.+?)-(\d{2,4})-([a-z]{2,4})$/

export function numberedSequences(
  publications: Publication[],
  options: { minMembers?: number; minPublishers?: number } = {}
): NumberedSequence[] {
  const minMembers = options.minMembers ?? 5
  const minPublishers = options.minPublishers ?? 2

  // Grouped by the invariant part of the shape — the suffix — because the stem
  // is what the campaign varies. `spingear-037-th` and `luckyhelper-039-th` are
  // one sequence; the stems have nothing in common and a stem-keyed grouping
  // would report seven sequences of one member each.
  const bySuffix = new Map<string, Array<{ package: string; number: number; publisher: string; at: string }>>()
  const seen = new Set<string>()

  for (const p of publications) {
    if (seen.has(p.package)) continue
    const m = NUMBERED.exec(p.package)
    if (!m) continue
    seen.add(p.package)
    const list = bySuffix.get(m[3]!) ?? []
    list.push({ package: p.package, number: Number.parseInt(m[2]!, 10), publisher: p.publisher, at: p.at })
    bySuffix.set(m[3]!, list)
  }

  const out: NumberedSequence[] = []
  for (const [suffix, members] of bySuffix) {
    if (members.length < minMembers) continue
    const publishers = [...new Set(members.map(m => m.publisher))]
    if (publishers.length < minPublishers) continue

    const byNumber = [...members].sort((a, b) => a.number - b.number)
    let cross = 0
    for (let i = 1; i < byNumber.length; i += 1) {
      if (byNumber[i]!.publisher !== byNumber[i - 1]!.publisher) cross += 1
    }

    const byTime = [...members].sort((a, b) => a.at.localeCompare(b.at))
    const gaps: number[] = []
    for (let i = 1; i < byTime.length; i += 1) {
      const gap = new Date(byTime[i]!.at).getTime() - new Date(byTime[i - 1]!.at).getTime()
      if (Number.isFinite(gap)) gaps.push(gap / 1000)
    }
    const sortedGaps = [...gaps].sort((a, b) => a - b)

    out.push({
      shape: `<stem>-N-${suffix}`,
      members: byNumber,
      publishers,
      crossAccountAdjacency: cross,
      adjacentPairs: byNumber.length - 1,
      spanMinutes:
        (new Date(byTime[byTime.length - 1]!.at).getTime() - new Date(byTime[0]!.at).getTime()) / 60_000,
      medianGapSeconds: sortedGaps.length > 0 ? sortedGaps[Math.floor(sortedGaps.length / 2)]! : null,
    })
  }

  return out.sort((a, b) => b.members.length - a.members.length)
}

// ---------------------------------------------------------------------------
// Publications from what is on disk
// ---------------------------------------------------------------------------

// Every authored release in a packument, attributed to the account that published
// the captured version.
//
// The attribution is the weak part and is stated rather than hidden: npm records
// `_npmUser` per version, but a removed package keeps only the placeholder, so
// for the 97 takedown captures the account has to come from the maintainer list
// or from another capture of the same name. Publications whose publisher cannot
// be established are dropped, not guessed, and the count of dropped ones is what
// a caller should report beside any family rate.
export function publicationsFrom(
  packument: Packument,
  publisher: string | null
): Publication[] {
  if (publisher === null) return []
  return authoredReleases(packument).map(r => ({
    package: packument.name,
    version: r.version,
    publisher,
    at: r.at,
  }))
}

// The subset of a profile list whose names are first publications, for
// `allFirstPublications`. A name is a first publication when the captured
// version is the earliest release the packument knows about.
export function firstPublicationNames(profiles: MetadataProfile[]): Set<string> {
  const out = new Set<string>()
  for (const p of profiles) {
    if (p.releaseCount === 1) out.add(p.package)
  }
  return out
}
