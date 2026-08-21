// The quarantine conjunction is calibrated for the decoy and lets the carrier
// through.
//
// On 2026-08-13 `javonayers999` published five packages in four minutes:
// async-critical-section, keyed-mutex-map, resource-lease-pool,
// single-flight-lock, try-lock-runner. Every one is 3-4KB, has no repository, is
// hours old — the observed class exactly — and every one was captured.
//
// All five declare a single dependency, and it is the same dependency:
// `mutex-forge`. That one was analysed twice while it was still live, scored 10,
// and was rejected, because it is 664KB with a repository field. It fails `tiny`
// and it fails `!hasRepository`, so it is not in the class, and it would not
// have been caught by widening the class to two conjuncts of three either.
//
// The five in the corpus are the decoys. The one thing all five point at is the
// one thing the filter was built to ignore, and it is not a coincidence: the
// class describes what a throwaway package looks like, so a package designed to
// be depended upon has to look like a library instead.
//
// The rule that follows is small. Whatever else is true of a package, if
// something this collector just decided to capture DECLARES it, and it is itself
// new, then it is part of the same event and its own profile does not get a
// vote.

import { nameAgeDays, YOUNG_NAME_DAYS } from './observed-class.js'
import {
  capturableByName, nonRegistryDependencies, type NonRegistryDependency,
} from './destinations.js'
import type { Packument, VersionMeta } from './packument.js'

// The dependency must itself be young. Not a new constant: `YOUNG_NAME_DAYS` is
// the conjunct already frozen in observed-class.ts, and `mutex-forge` satisfied
// it — the feed row records `young=true, tiny=false, repo=true`. Reusing it
// keeps one definition of "new" in the codebase, and means this rule relaxes
// exactly two of the three conjuncts rather than inventing a fourth threshold.
//
// It is also what makes the rule affordable. Sampled over the dependency names
// this corpus declares and has not captured, the median name age is 1,455 days
// and 1.8% are under seven: the rule reaches for about 163 packages across the
// whole corpus rather than the 9,330 distinct names that are declared.
export const DEPENDENCY_MUST_BE_YOUNGER_THAN_DAYS = YOUNG_NAME_DAYS

// Per capture, at most this many dependencies are followed. The median capture
// declares one and the mean is 3.7, but the maximum in the corpus is 519, and a
// package that declares 519 dependencies would otherwise turn one capture into
// 519 registry requests. The cap is a bound on the worst case, not a sampling
// decision — it is logged when it binds so a truncated follow is never mistaken
// for a package with few dependencies.
export const MAX_FOLLOWED_PER_CAPTURE = 12

export interface DependencyCandidate {
  // The dependency's own name.
  package: string
  // The capture that pointed at it. Recorded on the capture metadata so the
  // corpus can say WHY a package with an ordinary profile is in it.
  declaredBy: string
  declaredByVersion: string
}

// The names a capture points at, before any of them is fetched.
//
// devDependencies are deliberately excluded. They are not installed by a
// consumer, so a payload there does not reach anyone through this package, and
// including them roughly triples the fan-out for a path that does not execute.
export function declaredDependencies(
  packageName: string,
  version: string,
  meta: VersionMeta
): DependencyCandidate[] {
  // Only the names npm can be asked about. C1 found eight packages declaring
  // `{"ltidisafe": "https://ltidi.storage.googleapis.com/…/ltidisafe-3.7.4.tgz"}`
  // — the KEY is a name npm has never heard of, and the specifier is the thing
  // that actually gets fetched and run. Reading the keys blindly would have sent
  // this rule to look up a package that does not exist, 404, and then spend the
  // whole retry schedule on it.
  //
  // The off-registry ones are not dropped; they come back from
  // `offRegistryDependencies` so the caller can record them. They are the more
  // interesting half — a carrier npm never hosted cannot be captured from npm at
  // all.
  const names = capturableByName(meta.dependencies as Record<string, string> | undefined)
  return names.slice(0, MAX_FOLLOWED_PER_CAPTURE).map(name => ({
    package: name,
    declaredBy: packageName,
    declaredByVersion: version,
  }))
}

// The dependencies this collector cannot follow because they are not on the
// registry. Surfaced rather than silently skipped: `npm install` fetches and
// runs them, npm never scanned them, and nothing downstream would otherwise
// record that the package had one.
export function offRegistryDependencies(meta: VersionMeta): NonRegistryDependency[] {
  return nonRegistryDependencies(meta.dependencies as Record<string, string> | undefined)
}

export function truncatedFollow(meta: VersionMeta): number {
  const n = Object.keys(meta.dependencies ?? {}).length
  return n > MAX_FOLLOWED_PER_CAPTURE ? n - MAX_FOLLOWED_PER_CAPTURE : 0
}

export interface DependencyDecision {
  capture: boolean
  ageDays: number | null
  reason: string
}

// Whether a fetched dependency should be captured on the strength of who
// declared it.
//
// Note what is NOT consulted: size, repository, install script, score. That is
// the point — every one of those is a property `mutex-forge` used to stay out.
// The only question is whether the dependency is new enough to have been created
// for this, and being depended upon by something already captured is the rest of
// the argument.
export function shouldCaptureDependency(
  packument: Packument,
  now = Date.now()
): DependencyDecision {
  const age = nameAgeDaysOf(packument, now)

  if (age === null) {
    // No timestamp to read. Not captured, and said so explicitly: a dependency
    // whose age cannot be established is not a dependency known to be old, and
    // the two would otherwise be one silent `false`.
    return { capture: false, ageDays: null, reason: 'no publication timestamp to age it by' }
  }
  if (age < 0) {
    return { capture: false, ageDays: age, reason: 'timestamp in the future' }
  }
  if (age >= DEPENDENCY_MUST_BE_YOUNGER_THAN_DAYS) {
    return {
      capture: false,
      ageDays: age,
      reason: `${age.toFixed(1)} days old, past the ${DEPENDENCY_MUST_BE_YOUNGER_THAN_DAYS}-day bound`,
    }
  }
  return {
    capture: true,
    ageDays: age,
    reason:
      `declared by a captured package and ${age.toFixed(2)} days old: captured on the ` +
      `declaration, not on its own profile`,
  }
}

// The repaired age, for the same reason metadata-signals.ts uses it: npm resets
// `time.created` when it republishes a removed name, so a package that lived a
// week can report as newborn. Here the error runs toward capturing more, which
// is the safe direction for this rule, and it is corrected anyway so that the
// age written into the capture metadata is the true one.
function nameAgeDaysOf(p: Packument, now: number): number | null {
  const stamps = Object.entries(p.time ?? {})
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .map(([, at]) => at)
    .filter((at): at is string => typeof at === 'string' && at !== '')
    .sort()

  if (stamps.length === 0) return nameAgeDays(p, now)
  const ms = now - new Date(stamps[0]!).getTime()
  return Number.isFinite(ms) ? ms / 86_400_000 : null
}

// Whether a dependency sits under the same npm scope as the package that
// declared it.
//
// This is what a monorepo release looks like from inside the dependency rule:
// `@latticeag/adapter-stub` declaring `@latticeag/bus`, `@composy/layout-elements`
// declaring `@composy/layout-runtime`. Of the first 219 captures this path made,
// 203 — 92.7% — were that shape.
//
// It does NOT decide whether to capture. It decides whether to keep the bytes.
// Every carrier this rule was written for is cross-scope — async-critical-section
// -> mutex-forge, sui-gql-core -> bcs-core, sui-move-rpc -> leb128x,
// sui-move-graphql -> ulebkit — so a same-scope sibling is unlikely to be one,
// but "unlikely" is not "cannot", and an operator using one scope for both the
// decoy and the carrier is exactly the case that would be invisible if these
// were dropped. The packument is kept so that question stays answerable, at
// about 8% of the disk.
//
// Unscoped names never match: two unscoped packages share no scope, they share
// nothing, and treating them as siblings would degrade the mutex-forge case
// itself.
export function sameScope(declaredBy: string, dependency: string): boolean {
  const scopeOf = (name: string): string | null =>
    name.startsWith('@') && name.includes('/') ? name.slice(0, name.indexOf('/')) : null

  const a = scopeOf(declaredBy)
  const b = scopeOf(dependency)
  return a !== null && a === b
}

// A dependency this collector already holds does not need fetching again, and
// the check belongs here rather than at the call site so that "already captured"
// and "too old" cannot drift into being counted the same way.
export function alreadyHeld(candidate: DependencyCandidate, held: Set<string>): boolean {
  return held.has(candidate.package)
}
