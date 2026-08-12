// Scoring for packages with no genome: fewer than ten versions or less than
// ninety days old, so there is no baseline to diff against. That was 123 of 500
// packages in the run of 2026-08-12, which is why it needs more than the two
// signals it started with.
//
// Everything here comes from the packument the caller already fetched, so it
// stays affordable to run on the whole changes feed.
//
// Weights are provisional. fp-bench prints the prevalence of each signal across
// a clean sample, and a signal that fires on most new packages carries little
// information whatever its weight. Re-measure before defending any number here.

import type { Signal, Capability } from './types.js'
import { previousVersion, sortedVersions, type Packument, type VersionMeta } from './packument.js'
import { POPULAR_PACKAGE_NAMES } from './popular-names.js'
import { TINY_PACKAGE_BYTES } from './observed-class.js'

export interface AbsoluteRiskInput {
  packument: Packument
  currentMeta: VersionMeta
  now?: number
  // Absent by default: filling it costs one request per dependency, which on the
  // changes feed is tens of extra requests per publication.
  dependencyAgeDays?: Record<string, number>
  popularNames?: string[]
}

const NEW_PACKAGE_DAYS = 7
const YOUNG_PACKAGE_DAYS = 30
const NEW_DEPENDENCY_DAYS = 30

export function absoluteRiskSignals(input: AbsoluteRiskInput): Signal[] {
  const { packument, currentMeta } = input
  const now = input.now ?? Date.now()
  const signals: Signal[] = []

  if (currentMeta.hasInstallScript) {
    signals.push({
      type: 'absolute_install_script',
      surface: 'install_time',
      capability: 'install_script' as Capability,
      score: 20,
      description: 'Has an install script (new package, no history)',
      isHistorical: false,
    })
  }

  if (currentMeta.unpackedSize > 5_000_000) {
    signals.push({
      type: 'absolute_large_size',
      surface: 'install_time',
      score: 15,
      description: `Size ${(currentMeta.unpackedSize / 1e6).toFixed(1)}MB (new package)`,
      isHistorical: false,
    })
  }

  // "No genome" means no capability baseline, not necessarily no previous
  // version, so the provenance delta applies here too.
  const lost = provenanceLostSignal(packument, currentMeta.version)
  if (lost) signals.push(lost)

  if (!lost && !hasProvenance(currentMeta)) {
    signals.push({
      // Fires on 95.6% of packages with no genome, so it describes the registry
      // rather than this package. No weight makes a near-constant discriminate;
      // provenanceLostSignal is the form that does.
      type: 'absolute_no_provenance',
      surface: 'install_time',
      score: 0,
      description: 'No npm provenance (attestations/trustedPublisher): normal for 95.6% of new packages',
      isHistorical: false,
      informational: true,
    })
  }

  const maintainerCount = packument.maintainers?.length ?? 0
  if (maintainerCount <= 1) {
    signals.push({
      // 77.0% of packages with no genome: the default shape of a new package.
      type: 'absolute_single_maintainer',
      surface: 'install_time',
      score: 0,
      description: `${maintainerCount} maintainer${maintainerCount === 1 ? '' : 's'}: normal for 77% of new packages`,
      isHistorical: false,
      informational: true,
    })
  }

  // On a package with history this would be the takeover signal. Without
  // history it is still an inconsistency worth pricing.
  const publisher = currentMeta._npmUser?.name
  if (publisher && maintainerCount > 0) {
    const isMaintainer = packument.maintainers.some(m => m.name === publisher)
    if (!isMaintainer) {
      signals.push({
        type: 'absolute_publisher_not_maintainer',
        surface: 'install_time',
        score: 18,
        description: `Published by "${publisher}", who is not listed in maintainers`,
        isHistorical: false,
      })
    }
  }

  // /-/user/org.couchdb.user:<name> returns 401 without credentials, so account
  // age is recorded as a hole rather than approximated. Package age below is not
  // a substitute: an old account can publish a new name and vice versa.
  signals.push({
    type: 'absolute_account_age_unknown',
    surface: 'install_time',
    score: 0,
    description:
      'Maintainer account age: not verifiable, npm\'s user endpoint requires authentication (401)',
    isHistorical: false,
    informational: true,
  })

  const createdAt = packument.createdAt ?? oldestVersionTime(packument)
  if (createdAt) {
    const ageDays = (now - new Date(createdAt).getTime()) / 86_400_000
    if (ageDays >= 0 && ageDays < NEW_PACKAGE_DAYS) {
      signals.push({
        type: 'absolute_package_days_old',
        surface: 'install_time',
        score: 10,
        description: `The name has existed for ${ageDays.toFixed(1)} days`,
        isHistorical: false,
      })
    } else if (ageDays >= 0 && ageDays < YOUNG_PACKAGE_DAYS) {
      signals.push({
        type: 'absolute_package_weeks_old',
        surface: 'install_time',
        score: 5,
        description: `The name has existed for ${ageDays.toFixed(0)} days`,
        isHistorical: false,
      })
    }
  }

  // Individually trivial and trivially faked. Together they say whether the
  // package was published to be read by people or resolved by a machine.
  if (!currentMeta.repository) {
    signals.push({
      type: 'absolute_no_repository',
      surface: 'install_time',
      score: 7,
      description: 'No repository field: no source to compare the tarball against',
      isHistorical: false,
    })
  }

  if (packument.hasReadme === false) {
    signals.push({
      type: 'absolute_no_readme',
      surface: 'install_time',
      score: 6,
      description: 'No README',
      isHistorical: false,
    })
  }

  if (!currentMeta.description) {
    signals.push({
      type: 'absolute_no_description',
      surface: 'install_time',
      score: 3,
      description: 'No description',
      isHistorical: false,
    })
  }

  const squat = nearestPopularName(packument.name, input.popularNames ?? POPULAR_PACKAGE_NAMES)
  if (squat && squat.distance === 1) {
    signals.push({
      type: 'absolute_typosquat_distance_1',
      surface: 'install_time',
      score: 30,
      description: `One edit away from "${squat.name}", which is among the most downloaded`,
      isHistorical: false,
    })
  } else if (squat && squat.distance === 2) {
    signals.push({
      type: 'absolute_typosquat_distance_2',
      surface: 'install_time',
      score: 12,
      description: `Two edits away from "${squat.name}", which is among the most downloaded`,
      isHistorical: false,
    })
  }

  // Two candidate signals, recorded and deliberately not scored.
  //
  // They describe the only two packages this collector saw npm remove after
  // scoring them, which is a sample of two. Weighting them on that would be
  // fitting the detector to the two cases that happen to exist. Recorded at 0
  // they cost nothing, appear on every publication, and in a few months there
  // will be a prevalence to weigh them against. Measuring is not overfitting;
  // scoring is.
  if (currentMeta.unpackedSize > 0 && currentMeta.unpackedSize < TINY_PACKAGE_BYTES) {
    signals.push({
      type: 'absolute_tiny_size',
      surface: 'install_time',
      score: 0,
      description:
        `Size ${(currentMeta.unpackedSize / 1024).toFixed(1)}KB, below ` +
        `${TINY_PACKAGE_BYTES / 1000}KB. absolute_large_size watches the other end; ` +
        `the two npm removed weighed 25KB and 1.4KB`,
      isHistorical: false,
      informational: true,
    })
  }

  const implied = impliedHistory(packument, currentMeta.version)
  if (implied !== null) {
    signals.push({
      type: 'version_implies_history',
      surface: 'install_time',
      score: 0,
      description:
        `First published version is ${currentMeta.version}: the number implies ` +
        `${implied} earlier releases that time{} does not record`,
      isHistorical: false,
      informational: true,
    })
  }

  const deps = Object.keys(currentMeta.dependencies ?? {})
  if (input.dependencyAgeDays) {
    const known = deps.filter(d => input.dependencyAgeDays![d] !== undefined)
    const fresh = known.filter(d => input.dependencyAgeDays![d]! < NEW_DEPENDENCY_DAYS)

    if (known.length > 0 && fresh.length / known.length > 0.5) {
      signals.push({
        type: 'absolute_deps_mostly_new',
        surface: 'install_time',
        score: 14,
        description:
          `${fresh.length}/${known.length} direct dependencies are under ` +
          `${NEW_DEPENDENCY_DAYS} days old: the whole tree was built recently`,
        isHistorical: false,
      })
    }
  } else if (deps.length > 0) {
    // Declared rather than skipped silently, so a reader of the signal list can
    // see the check did not run.
    signals.push({
      type: 'absolute_dep_ages_unchecked',
      surface: 'install_time',
      score: 0,
      description: `Age of the ${deps.length} direct dependencies: not checked (one request per dependency)`,
      isHistorical: false,
      informational: true,
    })
  }

  return signals
}

export function hasProvenance(meta: VersionMeta): boolean {
  return Boolean(meta.dist?.attestations) || Boolean(meta.trustedPublisher)
}

// Absent provenance describes 95.6% of new packages. Losing it describes one
// whose previous release went through a signing CI and whose current one did
// not, which is what a publish with a stolen token looks like from outside: the
// attacker holds the npm credential, not the pipeline that mints the
// attestation. Both versions are already in the packument.
export function provenanceLostSignal(
  packument: Packument,
  version: string
): Signal | null {
  const current = packument.versions[version]
  if (!current || hasProvenance(current)) return null

  const previous = previousVersion(packument, version)
  if (!previous || !hasProvenance(previous)) return null

  // Lets the description say whether this is a one-off gap or the end of a run.
  const history = sortedVersions(packument)
    .filter(v => new Date(v.publishedAt).getTime() < new Date(current.publishedAt).getTime())
    .slice(-10)
  const signedBefore = history.filter(hasProvenance).length

  return {
    type: 'provenance_lost',
    surface: 'install_time',
    score: 35,
    description:
      `Lost provenance: ${previous.version} was signed and ${version} is not ` +
      `(${signedBefore}/${history.length} recent versions carried it). ` +
      `The npm credential is enough to publish; the pipeline that signs is not.`,
    isHistorical: false,
  }
}

// A package whose only published version is 1.0.7 claims seven patch releases
// that its own time{} says never happened. internallib_v756 did exactly that,
// seventeen seconds after the name was created.
//
// Conservative on purpose: 1.0.0, 0.1.0 and 2.0.0 are ordinary first versions
// and do not fire. Only a non-zero patch on a sole version does.
export function impliedHistory(p: Packument, version: string): number | null {
  const published = Object.keys(p.time ?? {}).filter(v => v !== 'created' && v !== 'modified')
  if (published.length !== 1) return null

  const core = version.replace(/[+-].*$/, '').split('.')
  if (core.length < 3 || core.some(part => !/^\d+$/.test(part))) return null

  const patch = Number(core[2])
  return patch > 0 ? patch : null
}

function oldestVersionTime(p: Packument): string | undefined {
  let oldest: string | undefined
  for (const [version, ts] of Object.entries(p.time ?? {})) {
    if (version === 'created' || version === 'modified') continue
    if (!oldest || ts < oldest) oldest = ts
  }
  return oldest
}

export interface NameProximity {
  name: string
  distance: number
}

// Compared on the unscoped basename: "@evil/react" is not a typo of "react",
// but "@evil/raect" is the same trick applied inside a scope.
export function nearestPopularName(
  name: string,
  popular: string[] = POPULAR_PACKAGE_NAMES
): NameProximity | null {
  const candidate = name.startsWith('@') ? (name.split('/')[1] ?? name) : name
  if (candidate.length < 5) return null

  let best: NameProximity | null = null

  for (const target of popular) {
    // Distance 0 means this IS the popular package, not an imitation of it.
    if (target === candidate) return null

    // Free lower bound on edit distance, and it keeps this cheap enough to run
    // on every change in the feed.
    if (Math.abs(target.length - candidate.length) > 2) continue

    const distance = osaDistance(candidate, target, 2)
    if (distance > 0 && distance <= 2 && (!best || distance < best.distance)) {
      best = { name: target, distance }
    }
  }

  return best
}

// Optimal string alignment: Levenshtein plus adjacent transposition, the
// mistake a typosquat is built on ("axios" → "axois"). Anything above `max` is
// reported as max + 1 rather than refined.
export function osaDistance(a: string, b: string, max = Infinity): number {
  if (a === b) return 0

  const rows = a.length + 1
  const cols = b.length + 1

  let prev2: number[] = []
  let prev: number[] = new Array(cols)
  let curr: number[] = new Array(cols)

  for (let j = 0; j < cols; j++) prev[j] = j

  for (let i = 1; i < rows; i++) {
    curr[0] = i
    let rowMin = curr[0]!

    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1

      let value = Math.min(
        curr[j - 1]! + 1,     // insertion
        prev[j]! + 1,         // deletion
        prev[j - 1]! + cost,  // substitution
      )

      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, prev2[j - 2]! + 1)   // transposition
      }

      curr[j] = value
      if (value < rowMin) rowMin = value
    }

    // Remaining rows can only grow, so once the best cell passes the bound the
    // answer has too.
    if (rowMin > max) return max + 1

    prev2 = prev
    prev = curr
    curr = new Array(cols)
  }

  return prev[cols - 1]!
}
