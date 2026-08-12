// The shape of the two packages npm removed after this collector had scored
// them: prezdentkxheiw@1.0.1 (25KB, name six days old, no repository) and
// internallib_v756@1.0.7 (1.4KB, name seventeen seconds old, no repository).
// Neither had an install script; both scored 20-26 and passed.
//
// One definition, three uses: it decides what quarantine keeps, it is recorded
// on every publication so its prevalence can be measured, and it is what the two
// candidate signals in absolute-risk.ts describe.
//
// n=2. This is a description of what was seen, not a detector — nothing here
// contributes a point to any score.

import type { Packument, VersionMeta } from './packument.js'

export const YOUNG_NAME_DAYS = 7
export const TINY_PACKAGE_BYTES = 100_000

export interface ClassMarkers {
  noGenome: boolean
  nameAgeDays: number | null
  unpackedSize: number
  hasRepository: boolean
  young: boolean
  tiny: boolean
  // All three markers plus the regime. Large new packages are not this class:
  // whatever they are, they are not what was observed.
  inClass: boolean
}

export function nameAgeDays(p: Packument, now = Date.now()): number | null {
  const created = p.createdAt ?? Object.entries(p.time ?? {})
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .map(([, ts]) => ts)
    .sort()[0]

  if (!created) return null
  const ms = now - new Date(created).getTime()
  return Number.isFinite(ms) ? ms / 86_400_000 : null
}

export function classifyPublication(
  packument: Packument,
  currentMeta: VersionMeta,
  regime: string,
  now = Date.now()
): ClassMarkers {
  const age = nameAgeDays(packument, now)
  const young = age !== null && age >= 0 && age < YOUNG_NAME_DAYS
  const tiny = currentMeta.unpackedSize > 0 && currentMeta.unpackedSize < TINY_PACKAGE_BYTES
  const hasRepository = Boolean(currentMeta.repository)
  const noGenome = regime === 'no-genome'

  return {
    noGenome,
    nameAgeDays: age,
    unpackedSize: currentMeta.unpackedSize,
    hasRepository,
    young,
    tiny,
    inClass: noGenome && young && tiny && !hasRepository,
  }
}

// Compact form for the change log, so months of it stay cheap to keep and the
// prevalence can be recomputed from disk at any cut-off.
export function compactMarkers(m: ClassMarkers): Record<string, unknown> {
  return {
    inClass: m.inClass,
    young: m.young,
    tiny: m.tiny,
    repo: m.hasRepository,
    ageDays: m.nameAgeDays === null ? null : Math.round(m.nameAgeDays * 100) / 100,
    bytes: m.unpackedSize,
  }
}
