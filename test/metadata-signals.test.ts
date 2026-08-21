/**
 * IDEA 3 — the endpoints that survive the takedown.
 *
 * Hand-built packuments, one per mechanic, NOT the corpus. Two of these encode
 * defects the corpus is what revealed — `time.created` reset by the takedown, and
 * the registry publishing as itself — and a test written against the samples that
 * revealed them would pass on those samples and nothing else.
 *
 * The invariant is that a fact the record does not support comes back null rather
 * than as a number. Every rate in A5 that had to be withdrawn was a zero standing
 * in for "we could not tell".
 */

import { describe, it, expect } from 'vitest'
import {
  metadataProfileOf, releaseTimestamps, authoredReleases, firstReleaseAt,
  createdAtIsAfterFirstRelease, isRegistryIdentity, publisherFor, inObservedClass,
  ENDPOINTS, declarationOf, TAKEDOWN_PLACEHOLDER,
} from '../src/metadata-signals.js'
import { normalizePackument } from '../src/packument.js'
import type { Packument } from '../src/packument.js'

interface VersionSpec {
  at: string
  size?: number
  deps?: Record<string, string>
  repository?: unknown
  user?: { name?: string; email?: string }
  gone?: boolean
}

// A packument shaped the way npm serves one: `time` carries every version ever
// published, `versions` only the ones that still resolve.
function packument(input: {
  name: string
  versions: Record<string, VersionSpec>
  maintainers?: Array<{ name: string; email: string }>
  created?: string
}): Packument {
  const time: Record<string, string> = {}
  const versions: Record<string, unknown> = {}

  for (const [version, spec] of Object.entries(input.versions)) {
    time[version] = spec.at
    if (spec.gone) continue
    versions[version] = {
      dist: { unpackedSize: spec.size ?? 1000, tarball: '', integrity: '', shasum: '' },
      dependencies: spec.deps ?? {},
      repository: spec.repository,
      _npmUser: spec.user ?? { name: 'someone', email: 'a@b.c' },
    }
  }

  const stamps = Object.values(input.versions).map(v => v.at).sort()
  time['created'] = input.created ?? stamps[0]!
  time['modified'] = stamps[stamps.length - 1]!

  return normalizePackument({
    name: input.name,
    time,
    versions,
    maintainers: input.maintainers ?? [{ name: 'someone', email: 'a@b.c' }],
  })
}

const profile = (p: Packument, version: string, capturedAt: string) =>
  metadataProfileOf({ packument: p, version, capturedAt })!

describe('the publication record survives the versions', () => {
  it('reads timestamps for versions npm no longer serves', () => {
    const p = packument({
      name: 'gone',
      versions: {
        '1.0.0': { at: '2026-08-01T00:00:00.000Z', gone: true },
        '1.0.1': { at: '2026-08-01T01:00:00.000Z', gone: true },
        [TAKEDOWN_PLACEHOLDER]: { at: '2026-08-05T00:00:00.000Z' },
      },
    })

    // The whole point: one version resolves, three were published.
    expect(Object.keys(p.versions)).toEqual([TAKEDOWN_PLACEHOLDER])
    expect(releaseTimestamps(p)).toHaveLength(3)
    // npm's own write is not one of the publisher's releases.
    expect(authoredReleases(p).map(r => r.version)).toEqual(['1.0.0', '1.0.1'])
  })

  it('measures the cadence of a removed package', () => {
    const versions: Record<string, VersionSpec> = {}
    for (let i = 0; i < 10; i += 1) {
      versions[`1.0.${i}`] = { at: new Date(Date.UTC(2026, 7, 12, 10, i * 30)).toISOString(), gone: true }
    }
    versions[TAKEDOWN_PLACEHOLDER] = { at: '2026-08-17T00:00:00.000Z' }

    const m = profile(packument({ name: 'yorn-like', versions }), TAKEDOWN_PLACEHOLDER, '2026-08-17T01:00:00.000Z')
    expect(m.releaseCount).toBe(10)
    expect(m.medianIntervalMinutes).toBe(30)
    expect(m.fastestIntervalMinutes).toBe(30)
  })
})

describe('time.created is not the birth', () => {
  it('detects a created stamp later than the first release', () => {
    const p = packument({
      name: 'taken-down',
      versions: {
        '1.0.0': { at: '2026-08-12T10:55:00.000Z', gone: true },
        [TAKEDOWN_PLACEHOLDER]: { at: '2026-08-17T10:09:45.000Z' },
      },
      created: '2026-08-17T10:09:45.000Z',
    })

    expect(createdAtIsAfterFirstRelease(p)).toBe(true)
    // The repaired answer, which is the one every age here is taken from.
    expect(firstReleaseAt(p)).toBe('2026-08-12T10:55:00.000Z')
  })

  it('ages from the first release, so a removed package is not newborn', () => {
    const p = packument({
      name: 'taken-down',
      versions: {
        '1.0.0': { at: '2026-08-12T00:00:00.000Z', gone: true },
        [TAKEDOWN_PLACEHOLDER]: { at: '2026-08-17T00:00:00.000Z' },
      },
      created: '2026-08-17T00:00:00.000Z',
    })

    const m = profile(p, TAKEDOWN_PLACEHOLDER, '2026-08-17T00:00:00.000Z')
    // Five days, not zero. Reading `created` would have said zero and put the
    // package in the young conjunct it does not belong to.
    expect(m.nameAgeDays).toBeCloseTo(5, 3)
    expect(m.createdAtAfterFirstRelease).toBe(true)
  })

  it('leaves an ordinary packument alone', () => {
    const p = packument({
      name: 'ordinary',
      versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z' } },
    })
    expect(createdAtIsAfterFirstRelease(p)).toBe(false)
    expect(profile(p, '1.0.0', '2026-08-13T00:00:00.000Z').nameAgeDays).toBeCloseTo(3, 3)
  })
})

describe('the registry is not a publisher', () => {
  it('recognises npm publishing the takedown placeholder', () => {
    expect(isRegistryIdentity({ name: 'npm', email: 'npm@npmjs.com' })).toBe(true)
    expect(isRegistryIdentity({ name: 'npm-support', email: 'support@npmjs.com' })).toBe(true)
    expect(isRegistryIdentity({ name: 'someone', email: 'a@b.c' })).toBe(false)
    expect(isRegistryIdentity(undefined)).toBe(false)
  })

  it('refuses to attribute a removed package to npm', () => {
    // Both halves of the fallback are the registry after a takedown, which is why
    // the guard cannot live inside publisherOf's `??` chain.
    const p = packument({
      name: 'removed',
      versions: {
        '1.0.0': { at: '2026-08-12T00:00:00.000Z', gone: true },
        [TAKEDOWN_PLACEHOLDER]: { at: '2026-08-17T00:00:00.000Z', user: { name: 'npm', email: 'npm@npmjs.com' } },
      },
      maintainers: [{ name: 'npm-support', email: 'support@npmjs.com' }],
    })

    expect(publisherFor(p, TAKEDOWN_PLACEHOLDER)).toBeNull()
    expect(profile(p, TAKEDOWN_PLACEHOLDER, '2026-08-17T01:00:00.000Z').publisher).toBeNull()
  })

  it('still attributes an ordinary publication', () => {
    const p = packument({
      name: 'ordinary',
      versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z', user: { name: 'chris', email: 'c@d.e' } } },
      maintainers: [{ name: 'chris', email: 'c@d.e' }],
    })
    expect(publisherFor(p, '1.0.0')).toBe('chris')
    expect(profile(p, '1.0.0', '2026-08-11T00:00:00.000Z').publisherIsDeclaredMaintainer).toBe(true)
  })

  it('reports an outside publisher as false and an unreadable one as null', () => {
    const outsider = packument({
      name: 'outsider',
      versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z', user: { name: 'stranger', email: 'x@y.z' } } },
      maintainers: [{ name: 'chris', email: 'c@d.e' }],
    })
    expect(profile(outsider, '1.0.0', '2026-08-11T00:00:00.000Z').publisherIsDeclaredMaintainer).toBe(false)

    const unreadable = packument({
      name: 'unreadable',
      versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z' } },
      maintainers: [],
    })
    // No maintainer list is "we cannot say", and false would assert the account
    // is an outsider.
    expect(profile(unreadable, '1.0.0', '2026-08-11T00:00:00.000Z').publisherIsDeclaredMaintainer).toBeNull()
  })
})

describe('an absent fact is null, not zero', () => {
  it('gives a single release no interval', () => {
    const m = profile(
      packument({ name: 'one', versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z' } } }),
      '1.0.0', '2026-08-11T00:00:00.000Z'
    )
    expect(m.releaseCount).toBe(1)
    expect(m.medianIntervalMinutes).toBeNull()
    expect(m.fastestIntervalMinutes).toBeNull()
    expect(m.releasesPerDay).toBeNull()
  })

  it('gives a first publication no dependency churn', () => {
    const m = profile(
      packument({ name: 'one', versions: { '1.0.0': { at: '2026-08-10T00:00:00.000Z', deps: { a: '1' } } } }),
      '1.0.0', '2026-08-11T00:00:00.000Z'
    )
    expect(m.dependencyChurn).toBeNull()
  })

  it('counts dependencies added and removed against the predecessor', () => {
    const p = packument({
      name: 'churn',
      versions: {
        '1.0.0': { at: '2026-08-10T00:00:00.000Z', deps: { keep: '1', drop: '1' } },
        '1.0.1': { at: '2026-08-10T01:00:00.000Z', deps: { keep: '1', add: '1' } },
      },
    })
    expect(profile(p, '1.0.1', '2026-08-11T00:00:00.000Z').dependencyChurn)
      .toEqual({ added: 1, removed: 1, kept: 1, previousVersion: '1.0.0' })
  })

  it('walks back past versions npm has removed to find a readable predecessor', () => {
    const p = packument({
      name: 'holes',
      versions: {
        '1.0.0': { at: '2026-08-10T00:00:00.000Z', deps: { keep: '1' } },
        '1.0.1': { at: '2026-08-10T01:00:00.000Z', gone: true },
        '1.0.2': { at: '2026-08-10T02:00:00.000Z', deps: { keep: '1', add: '1' } },
      },
    })
    // The immediate predecessor is gone; stopping there would report null for a
    // package whose history is exactly what is being measured.
    expect(profile(p, '1.0.2', '2026-08-11T00:00:00.000Z').dependencyChurn?.previousVersion).toBe('1.0.0')
  })

  it('claims a version ahead of its history only above 1.0.0', () => {
    const ahead = packument({ name: 'a', versions: { '3.0.0': { at: '2026-08-10T00:00:00.000Z' } } })
    expect(profile(ahead, '3.0.0', '2026-08-11T00:00:00.000Z').versionAheadOfReleases).toBe(true)

    // Pre-1.0 semver claims no history, and firing here would fire on every
    // ordinary young package.
    const pre = packument({ name: 'b', versions: { '0.9.4': { at: '2026-08-10T00:00:00.000Z' } } })
    expect(profile(pre, '0.9.4', '2026-08-11T00:00:00.000Z').versionAheadOfReleases).toBeNull()
  })
})

describe('contamination is declared, not discovered', () => {
  it('gives every endpoint a status and a reason', () => {
    for (const e of ENDPOINTS) {
      expect(['entailed', 'partial', 'independent']).toContain(e.contamination)
      expect(e.because.length).toBeGreaterThan(40)
      expect(declarationOf(e.key)).toBe(e)
    }
  })

  it('marks the conjuncts and what they entail as entailed', () => {
    // These are the rows D11 proved cannot be read against a class-matched
    // control. A future edit demoting one of them to `independent` fails here.
    for (const key of ['name_age_days', 'has_provenance', 'provenance_lost']) {
      expect(declarationOf(key)?.contamination).toBe('entailed')
    }
  })

  it('keeps at least one independent endpoint, or there is nothing to find', () => {
    expect(ENDPOINTS.filter(e => e.contamination === 'independent').length).toBeGreaterThan(0)
  })

  it('recomputes the class from the repaired age', () => {
    const p = packument({
      name: 'in-class',
      versions: {
        '1.0.0': { at: '2026-08-16T00:00:00.000Z', size: 20_000 },
        [TAKEDOWN_PLACEHOLDER]: { at: '2026-08-17T00:00:00.000Z', size: 1000 },
      },
      created: '2026-08-17T00:00:00.000Z',
    })
    // Young by the repaired age too, so it really is in the class.
    expect(inObservedClass(profile(p, '1.0.0', '2026-08-17T00:00:00.000Z'))).toBe(true)

    const old = packument({
      name: 'not-in-class',
      versions: { '1.0.0': { at: '2024-01-01T00:00:00.000Z', size: 20_000 } },
      created: '2026-08-17T00:00:00.000Z',
    })
    // `created` says newborn, the release record says two and a half years. The
    // repaired reading is what decides, so this stays out.
    expect(inObservedClass(profile(old, '1.0.0', '2026-08-17T00:00:00.000Z'))).toBe(false)
  })
})
