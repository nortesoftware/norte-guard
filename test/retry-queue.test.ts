/**
 * The 404 retry queue and the dependency rule.
 *
 * Both exist because of a specific loss that is on disk and countable, and both
 * tests below encode that loss rather than a hypothetical. A retry that gives up
 * inside an hour would miss the packages npm is about to remove — the median time
 * to remediation is 64 minutes — and a dependency rule that consults the
 * dependency's own size or repository would reject `mutex-forge` exactly as the
 * quarantine conjunction already did.
 */

import { describe, it, expect } from 'vitest'
import {
  enqueue, due, recordAttempt, isRetryable,
  RETRY_SCHEDULE_SECONDS, MAX_QUEUE, RETRYABLE,
  type QueueState,
} from '../src/retry-queue.js'
import {
  declaredDependencies, truncatedFollow, shouldCaptureDependency, alreadyHeld, sameScope,
  DEPENDENCY_MUST_BE_YOUNGER_THAN_DAYS, MAX_FOLLOWED_PER_CAPTURE,
} from '../src/dependency-capture.js'
import { normalizePackument, type VersionMeta } from '../src/packument.js'
import { YOUNG_NAME_DAYS } from '../src/observed-class.js'

const T0 = Date.UTC(2026, 7, 13, 9, 30, 0)
const empty = (): QueueState => ({ entries: [], dropped: 0 })

describe('a 404 is not an answer', () => {
  it('schedules the first retry 30 seconds out', () => {
    const q = enqueue(empty(), { package: 'shared-slot-gate', seq: 124773917, reason: '404', now: T0 })
    expect(q.entries).toHaveLength(1)
    expect(q.entries[0]!.nextAttemptAt).toBe(new Date(T0 + 30_000).toISOString())
    expect(due(q, T0)).toHaveLength(0)
    expect(due(q, T0 + 30_000)).toHaveLength(1)
  })

  it('spans past npm\'s median remediation before giving up', () => {
    // 64 minutes is the median time from publication to removal. A schedule that
    // finished inside that window would drop exactly the packages worth having.
    const total = RETRY_SCHEDULE_SECONDS.reduce((a, b) => a + b, 0)
    expect(total).toBeGreaterThan(64 * 60)
  })

  it('walks the whole schedule, then exhausts', () => {
    let q = enqueue(empty(), { package: 'gone', seq: 1, reason: '404', now: T0 })
    let now = T0
    for (let i = 0; i < RETRY_SCHEDULE_SECONDS.length - 1; i += 1) {
      now += RETRY_SCHEDULE_SECONDS[i]! * 1000
      const step = recordAttempt(q, 'gone', false, now)
      expect(step.exhausted).toBe(false)
      q = step.state
      expect(q.entries[0]!.attempts).toBe(i + 1)
    }
    const last = recordAttempt(q, 'gone', false, now + 7_200_000)
    expect(last.exhausted).toBe(true)
    expect(last.state.entries).toHaveLength(0)
  })

  it('drops the entry as soon as it recovers', () => {
    const q = enqueue(empty(), { package: 'async-lock-queue', seq: 2, reason: '404', now: T0 })
    const out = recordAttempt(q, 'async-lock-queue', true, T0 + 30_000)
    expect(out.state.entries).toHaveLength(0)
    expect(out.exhausted).toBe(false)
  })

  it('keeps one entry per package however often it is announced', () => {
    let q = enqueue(empty(), { package: 'x', seq: 1, reason: '404', now: T0 })
    q = enqueue(q, { package: 'x', seq: 2, reason: '404', now: T0 + 1000 })
    q = enqueue(q, { package: 'x', seq: 3, reason: 'timeout', now: T0 + 2000 })
    expect(q.entries).toHaveLength(1)
    expect(q.entries[0]!.seq).toBe(1)
  })

  it('does not retry a malformed packument', () => {
    // It parsed badly and will parse badly again; a retry spends a request to
    // reach the same branch.
    expect(isRetryable('malformed')).toBe(false)
    expect(RETRYABLE).not.toContain('malformed')
    expect(enqueue(empty(), { package: 'x', seq: 1, reason: 'malformed', now: T0 }).entries).toHaveLength(0)
  })

  it('remembers WHY a package is queued, so the retry uses the right path', () => {
    // A dependency replayed through the score path would be rejected for the
    // reasons the dependency rule exists to overrule: mutex-forge scored 10.
    const q = enqueue(empty(), {
      package: 'mutex-forge', seq: 0, reason: '404', now: T0,
      origin: 'dependency', declaredBy: 'async-critical-section', declaredByVersion: '1.0.0',
    })
    expect(q.entries[0]!.origin).toBe('dependency')
    expect(q.entries[0]!.declaredBy).toBe('async-critical-section')
  })

  it('defaults to the feed origin when none is given', () => {
    const q = enqueue(empty(), { package: 'x', seq: 1, reason: '404', now: T0 })
    expect(q.entries[0]!.origin).toBe('feed')
    expect(q.entries[0]!.declaredBy).toBeUndefined()
  })

  it('bounds the queue and counts what it dropped', () => {
    // A registry outage announces thousands at once. A queue that grew without
    // limit would become the outage's memory.
    let q = empty()
    for (let i = 0; i < MAX_QUEUE + 25; i += 1) {
      q = enqueue(q, { package: `p${i}`, seq: i, reason: '404', now: T0 })
    }
    expect(q.entries).toHaveLength(MAX_QUEUE)
    expect(q.dropped).toBe(25)
    // Oldest first, so the newest announcement is the one kept.
    expect(q.entries[q.entries.length - 1]!.package).toBe(`p${MAX_QUEUE + 24}`)
  })
})

describe('the dependency the class was built to ignore', () => {
  const packument = (input: { name: string; firstAt: string; size?: number; repository?: unknown }) =>
    normalizePackument({
      name: input.name,
      'dist-tags': { latest: '1.0.0' },
      time: { created: input.firstAt, modified: input.firstAt, '1.0.0': input.firstAt },
      versions: {
        '1.0.0': {
          dist: { unpackedSize: input.size ?? 1000, tarball: '', integrity: '', shasum: '' },
          repository: input.repository,
        },
      },
      maintainers: [{ name: 'someone', email: 'a@b.c' }],
    })

  const meta = (deps: string[]): VersionMeta =>
    ({ dependencies: Object.fromEntries(deps.map(d => [d, '^1.0.0'])) } as unknown as VersionMeta)

  it('captures mutex-forge, which the quarantine conjunction rejects', () => {
    // 664KB with a repository: fails `tiny`, fails `!hasRepository`, and scored
    // 10. Two of the three conjuncts, so widening the class to 2-of-3 would not
    // have kept it either. It was published hours before the five packages that
    // declare it.
    const dep = packument({
      name: 'mutex-forge',
      firstAt: new Date(T0 - 6 * 3_600_000).toISOString(),
      size: 664_297,
      repository: { type: 'git', url: 'https://github.com/x/y' },
    })
    const decision = shouldCaptureDependency(dep, T0)
    expect(decision.capture).toBe(true)
    expect(decision.ageDays).toBeLessThan(1)
  })

  it('leaves an ordinary old dependency alone', () => {
    // The median declared dependency in this corpus is 1,455 days old. If those
    // were followed the rule would reach 9,330 names instead of about 163.
    const lodash = packument({ name: 'lodash', firstAt: '2012-04-23T00:00:00.000Z' })
    const decision = shouldCaptureDependency(lodash, T0)
    expect(decision.capture).toBe(false)
    expect(decision.ageDays).toBeGreaterThan(1000)
  })

  it('reuses the frozen young bound rather than inventing a threshold', () => {
    expect(DEPENDENCY_MUST_BE_YOUNGER_THAN_DAYS).toBe(YOUNG_NAME_DAYS)
    const edge = packument({
      name: 'edge',
      firstAt: new Date(T0 - (YOUNG_NAME_DAYS + 0.1) * 86_400_000).toISOString(),
    })
    expect(shouldCaptureDependency(edge, T0).capture).toBe(false)
  })

  it('says so when it cannot age a dependency at all', () => {
    // Not the same as old. A silent false here would put "we could not tell" and
    // "it is established as old" in one bucket.
    const undated = normalizePackument({ name: 'undated', versions: {}, time: {}, maintainers: [] })
    const decision = shouldCaptureDependency(undated, T0)
    expect(decision.capture).toBe(false)
    expect(decision.ageDays).toBeNull()
    expect(decision.reason).toContain('no publication timestamp')
  })

  it('reads dependencies but never devDependencies', () => {
    const withBoth = {
      dependencies: { runtime: '1' },
      devDependencies: { build: '1' },
    } as unknown as VersionMeta
    const candidates = declaredDependencies('caller', '1.0.0', withBoth)
    expect(candidates.map(c => c.package)).toEqual(['runtime'])
  })

  it('records who declared it, so the corpus can say why it is there', () => {
    const [c] = declaredDependencies('async-critical-section', '1.0.0', meta(['mutex-forge']))
    expect(c).toEqual({
      package: 'mutex-forge',
      declaredBy: 'async-critical-section',
      declaredByVersion: '1.0.0',
    })
  })

  it('caps the fan-out and reports the truncation instead of hiding it', () => {
    const many = meta(Array.from({ length: 519 }, (_, i) => `dep${i}`))
    expect(declaredDependencies('big', '1.0.0', many)).toHaveLength(MAX_FOLLOWED_PER_CAPTURE)
    expect(truncatedFollow(many)).toBe(519 - MAX_FOLLOWED_PER_CAPTURE)
    expect(truncatedFollow(meta(['one']))).toBe(0)
  })

  it('degrades a same-scope sibling instead of excluding it', () => {
    // 203 of the first 219 captures on this path were a package declaring
    // another under its own scope — a monorepo release. The bytes are declined
    // and the packument kept, so the population stays in the denominator: if an
    // operator ever does use one scope for both the decoy and the carrier, that
    // has to remain answerable.
    expect(sameScope('@latticeag/adapter-stub', '@latticeag/bus')).toBe(true)
    expect(sameScope('@composy/layout-elements', '@composy/layout-runtime')).toBe(true)
    expect(sameScope('@a/one', '@b/two')).toBe(false)
  })

  it('keeps full bytes for every carrier the rule was written for', () => {
    // All four known carriers are cross-scope. If any of these flipped to true
    // the degradation would be taking bytes off the only samples that motivated
    // the rule.
    expect(sameScope('async-critical-section', 'mutex-forge')).toBe(false)
    expect(sameScope('sui-gql-core', 'bcs-core')).toBe(false)
    expect(sameScope('sui-move-rpc', 'leb128x')).toBe(false)
    expect(sameScope('sui-move-graphql', 'ulebkit')).toBe(false)
  })

  it('never calls two unscoped packages siblings', () => {
    // Two unscoped names share no scope; they share nothing. Treating them as
    // siblings would degrade the mutex-forge case itself.
    expect(sameScope('anything', 'anything-else')).toBe(false)
    expect(sameScope('@scoped/a', 'unscoped')).toBe(false)
    expect(sameScope('unscoped', '@scoped/a')).toBe(false)
    // A bare '@name' with no slash is not a scope.
    expect(sameScope('@weird', '@weird')).toBe(false)
  })

  it('skips what the corpus already holds', () => {
    const [c] = declaredDependencies('caller', '1.0.0', meta(['mutex-forge']))
    expect(alreadyHeld(c!, new Set(['mutex-forge']))).toBe(true)
    expect(alreadyHeld(c!, new Set())).toBe(false)
  })
})
