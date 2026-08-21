/**
 * IDEA 4 — the batch as the unit.
 *
 * Hand-built publication lists, not the corpus. The two shapes that matter here
 * were both found by running the pass over the store and both would pass a test
 * written only against the attacks: a monorepo release is a tight batch, and
 * npm's own takedown writes look like one account publishing many names.
 *
 * The invariant is that the definition must separate a BATCH from a CADENCE.
 * @siwatfa/yorn is 149 releases of one name, and a unit that counted
 * publications would call it the largest campaign in the corpus.
 */

import { describe, it, expect } from 'vitest'
import {
  partitionIntoFamilies, familyProfileOf, numberedSequences,
  tokensOf, sharedTokenOf, sharedScopeOf,
  BURST_GAP_MINUTES, MIN_FAMILY_PACKAGES, TIGHT_BATCH_PACKAGES, TIGHT_BATCH_MINUTES,
  type Publication,
} from '../src/family.js'

const base = Date.UTC(2026, 7, 19, 20, 0, 0)
const at = (minutes: number): string => new Date(base + minutes * 60_000).toISOString()

const pub = (pkg: string, publisher: string, minutes: number, version = '1.0.0'): Publication =>
  ({ package: pkg, version, publisher, at: at(minutes) })

describe('a batch is not a cadence', () => {
  it('calls several names from one account inside the window a family', () => {
    const { families, cadences } = partitionIntoFamilies([
      pub('depcruise-fmt', 'whltd4', 0),
      pub('depcruise-baseline', 'whltd4', 1),
      pub('gunzip-js', 'whltd4', 4),
    ])
    expect(families).toHaveLength(1)
    expect(cadences).toHaveLength(0)
    expect(families[0]!.distinctPackages).toBe(3)
    expect(families[0]!.spanMinutes).toBe(4)
  })

  it('calls one name republishing a cadence, however many times', () => {
    // 149 releases of @siwatfa/yorn is one package on a release loop, and the
    // family unit exists so that it cannot be counted as 149 independent events.
    const loop = Array.from({ length: 40 }, (_, i) => pub('@siwatfa/yorn', 'siwatfa', i * 2, `1.0.${i}`))
    const { families, cadences } = partitionIntoFamilies(loop)
    expect(families).toHaveLength(0)
    expect(cadences).toHaveLength(1)
    expect(cadences[0]!.publications).toHaveLength(40)
  })

  it('splits one account into separate bursts across a gap', () => {
    const { families } = partitionIntoFamilies([
      pub('a', 'op', 0), pub('b', 'op', 2),
      pub('c', 'op', BURST_GAP_MINUTES + 10), pub('d', 'op', BURST_GAP_MINUTES + 12),
    ])
    // Two decisions to publish a batch, not one batch with a long span.
    expect(families).toHaveLength(2)
    expect(families.every(f => f.distinctPackages === MIN_FAMILY_PACKAGES)).toBe(true)
  })

  it('leaves a lone publication isolated', () => {
    const { families, cadences, isolated } = partitionIntoFamilies([pub('alone', 'op', 0)])
    expect(families).toHaveLength(0)
    expect(cadences).toHaveLength(0)
    expect(isolated).toHaveLength(1)
  })

  it('never groups across accounts', () => {
    const { families } = partitionIntoFamilies([
      pub('a', 'one', 0), pub('b', 'two', 1), pub('c', 'three', 2),
    ])
    expect(families).toHaveLength(0)
  })

  it('drops publications with no attributable publisher rather than pooling them', () => {
    const { families, isolated } = partitionIntoFamilies([
      { package: 'a', version: '1.0.0', publisher: '', at: at(0) },
      { package: 'b', version: '1.0.0', publisher: '', at: at(1) },
    ])
    expect(families).toHaveLength(0)
    expect(isolated).toHaveLength(0)
  })
})

describe('the tight batch', () => {
  it('needs three names inside the hour', () => {
    const three = partitionIntoFamilies([
      pub('a', 'op', 0), pub('b', 'op', 1), pub('c', 'op', 2),
    ]).families[0]!
    expect(familyProfileOf(three).isTightBatch).toBe(true)

    const two = partitionIntoFamilies([pub('a', 'op', 0), pub('b', 'op', 1)]).families[0]!
    expect(two.distinctPackages).toBeLessThan(TIGHT_BATCH_PACKAGES)
    expect(familyProfileOf(two).isTightBatch).toBe(false)
  })

  it('does not divide by zero when a batch lands in one instant', () => {
    // Several packages published simultaneously is the strongest form of the
    // observation, so it must not come back as a missing number.
    const f = partitionIntoFamilies([
      pub('a', 'op', 0), pub('b', 'op', 0), pub('c', 'op', 0),
    ]).families[0]!
    expect(f.spanMinutes).toBe(0)
    expect(f.packagesPerHour).toBeNull()
    expect(familyProfileOf(f).isTightBatch).toBe(true)
  })

  it('is ordinary on its own — a monorepo release is a tight batch', () => {
    // 84 @hive-ui components in 2 minutes is what changesets does. This test
    // records that the endpoint fires on it, because a reading of the family
    // pass that treats a tight batch as suspicious is wrong at the base rate:
    // 58.9% of the families in the store are tight.
    const monorepo = Array.from({ length: 84 }, (_, i) => pub(`@hive-ui/c${i}`, 'maintainer', i / 60))
    const f = partitionIntoFamilies(monorepo).families[0]!
    expect(familyProfileOf(f).isTightBatch).toBe(true)
    expect(f.spanMinutes).toBeLessThan(TIGHT_BATCH_MINUTES)
  })

  it('separates the monorepo from the campaign on all-first-publication', () => {
    const names = ['a', 'b', 'c']
    const batch = names.map((n, i) => pub(n, 'op', i))

    const allNew = partitionIntoFamilies(batch, { firstPublications: new Set(names) }).families[0]!
    expect(familyProfileOf(allNew).allFirstPublications).toBe(true)

    // The monorepo re-releases names it already owns.
    const reReleased = partitionIntoFamilies(batch, { firstPublications: new Set(['a']) }).families[0]!
    expect(familyProfileOf(reReleased).allFirstPublications).toBe(false)
  })
})

describe('the lexical domain', () => {
  it('finds the token every name shares', () => {
    expect(sharedTokenOf(['kit-hydration-vim', 'svelte-goal-vim'])).toBe('vim')
    expect(sharedTokenOf(['depcruise-fmt', 'depcruise-baseline'])).toBe('depcruise')
  })

  it('reads the scope as a token, so a new scope counts as shared', () => {
    expect(tokensOf('@noxzacode/lock-file')).toEqual(['noxzacode', 'lock', 'file'])
    expect(sharedTokenOf(['@platformize/core', '@platformize/cli'])).toBe('platformize')
    expect(sharedScopeOf(['@platformize/core', '@platformize/cli'])).toBe('@platformize')
    expect(sharedScopeOf(['@a/one', '@b/two'])).toBeNull()
  })

  it('reports nothing shared rather than something trivial', () => {
    expect(sharedTokenOf(['gunzip-js', 'depcruise-fmt'])).toBeNull()
    // Single characters and bare digits are shared by half the registry, and
    // reporting them would make the endpoint fire on any batch at all.
    expect(sharedTokenOf(['a-v-2', 'b-v-2'])).toBeNull()
    expect(sharedTokenOf(['solo'])).toBeNull()
  })
})

describe('the sequence that spans accounts', () => {
  // The shape found in the store: one counter, three accounts, about a minute
  // apart. Reproduced here at the numbers and the rotation, not the names.
  const campaign: Publication[] = [
    pub('spingear-037-th', 'node-mini-tools', 0),
    pub('reelutil-038-th', 'pkg-utils-lab', 2),
    pub('luckyhelper-039-th', 'tiny-js-helpers', 3),
    pub('demospin-041-th', 'pkg-utils-lab', 5),
    pub('baccarathelp-044-th', 'pkg-utils-lab', 11),
    pub('credithelper-045-th', 'tiny-js-helpers', 12),
    pub('gamehubutil-047-th', 'tiny-js-helpers', 15),
    pub('slotkit-048-th', 'node-mini-tools', 16),
  ]

  it('detects one counter driving several accounts', () => {
    const seqs = numberedSequences(campaign)
    expect(seqs).toHaveLength(1)
    const s = seqs[0]!
    expect(s.shape).toBe('<stem>-N-th')
    expect(s.publishers.sort()).toEqual(['node-mini-tools', 'pkg-utils-lab', 'tiny-js-helpers'])
    expect(s.members.map(m => m.number)).toEqual([37, 38, 39, 41, 44, 45, 47, 48])
    // The rotation is the evidence. One account working alone scores 0 here.
    // Five of the seven adjacent pairs change account: 41->44 and 45->47 do not.
    expect(s.crossAccountAdjacency).toBe(5)
    expect(s.adjacentPairs).toBe(7)
  })

  it('stays silent on one account numbering its own releases', () => {
    const solo = campaign.map(p => ({ ...p, publisher: 'one-account' }))
    expect(numberedSequences(solo)).toHaveLength(0)
  })

  it('stays silent below the member floor', () => {
    expect(numberedSequences(campaign.slice(0, 3))).toHaveLength(0)
  })

  it('does not match a platform binary or a version suffix', () => {
    // The detector is narrow on purpose: a general "there is a number in the
    // name" would fire on every napi build in the registry.
    const binaries = [
      pub('castclaw-load-linux-x64-musl', 'a', 0),
      pub('postcss-go-native-win32-x64-msvc', 'b', 1),
      pub('cli-darwin-arm64', 'c', 2),
      pub('thing-v2', 'd', 3),
      pub('some-2026-pkg', 'e', 4),
    ]
    expect(numberedSequences(binaries)).toHaveLength(0)
  })

  it('counts each name once however many versions it published', () => {
    const withVersions = campaign.flatMap(p => [p, { ...p, version: '1.0.1' }])
    const s = numberedSequences(withVersions)[0]!
    expect(s.members).toHaveLength(8)
  })
})
