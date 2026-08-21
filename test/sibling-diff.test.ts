/**
 * D — the sibling diff, and the uniformity check that did not survive it.
 *
 * The ranking is frozen in the module and these tests are what stops it moving.
 * D2 was validated against the two captures whose payload location is known from
 * other work — `kit-hydration-vim/dist/internal/calc.dat` and the off-registry
 * dependency line in `gunzip-js/package.json` — and both are reproduced here at
 * the shape that made them pass, so a later change to the tiering fails loudly
 * rather than quietly re-ordering them.
 *
 * D1 is here too, and its test records a NEGATIVE: it flagged 4 of 45 captures
 * and none of the known payloads, because none of them is JavaScript with odd
 * indentation. Keeping the code and the failing case together is the point — the
 * next person to have this idea should find the measurement, not the idea.
 */

import { describe, it, expect } from 'vitest'
import {
  rankCandidates, hashFiles, normalisePath, styleOf, uniformityOf,
} from '../src/sibling-diff.js'

const file = (name: string, content: string) => ({ name, data: Buffer.from(content) })
const sibling = (pkg: string, files: Array<{ name: string; data: Buffer }>) =>
  ({ package: pkg, version: '1.0.0', files: hashFiles(files) })

describe('D2 — what is not identical between siblings', () => {
  it('ranks a file only one sibling has above one they all differ on', () => {
    const ranked = rankCandidates([
      sibling('a', [file('package/index.js', 'shared'), file('package/package.json', '{"name":"a"}'), file('package/secret.dat', 'x'.repeat(500))]),
      sibling('b', [file('package/index.js', 'shared'), file('package/package.json', '{"name":"b"}')]),
    ])
    expect(ranked[0]!.file).toBe('secret.dat')
    expect(ranked[0]!.tier).toBe(1)
    // The manifest differs in every package by construction, so it is tier 2 and
    // never outranks a file that exists nowhere else.
    expect(ranked.find(c => c.file === 'package.json')!.tier).toBe(2)
    // Byte-identical across siblings is the scaffolding.
    expect(ranked.find(c => c.file === 'index.js')!.tier).toBe(3)
  })

  it('reproduces the kit-hydration-vim result', () => {
    // The real capture: 9 files against a sibling's 8, sharing only LICENSE.
    // calc.dat is the payload and is 63,616 bytes against a next-largest unique
    // file of 1,819.
    const ranked = rankCandidates([
      sibling('kit-hydration-vim', [
        file('package/LICENSE', 'MIT'),
        file('package/dist/internal/calc.dat', 'p'.repeat(63_616)),
        file('package/dist/internal/daymath.mjs', 'd'.repeat(1_819)),
        file('package/dist/store.mjs', 's'.repeat(1_181)),
      ]),
      sibling('svelte-goal-vim', [
        file('package/LICENSE', 'MIT'),
        file('package/dist/server.mjs', 'v'.repeat(1_588)),
        file('package/dist/internal/streakmath.mjs', 'm'.repeat(1_310)),
      ]),
    ])
    expect(ranked[0]!.package).toBe('kit-hydration-vim')
    expect(ranked[0]!.file).toBe('dist/internal/calc.dat')
  })

  it('reproduces the gunzip-js result, and it is a weak pass', () => {
    // Two files, one byte-identical across all three siblings. Ranking the
    // manifest first here is not much of an achievement and the test says so.
    const stub = "'use strict';\nmodule.exports = {};\n"
    const ranked = rankCandidates([
      sibling('gunzip-js', [file('package/index.js', stub), file('package/package.json', '{"d":"3.7.2"}')]),
      sibling('depcruise-fmt', [file('package/index.js', stub), file('package/package.json', '{"d":"3.7.3"}')]),
      sibling('depcruise-baseline', [file('package/index.js', stub), file('package/package.json', '{"d":"3.7.4"}')]),
    ])
    const inGunzip = ranked.filter(c => c.package === 'gunzip-js')
    expect(inGunzip[0]!.file).toBe('package.json')
    // There were only two files to choose between.
    expect(inGunzip).toHaveLength(2)
  })

  it('counts how many siblings share a path and how many share the content', () => {
    // The sui group: three names shipping a byte-identical index.js, three more
    // whose index.js differs. The tier hides that; these two numbers are what
    // show it.
    const identical = 'primitive'
    const ranked = rankCandidates([
      sibling('bcs-core', [file('package/index.js', identical)]),
      sibling('leb128x', [file('package/index.js', identical)]),
      sibling('ulebkit', [file('package/index.js', identical)]),
      sibling('sui-gql-core', [file('package/index.js', 'importer one')]),
    ])
    const primitive = ranked.find(c => c.package === 'bcs-core')!
    expect(primitive.siblingsWithPath).toBe(4)
    expect(primitive.siblingsWithSameContent).toBe(3)
  })

  it('strips npm\'s directory prefix and nothing else', () => {
    expect(normalisePath('package/dist/x.js')).toBe('dist/x.js')
    // A payload moved to a different directory changed the path, and the rule
    // should see that rather than be helped past it.
    expect(normalisePath('package/lib/x.js')).not.toBe(normalisePath('package/dist/x.js'))
  })
})

describe('D1 — internal uniformity, and why it does not work here', () => {
  it('detects a file that disagrees with its neighbours on two counts', () => {
    const tidy = styleOf('a.js', "const a = 1;\n  const b = 'x';\n  return a;\n")
    const odd = styleOf('b.js', 'const a = 1\n\tconst b = "x"\n\treturn a\n')
    const report = uniformityOf('p', [tidy, tidy, odd])
    expect(report.outliers).toContain('b.js')
  })

  it('does not call a stub an outlier', () => {
    // A two-line file has no style to disagree with, and counting it would make
    // every package with an index stub look inconsistent.
    const tidy = styleOf('a.js', "const a = 1;\n  const b = 'x';\n")
    const stub = styleOf('index.js', "'use strict';\nmodule.exports = {};\n")
    expect(uniformityOf('p', [tidy, tidy, stub]).outliers).not.toContain('index.js')
  })

  it('cannot see either known payload, which is the finding', () => {
    // `calc.dat` is magic bytes and the ltidi payload is a line of JSON. D1 only
    // reads javascript and typed-source, so neither is ever a candidate. Over
    // the corpus it flagged 4 of 45 captures and 0 known payloads.
    //
    // This test exists so the negative is not rediscovered: the payloads here
    // are a .dat file, a manifest line, a V8 bytecode cache and byte-identical
    // code under different names. None of them is a .js file with unusual
    // indentation.
    const payloadShapes = ['dist/internal/calc.dat', 'package.json', 'dist/yorn.jsc']
    for (const name of payloadShapes) {
      expect(/\.(js|mjs|cjs|ts)$/.test(name)).toBe(false)
    }
  })
})
