/**
 * IDEA 1 AND 2 — the opacity as the signal, and evidence a reader can check.
 *
 * Hand-written cases, one per mechanic, NOT the corpus. The corpus is what these
 * are scored against in A5, and a measure fitted to it first and scored against it
 * afterwards measures nothing.
 *
 * The invariant these hold is the direction of every term. Getting `hasAuthoredOpacity`
 * backwards, or letting one of the analyser's own bounds count as the package's
 * doing, would produce a difference on both arms and call it a property of malware.
 */

import { describe, it, expect } from 'vitest'
import { analyzePackage } from '../src/reachability.js'
import { capabilitiesOf } from '../src/capabilities.js'
import {
  resolutionProfileOf, strictCapabilitiesOf, compareBinary, compareContinuous,
  AUTHORED_OPACITY, ANALYSER_BOUNDS,
} from '../src/import-opacity.js'
import type { CapabilityScan } from '../src/capability-run.js'
import { zForFamily } from '../src/stats.js'

// A package of one file, scanned the way capability-run.ts scans one.
function scan(source: string, extra: Record<string, string> = {}): CapabilityScan {
  const files = new Map<string, string>([['package/index.js', source]])
  for (const [name, code] of Object.entries(extra)) files.set(`package/${name}`, code)
  const reachability = analyzePackage({ files, packageJson: { main: 'index.js' }, root: 'package' })
  return {
    capabilities: capabilitiesOf({ reachability, sources: files }),
    reachability,
    refusal: null,
    parseableFiles: files.size,
    sourceBytes: [...files.values()].reduce((n, s) => n + s.length, 0),
    opaqueExecutable: false,
    opaqueKinds: [],
  }
}

const profile = (source: string, extra?: Record<string, string>) =>
  resolutionProfileOf(scan(source, extra))!

describe('the two kinds of not-knowing are counted apart', () => {
  it('every lost reason is on exactly one of the two lists', () => {
    const overlap = AUTHORED_OPACITY.filter(r => (ANALYSER_BOUNDS as string[]).includes(r))
    expect(overlap).toEqual([])
  })

  it("the analyser's own bounds are never counted as the package's doing", () => {
    // depth-limit, origin-bound, ambient-bound, argument-bound and
    // unresolved-import are budgets this project chose. A package cannot be
    // blamed for them, and counting them would measure the analyser on both arms.
    for (const reason of ANALYSER_BOUNDS) {
      expect(AUTHORED_OPACITY).not.toContain(reason)
    }
  })
})

describe('a package that hides its imports is measured as hiding them', () => {
  it('an ordinary static require hides nothing', () => {
    const p = profile(`const fs = require('fs'); fs.readFileSync('./data.txt')`)
    expect(p.hasAuthoredOpacity).toBe(false)
    expect(p.authoredOpacitySites).toBe(0)
    expect(p.importResolutionRate).toBe(1)
  })

  it('a specifier decided at runtime is authored opacity', () => {
    const p = profile(`const m = require(process.env.WHICH)`)
    expect(p.hasAuthoredOpacity).toBe(true)
    expect(p.bySite['dynamic-specifier']).toBeGreaterThan(0)
    expect(p.importResolutionRate).toBeLessThan(1)
  })

  it('eval is authored opacity even when the body is readable', () => {
    const p = profile(`eval('1 + 1')`)
    expect(p.evalOrFunctionCalls).toBeGreaterThan(0)
  })

  it('sites are counted once per file:line, so repetition cannot inflate them', () => {
    // The same construct on one line, reached many times, is one authoring
    // decision. Counting occurrences would let file size decide the answer.
    const once = profile(`const m = require(pick())`)
    const repeated = profile(
      `const m = require(pick())`,
      { 'a.js': `module.exports = require('./index.js')`, 'b.js': `module.exports = require('./index.js')` }
    )
    expect(repeated.bySite['dynamic-specifier']).toBe(once.bySite['dynamic-specifier'])
  })

  it('a package nothing could open has no profile, which is not a zero', () => {
    const unopened: CapabilityScan = {
      ...scan(`require('fs')`),
      reachability: null,
      refusal: 'no JavaScript in the archive',
    }
    expect(resolutionProfileOf(unopened)).toBeNull()
  })
})

describe('the strict answer counts only evidence a reader can check', () => {
  it('a module resolved by name stays reached', () => {
    const strict = strictCapabilitiesOf(scan(`const cp = require('child_process'); cp.spawn('sh')`))!
    const exec = strict.find(s => s.capability === 'external_exec')!
    expect(exec.frozenAnswer).toBe('reached')
    expect(exec.strictAnswer).toBe('reached')
    expect(exec.resolvedRoutes).toBeGreaterThan(0)
  })

  it('an ambient call the parser read is resolved evidence, not a lost point', () => {
    const strict = strictCapabilitiesOf(scan(`eval('x')`))!
    const dyn = strict.find(s => s.capability === 'dynamic_code')!
    expect(dyn.ambientCalls).toBeGreaterThan(0)
    expect(dyn.strictAnswer).toBe('reached')
  })

  it('reached ONLY because the specifier could not be read is demoted, and to indeterminate', () => {
    // The heart of idea 2. capabilities.ts makes a dynamic specifier positive
    // evidence for dynamic_code, which is correct by the frozen definition and is
    // also the analysis reporting its own failure. It must not become
    // `not-reached` — failing to read a specifier is not evidence of absence.
    const strict = strictCapabilitiesOf(scan(`const m = require(pick())`))!
    const dyn = strict.find(s => s.capability === 'dynamic_code')!
    expect(dyn.frozenAnswer).toBe('reached')
    expect(dyn.fromLostPoint).toBe(true)
    expect(dyn.resolvedRoutes).toBe(0)
    expect(dyn.ambientCalls).toBe(0)
    expect(dyn.strictAnswer).toBe('indeterminate')
    expect(dyn.strictAnswer).not.toBe('not-reached')
  })

  it('a clean package answers not-reached under both definitions', () => {
    const strict = strictCapabilitiesOf(scan(`module.exports = a => a + 1`))!
    for (const s of strict) {
      expect(s.frozenAnswer).toBe(s.strictAnswer)
    }
  })
})

describe('the comparison states what its denominator is', () => {
  const z = zForFamily(29)
  const hiding = { hasAuthoredOpacity: true } as never
  const clean = { hasAuthoredOpacity: false } as never

  it('a difference over an empty side is not calculable, not zero', () => {
    const c = compareBinary({
      measure: 'x', unitOfMeasure: 'y', cases: [], controls: [clean],
      pick: p => p.hasAuthoredOpacity, z,
    })
    expect(c.verdict).toContain('Not calculable')
  })

  it('a small n comes back inconclusive rather than separating', () => {
    const c = compareBinary({
      measure: 'x', unitOfMeasure: 'y',
      cases: [hiding, hiding], controls: [clean, clean],
      pick: p => p.hasAuthoredOpacity, z,
    })
    expect(c.verdict).toContain('INCONCLUSIVE')
  })

  it('the common-language effect is 50% when the two are the same', () => {
    const c = compareContinuous({
      measure: 'x', unitOfMeasure: 'y', cases: [1, 2, 3], controls: [1, 2, 3],
    })
    expect(c.probabilityCaseExceedsControl).toBeCloseTo(0.5, 10)
  })

  it('and 100% when every case exceeds every control', () => {
    const c = compareContinuous({
      measure: 'x', unitOfMeasure: 'y', cases: [4, 5], controls: [1, 2],
    })
    expect(c.probabilityCaseExceedsControl).toBe(1)
  })

  it('a handful of members is labelled a description, not a test', () => {
    const c = compareContinuous({ measure: 'x', unitOfMeasure: 'y', cases: [1], controls: [2] })
    expect(c.note).toContain('description, not a test')
  })
})
