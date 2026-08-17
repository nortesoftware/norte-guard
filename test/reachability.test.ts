/**
 * FASE A1 + A2 — the reachability graph, validated on hand-written cases.
 *
 * Deliberately NOT validated against the corpus. The corpus has two confirmed
 * samples with bytes; a mechanic checked against it would be fitted to two
 * packages and then quoted as if it had been measured. These cases are written
 * to state the mechanic, one per pattern, and a pattern discovered later is
 * added here as a test rather than patched in as a special case.
 *
 * The question every one of them asks is "can this reach X?", never "is this
 * dangerous?" — that is A3, and A3 does not have the samples yet.
 */

import { describe, it, expect } from 'vitest'
import {
  analyzeModuleSource,
  analyzePackage,
  declaredEntryPoints,
  resolveLocal,
  MAX_MODULE_LOST,
  type LostReason,
} from '../src/reachability.js'

// Every module the source can reach, by name. The member path and route are
// asserted separately where they are the point.
const modules = (src: string): string[] =>
  [...new Set(
    analyzeModuleSource(src).origins
      .filter(o => o.module !== null)
      .map(o => o.module!)
  )].sort()

const lostReasons = (src: string): LostReason[] =>
  [...new Set(analyzeModuleSource(src).lost.map(l => l.reason))].sort()

const pathsTo = (src: string, module: string): string[] =>
  analyzeModuleSource(src).origins
    .filter(o => o.module === module && o.path.length > 0)
    .map(o => o.path.join('.'))

// ---------------------------------------------------------------------------
// A1 — the three doors
// ---------------------------------------------------------------------------

describe('A1: the three gates, and nothing else is one', () => {
  it('require, import and process.binding are all origins', () => {
    expect(modules(`require('fs')`)).toEqual(['fs'])
    expect(modules(`import('fs')`)).toEqual(['fs'])
    expect(modules(`import 'fs'`)).toEqual(['fs'])
    expect(modules(`process.binding('fs')`)).toEqual(['fs'])
  })

  it('the gate is recorded, so three doors are never one', () => {
    expect(analyzeModuleSource(`require('fs')`).origins[0]!.gate).toBe('require')
    expect(analyzeModuleSource(`import('fs')`).origins[0]!.gate).toBe('import')
    expect(analyzeModuleSource(`process.binding('fs')`).origins[0]!.gate).toBe('process.binding')
  })

  // Not a fourth door: the same door reached by another name.
  it('the aliases of require resolve to require', () => {
    expect(modules(`module.require('fs')`)).toEqual(['fs'])
    expect(modules(`require.resolve('fs')`)).toEqual(['fs'])
    expect(modules(`(0, require)('fs')`)).toEqual(['fs'])
  })

  it('a name that merely looks like a gate is not one', () => {
    // A local function called require is still a call this analysis follows, but
    // it is not a door: nothing is born here.
    expect(modules(`function requireish(x) { return x } requireish('fs')`)).toEqual([])
    expect(modules(`const o = { require: (x) => x }; o.require('fs')`)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// A2 — the seven propagation patterns, each of which must reach 'fs'
// ---------------------------------------------------------------------------

describe('A2: the seven patterns all resolve to fs', () => {
  it('1. assignment', () => {
    const src = `const fs = require('fs')`
    expect(modules(src)).toEqual(['fs'])
  })

  it('2. destructuring', () => {
    const src = `const { readFileSync } = require('fs')`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('3. renaming', () => {
    const src = `const fs = require('fs'); const r = fs.readFileSync`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('4. argument', () => {
    const src = `function f(mod) { return mod.readFileSync } f(require('fs'))`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('5. return', () => {
    const src = `function g() { return require('fs') } const fs = g(); fs.readFileSync`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('6. property', () => {
    const src = `const obj = {}; obj.fs = require('fs'); obj.fs.readFileSync`
    expect(modules(src)).toEqual(['fs'])
  })

  it('7. computed access with a foldable key', () => {
    const src = `const fs = require('fs'); fs['read' + 'FileSync']`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  // The route is the "por qué" half of the output. Without it, "reaches fs" and
  // "reaches fs through a rename, an argument and a return" read the same.
  it('the route records how the value travelled', () => {
    const src = `function g() { return require('fs') } const fs = g()`
    const origins = analyzeModuleSource(src).origins.filter(o => o.module === 'fs')
    const route = origins.map(o => o.route.join('>')).join(' | ')
    expect(route).toContain('gate')
    expect(route).toContain('return')
  })
})

// ---------------------------------------------------------------------------
// Negatives — code that does not reach fs must not report it
// ---------------------------------------------------------------------------

describe('negatives: what does not reach fs is not reported', () => {
  it('another module is not fs', () => {
    expect(modules(`const path = require('path'); path.join('a','b')`)).toEqual(['path'])
  })

  it('a local object with the same shape is not a module', () => {
    const src = `const fs = { readFileSync: () => 1 }; fs.readFileSync()`
    expect(modules(src)).toEqual([])
  })

  it('the string "fs" on its own reaches nothing', () => {
    expect(modules(`const name = 'fs'; console.log(name)`)).toEqual([])
  })

  // The whole reason this is not a text search: a rename defeats grep and must
  // not defeat this, and a coincidence of names must not fool it either.
  it('a local binding named readFileSync is not fs.readFileSync', () => {
    const src = `function readFileSync() { return 1 } readFileSync()`
    expect(modules(src)).toEqual([])
  })

  it('a shadowed binding does not leak the outer module', () => {
    const src = `const fs = require('path'); function f() { const fs = { x: 1 }; return fs.x } f()`
    expect(modules(src)).toEqual(['path'])
  })
})

// ---------------------------------------------------------------------------
// Lost — marked, never ignored, and never a pass
// ---------------------------------------------------------------------------

describe('lost trails are recorded, not skipped', () => {
  it('require of a value decided at runtime', () => {
    const src = `function f(name) { return require(name) } f(process.argv[2])`
    expect(lostReasons(src)).toContain('dynamic-specifier')
    // And it does not silently claim to reach nothing: the origin exists with a
    // null module, which is "a module I could not name", not "no module".
    const origins = analyzeModuleSource(src).origins
    expect(origins.some(o => o.module === null)).toBe(true)
  })

  it('eval over a string built at runtime', () => {
    const src = `eval('req' + variable)`
    expect(lostReasons(src)).toContain('dynamic-eval')
  })

  it('import() of a computed specifier', () => {
    const src = `const which = pick(); import(which)`
    expect(lostReasons(src)).toContain('dynamic-specifier')
  })

  it('a computed member whose key is not foldable', () => {
    const src = `const fs = require('fs'); fs[pick()]`
    expect(lostReasons(src)).toContain('computed-member')
    // The module is still reached — losing the member name does not lose the door.
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('*')
  })

  it('a template specifier with a runtime hole is lost, and the gate still counts', () => {
    const src = 'require(`./locales/${lang}`)'
    expect(lostReasons(src)).toContain('dynamic-specifier')
  })

  it('recursion past the frame budget is reported rather than followed forever', () => {
    const src = `function f() { return f() } f()`
    expect(lostReasons(src)).toContain('depth-limit')
  })

  it('a file that does not parse is one lost point, not an empty answer', () => {
    const result = analyzeModuleSource(`function ( { { {`)
    expect(result.origins).toEqual([])
    expect(result.lost).toHaveLength(1)
    expect(result.lost[0]!.detail).toContain('did not parse')
  })
})

// ---------------------------------------------------------------------------
// Folding — the deliberate difference from A4
// ---------------------------------------------------------------------------

describe('an assembled specifier that folds is followed, not lost', () => {
  // A4 marks this file `dynamic-require`, because there the question is whether
  // a parser can bound the file and an assembled specifier is what obfuscation
  // looks like. Here the question is whether the code reaches fs, and it
  // provably does. Both are true about the same line, and reporting this as
  // lost would be a false negative in the one direction this phase must not
  // have.
  it('literal concatenation folds', () => {
    expect(modules(`require('f' + 's')`)).toEqual(['fs'])
    expect(lostReasons(`require('f' + 's')`)).toEqual([])
  })

  it('a template with no holes folds', () => {
    expect(modules('require(`fs`)')).toEqual(['fs'])
  })

  it('a name bound once to a literal folds', () => {
    expect(modules(`const m = 'fs'; require(m)`)).toEqual(['fs'])
  })

  // A name written twice is not a constant, and folding it as one would make the
  // answer depend on which write the analysis happened to see first.
  it('a name written twice does not fold', () => {
    const src = `let m = 'fs'; m = compute(); require(m)`
    expect(modules(src)).toEqual([])
    expect(lostReasons(src)).toContain('dynamic-specifier')
  })
})

// ---------------------------------------------------------------------------
// Deeper shapes, each one a pattern found while writing the mechanic
// ---------------------------------------------------------------------------

describe('shapes that exist to hide the origin', () => {
  it('a chain of renames still ends at the gate', () => {
    const src = `const a = require('fs'); const b = a; const c = b; const d = c.readFileSync`
    expect(modules(src)).toEqual(['fs'])
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('destructuring with a rename is the same edge', () => {
    const src = `const { readFileSync: rf } = require('fs'); rf('/etc/passwd')`
    expect(pathsTo(src, 'fs')).toContain('readFileSync')
  })

  it('a value carried through an object literal and back out', () => {
    const src = `const box = { inner: require('fs') }; const fs = box.inner; fs.readFileSync`
    expect(modules(src)).toEqual(['fs'])
  })

  it('both branches of a conditional are reachable', () => {
    const src = `const m = flag ? require('fs') : require('path')`
    expect(modules(src)).toEqual(['fs', 'path'])
  })

  it('a reassigned binding keeps both modules, not the last one', () => {
    const src = `let m = require('fs'); m = require('path'); m.x`
    expect(modules(src)).toEqual(['fs', 'path'])
  })

  it('an eval of a literal body is source, and is analysed as source', () => {
    const src = `eval("require('fs')")`
    expect(modules(src)).toEqual(['fs'])
  })

  it('a gate inside a nested arrow is still a gate', () => {
    const src = `const f = () => () => require('fs'); f()()`
    expect(modules(src)).toEqual(['fs'])
  })

  it('an await does not hide a dynamic import', () => {
    const src = `async function f() { const m = await import('fs'); return m.readFileSync }`
    expect(modules(src)).toEqual(['fs'])
  })
})

// ---------------------------------------------------------------------------
// The package graph
// ---------------------------------------------------------------------------

describe('the package graph', () => {
  const pkg = (files: Record<string, string>, packageJson: unknown) =>
    analyzePackage({ files: new Map(Object.entries(files)), packageJson })

  it('follows a relative require into another file in the package', () => {
    const result = pkg({
      'package/index.js': `const helper = require('./lib/helper.js'); helper.run()`,
      'package/lib/helper.js': `const fs = require('fs'); module.exports = { run: () => fs.readFileSync }`,
    }, { main: 'index.js' })

    expect(result.entryPoints).toEqual(['package/index.js'])
    expect(result.filesAnalysed).toContain('package/lib/helper.js')
    expect(result.reachable.map(r => r.module)).toEqual(['fs'])
    expect(result.reachable[0]!.files).toContain('package/lib/helper.js')
  })

  it('a relative specifier is a file, never a reachable module', () => {
    const result = pkg({
      'package/index.js': `require('./other.js')`,
      'package/other.js': `// nothing`,
    }, { main: 'index.js' })
    expect(result.reachable).toEqual([])
  })

  it('resolves extensions and index files the way Node would', () => {
    const files = new Set(['package/index.js', 'package/lib/index.js', 'package/a.mjs'])
    expect(resolveLocal('./lib', 'package/index.js', files, 'package')).toBe('package/lib/index.js')
    expect(resolveLocal('./a', 'package/index.js', files, 'package')).toBe('package/a.mjs')
    expect(resolveLocal('./missing', 'package/index.js', files, 'package')).toBeNull()
  })

  it('an install script is an entry point: it runs before anything imports anything', () => {
    const entries = declaredEntryPoints({
      main: 'index.js',
      scripts: { postinstall: 'node ./scripts/setup.js', test: 'vitest' },
    })
    expect(entries).toContain('index.js')
    expect(entries).toContain('./scripts/setup.js')
    expect(entries).not.toContain('vitest')
  })

  it('bin and exports are entry points too', () => {
    const entries = declaredEntryPoints({
      bin: { tool: './cli.js' },
      exports: { '.': { import: './esm.js', require: './cjs.js' } },
    })
    expect(entries).toEqual(expect.arrayContaining(['./cli.js', './esm.js', './cjs.js']))
  })

  // These are declared in `exports` by convention and Node loads neither for
  // behaviour. Reporting them as declared-but-absent was a false alarm on the
  // first real capture: they are in the tarball, they are just not code.
  it('type declarations and the package.json self-reference are not entry points', () => {
    const entries = declaredEntryPoints({
      exports: {
        '.': { types: './types/index.d.ts', import: './dist/index.mjs' },
        './package.json': './package.json',
      },
    })
    expect(entries).toEqual(['./dist/index.mjs'])
  })

  it('with no package.json field at all it still starts somewhere', () => {
    expect(declaredEntryPoints({})).toEqual(['index.js'])
  })

  it('a declared entry point that is not in the tarball is reported, not skipped', () => {
    const result = pkg({ 'package/index.js': `require('fs')` }, { main: 'index.js', bin: './missing.js' })
    expect(result.missingEntryPoints).toContain('./missing.js')
    expect(result.reachable.map(r => r.module)).toEqual(['fs'])
  })

  it('an unresolvable relative require is a packaging fact, kept apart from a lost trail', () => {
    const result = pkg({ 'package/index.js': `require('./gone.js')` }, { main: 'index.js' })
    expect(result.unresolvedLocal).toHaveLength(1)
    expect(result.unresolvedLocal[0]).toContain('./gone.js')
    expect(result.lost).toEqual([])
  })

  it('a file the entry point never reaches is not analysed', () => {
    const result = pkg({
      'package/index.js': `module.exports = 1`,
      'package/unused.js': `require('child_process')`,
    }, { main: 'index.js' })

    expect(result.filesAnalysed).toEqual(['package/index.js'])
    expect(result.reachable).toEqual([])
  })

  it('a cycle between two files terminates', () => {
    const result = pkg({
      'package/index.js': `require('./a.js')`,
      'package/a.js': `require('./b.js'); require('fs')`,
      'package/b.js': `require('./a.js')`,
    }, { main: 'index.js' })

    expect(result.filesAnalysed.sort()).toEqual(['package/a.js', 'package/b.js', 'package/index.js'])
    expect(result.reachable.map(r => r.module)).toEqual(['fs'])
  })

  it('the lost points carry the file they were lost in', () => {
    const result = pkg({
      'package/index.js': `require('./x.js')`,
      'package/x.js': `require(process.argv[2])`,
    }, { main: 'index.js' })

    expect(result.lost).toHaveLength(1)
    expect(result.lost[0]!.file).toBe('package/x.js')
    expect(result.lost[0]!.reason).toBe('dynamic-specifier')
  })
})

/**
 * The two failures a corpus pass found that no hand-written case had provoked.
 * Both are about scale rather than about JavaScript, and both took the pass
 * down rather than producing a wrong answer — which is the better failure, and
 * still a failure.
 */
describe('shapes that broke the corpus pass', () => {
  // `origins.push(...v.origins)` becomes one argument per element. An array of a
  // hundred thousand origins is a call with a hundred thousand arguments, and
  // the pass died with `Maximum call stack size exceeded` inside merge().
  it('a file that assigns to one name thousands of times does not overflow the stack', () => {
    const src = `let m; ` + Array.from({ length: 20_000 }, (_, i) =>
      `m = require('mod${i % 40}')`).join('; ')

    expect(() => analyzeModuleSource(src)).not.toThrow()
    const result = analyzeModuleSource(src)
    expect(result.origins.length).toBeGreaterThan(0)
    // 40 distinct modules, however many statements name them.
    expect(new Set(result.origins.map(o => o.module)).size).toBe(40)
  })

  it('a deeply chained expression does not overflow the evaluator', () => {
    const src = `const fs = require('fs'); fs` + '.a'.repeat(2_000)
    expect(() => analyzeModuleSource(src)).not.toThrow()
    expect(analyzeModuleSource(src).origins.some(o => o.module === 'fs')).toBe(true)
  })

  it('a very long member chain still names the module it started at', () => {
    const src = `const x = require('fs').a.b.c.d.e.f.g`
    const origins = analyzeModuleSource(src).origins.filter(o => o.module === 'fs')
    expect(origins.some(o => o.path.join('.') === 'a.b.c.d.e.f.g')).toBe(true)
  })

  // The half of merge() the dedup was never applied to. `lost` was appended on
  // every union, so a value that loses its trail once and then flows through a
  // chain of calls carried a copy per route, and the copies compounded.
  //
  // On @async23/chrome-devtools-mcp@1.7.0 that turned 14,853 emitted lost points
  // into 35,110,656 array entries and killed the pass with "Ineffective
  // mark-compacts near heap limit". This is the same shape at 763 bytes: before
  // the fix it returned 324 entries of 22 distinct points.
  it('records a lost point once however many routes reach it', () => {
    const lines = ['const dyn = process.argv[2]', 'const a = require(dyn)']
    for (let i = 0; i < 20; i++) lines.push(`function f${i}(x) { return f${i + 1}(x) }`)
    lines.push('function f20(x) { return x }', 'module.exports = f0(a)')

    const result = analyzeModuleSource(lines.join('\n'), { file: 's.js' })
    const keys = new Set(result.lost.map(p => `${p.reason}|${p.file}|${p.line}|${p.detail}`))

    expect(result.lost.length).toBe(keys.size)
    expect(result.lost.length).toBeLessThan(50)
  })

  it('bounds the list even when every lost point is genuinely distinct', () => {
    // One computed member per line, each on its own line, so no two of them
    // share a key and the dedup cannot be what holds the number down.
    const src = ['const dyn = process.argv[2]', 'const a = require(dyn)']
      .concat(Array.from({ length: 3_000 }, (_, i) => `const v${i} = a[k${i}]`))
      .join('\n')

    const result = analyzeModuleSource(src, { file: 's.js' })
    expect(result.lost.length).toBeLessThanOrEqual(MAX_MODULE_LOST)
    // And it still answers the question it exists to answer.
    expect(result.lost.some(p => p.reason === 'computed-member')).toBe(true)
  })
})
