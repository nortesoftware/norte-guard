// Where a value came from, and where it went.
//
// In Node there are exactly three doors a capability can walk through:
//
//     require(...)      import(...)      process.binding(...)
//
// There is no fourth. Every alias, every assembled name, every indirection and
// every obfuscation eventually hands back a value that was born at one of those
// three, because there is nowhere else for it to have come from. So this does
// not search for text — `grep readFileSync` is defeated by one rename — it finds
// the ORIGIN of a value and follows it.
//
// It answers one question: **can this code reach X?** It does not answer whether
// reaching X is dangerous. That is A3, and A3 needs confirmed samples this
// project does not have yet: two with bytes, not eight. Deciding what is
// malicious on n=2 would be a preference wearing a measurement's clothes.
//
// Where the trail is lost, it is recorded as lost. Never as absent, and never as
// a pass — that is the discipline A4 exists to enforce and this module inherits
// it: a route nobody could follow is not a route that goes nowhere.
//
// One deliberate difference from A4, and it is not an inconsistency. A4 marks
// `require("f" + "s")` as `dynamic-require`, because the question there is
// whether a parser can bound what the file does, and an assembled specifier is
// exactly the shape obfuscation takes. Here the question is whether the code can
// reach `fs`, and it demonstrably can: the concatenation folds, the answer is
// knowable, and reporting it as lost would be a false negative in the one
// direction this phase must not have. Both are true about the same line.

import { parse } from 'acorn'

// A4's walker is a stack and visits nodes in whatever order they pop, which is
// correct there: it counts nodes and finds calls, and neither depends on order.
// Here it is wrong. `const fs = require('fs'); const r = fs.readFileSync` is two
// statements and the second only resolves if the first has already run, so this
// walker keeps source order — children are pushed reversed so they pop in the
// order they were written. Still iterative: a minified bundle nests deeply
// enough to overflow a recursive one, and that is the input this will see.
interface WalkNode { type: string; [key: string]: unknown }

const SKIP_KEYS = new Set(['type', 'start', 'end', 'loc', 'range'])

function walkOrdered(root: unknown, visit: (node: WalkNode) => void): void {
  const stack: unknown[] = [root]

  while (stack.length > 0) {
    const current = stack.pop()
    if (!current || typeof current !== 'object') continue

    if (Array.isArray(current)) {
      for (let i = current.length - 1; i >= 0; i--) stack.push(current[i])
      continue
    }

    const node = current as WalkNode
    if (typeof node.type === 'string') visit(node)

    const children: unknown[] = []
    for (const key of Object.keys(node)) {
      if (SKIP_KEYS.has(key)) continue
      const value = node[key]
      if (value && typeof value === 'object') children.push(value)
    }
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i])
  }
}

export type Gate = 'require' | 'import' | 'process.binding'

// How far a value travelled from its gate, in the order it travelled. Printed as
// the route, because "reaches fs" and "reaches fs through three renames and a
// property write" are the same fact and very different reading.
export type RouteStep =
  | 'gate'
  | 'binding'
  | 'destructuring'
  | 'rename'
  | 'argument'
  | 'return'
  | 'property'
  | 'member'
  | 'computed-member'
  | 'reexport'

export interface Origin {
  gate: Gate
  // The specifier, when it could be established. Null is not "no module": it is
  // a module this analysis could not name, and it always travels with a lost
  // point saying why.
  module: string | null
  // The member path taken off the gate value. `require('fs').promises.readFile`
  // is ['promises', 'readFile']. A '*' element is a member this analysis could
  // not name, which does not stop the module itself from being reached.
  path: string[]
  route: RouteStep[]
}

export type LostReason =
  | 'dynamic-specifier'
  | 'dynamic-eval'
  | 'computed-member'
  | 'unresolved-callee'
  | 'depth-limit'
  | 'unresolved-import'

export interface LostPoint {
  reason: LostReason
  detail: string
  // Where in the file, when the parser gave it to us.
  line: number | null
  file?: string
}

// A value in flight. Both halves matter: `origins` is what it is known to carry,
// `lost` is where following it stopped. A value with origins AND lost points is
// the normal case for real code, and collapsing either into the other is how an
// analysis starts lying.
export interface Value {
  origins: Origin[]
  lost: LostPoint[]
}

const EMPTY: Value = { origins: [], lost: [] }

// One value cannot carry more than this many distinct origins. Reached only by
// code that assigns to the same name thousands of times, which is what a
// minified bundle looks like, and the cap is what stops the union below from
// growing quadratically through it.
const MAX_ORIGINS_PER_VALUE = 64

// Deduplicating, and never spreading.
//
// `origins.push(...v.origins)` is the obvious way to write this and it took the
// corpus pass down with `Maximum call stack size exceeded`: a spread becomes one
// argument per element, and an array of a hundred thousand origins is a call
// with a hundred thousand arguments. The dedup is the other half — `Scope.set`
// unions on every write, so without it a name assigned in a loop accumulates one
// origin per iteration and the union goes quadratic.
function originKey(o: Origin): string {
  return `${o.gate}|${o.module ?? '?'}|${o.path.join('.')}|${o.route.join('>')}`
}

// The same treatment for the other half of a Value, for the same reason, found
// the same way: the corpus pass died on it.
//
// The comment above was written about `origins` and the fix was applied to
// `origins` only. `lost` kept the shape the origins had before it: appended
// without dedup and without a cap, on every union. A value carrying L lost
// points that is merged N times along a chain of assignments and calls copies
// L into a new array N times, and the copies compound.
//
// Measured on @async23/chrome-devtools-mcp@1.7.0, whose 7.4MB bundle is a
// combinator library — the same values flow through thousands of call sites:
//
//   14,853 lost points were emitted, of 3,744 distinct (reason, line) pairs
//   35,110,656 were in the array at the end — every one duplicated ~2,364 times
//   210,699 merges copied 125,721,046 entries between them, one of them 2.27M
//
// That is what took the process down with "Ineffective mark-compacts near heap
// limit": not the syntax tree, which is 213MB for that file, and not the tar,
// which is 13MB. Deduplication is lossless here — two lost points with the same
// reason, file, line and detail are the same fact recorded twice — and the cap
// bounds the adversarial case where they are all genuinely distinct.
function lostKey(l: LostPoint): string {
  return `${l.reason}|${l.file ?? ''}|${l.line ?? ''}|${l.detail}`
}

const MAX_LOST_PER_VALUE = 64

function merge(...values: Value[]): Value {
  const byKey = new Map<string, Origin>()
  const lostByKey = new Map<string, LostPoint>()

  for (const v of values) {
    for (const o of v.origins) {
      if (byKey.size >= MAX_ORIGINS_PER_VALUE) break
      byKey.set(originKey(o), o)
    }
    for (const l of v.lost) {
      if (lostByKey.size >= MAX_LOST_PER_VALUE) break
      lostByKey.set(lostKey(l), l)
    }
  }

  return { origins: [...byKey.values()], lost: [...lostByKey.values()] }
}

// A binding is a name and what it holds. Scopes chain to their parent, so a
// module-level `const fs = require('fs')` is visible inside every function that
// does not shadow it — which is how nearly all real code reaches anything.
class Scope {
  private readonly names = new Map<string, Value>()

  constructor(private readonly parent: Scope | null = null) {}

  set(name: string, value: Value): void {
    // Re-assignment unions rather than replaces. Following only the last write
    // would let `let m = require('fs'); m = require('path')` hide the first, and
    // a reachability answer that depends on statement order is not an answer.
    const existing = this.names.get(name)
    this.names.set(name, existing ? merge(existing, value) : value)
  }

  get(name: string): Value | undefined {
    return this.names.get(name) ?? this.parent?.get(name)
  }

  child(): Scope {
    return new Scope(this)
  }
}

interface AstNode { type: string; loc?: { start?: { line?: number } }; [key: string]: unknown }

function lineOf(node: unknown): number | null {
  const n = node as AstNode | undefined
  return n?.loc?.start?.line ?? null
}

// ---------------------------------------------------------------------------
// Static strings
// ---------------------------------------------------------------------------

// A specifier the analysis can read off the page, following constant bindings.
//
// Folding `"f" + "s"` is not a courtesy to the author, it is the only honest
// answer: the code reaches `fs` and a reader can see that it does. The same
// applies to a name bound to a literal and never reassigned. What does not fold
// is anything whose value is decided at runtime, and that is exactly what gets
// recorded as lost.
export function staticString(node: unknown, scope: Scope, strings: Map<string, string | null>): string | null {
  if (!node || typeof node !== 'object') return null
  const n = node as AstNode

  if (n.type === 'Literal') return typeof n.value === 'string' ? n.value : null

  if (n.type === 'TemplateLiteral') {
    const expressions = (n.expressions ?? []) as unknown[]
    const quasis = (n.quasis ?? []) as Array<{ value?: { cooked?: string } }>
    if (expressions.length === 0) return quasis.map(q => q.value?.cooked ?? '').join('')
    // A template with a runtime hole: the prefix is readable and the target is
    // not, so the whole specifier is not resolvable.
    return null
  }

  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const left = staticString(n.left, scope, strings)
    const right = staticString(n.right, scope, strings)
    return left !== null && right !== null ? left + right : null
  }

  if (n.type === 'Identifier' && typeof n.name === 'string') {
    // Only names bound exactly once to a literal string. A name written twice is
    // not a constant and must not be folded as one.
    return strings.get(n.name) ?? null
  }

  return null
}

// ---------------------------------------------------------------------------
// One module
// ---------------------------------------------------------------------------

export interface ModuleAnalysis {
  // Every specifier the module reaches, with how it got there.
  origins: Origin[]
  lost: LostPoint[]
  // What the module hands out, so a caller following a relative require can keep
  // going through it.
  exports: Value
}

export interface AnalyzeOptions {
  // How deep to follow calls into locally declared functions. Recursion is
  // bounded rather than detected: a cycle is not the only way to go deep, and a
  // budget is the only thing that bounds both.
  maxCallDepth?: number
  file?: string
}

const DEFAULT_CALL_DEPTH = 6

// Origins held for one module before it stops collecting. Well above what any
// honest file produces and far below what a minified bundle will.
// Distinct facts, not occurrences. The first version kept an array and
// deduplicated on the way out, with a cap of 20,000 per module — which multiplied
// by the 400 files a package graph will walk is millions of live objects, each
// holding two arrays, and the pass died with a real V8 heap OOM. Keyed at the
// point of record, the cost is the number of distinct things reached, which is
// small in every package that is not trying to be large.
const MAX_MODULE_ORIGINS = 2_000

// Member path elements kept. `fs.a.b.c` says what it needs to in a few links,
// and a bundle writes chains two thousand long: every link copies the path
// array, so an unbounded path makes one expression quadratic in its own length.
const MAX_PATH_DEPTH = 12

// Function bodies re-walked per module before the analysis gives up.
//
// `callLocal` walks the callee's body at every call site, and the walk finds
// more calls, which walk more bodies. Six frames of that with any branching is
// exponential, and it is not a theoretical worry: `@siwatfa/yorn` has TWO
// JavaScript files and allocated 1,415MB on its own before this bound existed.
// Nothing memoises, because a body's result depends on the arguments bound into
// it; what is bounded instead is how many times any body may be entered.
const MAX_BODY_WALKS = 300

export function analyzeModuleSource(
  source: string,
  options: AnalyzeOptions = {}
): ModuleAnalysis {
  let ast: unknown
  try {
    ast = parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
    })
  } catch {
    try {
      ast = parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowSuperOutsideMethod: true,
      })
    } catch (e) {
      // A file nobody parsed reaches everything and nothing. A4 already owns the
      // question of why; here it is one lost point covering the whole file.
      return {
        origins: [],
        lost: [{
          reason: 'unresolved-import',
          detail: `file did not parse: ${e instanceof Error ? e.message : String(e)}`,
          line: null,
          file: options.file,
        }],
        exports: EMPTY,
      }
    }
  }

  return new ModuleAnalyzer(ast, options).run()
}

// The module's own list, bounded the same way its origins are. A file that
// really does lose the trail in two thousand distinct places has been described
// well enough by the first two thousand, and nothing downstream reads more than
// a count and the first few.
export const MAX_MODULE_LOST = 2_000

class ModuleAnalyzer {
  private readonly originsByKey = new Map<string, Origin>()
  // Keyed, not appended: the same lost point arrives once per route that reaches
  // it, and every route through a combinator library reaches all of them.
  private readonly lostByKey = new Map<string, LostPoint>()
  private readonly functions = new Map<string, AstNode>()
  private readonly handledMembers = new WeakSet<AstNode>()
  private bodyWalks = 0
  private readonly strings = new Map<string, string | null>()
  private exported: Value = EMPTY
  private readonly file?: string
  private readonly maxDepth: number

  constructor(private readonly ast: unknown, options: AnalyzeOptions) {
    this.file = options.file
    this.maxDepth = options.maxCallDepth ?? DEFAULT_CALL_DEPTH
  }

  run(): ModuleAnalysis {
    // Two sweeps. The first collects what the second needs to already know:
    // function declarations are hoisted, and a constant string can be used
    // before the line that defines it inside a function body.
    this.collectDeclarations()

    const scope = new Scope()
    this.walkStatements(this.ast, scope, 0)

    // Deduplicated at the point of record rather than here, so the map above is
    // already the answer. Exact duplicates only: `function g() { return
    // require('fs') }` reaches fs at the gate AND through a return, and
    // collapsing those by (gate, module, path) would throw away the second half
    // of the question. The route is part of the fact.
    return {
      origins: [...this.originsByKey.values()],
      lost: [...this.lostByKey.values()],
      exports: this.exported,
    }
  }

  private collectDeclarations(): void {
    // Writes are counted first and constancy decided afterwards. Deciding it
    // while walking made the answer depend on the order the walker happened to
    // reach the nodes in: `let m = 'fs'; m = compute(); require(m)` folded to
    // 'fs' whenever the assignment was visited before the declaration.
    const writes = new Map<string, number>()
    const literal = new Map<string, string>()

    walkOrdered(this.ast, node => {
      const n = node as AstNode

      if (n.type === 'FunctionDeclaration' && (n.id as AstNode | undefined)?.name) {
        this.functions.set(String((n.id as AstNode).name), n)
      }

      if (n.type === 'VariableDeclarator') {
        const id = n.id as AstNode | undefined
        const init = n.init as AstNode | undefined
        if (id?.type === 'Identifier' && typeof id.name === 'string') {
          const name = id.name
          writes.set(name, (writes.get(name) ?? 0) + 1)
          if (init?.type === 'FunctionExpression' || init?.type === 'ArrowFunctionExpression') {
            this.functions.set(name, init)
          }
          if (init?.type === 'Literal' && typeof init.value === 'string') {
            literal.set(name, init.value)
          }
        }
      }

      if (n.type === 'AssignmentExpression') {
        const left = n.left as AstNode | undefined
        if (left?.type === 'Identifier' && typeof left.name === 'string') {
          writes.set(left.name, (writes.get(left.name) ?? 0) + 1)
        }
      }

      // A parameter is a write nobody can see the value of.
      if (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' ||
          n.type === 'ArrowFunctionExpression') {
        for (const param of (n.params ?? []) as AstNode[]) {
          if (param?.type === 'Identifier' && typeof param.name === 'string') {
            writes.set(param.name, (writes.get(param.name) ?? 0) + 1)
          }
        }
      }
    })

    for (const [name, value] of literal) {
      if (writes.get(name) === 1) this.strings.set(name, value)
    }
  }

  private record(origin: Origin): void {
    if (this.originsByKey.size >= MAX_MODULE_ORIGINS) return
    this.originsByKey.set(originKey(origin), origin)
  }

  private lose(reason: LostReason, detail: string, node: unknown): void {
    this.noteLost({ reason, detail, line: lineOf(node), file: this.file })
  }

  // Every route into the module's list goes through here, so the bound holds
  // whether a point was raised here or arrived on a value from somewhere else.
  private noteLost(point: LostPoint): void {
    if (this.lostByKey.size >= MAX_MODULE_LOST) return
    this.lostByKey.set(lostKey(point), point)
  }

  // -------------------------------------------------------------------------

  private walkStatements(root: unknown, scope: Scope, depth: number): void {
    walkOrdered(root, node => {
      const n = node as AstNode

      switch (n.type) {
        case 'VariableDeclarator':
          this.bindPattern(n.id, this.evaluate(n.init, scope, depth), scope, depth)
          break

        case 'AssignmentExpression': {
          const value = this.evaluate(n.right, scope, depth)
          const left = n.left as AstNode | undefined
          if (left?.type === 'Identifier' && typeof left.name === 'string') {
            scope.set(left.name, this.step(value, 'binding'))
          } else if (left?.type === 'MemberExpression') {
            // obj.fs = require('fs'). The value is live from here whatever the
            // object is; tracking which object holds it is a heap analysis and
            // this phase does not have one, so the origin is kept and the
            // container is not.
            this.absorb(this.step(value, 'property'))
            this.noteExportTarget(left, value)
          } else if (left) {
            this.bindPattern(left, value, scope, depth)
          }
          break
        }

        case 'ImportDeclaration': {
          const specifier = (n.source as AstNode | undefined)?.value
          const module = typeof specifier === 'string' ? specifier : null
          if (module === null) this.lose('unresolved-import', 'import with no readable specifier', n)

          for (const raw of (n.specifiers ?? []) as AstNode[]) {
            const local = (raw.local as AstNode | undefined)?.name
            const imported = (raw.imported as AstNode | undefined)?.name
            const path = raw.type === 'ImportDefaultSpecifier' ? ['default']
                       : raw.type === 'ImportNamespaceSpecifier' ? []
                       : typeof imported === 'string' ? [imported] : []
            const origin: Origin = {
              gate: 'import', module, path,
              route: ['gate', raw.type === 'ImportSpecifier' ? 'destructuring' : 'binding'],
            }
            this.record(origin)
            if (typeof local === 'string') scope.set(local, { origins: [origin], lost: [] })
          }
          // A bare `import 'x'` has no specifiers and still reaches x.
          if (((n.specifiers ?? []) as unknown[]).length === 0) {
            this.record({ gate: 'import', module, path: [], route: ['gate'] })
          }
          break
        }

        case 'ExportNamedDeclaration':
        case 'ExportDefaultDeclaration': {
          const declaration = n.declaration as AstNode | undefined
          if (declaration && declaration.type !== 'VariableDeclaration' &&
              declaration.type !== 'FunctionDeclaration' && declaration.type !== 'ClassDeclaration') {
            this.exported = merge(this.exported, this.step(this.evaluate(declaration, scope, depth), 'reexport'))
          }
          break
        }

        default:
          break
      }

      // Gate calls anywhere, including inside expressions nothing binds:
      // `f(require('fs'))` reaches fs whether or not f does anything with it.
      if (n.type === 'CallExpression' || n.type === 'ImportExpression' || n.type === 'NewExpression') {
        this.absorb(this.evaluateCall(n, scope, depth))
      }

      // `fs[pick()]` on its own line binds nothing and still reaches fs. Without
      // this the analysis only followed members that something assigned.
      if (n.type === 'MemberExpression' && !this.handledMembers.has(n)) {
        this.evaluate(n, scope, depth)
      }
    })
  }

  // module.exports = x / exports.y = x, so a relative require can follow through.
  private noteExportTarget(member: AstNode, value: Value): void {
    const object = member.object as AstNode | undefined
    const property = member.property as AstNode | undefined
    const objectName = object?.type === 'Identifier' ? String(object.name) : null
    const propertyName = property?.type === 'Identifier' ? String(property.name) : null

    if (objectName === 'exports' || (objectName === 'module' && propertyName === 'exports')) {
      this.exported = merge(this.exported, this.step(value, 'reexport'))
    }
  }

  private absorb(value: Value): void {
    for (const o of value.origins) this.record(o)
    for (const l of value.lost) this.noteLost(l)
  }

  // A value that gained a member is a new fact about what is reached, and it has
  // to be reported and not only bound. Origins derived by member access lived in
  // the scope and never in the answer, so `const { readFileSync } = require('fs')`
  // reported reaching fs and nothing about which part of it.
  private derive(value: Value, member: string, route: RouteStep): Value {
    const origins: Origin[] = value.origins.map(o => ({
      ...o,
      path: o.path.length >= MAX_PATH_DEPTH ? o.path : [...o.path, member],
      route: o.route.length >= MAX_PATH_DEPTH ? o.route : [...o.route, route],
    }))
    for (const o of origins) this.record(o)
    return { origins, lost: value.lost }
  }

  private step(value: Value, route: RouteStep): Value {
    return {
      origins: value.origins.map(o => ({ ...o, route: [...o.route, route] })),
      lost: value.lost,
    }
  }

  // -------------------------------------------------------------------------

  private bindPattern(pattern: unknown, value: Value, scope: Scope, depth: number): void {
    const p = pattern as AstNode | undefined
    if (!p) return

    if (p.type === 'Identifier' && typeof p.name === 'string') {
      scope.set(p.name, this.step(value, 'binding'))
      return
    }

    // const { readFileSync } = require('fs')  — and the renaming form
    // const { readFileSync: rf } = require('fs'), which is the same edge.
    if (p.type === 'ObjectPattern') {
      for (const raw of (p.properties ?? []) as AstNode[]) {
        if (raw.type === 'RestElement') {
          this.bindPattern(raw.argument, this.step(value, 'destructuring'), scope, depth)
          continue
        }
        const key = raw.key as AstNode | undefined
        const name = key?.type === 'Identifier' ? String(key.name)
                   : key?.type === 'Literal' && typeof key.value === 'string' ? key.value
                   : null

        const member: Value = name === null
          ? this.opaqueMember(value, raw)
          : this.derive(value, name, 'destructuring')

        this.bindPattern(raw.value, member, scope, depth)
      }
      return
    }

    if (p.type === 'ArrayPattern') {
      for (const element of (p.elements ?? []) as unknown[]) {
        if (element) this.bindPattern(element, this.step(value, 'destructuring'), scope, depth)
      }
      return
    }

    if (p.type === 'AssignmentPattern') {
      this.bindPattern(p.left, value, scope, depth)
      return
    }
  }

  private opaqueMember(value: Value, node: unknown): Value {
    // Only when there is something to lose. `process.argv[2]` is a computed
    // member on a value that carries no capability, and reporting it as a lost
    // trail would fill the output with places the analysis was never following
    // anything — which is how a lost-points list stops being read.
    if (value.origins.length === 0) return value

    this.lose('computed-member', 'member name is decided at runtime', node)
    const origins: Origin[] = value.origins.map(o => ({
      ...o, path: [...o.path, '*'], route: [...o.route, 'computed-member' as RouteStep],
    }))
    for (const o of origins) this.record(o)
    return { origins, lost: value.lost }
  }

  // -------------------------------------------------------------------------

  private evaluate(node: unknown, scope: Scope, depth: number): Value {
    if (!node || typeof node !== 'object') return EMPTY
    const n = node as AstNode

    switch (n.type) {
      case 'Identifier':
        return typeof n.name === 'string' ? scope.get(n.name) ?? EMPTY : EMPTY

      case 'CallExpression':
      case 'NewExpression':
      case 'ImportExpression':
        return this.evaluateCall(n, scope, depth)

      case 'MemberExpression':
        return this.evaluateMemberChain(n, scope, depth)

      case 'AwaitExpression':
      case 'TSNonNullExpression':
        return this.evaluate(n.argument ?? n.expression, scope, depth)

      case 'ParenthesizedExpression':
        return this.evaluate(n.expression, scope, depth)

      case 'ConditionalExpression':
        // Both branches: which one runs is a runtime fact and reachability is
        // about what CAN be reached.
        return merge(
          this.evaluate(n.consequent, scope, depth),
          this.evaluate(n.alternate, scope, depth)
        )

      case 'LogicalExpression':
        return merge(this.evaluate(n.left, scope, depth), this.evaluate(n.right, scope, depth))

      case 'SequenceExpression': {
        const parts = (n.expressions ?? []) as unknown[]
        return this.evaluate(parts[parts.length - 1], scope, depth)
      }

      case 'AssignmentExpression':
        return this.evaluate(n.right, scope, depth)

      case 'ObjectExpression': {
        // The object itself carries whatever its values carry: `const o = { fs:
        // require('fs') }` puts fs one property away, and `o.fs` finds it.
        let value = EMPTY
        for (const raw of (n.properties ?? []) as AstNode[]) {
          value = merge(value, this.step(this.evaluate(raw.value ?? raw.argument, scope, depth), 'property'))
        }
        return value
      }

      case 'ArrayExpression': {
        let value = EMPTY
        for (const element of (n.elements ?? []) as unknown[]) {
          value = merge(value, this.evaluate(element, scope, depth))
        }
        return value
      }

      default:
        return EMPTY
    }
  }

  // `a.b.c.d` nests to the left, so evaluating it by recursing into `object`
  // costs one frame per link. A minified bundle writes chains thousands of links
  // long and the corpus pass died on one: the chain is walked down to its base
  // iteratively, then the properties are applied on the way back up.
  private evaluateMemberChain(node: AstNode, scope: Scope, depth: number): Value {
    const chain: AstNode[] = []
    let current: AstNode = node

    while (current.type === 'MemberExpression') {
      chain.push(current)
      // Every link is marked as handled by this one pass. The statement walker
      // visits each of them too, and evaluating the chain again from each link
      // makes one expression cubic in its own length: the pass spent thirty
      // seconds on a single line before this.
      this.handledMembers.add(current)
      const next = current.object as AstNode | undefined
      if (!next) break
      current = next
    }

    let value = this.evaluate(current, scope, depth)
    for (let i = chain.length - 1; i >= 0; i--) {
      value = this.applyMember(chain[i]!, value, scope)
    }
    return value
  }

  private applyMember(n: AstNode, object: Value, scope: Scope): Value {
    const property = n.property as AstNode | undefined

    if (!n.computed && property?.type === 'Identifier' && typeof property.name === 'string') {
      return this.derive(object, String(property.name), 'member')
    }

    // fs['read' + 'FileSync'] — the concatenation folds, and the member is as
    // known as if it had been written out. This is the case the phase brief
    // names, and it is the difference between following obfuscation and being
    // stopped by it.
    const folded = staticString(property, scope, this.strings)
    if (folded !== null) return this.derive(object, folded, 'computed-member')

    return this.opaqueMember(object, n)
  }

  private evaluateCall(n: AstNode, scope: Scope, depth: number): Value {
    const args = (n.arguments ?? []) as unknown[]

    // Arguments are evaluated whatever the callee turns out to be: the gate call
    // inside f(require('fs')) has already happened.
    let fromArguments = EMPTY
    for (const arg of args) fromArguments = merge(fromArguments, this.evaluate(arg, scope, depth))

    if (n.type === 'ImportExpression') {
      const module = staticString(n.source, scope, this.strings)
      if (module === null) {
        this.lose('dynamic-specifier', 'import() of an expression decided at runtime', n)
      }
      const origin: Origin = { gate: 'import', module, path: [], route: ['gate'] }
      this.record(origin)
      return merge(fromArguments, { origins: [origin], lost: [] })
    }

    const gate = this.gateOf(n.callee, scope)

    if (gate === 'require' || gate === 'import') {
      const module = staticString(args[0], scope, this.strings)
      if (module === null) {
        this.lose('dynamic-specifier', `${gate}() of an expression decided at runtime`, n)
      }
      const origin: Origin = { gate, module, path: [], route: ['gate'] }
      this.record(origin)
      return merge(fromArguments, { origins: [origin], lost: [] })
    }

    if (gate === 'process.binding') {
      const module = staticString(args[0], scope, this.strings)
      if (module === null) {
        this.lose('dynamic-specifier', 'process.binding() of an expression decided at runtime', n)
      }
      const origin: Origin = { gate: 'process.binding', module, path: [], route: ['gate'] }
      this.record(origin)
      return merge(fromArguments, { origins: [origin], lost: [] })
    }

    // eval and the Function constructor: a door this analysis cannot walk
    // through. Recorded, never skipped — code behind an eval is code nobody
    // read, and A4 is where that lands.
    const calleeName = this.calleeName(n.callee)
    if (calleeName === 'eval' || calleeName === 'Function') {
      const literal = staticString(args[args.length - 1], scope, this.strings)
      if (literal === null) {
        this.lose('dynamic-eval', `${calleeName}() over a body built at runtime`, n)
        return merge(fromArguments, { origins: [], lost: [] })
      }
      // A literal body can be analysed: it is source, and there is a parser here.
      const inner = analyzeModuleSource(literal, { file: this.file, maxCallDepth: this.maxDepth })
      for (const o of inner.origins) this.record({ ...o, route: [...o.route, 'argument'] })
      for (const l of inner.lost) this.noteLost(l)
      return merge(fromArguments, { origins: inner.origins, lost: inner.lost })
    }

    // A call into a function declared here: bind the parameters and read what it
    // returns. This is what makes `function g() { return require('fs') }` and
    // `f(require('fs'))` different from text matching.
    if (calleeName && this.functions.has(calleeName)) {
      if (depth >= this.maxDepth) {
        this.lose('depth-limit', `call to ${calleeName}() past ${this.maxDepth} frames`, n)
        return fromArguments
      }
      return merge(fromArguments, this.callLocal(this.functions.get(calleeName)!, args, scope, depth))
    }

    // Calling the result of something we followed: `const r = fs.readFileSync;
    // r(path)` returns whatever it returns, which we do not model. The callee's
    // own origins still count — the capability was reached to call it.
    const callee = this.evaluate(n.callee, scope, depth)
    if (callee.origins.length === 0 && calleeName === null && n.callee) {
      const c = n.callee as AstNode
      if (c.type !== 'Identifier' && c.type !== 'MemberExpression') {
        this.lose('unresolved-callee', `call to a ${c.type} this analysis does not follow`, n)
      }
    }

    return merge(fromArguments, callee)
  }

  private callLocal(fn: AstNode, args: unknown[], scope: Scope, depth: number): Value {
    if (this.bodyWalks >= MAX_BODY_WALKS) {
      this.lose('depth-limit', `stopped after ${MAX_BODY_WALKS} function bodies`, fn)
      return EMPTY
    }
    this.bodyWalks++

    const inner = scope.child()
    const params = (fn.params ?? []) as unknown[]

    params.forEach((param, i) => {
      this.bindPattern(param, this.step(this.evaluate(args[i], scope, depth), 'argument'), inner, depth + 1)
    })

    const body = fn.body as AstNode | undefined
    if (!body) return EMPTY

    // An arrow with an expression body returns it directly.
    if (body.type !== 'BlockStatement') {
      const value = this.evaluate(body, inner, depth + 1)
      this.walkStatements(body, inner, depth + 1)
      return this.step(value, 'return')
    }

    this.walkStatements(body, inner, depth + 1)

    let returned = EMPTY
    walkOrdered(body, node => {
      const n = node as AstNode
      if (n.type === 'ReturnStatement' && n.argument) {
        returned = merge(returned, this.evaluate(n.argument, inner, depth + 1))
      }
    })

    return this.step(returned, 'return')
  }

  // The three doors, and every way of naming them that still resolves to one.
  private gateOf(callee: unknown, scope: Scope): Gate | null {
    const name = this.calleeName(callee)
    if (name === 'require') return 'require'
    if (name === 'import') return 'import'

    const c = callee as AstNode | undefined
    if (c?.type === 'MemberExpression') {
      const object = c.object as AstNode | undefined
      const property = c.property as AstNode | undefined
      const objectName = object?.type === 'Identifier' ? String(object.name) : null
      const propertyName = !c.computed && property?.type === 'Identifier'
        ? String(property.name)
        : staticString(property, scope, this.strings)

      if (objectName === 'process' && propertyName === 'binding') return 'process.binding'
      // require.resolve and module.require are the same door.
      if (objectName === 'require' && propertyName === 'resolve') return 'require'
      if (objectName === 'module' && propertyName === 'require') return 'require'
    }

    return null
  }

  // Reads through the shapes that exist only to hide a name: (0, require)(...),
  // (require)(...), and a sequence whose last element is the callee.
  private calleeName(callee: unknown): string | null {
    if (!callee || typeof callee !== 'object') return null
    const c = callee as AstNode

    if (c.type === 'Identifier') return typeof c.name === 'string' ? c.name : null
    if (c.type === 'ParenthesizedExpression') return this.calleeName(c.expression)
    if (c.type === 'SequenceExpression') {
      const parts = (c.expressions ?? []) as unknown[]
      return this.calleeName(parts[parts.length - 1])
    }
    return null
  }
}

// ---------------------------------------------------------------------------
// One package
// ---------------------------------------------------------------------------

export interface ReachableModule {
  module: string
  gates: Gate[]
  // The shortest route found to it. A module reached three ways is reached; the
  // shortest is what a reader needs to check the claim.
  route: RouteStep[]
  // Member paths taken off it, deduplicated. '*' is a member this analysis could
  // not name.
  paths: string[][]
  // Files it is reached from, so "por qué ruta" has a place to start.
  files: string[]
}

export interface PackageReachability {
  entryPoints: string[]
  // Entry points package.json declares that are not in the tarball.
  missingEntryPoints: string[]
  filesAnalysed: string[]
  reachable: ReachableModule[]
  // Relative specifiers that could not be resolved to a file in the package.
  // Kept apart from `lost`: an unresolved local file is a packaging fact, and a
  // lost trail is an analysis limit.
  unresolvedLocal: string[]
  lost: LostPoint[]
}

const ENTRY_EXTENSIONS = ['', '.js', '.mjs', '.cjs', '.json', '/index.js', '/index.mjs', '/index.cjs']

// Every string a package.json points at that Node could load. Deliberately
// generous: an entry point nobody analysed is a file whose reachable set is
// missing from the answer, and this phase would rather analyse one file too many
// than miss the one the attacker put in `bin`.
export function declaredEntryPoints(packageJson: unknown): string[] {
  const pkg = (packageJson ?? {}) as Record<string, unknown>
  const found: string[] = []

  const take = (value: unknown): void => {
    if (typeof value === 'string') { found.push(value); return }
    if (Array.isArray(value)) { for (const v of value) take(v); return }
    if (value && typeof value === 'object') {
      for (const v of Object.values(value as Record<string, unknown>)) take(v)
    }
  }

  take(pkg['main'])
  take(pkg['module'])
  take(pkg['exports'])
  take(pkg['bin'])
  // An install script names a file that runs before anything imports anything.
  const scripts = pkg['scripts']
  if (scripts && typeof scripts === 'object') {
    for (const [name, command] of Object.entries(scripts as Record<string, unknown>)) {
      if (!/^(pre|post)?install$|^prepare$/.test(name)) continue
      if (typeof command !== 'string') continue
      for (const token of command.split(/\s+/)) {
        if (/\.(c|m)?js$/.test(token)) found.push(token)
      }
    }
  }

  if (found.length === 0) found.push('index.js')

  // `exports` also names type declarations and, by convention, the package.json
  // itself. Node loads neither for behaviour, so following them reaches nothing
  // — and reporting them as declared-but-absent was worse than useless: they are
  // in the tarball, they are just not code.
  const executable = (f: string) =>
    !f.includes('*') &&
    !/\.d\.[cm]?ts$/.test(f) &&
    !/(^|\/)package\.json$/.test(f) &&
    !/\.(json|css|wasm|node)$/.test(f)

  return [...new Set(found.filter(executable))]
}

function normalise(path: string): string {
  const parts: string[] = []
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') { parts.pop(); continue }
    parts.push(segment)
  }
  return parts.join('/')
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/')
  return i === -1 ? '' : path.slice(0, i)
}

// Node's resolution, narrowed to what a tarball can answer: extensions and
// index files, no node_modules walk and no conditional exports. What it cannot
// resolve it reports rather than guesses.
export function resolveLocal(specifier: string, fromFile: string, files: Set<string>, root: string): string | null {
  const base = specifier.startsWith('.')
    ? normalise(`${dirOf(fromFile)}/${specifier}`)
    : normalise(`${root}/${specifier}`)

  for (const suffix of ENTRY_EXTENSIONS) {
    const candidate = `${base}${suffix}`
    if (files.has(candidate)) return candidate
  }
  return null
}

export function analyzePackage(input: {
  // Path inside the tarball -> source. Only files a parser can read need be here.
  files: Map<string, string>
  packageJson: unknown
  // The tarball's root prefix, "package" for anything npm produced.
  root?: string
  maxFiles?: number
}): PackageReachability {
  const root = input.root ?? 'package'
  const names = new Set(input.files.keys())
  const maxFiles = input.maxFiles ?? 400

  const entryPoints: string[] = []
  const missingEntryPoints: string[] = []

  for (const declared of declaredEntryPoints(input.packageJson)) {
    const resolved = resolveLocal(declared.startsWith('.') ? declared : `./${declared}`, `${root}/x`, names, root)
    if (resolved) entryPoints.push(resolved)
    else missingEntryPoints.push(declared)
  }

  const analysed: string[] = []
  const lost: LostPoint[] = []
  const unresolvedLocal: string[] = []
  const byModule = new Map<string, ReachableModule>()

  const queue = [...entryPoints]
  const seen = new Set<string>(queue)

  while (queue.length > 0) {
    const file = queue.shift()!
    if (analysed.length >= maxFiles) {
      lost.push({
        reason: 'depth-limit',
        detail: `stopped after ${maxFiles} files; ${queue.length + 1} still queued`,
        line: null,
      })
      break
    }

    const source = input.files.get(file)
    if (source === undefined) continue
    analysed.push(file)

    const result = analyzeModuleSource(source, { file })
    for (const point of result.lost) lost.push({ ...point, file })

    for (const origin of result.origins) {
      if (origin.module === null) continue

      // A relative specifier is another file in this package, not a capability.
      // Following it is what makes the answer about the package rather than
      // about one file.
      if (origin.module.startsWith('.')) {
        const target = resolveLocal(origin.module, file, names, root)
        if (target === null) {
          unresolvedLocal.push(`${file} -> ${origin.module}`)
          continue
        }
        if (!seen.has(target)) { seen.add(target); queue.push(target) }
        continue
      }

      const existing = byModule.get(origin.module)
      if (!existing) {
        byModule.set(origin.module, {
          module: origin.module,
          gates: [origin.gate],
          route: origin.route,
          paths: origin.path.length > 0 ? [origin.path] : [],
          files: [file],
        })
        continue
      }

      if (!existing.gates.includes(origin.gate)) existing.gates.push(origin.gate)
      if (!existing.files.includes(file)) existing.files.push(file)
      if (origin.route.length < existing.route.length) existing.route = origin.route
      if (origin.path.length > 0 &&
          !existing.paths.some(p => p.join('.') === origin.path.join('.'))) {
        existing.paths.push(origin.path)
      }
    }
  }

  return {
    entryPoints,
    missingEntryPoints,
    filesAnalysed: analysed,
    reachable: [...byModule.values()].sort((a, b) => a.module.localeCompare(b.module)),
    unresolvedLocal: [...new Set(unresolvedLocal)],
    lost,
  }
}
