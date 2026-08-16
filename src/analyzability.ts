// How much of a package can be looked at at all, before anything looks.
//
// Every detector this project has built reports PASS on what it could not read.
// That is the correct default for a gate — lack of context is not evidence of
// risk — and it is a lie about coverage unless somebody publishes the size of
// the blind spot. A recall figure computed over packages whose payload is a
// stripped Mach-O binary is a measurement of the packages that happened to ship
// readable JavaScript.
//
// So this measures reach and detects nothing. It answers one question: of the
// bytes that can execute, what fraction could a spec-conforming JavaScript
// parser read and follow, and for the rest, why not.
//
// FAIL CLOSED. A file counts as covered only if every one of these holds: it
// parses, it is legible, and it contains no construct that moves behaviour out
// of the parser's reach. One eval() of a runtime-built string makes the whole
// file uncovered — not 95% covered — because the parser cannot bound what the
// remaining 5% does. Being wrong in this direction costs a pessimistic number.
// Being wrong in the other direction is the failure this file exists to stop.

import { parse, type Options } from 'acorn'
import { classifyFile, isExecutableKind, extensionOf, isTypeDeclaration, type FileKind } from './file-kind.js'

// Above this a file is not parsed. Acorn is linear but the constant is not free,
// and the corpus holds single bundles over 100MB. Reported as its own reason
// rather than skipped: a file nobody read is not a file that was clean.
export const MAX_PARSE_BYTES = 8 * 1024 * 1024

export type NonCoverageReason =
  // A package published to npm parses. One that defeats a conforming parser is
  // either broken or built to be. Maximum severity, and separated below from
  // "was never JavaScript in the first place", which is neither.
  | 'parse-failure'
  | 'not-javascript'
  // The parser declined before the file did. acorn carries its own recursion
  // guard and gives up on a deeply nested expression — `a+a+a+...` past about
  // ten thousand terms — with "Not enough stack space to parse input". That is a
  // limit of this tool, not a property of the package, and filing it under
  // parse-failure would put the maximum-severity label on acorn's own bound.
  // Still uncovered: nobody read the file.
  | 'parser-limit'
  | 'dynamic-eval'
  | 'dynamic-require'
  | 'native-binary'
  | 'wasm'
  | 'bytecode'
  | 'foreign-script'
  | 'minified'
  | 'too-large'

export const NON_COVERAGE_REASONS: readonly NonCoverageReason[] = [
  'parse-failure', 'not-javascript', 'parser-limit', 'dynamic-eval', 'dynamic-require',
  'native-binary', 'wasm', 'bytecode', 'foreign-script', 'minified', 'too-large',
]

// Everything a JavaScript file can be measured on that might separate minified
// from readable. Collected on every parsed file whether or not a threshold uses
// it, because the threshold has to be derived from this distribution and a
// metric nobody recorded cannot be compared against the one that was chosen.
export interface LegibilityMetrics {
  bytes: number
  lines: number
  // Mean rather than median: computing a median needs every line length held at
  // once, and over a 100k-line bundle that is the expensive part of the pass.
  // The two agree on the shape that matters — minified files are one enormous
  // line — and where they disagree, maxLineLength below says so.
  bytesPerLine: number
  maxLineLength: number
  nodes: number
  bytesPerNode: number
  identifiers: number
  meanIdentifierLength: number
  // Minifiers rename everything they can reach to one or two characters. What
  // they cannot rename — imported names, property keys, globals — is what keeps
  // this below 1.0 even on thoroughly minified code.
  shortIdentifierRatio: number
}

export interface FileAnalysis {
  name: string
  bytes: number
  kind: FileKind
  classifiedBy: string
  covered: boolean
  reasons: NonCoverageReason[]
  // Present for every file that parsed, absent otherwise.
  metrics?: LegibilityMetrics
  // The parser's own message, kept for the failures that claim to be adversarial.
  parseError?: string
}

export interface OpacityMarker {
  kind: 'dynamic-eval' | 'dynamic-require'
  detail: string
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

export interface ParseOutcome {
  ok: boolean
  ast?: unknown
  // Which of the three kinds of failure this was. Only 'malformed' supports the
  // claim that a parse failure is evidence of something; a .js file that is
  // really TypeScript is a packaging habit, and reporting it as adversarial
  // would make this a false-alarm engine on its first run.
  failure?: 'malformed' | 'not-javascript' | 'parser-limit'
  error?: string
}

const BASE_OPTIONS: Options = {
  ecmaVersion: 'latest',
  // Real packages ship CLI entry points with a shebang, and acorn treats the
  // line as a syntax error unless told.
  allowHashBang: true,
  allowAwaitOutsideFunction: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
}

// A .mjs is a module, a .cjs is a script, and a .js is whichever package.json
// says. Getting it wrong turns a valid file into a parse failure, and this
// design calls a parse failure maximum severity — so the fallback tries the
// other mode before anything is called broken. What the fallback costs is that
// a file which is genuinely broken as a module and accidentally valid as a
// script reads as fine; what it buys is not reporting half the ecosystem as
// adversarial because a package omitted "type".
export function parseJavaScript(
  source: string,
  fileName: string,
  packageType: 'module' | 'commonjs' | undefined
): ParseOutcome {
  const ext = extensionOf(fileName)
  const declared: 'module' | 'script' =
    ext === '.mjs' ? 'module'
    : ext === '.cjs' ? 'script'
    : packageType === 'module' ? 'module'
    : 'script'

  const first = tryParse(source, declared)
  if (first.ok) return first

  const second = tryParse(source, declared === 'module' ? 'script' : 'module')
  if (second.ok) return second

  // Both modes failed. Whether that is evidence depends on what the file was —
  // and on whether the parser gave up before reading it.
  return {
    ok: false,
    failure: isParserLimit(first.error) || isParserLimit(second.error)
      ? 'parser-limit'
      : looksLikeAnotherLanguage(source, fileName) ? 'not-javascript' : 'malformed',
    error: first.error,
  }
}

// acorn's own recursion guard, not a statement about the file. Matched on the
// message because acorn throws a plain SyntaxError for it with no code to test.
function isParserLimit(message: string | undefined): boolean {
  return message !== undefined && /not enough stack space/i.test(message)
}

function tryParse(source: string, sourceType: 'module' | 'script'): ParseOutcome {
  try {
    return { ok: true, ast: parse(source, { ...BASE_OPTIONS, sourceType }) }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

// Told apart by what the file IS, not by where the parser stopped: an error
// offset in a minified bundle points at whatever the minifier happened to emit
// there, and reading a language out of it would be guessing.
export function looksLikeAnotherLanguage(source: string, fileName: string): boolean {
  if (isTypeDeclaration(fileName)) return true

  const head = source.slice(0, 4096)

  // JSON served with a .js name. Parsed rather than pattern-matched: a file that
  // JSON.parse accepts is JSON, and nothing else has to be decided.
  const trimmed = source.trimStart()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try { JSON.parse(source); return true } catch { /* not JSON, carry on */ }
  }

  // Markup. A .js that begins with a tag or a doctype is a build artefact in the
  // wrong place, not an attack.
  if (/^\s*(<!doctype|<html|<\?xml|<svg)/i.test(head)) return true

  // TypeScript and Flow constructs that are syntax errors in JavaScript. Kept
  // narrow on purpose: `interface` and `enum` are contextual keywords and these
  // patterns require the shape that only the typed dialects produce.
  if (/^\s*(import|export)\s+type\s/m.test(head)) return true
  if (/^\s*(declare|abstract)\s+(class|module|namespace|global|const|function)\b/m.test(head)) return true
  if (/^\s*interface\s+[A-Za-z_$][\w$]*\s*(<[^>]*>)?\s*(extends\s[^{]+)?\{/m.test(head)) return true
  if (/^\s*(export\s+)?(declare\s+)?enum\s+[A-Za-z_$][\w$]*\s*\{/m.test(head)) return true
  if (/^\s*\/\/\s*@flow/m.test(head)) return true

  return false
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

interface AstNode { type: string; [key: string]: unknown }

// Iterative, and generic over node types on purpose.
//
// Iterative because a minified bundle is a legal way to write `a+b+c+` fifty
// thousand times, and a recursive walk over that BinaryExpression chain
// overflows the stack — on hostile input, which is the whole corpus.
//
// Generic because an explicit switch over node types silently skips whatever it
// has not heard of, and the thing it has not heard of is the newest syntax,
// which is exactly where an eval would hide. Walking every own property that
// carries a `.type` cannot miss a node for not knowing its name.
export function walkAst(root: unknown, visit: (node: AstNode) => void): void {
  const stack: unknown[] = [root]

  while (stack.length > 0) {
    const current = stack.pop()
    if (!current || typeof current !== 'object') continue

    if (Array.isArray(current)) {
      for (const item of current) stack.push(item)
      continue
    }

    const node = current as AstNode
    if (typeof node.type === 'string') visit(node)

    for (const key of Object.keys(node)) {
      if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue
      const value = node[key]
      if (value && typeof value === 'object') stack.push(value)
    }
  }
}

// A string the parser can read off the page. A template literal with no
// substitutions is one; the moment it has an expression in it, whatever it
// resolves to is decided at runtime and this layer cannot follow it.
function isStaticString(node: unknown): boolean {
  if (!node || typeof node !== 'object') return false
  const n = node as AstNode

  if (n.type === 'Literal') return typeof n.value === 'string'
  if (n.type === 'TemplateLiteral') return Array.isArray(n.expressions) && n.expressions.length === 0
  return false
}

function calleeName(node: unknown): string | null {
  if (!node || typeof node !== 'object') return null
  const n = node as AstNode

  if (n.type === 'Identifier') return typeof n.name === 'string' ? n.name : null
  // Indirect eval: `(0, eval)(src)` is the documented way to reach global scope,
  // and it is a different AST shape from a plain call. Reading through the
  // sequence catches it with no special case downstream.
  if (n.type === 'SequenceExpression' && Array.isArray(n.expressions)) {
    return calleeName(n.expressions[n.expressions.length - 1])
  }
  if (n.type === 'ParenthesizedExpression') return calleeName(n.expression)
  return null
}

export function findOpacity(ast: unknown): OpacityMarker[] {
  const markers: OpacityMarker[] = []

  walkAst(ast, node => {
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const args = Array.isArray(node.arguments) ? node.arguments : []
      const name = calleeName(node.callee)

      if (name === 'eval') {
        // A literal eval("1+1") is unusual and analysable: the parser can read
        // the string and, in principle, parse it. It is not what this reason is
        // about, so it does not fire.
        if (!args.length || !isStaticString(args[0])) {
          markers.push({ kind: 'dynamic-eval', detail: 'eval() of an expression built at runtime' })
        }
      }

      if (name === 'Function' && args.length > 0) {
        // The body is the last argument; the ones before it are parameter names.
        if (!isStaticString(args[args.length - 1])) {
          markers.push({ kind: 'dynamic-eval', detail: 'new Function() over a runtime-built body' })
        }
      }

      if (name === 'require' && args.length > 0 && !isStaticString(args[0])) {
        const partial = (args[0] as AstNode | undefined)?.type === 'TemplateLiteral'
        markers.push({
          kind: 'dynamic-require',
          detail: partial
            ? 'require() of a template with a runtime part: the prefix is readable, the target is not'
            : 'require() of an expression the parser cannot resolve',
        })
      }
    }

    // import(expr). acorn emits ImportExpression, whose child is `source`.
    if (node.type === 'ImportExpression' && !isStaticString(node.source)) {
      markers.push({
        kind: 'dynamic-require',
        detail: 'import() of an expression the parser cannot resolve',
      })
    }
  })

  return markers
}

// ---------------------------------------------------------------------------
// Legibility
// ---------------------------------------------------------------------------

export function measureLegibility(source: string, ast: unknown): LegibilityMetrics {
  const bytes = Buffer.byteLength(source, 'utf-8')

  let lines = 1
  let maxLineLength = 0
  let currentLine = 0
  for (let i = 0; i < source.length; i++) {
    if (source.charCodeAt(i) === 10) {
      if (currentLine > maxLineLength) maxLineLength = currentLine
      currentLine = 0
      lines++
    } else {
      currentLine++
    }
  }
  if (currentLine > maxLineLength) maxLineLength = currentLine

  let nodes = 0
  let identifiers = 0
  let identifierChars = 0
  let shortIdentifiers = 0

  walkAst(ast, node => {
    nodes++
    if (node.type === 'Identifier' && typeof node.name === 'string') {
      identifiers++
      identifierChars += node.name.length
      if (node.name.length <= 2) shortIdentifiers++
    }
  })

  return {
    bytes,
    lines,
    bytesPerLine: bytes / lines,
    maxLineLength,
    nodes,
    bytesPerNode: nodes > 0 ? bytes / nodes : 0,
    identifiers,
    meanIdentifierLength: identifiers > 0 ? identifierChars / identifiers : 0,
    shortIdentifierRatio: identifiers > 0 ? shortIdentifiers / identifiers : 0,
  }
}

// The cut, and where it came from.
//
// DERIVED, NOT CHOSEN. `norte-guard analyzability --metrics` writes every
// metric above for every parsed file in the corpus, and the constants here come
// out of that run — see docs/benchmark.md for the histogram and the
// self-labelled set the cut was checked against. Editing them without re-running
// it puts a number in this file that nothing measured.
//
// Two conditions, not one, and both have to hold. A single metric is too easy to
// fail in a way that matters: a generated-but-readable file (a big lookup table,
// one entry per line) has short identifiers and short lines, and a hand-written
// file with one enormous inlined data string has a huge maxLineLength and
// perfectly ordinary names. Requiring the layout AND the renaming to agree is
// what keeps both of those out.
export interface LegibilityThreshold {
  bytesPerLine: number
  shortIdentifierRatio: number
}

// Both numbers are the ANTIMODE of their own distribution, measured over 28,519
// parsed JavaScript files from 182 packages in 700 captures on 2026-08-16. Both
// distributions are bimodal and the cut falls in the empty valley between the
// humps, which is what makes it a cut rather than a preference:
//
//   shortIdentifierRatio   5,592 files at 0.00-0.05, 12,933 at 0.65-0.70,
//                          and the minimum of the valley at 0.500 holds 46.
//   bytesPerLine           4,786 files at 20-40, 7,245 at 400-600,
//                          and the minimum of the valley at 130 holds 15.
//
// Checked a second way, because the first way could have been five packages.
// FIVE of the 182 packages hold 52.9% of those files, so a file-weighted
// histogram is largely a picture of whoever ships the most files. Re-derived
// with one vote per package, on each package's median: the valley at 100-120
// bytes per line holds ZERO packages and the valley at 0.25-0.30 holds one. The
// same cut sits in an empty region under both weightings, and that is the
// evidence — not the shape of either histogram on its own.
//
// The choice is also insensitive across the whole valley: every cut from
// (100, 0.40) to (200, 0.50) catches the same 12 of the 14 unambiguous *.min.js
// files and fires on 1.1%-1.7% of the readable ones. It barely matters where in
// an empty valley the line falls, because nothing lives there.
//
// What the cut then says, and the two answers are both true and very different:
//   64.6% of parsed JavaScript FILES are minified
//   14.8% of PACKAGES ship at least one minified file
//    6.0% of PACKAGES are minified in the majority of their files
// The command reports the package-weighted figure, because "what fraction of new
// npm packages ships unreadable code" is a question about packages.
//
// Validation against what labels itself, and the bias in both directions:
//   caught 12 of 14 files named *.min.js. One of the two misses is a 353-byte
//   re-export stub that is not minified despite its name; the other has a mean
//   line of 2,189 bytes and identifiers averaging 7.2 characters, which is one
//   inlined data blob rather than renamed code, and the second condition
//   declines it on purpose.
//   fired on 37 of 3,298 files that ship a sourcemap alongside them, 1.12%.
//   Those are an upper bound on the error: some of them are minified and simply
//   were never labelled.
//
// Re-derive with `norte-guard analyzability --metrics` against a fresh corpus.
// Editing these by hand puts a number here that nothing measured.
export const MINIFIED_THRESHOLD: LegibilityThreshold = {
  bytesPerLine: 130,
  shortIdentifierRatio: 0.50,
}

export function isMinified(
  metrics: LegibilityMetrics,
  threshold: LegibilityThreshold = MINIFIED_THRESHOLD
): boolean {
  // A threshold of zero is the unset state and must never silently mark
  // everything: an unmeasured constant reporting 100% minified would be read as
  // a finding.
  if (threshold.bytesPerLine <= 0 || threshold.shortIdentifierRatio <= 0) return false

  return metrics.bytesPerLine >= threshold.bytesPerLine &&
    metrics.shortIdentifierRatio >= threshold.shortIdentifierRatio
}

// ---------------------------------------------------------------------------
// One file
// ---------------------------------------------------------------------------

export function analyzeFile(input: {
  name: string
  data: Buffer
  packageType: 'module' | 'commonjs' | undefined
  threshold?: LegibilityThreshold
}): FileAnalysis {
  const { name, data } = input
  const classification = classifyFile(name, data.subarray(0, 256))
  const base = {
    name,
    bytes: data.length,
    kind: classification.kind,
    classifiedBy: `${classification.by}: ${classification.detail}`,
  }

  if (!isExecutableKind(classification.kind)) {
    // Held out of the denominator entirely rather than counted as covered. A
    // README is not analysable code and it is not an analysis gap either.
    return { ...base, covered: false, reasons: [] }
  }

  switch (classification.kind) {
    case 'native':
      return { ...base, covered: false, reasons: ['native-binary'] }
    case 'wasm':
      return { ...base, covered: false, reasons: ['wasm'] }
    case 'bytecode':
      return { ...base, covered: false, reasons: ['bytecode'] }
    case 'foreign-script':
      return { ...base, covered: false, reasons: ['foreign-script'] }
    default:
      break
  }

  if (data.length > MAX_PARSE_BYTES) {
    return { ...base, covered: false, reasons: ['too-large'] }
  }

  const source = data.toString('utf-8')
  const parsed = parseJavaScript(source, name, input.packageType)

  if (!parsed.ok) {
    const reason: NonCoverageReason =
      parsed.failure === 'not-javascript' ? 'not-javascript'
      : parsed.failure === 'parser-limit' ? 'parser-limit'
      : 'parse-failure'
    return { ...base, covered: false, reasons: [reason], parseError: parsed.error }
  }

  const metrics = measureLegibility(source, parsed.ast)
  const reasons: NonCoverageReason[] = []

  // Every reason that applies, not the first one found. A minified bundle with a
  // dynamic require is both, and a prevalence table built from first-reason-wins
  // would under-report whichever reason lost the race.
  if (isMinified(metrics, input.threshold)) reasons.push('minified')

  const opacity = findOpacity(parsed.ast)
  if (opacity.some(o => o.kind === 'dynamic-eval')) reasons.push('dynamic-eval')
  if (opacity.some(o => o.kind === 'dynamic-require')) reasons.push('dynamic-require')

  return { ...base, covered: reasons.length === 0, reasons, metrics }
}

// ---------------------------------------------------------------------------
// One capture
// ---------------------------------------------------------------------------

export interface KindTotals {
  files: number
  bytes: number
}

export interface CaptureAnalyzability {
  package: string
  version: string
  capturedAt: string
  ngpackPath: string
  label: string
  // The denominator: bytes of files that execute or load as code.
  executableBytes: number
  executableFiles: number
  coveredBytes: number
  coveredFiles: number
  // Null, never zero, when the package ships nothing executable at all. A
  // types-only or assets-only package has no coverage rather than 0% coverage,
  // and averaging the second into a corpus figure would invent a blind spot.
  coverage: number | null
  byReason: Partial<Record<NonCoverageReason, KindTotals>>
  // What was held out of the denominator, by kind, so the exclusion can be
  // argued with instead of taken on trust.
  heldOut: Partial<Record<FileKind, KindTotals>>
  files: FileAnalysis[]
  // The archive could not be read at all. Distinct from 0% coverage: one is a
  // corpus defect and the other is a finding about the package.
  error?: string
}

function addTo<K extends string>(
  totals: Partial<Record<K, KindTotals>>,
  key: K,
  bytes: number
): void {
  const entry = totals[key] ?? { files: 0, bytes: 0 }
  entry.files++
  entry.bytes += bytes
  totals[key] = entry
}

// package.json "type" decides whether a bare .js is a module, and getting it
// wrong is the difference between a clean parse and a reported parse failure.
// Read from the archive rather than from the packument: the packument's version
// metadata does not carry it.
export function packageTypeOf(entries: Array<{ name: string; data: Buffer }>): 'module' | 'commonjs' | undefined {
  // The root manifest only. A nested node_modules/x/package.json describes a
  // different package and would answer for the wrong one.
  const root = entries.find(e => {
    const parts = e.name.split('/')
    return parts.length === 2 && parts[1] === 'package.json'
  }) ?? entries.find(e => e.name === 'package.json')

  if (!root) return undefined
  try {
    const parsed = JSON.parse(root.data.toString('utf-8')) as { type?: string }
    return parsed.type === 'module' ? 'module' : parsed.type === 'commonjs' ? 'commonjs' : undefined
  } catch {
    return undefined
  }
}

export function summariseFiles(files: FileAnalysis[]): Pick<
  CaptureAnalyzability,
  'executableBytes' | 'executableFiles' | 'coveredBytes' | 'coveredFiles' | 'coverage' | 'byReason' | 'heldOut'
> {
  const byReason: Partial<Record<NonCoverageReason, KindTotals>> = {}
  const heldOut: Partial<Record<FileKind, KindTotals>> = {}

  let executableBytes = 0, executableFiles = 0, coveredBytes = 0, coveredFiles = 0

  for (const f of files) {
    if (!isExecutableKind(f.kind)) {
      addTo(heldOut, f.kind, f.bytes)
      continue
    }

    executableBytes += f.bytes
    executableFiles++

    if (f.covered) {
      coveredBytes += f.bytes
      coveredFiles++
      continue
    }

    // Every reason the file carries, so a file with two of them appears under
    // both. The per-reason columns therefore sum to more than the uncovered
    // total, which is the honest shape and is why they are never presented as a
    // partition.
    for (const reason of f.reasons) addTo(byReason, reason, f.bytes)
  }

  return {
    executableBytes,
    executableFiles,
    coveredBytes,
    coveredFiles,
    coverage: executableBytes > 0 ? coveredBytes / executableBytes : null,
    byReason,
    heldOut,
  }
}
