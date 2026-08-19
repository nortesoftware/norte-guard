// A3. Four capabilities, over the graph A1/A2 already builds.
//
// A1/A2 answers "can this code reach X". It says nothing about whether reaching
// X matters, and it said so in its own header, because deciding that on two
// confirmed samples would have been a preference wearing a measurement's
// clothes. There are 42 confirmed captures with bytes now, so the question can
// be asked. Whether 42 is the number it looks like is A5's problem and A5 says
// so out loud; this file's job is only to answer, per package, which of four
// capabilities the code can reach.
//
// FOUR, FIXED BEFORE THE RUN:
//
//     credential_read   fs over paths that name a secret, plus process.env
//                       reads of token-shaped variables
//     network_egress    net · http · https · dgram · fetch
//     external_exec     child_process
//     dynamic_code      eval · Function · vm · a specifier decided at runtime
//
// They are not derived from the confirmed samples and must not become derived
// from them. They are the capability set the public accounts of the campaigns
// this project exists to catch describe — read the secret, send it somewhere,
// run something, and hide all three behind code assembled at runtime.
//
// What can be checked about that, and what cannot, stated plainly because this
// file is the wrong place for a claim nobody can audit.
//
// CHECKABLE. `git show 3ec6e76:src/types.ts` — the first commit, 2026-08-12
// 19:39, before every one of the six confirmed packages existed — already
// declares the same four:
//
//     | 'network'
//     | 'credential_read'   // ~/.aws, ~/.npmrc, ~/.ssh, env tokens
//     | 'exec_external'
//     | 'code_download'     // fetch paired with eval or execFile
//
// Three of them are renamed here and none is redefined, and the comment on
// credential_read is the list below in prose: the three dot-directories and the
// environment tokens. So the shape of both lists predates the samples.
//
// NOT CHECKABLE from this repository: the exact 16 strings and 11 words, since
// the file holding them was written after the captures were on disk. A reader
// who wants that guarantee has the lists in front of them and the six packages
// in the corpus, and can check that no entry was drawn from one — the single
// case where an entry WOULD have been is not in the list at all. It is recorded
// as the post-hoc definition in capability-control.ts instead.
//
// Nothing may be widened after seeing a result: a definition tuned to the
// samples it is scored against is scored against nothing.
//
// NO NEW PATTERNS. Three of the four are pure reachability: the capability is
// the module, and the module is reached or it is not. `grep child_process` is
// defeated by one rename and this is not that — it follows a value from its gate
// through the renames, the destructuring, the property writes and the folded
// concatenations, and reports where it lost the trail.
//
// The fourth is different and the difference is not a slip. "fs" is not a
// capability anybody would report: nearly every package reaches it, and
// `readFileSync('./package.json')` is not a credential read. What makes it one
// is what was handed to it, so credential_read is the one that needs an
// argument, and an argument has to be compared against something. Two lists
// therefore exist below and they are the only lists in this file. They are
// frozen, they are short, they are declared here where they can be read, and
// they are applied ONLY to strings that demonstrably flowed into a call on a
// value the graph was already following. A string that merely appears in the
// file does not qualify — `secretPathGrepOnly` on every result counts the ones
// that only a text search would have found, because if that count is always zero
// then the graph bought nothing over grep here and somebody should be told.
//
// THREE ANSWERS, NEVER TWO. reached · not-reached · indeterminate. A capability
// nobody could rule out is not a capability that is absent, and this is the
// whole reason the module exists rather than a boolean per package: 36 of the 42
// confirmed captures ship their payload as a V8 bytecode cache, and a two-valued
// answer would have recorded them as reaching nothing at all — the malicious
// cohort looking cleaner than the control because it was better hidden.

import { builtinModules } from 'node:module'
import type {
  AmbientUse,
  CallArgument,
  LostPoint,
  LostReason,
  PackageReachability,
} from './reachability.js'

export type Capability =
  | 'credential_read'
  | 'network_egress'
  | 'external_exec'
  | 'dynamic_code'

export const CAPABILITIES: Capability[] = [
  'credential_read',
  'network_egress',
  'external_exec',
  'dynamic_code',
]

export type Answer = 'reached' | 'not-reached' | 'indeterminate'

// The modules whose reachability IS the capability. Names are compared after
// folding `node:` off the front and taking the first segment, so `node:fs` and
// `fs/promises` are `fs`.
export const CAPABILITY_MODULES: Record<Capability, string[]> = {
  credential_read: ['fs'],
  network_egress: ['net', 'http', 'https', 'dgram'],
  external_exec: ['child_process'],
  dynamic_code: ['vm'],
}

// ---------------------------------------------------------------------------
// The two lists
// ---------------------------------------------------------------------------

// Paths that name a secret rather than a file. Matched case-insensitively
// against a string that reached a filesystem or path call, never against the
// text of a file.
//
// Chosen for what the published campaigns took and nothing else: npm and git
// credentials, SSH keys, the three big clouds, container and cluster config, and
// the environment files a project keeps its own secrets in. Deliberately not a
// wallet list, not a browser-profile list, not a keychain list — each of those
// would be defensible and none of them was written down before the run, so
// adding one now is adding a pattern to fit a sample.
export const SECRET_PATHS: string[] = [
  '.npmrc',
  '.netrc',
  '.git-credentials',
  '.config/git/credentials',
  '.ssh/',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  '.aws/credentials',
  '.aws/config',
  '.config/gcloud',
  'gcloud/credentials',
  '.docker/config.json',
  '.kube/config',
  'kubeconfig',
  '.gnupg',
]

// A read of `process.env.X` is a credential read when X names a credential. The
// test is on the shape of the name, because the name is the only thing there is:
// nothing in a packument says which variables a machine has set.
//
// The word list is the discriminating half — TOKEN, SECRET, PASSWORD and the
// rest — and the named variables after it are the ones whose names do not
// contain any of those words and are credentials anyway.
export const TOKEN_ENV_WORDS = [
  'TOKEN', 'SECRET', 'PASSWORD', 'PASSWD', 'APIKEY', 'API_KEY',
  'ACCESS_KEY', 'PRIVATE_KEY', 'CREDENTIAL', 'CREDENTIALS', 'AUTH',
]

export const TOKEN_ENV_NAMES = [
  'GOOGLE_APPLICATION_CREDENTIALS',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'DOCKER_AUTH_CONFIG',
  'NODE_AUTH_TOKEN',
  'CI_JOB_TOKEN',
]

export function isSecretPath(value: string): boolean {
  const lower = value.toLowerCase()
  if (SECRET_PATHS.some(p => lower.includes(p.toLowerCase()))) return true
  // `.env` on its own, or `.env.production`, but not `environment.js` and not
  // `docs/.environment` — the dot and the boundary are what make it the file
  // rather than a word that starts the same way.
  return /(^|[/\\])\.env(\.[a-z0-9_-]+)?$/i.test(value)
}

export function isTokenEnvName(name: string): boolean {
  const upper = name.toUpperCase()
  if (TOKEN_ENV_NAMES.includes(upper)) return true
  return TOKEN_ENV_WORDS.some(word => upper.includes(word))
}

// ---------------------------------------------------------------------------
// What hides what
// ---------------------------------------------------------------------------

// Where the trail was lost decides which answers may still be given, and the
// mapping is a fact about each kind of loss rather than a policy:
//
//   dynamic-specifier   a require of a name decided at runtime can be ANY
//                       module, so the module set is not complete. It is also
//                       exactly what dynamic_code is, which is why that one is
//                       reached by the same fact that blinds the other three.
//   dynamic-eval        the same, through a body nobody read.
//   depth-limit         the walk stopped. Everything past it is unread.
//   unresolved-callee   a call whose target this analysis does not model can
//                       return anything, including a module.
//   unresolved-import   the file did not parse. Nothing in it was read.
//   computed-member     the module is known and the member is not, so the module
//                       answers stand and only the one that needs a member —
//                       credential_read — is blinded.
//   origin-bound        the module origin list for a file filled up, so a module
//                       reached after it is not written down. Every capability
//                       is answered off that list, so all four are blinded.
//   ambient-bound       the ambient list filled up. process.env, the global
//                       fetch, eval and Function all live there; external_exec
//                       does not, and keeps its answer.
//   argument-bound      the call-argument list filled up. Only credential_read
//                       reads arguments, so only credential_read is blinded —
//                       blinding the other three would discard answers that the
//                       module graph still supports.
const BLINDS: Record<LostReason, Capability[]> = {
  'dynamic-specifier': ['credential_read', 'network_egress', 'external_exec'],
  'dynamic-eval': ['credential_read', 'network_egress', 'external_exec'],
  'depth-limit': CAPABILITIES,
  'unresolved-callee': CAPABILITIES,
  'unresolved-import': CAPABILITIES,
  'computed-member': ['credential_read'],
  'origin-bound': CAPABILITIES,
  'ambient-bound': ['credential_read', 'network_egress', 'dynamic_code'],
  'argument-bound': ['credential_read'],
}

// The table, readable but not writable. Which capabilities a lost reason blinds
// is the single most consequential mapping in this module — it is what decides
// whether a package that could not be read comes back `indeterminate` or
// `not-reached` — so it is exported to be asserted against rather than left as a
// private constant that a later edit can widen unnoticed.
export function blindsFor(reason: LostReason): Capability[] {
  return [...BLINDS[reason]]
}

// Losses that are not lost points: facts about the package, or about the run,
// that make a negative answer unsayable before a single file is parsed.
export interface OpacityInput {
  // The archive holds a native binary, a WASM module, a V8 bytecode cache or a
  // minified file the analyser could not read. Whatever is in there reaches
  // whatever it likes and appears in no graph.
  opaqueExecutable?: boolean
  // The package was too large to follow at all — reachableModulesOf's file and
  // byte bounds. Distinct from opaque: nothing here is unreadable, it is only
  // unread.
  analysisRefused?: boolean
  // Set when the caller knows the archive could not be opened.
  unreadableArchive?: boolean
}

// ---------------------------------------------------------------------------
// The answer
// ---------------------------------------------------------------------------

export interface CapabilityAnswer {
  capability: Capability
  answer: Answer
  // Why it is reached, in the words of the thing that reached it. Empty for
  // every answer that is not `reached`.
  evidence: string[]
  // Why a negative could not be given. Empty when the answer is `reached` — a
  // capability that was found does not need the trail that was lost — and empty
  // when the analysis really did complete.
  blindedBy: string[]
}

export interface PackageCapabilities {
  answers: CapabilityAnswer[]
  // Modules reached that are neither builtins nor files in this package: the
  // package's declared dependencies. Their code was not analysed — it is not in
  // this tarball — so a package that reaches none of the four capabilities in
  // its own code but hands control to a dependency is not a package that reaches
  // nothing. Reported rather than folded into the answers, because folding it in
  // would blind almost every real package and blinding everything measures
  // nothing.
  externalModules: string[]
  // The count of secret-path strings that appear in the analysed files but did
  // NOT flow into a filesystem or path call. The difference between this and the
  // strings that did is the difference between this analysis and grep, and it is
  // reported on every package so the difference can be seen rather than claimed.
  secretPathGrepOnly: number
  // Every static string that DID reach a filesystem or path call and matched.
  secretPathsReached: string[]
  // Token-shaped environment variables read, and whether any read was of a
  // variable nobody could name.
  tokenEnvRead: string[]
  namelessEnvRead: boolean
}

const BUILTINS = new Set(builtinModules.map(m => m.replace(/^node:/, '')))

// `node:fs/promises` and `fs` are one module here. Scoped names keep both of
// their segments, since `@scope` alone names nothing.
export function moduleKey(specifier: string): string {
  const bare = specifier.startsWith('node:') ? specifier.slice(5) : specifier
  if (bare.startsWith('@')) return bare.split('/').slice(0, 2).join('/')
  return bare.split('/')[0] ?? bare
}

export function isBuiltin(specifier: string): boolean {
  return BUILTINS.has(moduleKey(specifier))
}

// Whether a call argument was handed to something that builds or opens a path.
// `path` is in here beside `fs` because `fs.readFileSync(path.join(home,
// '.npmrc'))` puts the literal on the path call and never on the fs one, and an
// analysis that only looked at fs arguments would miss the form every real
// program uses.
function pathBearing(argument: CallArgument): boolean {
  const key = argument.module === null ? null : moduleKey(argument.module)
  return key === 'fs' || key === 'path' || key === 'os'
}

export interface CapabilityInput extends OpacityInput {
  reachability: PackageReachability
  // The analysed sources, for the grep contrast only. Nothing in this file
  // decides an answer from them.
  sources?: Map<string, string>
  // A SECOND definition of the secret-path half of credential_read, and it was
  // written after the first six confirmed packages were opened. It is off by
  // default and it exists to be reported beside the frozen answer, never
  // instead of it.
  //
  // What it repairs is mechanical rather than a matter of taste. SECRET_PATHS
  // holds joined paths — '.aws/credentials' — and real code never writes one:
  // it writes `path.join(home, '.aws', 'credentials')`, three arguments of
  // which no single one is in the list. Turning this on reassembles the
  // arguments of each `path.join`/`path.resolve` call site in order and matches
  // the result.
  //
  // It is a repair to a defect, not a new pattern, and it still must not be
  // read as validated: a definition changed after seeing the cases is fitted to
  // them, however mechanical the change, and the run reports it under its own
  // heading with that said in full.
  joinPathSegments?: boolean
}

export function capabilitiesOf(input: CapabilityInput): PackageCapabilities {
  const r = input.reachability
  const reachedModules = new Set(r.reachable.map(m => moduleKey(m.module)))

  const blinded = new Map<Capability, Set<string>>(
    CAPABILITIES.map(c => [c, new Set<string>()])
  )
  const blind = (capabilities: Capability[], why: string): void => {
    for (const c of capabilities) blinded.get(c)!.add(why)
  }

  // The blinders that do not need a single line to be parsed.
  if (input.unreadableArchive) blind(CAPABILITIES, 'the archive could not be opened')
  if (input.analysisRefused) {
    blind(CAPABILITIES, 'too large to follow: the file or byte bound was reached before anything was read')
  }
  if (input.opaqueExecutable) {
    blind(CAPABILITIES, 'ships a native binary, WASM, a bytecode cache or unreadable minified code — that part reaches whatever it likes and is in no graph')
  }
  if (r.entryPoints.length === 0) blind(CAPABILITIES, 'no declared entry point resolves to a file in the tarball')
  if (r.filesAnalysed.length === 0) blind(CAPABILITIES, 'no JavaScript was read')
  for (const missing of r.missingEntryPoints) {
    blind(CAPABILITIES, `entry point "${missing}" is declared and not in the tarball`)
  }
  for (const unresolved of r.unresolvedLocal) {
    blind(CAPABILITIES, `a relative specifier resolves to no file in the package: ${unresolved}`)
  }

  // The blinders the walk itself recorded.
  for (const point of dedupeLost(r.lost)) {
    blind(BLINDS[point.reason], `${point.reason} at ${point.file ?? '?'}:${point.line ?? '?'}`)
  }

  // Arguments nobody could read, at a call on something that opens paths. This
  // is what stops "no secret path was found" from meaning "no secret path was
  // read": a filesystem call handed a variable is a filesystem call whose target
  // is unknown.
  const unreadPathArguments = r.callArguments.filter(a => a.value === null && pathBearing(a))
  for (const a of unreadPathArguments.slice(0, 8)) {
    blind(['credential_read'], `a path handed to ${describeCall(a)} was decided at runtime`)
  }

  const namelessEnvRead = r.ambient.some(a => a.what === 'process.env' && a.name === null)
  if (namelessEnvRead) {
    blind(['credential_read'], 'process.env was reached with the variable named somewhere this analysis does not follow')
  }

  // ---- the positive evidence -------------------------------------------

  const secretPathsReached = [...new Set([
    ...r.callArguments
      .filter(a => a.value !== null && pathBearing(a) && isSecretPath(a.value))
      .map(a => a.value!),
    ...(input.joinPathSegments ? joinedPaths(r.callArguments).filter(isSecretPath) : []),
  ])]

  const tokenEnvRead = [...new Set(
    r.ambient
      .filter(a => a.what === 'process.env' && a.name !== null && isTokenEnvName(a.name))
      .map(a => a.name!)
  )]

  const evidence = new Map<Capability, string[]>(CAPABILITIES.map(c => [c, []]))
  const found = (capability: Capability, why: string): void => {
    evidence.get(capability)!.push(why)
  }

  for (const capability of CAPABILITIES) {
    for (const module of CAPABILITY_MODULES[capability]) {
      if (!reachedModules.has(module)) continue
      // credential_read is not "reaches fs". The module being reached is a
      // precondition it shares with most of npm; the argument is the fact.
      if (capability === 'credential_read') continue
      const reached = r.reachable.find(m => moduleKey(m.module) === module)!
      found(capability, `reaches ${reached.module} via ${reached.route.join(' > ')} from ${reached.files[0]}`)
    }
  }

  for (const value of secretPathsReached) {
    found('credential_read', `a path naming a secret reached a filesystem call: ${JSON.stringify(value)}`)
  }
  for (const name of tokenEnvRead) {
    found('credential_read', `reads process.env.${name}`)
  }

  for (const use of r.ambient) {
    if (use.what === 'fetch') {
      found('network_egress', `calls the global fetch at ${use.file ?? '?'}:${use.line ?? '?'}`)
    }
    if (use.what === 'eval' || use.what === 'Function') {
      found('dynamic_code', `calls ${use.what} at ${use.file ?? '?'}:${use.line ?? '?'}`)
    }
  }

  for (const point of dedupeLost(r.lost)) {
    if (point.reason === 'dynamic-eval') {
      found('dynamic_code', `${point.detail} at ${point.file ?? '?'}:${point.line ?? '?'}`)
    }
    if (point.reason === 'dynamic-specifier') {
      found('dynamic_code', `${point.detail} at ${point.file ?? '?'}:${point.line ?? '?'}`)
    }
  }

  // ---- the three-valued answer ------------------------------------------

  const answers: CapabilityAnswer[] = CAPABILITIES.map(capability => {
    const why = evidence.get(capability)!
    if (why.length > 0) {
      return { capability, answer: 'reached', evidence: dedupe(why).slice(0, 12), blindedBy: [] }
    }
    const blinders = [...blinded.get(capability)!]
    if (blinders.length > 0) {
      return { capability, answer: 'indeterminate', evidence: [], blindedBy: blinders.slice(0, 12) }
    }
    return { capability, answer: 'not-reached', evidence: [], blindedBy: [] }
  })

  return {
    answers,
    externalModules: [...new Set(
      r.reachable.map(m => m.module).filter(m => !isBuiltin(m) && !m.startsWith('.'))
    )].sort(),
    secretPathGrepOnly: grepContrast(input.sources, secretPathsReached),
    secretPathsReached,
    tokenEnvRead,
    namelessEnvRead,
  }
}

export function answerFor(result: PackageCapabilities, capability: Capability): Answer {
  return result.answers.find(a => a.capability === capability)?.answer ?? 'indeterminate'
}

// How many secret-path strings sit in the analysed sources without ever reaching
// a filesystem call. This decides nothing; it measures what the graph is worth.
// If it is always zero, the graph agrees with grep and the extra machinery is
// buying nothing here — which would be worth knowing and is not knowable without
// counting it.
function grepContrast(sources: Map<string, string> | undefined, reached: string[]): number {
  if (!sources) return 0
  const alreadyReached = new Set(reached)
  const found = new Set<string>()

  for (const source of sources.values()) {
    // Every quoted string in the file, bounded: a minified bundle holds hundreds
    // of thousands and only the matching ones are kept.
    for (const match of source.matchAll(/(['"])((?:(?!\1)[^\\\n]|\\.){1,200})\1/g)) {
      const value = match[2]
      if (value === undefined || alreadyReached.has(value)) continue
      if (isSecretPath(value)) found.add(value)
      if (found.size >= 64) return found.size
    }
  }
  return found.size
}

// Every `path.join(...)` / `path.resolve(...)` call site put back together: the
// folded arguments in the order they were written, joined with the separator the
// function itself would have used. Arguments that did not fold are skipped
// rather than treated as empty, so `join(home, '.aws', 'credentials')` becomes
// '.aws/credentials' and not '/.aws/credentials'.
//
// One call site is (file, line, member path). Two joins on one line of a
// minified bundle merge into a single reconstruction, which can only invent a
// path that was not built — so this is reported as the post-hoc definition it
// is, never as the frozen one.
export function joinedPaths(callArguments: CallArgument[]): string[] {
  const sites = new Map<string, CallArgument[]>()

  for (const a of callArguments) {
    if (a.module === null || moduleKey(a.module) !== 'path') continue
    const member = a.memberPath[a.memberPath.length - 1]
    if (member !== 'join' && member !== 'resolve') continue
    const key = `${a.file ?? ''}|${a.line ?? '?'}|${a.memberPath.join('.')}`
    const at = sites.get(key)
    if (at) at.push(a)
    else sites.set(key, [a])
  }

  const joined: string[] = []
  for (const site of sites.values()) {
    const parts = [...site]
      .sort((x, y) => x.index - y.index)
      .map(a => a.value)
      .filter((v): v is string => v !== null)
    if (parts.length > 1) joined.push(parts.join('/'))
  }
  return [...new Set(joined)]
}

function describeCall(a: CallArgument): string {
  const path = a.memberPath.length > 0 ? `.${a.memberPath.join('.')}` : ''
  return `${a.module ?? '?'}${path}()`
}

function dedupeLost(points: LostPoint[]): LostPoint[] {
  const seen = new Map<string, LostPoint>()
  for (const p of points) {
    seen.set(`${p.reason}|${p.file ?? ''}|${p.line ?? ''}|${p.detail}`, p)
  }
  return [...seen.values()]
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)]
}

// Printed under any table of capability rates. Every one of these is a reason a
// rate here is not the rate in the ecosystem, and they belong beside the number
// rather than in a footnote nobody reaches.
export function capabilityCaveats(): string[] {
  return [
    'Reachability is package-local. A package that reaches a declared dependency hands control to code that is not in this tarball and was not analysed; `externalModules` counts those packages so the bound can be read.',
    'Three of the four capabilities are answered by which module is reached, which is what the code CAN do and never what it does. A package that requires child_process and never calls it is reported as reaching external_exec, correctly.',
    'credential_read is the exception and needs an argument, so its negative is the weakest of the four: it says no path naming a secret was demonstrated, over the call sites whose arguments could be read.',
    'dynamic_code is reached by the same facts that blind the other three. It is closer to "this package hides what it does" than to a capability in its own right, and a run where it is the only thing that fires is a run that measured opacity.',
    'Nothing here scores. A capability is not a verdict, the four are not weighted, and no number in this module contributes a point to anything.',
  ]
}

// Everything above, fixed. Printed by the run so a report carries the definition
// it was produced under, and a later run with a different one cannot be mistaken
// for the same measurement.
export function capabilityDefinitions(): Array<{ capability: Capability; definition: string }> {
  return [
    {
      capability: 'credential_read',
      definition:
        `fs reached AND a string naming a secret reached a filesystem or path call ` +
        `(${SECRET_PATHS.length} paths, plus .env files), OR process.env read of a ` +
        `token-shaped variable (${TOKEN_ENV_WORDS.length} words, ${TOKEN_ENV_NAMES.length} named)`,
    },
    {
      capability: 'network_egress',
      definition: `reaches ${CAPABILITY_MODULES.network_egress.join(', ')}, or calls the global fetch`,
    },
    {
      capability: 'external_exec',
      definition: 'reaches child_process',
    },
    {
      capability: 'dynamic_code',
      definition: 'reaches vm, or calls eval/Function, or a require/import specifier decided at runtime',
    },
  ]
}
