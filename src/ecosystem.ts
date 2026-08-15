// Every other module looks at one package. This one looks at the ecosystem.
//
// Thirty unrelated packages gaining their first network capability in the same
// hour are not thirty anomalies — they are one worm. ChainDrop touched 444
// packages in 4 hours; individually each was a medium signal, together they were
// certainty. It runs on the capability deltas that already exist, needs no new
// infrastructure, and catches a campaign on day zero with no prior corpus.

import type { Packument, VersionMeta } from './packument.js'
import type { Capability } from './types.js'
import { extractCapabilities } from './genome.js'
import { sortedVersions } from './packument.js'
import { nameAgeDays, YOUNG_NAME_DAYS, TINY_PACKAGE_BYTES } from './observed-class.js'
import { POPULAR_PACKAGE_NAMES } from './popular-names.js'

export interface CapabilityDeltaEvent {
  package: string
  version: string
  publishedAt: string
  newCapabilities: Capability[]
  maintainer: string
  // The party behind the publication, after collapsing a monorepo to the one
  // decision it actually is. See publishingEntity.
  entity: string
}

export interface CampaignSignal {
  type: 'coordinated_capability_gain' | 'velocity_burst' | 'maintainer_wave' | 'fabricated_family'
  certainty: number
  packages: string[]
  // Distinct publishing parties behind those packages. Seven packages from one
  // monorepo are seven entries here and one entity, and it is the second number
  // that decides whether anything is coordinated.
  entities: string[]
  capability?: Capability
  windowMinutes: number
  description: string
  // What tied the members together. Empty for the genome detectors, where the
  // shared capability is the link.
  linkedBy?: string[]
}

export interface EcosystemSnapshot {
  capturedAt: string
  packages: Record<string, PackageDelta>
}

export interface PackageDelta {
  package: string
  latestVersion: string
  publishedAt: string
  maintainer: string
  newCapabilities: Capability[]
  hasInstallScript: boolean
}

// Tokens too common to mean anything, measured over the 41,356 distinct package
// names this collector observed to 2026-08-14. "cli" is in one name in twenty,
// so two packages sharing it share nothing.
//
// The point of the list is the contrast. "mutex" appears in 3 names of 41,356
// (0.007%), "lock" in 10 (0.024%), "lease" in 2. A token that rare, shared by
// two packages published in the same hour, is a fact about them rather than
// about npm. Recompute it from changes-log.ndjson rather than editing by hand.
const GENERIC_NAME_TOKENS = new Set([
  // Measured: every token appearing in 0.15% or more of them.
  'cli', 'sdk', 'plugin', 'x64', 'react', 'client', 'core', 'linux', 'arm64',
  'mcp', 'darwin', 'dsh', 'api', 'server', 'agent', 'win32', 'native', 'web',
  'config', 'node', 'components', 'app', 'utils', 'editor', 'kit', 'eslint',
  'create', 'adapter', 'vue', 'gnu', 'musl', 'runtime', 'types', 'design',
  'auth', 'code', 'wijmo', 'angular', 'module', 'provider', 'shared',
  'extension', 'tool', 'test', 'platform', 'msvc', 'common', 'sandbox',
  'radius', 'engine', 'stroke', 'data', 'backend', 'tools', 'opencode',
  'bridge', 'vite', 'browser', 'claude', 'form', 'search', 'chat', 'round',
  'service', 'gapi', 'theme', 'next', 'lib', 'player', 'system', 'huaweicloud',
  'dev', 'icons', 'component', 'casino', 'windows', 'grid', 'chart', 'http',
  'game', 'table', 'protocol', 'coin', 'binding', 'base', 'xui', 'builder',
  'wallet', 'n8n', 'generator', 'vega', 'manager', 'aws', 'memory',
  'contracts', 'local', 'ckeditor5', 'storage', 'schema', 'admin', 'docs',
  'nodes', 'harness', 'json', 'image', 'wasm', 'miaoda', 'store', 'controller',
  'codex', 'connector', 'cloud', 'renderer', 'skills', 'graphql', 'hooks',
  'skill', 'i18n', 'router', 'filled', 'outlined', 'analytics', 'session',
  'auto', 'esm', 'context', 'widget', 'svelte', 'exchange', 'registry',
  'query', 'typescript', 'rate', 'lint', 'pkg', 'loader', 'text', 'addon',
  'input', 'gateway', 'library', 'catalog', 'frontend', 'connect', 'compiler',
  'llm', 'viewer', 'cache', 'model', 'dashboard', 'content', 'file', 'preset',
  'card', 'canvas', 'template', 'account', 'css', 'baseline', 'sqlite', 'list',
  'devtools', 'runner', 'nodejs', 'workspace', 'product', 'nuxt', 'framework',
  'google', 'user', 'brick', 'parser', 'tokens', 'use', 'talos', 'workflow',
  'hub', 'events',

  // Not measured out, because frequency does not reach them: English function
  // words are rare as package-name tokens — "and" is in 0.065% of names — and
  // carry nothing at any rate. Four SEO-spam packages were grouped into a
  // family by sharing the word "and".
  'and', 'for', 'the', 'with', 'from', 'into', 'that', 'this', 'you', 'your',
  'are', 'not', 'all', 'any', 'new', 'get', 'set', 'out', 'via',
])

// Vocabularies, not tokens. The five packages in the lock family share no token
// at all — async-critical-section, keyed-mutex-map, resource-lease-pool,
// try-lock-runner and single-flight-lock have "lock" in common between exactly
// two of them — so a rule built on repeated substrings would have linked a pair
// and missed the family.
//
// This is the weakest of the linkers below and the most honest about it: a
// vocabulary only catches a domain somebody thought to write down, and the one
// here was written down after reading a campaign. It costs nothing and it earns
// no certainty on its own; the shared maintainer and the shared fresh
// dependency are what actually carried this case.
//
// Every word in it appears in under 0.05% of observed package names. "atomic"
// (0.058%) and "queue" (0.065%) were dropped by that cut, and dropping them is
// the point of having one: both are ordinary words in npm — atomic design,
// atomic css, job queues — and both pulled unrelated packages into a real
// family while they were in.
const LEXICAL_DOMAINS: Record<string, string[]> = {
  concurrency: [
    'mutex', 'lock', 'locks', 'lease', 'semaphore', 'critical', 'section',
    'barrier', 'latch', 'rwlock', 'spinlock', 'flight', 'debounce',
    'throttle', 'serialize', 'concurrency', 'contention',
  ],
}

// Dependencies shared by so many packages of this class that sharing one says
// nothing. Measured over the dependency lists of the 3,849 captures on disk,
// which is the right population precisely because it is not the ecosystem: the
// detector only ever looks at packages of this shape, so what counts as common
// is what is common among them.
//
// The separation is not subtle. zod is a dependency of 10.83% of them and
// @modelcontextprotocol/sdk of 5.69%; mutex-forge, the package that carried the
// lock family's payload, of 0.13% — and those five are the family itself. This
// is the list at 1% and above; recompute it rather than adding names by hand.
const COMMON_DEPENDENCIES = new Set([
  'zod', 'commander', '@modelcontextprotocol/sdk', 'yaml', 'ws', 'react',
  'chalk', 'semver', 'axios', 'express', 'dotenv', '@clack/prompts', 'marked',
  '@deterministic-code/co-rule-kit', 'undici', 'jose', '@anthropic-ai/sdk',
  'node-pty', 'diff', 'react-dom', '@inquirer/prompts', 'tslib',
  'lucide-react', 'typescript', 'openai', 'pino', 'glob', '@bamboocss/types',
  'chokidar', 'uuid', '@hive-ui/style-props', 'picocolors', 'hono', 'jiti',
  'pg', 'typebox', '@hive-ui/box', 'esbuild', 'ignore', 'highlight.js',
  'open', 'proper-lockfile',
])

export function nameTokens(name: string): string[] {
  const base = name.startsWith('@') ? name.split('/').slice(1).join('/') : name
  return [...new Set(
    base
      .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(t => t.length > 2)
  )]
}

// The unit that has to be counted, because seven packages published in one batch
// from one repository are one decision by one team, and counting them as seven
// parties is what turned fwork-jsts-* into a campaign alert forty times over.
//
// Ordered most specific first: an npm scope and a repository URL are declared
// identities. The shared name prefix is the fallback for the many unscoped
// monorepos that declare neither — fwork-jsts-common, fwork-jsts-db,
// fwork-jsts-server, fwork-jsts-browser, fwork-jsts-test and fwork-react-mui-ext
// share "fwork", a token in 6 names of 41,356.
//
// The prefix rule needs the account as well as the name, and needs both for a
// reason. dsh-mobile-control, dsh-browser-control, dsh-port-guard and five more
// are one person's plugin set; the lock family shares an account and nothing
// else, its five names beginning async-, keyed-, resource-, single- and try-.
// So a prefix collapses only when one party is behind it — which is what a
// naming convention is — and never merges two accounts that happened to pick
// the same first word.
export function publishingEntity(
  name: string,
  meta: VersionMeta | undefined,
  maintainer?: string,
  peers: Array<{ name: string; maintainer: string }> = []
): string {
  if (name.startsWith('@')) return `scope:${name.split('/')[0]}`

  const repo = repositoryIdentity(meta?.repository)
  if (repo) return `repo:${repo}`

  const first = nameTokens(name)[0]
  if (first && maintainer) {
    const shared = peers.filter(p =>
      p.name !== name &&
      !p.name.startsWith('@') &&
      p.maintainer === maintainer &&
      nameTokens(p.name)[0] === first
    )
    if (shared.length > 0) return `prefix:${first}`
  }

  return `package:${name}`
}

function repositoryIdentity(repository: unknown): string | null {
  const url = typeof repository === 'string'
    ? repository
    : (repository as { url?: string } | undefined)?.url
  if (!url) return null

  // Everything after the host, minus the git decorations. Two packages pointing
  // at the same GitHub repo are the same project however the URL is spelled.
  const match = /(?:[/:])([^/:]+\/[^/]+?)(?:\.git)?\/?$/.exec(url.replace(/^git\+/, ''))
  return match ? match[1]!.toLowerCase() : null
}

// The null model is per-package, not global. npm publishes ~100k versions a day,
// so any ecosystem-wide rate makes everything look anomalous. Comparing each
// package against its own history instead removes the "busy Tuesday" false
// positive: the baseline is the package's own behaviour.
export function detectCampaigns(
  packuments: Packument[],
  windowMinutes = 60,
  now = Date.now()
): CampaignSignal[] {
  const signals: CampaignSignal[] = [
    // Runs first because it is the one that answers for the packages the rest
    // cannot see at all: a package published today has no own-history to be
    // anomalous against, so every rule below skips it.
    ...detectFabricatedFamilies(packuments, windowMinutes, now),
  ]
  const windowMs = windowMinutes * 60_000

  const anomalousDeltas: CapabilityDeltaEvent[] = []
  const latestOf = new Map<string, VersionMeta>()

  for (const p of packuments) {
    const sorted = sortedVersions(p)
    if (sorted.length < 3) continue   // too little history to call anything anomalous

    const latest = sorted[sorted.length - 1]
    const publishedMs = new Date(latest.publishedAt).getTime()
    if (now - publishedMs > windowMs) continue

    const prev = sorted[sorted.length - 2]
    const currCaps = extractCapabilities(latest)
    const prevCaps = extractCapabilities(prev)
    const newCaps = [...currCaps].filter(c => !prevCaps.has(c)) as Capability[]
    if (newCaps.length === 0) continue

    let historicalCapGains = 0
    let totalDaysCovered = 0

    for (let i = 1; i < sorted.length - 1; i++) {
      const c = extractCapabilities(sorted[i])
      const p2 = extractCapabilities(sorted[i - 1])
      const gained = [...c].filter(x => !p2.has(x)).length
      if (gained > 0) historicalCapGains++

      const daysBetween = (
        new Date(sorted[i].publishedAt).getTime() -
        new Date(sorted[i - 1].publishedAt).getTime()
      ) / (1000 * 60 * 60 * 24)
      totalDaysCovered += daysBetween
    }

    const historicalRate = totalDaysCovered > 0
      ? historicalCapGains / totalDaysCovered
      : 0

    // A package that has never gained a capability has no rate to compare
    // against, so its first gain is treated as maximally anomalous.
    const currentRateMultiplier = historicalRate === 0
      ? Infinity
      : (1 / (windowMinutes / 60 / 24)) / historicalRate

    if (currentRateMultiplier >= 20 || historicalRate === 0) {
      latestOf.set(p.name, latest)
      anomalousDeltas.push({
        package: p.name,
        version: latest.version,
        publishedAt: latest.publishedAt,
        newCapabilities: newCaps,
        maintainer: latest.publishedBy ?? 'unknown',
        entity: '',   // filled in below, once the group it belongs to is known
      })
    }
  }

  if (anomalousDeltas.length === 0) return signals

  // Everything below is already filtered to packages that individually failed
  // their own anomaly test.
  //
  // What separates a coordinated campaign from one team's release afternoon is
  // distinct PARTIES, and a package name is not a party. fwork-jsts-common,
  // fwork-jsts-db, fwork-jsts-server and fwork-react-mui-ext are one repository
  // publishing in a batch; counted as four they cleared the threshold of three
  // and two unrelated packages supplied the maintainer diversity, which is how
  // one monorepo produced forty campaign alerts.
  //
  // Here the maintainer is part of the identity, because the threat model is
  // many independent accounts doing the same unusual thing at once. The
  // fabricated-family detector deliberately does the opposite: see below.
  // No peers passed, so the shared-prefix rule never applies here: two packages
  // called babel-plugin-a and babel-plugin-b from two accounts are two parties,
  // and a name is not evidence against that. The maintainer fallback already
  // collapses a monorepo, because one account publishing the batch is what a
  // monorepo is.
  for (const delta of anomalousDeltas) {
    const collapsed = publishingEntity(delta.package, latestOf.get(delta.package))
    delta.entity = collapsed.startsWith('package:') ? `maintainer:${delta.maintainer}` : collapsed
  }

  const byCapability = new Map<Capability, CapabilityDeltaEvent[]>()
  for (const delta of anomalousDeltas) {
    for (const cap of delta.newCapabilities) {
      if (!byCapability.has(cap)) byCapability.set(cap, [])
      byCapability.get(cap)!.push(delta)
    }
  }

  for (const [cap, events] of byCapability) {
    const entities = [...new Set(events.map(e => e.entity))]
    if (entities.length >= 3) {
      const certainty = Math.min(99, entities.length * 10 + events.length * 2)
      signals.push({
        type: 'coordinated_capability_gain',
        certainty,
        packages: events.map(e => `${e.package}@${e.version}`),
        entities,
        capability: cap,
        windowMinutes,
        description:
          `${events.length} packages from ${entities.length} distinct parties ` +
          `each with a "${cap}" capability gain anomalous for its OWN history, ` +
          `published in the last ${windowMinutes} minutes. Possible campaign.`,
      })
    }
  }

  // Fires on compression in time rather than on a shared capability: a worm that
  // varies its payload still cannot spread slowly.
  const burstEntities = [...new Set(anomalousDeltas.map(d => d.entity))]
  if (anomalousDeltas.length >= 5 && burstEntities.length >= 3) {
    const byTime = [...anomalousDeltas].sort(
      (a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime()
    )
    const firstMs = new Date(byTime[0]!.publishedAt).getTime()
    const lastMs  = new Date(byTime[byTime.length - 1]!.publishedAt).getTime()
    const burstMins = (lastMs - firstMs) / 60_000

    if (burstMins < windowMinutes / 2 && burstEntities.length >= 3) {
      signals.push({
        type: 'velocity_burst',
        certainty: Math.min(95, burstEntities.length * 12),
        packages: anomalousDeltas.map(d => `${d.package}@${d.version}`),
        entities: burstEntities,
        windowMinutes: Math.ceil(burstMins),
        description:
          `${anomalousDeltas.length} packages with individual anomalies, ` +
          `from ${burstEntities.length} distinct parties, ` +
          `in ${burstMins.toFixed(0)} minutes. Worm pattern.`,
      })
    }
  }

  return signals
}

// The detector for the class every rule above is blind to.
//
// detectCampaigns asks whether a package gained a capability that is anomalous
// against its own history. A package published forty seconds ago has no history,
// so it can never be anomalous against it and never reaches the coordination
// test. The lock family — async-critical-section, keyed-mutex-map,
// resource-lease-pool, single-flight-lock and try-lock-runner, five first
// publications inside four minutes, every one of them removed by npm seven hours
// later — went past that detector without touching it, while a monorepo's batch
// release was reported forty times.
//
// So this asks a different question, and every part of it comes from the
// packument that was already fetched:
//
//   the class     no genome, name under 7 days, under 100KB, no repository —
//                 the same four free conditions the gate blocks on
//   the window    all of them published inside it
//   the link      something ties them to each other
//   the count     at least three DISTINCT parties by the naming rules above
//
// The link is where a campaign stops being a coincidence, and it is deliberately
// several things rather than one, because the case that motivated it defeats the
// obvious one: the five names share no token. What they share is a maintainer
// and a single dependency, published two days earlier, that carried the payload
// while the five were lures.
export type FamilyLink = 'maintainer' | 'dependency' | 'token' | 'domain'

export const MIN_FAMILY_ENTITIES = 3
export const MIN_FAMILY_LINKS = 2

interface FamilyMember {
  package: string
  version: string
  publishedAt: string
  maintainer: string
  tokens: string[]
  dependencies: string[]
  meta: VersionMeta
}

export function detectFabricatedFamilies(
  packuments: Packument[],
  windowMinutes = 60,
  now = Date.now()
): CampaignSignal[] {
  const windowMs = windowMinutes * 60_000
  const members: FamilyMember[] = []

  for (const p of packuments) {
    const latest = sortedVersions(p).at(-1)
    if (!latest) continue

    const publishedMs = new Date(latest.publishedAt).getTime()
    if (!Number.isFinite(publishedMs) || now - publishedMs > windowMs) continue

    // A name under seven days old cannot have ninety days of history, so this
    // is the no-genome regime and the observed class in one test. It also
    // survives the window's trimming to three versions, which a version count
    // does not.
    const age = nameAgeDays(p, now)
    if (age === null || age < 0 || age >= YOUNG_NAME_DAYS) continue
    if (!(latest.unpackedSize > 0 && latest.unpackedSize < TINY_PACKAGE_BYTES)) continue
    if (latest.repository) continue

    members.push({
      package: p.name,
      version: latest.version,
      publishedAt: latest.publishedAt,
      maintainer: latest.publishedBy || p.maintainers?.[0]?.name || 'unknown',
      tokens: nameTokens(p.name),
      dependencies: Object.keys(latest.dependencies ?? {}),
      meta: latest,
    })
  }

  if (members.length < MIN_FAMILY_ENTITIES) return []

  // Union-find over the links, so a family held together by a chain — A and B
  // share a maintainer, B and C share a dependency — comes out as one campaign
  // instead of two overlapping ones.
  const parent = new Map<string, string>(members.map(m => [m.package, m.package]))
  const find = (x: string): string => {
    let root = x
    while (parent.get(root) !== root) root = parent.get(root)!
    while (parent.get(x) !== root) { const next = parent.get(x)!; parent.set(x, root); x = next }
    return root
  }
  const union = (a: string, b: string) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb) }

  const linksOf = new Map<string, Set<FamilyLink>>()
  const linkAll = (group: FamilyMember[], link: FamilyLink) => {
    if (group.length < 2) return
    for (let i = 1; i < group.length; i++) union(group[0]!.package, group[i]!.package)
    for (const m of group) {
      if (!linksOf.has(m.package)) linksOf.set(m.package, new Set())
      linksOf.get(m.package)!.add(link)
    }
  }

  for (const group of groupBy(members, m => [m.maintainer])) linkAll(group, 'maintainer')
  // A dependency shared by two brand-new tiny packages published in the same
  // hour. Popular packages are excluded by name: two fabricated packages both
  // depending on lodash have nothing in common.
  for (const group of groupBy(members, m => m.dependencies.filter(d => !isCommonDependency(d)))) {
    linkAll(group, 'dependency')
  }
  for (const group of groupBy(members, m => m.tokens.filter(t => !GENERIC_NAME_TOKENS.has(t)))) {
    linkAll(group, 'token')
  }
  for (const group of groupBy(members, m => lexicalDomains(m.tokens))) linkAll(group, 'domain')

  const components = new Map<string, FamilyMember[]>()
  for (const m of members) {
    const root = find(m.package)
    if (!components.has(root)) components.set(root, [])
    components.get(root)!.push(m)
  }

  const signals: CampaignSignal[] = []

  for (const group of components.values()) {
    if (group.length < MIN_FAMILY_ENTITIES) continue

    // The maintainer is NOT part of the identity here, and that is the whole
    // difference from the detector above. There, one party doing something
    // unusual is a busy afternoon. Here, one party manufacturing five packages
    // in four minutes is the event itself. What still collapses is a naming
    // convention that declares a single family: a shared scope, a shared
    // repository, a shared distinctive prefix.
    const peers = group.map(m => ({ name: m.package, maintainer: m.maintainer }))
    const entities = [...new Set(group.map(m =>
      publishingEntity(m.package, m.meta, m.maintainer, peers)
    ))]
    if (entities.length < MIN_FAMILY_ENTITIES) continue

    // Two independent links, not one. A shared maintainer on its own describes
    // anybody who publishes three small packages in an hour, and on the corpus
    // that is most of what a one-link rule reports. The lock family has four.
    const links = [...new Set(group.flatMap(m => [...(linksOf.get(m.package) ?? [])]))].sort()
    if (links.length < MIN_FAMILY_LINKS) continue
    const byTime = [...group].sort((a, b) => a.publishedAt.localeCompare(b.publishedAt))
    const spanMins =
      (new Date(byTime[byTime.length - 1]!.publishedAt).getTime() -
       new Date(byTime[0]!.publishedAt).getTime()) / 60_000

    // A description of one campaign, not a probability. n=1: the lock family is
    // the only one this has been read against, and a number fitted to it would
    // be a number about it. It rises with parties and with agreeing links
    // because both are harder to arrange, and it stops at 90 because nothing
    // here has been measured against a base rate.
    const certainty = Math.min(90, 45 + (entities.length - MIN_FAMILY_ENTITIES) * 8 + links.length * 7)

    signals.push({
      type: 'fabricated_family',
      certainty,
      packages: group.map(m => `${m.package}@${m.version}`),
      entities,
      windowMinutes: Math.max(1, Math.ceil(spanMins)),
      linkedBy: links,
      description:
        `${group.length} packages from ${entities.length} distinct names, all first ` +
        `publications with no history, under 100KB and with no repository, published ` +
        `in ${spanMins.toFixed(0)} minutes and linked by ${links.join(' + ') || 'nothing but their shape'}. ` +
        `No rule that compares a package against its own past can see this: they do not have one.`,
    })
  }

  return signals
}

// Every group of members sharing at least one of the keys the selector returns.
function groupBy(
  members: FamilyMember[],
  keysOf: (m: FamilyMember) => string[]
): FamilyMember[][] {
  const byKey = new Map<string, FamilyMember[]>()
  for (const m of members) {
    for (const key of keysOf(m)) {
      if (!byKey.has(key)) byKey.set(key, [])
      byKey.get(key)!.push(m)
    }
  }
  return [...byKey.values()].filter(g => g.length > 1)
}

function lexicalDomains(tokens: string[]): string[] {
  const domains: string[] = []
  for (const [domain, vocabulary] of Object.entries(LEXICAL_DOMAINS)) {
    if (tokens.some(t => vocabulary.includes(t))) domains.push(`domain:${domain}`)
  }
  return domains
}

function isCommonDependency(name: string): boolean {
  return COMMON_DEPENDENCIES.has(name) || POPULAR_PACKAGE_NAMES.includes(name)
}

// A campaign is one event. The detector runs every fifty publications over a
// sliding hour, so the same one is re-detected on every pass for as long as its
// members stay in the window: 163 alerts on disk describing 27 campaigns, one of
// them written 19 times. An alert stream where five sixths of the lines are
// repeats is one nobody reads to the end.
//
// So detection and notification are separated. The detector keeps saying what it
// sees, which is correct — it has no memory and should not. The ledger holds one
// record per campaign and reports only what changed: the first sighting, and
// afterwards only a campaign that has grown. A campaign that is merely still
// there updates its record in place and says nothing.
export interface CampaignRecord {
  id: string
  type: CampaignSignal['type']
  capability?: Capability
  firstSeenAt: string
  lastSeenAt: string
  // How many detector passes have seen it. The number that used to be a line
  // each.
  sightings: number
  packages: string[]
  entities: string[]
  certainty: number
  windowMinutes: number
  description: string
  linkedBy?: string[]
  // Records that turned out to be this one and were folded into it.
  sightingsAbsorbed?: number
}

export type CampaignChange = 'new' | 'grown' | null

export interface LedgerUpdate {
  records: CampaignRecord[]
  record: CampaignRecord
  change: CampaignChange
  // Members this pass added, so a "grown" line can say what is new rather than
  // reprinting the whole set.
  added: string[]
}

// Same type, same capability, and at least one package in common. Identity by
// membership rather than by an exact set, because the set is exactly what a
// sliding window changes.
// A campaign nothing has seen for this long is closed. Without it a sliding
// window chains: today's burst shares a member with yesterday's, that one shared
// a member with the day before, and one record grows to hold a week of unrelated
// publications under the first id it was ever given.
export const CAMPAIGN_OPEN_MS = 6 * 3_600_000

export function mergeCampaign(
  records: CampaignRecord[],
  signal: CampaignSignal,
  at: string
): LedgerUpdate {
  const atMs = new Date(at).getTime()
  const isOpen = (r: CampaignRecord) => {
    const last = new Date(r.lastSeenAt).getTime()
    return !Number.isFinite(last) || !Number.isFinite(atMs) || atMs - last <= CAMPAIGN_OPEN_MS
  }

  // Every match, not the first: a signal can span two records that were opened
  // separately and have since turned out to be one campaign. Taking the first
  // and leaving the rest behind would keep re-announcing the orphan forever.
  const matching = records.filter(r =>
    r.type === signal.type &&
    r.capability === signal.capability &&
    isOpen(r) &&
    r.packages.some(p => signal.packages.includes(p))
  )
  const existing = matching[0]

  if (!existing) {
    const record: CampaignRecord = {
      // Deterministic: same first detection, same id, on a restart or a replay.
      // The capability is part of the identity, because it is part of the
      // match below: without it two campaigns over the same packages with
      // different capabilities are two records sharing one id.
      id: `${signal.type}:${signal.capability ?? '-'}:${[...signal.packages].sort()[0] ?? 'empty'}`,
      type: signal.type,
      capability: signal.capability,
      firstSeenAt: at,
      lastSeenAt: at,
      sightings: 1,
      packages: [...signal.packages].sort(),
      entities: [...signal.entities].sort(),
      certainty: signal.certainty,
      windowMinutes: signal.windowMinutes,
      description: signal.description,
      linkedBy: signal.linkedBy,
    }
    return { records: [...records, record], record, change: 'new', added: record.packages }
  }

  const known = new Set(matching.flatMap(r => r.packages))
  const added = signal.packages.filter(p => !known.has(p))
  const absorbed = matching.slice(1)

  const updated: CampaignRecord = {
    ...existing,
    lastSeenAt: at,
    sightings: existing.sightings + 1,
    // Union, never replacement: a member that has aged out of the window was
    // still part of the campaign.
    packages: [...new Set([...known, ...signal.packages])].sort(),
    entities: [...new Set([
      ...matching.flatMap(r => r.entities),
      ...signal.entities,
    ])].sort(),
    certainty: Math.max(...matching.map(r => r.certainty), signal.certainty),
    windowMinutes: Math.max(...matching.map(r => r.windowMinutes), signal.windowMinutes),
    description: added.length > 0 ? signal.description : existing.description,
    linkedBy: [...new Set([
      ...matching.flatMap(r => r.linkedBy ?? []),
      ...(signal.linkedBy ?? []),
    ])].sort(),
    sightingsAbsorbed: (existing.sightingsAbsorbed ?? 0) + absorbed.length,
  }

  const absorbedIds = new Set(absorbed.map(r => r.id))

  return {
    records: records
      .filter(r => !absorbedIds.has(r.id))
      .map(r => (r.id === existing.id ? updated : r)),
    record: updated,
    change: added.length > 0 || absorbed.length > 0 ? 'grown' : null,
    added,
  }
}

export function renderCampaignSignals(signals: CampaignSignal[]): string {
  const RED   = '\x1b[31m'
  const BOLD  = '\x1b[1m'
  const DIM   = '\x1b[2m'
  const RESET = '\x1b[0m'

  const lines: string[] = ['']

  if (signals.length === 0) {
    lines.push(`${DIM}No coordinated-campaign signals in the analysed window.${RESET}`)
    lines.push('')
    return lines.join('\n')
  }

  lines.push(`${RED}${BOLD}CAMPAIGN SIGNALS DETECTED${RESET}`)
  lines.push('')

  for (const signal of signals) {
    lines.push(`${RED}${BOLD}[${signal.certainty}% certainty]${RESET} ${signal.description}`)
    lines.push('')
    lines.push(`  Packages affected (${signal.packages.length}):`)
    for (const pkg of signal.packages.slice(0, 10)) {
      lines.push(`    ${pkg}`)
    }
    if (signal.packages.length > 10) {
      lines.push(`    ${DIM}... and ${signal.packages.length - 10} more${RESET}`)
    }
    lines.push('')
  }

  lines.push(`${DIM}Recommendation: install none of the listed packages ` +
             `until the incident is contained.${RESET}`)
  lines.push('')

  return lines.join('\n')
}
