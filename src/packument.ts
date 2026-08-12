// Zero external dependencies, only node:https — norte-guard is a supply-chain
// tool, so every dependency it adds is a dependency it asks users to trust.
// The packument alone carries metadata for every version without downloading
// a single tarball, which is why the whole v1 analysis fits in one request.

import https from 'node:https'

const REGISTRY = 'https://registry.npmjs.org'

export interface VersionMeta {
  version: string
  publishedAt: string
  publishedBy: string
  unpackedSize: number
  hasInstallScript: boolean
  scripts: Record<string, string>
  dependencies: Record<string, string>
  devDependencies: Record<string, string>
  // Entry points decide which file actually runs on import, so they are carried
  // through even though they say nothing on their own — the signal is the change.
  main?: string
  browser?: unknown
  exports?: unknown
  dist: {
    tarball: string
    integrity: string
    fileCount?: number
    unpackedSize?: number
    // A signed statement tying this tarball to the commit and CI run that
    // produced it. Its absence means little, since most of the registry predates
    // it, but its presence is one of the few facts an attacker does not control.
    attestations?: { url?: string; provenance?: { predicateType?: string } }
    signatures?: unknown[]
  }
  _npmUser?: { name: string; email: string }
  gitHead?: string
  trustedPublisher?: unknown
  // Cheap to fill in and cheap to fake, so none of them means much alone. A
  // package with none was not published to be read.
  repository?: unknown
  description?: string
  homepage?: string
  license?: unknown
}

export interface Packument {
  name: string
  distTags: Record<string, string>
  versions: Record<string, VersionMeta>
  // Holds entries for versions that no longer exist in versions{} — the basis
  // for ghost-version detection.
  time: Record<string, string>
  maintainers: Array<{ name: string; email: string }>
  // From time.created. For a package with no version history it is the only age
  // there is.
  createdAt?: string
  // A boolean because the text is the largest field in the packument and nothing
  // here reads it.
  hasReadme?: boolean
}

export async function fetchPackument(name: string): Promise<Packument> {
  // Only the part after the scope may be percent-encoded; encoding the '@'
  // makes the registry return 404.
  const encoded = name.startsWith('@')
    ? '@' + encodeURIComponent(name.slice(1))
    : name

  const raw = await get(`${REGISTRY}/${encoded}`)
  return normalizePackument(JSON.parse(raw))
}

// Split out from the fetch because the _changes feed delivers the same document
// shape inline, so the watcher can score a change without asking the registry
// for bytes it was just handed.
export function normalizePackument(data: unknown): Packument {
  const doc = data as Record<string, any>
  const versions: Record<string, VersionMeta> = {}

  for (const [ver, meta] of Object.entries(doc.versions ?? {})) {
    const m = meta as Record<string, unknown>
    const scripts = (m.scripts ?? {}) as Record<string, string>

    const hasInstallScript = ['preinstall', 'install', 'postinstall', 'prepare']
      .some(k => k in scripts)

    versions[ver] = {
      version: ver,
      publishedAt: (doc.time?.[ver] as string) ?? '',
      publishedBy: ((m._npmUser as Record<string, string>)?.name) ?? 'unknown',
      unpackedSize: ((m.dist as Record<string, unknown>)?.unpackedSize as number) ?? 0,
      hasInstallScript,
      scripts,
      dependencies: (m.dependencies ?? {}) as Record<string, string>,
      devDependencies: (m.devDependencies ?? {}) as Record<string, string>,
      main: m.main as string | undefined,
      browser: m.browser,
      exports: m.exports,
      dist: (m.dist ?? {}) as VersionMeta['dist'],
      _npmUser: m._npmUser as VersionMeta['_npmUser'],
      gitHead: m.gitHead as string | undefined,
      trustedPublisher: m.trustedPublisher,
      repository: m.repository,
      description: m.description as string | undefined,
      homepage: m.homepage as string | undefined,
      license: m.license,
    }
  }

  const time = (doc.time ?? {}) as Record<string, string>

  return {
    name: doc.name as string,
    distTags: (doc['dist-tags'] ?? {}) as Record<string, string>,
    versions,
    time,
    maintainers: (doc.maintainers ?? []) as Packument['maintainers'],
    createdAt: time['created'],
    hasReadme: typeof doc.readme === 'string' && doc.readme.trim().length > 0,
  }
}

export interface AbbreviatedPackument {
  name: string
  distTags: Record<string, string>
  modified: string
  versionCount: number
}

// An order of magnitude smaller than the full document: no README, no per-version
// metadata beyond what an installer needs.
//
// A filter, not an analysis input. Without include_docs on the changes feed,
// deciding whether a change is a publication would cost a full packument each —
// around 112 a minute against a public service, most of them for dist-tag edits.
// This answers "did latest move?" for a fraction of the bytes.
//
// It cannot replace the full packument for scoring: it drops per-version publish
// times, and every genome signal is anchored on those.
export async function fetchAbbreviatedPackument(name: string): Promise<AbbreviatedPackument> {
  const encoded = name.startsWith('@')
    ? '@' + encodeURIComponent(name.slice(1))
    : name

  const raw = await get(`${REGISTRY}/${encoded}`, 'application/vnd.npm.install-v1+json')
  const data = JSON.parse(raw) as Record<string, any>

  return {
    name: (data.name as string) ?? name,
    distTags: (data['dist-tags'] ?? {}) as Record<string, string>,
    modified: (data.modified as string) ?? '',
    versionCount: Object.keys(data.versions ?? {}).length,
  }
}

// Ordered by publish time rather than semver, because an attacker controls the
// version string but not when the registry recorded the upload.
export function sortedVersions(p: Packument): VersionMeta[] {
  return Object.values(p.versions).sort(
    (a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime()
  )
}

export function previousVersion(p: Packument, version: string): VersionMeta | null {
  const sorted = sortedVersions(p)
  const idx = sorted.findIndex(v => v.version === version)
  return idx > 0 ? sorted[idx - 1] : null
}

function get(url: string, accept = 'application/json'): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'Accept': accept,
        'User-Agent': 'norte-guard/0.1.0 (security analysis)',
      },
      timeout: 10_000,
    }, res => {
      if (res.statusCode === 404) {
        reject(new Error(`Package not found: ${url}`))
        return
      }
      if ((res.statusCode ?? 0) >= 400) {
        reject(new Error(`HTTP ${res.statusCode}: ${url}`))
        return
      }

      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => chunks.push(chunk))
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')))
      res.on('error', reject)
    })
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy()
      reject(new Error(`Timeout fetching: ${url}`))
    })
  })
}
