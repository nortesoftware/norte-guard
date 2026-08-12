// The genome is a deterministic function of public data, so anyone can recompute
// it and get the same answer — norte-guard never asks to be trusted.
// It tracks capabilities rather than sizes: the signal that matters is
// capabilities(v_n) minus capabilities(v_n-1).

import { fetchPackument, sortedVersions, type Packument, type VersionMeta } from './packument.js'
import type { Capability, PackageGenome } from './types.js'
import type { PackageSource } from './source.js'

export function extractCapabilities(v: VersionMeta): Set<Capability> {
  const caps = new Set<Capability>()

  if (v.hasInstallScript) {
    caps.add('install_script')
  }

  // binding.gyp triggers node-gyp rebuild even with no scripts declared, but the
  // packument does not list files. Depending on a native build toolchain is the
  // closest proxy available without downloading the tarball.
  const allDeps = { ...v.dependencies, ...v.devDependencies }
  if ('node-gyp' in allDeps || 'prebuild-install' in allDeps || 'node-pre-gyp' in allDeps) {
    caps.add('native_addon')
  }

  // Same constraint: without the tarball, a declared dependency on a network or
  // exec library is the only evidence the packument carries.
  const networkDeps = ['node-fetch', 'axios', 'got', 'superagent', 'cross-fetch', 'undici']
  if (networkDeps.some(d => d in allDeps)) {
    caps.add('network')
  }

  const execDeps = ['cross-spawn', 'execa', 'shelljs', 'child_process']
  if (execDeps.some(d => d in allDeps)) {
    caps.add('exec_external')
  }

  return caps
}

function publishVelocity(versions: VersionMeta[], windowHours = 24): number {
  if (versions.length < 2) return 0

  const now = Date.now()
  const windowMs = windowHours * 3_600_000
  const recent = versions.filter(v => now - new Date(v.publishedAt).getTime() < windowMs)

  return recent.length / windowHours
}

// Monorepos publish dozens of versions at once, which looks identical to an
// attacker spraying releases. Detecting the pattern is what keeps velocity from
// firing on every Lerna repo in the ecosystem.
function detectMonorepoPattern(p: Packument): { isMonorepo: boolean; avgBatchSize: number } {
  const sorted = sortedVersions(p)
  if (sorted.length < 5) return { isMonorepo: false, avgBatchSize: 1 }

  let batchCount = 0
  let totalBatches = 0

  for (let i = 1; i < sorted.length; i++) {
    const delta = new Date(sorted[i].publishedAt).getTime()
                - new Date(sorted[i-1].publishedAt).getTime()
    if (delta < 5 * 60_000) {   // versions under 5 minutes apart are one release
      batchCount++
    } else {
      if (batchCount > 0) totalBatches++
      batchCount = 0
    }
  }

  const batchRatio = totalBatches / sorted.length
  return {
    isMonorepo: batchRatio > 0.3,
    avgBatchSize: batchRatio > 0.3 ? (batchCount / Math.max(totalBatches, 1)) + 1 : 1,
  }
}

// Takes a source so a genome can be rebuilt from an .ngpack snapshot of a
// version npm has purged. Otherwise a benchmark entry is only reproducible while
// npm keeps serving it, which for the versions that matter was under two hours.
export async function buildGenome(
  packageName: string,
  source?: Pick<PackageSource, 'fetchPackument'>
): Promise<PackageGenome> {
  const packument = source
    ? await source.fetchPackument(packageName)
    : await fetchPackument(packageName)

  return buildGenomeFromPackument(packageName, packument)
}

// For callers that already hold the packument. fp-bench analyses 500 packages
// and would otherwise fetch each twice, doubling the load on a public service
// for data already in memory.
export function buildGenomeFromPackument(
  packageName: string,
  packument: Packument
): PackageGenome {
  const sorted = sortedVersions(packument)

  const capabilityHistory: PackageGenome['capabilityHistory'] = []
  let prevCaps = new Set<Capability>()

  for (const v of sorted) {
    const caps = extractCapabilities(v)
    const delta = [...caps].filter(c => !prevCaps.has(c)) as Capability[]

    capabilityHistory.push({
      version: v.version,
      publishedAt: v.publishedAt,
      capabilities: [...caps] as Capability[],
      delta,
    })

    prevCaps = caps
  }

  // Intersection, not union: only a capability the package has always had earns
  // the "this is normal for it" discount downstream.
  const allVersionCaps = capabilityHistory.map(h => new Set(h.capabilities))
  const stableCapabilities = (
    allVersionCaps.length > 0
      ? [...allVersionCaps[0]].filter(c => allVersionCaps.every(s => s.has(c)))
      : []
  ) as Capability[]

  // Median resists the single 40MB release that would drag a mean baseline up
  // far enough to hide a real size anomaly.
  const sizes = sorted.map(v => v.unpackedSize).filter(s => s > 0).sort((a, b) => a - b)
  const sizeBaseline = sizes[Math.floor(sizes.length / 2)] ?? 0

  // Measured over the last month excluding the newest five versions, so a burst
  // that is itself the attack cannot raise its own baseline.
  const historicalVelocity = publishVelocity(sorted.slice(0, -5), 24 * 30)

  const { isMonorepo } = detectMonorepoPattern(packument)

  return {
    package: packageName,
    computedAt: new Date().toISOString(),
    versionsAnalyzed: sorted.length,
    stableCapabilities,
    capabilityHistory,
    sizeBaseline,
    publishVelocityBaseline: historicalVelocity,
    isMonorepo,
    batchPeers: [],   // filled in by batch analysis
  }
}

export function capabilityDiff(
  current: Set<Capability>,
  historical: Set<Capability>
): { new: Capability[]; removed: Capability[] } {
  return {
    new: [...current].filter(c => !historical.has(c)) as Capability[],
    removed: [...historical].filter(c => !current.has(c)) as Capability[],
  }
}

export function velocityAnomaly(
  packument: Packument,
  version: string,
  genome: PackageGenome
): { ratio: number; windowVersions: number } {
  const sorted = sortedVersions(packument)
  const targetIdx = sorted.findIndex(v => v.version === version)
  if (targetIdx < 0) return { ratio: 0, windowVersions: 0 }

  // Anchored on the target version's own publish time, not on now, so the same
  // verdict comes back whether the version is inspected today or next year.
  const targetTime = new Date(sorted[targetIdx].publishedAt).getTime()
  const windowMs = 3_600_000

  const recentVersions = sorted
    .slice(0, targetIdx + 1)
    .filter(v => targetTime - new Date(v.publishedAt).getTime() < windowMs)

  const currentVelocity = recentVersions.length

  const baseline = genome.publishVelocityBaseline || 0.1   // floor avoids div/0
  const ratio = currentVelocity / baseline

  return { ratio, windowVersions: recentVersions.length }
}

export interface GhostVersion {
  version: string
  publishedAt: string
  ageMs: number
  isRecent: boolean
}

// A version that appears in time{} but not in versions{} was published and then
// pulled — usually by an attacker cleaning up, or by npm taking it down. No
// other tool reads this gap. Real case: @qlik/embed-runtime@1.6.4, Shai-Hulud,
// 4 Aug 2026.
export function detectGhostVersions(p: Packument): GhostVersion[] {
  const ghosts: GhostVersion[] = []
  const now = Date.now()
  const thirtyDaysMs = 30 * 24 * 3600_000

  for (const [ver, ts] of Object.entries(p.time)) {
    if (ver === 'created' || ver === 'modified') continue
    if (ver in p.versions) continue

    const publishedMs = new Date(ts as string).getTime()
    const ageMs = now - publishedMs

    ghosts.push({
      version: ver,
      publishedAt: ts as string,
      ageMs,
      isRecent: ageMs < thirtyDaysMs,
    })
  }

  return ghosts.sort((a, b) => a.ageMs - b.ageMs)
}

// Hand-rolled semver comparison: norte-guard ships no runtime dependencies, and
// only the ordering is needed. Returns null for anything it cannot parse rather
// than guessing, since a wrong order here flips a classification.
export function compareVersions(a: string, b: string): number | null {
  const parse = (v: string) => {
    const [core, ...pre] = v.replace(/\+.*$/, '').split('-')
    const parts = core!.split('.')
    if (parts.length === 0 || parts.some(p => !/^\d+$/.test(p))) return null
    return { release: parts.map(Number), prerelease: pre.join('-') }
  }

  const va = parse(a), vb = parse(b)
  if (!va || !vb) return null

  const len = Math.max(va.release.length, vb.release.length)
  for (let i = 0; i < len; i++) {
    const diff = (va.release[i] ?? 0) - (vb.release[i] ?? 0)
    if (diff !== 0) return diff < 0 ? -1 : 1
  }

  // 1.0.0-rc.1 precedes 1.0.0.
  if (va.prerelease === vb.prerelease) return 0
  if (!va.prerelease) return 1
  if (!vb.prerelease) return -1

  const ia = va.prerelease.split('.'), ib = vb.prerelease.split('.')
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    const x = ia[i], y = ib[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    if (x === y) continue

    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y)
    if (nx && ny) return Number(x) < Number(y) ? -1 : 1
    if (nx) return -1
    if (ny) return 1
    return x < y ? -1 : 1
  }

  return 0
}

// What npm publishes over a package it has taken down. Finding it as the
// replacement for a ghost is not a publisher changing their mind: it is the
// registry removing the package, which is the strongest thing a ghost can mean.
// The previous classifier called these "patch" along with everything else.
const NPM_SECURITY_HOLDER = '0.0.1-security'

export type GhostReversionKind = 'rollback' | 'patch' | 'takedown' | 'unknown'

export interface GhostReversion {
  ghostVersion: string
  before: string | null
  after: string | null
  kind: GhostReversionKind
  detail: string
}

// A ghost cannot be fetched, so the classification has to come from what the
// packument still carries about the versions around it.
//
// This used to compare the dist.integrity of the versions either side of the
// ghost, on the theory that identical bytes meant a rollback. That theory is
// wrong: those are two different releases of a live package, and two different
// releases always differ. Measured over seven hours it returned "patch" 42 times
// and "rollback" zero — it classified nothing.
//
//   pi-mega-compact  ghost 0.10.0, compared 0.9.1 against 0.9.2
//   pgautopilot      ghost 2.0.0,  compared 1.0.0 against 2.0.1
//
// The discriminator is the version order of the replacement. A publisher who
// pulls 0.10.0 and ships 0.9.2 went backwards: the ghost was a mistake. One who
// pulls 2.0.0 and ships 2.0.1 went forwards: something in 2.0.0 had to be
// replaced.
export function classifyGhostReversion(p: Packument, ghostVersion: string): GhostReversion {
  const chronological = Object.entries(p.time)
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .sort(([, a], [, b]) => new Date(a).getTime() - new Date(b).getTime())
    .map(([v]) => v)

  const idx = chronological.indexOf(ghostVersion)
  const unknown = (detail: string): GhostReversion =>
    ({ ghostVersion, before: null, after: null, kind: 'unknown', detail })

  if (idx < 0) return unknown('the ghost version does not appear in time{}')

  // The immediate neighbours may themselves be ghosts, so walk outwards until a
  // version that still exists is found.
  let before: string | null = null
  for (let i = idx - 1; i >= 0; i--) {
    if (chronological[i]! in p.versions) { before = chronological[i]!; break }
  }

  let after: string | null = null
  for (let i = idx + 1; i < chronological.length; i++) {
    if (chronological[i]! in p.versions) { after = chronological[i]!; break }
  }

  // Only `after` decides. It is the version that took the ghost's place; `before`
  // is context.
  if (!after) {
    return { ghostVersion, before, after, kind: 'unknown',
             detail: 'no version after the ghost: nothing has replaced it yet' }
  }

  if (after === NPM_SECURITY_HOLDER) {
    return {
      ghostVersion, before, after, kind: 'takedown',
      detail: `replaced by ${NPM_SECURITY_HOLDER}: npm removed the package, not the publisher`,
    }
  }

  const order = compareVersions(after, ghostVersion)
  if (order === null) {
    return { ghostVersion, before, after, kind: 'unknown',
             detail: `cannot order ${after} against ${ghostVersion}` }
  }

  if (order < 0) {
    return {
      ghostVersion, before, after, kind: 'rollback',
      detail: `${after} replaced ${ghostVersion} with a LOWER number: the publisher went backwards, likely a mistake`,
    }
  }

  if (order > 0) {
    return {
      ghostVersion, before, after, kind: 'patch',
      detail: `${after} replaced ${ghostVersion} moving the number forward: something in ${ghostVersion} had to be replaced`,
    }
  }

  // npm does not let a purged version number be reused, so this should not occur.
  return { ghostVersion, before, after, kind: 'unknown',
           detail: `${after} and ${ghostVersion} are the same version` }
}

// An attacker who knows how the genome works can poison the baseline: ship
// v1.0-v1.20 with an empty install script and a network call to their own CDN,
// then land the real payload in v1.21 with a delta of zero. The three functions
// below make that preparation expensive rather than free.

// Once acquired, a capability never buys back the "never had it" discount, so
// the attacker pays for the setup permanently. Union across history, in contrast
// to the intersection used for stableCapabilities: having held a capability at
// some point is weaker evidence than having always held it, and is scored as
// such.
export function computeEverHadCapabilities(
  history: PackageGenome['capabilityHistory']
): Set<Capability> {
  const union = new Set<Capability>()
  for (const h of history) {
    for (const cap of h.capabilities) union.add(cap)
  }
  return union
}

// A capability only counts as history once it is old enough. An attacker
// starting a campaign today has to wait out the window before the cover
// versions help, which costs time and exposure.
export function getCapabilitiesOlderThan(
  history: PackageGenome['capabilityHistory'],
  minAgeDays: number
): Set<Capability> {
  const cutoff = Date.now() - minAgeDays * 86_400_000
  const old = new Set<Capability>()

  for (const h of history) {
    if (new Date(h.publishedAt).getTime() < cutoff) {
      for (const cap of h.capabilities) old.add(cap)
    }
  }

  return old
}

// History only counts while the account behind it stays the same. After a
// takeover the previous maintainer's track record would otherwise launder the
// new one's first malicious release, so trust restarts at the handover.
export function findTrustResetIndex(
  history: PackageGenome['capabilityHistory'],
  maintainerHistory: Array<{ version: string; maintainer: string }>
): number {
  if (maintainerHistory.length < 2) return 0

  let lastChangeIdx = 0
  let lastMaintainer = maintainerHistory[0]?.maintainer ?? ''

  for (let i = 1; i < maintainerHistory.length; i++) {
    const current = maintainerHistory[i]?.maintainer ?? ''
    if (current !== lastMaintainer) {
      lastChangeIdx = i
      lastMaintainer = current
    }
  }

  const resetVersion = maintainerHistory[lastChangeIdx]?.version
  if (!resetVersion) return 0

  const resetIdx = history.findIndex(h => h.version === resetVersion)
  return resetIdx >= 0 ? resetIdx : 0
}

// Replaces the plain isHistorical flag in the scorer with the four outcomes the
// mitigations above make possible.
export function classifyCapability(
  cap: Capability,
  prevVersion: PackageGenome['capabilityHistory'][0] | undefined,
  genome: PackageGenome,
  trustResetIdx: number
): 'new' | 'returned' | 'historical_recent' | 'historical_old' {
  const MIN_BASELINE_AGE_DAYS = 90

  const wasInPrev = prevVersion?.capabilities.includes(cap) ?? false

  const historyFromReset = genome.capabilityHistory.slice(trustResetIdx)
  const everHad = historyFromReset.some(h => h.capabilities.includes(cap))

  if (!everHad) {
    return 'new'   // never seen since the trust reset — full penalty
  }

  if (!wasInPrev && everHad) {
    return 'returned'   // held, dropped, brought back — the poisoning shape
  }

  const oldCaps = getCapabilitiesOlderThan(historyFromReset, MIN_BASELINE_AGE_DAYS)

  if (oldCaps.has(cap)) {
    return 'historical_old'   // predates the window, so the discount is earned
  }

  return 'historical_recent'   // too young to trust — poisoning may be in progress
}
