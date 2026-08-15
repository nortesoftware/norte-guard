import type { SourceInfo } from './source.js'

export type Capability =
  | 'network'
  | 'credential_read'   // ~/.aws, ~/.npmrc, ~/.ssh, env tokens
  | 'exec_external'
  | 'code_download'     // fetch paired with eval or execFile
  | 'fs_write'          // outside the cwd
  | 'native_addon'      // .node binaries or binding.gyp
  | 'install_script'    // preinstall/install/postinstall/prepare

// Where a capability runs decides how much it matters: install_time fires
// without the user importing anything, file_presence fires on mere existence.
export type Surface =
  | 'install_time'
  | 'import_time'
  | 'build_time'
  | 'file_presence'

export interface Signal {
  type: string
  surface: Surface
  capability?: Capability
  score: number
  description: string
  // The capability already existed in earlier versions, so it is baseline
  // behaviour rather than an acquisition. Drives the score discount.
  isHistorical: boolean
  // Scored at 0 because at this layer the signal cannot separate an attack from
  // an ordinary refactor. Kept so the observation survives for the layer that
  // can.
  informational?: boolean
}

export interface InspectResult {
  package: string
  version: string
  analyzedAt: string
  // Where the evidence came from: the live registry or an .ngpack snapshot of a
  // version npm has since purged. A verdict nobody can trace to its origin is
  // not reproducible, whatever the score says.
  source: SourceInfo
  // The instant the age-based signals were measured against, which for a
  // snapshot is when it was captured rather than when this ran.
  evaluatedAsOf: string
  totalScore: number
  signals: Signal[]
  newCapabilities: Capability[]
  historicalCapabilities: Capability[]
  diff: FileDiff
  // Reported so the verdict is falsifiable: the user sees what was never checked.
  coverage: CoverageReport
  baselineVersion: string | null
  verdict: 'BLOCK' | 'WARN' | 'PASS' | 'INSUFFICIENT_HISTORY' | 'UNKNOWN'
  regime: 'genome' | 'no-genome'
}

export interface FileDiff {
  added: string[]
  removed: string[]
  grown: Array<{ file: string; ratio: number }>
  newInstallScripts: string[]
  newBindingGyp: boolean
  newNativeAddon: boolean
}

export interface CoverageReport {
  packumentSignals: number
  tarballs: boolean
  entryPointAnalyzed: boolean
  staticModuleHops: number
  uncoveredDynamicRequires: number
  coveragePercent: number
}

export interface PackageGenome {
  package: string
  computedAt: string
  versionsAnalyzed: number

  // Intersection across every version, not the union — a capability here is
  // baseline behaviour and earns a discount instead of a penalty.
  stableCapabilities: Capability[]

  capabilityHistory: Array<{
    version: string
    publishedAt: string
    capabilities: Capability[]
    delta: Capability[]   // gained relative to the previous version
  }>

  // Median rather than mean, so one oversized release cannot move the baseline.
  sizeBaseline: number

  publishVelocityBaseline: number   // versions per hour

  isMonorepo: boolean
  batchPeers: string[]   // packages this one always publishes alongside
}

export interface ThresholdConfig {
  mode: 'gate' | 'audit'
  blockScore: number
  // The only rule that can block a package with no history, and it does so on a
  // conjunction rather than on a score. See fabricated-profile.ts.
  //
  // On by default since 2026-08-14. It was opt-in while the false-positive cost
  // was unmeasured and no confirmed removal stood behind it; both of those
  // changed on the same day:
  //
  //   4 confirmed removals. async-critical-section@1.0.0, keyed-mutex-map@2.1.2,
  //   resource-lease-pool@1.4.2 and try-lock-runner@3.2.1 were quarantined at
  //   publication with all four free conditions holding, and npm published
  //   0.0.1-security over every one of them seven hours later. The criterion in
  //   watchlist.ts asks for three.
  //
  //   0 confirmed false positives, against a ceiling of one.
  //
  //   0 of 500 in fp-bench's stratified sample could match: the conjunction
  //   needs zero weekly downloads and every package in that sample has some.
  //   The sample is drawn by download rank, which is what a dependency in a real
  //   lockfile looks like.
  //
  // What it costs is 2.65% of the raw publish stream (1,116 of 42,164 scored
  // publications) — but that is the stream, not anybody's dependencies. This
  // fires on a package somebody typed into a package.json today, and
  // `norte-guard approve` is the one-line exit.
  blockFabricatedProfile?: boolean
}

// Gate blocks late to keep CI usable; audit blocks early because a human
// is already reading the output.
export const DEFAULT_THRESHOLDS: Record<'gate' | 'audit', ThresholdConfig> = {
  gate:  { mode: 'gate',  blockScore: 70, blockFabricatedProfile: true },
  audit: { mode: 'audit', blockScore: 40, blockFabricatedProfile: true },
}
