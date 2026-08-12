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
  // Off until the false-positive cost is measured. See fabricated-profile.ts:
  // it is the only rule that can block a package with no history, and it does so
  // on a conjunction rather than on a score.
  blockFabricatedProfile?: boolean
}

// Gate blocks late to keep CI usable; audit blocks early because a human
// is already reading the output.
export const DEFAULT_THRESHOLDS: Record<'gate' | 'audit', ThresholdConfig> = {
  gate:  { mode: 'gate',  blockScore: 70 },
  audit: { mode: 'audit', blockScore: 40 },
}
