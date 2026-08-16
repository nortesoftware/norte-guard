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
  // Opt-in. It went on by default on 2026-08-14 and came back off on 2026-08-16,
  // and the three things that were taken for evidence are worth keeping written
  // down, because each of them looked like a measurement and none of them was:
  //
  //   "4 confirmed removals." npm did publish 0.0.1-security over
  //   async-critical-section@1.0.0, keyed-mutex-map@2.1.2, resource-lease-pool@1.4.2
  //   and try-lock-runner@3.2.1 — eight of them by now. But they were selected by
  //   the capture filter, which is four conditions, and this rule is five. Not one
  //   of their snapshots carries the weekly download count, so what this rule
  //   would have done with them cannot be established, then or ever: npm serves
  //   one complete week at a time and those weeks have closed. Two criteria were
  //   sharing the name "the four free conditions" and the evidence for one was
  //   being counted for the other.
  //
  //   "0 confirmed false positives, against a ceiling of one." A false positive
  //   is defined as thirty days alive and installed by somebody, and the first
  //   capture was three days old. The zero was the calendar, not the rule. Five
  //   marked packages are already alive with 56 to 332 weekly downloads, and
  //   re-running six of them from their snapshots with the count forced to zero
  //   returns BLOCK on every one: the rule as written would have failed builds
  //   over packages people install.
  //
  //   "0 of 500 in fp-bench's stratified sample could match." True, and it bounds
  //   nothing. That sample is ranked by weekly downloads and the rule needs a name
  //   under seven days old with none: in the 2026-08-16 run, 0 of 500 packages met
  //   either condition. A sample with no candidate in it cannot report a rate for
  //   the rule, and its 0% was being read as one.
  //
  // What would settle it: quarantine captures taken with the download count
  // recorded, aged past the thirty days, with removals outnumbering the packages
  // that turn out to be ordinary. The collector writes the count now; nothing on
  // disk predates that, so the clock starts at the first capture that carries it.
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
  gate:  { mode: 'gate',  blockScore: 70, blockFabricatedProfile: false },
  audit: { mode: 'audit', blockScore: 40, blockFabricatedProfile: false },
}
