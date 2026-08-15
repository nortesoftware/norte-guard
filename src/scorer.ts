// Turns signals into a number and a verdict. Signals can score negative, which
// is how trust is expressed: isHistorical means the behaviour is already part of
// the package and the score drops sharply.

import type { Signal, InspectResult as InspectResultType, ThresholdConfig } from './types.js'
import type { PackageGenome } from './types.js'
import type { Packument, VersionMeta } from './packument.js'
import { extractCapabilities, velocityAnomaly } from './genome.js'
import { previousVersion } from './packument.js'
import { absoluteRiskSignals, provenanceLostSignal } from './absolute-risk.js'
import { fabricatedProfile, type FabricatedProfile } from './fabricated-profile.js'

interface ScorerInput {
  packument: Packument
  version: string
  currentMeta: VersionMeta
  genome: PackageGenome
  config: ThresholdConfig
  // No-genome regime only, and only when the caller paid for it.
  dependencyAgeDays?: Record<string, number>
  // Weekly downloads, when the caller paid the request for them. Only the
  // fabricated-profile conjunction reads it, and only when the four free
  // conditions already hold.
  weeklyDownloads?: number | null
  // End of the week that count covers, so the conjunction can report whether the
  // fifth condition measured anything.
  downloadWindowEnd?: string | null
  // The instant the age-based rules are measured against. An .ngpack passes the
  // capture time so a snapshot answers the question as it stood, rather than
  // ageing every sample by however long ago the corpus was collected.
  now?: number
}

export function score(input: ScorerInput): Pick<InspectResultType, 'signals' | 'totalScore' | 'verdict' | 'regime' | 'newCapabilities' | 'historicalCapabilities' | 'baselineVersion'> {
  const { packument, version, currentMeta, genome, config } = input
  const signals: Signal[] = []

  const prevMeta = previousVersion(packument, version)
  const prevCaps = prevMeta ? extractCapabilities(prevMeta) : new Set()
  const currCaps = extractCapabilities(currentMeta)

  const stableSet = new Set(genome.stableCapabilities)
  const baselineVersion = prevMeta?.version ?? null

  // Highest weight in the system: an install script that was never there before
  // runs attacker code on every machine that installs the package.
  if (currentMeta.hasInstallScript && prevMeta && !prevMeta.hasInstallScript) {
    signals.push({
      type: 'new_install_script',
      surface: 'install_time',
      capability: 'install_script',
      score: 45,
      description: 'A preinstall/install/postinstall script appeared in this version (never existed before)',
      isHistorical: false,
    })
  }

  // Scored low but not zero — esbuild and sharp legitimately need this, yet the
  // execution surface is still there if the account is ever taken over.
  if (currentMeta.hasInstallScript && stableSet.has('install_script')) {
    signals.push({
      type: 'historical_install_script',
      surface: 'install_time',
      capability: 'install_script',
      score: 5,
      description: 'Has an install script, but has always had one (esbuild, sharp, and the like)',
      isHistorical: true,
    })
  }

  if (currCaps.has('native_addon') && !prevCaps.has('native_addon')) {
    signals.push({
      type: 'new_native_addon',
      surface: 'file_presence',
      capability: 'native_addon',
      score: 40,
      description: 'New node-gyp/prebuild-install dependency: possible Phantom Gyp vector',
      isHistorical: false,
    })
  }

  // Deactivated at layer 1: scored 0, still recorded. See ENTRYPOINT_LAYER_2.
  if (prevMeta) {
    const movedEntrypoints = ENTRYPOINT_FIELDS.filter(
      f => stableStringify(currentMeta[f]) !== stableStringify(prevMeta[f])
    )

    if (movedEntrypoints.length > 0) {
      signals.push({
        type: 'entrypoint_changed',
        surface: 'import_time',
        score: ENTRYPOINT_LAYER_1_SCORE,
        description:
          `Entry point changed against ${prevMeta.version}: ` +
          movedEntrypoints
            .map(f => `${f} ${summarize(prevMeta[f])} -> ${summarize(currentMeta[f])}`)
            .join('; ') +
          ' - informational, 0 pts (layer 2 is needed to tell an attack from a refactor)',
        isHistorical: false,
        informational: true,
      })
    }
  }

  // Absence of provenance is the registry's normal state and says nothing.
  // Losing it breaks a run this package had already established, and the account
  // credential alone cannot restore it.
  const provenanceLost = provenanceLostSignal(packument, version)
  if (provenanceLost) signals.push(provenanceLost)

  // 10x is deliberately loose: bundling a new asset directory is common, so the
  // threshold only fires where a payload is the likelier explanation.
  if (genome.sizeBaseline > 0 && currentMeta.unpackedSize > 0) {
    const sizeRatio = currentMeta.unpackedSize / genome.sizeBaseline
    if (sizeRatio > 10) {
      signals.push({
        type: 'size_anomaly',
        surface: 'install_time',
        score: Math.min(50, Math.floor(sizeRatio * 3)),
        description: `Size ${sizeRatio.toFixed(1)}x the historical median (${fmtBytes(currentMeta.unpackedSize)} vs baseline ${fmtBytes(genome.sizeBaseline)})`,
        isHistorical: false,
      })
    }
  }

  // Skipped for monorepos, where batch publishing makes this signal fire on
  // every release and drown everything else out.
  const vel = velocityAnomaly(packument, version, genome)
  if (!genome.isMonorepo && vel.ratio > 10) {
    const velScore = Math.min(40, Math.floor(vel.ratio * 1.5))
    signals.push({
      type: 'velocity_anomaly',
      surface: 'install_time',
      score: velScore,
      description: `Publish velocity ${vel.ratio.toFixed(0)}x the historical rate (${vel.windowVersions} versions in 1h)`,
      isHistorical: false,
    })
  }

  // Recorded at near-zero weight to leave a trail: catching an unexpected peer
  // in the batch needs cross-package analysis that does not exist yet.
  if (genome.isMonorepo && vel.windowVersions > 0) {
    signals.push({
      type: 'monorepo_batch',
      surface: 'install_time',
      score: 2,
      description: `Monorepo package: batch velocity is expected. Check the batch holds only its usual peers.`,
      isHistorical: true,
    })
  }

  const newCaps = [...currCaps].filter(c => !prevCaps.has(c))
  for (const cap of newCaps) {
    if (cap !== 'install_script' && cap !== 'native_addon') {   // already scored above
      signals.push({
        type: `new_capability_${cap}`,
        surface: 'install_time',
        capability: cap,
        score: 25,
        description: `Capability "${cap}" appears for the first time in this version`,
        isHistorical: false,
      })
    }
  }

  // The only negative signal. A long release history is expensive to fake, so it
  // buys back enough score to keep well-established packages out of the way.
  const historyLen = genome.versionsAnalyzed
  if (historyLen > 20) {
    signals.push({
      type: 'long_history',
      surface: 'install_time',
      score: -15,
      description: `Maintainer with ${historyLen} versions of history (reduces the score)`,
      isHistorical: true,
    })
  }

  const totalScore = signals.reduce((sum, s) => sum + s.score, 0)
  // WARN at 60% of the block threshold: enough to surface a package for review
  // without failing the build on a single mid-weight signal.
  const totalScoreVerdict = totalScore >= config.blockScore ? 'BLOCK' as const
                : totalScore >= config.blockScore * 0.6 ? 'WARN' as const
                : 'PASS' as const

  return {
    signals,
    totalScore,
    verdict: totalScoreVerdict,
    regime: 'genome' as const,
    newCapabilities: newCaps,
    historicalCapabilities: [...stableSet],
    baselineVersion,
  }
}

function fmtBytes(b: number): string {
  if (b > 1_000_000) return `${(b / 1_000_000).toFixed(1)}MB`
  if (b > 1_000)     return `${(b / 1_000).toFixed(0)}KB`
  return `${b}B`
}

const ENTRYPOINT_FIELDS = ['main', 'exports', 'browser'] as const

// Was 30. Measured against the top 500 by download, a bare main/exports/browser
// delta fires on ordinary maintenance: adding an exports map, splitting CJS from
// ESM, moving dist/. The ESM migration is still in progress across the
// ecosystem, so at layer 1 this is a proxy for "the package modernised" rather
// than "the package was taken over", and 30 points of that is a false-positive
// engine.
//
// The signal it was trying to be needs both halves: the entry point changed AND
// the file it now resolves to carries capabilities the previous one did not.
// That means downloading both tarballs, resolving the entry fields to real files
// and diffing the capabilities reachable from each. Only the conjunction is
// evidence — AsyncAPI/Miasma redirected to a file whose behaviour was new, while
// a CJS→ESM split redirects to one whose behaviour is identical.
//
// Kept at 0 rather than deleted: the observation is cheap, it lands in the JSON
// output and the capture deltas, and layer 2 needs exactly this delta as its
// trigger. What was wrong is charging for it.
const ENTRYPOINT_LAYER_1_SCORE = 0

// Key order in a parsed packument follows whatever the publisher's JSON looked
// like, so a plain JSON.stringify would report reordered-but-identical exports
// maps as a change. Sorting keys makes the comparison about content only.
function stableStringify(value: unknown): string {
  if (value === undefined) return 'undefined'
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'undefined'
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`

  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`
}

// exports maps can be large; the verdict line needs the shape of the change, not
// the whole tree.
function summarize(value: unknown): string {
  if (value === undefined) return '(ausente)'
  const s = stableStringify(value)
  return s.length > 60 ? `${s.slice(0, 57)}...` : s
}

// A brand new package has no baseline, so every capability reads as a delta.
// Absolute risk instead keeps the tool from rubber-stamping newcomers or
// blocking every first release.
const MIN_VERSIONS_FOR_GENOME = 10
const MIN_AGE_DAYS_FOR_GENOME = 90

// Both conditions, not either: 30 versions published in a week is exactly what a
// prepared attacker looks like. Exported so a caller can know which regime a
// package falls into before paying for anything the regime decides.
export function hasGenomeRegime(genome: PackageGenome, now = Date.now()): boolean {
  const ageDays = genome.capabilityHistory.length > 0
    ? (now - new Date(genome.capabilityHistory[0]!.publishedAt).getTime()) / 86_400_000
    : 0

  return genome.versionsAnalyzed >= MIN_VERSIONS_FOR_GENOME && ageDays >= MIN_AGE_DAYS_FOR_GENOME
}

export function scoreWithRegime(input: ScorerInput & { genome: PackageGenome }) {
  const { genome } = input
  const now = input.now ?? Date.now()
  const hasGenome = hasGenomeRegime(genome, now)

  if (!hasGenome) {
    // Two signals inline here meant a quarter of the ecosystem was judged on a
    // score that could take exactly two values.
    const signals = absoluteRiskSignals({
      packument: input.packument,
      currentMeta: input.currentMeta,
      dependencyAgeDays: input.dependencyAgeDays,
      now,
    })

    const absoluteScore = signals.reduce((s, sig) => s + sig.score, 0)

    // The one thing that can block without a history to diff against, because it
    // does not ask about the package's past: it asks whether anything in the
    // ecosystem has ever touched it. A boolean, deliberately not a score — the
    // ceiling for this shape is 26 and no weighting reaches a block threshold
    // without firing on every ordinary new package.
    const profile = fabricatedProfile({
      packument: input.packument,
      currentMeta: input.currentMeta,
      regime: 'no-genome',
      weeklyDownloads: input.weeklyDownloads,
      downloadWindowEnd: input.downloadWindowEnd,
      now,
    })

    if (profile.matches) {
      signals.push({
        type: 'fabricated_package_profile',
        surface: 'install_time',
        score: 0,
        description: profile.reason,
        isHistorical: false,
      })
    } else if (freeConjunctsHold(profile)) {
      // The four free conditions hold and the fifth does not, or could not be
      // established. That is 2.65% of the publish stream, so recording it costs
      // almost nothing, and without it a near-miss is indistinguishable in the
      // output from a package the rule never looked at.
      //
      // The two cases get different types on purpose. "Does not match" is a
      // verdict; "could not be checked" is a gap, and something downstream has
      // to be able to tell a sample the rule cleared from one it never got to
      // judge — otherwise an offline benchmark reports the second as a miss.
      //
      // A rule that was switched off is neither of those. It gets the ordinary
      // type, because 'unverified' is what moves a benchmark sample out of the
      // recall denominator, and a run with the rule disabled must count its
      // misses rather than quietly stop counting.
      const ruleOff = input.config.blockFabricatedProfile !== true

      signals.push({
        type: ruleOff || profile.downloadsChecked
          ? 'fabricated_profile_partial'
          : 'fabricated_profile_unverified',
        surface: 'install_time',
        score: 0,
        description: ruleOff
          ? `Fabricated-package profile: the four free conditions hold. The rule is ` +
            `switched off, so the download count was never requested and nothing follows ` +
            `from this either way.`
          : profile.downloadsChecked
            ? `Fabricated-package profile, 4 of 5 conditions: ${profile.reason}`
            : `Fabricated-package profile: the four free conditions hold and the download ` +
              `count could not be established, so the rule does not apply. This is a gap, ` +
              `not a clearance.`,
        isHistorical: false,
        informational: true,
      })
    }

    const blockedByProfile = profile.matches && input.config.blockFabricatedProfile === true

    return {
      signals,
      totalScore: absoluteScore,
      // Gate reports the missing history instead of blocking, because "new" is
      // not "malicious" and a CI gate that fails on it becomes noise. Audit,
      // read by a human, is allowed to warn. The conjunction above is the single
      // exception, and it is off unless the caller turns it on.
      verdict: (blockedByProfile
        ? 'BLOCK'
        : input.config.mode === 'gate'
        ? 'INSUFFICIENT_HISTORY'
        : absoluteScore >= 20 ? 'WARN' : 'PASS') as InspectResultType['verdict'],
      regime: 'no-genome' as const,
      newCapabilities: [] as import('./types.js').Capability[],
      historicalCapabilities: [] as import('./types.js').Capability[],
      baselineVersion: null,
    }
  }

  const result = score(input)
  return { ...result, regime: 'genome' as const }
}

// The four conditions that cost nothing, read off a profile already computed
// rather than evaluated a second time.
function freeConjunctsHold(profile: FabricatedProfile): boolean {
  const c = profile.conjuncts
  return c.noGenome && c.youngName && c.tiny && c.noRepository
}
