// Every other module looks at one package. This one looks at the ecosystem.
//
// Thirty unrelated packages gaining their first network capability in the same
// hour are not thirty anomalies — they are one worm. ChainDrop touched 444
// packages in 4 hours; individually each was a medium signal, together they were
// certainty. It runs on the capability deltas that already exist, needs no new
// infrastructure, and catches a campaign on day zero with no prior corpus.

import type { Packument } from './packument.js'
import type { Capability } from './types.js'
import { extractCapabilities } from './genome.js'
import { sortedVersions } from './packument.js'

export interface CapabilityDeltaEvent {
  package: string
  version: string
  publishedAt: string
  newCapabilities: Capability[]
  maintainer: string
}

export interface CampaignSignal {
  type: 'coordinated_capability_gain' | 'velocity_burst' | 'maintainer_wave'
  certainty: number
  packages: string[]
  capability?: Capability
  windowMinutes: number
  description: string
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

// The null model is per-package, not global. npm publishes ~100k versions a day,
// so any ecosystem-wide rate makes everything look anomalous. Comparing each
// package against its own history instead removes the "busy Tuesday" false
// positive: the baseline is the package's own behaviour.
export function detectCampaigns(
  packuments: Packument[],
  windowMinutes = 60
): CampaignSignal[] {
  const signals: CampaignSignal[] = []
  const windowMs = windowMinutes * 60_000
  const now = Date.now()

  const anomalousDeltas: CapabilityDeltaEvent[] = []

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
      anomalousDeltas.push({
        package: p.name,
        version: latest.version,
        publishedAt: latest.publishedAt,
        newCapabilities: newCaps,
        maintainer: latest.publishedBy ?? 'unknown',
      })
    }
  }

  if (anomalousDeltas.length === 0) return []

  // Everything below is already filtered to packages that individually failed
  // their own anomaly test. Distinct maintainers are what separate a coordinated
  // campaign from one maintainer having a busy afternoon.

  const byCapability = new Map<Capability, CapabilityDeltaEvent[]>()
  for (const delta of anomalousDeltas) {
    for (const cap of delta.newCapabilities) {
      if (!byCapability.has(cap)) byCapability.set(cap, [])
      byCapability.get(cap)!.push(delta)
    }
  }

  for (const [cap, events] of byCapability) {
    const distinctMaintainers = new Set(events.map(e => e.maintainer))
    if (events.length >= 3 && distinctMaintainers.size >= 2) {
      const certainty = Math.min(99,
        events.length * 10 + distinctMaintainers.size * 8
      )
      signals.push({
        type: 'coordinated_capability_gain',
        certainty,
        packages: events.map(e => `${e.package}@${e.version}`),
        capability: cap,
        windowMinutes,
        description:
          `${events.length} paquetes de ${distinctMaintainers.size} mantenedores distintos ` +
          `each with a "${cap}" capability gain anomalous for its OWN history, ` +
          `published in the last ${windowMinutes} minutes. Possible campaign.`,
      })
    }
  }

  // Fires on compression in time rather than on a shared capability: a worm that
  // varies its payload still cannot spread slowly.
  if (anomalousDeltas.length >= 5) {
    const byTime = [...anomalousDeltas].sort(
      (a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime()
    )
    const firstMs = new Date(byTime[0].publishedAt).getTime()
    const lastMs  = new Date(byTime[byTime.length - 1].publishedAt).getTime()
    const burstMins = (lastMs - firstMs) / 60_000

    const distinctMaintainers = new Set(anomalousDeltas.map(d => d.maintainer))

    if (burstMins < windowMinutes / 2 && distinctMaintainers.size >= 3) {
      signals.push({
        type: 'velocity_burst',
        certainty: Math.min(95, anomalousDeltas.length * 12),
        packages: anomalousDeltas.map(d => `${d.package}@${d.version}`),
        windowMinutes: Math.ceil(burstMins),
        description:
          `${anomalousDeltas.length} packages with individual anomalies, ` +
          `from ${distinctMaintainers.size} distinct maintainers, ` +
          `in ${burstMins.toFixed(0)} minutes. Worm pattern.`,
      })
    }
  }

  return signals
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
