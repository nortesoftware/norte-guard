// A package with no history cannot be compared against its own past. It can be
// compared against its peers: the other packages published around it.
//
// The background is built from the delta snapshots the collector already holds —
// tens of thousands of publications, no extra requests — restricted to names of
// the same age. What a legitimate new package looks like is an empirical
// question with an answer on disk, and the answer is the yardstick.
//
// This produces a distance, not a verdict. Whether it separates better than the
// five-condition conjunction is the thing it exists to establish; until it does,
// it scores nothing.

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'

export interface PublicationFeatures {
  package: string
  observedAt: string
  nameAgeDays: number | null
  unpackedSize: number
  dependencies: number
  scripts: number
  hasInstallScript: boolean
  versionCount: number
  // A first version of 1.0.7 claims a history that time{} does not show.
  initialVersionPatch: number | null
  // Null on deltas written before these were recorded. Null is not false: an
  // absent field and an absent repository are different facts.
  hasRepository: boolean | null
  hasDescription: boolean | null
  hasReadme: boolean | null
}

// Everything here comes out of what logPackumentDelta already writes.
export function featuresFromDelta(raw: string): PublicationFeatures | null {
  let delta: {
    name?: string
    capturedAt?: string
    time?: Record<string, string>
    distTags?: Record<string, string>
    hasReadme?: boolean | null
    versionSummaries?: Record<string, {
      scripts?: string[]
      hasInstallScript?: boolean
      unpackedSize?: number
      deps?: number
      hasRepository?: boolean
      hasDescription?: boolean
    }>
  }

  try { delta = JSON.parse(raw) } catch { return null }

  const name = delta.name
  const latest = delta.distTags?.['latest']
  if (!name || !latest) return null

  const summary = delta.versionSummaries?.[latest]
  if (!summary) return null

  const versions = Object.entries(delta.time ?? {})
    .filter(([v]) => v !== 'created' && v !== 'modified')

  const created = delta.time?.['created']
    ?? versions.map(([, ts]) => ts).sort()[0]

  const observedAt = delta.capturedAt ?? ''
  const nameAgeDays = created && observedAt
    ? (new Date(observedAt).getTime() - new Date(created).getTime()) / 86_400_000
    : null

  const firstVersion = versions.sort(([, a], [, b]) => a.localeCompare(b))[0]?.[0]
  const core = firstVersion?.replace(/[+-].*$/, '').split('.')
  const initialVersionPatch = core && core.length >= 3 && /^\d+$/.test(core[2]!)
    ? Number(core[2])
    : null

  return {
    package: name,
    observedAt,
    nameAgeDays: nameAgeDays !== null && Number.isFinite(nameAgeDays) ? nameAgeDays : null,
    unpackedSize: summary.unpackedSize ?? 0,
    dependencies: summary.deps ?? 0,
    scripts: summary.scripts?.length ?? 0,
    hasInstallScript: summary.hasInstallScript === true,
    versionCount: versions.length,
    initialVersionPatch,
    hasRepository: summary.hasRepository ?? null,
    hasDescription: summary.hasDescription ?? null,
    hasReadme: delta.hasReadme ?? null,
  }
}

export function readAllFeatures(outputDir: string): PublicationFeatures[] {
  const deltaDir = join(outputDir, 'deltas')
  if (!existsSync(deltaDir)) return []

  const features: PublicationFeatures[] = []

  for (const file of readdirSync(deltaDir)) {
    const consolidated = file.endsWith('.ndjson.gz')
    if (!consolidated && !file.endsWith('.json.gz')) continue

    try {
      const text = gunzipSync(readFileSync(join(deltaDir, file))).toString()
      if (consolidated) {
        for (const line of text.split('\n')) {
          if (!line.trim()) continue
          const f = featuresFromDelta(line)
          if (f) features.push(f)
        }
      } else {
        const f = featuresFromDelta(text)
        if (f) features.push(f)
      }
    } catch { /* skip */ }
  }

  return features
}

export interface AxisProfile {
  axis: string
  n: number
  // Share of the peer background sitting at the value being scored, which is
  // what makes a deviation rare rather than merely different.
  p50: number
  p90: number
  fractionZero: number
}

export interface PeerBackground {
  n: number
  maxAgeDays: number
  size: AxisProfile
  dependencies: AxisProfile
  withInstallScript: number
  withScripts: number
  singleVersion: number
  impliedHistory: number
  // Counted over the peers that carry the field at all, so deltas written before
  // it existed do not read as absences.
  metadataKnown: number
  withoutRepository: number
  withoutDescription: number
  withoutReadme: number
}

const percentile = (sorted: number[], p: number) =>
  sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))]!

// The peers of a new package are the other new packages, not the registry as a
// whole. Comparing a two-day-old name against lodash measures age, not intent.
export function buildBackground(features: PublicationFeatures[], maxAgeDays = 7): PeerBackground {
  const peers = features.filter(f => f.nameAgeDays !== null && f.nameAgeDays >= 0 && f.nameAgeDays < maxAgeDays)

  const sizes = peers.map(f => f.unpackedSize).filter(s => s > 0).sort((a, b) => a - b)
  const deps = peers.map(f => f.dependencies).sort((a, b) => a - b)

  const axis = (name: string, values: number[], all: number[]): AxisProfile => ({
    axis: name,
    n: values.length,
    p50: percentile(values, 50),
    p90: percentile(values, 90),
    fractionZero: all.length === 0 ? 0 : all.filter(v => v === 0).length / all.length,
  })

  return {
    n: peers.length,
    maxAgeDays,
    size: axis('unpackedSize', sizes, peers.map(f => f.unpackedSize)),
    dependencies: axis('dependencies', deps, deps),
    withInstallScript: peers.filter(f => f.hasInstallScript).length,
    withScripts: peers.filter(f => f.scripts > 0).length,
    singleVersion: peers.filter(f => f.versionCount === 1).length,
    impliedHistory: peers.filter(f => f.versionCount === 1 && (f.initialVersionPatch ?? 0) > 0).length,
    metadataKnown: peers.filter(f => f.hasRepository !== null).length,
    withoutRepository: peers.filter(f => f.hasRepository === false).length,
    withoutDescription: peers.filter(f => f.hasDescription === false).length,
    withoutReadme: peers.filter(f => f.hasReadme === false).length,
  }
}

export interface PeerDistance {
  package: string
  // Each component is the share of peers that are at least this unusual on that
  // axis. Low means rare among peers.
  components: Array<{ axis: string; value: number | string; rarity: number }>
  // Product of the rarities: the share of peers that would match on every axis
  // at once. It is the same conjunction logic as the boolean rule, measured
  // instead of assumed.
  jointRarity: number
}

export function distanceFromPeers(
  feature: PublicationFeatures,
  peers: PublicationFeatures[]
): PeerDistance {
  const n = peers.length || 1

  const rarityBelow = (values: number[], v: number) => values.filter(x => x <= v).length / n
  const sizes = peers.map(f => f.unpackedSize)
  const deps = peers.map(f => f.dependencies)

  const components: PeerDistance['components'] = [
    { axis: 'size', value: feature.unpackedSize, rarity: rarityBelow(sizes, feature.unpackedSize) },
    { axis: 'dependencies', value: feature.dependencies, rarity: rarityBelow(deps, feature.dependencies) },
    {
      axis: 'scripts',
      value: feature.scripts,
      rarity: peers.filter(f => f.scripts <= feature.scripts).length / n,
    },
    {
      axis: 'single version',
      value: feature.versionCount === 1 ? 'yes' : 'no',
      rarity: feature.versionCount === 1 ? peers.filter(f => f.versionCount === 1).length / n : 1,
    },
    {
      axis: 'implied history',
      value: feature.initialVersionPatch ?? 0,
      rarity: (feature.initialVersionPatch ?? 0) > 0
        ? peers.filter(f => f.versionCount === 1 && (f.initialVersionPatch ?? 0) > 0).length / n
        : 1,
    },
  ]

  // Only when the peers carry the field. Scoring metadata absence against a
  // background that never recorded it would compare against nothing.
  const known = peers.filter(f => f.hasRepository !== null)
  if (known.length > 0 && feature.hasRepository !== null) {
    components.push({
      axis: 'no repository',
      value: feature.hasRepository ? 'no' : 'yes',
      rarity: feature.hasRepository ? 1 : known.filter(f => f.hasRepository === false).length / known.length,
    })
  }

  return {
    package: feature.package,
    components,
    jointRarity: components.reduce((a, c) => a * c.rarity, 1),
  }
}
