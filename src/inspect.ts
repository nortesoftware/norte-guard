import { buildGenomeFromPackument } from './genome.js'
import { scoreWithRegime, hasGenomeRegime } from './scorer.js'
import { matchesLocalConjuncts } from './fabricated-profile.js'
import { fetchWeeklyDownloads } from './downloads.js'
import { defaultSource, type PackageSource } from './source.js'
import type { InspectResult, ThresholdConfig, FileDiff, CoverageReport } from './types.js'
import { DEFAULT_THRESHOLDS } from './types.js'

export interface InspectOptions {
  mode?: 'gate' | 'audit'
  json?: boolean
  // Overrides the mode defaults. Used to turn on the fabricated-profile rule,
  // which is opt-in.
  config?: ThresholdConfig
  // An .ngpack snapshot instead of the live registry: the versions worth
  // benchmarking are the ones npm has already purged.
  source?: PackageSource
}

export async function inspect(
  packageSpec: string,
  opts: InspectOptions = {}
): Promise<InspectResult> {
  const config: ThresholdConfig = opts.config ?? DEFAULT_THRESHOLDS[opts.mode ?? 'gate']

  // Split on the last '@' so scoped names survive: the leading '@' of
  // "@scope/pkg" is part of the name, not a version separator.
  const lastAt = packageSpec.lastIndexOf('@')
  const isScoped = packageSpec.startsWith('@')

  let name: string
  let version: string | undefined

  if (lastAt > 0 && !(isScoped && lastAt === 0)) {
    name = packageSpec.slice(0, lastAt)
    version = packageSpec.slice(lastAt + 1)
  } else {
    name = packageSpec
  }

  const source = opts.source ?? defaultSource
  const packument = await source.fetchPackument(name)

  const resolvedVersion = version ?? packument.distTags['latest'] ?? Object.keys(packument.versions).pop() ?? ''
  if (!resolvedVersion) throw new Error(`No version found for ${name}`)

  const currentMeta = packument.versions[resolvedVersion]
  if (!currentMeta) throw new Error(`Version ${resolvedVersion} not found for ${name}`)

  // One packument, one genome. Fetching twice spent two requests on the same
  // bytes and gave the two copies a chance to disagree.
  const genome = buildGenomeFromPackument(name, packument)

  // The download lookup is paid for only when the four free conditions of the
  // fabricated-profile conjunction already hold, which is 0.75% of the publish
  // stream. Everything else never makes the request.
  let weeklyDownloads: number | null | undefined
  if (config.blockFabricatedProfile && matchesLocalConjuncts({
    packument, currentMeta, regime: hasGenomeRegime(genome) ? 'genome' : 'no-genome',
  })) {
    weeklyDownloads = await fetchWeeklyDownloads(name)
  }

  // scoreWithRegime, not score: running the genome rules over a package with no
  // baseline is what let brand-new packages come back PASS from a gate that
  // never examined them.
  const scored = scoreWithRegime({
    packument, version: resolvedVersion, currentMeta, genome, config, weeklyDownloads,
  })

  const prevMeta = scored.baselineVersion ? packument.versions[scored.baselineVersion] : null

  // Only the script names are known without the tarball; file-level fields stay
  // empty rather than guessed, so coverage below can report them as unchecked.
  const diff: FileDiff = {
    added: [],
    removed: [],
    grown: [],
    newInstallScripts: currentMeta.hasInstallScript && prevMeta && !prevMeta.hasInstallScript
      ? Object.keys(currentMeta.scripts).filter(k =>
          ['preinstall', 'install', 'postinstall', 'prepare'].includes(k))
      : [],
    newBindingGyp: false,
    newNativeAddon: scored.newCapabilities.includes('native_addon'),
  }

  // Published so a PASS cannot be read as a clean bill of health. The packument
  // alone reaches roughly 55% of the known attack surface; the rest waits on
  // tarball and import-time analysis.
  const coverage: CoverageReport = {
    packumentSignals: scored.signals.length,
    tarballs: false,
    entryPointAnalyzed: false,
    staticModuleHops: 0,
    uncoveredDynamicRequires: 0,
    coveragePercent: 55,
  }

  return {
    package: name,
    version: resolvedVersion,
    analyzedAt: new Date().toISOString(),
    ...scored,
    diff,
    coverage,
  }
}
