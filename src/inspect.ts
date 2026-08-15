import { buildGenomeFromPackument } from './genome.js'
import { scoreWithRegime, hasGenomeRegime } from './scorer.js'
import { matchesLocalConjuncts } from './fabricated-profile.js'
import { fetchWeeklyDownloadsWindow } from './downloads.js'
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
  // The instant the verdict is dated to. Half the no-genome signals are ages —
  // "the name is three hours old", "under 90 days of history" — and those are
  // facts about the publication, not about when somebody re-ran the analysis.
  // Left at Date.now() a snapshot's score drifts with the wall clock, which
  // costs .ngpack the one thing it exists to provide. Defaults to the capture
  // time when reading a snapshot, and to now when reading the registry.
  now?: number
}

export interface PackageSpec {
  name: string
  version?: string
}

// Split on the last '@' so scoped names survive: the leading '@' of "@scope/pkg"
// is part of the name, not a version separator. Exported because the CLI has to
// resolve the name against a capture directory before inspect() ever runs.
export function parsePackageSpec(packageSpec: string): PackageSpec {
  const lastAt = packageSpec.lastIndexOf('@')
  const isScoped = packageSpec.startsWith('@')

  if (lastAt > 0 && !(isScoped && lastAt === 0)) {
    return { name: packageSpec.slice(0, lastAt), version: packageSpec.slice(lastAt + 1) }
  }
  return { name: packageSpec }
}

export async function inspect(
  packageSpec: string,
  opts: InspectOptions = {}
): Promise<InspectResult> {
  const config: ThresholdConfig = opts.config ?? DEFAULT_THRESHOLDS[opts.mode ?? 'gate']

  const { name, version } = parsePackageSpec(packageSpec)

  const source: PackageSource = opts.source ?? defaultSource
  const now = opts.now ?? capturedAtMs(source) ?? Date.now()
  const packument = await source.fetchPackument(name)

  const resolvedVersion = version ?? packument.distTags['latest'] ?? Object.keys(packument.versions).pop() ?? ''
  if (!resolvedVersion) throw new Error(`No version found for ${name}`)

  const currentMeta = packument.versions[resolvedVersion]
  if (!currentMeta) throw new Error(`Version ${resolvedVersion} not found for ${name}`)

  // One packument, one genome. Fetching twice spent two requests on the same
  // bytes and gave the two copies a chance to disagree.
  const genome = buildGenomeFromPackument(name, packument, now)

  // The download lookup is paid for only when the four free conditions of the
  // fabricated-profile conjunction already hold, which is 0.75% of the publish
  // stream. Everything else never makes the request.
  //
  // Offline it is not attempted at all. The result is the same as a failed
  // request — unknown, so the rule does not apply — but reached in milliseconds
  // instead of a ten-second timeout per package.
  let weeklyDownloads: number | null | undefined
  let downloadWindowEnd: string | null | undefined
  if (config.blockFabricatedProfile && matchesLocalConjuncts({
    packument, currentMeta, now,
    regime: hasGenomeRegime(genome, now) ? 'genome' : 'no-genome',
  })) {
    // A snapshot answers with the count it recorded, or it does not answer.
    //
    // Falling back to a live query here looks harmless and is not. npm reports
    // one complete week and that week now ends days after the snapshot, so the
    // number describes a different question. Worse, the packages a snapshot is
    // most often asked about are the ones npm has removed, and the downloads
    // endpoint answers 404 for those — which this code maps to zero. The fifth
    // condition would then hold *because* the package was taken down, and a
    // benchmark whose labels are npm takedowns would be measuring its own
    // labels. So: recorded, or unverified.
    const recorded = source.capturedFacts ? source.capturedFacts(name) : null
    if (recorded && recorded.weeklyDownloads !== undefined) {
      weeklyDownloads = recorded.weeklyDownloads
      downloadWindowEnd = recorded.downloadWindowEnd
    } else if (source.sourceInfo.type === 'registry' && !process.env['NORTE_GUARD_OFFLINE']) {
      const counted = await fetchWeeklyDownloadsWindow(name)
      weeklyDownloads = counted ? counted.downloads : null
      downloadWindowEnd = counted?.end
    } else {
      weeklyDownloads = null
    }
  }

  // scoreWithRegime, not score: running the genome rules over a package with no
  // baseline is what let brand-new packages come back PASS from a gate that
  // never examined them.
  const scored = scoreWithRegime({
    packument, version: resolvedVersion, currentMeta, genome, config,
    weeklyDownloads, downloadWindowEnd, now,
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
    // What the verdict was computed against, and as of when. A result read out
    // of context otherwise cannot say whether it came from today's registry or
    // from a snapshot of a version that no longer exists.
    source: source.sourceInfo,
    evaluatedAsOf: new Date(now).toISOString(),
    ...scored,
    diff,
    coverage,
  }
}

function capturedAtMs(source: PackageSource): number | null {
  const capturedAt = source.sourceInfo.capturedAt
  if (!capturedAt) return null
  const ms = new Date(capturedAt).getTime()
  return Number.isFinite(ms) ? ms : null
}
