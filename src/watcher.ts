// Watches npm for what the registry does not keep: exact unpublish times, and
// metadata as it looked when it was first served.
//
// The source is the _changes cursor, with RSS as a fallback. Disappearances give
// a real time-to-removal rather than a proxy, and packument deltas are logged
// because they cost kilobytes and turn the feed into a re-scorable corpus:
// December's detector can analyse what August's could not see. Tarballs are only
// kept above the capture budget, since those cost megabytes and carry live
// malware.

import https from 'node:https'
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import {
  fetchPackument,
  fetchAbbreviatedPackument,
  normalizePackument,
  type Packument,
} from './packument.js'
import { buildGenomeFromPackument, detectGhostVersions, classifyGhostReversion } from './genome.js'
import { sortedVersions } from './packument.js'
import { detectCampaigns, mergeCampaign, type CampaignRecord } from './ecosystem.js'
import { scoreWithRegime } from './scorer.js'
import { createNgpack, writeCaptureMetadata, labelCapture, type CaptureComposition } from './ngpack.js'
import { NPM_SECURITY_HOLDER } from './takedown.js'
import { fetchWeeklyDownloadsWindow } from './downloads.js'
import { classifyPublication, compactMarkers, YOUNG_NAME_DAYS, TINY_PACKAGE_BYTES, type ClassMarkers } from './observed-class.js'
import { windowCovers } from './fabricated-profile.js'
import { rotateLogs } from './log-rotation.js'
import { storeStats } from './object-store.js'
import { PlatformFamilyTracker } from './platform-family.js'
import {
  DailyCaptureBudget,
  directorySize,
  formatBytes,
  rotateCaptures,
  sweepQuarantine,
  DEFAULT_DAILY_BYTES,
  DEFAULT_TOTAL_BYTES,
  DEFAULT_QUARANTINE,
  DEFAULT_MAX_CAPTURE_BYTES,
  QUARANTINE_REASON,
  type QuarantinePolicy,
} from './capture-budget.js'
import { engineVersion } from './fp-bench-store.js'
import { DEFAULT_THRESHOLDS } from './types.js'
import {
  streamChanges,
  probeCapabilities,
  loadLastSeq,
  saveLastSeq,
  ChangesFeedFailure,
  type Seq,
  type ChangeEvent,
} from './changes-feed.js'

const RSS_URL = 'https://registry.npmjs.org/-/rss'

// Matches the feed's own max-age, so polling faster would only re-read a cached
// response.
const POLL_INTERVAL_MS = 60_000

// The feed carries every document update, not just publications: dist-tag moves,
// maintainer edits, README changes. Only a fresh version publish is scored,
// which is the set RSS carried, except this one cannot silently drop any of it.
const PUBLISH_WINDOW_MS = 15 * 60_000

// How much disk and bandwidth this collector will spend, expressed as a score
// cut-off. Not a detection threshold, which is the reason for the name.
//
// It was briefly derived from the p99 of the publication stream. That is
// circular: a campaign in progress raises the scores in the stream, raising the
// percentile, raising the cut-off, so the collector relaxes itself on the day it
// should not. A percentile of the live stream only says what is normal right
// now, and that is the thing an attack changes.
//
// So it is fixed, chosen for cost, and never recomputed from the feed. Raising
// it buys disk, lowering it buys corpus, and neither changes what norte-guard
// detects — that is the scorer and the thresholds in types.ts.
//
// One cut-off per regime, because the two regimes score on different scales and
// the interesting class lives in the lower one.
//
// Under the genome regime a real anomaly scores hard: a new install script alone
// is 45. Under no-genome the ceiling is around 26 for a package with no install
// script, and the two takedowns this collector observed before npm removed them
// scored 26 and 20. A single cut-off at 50 kept the loud packages and threw away
// exactly the class that later turned out to be malware.
export interface CaptureBudgetThresholds {
  genome: number
  noGenome: number
}

export const DEFAULT_CAPTURE_BUDGET: CaptureBudgetThresholds = {
  genome: 50,
  noGenome: 20,
}

export function budgetFor(
  threshold: number | CaptureBudgetThresholds,
  regime: string
): number {
  if (typeof threshold === 'number') return threshold
  return regime === 'no-genome' ? threshold.noGenome : threshold.genome
}

// Sequence numbers behind the tip before it is worth saying so. The lag grew
// 20 → 26 → 92 → 103 across runs, which is a trend rather than noise even though
// none of those is dangerous on its own.
export const DEFAULT_LAG_ALERT = 150

export interface WatcherConfig {
  outputDir: string
  // Score at or above which a tarball is worth its disk. Budget, not detection.
  captureBudgetThreshold: number | CaptureBudgetThresholds
  verbose: boolean
  // 'rss' stays reachable so the degraded mode can be exercised deliberately
  // rather than only during an outage.
  feed?: 'changes' | 'rss'
  publishWindowMs?: number
  concurrency?: number
  // Hard stop on bytes downloaded per UTC day. The score cut-off bounds which
  // packages are captured, not what they weigh.
  dailyByteBudget?: number
  // Total size of captures/ before the oldest unconfirmed ones are rotated out.
  maxCaptureBytes?: number
  // The largest package the SCORE path will download the bytes of, by the
  // unpacked size the packument declares. Quarantine has its own, smaller, cap.
  maxCaptureUnpackedBytes?: number
  lagAlertThreshold?: number
  familyWindowMs?: number
  quarantine?: Partial<QuarantinePolicy>
}

let familyTracker = new PlatformFamilyTracker()
let budget: DailyCaptureBudget | undefined

// Persisted so a crash costs nothing: the next run resumes from the newest
// publish it already handled instead of replaying or skipping the window.
function loadLastPubDate(dir: string): number {
  const p = join(dir, '.last_pubdate')
  if (!existsSync(p)) return 0
  const parsed = Number(readFileSync(p, 'utf-8').trim())
  return Number.isFinite(parsed) ? parsed : 0
}

function saveLastPubDate(dir: string, ms: number): void {
  writeFileSync(join(dir, '.last_pubdate'), String(ms))
}

// In-memory only: rebuilt from the feed after a restart, a disappearance would
// be indistinguishable from a package never seen.
const knownVersions = new Map<string, Set<string>>()

// The feed is a rolling window, so consecutive polls overlap heavily. Keyed by
// name and publish time so a repeated entry is skipped while a genuine republish
// of the same package still gets analysed.
const processed = new Map<string, number>()

// Names from the previous poll. Overlap between consecutive windows is what says
// whether the feed was read fast enough to be continuous.
let previousWindow = new Set<string>()

// A watcher that silently drops publications produces a corpus that looks
// complete, so the gap between what npm published and what was scored is printed
// rather than left to inference.
const coverage = {
  polls: 0,
  feedEntries: 0,
  fresh: 0,
  analyzed: 0,
  unreachable: 0,
  windowRollovers: 0,
  // A jump in the sequence is the only observable that could reveal a lost
  // change, so it is counted whether or not it turns out to be benign.
  changes: 0,
  seqGaps: 0,
  seqMissing: 0,
  reconnects: 0,
  deletions: 0,
  skippedNonPublish: 0,
  rewinds: 0,
  maxLag: 0,
  lastLag: 0,
  lagAlerts: 0,
  coalesced: 0,
  familyRedundant: 0,
  overBudget: 0,
  tarballRefusedForSize: 0,
  capturedBytes: 0,
  quarantined: 0,
  quarantineExpired: 0,
  campaigns: 0,
  quarantineRejects: {
    withGenome: 0,
    oldName: 0,
    tooLarge: 0,
    withRepository: 0,
    overCaptureCap: 0,
    accepted: 0,
  },
  unreachableByReason: {} as Record<string, number>,
}

// The age of the name, which is what decides whether a package is in the class
// quarantine is for.
function packageAgeDays(p: Packument, now = Date.now()): number {
  const created = p.createdAt ?? Object.entries(p.time ?? {})
    .filter(([v]) => v !== 'created' && v !== 'modified')
    .map(([, ts]) => ts)
    .sort()[0]

  if (!created) return Infinity
  const ms = now - new Date(created).getTime()
  return Number.isFinite(ms) ? ms / 86_400_000 : Infinity
}

export interface FeedItem {
  name: string
  pubDate: string
  publishedMs: number
}

export function feedItemKey(item: FeedItem): string {
  return `${item.name}|${item.publishedMs}`
}

// These two decide what the corpus covers, so they live out here as pure
// functions rather than being observable only by running against the live feed.
export function selectFreshItems(
  items: FeedItem[],
  lastSeenMs: number,
  seen: ReadonlyMap<string, number>
): FeedItem[] {
  return items.filter(i => i.publishedMs >= lastSeenMs && !seen.has(feedItemKey(i)))
}

// Overlap is measured by name rather than by timestamp because the feed's dates
// span weeks and cannot bound the window. Zero shared names means everything
// that fell off between reads was never seen.
export function computeWindowOverlap(
  previous: ReadonlySet<string>,
  current: ReadonlySet<string>
): { overlap: number; rolledOver: boolean } {
  const overlap = [...current].filter(n => previous.has(n)).length
  return { overlap, rolledOver: previous.size > 0 && overlap === 0 }
}

// Hand-rolled: norte-guard ships zero runtime dependencies, and pulling an XML
// parser into a supply-chain tool would be its own argument against it. The feed
// is a fixed machine-generated shape, not arbitrary XML.
export function parseRssItems(xml: string): FeedItem[] {
  const items: FeedItem[] = []

  for (const block of xml.match(/<item>[\s\S]*?<\/item>/g) ?? []) {
    // Every value in this feed is CDATA-wrapped; the plain form is a fallback.
    const title = block.match(/<title>\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*<\/title>/)
               ?? block.match(/<title>([^<]*)<\/title>/)
    if (!title) continue

    const name = title[1]!.trim()
    if (!name) continue

    const pubDate = block.match(/<pubDate>([^<]*)<\/pubDate>/)?.[1]?.trim() ?? ''
    const parsed = pubDate ? new Date(pubDate).getTime() : NaN

    items.push({
      name,
      pubDate,
      publishedMs: Number.isFinite(parsed) ? parsed : 0,
    })
  }

  return items
}

function fetchRss(): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(RSS_URL, {
      headers: {
        'Accept': 'application/rss+xml',
        'User-Agent': 'norte-guard-watcher/0.1.0',
      },
      timeout: 15_000,
    }, res => {
      if ((res.statusCode ?? 0) >= 400) {
        reject(new Error(`HTTP ${res.statusCode}: ${RSS_URL}`))
        res.resume()
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
      reject(new Error(`Timeout fetching: ${RSS_URL}`))
    })
  })
}

interface TtrEvent {
  package: string
  version: string
  publishedAt: string
  unpublishedAt: string   // when the watcher saw it vanish, not when npm removed it
  ttrMinutes: number
  // The removal happened between two polls, so the measurement is only as sharp
  // as the interval. Recorded alongside because a bare "285min" invites more
  // precision than was ever measured, and a later reader cannot recover it.
  pollIntervalSeconds: number
  resolutionMinutes: number
}

// Ceiling of one interval: the true unpublish time cannot be further from the
// measurement than the gap between the two polls that bracketed it.
const TTU_RESOLUTION_MINUTES = Math.max(1, Math.ceil(POLL_INTERVAL_MS / 60_000))

function logTtr(dir: string, event: TtrEvent): void {
  const logPath = join(dir, 'ttr-log.ndjson')
  writeFileSync(logPath, JSON.stringify(event) + '\n', { flag: 'a' })
  console.log(
    `TTU: ${event.ttrMinutes}min +/-${event.resolutionMinutes}min ` +
    `(poll interval: ${event.pollIntervalSeconds}s) - ` +
    `${event.package}@${event.version} ` +
    `(published ${event.publishedAt.slice(11,16)}, ` +
    `unpublish seen ${event.unpublishedAt.slice(11,16)})`
  )
}

function logPackumentDelta(dir: string, name: string, p: Packument, feedPubDate: string): void {
  const deltaDir = join(dir, 'deltas')
  mkdirSync(deltaDir, { recursive: true })

  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  const safeName = name.replace(/[@/]/g, '_')

  // Only the newest versions are summarised. Rewriting the full history into
  // every record meant a package with 500 versions wrote 500 summaries per
  // publish, which on this feed is the difference between kilobytes a day and
  // gigabytes. time{} is kept whole: it is small, and it is the ghost evidence.
  const recentVersions = Object.entries(p.versions)
    .sort(([, a], [, b]) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
    .slice(0, 5)

  const delta = {
    name,
    feedPubDate,
    capturedAt: new Date().toISOString(),
    distTags: p.distTags,
    time: p.time,
    maintainers: p.maintainers,
    totalVersions: Object.keys(p.versions).length,
    // Presence flags, not contents. The peer profile could not tell
    // prezdentkxheiw from an ordinary new package because these three were the
    // difference and the delta did not carry them. A boolean each costs nothing.
    hasReadme: p.hasReadme ?? null,
    versionSummaries: Object.fromEntries(
      recentVersions.map(([v, m]) => [v, {
        scripts: Object.keys(m.scripts ?? {}),
        hasInstallScript: m.hasInstallScript,
        unpackedSize: m.unpackedSize,
        deps: Object.keys(m.dependencies ?? {}).length,
        hasRepository: Boolean(m.repository),
        hasDescription: Boolean(m.description),
      }])
    ),
  }

  try {
    writeFileSync(
      join(deltaDir, `${ts}_${safeName}.json.gz`),
      gzipSync(Buffer.from(JSON.stringify(delta)))
    )
  } catch {
    // Losing one delta must never take down the watcher.
  }
}

function checkDisappearances(dir: string, name: string, p: Packument): void {
  const currentVersions = new Set(Object.keys(p.versions))
  const prev = knownVersions.get(name)

  if (prev) {
    for (const ver of prev) {
      if (!currentVersions.has(ver)) {
        // Still in time{} after leaving versions{}: the only remaining record
        // that the version existed.
        const publishedAt = p.time[ver]

        if (publishedAt) {
          const now = new Date().toISOString()
          const ttrMin = Math.round(
            (new Date(now).getTime() - new Date(publishedAt).getTime()) / 60_000
          )
          logTtr(dir, {
            package: name,
            version: ver,
            publishedAt,
            unpublishedAt: now,
            ttrMinutes: ttrMin,
            pollIntervalSeconds: POLL_INTERVAL_MS / 1000,
            resolutionMinutes: TTU_RESOLUTION_MINUTES,
          })
        }
      }
    }
  }

  knownVersions.set(name, currentVersions)
}

async function analyzePackage(
  name: string,
  config: WatcherConfig,
  feedPubDate: string,
  // Supplied when the feed delivers the document inline. Re-fetching would spend
  // a request on bytes already in hand and read a later state than the one the
  // sequence number refers to.
  provided?: Packument
): Promise<AnalysisResult> {
  let packument: Packument
  // Returned whether or not the version was captured: the scores below the
  // budget are what say what the budget costs.
  let scored: ScoredPublication | undefined

  if (provided) {
    packument = provided
  } else {
    try {
      packument = await fetchPackument(name)
    } catch (e) {
      // Private, or unpublished between the feed and this fetch. The reason is
      // recorded because 5% of publications landing here is either noise or a
      // real coverage hole, and the count alone cannot say which.
      return { outcome: 'unreachable', unreachableReason: classifyFetchFailure(e) }
    }
  }

  // Both run unconditionally: cheap once the packument is in hand, and their
  // value is in being unbroken series.
  checkDisappearances(config.outputDir, name, packument)
  logPackumentDelta(config.outputDir, name, packument, feedPubDate)

  const latestVersion = packument.distTags['latest']
  if (!latestVersion) return { outcome: 'analyzed' }

  const currentMeta = packument.versions[latestVersion]
  if (!currentMeta) return { outcome: 'analyzed' }

  try {
    const genome = buildGenomeFromPackument(name, packument)

    // Audit thresholds: this is a forensic collector, not a CI gate. Most of
    // what the feed carries is a first publication, scored on absolute risk
    // rather than on a delta against a baseline that does not exist.
    const result = scoreWithRegime({
      packument,
      version: latestVersion,
      currentMeta,
      genome,
      config: DEFAULT_THRESHOLDS.audit,
    })

    // A recent ghost is the strongest single indicator available here, so it is
    // added on top of the score rather than left to the renderer.
    const ghosts = detectGhostVersions(packument)
    const recentGhost = ghosts.find(g => g.isRecent)
    const effectiveScore = result.totalScore + (recentGhost ? 20 : 0)

    const threshold = budgetFor(config.captureBudgetThreshold, result.regime)

    // Two independent reasons to keep a tarball. The score means "this looks
    // alarming now"; quarantine means "this is the class that turns out to be
    // malware later, and a week of disk is what it costs to find out".
    const quarantine = { ...DEFAULT_QUARANTINE, ...config.quarantine }
    const markers = classifyPublication(packument, currentMeta, result.regime)

    // Filtered by the shape of the class, not only capped by size. New packages
    // that are large are not what was observed, and keeping them was what turned
    // quarantine into 172MB a minute.
    // Counted per condition. Zero captures is consistent with a prevalence of
    // 0.75% and equally consistent with a filter that is simply broken, and the
    // two are only told apart by knowing which condition rejected what.
    if (quarantine.enabled && effectiveScore < threshold) {
      // The three conjuncts first, in the order they exclude. `withGenome` is
      // now the residual and reads 0 by construction: `young` entails
      // `noGenome`, so nothing reaches that branch. It is kept, and kept last,
      // because a counter that stays at zero in production is the cheapest
      // standing proof that the conjunct removed from the definition really did
      // exclude nothing — and the day it moves, the entailment has broken.
      if (!markers.young) coverage.quarantineRejects.oldName++
      else if (!markers.tiny) coverage.quarantineRejects.tooLarge++
      else if (markers.hasRepository) coverage.quarantineRejects.withRepository++
      else if (!markers.noGenome) coverage.quarantineRejects.withGenome++
      else if (currentMeta.unpackedSize > quarantine.maxBytes) coverage.quarantineRejects.overCaptureCap++
      else coverage.quarantineRejects.accepted++
    }

    const quarantined = quarantine.enabled
      && markers.inClass
      && currentMeta.unpackedSize <= quarantine.maxBytes
      && effectiveScore < threshold

    scored = {
      score: effectiveScore,
      regime: result.regime,
      verdict: result.verdict,
      captured: effectiveScore >= threshold || quarantined,
      markers,
    }

    // A rollback and an incident both leave a ghost behind. The integrity hashes
    // either side of it separate the two without downloading anything.
    const reversion = recentGhost
      ? classifyGhostReversion(packument, recentGhost.version)
      : null

    if (config.verbose || effectiveScore >= threshold) {
      const mark = result.verdict === 'BLOCK' ? 'BLOCK'
                 : recentGhost ? 'GHOST'
                 : '     '
      console.log(
        `${mark} ${name}@${latestVersion}`.padEnd(48),
        `score=${effectiveScore}`.padEnd(12),
        recentGhost ? `[GHOST:${recentGhost.version} ${reversion!.kind}]` : ''
      )
      if (reversion && reversion.kind !== 'unknown') {
        console.log(`        ${reversion.detail}`)
      }
    }

    // Tarballs are only worth their disk cost above the threshold, and an
    // unpublish can make them unobtainable within the hour.
    if (effectiveScore >= threshold || quarantined) {
      const now = Date.now()

      // One release published as eleven platform packages is one event. The
      // other ten cost disk and add nothing.
      const family = familyTracker.decide(name, latestVersion, now)
      if (family.redundant) {
        coverage.familyRedundant++
        console.log(
          `platform family: ${name}@${latestVersion} is the same release as ` +
          `${family.capturedMember}, not captured`
        )
        return { outcome: 'analyzed', scored }
      }

      if (budget?.exhausted) {
        budget.recordSkip()
        coverage.overBudget++
        if (coverage.overBudget === 1 || coverage.overBudget % 25 === 0) {
          console.error(
            `DAILY BUDGET EXHAUSTED: ${formatBytes(budget.spent)} of ` +
            `${formatBytes(budget.dailyBytes)}. ${coverage.overBudget} captures skipped today. ` +
            `The feed is still enumerated and scored; only tarball downloads stop.`
          )
        }
        return { outcome: 'analyzed', scored }
      }

      // Too large to be worth its bytes on the score path. The packument is
      // captured anyway and the refusal is recorded on it: the package stays in
      // every population and every denominator, and only the tarball is
      // declined. Quarantine is never refused here — it has its own cap, and
      // the class it selects is under 100KB by definition.
      const unpackedCap = config.maxCaptureUnpackedBytes ?? DEFAULT_MAX_CAPTURE_BYTES
      const refuseTarball = !quarantined && currentMeta.unpackedSize > unpackedCap

      const safeName = name.replace(/[@/]/g, '_')
      const dir = join(config.outputDir, 'captures', `${safeName}@${latestVersion}_${now}`)
      console.log(
        refuseTarball
          ? `PACKUMENT ONLY ${name}@${latestVersion} (${formatBytes(currentMeta.unpackedSize)} unpacked, cap ${formatBytes(unpackedCap)})`
          : `${quarantined ? 'QUARANTINE' : 'CAPTURED'} ${name}@${latestVersion}`
      )
      if (refuseTarball) coverage.tarballRefusedForSize++
      try {
        await createNgpack(name, dir, {
          // An empty list captures the packument and no bytes.
          versions: refuseTarball ? [] : [latestVersion],
          objectStore: join(config.outputDir, 'captures'),
        })

        // Written with every capture, never later: a snapshot with no metadata
        // loses the score and the reason it was kept, which is the only evidence
        // anyone would have to confirm or clear it.
        //
        // 'unconfirmed' is not a placeholder awaiting an upgrade. Only an npm
        // advisory, a public report, or content analysis promotes it.
        // Structured, not only prose in `notes`. A count of captures cannot say
        // whether 4.6GB is corpus or noise; this is what the breakdown reads.
        const composition: CaptureComposition = {
          regime: result.regime,
          signals: result.signals.map(s => s.type),
          firstPublication: Object.keys(packument.versions).length <= 1,
          ghost: recentGhost ? recentGhost.version : null,
          ghostKind: reversion?.kind ?? null,
          newInstallScript: result.signals.some(
            s => s.type === 'new_install_script' || s.type === 'absolute_install_script'
          ),
          platformFamily: family.family?.base ?? null,
        }

        // npm reports one week at a time and the count for the week a package
        // was published in stops being answerable a week later. The
        // fabricated-profile conjunction needs exactly that number, so a capture
        // that does not carry it is a snapshot that cannot reproduce its own
        // verdict — which is the whole point of taking one.
        //
        // Asked only for captures of the observed class, which is the only
        // shape the conjunction can apply to: 2.65% of the stream, the same
        // budget the rule already assumes.
        const counted = markers.inClass ? await fetchWeeklyDownloadsWindow(name) : null

        writeCaptureMetadata(dir, {
          package: name,
          version: latestVersion,
          capturedAt: new Date().toISOString(),
          score: effectiveScore,
          label: 'unconfirmed',
          weeklyDownloads: counted ? counted.downloads : (markers.inClass ? null : undefined),
          downloadWindowEnd: counted?.end ?? undefined,
          // Recorded now because it cannot be recomputed later: it needs both
          // the packument and the week npm reported on, and the second is gone
          // within days. False for a 404 — there is no window to overlap, and a
          // zero with no window is what npm says about a name it has never heard
          // of, which is what it says about most of this class.
          downloadWindowCovers: markers.inClass
            ? (counted && !counted.synthesizedFrom404
                ? windowCovers(packument, counted.end, now)
                : false)
            : undefined,
          // Which engine selected a sample is part of the sample: a corpus
          // collected by a detector with a known bug is a draw from what that
          // bug flagged, and a benchmark cannot correct for what it cannot see.
          captureReason: quarantined ? QUARANTINE_REASON : 'watcher-threshold',
          // The capture reason says which filter selected it; this says what
          // was kept. Both are needed: a denominator built from the first alone
          // would count a packument-only capture as a package that was looked
          // at.
          tarballRefused: refuseTarball
            ? { reason: 'over-capture-cap' as const, unpackedSize: currentMeta.unpackedSize, capBytes: unpackedCap }
            : undefined,
          engineVersion: engineVersion(),
          retainUntil: quarantined
            ? new Date(now + quarantine.retentionDays * 86_400_000).toISOString()
            : undefined,
          composition,
          notes:
            `captured at score=${effectiveScore} (budget ${threshold}, regime ${result.regime}` +
            (quarantined ? ', quarantine' : '') + '); ' +
            `signals: ${result.signals.map(s => `${s.type}${s.score >= 0 ? '+' : ''}${s.score}`).join(', ') || 'none'}` +
            (recentGhost ? `; fantasma reciente ${recentGhost.version} (${reversion?.kind ?? 'unknown'})` : ''),
        })

        if (family.family) familyTracker.recordCapture(family.family, `${name}@${latestVersion}`, now)

        const bytes = directorySize(dir)
        budget?.recordCapture(bytes)
        coverage.capturedBytes += bytes

        if (quarantined) coverage.quarantined++
        console.log(`  -> ${dir} (${formatBytes(bytes)})${quarantined ? ' [quarantine]' : ''}`)
      } catch (e) {
        console.error(`  -> error: ${e}`)
      }
    }
  } catch (e) {
    if (config.verbose) console.error(`[err] ${name}: ${e}`)
  }

  return { outcome: 'analyzed', scored }
}

async function poll(config: WatcherConfig, lastSeenMs: number): Promise<number> {
  const xml = await fetchRss()

  // Document order in this feed is neither ascending nor descending by pubDate,
  // so the newest entry cannot be taken from either end without sorting.
  const items = parseRssItems(xml).sort((a, b) => a.publishedMs - b.publishedMs)

  const fresh = selectFreshItems(items, lastSeenMs, processed)

  // A fixed-size window only stays continuous while consecutive polls overlap,
  // and losing that leaves no other trace.
  const window = new Set(items.map(i => i.name))
  const hadPreviousWindow = previousWindow.size > 0
  const { overlap, rolledOver } = computeWindowOverlap(previousWindow, window)

  coverage.polls++
  coverage.feedEntries += items.length
  coverage.fresh += fresh.length
  if (rolledOver) coverage.windowRollovers++

  let newest = lastSeenMs
  let analyzed = 0
  let unreachable = 0

  // Sequential: 50 names already cost two registry requests each, and firing
  // them in parallel would turn a monitor into a load generator.
  for (const item of fresh) {
    const analysis = await analyzePackage(item.name, config, item.pubDate)
    if (analysis.outcome === 'analyzed') analyzed++
    else { unreachable++; countUnreachable(analysis.unreachableReason) }
    processed.set(feedItemKey(item), item.publishedMs)
    if (item.publishedMs > newest) newest = item.publishedMs
  }

  coverage.analyzed += analyzed
  coverage.unreachable += unreachable
  previousWindow = window

  console.log(
    `[coverage] poll ${coverage.polls}: ${items.length} received, ${fresh.length} new, ` +
    `${analyzed} analysed, ${unreachable} unreachable ` +
    `| overlap with previous poll: ${hadPreviousWindow ? overlap : 'n/a'}` +
    ` | cumulative: ${coverage.analyzed}/${coverage.fresh}`
  )

  if (rolledOver) {
    console.error(
      `COVERAGE GAP: the feed window rotated completely between polls ` +
      `(0 names in common). More than ${items.length} packages were published in ` +
      `${POLL_INTERVAL_MS / 1000}s and whatever did not fit was never seen. ` +
      `Rollovers this run: ${coverage.windowRollovers}`
    )
  }

  if (newest > lastSeenMs) saveLastPubDate(config.outputDir, newest)

  // Bounded by one feed window: anything older can no longer reappear.
  for (const [key, ms] of processed) {
    if (ms < newest) processed.delete(key)
  }

  return newest
}

// Scoring every change would re-score the same package on every dist-tag move,
// maintainer edit and README update.
export function isRecentPublish(p: Packument, windowMs: number, now = Date.now()): boolean {
  let newest = 0
  for (const meta of Object.values(p.versions)) {
    const t = new Date(meta.publishedAt).getTime()
    if (Number.isFinite(t) && t > newest) newest = t
  }
  return newest > 0 && now - newest <= windowMs
}

export async function startWatcher(config: WatcherConfig): Promise<void> {
  mkdirSync(config.outputDir, { recursive: true })

  const dailyBytes = config.dailyByteBudget ?? DEFAULT_DAILY_BYTES
  const maxBytes = config.maxCaptureBytes ?? DEFAULT_TOTAL_BYTES

  familyTracker = new PlatformFamilyTracker(config.familyWindowMs)
  budget = new DailyCaptureBudget(config.outputDir, dailyBytes)

  console.log(`norte-guard watch, output: ${config.outputDir}`)
  const budgets = typeof config.captureBudgetThreshold === 'number'
    ? { genome: config.captureBudgetThreshold, noGenome: config.captureBudgetThreshold }
    : config.captureBudgetThreshold
  const quarantinePolicy = { ...DEFAULT_QUARANTINE, ...config.quarantine }

  console.log(
    `Capture budget: genome ${budgets.genome} - no-genome ${budgets.noGenome} ` +
    `(not a detection threshold) | engine v${engineVersion()}`
  )
  console.log(
    quarantinePolicy.enabled
      ? `Quarantine: no-genome - name under ${YOUNG_NAME_DAYS} days - ` +
        `under ${TINY_PACKAGE_BYTES / 1000}KB - no repository, retained ` +
        `${quarantinePolicy.retentionDays} days`
      : 'Quarantine: disabled'
  )
  const unpackedCap = config.maxCaptureUnpackedBytes ?? DEFAULT_MAX_CAPTURE_BYTES
  console.log(
    `Daily budget: ${formatBytes(budget.spent)} / ${formatBytes(dailyBytes)} spent today | ` +
    `total cap: ${formatBytes(maxBytes)}`
  )
  console.log(
    `Score path: no tarball above ${formatBytes(unpackedCap)} unpacked — the packument is ` +
    `captured anyway and the refusal recorded, so the package stays in every denominator`
  )

  const rotatedLogs = rotateLogs(config.outputDir)
  if (rotatedLogs.rotated.length > 0) {
    for (const r of rotatedLogs.rotated) {
      const ratio = r.bytes > 0 ? (r.bytes / r.compressed).toFixed(1) : '1'
      console.log(`ROTATED ${r.from} -> ${r.to} (${formatBytes(r.bytes)} -> ${formatBytes(r.compressed)}, ${ratio}x)`)
    }
  }

  const store = storeStats(join(config.outputDir, 'captures'))
  if (store.references > 0) {
    console.log(
      `Object store: ${store.objects} objects - ${formatBytes(store.bytes)} - ` +
      `${store.dedupedReferences} deduplicated references (${formatBytes(store.bytesSaved)} saved)`
    )
  }

  // Expired quarantine first: it frees space that rotation would otherwise take
  // from captures nobody has decided about yet.
  const expired = sweepQuarantine(join(config.outputDir, 'captures'))
  if (expired.expired.length > 0 || expired.promoted > 0) {
    console.log(
      `Quarantine sweep: ${expired.expired.length} expired and deleted - ` +
      `${expired.kept} within window - ${expired.promoted} promoted and kept`
    )
  }
  // A refusal deletes nothing, so every count above stays zero and the run looks
  // like a quiet one. It is the opposite: it is the collector saying it could not
  // tell orphans from the whole store, on the only copy of bytes npm has already
  // removed.
  if (expired.objectSweepRefused) {
    console.error(`OBJECT SWEEP REFUSED: ${expired.objectSweepRefused}`)
  }

  // Before the first capture, so a run that starts over the cap frees space
  // instead of adding to it.
  const rotation = rotateCaptures(join(config.outputDir, 'captures'), maxBytes)
  if (rotation.refused) {
    console.error(`ROTATION REFUSED: ${rotation.refused}`)
  }
  if (rotation.deleted.length > 0) {
    console.log(
      `Rotation: ${rotation.deleted.length} old captures deleted ` +
      `(${formatBytes(rotation.before)} -> ${formatBytes(rotation.after)}), ` +
      `${rotation.protectedCount} labelled ones untouched`
    )
    for (const d of rotation.deleted.slice(0, 5)) console.log(`   - ${d.path} (${formatBytes(d.bytes)})`)
    if (rotation.deleted.length > 5) console.log(`   - and ${rotation.deleted.length - 5} more`)
  } else if (rotation.before > 0) {
    console.log(
      `Captures on disk: ${formatBytes(rotation.before)} ` +
      `(${rotation.protectedCount} labelled, never rotated)`
    )
  }

  if ((config.feed ?? 'changes') === 'changes') {
    try {
      await runChangesFeed(config)
      return
    } catch (e) {
      if (!(e instanceof ChangesFeedFailure)) throw e

      console.error(`
  DEGRADED TO RSS

    _changes is not responding: ${e.message}

    RSS is a 50-entry window, not a cursor. If npm publishes more than 50
    packages between polls, whatever fell off the window is never seen: not
    retried, lost. Captures from this period are an incomplete sample and are
    not comparable with those from the changes feed.
`)
    }
  }

  await runRssFeed(config)
}

// Primary path: every change arrives once, in order, and the cursor is on disk,
// so a crash costs the seconds since the last write rather than everything
// published while the process was down.
async function runChangesFeed(config: WatcherConfig): Promise<void> {
  const publishWindowMs = config.publishWindowMs ?? PUBLISH_WINDOW_MS

  // 'now' rather than 0 on a first run: since=0 replays millions of documents.
  // Resuming runs start from the persisted cursor and lose nothing.
  const resumed = loadLastSeq(config.outputDir)
  const since: Seq | 'now' = resumed ?? 'now'

  // npm's engine implements only the paged form, a CouchDB mirror implements
  // both, and which one is in use changes the latency of every capture.
  const capabilities = await probeCapabilities()

  console.log(
    `Feed: _changes ${capabilities.continuous ? '(continuous)' : '(paged cursor)'} - ${capabilities.detail}`
  )
  if (!capabilities.continuous) {
    console.log(
      `      the server does not support feed=continuous; it pages with since=<seq>.\n` +
      `      Same delivery guarantee, one poll of latency.`
    )
  }
  console.log(
    `Resuming from: ${resumed !== null ? `seq ${resumed}` : `current tip (${capabilities.updateSeq}), first run`}`
  )
  console.log('Ctrl+C to stop\n')

  let lastPersisted = 0

  await streamChanges({
    since,
    capabilities,
    includeDocs: true,

    onConnect: (from, mode) => {
      if (coverage.reconnects > 0) {
        console.error(`Resuming from seq ${from} (mode ${mode}, resumption ${coverage.reconnects})`)
      }
    },

    onDisconnect: (reason, attempt) => {
      coverage.reconnects++
      console.error(`Feed interrupted (${reason}), attempt ${attempt}`)
    },

    onGap: gap => {
      coverage.seqGaps++
      coverage.seqMissing += gap.missing
      console.error(
        `SEQUENCE GAP: ${gap.from} -> ${gap.to} (${gap.missing} seq not delivered). ` +
        `Cumulative: ${coverage.seqGaps} gaps, ${coverage.seqMissing} seq`
      )
    },

    // Should be impossible: a rewind skips everything between the two positions
    // on the next resume.
    onRewind: (from, to) => {
      coverage.rewinds++
      console.error(`CURSOR REWOUND: ${from} -> ${to}. Check .last_seq before trusting this run.`)
    },

    // Replaces RSS's rollover warning. Behind is not lost, the cursor catches
    // up, but it still has to be visible.
    onLag: (lag, tip) => {
      coverage.lastLag = lag
      if (lag > coverage.maxLag) coverage.maxLag = lag

      if (lag > (config.lagAlertThreshold ?? DEFAULT_LAG_ALERT)) {
        coverage.lagAlerts++
        console.error(
          `CURSOR LAG: ${lag} seq behind the tip (${tip}), max this run ${coverage.maxLag}. ` +
          `Nothing is lost, the cursor catches up, but if the max climbs run after run ` +
          `the analysis is not keeping pace with the feed.`
        )
      }
    },

    onSeq: seq => {
      // At most once a second. A stale cursor makes a crash replay changes,
      // which is harmless; persisting ahead of the work would skip them.
      const now = Date.now()
      if (now - lastPersisted >= 1_000) {
        saveLastSeq(config.outputDir, seq)
        lastPersisted = now
      }
    },

    onChange: async event => {
      coverage.changes++
      coverage.feedEntries++
      budget?.rollIfNewDay()
      await handleChange(event, config, publishWindowMs)
      if (coverage.changes % 100 === 0) reportCoverage()
    },

    onPage: async events => {
      coverage.changes += events.length
      coverage.feedEntries += events.length
      budget?.rollIfNewDay()

      // A monorepo publishing its members puts several changes for the same
      // package in one page. Only the last describes the current state, and the
      // rest would each cost two requests to learn the same thing.
      const { kept, superseded } = coalesceByPackage(events)
      for (const event of superseded) {
        coverage.coalesced++
        logChange(config.outputDir, event, 'coalescido')
      }

      await mapWithConcurrency(
        kept,
        config.concurrency ?? DEFAULT_CONCURRENCY,
        event => handleChange(event, config, publishWindowMs)
      )

      reportCoverage()
    },
  })
}

// Two registry requests per change. Six at a time keeps up with the measured
// arrival rate without turning a monitor into a load generator.
const DEFAULT_CONCURRENCY = 6

// Superseded events are returned rather than dropped, so the enumeration log
// still records that they happened.
export function coalesceByPackage(
  events: ChangeEvent[]
): { kept: ChangeEvent[]; superseded: ChangeEvent[] } {
  const latest = new Map<string, ChangeEvent>()
  const superseded: ChangeEvent[] = []

  for (const event of events) {
    const previous = latest.get(event.id)
    if (previous) superseded.push(previous)
    latest.set(event.id, event)
  }

  return { kept: [...latest.values()], superseded }
}

async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>
): Promise<void> {
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      for (;;) {
        const i = next++
        if (i >= items.length) return
        try {
          await fn(items[i]!)
        } catch {
          // Aborting the page would stall the cursor on one bad change forever.
        }
      }
    })
  )
}

// Recent publications, held for the ecosystem pass. Trimmed to the last three
// versions of each: detectCampaigns needs the capability deltas and the publish
// times, not the whole document, and a rolling window of full packuments would
// be hundreds of megabytes of resident memory.
const campaignWindow = new Map<string, Packument>()
const CAMPAIGN_WINDOW_MS = 60 * 60_000
const CAMPAIGN_CHECK_EVERY = 50
let sinceCampaignCheck = 0

function rememberForCampaigns(packument: Packument, now = Date.now()): void {
  const recent = sortedVersions(packument).slice(-3)
  if (recent.length === 0) return

  const versions: Packument['versions'] = {}
  const time: Record<string, string> = {}
  for (const v of recent) {
    versions[v.version] = v
    time[v.version] = v.publishedAt
  }

  campaignWindow.set(packument.name, { ...packument, versions, time })

  for (const [name, p] of campaignWindow) {
    const newest = sortedVersions(p).at(-1)
    const t = newest ? new Date(newest.publishedAt).getTime() : 0
    if (now - t > CAMPAIGN_WINDOW_MS) campaignWindow.delete(name)
  }
}

// Independent of everything else. It does not ask what a package looks like: it
// asks whether N unrelated accounts did the same unusual thing in the same hour,
// which is the only signal here that catches a day-zero campaign with no prior
// corpus. Recorded so the gate can read it — a campaign is a block reason on its
// own, whatever the per-package rules say.
// One record per campaign, held across passes so a campaign still sitting in the
// window is updated rather than announced again. Loaded from disk at startup so
// a restart does not re-announce everything currently open.
const CAMPAIGN_LEDGER_FILE = 'campaigns.json'
let campaignLedger: CampaignRecord[] | null = null

function loadCampaignLedger(dir: string): CampaignRecord[] {
  if (campaignLedger) return campaignLedger
  try {
    const parsed = JSON.parse(readFileSync(join(dir, CAMPAIGN_LEDGER_FILE), 'utf-8'))
    // Shape-checked, not trusted: a truncated write would otherwise become a
    // non-array that every merge below throws on, taking the feed with it.
    campaignLedger = Array.isArray(parsed) ? parsed as CampaignRecord[] : []
  } catch {
    campaignLedger = []
  }
  return campaignLedger
}

function checkCampaigns(config: WatcherConfig): void {
  if (campaignWindow.size < 3) return

  const signals = detectCampaigns([...campaignWindow.values()], 60)
  if (signals.length === 0) return

  const at = new Date().toISOString()
  let records = loadCampaignLedger(config.outputDir)
  let changed = false

  for (const signal of signals) {
    const update = mergeCampaign(records, signal, at)
    records = update.records

    // The record is always current; the alert is only for what changed. This is
    // what turns 163 lines into one per campaign plus one per growth.
    if (update.change === null) continue

    changed = true
    coverage.campaigns++

    const record = update.record
    console.log(
      update.change === 'new'
        ? `CAMPAIGN: ${record.type} - ${record.packages.length} packages, ` +
          `${record.entities.length} distinct parties - certainty ${record.certainty}%` +
          (record.linkedBy?.length ? ` - linked by ${record.linkedBy.join('+')}` : '')
        : `CAMPAIGN GREW: ${record.id} - ${update.added.length} new ` +
          `(${record.packages.length} total, ${record.entities.length} parties)`
    )
    console.log(
      `   ${update.added.slice(0, 8).join(', ')}${update.added.length > 8 ? '...' : ''}`
    )

    try {
      writeFileSync(
        join(config.outputDir, 'campaigns.ndjson'),
        JSON.stringify({ ...record, change: update.change, added: update.added, detectedAt: at }) + '\n',
        { flag: 'a' }
      )
    } catch { /* the console line is the fallback record */ }
  }

  campaignLedger = records
  // Written on every pass, not only on a change: sightings and lastSeenAt move
  // whether or not anything is announced, and that is the record of a campaign
  // still being open.
  try {
    writeFileSync(join(config.outputDir, CAMPAIGN_LEDGER_FILE), JSON.stringify(records, null, 2))
  } catch { /* the ndjson trail above survives it */ }

  if (!changed) return
}

// A change whose dist-tag latest has not moved is an edit to something else:
// real, but not worth a full packument each.
const knownLatest = new Map<string, string>()

// Written before anything is fetched, so whatever the analysis skips, defers or
// fails on, the record that the change happened survives with its sequence
// number. ~100 bytes each, about 16MB a day at the measured rate.
function countUnreachable(reason: UnreachableReason = 'other'): void {
  coverage.unreachable++
  coverage.unreachableByReason[reason] = (coverage.unreachableByReason[reason] ?? 0) + 1
}

function logChange(
  dir: string,
  event: ChangeEvent,
  outcome: string,
  scored?: ScoredPublication,
  unreachableReason?: UnreachableReason
): void {
  try {
    writeFileSync(
      join(dir, 'changes-log.ndjson'),
      JSON.stringify({
        seq: event.seq,
        package: event.id,
        deleted: event.deleted,
        outcome,
        // Every publication, captured or not. What a budget costs has to be
        // measured on this stream: a cut-off derived from fp-bench's
        // download-ranked sample captured 26% of publications instead of 1%.
        score: scored?.score,
        regime: scored?.regime,
        verdict: scored?.verdict,
        // Recorded on every publication so the prevalence of the class can be
        // recomputed from disk at any cut-off, without another sweep.
        class: scored?.markers ? compactMarkers(scored.markers) : undefined,
        unreachableReason,
        seenAt: new Date().toISOString(),
      }) + '\n',
      { flag: 'a' }
    )
  } catch {
    // Losing one log line must never take down the feed.
  }
}

// Labels any capture of this package that holds a version npm has now removed.
// A capture of the placeholder itself is left alone: it proves the takedown and
// says nothing about whether the detector would have caught the attack.
function recordTakedown(dir: string, packument: Packument): void {
  const purged = Object.keys(packument.time ?? {})
    .filter(v => v !== 'created' && v !== 'modified' && !(v in packument.versions))

  try {
    writeFileSync(
      join(dir, 'takedown-log.ndjson'),
      JSON.stringify({
        package: packument.name,
        seenAt: new Date().toISOString(),
        holderPublishedAt: packument.time?.[NPM_SECURITY_HOLDER] ?? null,
        purgedVersions: purged,
      }) + '\n',
      { flag: 'a' }
    )
  } catch { /* the labelling below matters more than the log line */ }

  const capturesDir = join(dir, 'captures')
  if (!existsSync(capturesDir)) return

  const prefix = `${packument.name.replace(/[@/]/g, '_')}@`
  let names: string[]
  try { names = readdirSync(capturesDir) } catch { return }

  for (const name of names) {
    if (!name.startsWith(prefix)) continue

    const version = name.slice(prefix.length).replace(/_\d+$/, '')
    if (version === NPM_SECURITY_HOLDER) continue
    if (!purged.includes(version)) continue

    try {
      labelCapture(
        join(capturesDir, name),
        'confirmed_malicious',
        `npm-takedown: ${NPM_SECURITY_HOLDER} publicado sobre ${packument.name}, ` +
        `captured version ${version} removed`
      )
      console.log(`TAKEDOWN CONFIRMED: ${packument.name}@${version}, capture labelled confirmed_malicious`)
    } catch (e) {
      console.error(`could not label ${name}: ${e}`)
    }
  }
}

async function handleChange(
  event: ChangeEvent,
  config: WatcherConfig,
  publishWindowMs: number
): Promise<void> {
  // RSS could not report this at all: it only ever carried publications.
  if (event.deleted) {
    coverage.deletions++
    console.log(`PACKAGE DELETED: ${event.id} (seq ${event.seq})`)
    logChange(config.outputDir, event, 'deleted')
    writeFileSync(
      join(config.outputDir, 'deletions.ndjson'),
      JSON.stringify({ package: event.id, seq: event.seq, detectedAt: new Date().toISOString() }) + '\n',
      { flag: 'a' }
    )
    return
  }

  let packument: Packument | null = null

  if (event.doc) {
    // The document as of this sequence number, rather than a later state read
    // afterwards.
    try {
      packument = normalizePackument(event.doc)
    } catch {
      packument = null
    }
  }

  if (!packument) {
    // Cheap filter first. Only a moved dist-tag earns the full document.
    let latest: string | undefined
    try {
      latest = (await fetchAbbreviatedPackument(event.id)).distTags['latest']
    } catch (e) {
      const reason = classifyFetchFailure(e)
      countUnreachable(reason)
      logChange(config.outputDir, event, 'unreachable', undefined, reason)
      return
    }

    if (latest === undefined) {
      coverage.skippedNonPublish++
      logChange(config.outputDir, event, 'sin-latest')
      return
    }

    const seen = knownLatest.get(event.id)
    knownLatest.set(event.id, latest)

    if (seen === latest) {
      coverage.skippedNonPublish++
      logChange(config.outputDir, event, 'sin-version-nueva')
      return
    }

    try {
      packument = await fetchPackument(event.id)
    } catch (e) {
      const reason = classifyFetchFailure(e)
      countUnreachable(reason)
      logChange(config.outputDir, event, 'unreachable', undefined, reason)
      return
    }
  }

  // Disappearances are checked on every change that got this far, publish or
  // not: a version being pulled shows up as an ordinary document update with a
  // smaller versions{}.
  checkDisappearances(config.outputDir, event.id, packument)

  // npm removing a package arrives here as an ordinary change. Recording it is
  // how a capture taken before the removal turns into a confirmed sample later —
  // the only path to a recall number that does not involve labelling our own
  // captures. It is a label; nothing above reads it.
  if (NPM_SECURITY_HOLDER in packument.versions) {
    recordTakedown(config.outputDir, packument)
  }

  if (!isRecentPublish(packument, publishWindowMs)) {
    coverage.skippedNonPublish++
    logChange(config.outputDir, event, 'no-publicacion')
    return
  }

  coverage.fresh++
  rememberForCampaigns(packument)
  if (++sinceCampaignCheck >= CAMPAIGN_CHECK_EVERY) {
    sinceCampaignCheck = 0
    checkCampaigns(config)
  }

  const analysis = await analyzePackage(event.id, config, new Date().toISOString(), packument)
  if (analysis.outcome === 'analyzed') coverage.analyzed++
  else countUnreachable(analysis.unreachableReason)

  logChange(config.outputDir, event, analysis.outcome, analysis.scored, analysis.unreachableReason)
}

export interface ScoredPublication {
  score: number
  regime: string
  verdict: string
  captured: boolean
  markers?: ClassMarkers
}

export type UnreachableReason = '404' | 'timeout' | 'http-error' | 'malformed' | 'other'

export interface AnalysisResult {
  outcome: 'analyzed' | 'unreachable'
  scored?: ScoredPublication
  unreachableReason?: UnreachableReason
}

// The four failures behind an unreachable publication mean different things. A
// 404 is a package unpublished between the feed and the fetch, which is normal.
// Timeouts are the registry being slow, and are recoverable. Malformed
// packuments are a parser gap, and are not.
export function classifyFetchFailure(error: unknown): UnreachableReason {
  const text = String(error)
  if (text.includes('Package not found')) return '404'
  if (text.includes('Timeout')) return 'timeout'
  if (text.includes('HTTP ')) return 'http-error'
  if (text.includes('JSON') || text.includes('Unexpected token')) return 'malformed'
  return 'other'
}

function reportCoverage(): void {
  const unreachable = Object.entries(coverage.unreachableByReason)
    .sort(([, a], [, b]) => b - a)
    .map(([reason, n]) => `${reason}:${n}`)
    .join(' ')

  console.log(
    `[coverage] ${coverage.changes} changes enumerated - ${coverage.fresh} publications - ` +
    `${coverage.analyzed} analysed - ${coverage.skippedNonPublish} with no new version - ` +
    `${coverage.coalesced} coalesced - ${coverage.deletions} deleted - ` +
    `lag ${coverage.lastLag}/max ${coverage.maxLag} seq - ${coverage.reconnects} resumptions` +
    (coverage.rewinds > 0 ? ` - ${coverage.rewinds} CURSOR REWINDS` : '')
  )
  console.log(
    `[captures] ${budget?.captures ?? 0} today - ${formatBytes(budget?.spent ?? 0)} of ` +
    `${formatBytes(budget?.dailyBytes ?? 0)} - ${coverage.familyRedundant} families skipped - ` +
    `${coverage.overBudget} skipped over budget - ${coverage.quarantined} quarantined - ` +
    `${coverage.campaigns} campaigns - ` +
    `${coverage.unreachable} unreachable${unreachable ? ` (${unreachable})` : ''}`
  )

  const r = coverage.quarantineRejects
  console.log(
    `[quarantine] rejects: ${r.withGenome} with genome - ${r.oldName} name too old - ` +
    `${r.tooLarge} >100KB - ${r.withRepository} with repository - ${r.overCaptureCap} over cap - ` +
    `${r.accepted} accepted`
  )
}

// Fallback only. Kept intact so the degraded mode behaves exactly as it always
// did, including announcing its own blind spot.
async function runRssFeed(config: WatcherConfig): Promise<void> {
  let lastSeenMs = loadLastPubDate(config.outputDir)

  console.log(
    `Feed: RSS every ${POLL_INTERVAL_MS / 1000}s | ` +
    `Resuming from: ${lastSeenMs ? new Date(lastSeenMs).toISOString() : 'the start of the feed'}`
  )
  console.log('Ctrl+C para parar\n')

  for (;;) {
    const startedAt = Date.now()

    try {
      lastSeenMs = await poll(config, lastSeenMs)
    } catch (e) {
      // A failed poll is not fatal: the next one re-reads the same window, and
      // the high-water mark means nothing in it was lost.
      console.error(`Feed unavailable (${e}), retrying in ${POLL_INTERVAL_MS / 1000}s`)
    }

    // Measured from the start of the cycle so a slow batch does not stack polls
    // on top of each other.
    const elapsed = Date.now() - startedAt
    await sleep(Math.max(0, POLL_INTERVAL_MS - elapsed))
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// The watcher downloads live malware to the user's disk, so the warning goes on
// stderr before the first fetch rather than in the README.
export function printMalwareWarning(): void {
  console.error(`
  WARNING: norte-guard watch downloads malware to your disk.

    Captured tarballs may contain malicious code. norte-guard never extracts
    or executes them.

    Your responsibilities:
      - do not extract captured .ngpack directories by hand
      - do not commit captures/ to a public repository
      - check the legal implications in your jurisdiction before sharing
        malware tarballs, research or not

    The capture directory is isolated and never executed.
    To continue: norte-guard watch --i-understand-the-risks
`)
}


import { gunzipSync } from 'node:zlib'

interface PackumentSnapshot {
  name: string
  capturedAt: string
  versionSummaries: Record<string, {
    scripts?: string[]
    hasInstallScript?: boolean
  }>
}

export interface HistoryIntegrityResult {
  package: string
  rewritten: boolean
  changes: string[]
}

// The genome trusts what npm says today about the past. The watcher knows what
// npm said when it looked. Comparing the two is the only check here that does
// not trust the registry: if npm ever serves different history to different
// clients, the stored deltas are evidence that cannot be retroactively forged.
export function checkHistoryIntegrity(
  outputDir: string,
  packageName: string,
  currentPackument: Record<string, unknown>
): HistoryIntegrityResult {
  const changes: string[] = []
  const deltaDir = join(outputDir, 'deltas')
  if (!existsSync(deltaDir)) return { package: packageName, rewritten: false, changes: [] }

  const safeName = packageName.replace(/[@/]/g, '_')
  const files = readdirSync(deltaDir)
    .filter(f => f.includes(safeName) && f.endsWith('.json.gz'))
    .sort()

  if (files.length === 0) return { package: packageName, rewritten: false, changes: [] }

  // The oldest snapshot is the strongest witness — it predates any rewrite the
  // attacker could have made after realising they were being watched.
  const oldestFile = files[0]!
  let snapshot: PackumentSnapshot | null = null
  try {
    const compressed = readFileSync(join(deltaDir, oldestFile))
    snapshot = JSON.parse(gunzipSync(compressed).toString()) as PackumentSnapshot
  } catch { return { package: packageName, rewritten: false, changes: [] } }

  const currentVersions = (currentPackument.versions ?? {}) as Record<string, unknown>

  for (const [ver, oldMeta] of Object.entries(snapshot.versionSummaries)) {
    const currentMeta = currentVersions[ver] as Record<string, unknown> | undefined

    if (!currentMeta) {
      changes.push(`version ${ver} existed at ${snapshot.capturedAt} and no longer does`)
      continue
    }

    // A version disappearing is normal enough. An existing version changing what
    // it declares is not — that is history being rewritten under the genome.
    const wasInstall = (oldMeta as Record<string, unknown>).hasInstallScript
    const isInstall = (currentMeta as Record<string, unknown>).hasInstallScript
    if (wasInstall !== isInstall) {
      changes.push(`${ver}: hasInstallScript changed ${wasInstall} -> ${isInstall} (REWRITE)`)
    }
  }

  const rewritten = changes.some(c => c.includes('REWRITE'))

  if (rewritten) {
    console.error(`\nHISTORY REWRITE DETECTED: ${packageName}`)
    for (const c of changes) console.error(`   ${c}`)
    console.error()
  }

  return { package: packageName, rewritten, changes }
}
