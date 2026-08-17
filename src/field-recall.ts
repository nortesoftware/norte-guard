// The recall this project has not been able to compute.
//
// Every earlier attempt needed a corpus of confirmed attacks, and confirmation
// was the missing piece: a high score is why a capture was kept, not evidence of
// what it is. npm publishing 0.0.1-security over a package is that evidence, and
// it comes from the registry rather than from us.
//
// The measurement only works one way round. The label comes from the registry
// today; the verdict comes from what the collector scored at the moment the
// version was published, which is on disk in changes-log.ndjson and was computed
// against the full packument as it stood then. Nothing about the removal was
// visible to the scorer, because the removal had not happened.
//
// Samples where the collector only ever saw 0.0.1-security are excluded: it
// observed the aftermath, so there is no decision to grade.

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { rateWithCI, type RateWithCI } from './stats.js'
import { NPM_SECURITY_HOLDER } from './takedown.js'
import type { CorpusSample } from './corpus.js'

export interface FieldSample {
  package: string
  version: string
  observedAt: string
  // What the collector scored when the version was published. Absent when the
  // publication was seen but never scored.
  score: number | null
  regime: string | null
  auditVerdict: string | null
  // Audit blocks at 40, gate at 70, and under the no-genome regime the gate
  // returns INSUFFICIENT_HISTORY whatever the score. Both are reported because
  // they answer different questions.
  auditBlocked: boolean
  gateBlocked: boolean
}

export interface FieldRecallReport {
  takedownsFound: number
  preTakedownObservations: number
  // How often the collector saw a package before npm removed it. Independent of
  // detection: it measures whether the collector is there in time, and a recall
  // computed over samples it never saw is not a recall at all.
  takedownCoverage: RateWithCI | null
  scored: FieldSample[]
  unscored: FieldSample[]
  auditRecall: RateWithCI | null
  gateRecall: RateWithCI | null
  calculable: boolean
  statement: string
  // Where each half of the fraction came from, and how old it is.
  evidence: CoverageEvidence
}

// Coverage was 4 of 73, 5.48%, and both numbers came from one file written by
// one sweep on 2026-08-12 at 20:43Z. The four packages that turned this project
// into something with confirmed samples were captured at 09:27 the next morning
// — after the file was written, so absent from both halves of its fraction.
//
// A sweep is a snapshot of an answer, and reading one as the current answer is
// the same error as reading a stale benchmark as a live one. The fix is not a
// bigger sweep: it is to say where each number came from, and to fold in the
// evidence that keeps arriving on its own — the takedown log the watcher writes
// as it sees removals, and the captures npm's own marker has since labelled.
export interface CoverageEvidence {
  // The broad but frozen source: every observed package, asked once.
  sweptAt: string | null
  sweepTakedowns: number
  sweepObserved: number
  // The narrow but current sources.
  liveLogTakedowns: number
  labelledCaptures: number
  // Removals known from the live sources that the sweep never saw. Every one of
  // them was missing from the denominator, and any that were observed
  // beforehand were missing from the numerator too.
  takedownsAfterSweep: number
  staleness: string | null
}

const MATCH_WINDOW_MS = 10 * 60_000

interface ChangeRow {
  package?: string
  score?: number
  regime?: string
  verdict?: string
  seenAt?: string
}

interface TakedownFinding {
  package: string
  observedVersion: string
  observedAt: string
}

interface SweepFile {
  sweptAt?: string
  takenDown?: TakedownFinding[]
  preTakedownObservations?: TakedownFinding[]
}

export function computeFieldRecall(
  outputDir: string,
  // The corpus, when the caller already has it. A capture labelled
  // confirmed_malicious from an npm takedown is a removal AND an observation of
  // the artifact before it: both halves of the fraction, and the half the sweep
  // is always behind on.
  captures: CorpusSample[] = []
): FieldRecallReport {
  const sweepPath = join(outputDir, 'takedowns.json')

  let sweep: SweepFile = {}
  let hasSweep = false
  if (existsSync(sweepPath)) {
    try {
      sweep = JSON.parse(readFileSync(sweepPath, 'utf-8')) as SweepFile
      hasSweep = true
    } catch { /* an unreadable sweep is one source down, not the end of the count */ }
  }

  // Denominator: every package known to have been removed, from whichever source
  // knows it. Numerator: those we hold an observation of a real version for,
  // made before the removal. A package can be in both, and a Set is what stops
  // it being counted twice.
  const removed = new Map<string, string>()   // package -> where it came from
  const observedBefore = new Set<string>()

  for (const t of sweep.takenDown ?? []) removed.set(t.package, 'sweep')
  for (const t of sweep.preTakedownObservations ?? []) observedBefore.add(t.package)

  const live = readLiveTakedowns(outputDir)
  for (const pkg of live) if (!removed.has(pkg)) removed.set(pkg, 'live')

  // A capture labelled from npm's own removal marker: the artifact is on disk,
  // so it was observed before the removal by construction.
  let labelledCaptures = 0
  for (const sample of captures) {
    // Contaminated captures are held out of every benchmark by policy, and
    // coverage is a benchmark. Letting them in here would put a sample the
    // recall denominator refuses into the coverage denominator.
    if (sample.contaminated) continue
    if (sample.label !== 'confirmed_malicious') continue
    if (!sample.labelSource?.includes('npm-takedown')) continue
    if (sample.version === NPM_SECURITY_HOLDER) continue
    labelledCaptures++
    if (!removed.has(sample.package)) removed.set(sample.package, 'capture')
    observedBefore.add(sample.package)
  }

  if (removed.size === 0) {
    return empty(
      hasSweep
        ? 'no removals known from any source yet'
        : 'no takedowns.json: run `norte-guard sweep-takedowns --include-observed`'
    )
  }

  const takedownsAfterSweep = [...removed.entries()].filter(([, from]) => from !== 'sweep').length
  const evidence: CoverageEvidence = {
    sweptAt: sweep.sweptAt ?? null,
    sweepTakedowns: sweep.takenDown?.length ?? 0,
    sweepObserved: sweep.preTakedownObservations?.length ?? 0,
    liveLogTakedowns: live.size,
    labelledCaptures,
    takedownsAfterSweep,
    staleness: takedownsAfterSweep > 0
      ? `the sweep of ${sweep.sweptAt ?? '(undated)'} knew ${sweep.takenDown?.length ?? 0} removals; ` +
        `${takedownsAfterSweep} more have been recorded since, by the watcher and by labelling. ` +
        `Re-run \`norte-guard sweep-takedowns --include-observed\` to recount the observed side too.`
      : null,
  }

  // Observations of packages nothing knows to have been removed are not
  // coverage of anything, so the numerator is intersected with the denominator.
  const observations = [
    ...(sweep.preTakedownObservations ?? []).filter(o => removed.has(o.package)),
    ...[...observedBefore]
      .filter(p => !(sweep.preTakedownObservations ?? []).some(o => o.package === p))
      .map(p => observationFromCapture(p, captures)),
  ].filter((o): o is TakedownFinding => o !== null)

  const takedownsFound = removed.size

  // The rotated days as well as the live file. Log rotation compresses every
  // closed day into changes-log-YYYY-MM-DD.ndjson.gz, so reading only the
  // current file loses the score of every observation older than the last
  // rotation — which is most of them, and which is what turns a graded decision
  // into an "observed without a score" line.
  const byPackage = new Map<string, ChangeRow[]>()
  for (const text of readChangeLogs(outputDir)) {
    for (const line of text.split('\n')) {
      if (!line) continue
      try {
        const row = JSON.parse(line) as ChangeRow
        if (!row.package || typeof row.score !== 'number') continue
        const list = byPackage.get(row.package) ?? []
        list.push(row)
        byPackage.set(row.package, list)
      } catch { /* one bad line does not invalidate the log */ }
    }
  }

  const samples: FieldSample[] = observations.map(obs => {
    // The scoring closest in time to the observation. Not "at or before": the
    // delta is written a beat before the log line, so an exact cutoff misses by
    // milliseconds. The window keeps a later scoring of the placeholder — hours
    // away — from being mistaken for the decision being graded.
    const observedMs = new Date(obs.observedAt).getTime()
    const row = (byPackage.get(obs.package) ?? [])
      .map(r => ({ row: r, distance: Math.abs(new Date(r.seenAt ?? '').getTime() - observedMs) }))
      .filter(c => Number.isFinite(c.distance) && c.distance <= MATCH_WINDOW_MS)
      .sort((a, b) => a.distance - b.distance)[0]?.row

    const auditVerdict = row?.verdict ?? null
    return {
      package: obs.package,
      version: obs.observedVersion,
      observedAt: obs.observedAt,
      score: row?.score ?? null,
      regime: row?.regime ?? null,
      auditVerdict,
      auditBlocked: auditVerdict === 'BLOCK',
      // Derived, not recorded: the collector logs one audit verdict and the gate
      // verdict has to be reconstructed from it. The reconstruction is that the
      // gate blocks where audit blocks and a baseline existed.
      //
      // That reconstruction cannot see the fabricated-profile rule, and no
      // amount of care would let it. The collector scores with
      // DEFAULT_THRESHOLDS.audit and never passes a download count into the
      // scorer, so the conjunction has never been able to fire on this path —
      // which is why every no-genome row in the log reads as not blocked
      // whatever the rule does. A zero out of this number is a fact about the
      // log format, not about the engine, and `regradeWithCurrentEngine` below
      // exists because that distinction is the whole measurement.
      gateBlocked: auditVerdict === 'BLOCK' && row?.regime === 'genome',
    }
  })

  const scored = samples.filter(s => s.score !== null)
  const unscored = samples.filter(s => s.score === null)

  if (scored.length === 0) {
    return {
      takedownsFound,
      preTakedownObservations: observations.length,
      takedownCoverage: rateWithCI(observations.length, takedownsFound),
      scored, unscored,
      auditRecall: null, gateRecall: null,
      calculable: false,
      statement: `not calculable: ${observations.length} pre-takedown observations, none with a recorded score`,
      evidence,
    }
  }

  const auditHits = scored.filter(s => s.auditBlocked).length
  const gateHits = scored.filter(s => s.gateBlocked).length

  return {
    takedownsFound,
    preTakedownObservations: observations.length,
    takedownCoverage: rateWithCI(observations.length, takedownsFound),
    scored, unscored,
    auditRecall: rateWithCI(auditHits, scored.length),
    gateRecall: rateWithCI(gateHits, scored.length),
    calculable: true,
    // Both columns, and when every sample is no-genome, the fact that neither
    // could have been anything but zero. The gate column is reconstructed as
    // "BLOCK and a baseline existed", which no-genome fails by definition; the
    // audit column looks independent and is not, because under that regime the
    // scorer returns WARN or PASS on absolute risk and reaches BLOCK only
    // through the fabricated-profile conjunction, which the collector never
    // gives a download count to. Fixing the first and leaving the second
    // standing would move the defect one column right.
    statement: `${gateHits}/${scored.length} blocked by the gate, ${auditHits}/${scored.length} by audit` +
      (scored.every(s => s.regime === 'no-genome')
        ? ` - every sample is no-genome, where neither column can be non-zero: the gate needs a ` +
          `baseline and audit reaches BLOCK only through a rule the collector never feeds`
        : ''),
    evidence,
  }
}

// The other half of field recall, and the half the log cannot answer.
//
// `computeFieldRecall` grades the decision the collector made at the time, which
// is the only honest answer to "was this caught when it happened". It is not an
// answer to "would this be caught now", and the two were being read as one
// number: the log line was written by whatever engine was running that day,
// under a rule that did not exist yet, and no re-reading of it will ever show a
// rule that came later.
//
// So the second number is computed rather than read. Each sample is re-run
// through the engine in this build, against the .ngpack captured at the time and
// dated to the capture, so what changes between the two numbers is the engine
// and nothing else.
//
// A sample the rule cannot judge — no download count in the snapshot — is
// neither a hit nor a miss and is held out of the fraction, for the same reason
// bench holds it out of recall: a rule that declined to apply is not a rule that
// was wrong.
export interface RegradedSample {
  package: string
  version: string
  historicalScore: number | null
  historicalVerdict: string | null
  historicalGateBlocked: boolean
  currentVerdict: string | null
  currentScore: number | null
  blocked: boolean
  unevaluable: boolean
  detail: string
}

export interface CurrentEngineRecall {
  mode: 'gate' | 'audit'
  // The config the re-grade ran under, spelled out. The rule is opt-in, and the
  // question this number answers is what turning it on would buy — so it is run
  // with the rule on and says so, rather than reporting a shipped default that
  // cannot block and calling it a recall.
  ruleEnabled: boolean
  samples: RegradedSample[]
  // Samples with a snapshot the rule could actually be applied to.
  graded: number
  blocked: number
  unevaluable: number
  noSnapshot: number
  recall: RateWithCI | null
  statement: string
}

const UNVERIFIED_SIGNAL = 'fabricated_profile_unverified'

export async function regradeWithCurrentEngine(
  samples: FieldSample[],
  captures: CorpusSample[],
  mode: 'gate' | 'audit' = 'gate',
  // Defaults to the shipped thresholds with the conjunction switched ON. The
  // rule is opt-in, so the default config could never block any of these and the
  // number would be a tautology; what the promotion decision needs to know is
  // what the rule would do if it were on.
  ruleEnabled = true
): Promise<CurrentEngineRecall> {
  // Imported here rather than at the top: field-recall is loaded by bench for
  // its types alone in some paths, and inspect pulls in the whole scorer.
  const { inspect } = await import('./inspect.js')
  const { NgpackSource } = await import('./ngpack.js')
  const { DEFAULT_THRESHOLDS } = await import('./types.js')
  const config = { ...DEFAULT_THRESHOLDS[mode], blockFabricatedProfile: ruleEnabled }

  const out: RegradedSample[] = []

  for (const s of samples) {
    const base = {
      package: s.package,
      version: s.version,
      historicalScore: s.score,
      historicalVerdict: s.auditVerdict,
      historicalGateBlocked: s.gateBlocked,
    }

    const snapshot = snapshotFor(s.package, s.version, captures)
    if (!snapshot) {
      out.push({
        ...base,
        currentVerdict: null, currentScore: null,
        blocked: false, unevaluable: false,
        detail: 'no .ngpack on disk: the current engine has nothing to re-read',
      })
      continue
    }

    try {
      const result = await inspect(`${s.package}@${snapshot.version}`, {
        mode,
        config,
        source: new NgpackSource(snapshot.ngpackPath),
      })
      const unevaluable = result.signals.some(sig => sig.type === UNVERIFIED_SIGNAL)

      out.push({
        ...base,
        currentVerdict: result.verdict,
        currentScore: result.totalScore,
        blocked: result.verdict === 'BLOCK',
        unevaluable,
        detail: unevaluable
          ? 'the conjunction needs a download count and the snapshot carries none'
          : `${result.verdict} at score ${result.totalScore}, regime ${result.regime}`,
      })
    } catch (e) {
      // An unreadable snapshot is a corpus defect and must not be scored as a
      // miss, for the same reason bench separates unreadable from missed.
      out.push({
        ...base,
        currentVerdict: null, currentScore: null,
        blocked: false, unevaluable: false,
        detail: `snapshot unreadable: ${e}`,
      })
    }
  }

  const noSnapshot = out.filter(r => r.currentVerdict === null).length
  const unevaluable = out.filter(r => r.unevaluable).length
  const graded = out.length - noSnapshot - unevaluable
  const blocked = out.filter(r => r.blocked).length

  return {
    mode,
    ruleEnabled,
    samples: out,
    graded,
    blocked,
    unevaluable,
    noSnapshot,
    recall: graded > 0 ? rateWithCI(blocked, graded) : null,
    statement: graded > 0
      ? `${blocked}/${graded} blocked by the engine running now` +
        (ruleEnabled ? ', with the fabricated-profile rule switched on' : '')
      : `not calculable: ${out.length} samples, ${unevaluable} the rule cannot judge, ` +
        `${noSnapshot} with no snapshot to re-read`,
  }
}

// The snapshot that holds the version the removal was about, when there is one.
// Contaminated captures are excluded here as everywhere: a benchmark that admits
// them in one place and refuses them in another reports two different corpora
// under one name.
function snapshotFor(
  pkg: string,
  version: string,
  captures: CorpusSample[]
): CorpusSample | null {
  const usable = captures.filter(
    s => s.package === pkg && !s.contaminated && s.version !== NPM_SECURITY_HOLDER
  )
  return usable.find(s => s.version === version)
    ?? usable.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))[0]
    ?? null
}

// Every takedown the watcher saw as it happened, including the rotated days.
// This is the source that keeps up: it is written the moment npm's marker
// appears on the feed, while the sweep only knows what it knew when it ran.
//
// Exported because the precision denominator needs the same set: what fraction
// of the packages the filter marked npm went on to remove is the same question
// as which of them are in here, and two readers of one log must not drift.
export function readLiveTakedowns(outputDir: string): Set<string> {
  const packages = new Set<string>()
  if (!existsSync(outputDir)) return packages

  const record = (text: string) => {
    for (const line of text.split('\n')) {
      if (!line.trim()) continue
      try {
        const row = JSON.parse(line) as { package?: string; purgedVersions?: string[] }
        // A row with nothing purged is npm's marker over a package whose
        // versions were already gone: a removal, still.
        if (row.package) packages.add(row.package)
      } catch { /* one bad line does not invalidate the log */ }
    }
  }

  let names: string[]
  try { names = readdirSync(outputDir) } catch { return packages }

  for (const name of names) {
    if (!name.startsWith('takedown-log')) continue
    const path = join(outputDir, name)
    try {
      record(name.endsWith('.gz')
        ? gunzipSync(readFileSync(path)).toString('utf-8')
        : readFileSync(path, 'utf-8'))
    } catch { /* skip */ }
  }

  return packages
}

// The capture itself is the observation: its version and its capture time are
// what the collector saw, and it saw them before npm removed the version.
function observationFromCapture(pkg: string, captures: CorpusSample[]): TakedownFinding | null {
  const usable = captures.filter(
    s => s.package === pkg && !s.contaminated && s.version !== NPM_SECURITY_HOLDER
  )
  // The capture npm's marker actually labelled, when there is one: a package
  // captured several times has one snapshot that holds the removed version, and
  // that is the observation being graded. Otherwise the earliest.
  const sample =
    usable.find(s => s.label === 'confirmed_malicious' && s.labelSource?.includes('npm-takedown')) ??
    usable.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))[0]
  if (!sample) return null

  return { package: pkg, observedVersion: sample.version, observedAt: sample.capturedAt }
}

// The live day plus every rotated one, newest content last. Gzip is decompressed
// in memory: a day compresses to roughly a tenth, and the alternative is losing
// the history the moment rotation runs.
export function readChangeLogs(outputDir: string): string[] {
  const texts: string[] = []
  let names: string[]
  try { names = readdirSync(outputDir) } catch { return texts }

  for (const name of names.sort()) {
    if (!name.startsWith('changes-log')) continue
    const path = join(outputDir, name)
    try {
      texts.push(name.endsWith('.gz')
        ? gunzipSync(readFileSync(path)).toString('utf-8')
        : readFileSync(path, 'utf-8'))
    } catch { /* an unreadable day is one day short, not a failure */ }
  }
  return texts
}

function empty(statement: string): FieldRecallReport {
  return {
    takedownsFound: 0,
    preTakedownObservations: 0,
    takedownCoverage: null,
    scored: [], unscored: [],
    auditRecall: null, gateRecall: null,
    calculable: false,
    statement,
    evidence: {
      sweptAt: null,
      sweepTakedowns: 0,
      sweepObserved: 0,
      liveLogTakedowns: 0,
      labelledCaptures: 0,
      takedownsAfterSweep: 0,
      staleness: null,
    },
  }
}
