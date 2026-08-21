// A5. Do the four capabilities separate the confirmed removals from packages of
// the same size, from the same days, that npm did not remove?
//
// The design is fixed here, in this file, before any of it runs, because every
// decision it makes has a version that produces a larger difference and the
// larger version is always available afterwards.
//
// THE CASES ARE NOT 42. The corpus holds 42 confirmed_malicious captures with
// their bytes, and that is a count of captures. They are 6 packages, and those 6
// packages were published by 3 npm accounts:
//
//     siwatfa      @siwatfa/yorn                                   36 captures
//     a_soclav     kit-hydration-vim, svelte-goal-vim               2 captures
//     ferrousdev   bcs-core, sui-gql-core, leb128x                  4 captures
//
// A rate over the 42 is a rate over how often one operator republished, and
// @siwatfa/yorn republished 36 times in 38 hours. So every number here is
// computed at three units — capture, package, publisher — the publisher one is
// the primary, and the capture one is printed beside it so the size of the
// difference between them is visible rather than arguable. `dedupeByPackage` in
// size-control.ts made the same decision for the same reason and this only takes
// it one level further, because the corpus turned out to have one level more of
// it than that file knew about.
//
// THE CONTROL: same size, same days, not withdrawn. Drawn from the captures the
// watcher already took, matched to each case on unpacked size, excluding every
// package known to have been removed by npm. Its acquisition is identical to the
// cases' — the same collector, the same disk, the same window — so the one thing
// that differs is what is being asked about. What that does NOT control for is
// what the capture filter selects on, and the report says so in its own words:
// both capture reasons are enriched populations, and a control drawn through the
// same filter represents the filter's output rather than the ecosystem.
//
// WHAT THIS CANNOT BECOME. Not a score. There are no weights here, nothing is
// summed, and no capability is worth more than another. The question is whether
// the four separate the populations at all; what to do about it if they do is a
// later decision that needs this answer first and would corrupt it if taken now.

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'
import { join } from 'node:path'
import { loadCorpus, type CorpusSample, type LabeledCorpus } from './corpus.js'
import { readLiveTakedowns } from './field-recall.js'
import { capturePackument } from './size-control.js'
import { NgpackSource } from './ngpack.js'
import { readTar, DEFAULT_TAR_LIMITS, type TarLimits, type TarReadResult } from './tarball.js'
import { analyzeArchive } from './analyzability-run.js'
import { scanArchive, type CapabilityScan } from './capability-run.js'
import {
  resolutionProfileOf, strictCapabilitiesOf, compareBinary, compareContinuous,
  AUTHORED_OPACITY,
  type ResolutionProfile, type OpacityComparison, type ContinuousComparison,
} from './import-opacity.js'
import { operatorOf, collapse, linkFor } from './operator.js'
import { capabilitiesOf, answerFor, CAPABILITIES, capabilityDefinitions, capabilityCaveats, type Answer, type Capability } from './capabilities.js'
import { NPM_SECURITY_HOLDER } from './takedown.js'
import type { LegibilityThreshold } from './analyzability.js'
import {
  differenceWithCI, rateWithCI, zForFamily,
  type DifferenceWithCI, type RateWithCI,
} from './stats.js'

// ---------------------------------------------------------------------------
// Declared before the run
// ---------------------------------------------------------------------------

// Controls drawn per case package. Ten is where the interval on the control rate
// stops being the thing that dominates the difference: past it the width is set
// by the case side, which has 6 packages in it and cannot be widened by drawing
// more of anything else.
export const MATCH_RATIO = 10

// How close in size a control has to be. 0.3 on a log10 scale is a factor of
// two, which is the tightest band that can be filled at every one of the sizes
// the cases occupy — 2.3KB at one end and 26MB at the other.
export const SIZE_CALIPER_LOG10 = 0.3

// Below this a difference is not worth calling one. Wider than size-control.ts's
// 0.10 and deliberately: this comparison has 6 packages on the case side, and a
// margin narrower than the interval can ever be is a margin that can only ever
// return "inconclusive", which is a decision rule that never decides.
export const EQUIVALENCE_MARGIN = 0.20

// The intervals the opacity section adds to the family, declared here beside the
// other pre-run constants rather than derived from the array that produces them —
// so that adding a measure and forgetting to widen the correction is a test
// failure and not a silent loosening. `test/capabilities.test.ts` pins it against
// what the run actually prints.
//
// Five binary opacity measures at the primary unit (any authored opacity, plus the
// four authored kinds one at a time) and four strict-capability comparisons. The
// continuous measures add none: they are reported as medians and a
// common-language effect size with no interval and no threshold, which is a
// description and not a test.
export const OPACITY_ENDPOINTS = 9

// The units a package can be counted at, and what each one represents.
//
//   capture      every snapshot. @siwatfa/yorn is 36 of them and one operator,
//                so a rate here is a rate of republishing.
//   package      one per name, represented by the EARLIEST capture of it.
//   publisher    one per npm account, represented by its earliest capture.
//
// The two `-any` units answer a different question with the same data: not
// "what did the first version reach" but "did this package, or this operator,
// ever demonstrate the capability in the window". They exist because the
// earliest-capture rule has a failure mode this corpus contains — leb128x@1.0.0
// requires ./_perf.js and does not ship it, and the payload arrives in 1.0.1, so
// the earliest capture of that package is the staging version and reports
// nothing. Taking the earliest is right for avoiding republication weight and
// wrong for asking what a package can do.
//
// Both sides are expanded the same way. Every control package brings every
// capture of it in the window too, so the union rule gives the cases and the
// controls the same number of chances to fire. Without that it would give the
// cases 36 draws and the controls one.
export type Unit = 'capture' | 'package' | 'publisher' | 'operator' | 'package-any' | 'publisher-any'
export const UNITS: Unit[] = ['capture', 'package', 'publisher', 'operator', 'package-any', 'publisher-any']

// The publisher unit assumes accounts are independent, and the corpus contains a
// counter-example: ferrousdev, wokorc and corssdev are one operator, established
// by a package.json field order no other publisher in 10,192 names uses and by
// the same two-tier dependency structure four times in 28.6 hours. See
// operator.ts.
//
// So `publisher` over-counts the independent events it exists to count, and the
// primary unit moves to `operator`, which is the publisher unit with the
// declared links collapsed. Where no link is declared an account is its own
// operator, so the operator unit is never coarser than the publisher unit by
// accident — it differs only where a merge has been demonstrated and written
// down.
//
// Both are printed. `publisher` stays in the output because every earlier run
// reported it and a reader comparing against those needs the same number, not a
// silently improved one.
export const PRIMARY_UNIT: Unit = 'operator'
export const PREVIOUS_PRIMARY_UNIT: Unit = 'publisher'
// The one to read when the question is what the code reaches rather than how
// many independent events there were. Both are printed; neither replaces the
// other.
export const CAPABILITY_UNIT: Unit = 'publisher-any'

// Names that must never enter the case cohort whatever their label says: the two
// packages the observed class was DEFINED from. A rule validated against the
// samples that produced it measures nothing, and this is the one place where
// that could happen silently.
//
// Neither is on disk — 0 of 17,904 captures — so today the guard removes
// nothing. It stays because the day one of them is re-captured is the day it
// would silently enter, and a guard that only exists once it is needed is a
// guard nobody wrote.
export const INSPIRED_THE_CLASS = ['prezdentkxheiw', 'internallib_v756']

// The other direction of the same rule, and the one that could not be handled by
// exclusion: cases that did not inspire a SIGNAL, but did set a BOUND in the
// machinery that answers the question about them. Declared here rather than
// discovered later by a reader with grep.
//
// Excluding them is not the fix. Two of the six would leave four, and the
// bounds they set are in the analyser rather than in the definitions — removing
// the packages would not remove their influence on how every other package is
// measured. What is done instead is to state each one, and to measure whether
// the bound it set changed its own answer. `blindedSolelyByDepthLimit` in the
// report is that measurement: it counts the capability answers that rest on the
// walk bound and on nothing else, and if it is zero then the contaminated bound
// decided nothing here.
export const NAMED_IN_THE_CODEBASE: Array<{ package: string; where: string; what: string }> = [
  {
    package: '@siwatfa/yorn',
    where: 'src/reachability.ts, the comment above MAX_BODY_WALKS',
    what: 'it is the named reason the function-body walk is bounded at 300, and that bound raises depth-limit, which blinds all four capabilities',
  },
  {
    package: 'kit-hydration-vim',
    where: 'test/analyzability.test.ts and docs/benchmark.md',
    what: 'its calc.dat is the worked example for classifying a file by magic bytes rather than extension, and that classifier is what sets opaqueExecutable, which blinds all four capabilities',
  },
  {
    package: 'svelte-goal-vim',
    where: 'docs/benchmark.md',
    what: 'reported there as a coverage result. It is a number that was printed about it, not a rule that was drawn from it',
  },
]

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

export interface CohortMember {
  package: string
  version: string
  capturedAt: string
  ngpackPath: string
  unpackedSize: number
  // The npm account that published the version captured. This is what makes a
  // campaign countable: three of the six cases share one, two more share
  // another. Null when the packument did not record it.
  publisher: string | null
  captureReason?: string
  label: string
}

export interface MeasuredMember {
  member: CohortMember
  scan: CapabilityScan
  answers: Record<Capability, Answer>
  // The same four under the post-hoc definition of credential_read. Reported
  // apart, always.
  repaired: Record<Capability, Answer>
  // The same four counting only evidence a reader can check: a module resolved by
  // name, or an ambient call the parser read. A frozen `reached` that rested on
  // the walk having LOST the specifier becomes indeterminate here, because "the
  // specifier could not be read" is not evidence that it does not reach. See
  // import-opacity.ts. Reported apart, like `repaired`, and never in place of
  // `answers`.
  strict: Record<Capability, Answer>
  // What the walk could and could not follow, as a measurement rather than as a
  // blinder. Null when the archive was never opened: a package nothing read has
  // no resolution rate, and a zero there would put "we did not look" and "it hides
  // nothing" in one bucket.
  profile: ResolutionProfile | null
  failure?: string
}

// Size and publisher from the capture's own packument, never from npm today: the
// packument on the registry now holds versions that did not exist when the
// watcher looked, and for a removed package it holds nothing at all.
export function memberOf(sample: CorpusSample): CohortMember | null {
  const packument = capturePackument(sample.ngpackPath)
  if (!packument) return null

  const meta = packument.versions[sample.version]
  if (!meta) return null

  const raw = meta as unknown as { _npmUser?: NpmUser }
  const maintainers = (packument as unknown as { maintainers?: Array<{ name?: string }> }).maintainers

  return {
    package: sample.package,
    version: sample.version,
    capturedAt: sample.capturedAt,
    ngpackPath: sample.ngpackPath,
    unpackedSize: meta.unpackedSize,
    publisher: publisherOf(raw._npmUser, maintainers),
    captureReason: sample.captureReason,
    label: sample.label,
  }
}

interface NpmUser {
  name?: string
  email?: string
  trustedPublisher?: unknown
}

// npm's OIDC trusted publishing writes the WORKFLOW as _npmUser, not the human:
// every package released that way carries _npmUser.name "GitHub Actions" (or
// "CircleCI") with the shared address npm-oidc-no-reply@github.com. Read
// literally, that is one publisher, and the publisher unit is the primary unit
// of the whole comparison — so eighteen control packages owned by eleven real
// accounts collapsed into two, and `atUnit` keeps one capture per group, which
// discarded sixteen of the sixty measured control packages from the primary
// analysis. The case arm never trips this (siwatfa, ferrousdev and a_soclav all
// publish with a token), so the error was one-sided and shrank the control side
// alone.
//
// trustedPublisher is the structural marker npm sets on exactly these releases
// and it was present on all 18 in the v1.3.0 control arm; the address is checked
// too so a provider that stops emitting the object still lands here.
export function isTrustedPublisherIdentity(user: NpmUser | undefined): boolean {
  if (!user) return false
  return user.trustedPublisher !== undefined || user.email === 'npm-oidc-no-reply@github.com'
}

// The account, not the workflow. Falls through to the first maintainer when
// _npmUser is a CI identity, which is the same fallback the missing-_npmUser
// case already used — the bug was that a bot identity is present, not absent, so
// `??` never reached it.
export function publisherOf(
  user: NpmUser | undefined,
  maintainers: Array<{ name?: string }> | undefined
): string | null {
  if (isTrustedPublisherIdentity(user)) return maintainers?.[0]?.name ?? null
  return user?.name ?? maintainers?.[0]?.name ?? null
}

// ---------------------------------------------------------------------------
// The match
// ---------------------------------------------------------------------------

export interface Match {
  case: CohortMember
  controls: CohortMember[]
  // How many short of MATCH_RATIO, and why. A case that could not be matched is
  // reported rather than dropped: the sizes that cannot be filled are the ones
  // where the class is unusual, which is exactly what a control is for.
  shortfall: number
}

function logSize(bytes: number): number {
  return Math.log10(Math.max(1, bytes))
}

// Nearest neighbour on log size, within the caliper, without replacement.
//
// Deciles were the method in size-control.ts and they are the wrong one here.
// Deciles need a distribution to cut, and six packages spanning four orders of
// magnitude do not have one: nine of the ten edges would fall between two
// points. Nearest neighbour asks the only question there is at this n — for
// THIS package, what else of this size was published that week — and the caliper
// is what stops it answering with something ten times larger because nothing
// closer was left.
export function matchOnSize(
  cases: CohortMember[],
  pool: CohortMember[],
  ratio = MATCH_RATIO,
  caliper = SIZE_CALIPER_LOG10
): Match[] {
  const taken = new Set<string>()

  // Largest case first. The tails are where the pool is thin, and a smaller case
  // that draws first can empty a band the larger one had no alternative to.
  const order = [...cases].sort((a, b) => b.unpackedSize - a.unpackedSize)
  const byCase = new Map<string, Match>()

  for (const c of order) {
    const target = logSize(c.unpackedSize)
    const candidates = pool
      .filter(p => !taken.has(p.package) && Math.abs(logSize(p.unpackedSize) - target) <= caliper)
      .sort((x, y) => {
        const dx = Math.abs(logSize(x.unpackedSize) - target)
        const dy = Math.abs(logSize(y.unpackedSize) - target)
        // The date breaks the tie, so a rerun draws the same control set.
        return dx !== dy ? dx - dy : x.capturedAt.localeCompare(y.capturedAt)
      })
      .slice(0, ratio)

    for (const picked of candidates) taken.add(picked.package)
    byCase.set(c.package, { case: c, controls: candidates, shortfall: ratio - candidates.length })
  }

  return cases.map(c => byCase.get(c.package)!)
}

// The widest size gap between a case and any control capture actually measured
// against it. Falls back to the matched representatives when the measured set is
// empty, so a case whose controls all dropped out still reports a ratio rather
// than a null that reads as "no mismatch".
export function worstRatioOver(match: Match, measured: CohortMember[]): number | null {
  const inMatch = new Set(match.controls.map(c => c.package))
  const sizes = measured.filter(m => inMatch.has(m.package)).map(m => m.unpackedSize)
  const pool = sizes.length > 0 ? sizes : match.controls.map(c => c.unpackedSize)
  if (pool.length === 0) return null

  return Math.max(...pool.map(size =>
    Math.max(size, match.case.unpackedSize) / Math.max(1, Math.min(size, match.case.unpackedSize))
  ))
}

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

export interface CapabilityCount {
  capability: Capability
  reached: number
  notReached: number
  indeterminate: number
  // Over the members whose answer is one or the other. The rate a difference is
  // computed on, and the one that assumes the indeterminate members would have
  // split the same way — which is the assumption, and it is stated.
  overDeterminate: RateWithCI
  // The two ends of what the whole group could be, with no assumption at all:
  // none of the indeterminate ones reach it, or all of them do. When these are
  // far apart, the rate above is an interpolation and should be read as one.
  atLeast: number
  atMost: number
}

export interface GroupReport {
  name: string
  unit: Unit
  members: number
  measured: number
  failures: Array<{ package: string; reason: string }>
  medianUnpackedSize: number | null
  byCapability: CapabilityCount[]
  // How the measurement itself went, which is half the finding here.
  refusedToAnalyse: number
  shipsOpaqueExecutable: number
  // Either of the two above: the members whose four answers were decided by the
  // reader failing rather than by the code. This is the number the differential-
  // blinding caveat has to quote, and quoting only the opacity half is what made
  // v1.3.0 report the control side as 15 of 99 instead of 29 of 99.
  blindedAtEntry: number
  noEntryPoint: number
  reachesExternalDependency: number
  byCaptureReason: Array<{ reason: string; members: number }>
  // credential_read is a disjunction, and the two halves are not the same claim:
  // a path naming a secret that reached a filesystem call is specific, and
  // reading process.env.NPM_TOKEN is what half of npm's build tooling does.
  // Counted apart so a rate driven entirely by the second half cannot be read as
  // if it were driven by the first.
  credentialEvidence: { secretPath: number; tokenEnv: number }
}

function counts(members: MeasuredMember[], pick: (m: MeasuredMember) => Record<Capability, Answer>): CapabilityCount[] {
  return CAPABILITIES.map(capability => {
    const answers = members.map(m => pick(m)[capability])
    const reached = answers.filter(a => a === 'reached').length
    const notReached = answers.filter(a => a === 'not-reached').length
    const indeterminate = answers.filter(a => a === 'indeterminate').length
    const n = members.length
    return {
      capability,
      reached, notReached, indeterminate,
      overDeterminate: rateWithCI(reached, reached + notReached),
      atLeast: n > 0 ? reached / n : 0,
      atMost: n > 0 ? (reached + indeterminate) / n : 0,
    }
  })
}

// One member per unit. The earliest capture, exactly as size-control.ts picks
// it: the clock starts when the collector first saw the thing, and taking the
// latest would let a package that republished for two days be represented by
// whichever version happened to be last.
//
// The `-any` units instead fold every capture of the unit into one answer, by
// the only lattice the three values admit: reached if any capture reached it,
// not-reached only if every capture answered and none of them did, and
// indeterminate otherwise. A capability demonstrated once is demonstrated.
export function atUnit(members: MeasuredMember[], unit: Unit): MeasuredMember[] {
  if (unit === 'capture') return members

  const byKey = new Map<string, MeasuredMember[]>()
  for (const m of members) {
    const key = unit === 'package' || unit === 'package-any'
      ? m.member.package
      : unit === 'operator'
        ? (operatorOf(m.member.publisher) ?? `unknown:${m.member.package}`)
        : (m.member.publisher ?? `unknown:${m.member.package}`)
    const at = byKey.get(key)
    if (at) at.push(m)
    else byKey.set(key, [m])
  }

  const out: MeasuredMember[] = []
  for (const group of byKey.values()) {
    const earliest = [...group].sort((a, b) => a.member.capturedAt.localeCompare(b.member.capturedAt))[0]!
    if (unit === 'package' || unit === 'publisher' || unit === 'operator') { out.push(earliest); continue }
    out.push({
      ...earliest,
      answers: unionAnswers(group.map(m => m.answers)),
      repaired: unionAnswers(group.map(m => m.repaired)),
      strict: unionAnswers(group.map(m => m.strict)),
      scan: foldScans(group.map(m => m.scan), earliest.scan),
    })
  }
  return out.sort((a, b) => a.member.capturedAt.localeCompare(b.member.capturedAt))
}

export function unionAnswers(all: Array<Record<Capability, Answer>>): Record<Capability, Answer> {
  return Object.fromEntries(CAPABILITIES.map(capability => {
    const answers = all.map(a => a[capability])
    if (answers.includes('reached')) return [capability, 'reached']
    if (answers.includes('indeterminate')) return [capability, 'indeterminate']
    return [capability, 'not-reached']
  })) as Record<Capability, Answer>
}

// The `-any` fold has to reach the SCAN as well as the answers, and until this
// was written it did not: `atUnit` unioned `answers` and kept the earliest
// capture's `scan`, so every scan-derived counter in `summariseGroup` — opacity,
// never-opened, blinded-at-entry, external dependency, both halves of
// credential_read — described one capture at a unit whose declared contract is
// "ever, in the window".
//
// It is not cosmetic and it hit the run's own headline. On 2026-08-21 three case
// packages ship an executable no parser reads — @siwatfa/yorn, kit-hydration-vim
// and ai-texts — from three distinct accounts, and publisher-any printed 2 of 8,
// because rihannasmith's earliest capture is ai-texts-utils and the minified one
// is ai-texts. Opacity is the finding this study can actually support, and it was
// being undercounted at the unit that states it.
//
// The fold is deliberately NOT a blanket OR. Two of these fields record what a
// unit demonstrated and two record a failure to look at it, and they go opposite
// ways:
//
//   opaqueExecutable, externalModules,     ANY capture. A thing demonstrated
//   secretPathsReached, tokenEnvRead,      once is demonstrated, which is the
//   namelessEnvRead                        same lattice `unionAnswers` uses.
//
//   refusal, entryPoints                   EVERY capture. "Never opened at all"
//                                          means not once, so a unit with one
//                                          readable capture was opened, and
//                                          reporting it as refused would count a
//                                          blinder the analysis did not have.
//
// `reachability` cannot be unioned field by field without inventing a graph that
// no capture had, so it is represented rather than merged: the earliest capture
// that was opened AND resolved an entry point stands for the unit, falling back
// to the earliest opened one and then to the earliest. That is what makes the
// two intersecting fields come out right — `refusedToAnalyse` counts a unit only
// if nothing was ever opened, and `noEntryPoint` only if nothing ever resolved
// one — without claiming a reachability graph that was never computed.
export function foldScans(scans: CapabilityScan[], earliest: CapabilityScan): CapabilityScan {
  if (scans.length <= 1) return earliest

  const opened = scans.filter(s => s.refusal === null)
  const representative =
    opened.find(s => (s.reachability?.entryPoints.length ?? 0) > 0) ?? opened[0] ?? earliest
  const union = <T>(pick: (s: CapabilityScan) => T[]): T[] =>
    [...new Set(scans.flatMap(pick))]

  return {
    ...representative,
    // Null the moment any capture of this unit was readable.
    refusal: opened.length > 0 ? null : earliest.refusal,
    reachability: representative.reachability,
    opaqueExecutable: scans.some(s => s.opaqueExecutable),
    opaqueKinds: union(s => s.opaqueKinds),
    parseableFiles: Math.max(...scans.map(s => s.parseableFiles)),
    sourceBytes: Math.max(...scans.map(s => s.sourceBytes)),
    capabilities: {
      ...representative.capabilities,
      externalModules: union(s => s.capabilities.externalModules),
      secretPathsReached: union(s => s.capabilities.secretPathsReached),
      tokenEnvRead: union(s => s.capabilities.tokenEnvRead),
      namelessEnvRead: scans.some(s => s.capabilities.namelessEnvRead),
      secretPathGrepOnly: Math.max(...scans.map(s => s.capabilities.secretPathGrepOnly)),
    },
  }
}

export function summariseGroup(input: {
  name: string
  unit: Unit
  members: MeasuredMember[]
  failures: Array<{ package: string; reason: string }>
  repaired?: boolean
  strict?: boolean
}): GroupReport {
  const { members } = input
  const byReason = new Map<string, number>()
  for (const m of members) {
    const reason = m.member.captureReason ?? 'unrecorded'
    byReason.set(reason, (byReason.get(reason) ?? 0) + 1)
  }

  const sizes = members.map(m => m.member.unpackedSize).sort((a, b) => a - b)

  return {
    name: input.name,
    unit: input.unit,
    members: members.length,
    measured: members.filter(m => !m.failure).length,
    failures: input.failures,
    medianUnpackedSize: sizes.length > 0 ? sizes[Math.floor(sizes.length / 2)]! : null,
    byCapability: counts(members, m => (input.strict ? m.strict : input.repaired ? m.repaired : m.answers)),
    refusedToAnalyse: members.filter(m => m.scan.refusal !== null).length,
    shipsOpaqueExecutable: members.filter(m => m.scan.opaqueExecutable).length,
    blindedAtEntry: members.filter(m => m.scan.opaqueExecutable || m.scan.refusal !== null).length,
    noEntryPoint: members.filter(m => m.scan.reachability?.entryPoints.length === 0).length,
    reachesExternalDependency: members.filter(m => m.scan.capabilities.externalModules.length > 0).length,
    byCaptureReason: [...byReason.entries()]
      .map(([reason, n]) => ({ reason, members: n }))
      .sort((a, b) => b.members - a.members),
    credentialEvidence: {
      secretPath: members.filter(m => m.scan.capabilities.secretPathsReached.length > 0).length,
      tokenEnv: members.filter(m => m.scan.capabilities.tokenEnvRead.length > 0).length,
    },
  }
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

export interface CapabilityComparison {
  capability: Capability
  unit: Unit
  difference: DifferenceWithCI
  // The same difference at the z the whole family of printed comparisons needs.
  familyAdjusted: DifferenceWithCI
  verdict: string
}

export interface UnitComparison {
  unit: Unit
  cases: GroupReport
  controls: GroupReport
  capabilities: CapabilityComparison[]
  // Per unit, because each one has a different n and the capture unit's n is
  // the one that looks strongest and means least.
  power: ReturnType<typeof smallestDetectableEffect>
}

export function compareAt(cases: GroupReport, controls: GroupReport, z: number): CapabilityComparison[] {
  return CAPABILITIES.map(capability => {
    const a = cases.byCapability.find(c => c.capability === capability)!
    const b = controls.byCapability.find(c => c.capability === capability)!

    const difference = differenceWithCI(
      a.overDeterminate.successes, a.overDeterminate.n,
      b.overDeterminate.successes, b.overDeterminate.n
    )
    const familyAdjusted = differenceWithCI(
      a.overDeterminate.successes, a.overDeterminate.n,
      b.overDeterminate.successes, b.overDeterminate.n,
      z
    )

    return {
      capability,
      unit: cases.unit,
      difference,
      familyAdjusted,
      verdict: verdictFor(capability, a, b, familyAdjusted),
    }
  })
}

const pp = (x: number): string => `${x >= 0 ? '+' : ''}${(x * 100).toFixed(1)}pp`

export function verdictFor(
  capability: Capability,
  cases: CapabilityCount,
  controls: CapabilityCount,
  d: DifferenceWithCI
): string {
  if (d.difference === null || d.low === null || d.high === null) {
    return (
      `Not calculable. ${cases.reached + cases.notReached} of the cases and ` +
      `${controls.reached + controls.notReached} of the controls got a yes-or-no answer for ` +
      `${capability}; the rest were indeterminate, and a rate over an empty denominator is not a rate.`
    )
  }

  // The bound comes first because at this n it is usually wider than the
  // interval, and quoting the interval without it is quoting the assumption.
  const bounded =
    cases.indeterminate > 0
      ? ` The case side has ${cases.indeterminate} indeterminate, so the group is between ` +
        `${(cases.atLeast * 100).toFixed(1)}% and ${(cases.atMost * 100).toFixed(1)}% whatever this interval says.`
      : ''

  if (d.separated && d.difference > 0) {
    return (
      `SEPARATES. ${capability} is reached by the cases ${pp(d.difference)} more often than by ` +
      `size-matched packages npm did not remove (family-adjusted CI ${pp(d.low)} to ${pp(d.high)}, ` +
      `excludes zero).${bounded}`
    )
  }
  if (d.separated && d.difference < 0) {
    return (
      `RUNS THE OTHER WAY. The controls reach ${capability} ${pp(-d.difference)} more often than the ` +
      `cases (family-adjusted CI ${pp(-d.high)} to ${pp(-d.low)}).${bounded}`
    )
  }

  const inside = d.high < EQUIVALENCE_MARGIN && d.low > -EQUIVALENCE_MARGIN
  if (inside) {
    return (
      `NO DIFFERENCE WORTH THE NAME. ${pp(d.difference)}, and the whole interval (${pp(d.low)} to ` +
      `${pp(d.high)}) is inside the ${pp(EQUIVALENCE_MARGIN)} margin declared before the run.${bounded}`
    )
  }

  return (
    `INCONCLUSIVE at this n. ${pp(d.difference)}, interval ${pp(d.low)} to ${pp(d.high)}, over ` +
    `${cases.overDeterminate.n} cases and ${controls.overDeterminate.n} controls. Neither a ` +
    `difference nor the absence of one.${bounded}`
  )
}

// What this run could have found, computed before it is read. The largest
// control rate that would still leave the interval clear of zero when every
// single case reaches the capability — i.e. the best case for a difference. If
// that number is high, the run cannot distinguish a real signal from a common
// one and the reader needs to know that before the rates.
export function smallestDetectableEffect(nCases: number, nControls: number, z: number): {
  nCases: number
  nControls: number
  maxControlsReaching: number
  statement: string
} {
  if (nCases === 0 || nControls === 0) {
    return { nCases, nControls, maxControlsReaching: 0, statement: 'not calculable: one side is empty' }
  }

  let best = -1
  for (let k = 0; k <= nControls; k++) {
    const d = differenceWithCI(nCases, nCases, k, nControls, z)
    if (d.separated) best = k
    else break
  }

  if (best < 0) {
    return {
      nCases, nControls, maxControlsReaching: 0,
      statement:
        `NOTHING IS DETECTABLE HERE. With ${nCases} cases and ${nControls} controls, even every case ` +
        `reaching a capability and no control reaching it does not produce an interval that excludes ` +
        `zero at the adjusted z. Every rate below is descriptive and none of them is a finding.`,
    }
  }

  return {
    nCases, nControls, maxControlsReaching: best,
    statement:
      `With ${nCases} cases and ${nControls} controls, the most this run can find is: every case ` +
      `reaches a capability and at most ${best} of ${nControls} controls (${(100 * best / nControls).toFixed(1)}%) do. ` +
      `Anything commoner than that in the controls cannot be separated from it at this n, whatever the ` +
      `cases do.`,
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface ControlOptions {
  roots?: string[]
  outputDir: string
  threshold?: LegibilityThreshold
  engineVersion: string
  limits?: TarLimits
  matchRatio?: number
  caliper?: number
  // Widens the window past the cases' own span. Off by default: the window IS
  // the days the cases were captured on, and choosing a wider one is choosing
  // which controls exist.
  since?: string
  until?: string
  // Restrict the control pool to one captureReason.
  //
  // Off by default, and it exists because the default is not the like-for-like
  // comparison it reads as. The two capture reasons select different
  // populations — 'quarantine-no-genome' keeps everything matching the three
  // conjuncts of the observed class, 'watcher-threshold' keeps whatever scored
  // high — and on the 2026-08-21 run the case arm was 7 of 8 quarantine while
  // the matched controls were 49 of 125. Size matching narrows that gap (the
  // pool is 13.5% quarantine and the matched controls are 39.2%, because the
  // cases are tiny and so is that class) and does not close it. Passing this
  // trades control-arm size for a control drawn through the same filter.
  controlCaptureReason?: string
  onProgress?: (stage: string, done: number, total: number) => void
  now?: () => string
}

export interface CapabilityControlReport {
  ranAt: string
  engineVersion: string
  definitions: Array<{ capability: Capability; definition: string }>
  design: {
    matchRatio: number
    caliper: number
    equivalenceMargin: number
    primaryUnit: Unit
    excluded: string[]
    // Null when the control pool was drawn from every capture reason, which is
    // the default and is NOT a like-for-like draw. See ControlOptions.
    controlCaptureReason: string | null
  }
  window: { since: string; until: string }
  cohort: {
    confirmedCaptures: number
    confirmedWithBytes: number
    excludedByName: string[]
    cases: number
    casePackages: number
    casePublishers: Array<{ publisher: string; packages: string[]; captures: number }>
    unclassifiable: number
  }
  pool: {
    inWindow: number
    withBytes: number
    afterRemovedExcluded: number
    removedKnown: number
    // Which record each name came from, before the union. The four are not the
    // same event and the difference is worth keeping: npm publishing
    // 0.0.1-security is a takedown, and an author unpublishing their own package
    // is not. Both disqualify a control, because the question the control
    // answers is "what did the packages that stayed look like".
    removedBySource: Array<{ source: string; names: number; newHere: number }>
    distinctPackages: number
    byCaptureReason: Array<{ reason: string; packages: number }>
  }
  matches: Array<{
    case: string
    caseBytes: number
    controls: number
    shortfall: number
    controlBytes: number[]
    // The furthest any drawn control is from its case, as a ratio. This is the
    // size control, checked; a pooled median cannot check it.
    worstRatio: number | null
    controlCaptures: number
    controlCaptureBytes: number[]
    // The control set, by name. A control group whose membership is not
    // recorded cannot be re-checked by anyone, including a later run of this.
    controlPackages: string[]
  }>
  // Captures of matched control packages that fell outside the size band on the
  // expansion and were dropped before measurement.
  outOfCaliper: Array<{ package: string; version: string; unpackedSize: number; ratio: number }>
  endpointFamily: number
  endpointZ: number
  power: ReturnType<typeof smallestDetectableEffect>
  // The six, one row each, because "what capabilities do the confirmed removals
  // reach" is a question about six packages and a rate over three publishers is
  // not a readable answer to it.
  caseDetail: Array<{
    package: string
    publisher: string | null
    captures: number
    versions: string[]
    unpackedSize: number
    opaque: string[]
    refusals: number
    answers: Record<Capability, Answer>
    evidence: string[]
  }>
  contamination: {
    declared: typeof NAMED_IN_THE_CODEBASE
    // Capability answers that are indeterminate because of the walk bound
    // @siwatfa/yorn set, and because of nothing else. Zero means the
    // contaminated bound changed no answer in this run.
    blindedSolelyByDepthLimit: number
    // The same for the classifier kit-hydration-vim is the example for.
    blindedSolelyByOpacity: number
    statement: string
  }
  comparisons: UnitComparison[]
  // What the run found at the primary unit, computed from the comparisons and
  // printed above them. It exists so the finding cannot be assembled by a reader
  // out of whichever row they reached first.
  headline: Headline
  // IDEA 1 AND 2 — what the walk could not follow, counted instead of only used
  // as a blinder, and the capability answers recomputed on resolved evidence
  // alone. See import-opacity.ts.
  opacity: {
    note: string
    unit: Unit
    endpointsAdded: number
    binary: OpacityComparison[]
    continuous: ContinuousComparison[]
    // How many members had no profile at all, per arm. A package nothing opened
    // cannot have a resolution rate, and it is held out rather than zeroed.
    withoutProfile: { cases: number; controls: number }
    strict: {
      note: string
      cases: GroupReport
      controls: GroupReport
      capabilities: CapabilityComparison[]
      // Frozen `reached` answers that the strict pass demotes, per capability and
      // per arm. If this is zero everywhere then the frozen answers rested on
      // resolved evidence all along and idea 2 changed nothing — which is a
      // result and is stated as one.
      demoted: Array<{ capability: Capability; cases: number; controls: number }>
    }
  }
  // The post-hoc definition, at the primary unit only, and never folded into the
  // comparisons above.
  posthoc: {
    note: string
    cases: GroupReport
    controls: GroupReport
    capabilities: CapabilityComparison[]
  } | null
  caveats: string[]
}

// The case arm, assembled once. Extracted from `runCapabilityControl` so that
// `norte-guard corpus --publishers` reports the number A5 will actually use
// rather than a second implementation of the same filter. The count of distinct
// publishers here is what decides whether A5 is worth re-running, and a decision
// number that two code paths can disagree about is a number nobody can act on.
export interface CaseCohort {
  confirmed: CorpusSample[]
  withBytes: CorpusSample[]
  // Confirmed removals whose tarball is gone. Not a filter detail: the sweep
  // documented in docs/audit-a5.md deleted 3,190 referenced objects, 31 of them
  // labelled, and that is why this arm is smaller than the corpus suggests.
  withoutBytes: CorpusSample[]
  excludedByName: string[]
  members: CohortMember[]
  unclassifiable: number
}

export function caseCohortOf(corpus: LabeledCorpus): CaseCohort {
  const confirmed = corpus.confirmedMalicious
  const withBytes = confirmed.filter(s => s.tarballPresent)
  const excludedByName = withBytes
    .filter(s => INSPIRED_THE_CLASS.includes(s.package))
    .map(s => `${s.package}@${s.version}`)

  const caseSamples = withBytes.filter(s => !INSPIRED_THE_CLASS.includes(s.package))

  const members: CohortMember[] = []
  let unclassifiable = 0
  for (const sample of caseSamples) {
    const member = memberOf(sample)
    if (!member) { unclassifiable++; continue }
    members.push(member)
  }

  return {
    confirmed,
    withBytes,
    withoutBytes: confirmed.filter(s => !s.tarballPresent),
    excludedByName,
    members,
    unclassifiable,
  }
}

export function runCapabilityControl(options: ControlOptions): CapabilityControlReport {
  const corpus = loadCorpus(options.roots)

  const cohort = caseCohortOf(corpus)
  const { withBytes, excludedByName, unclassifiable } = cohort
  const confirmed = cohort.confirmed
  const caseMembers = cohort.members

  // The window is the cases' own span unless the caller overrides it, and an
  // override is recorded in the report because it decides which controls exist.
  const times = caseMembers.map(m => m.capturedAt).sort()
  const since = options.since ?? times[0] ?? ''
  const until = options.until ?? times[times.length - 1] ?? ''

  // Every way of knowing a package left the registry, unioned. A control that
  // turns out to have been withdrawn is not a control.
  const withdrawn = withdrawnPackages(options.outputDir, corpus.samples)
  const removed = withdrawn.names

  const inWindow = corpus.samples.filter(s =>
    !s.contaminated && s.capturedAt >= since && s.capturedAt <= until
  )
  const poolWithBytes = inWindow.filter(s => s.tarballPresent)
  const poolSamples = poolWithBytes.filter(s =>
    s.label !== 'confirmed_malicious' && !removed.has(s.package) &&
    (options.controlCaptureReason === undefined || s.captureReason === options.controlCaptureReason)
  )

  const poolMembers: CohortMember[] = []
  for (const sample of poolSamples) {
    const member = memberOf(sample)
    if (member) poolMembers.push(member)
  }

  // One capture per package on the control side, before the match, so a package
  // that republished forty times cannot occupy forty of the ten slots.
  const poolByPackage = new Map<string, CohortMember>()
  for (const m of poolMembers) {
    const seen = poolByPackage.get(m.package)
    if (!seen || m.capturedAt < seen.capturedAt) poolByPackage.set(m.package, m)
  }
  const pool = [...poolByPackage.values()]

  // The cases are matched at the PACKAGE level — one case package, ten controls
  // — and the capture-level group is built by giving every capture of a package
  // the controls its package drew. Matching per capture would draw 360 controls
  // for one operator's republishing.
  const casePackages = new Map<string, CohortMember>()
  for (const m of caseMembers) {
    const seen = casePackages.get(m.package)
    if (!seen || m.capturedAt < seen.capturedAt) casePackages.set(m.package, m)
  }

  const matches = matchOnSize(
    [...casePackages.values()], pool,
    options.matchRatio ?? MATCH_RATIO,
    options.caliper ?? SIZE_CALIPER_LOG10
  )

  // Every capture of every matched control package, not only the one that was
  // matched. The cases bring all of theirs — 36 of @siwatfa/yorn alone — so a
  // control side of one capture per package would give the union rule 36 chances
  // to fire on the case side and one on the control side. The match is still
  // made on one representative per package; what is expanded is what gets
  // measured afterwards.
  // The caliper has to survive the expansion, and in v1.3.0 it did not. The
  // match is made on ONE representative capture per control package, so the
  // ratio printed in the match table describes that representative — but what
  // gets measured is every capture of the package in the window, and a package
  // that grew or shrank between captures walks straight out of the band nobody
  // re-checked. @vanillaskyai/sdk was matched to @siwatfa/yorn at 26,605,866 B
  // and measured at 2,289,754 B: 11.39x, against a declared 1.995x, inside the
  // one arm that carried the run's only SEPARATES row.
  //
  // Each control package is re-tested against the case it was actually drawn
  // for, not against the pooled sizes: the match is per case and so is the band.
  const caliperUsed = options.caliper ?? SIZE_CALIPER_LOG10
  const targetFor = new Map<string, number>()
  for (const m of matches) {
    for (const c of m.controls) targetFor.set(c.package, logSize(m.case.unpackedSize))
  }

  const controlMembers: CohortMember[] = []
  const outOfCaliper: Array<{ package: string; version: string; unpackedSize: number; ratio: number }> = []
  for (const m of poolMembers) {
    const target = targetFor.get(m.package)
    if (target === undefined) continue
    const distance = Math.abs(logSize(m.unpackedSize) - target)
    if (distance <= caliperUsed) {
      controlMembers.push(m)
      continue
    }
    outOfCaliper.push({
      package: m.package,
      version: m.version,
      unpackedSize: m.unpackedSize,
      ratio: Math.pow(10, distance),
    })
  }

  // ---- measure ----------------------------------------------------------

  const caseFailures: Array<{ package: string; reason: string }> = []
  const controlFailures: Array<{ package: string; reason: string }> = []

  const measure = (
    members: CohortMember[],
    stage: string,
    failures: Array<{ package: string; reason: string }>
  ): MeasuredMember[] => {
    const out: MeasuredMember[] = []
    let done = 0
    for (const member of members) {
      options.onProgress?.(stage, ++done, members.length)
      const measured = measureMember(member, options)
      if (measured.failure) failures.push({ package: `${member.package}@${member.version}`, reason: measured.failure })
      out.push(measured)
    }
    return out
  }

  const measuredCases = measure(caseMembers, 'cases', caseFailures)
  const measuredControls = measure(controlMembers, 'controls', controlFailures)

  // ---- compare ----------------------------------------------------------

  const groups = UNITS.map(unit => ({
    unit,
    cases: summariseGroup({
      name: 'confirmed removals',
      unit,
      members: atUnit(measuredCases, unit),
      failures: caseFailures,
    }),
    controls: summariseGroup({
      name: 'size-matched, same days, not withdrawn',
      unit,
      members: atUnit(measuredControls, unit),
      failures: controlFailures,
    }),
  }))

  // Every interval this report prints is one of a family, and the family is
  // counted before any of them is read.
  //
  // It grew when the opacity endpoints were added, and it had to. Testing more
  // endpoints on the same data because the first four saturated is the textbook
  // shape of multiplicity, and the correction is the only thing that stops "we
  // tried nine things and one separated" from reading as a finding. The widening
  // is applied to the FOUR CAPABILITIES TOO, so their intervals in this run are
  // wider than in the run of 2026-08-21 — that is the cost of having looked at
  // more, and charging it to the new endpoints alone would be helping oneself.
  const capabilityEndpoints = groups.length * CAPABILITIES.length
  const endpointFamily = capabilityEndpoints + OPACITY_ENDPOINTS
  const z = zForFamily(endpointFamily)

  const comparisons: UnitComparison[] = groups.map(g => ({
    unit: g.unit,
    cases: g.cases,
    controls: g.controls,
    capabilities: compareAt(g.cases, g.controls, z),
    power: smallestDetectableEffect(g.cases.members, g.controls.members, z),
  }))

  const primary = comparisons.find(c => c.unit === PRIMARY_UNIT)!

  // At the capability unit rather than the primary one. The primary unit takes
  // the earliest capture per account, and the whole reason this repair exists is
  // a payload that arrived in a later version.
  const posthocCases = summariseGroup({
    name: 'confirmed removals, post-hoc credential_read',
    unit: CAPABILITY_UNIT,
    members: atUnit(measuredCases, CAPABILITY_UNIT),
    failures: caseFailures,
    repaired: true,
  })
  const posthocControls = summariseGroup({
    name: 'controls, post-hoc credential_read',
    unit: CAPABILITY_UNIT,
    members: atUnit(measuredControls, CAPABILITY_UNIT),
    failures: controlFailures,
    repaired: true,
  })

  return {
    ranAt: options.now ? options.now() : new Date().toISOString(),
    engineVersion: options.engineVersion,
    definitions: capabilityDefinitions(),
    design: {
      matchRatio: options.matchRatio ?? MATCH_RATIO,
      caliper: options.caliper ?? SIZE_CALIPER_LOG10,
      equivalenceMargin: EQUIVALENCE_MARGIN,
      primaryUnit: PRIMARY_UNIT,
      excluded: INSPIRED_THE_CLASS,
      controlCaptureReason: options.controlCaptureReason ?? null,
    },
    window: { since, until },
    cohort: {
      confirmedCaptures: confirmed.length,
      confirmedWithBytes: withBytes.length,
      excludedByName,
      cases: caseMembers.length,
      casePackages: casePackages.size,
      casePublishers: publisherBreakdown(caseMembers),
      unclassifiable,
    },
    pool: {
      inWindow: inWindow.length,
      withBytes: poolWithBytes.length,
      afterRemovedExcluded: poolSamples.length,
      removedKnown: removed.size,
      removedBySource: withdrawn.bySource,
      distinctPackages: pool.length,
      byCaptureReason: captureReasonBreakdown(pool),
    },
    matches: matches.map(m => ({
      case: `${m.case.package}@${m.case.version}`,
      caseBytes: m.case.unpackedSize,
      controls: m.controls.length,
      shortfall: m.shortfall,
      controlBytes: m.controls.map(c => c.unpackedSize),
      // What the match actually achieved, per case, which is the only place the
      // size control can be checked. A median over the pooled groups cannot
      // check it: the cases are 36 captures of one 26MB package and six of five
      // tiny ones, so their pooled median is 26MB and the pooled control median
      // is 8KB while every individual pair is within a factor of two.
      //
      // Computed over the captures that are MEASURED, not over the ten matched
      // representatives. Those are the same set now that the expansion re-applies
      // the caliper, and this is written over the measured set so that if the two
      // ever diverge again the number that is printed is the one describing what
      // was compared.
      worstRatio: worstRatioOver(m, controlMembers),
      controlCaptures: controlMembers.filter(p => m.controls.some(c => c.package === p.package)).length,
      // The sizes of the captures that were measured, which is what the printed
      // range has to describe. v1.3.0 printed the range of the ten matched
      // representatives on the same line as a capture count covering more of
      // them, so the range and the count described different sets.
      controlCaptureBytes: controlMembers
        .filter(p => m.controls.some(c => c.package === p.package))
        .map(p => p.unpackedSize),
      controlPackages: m.controls.map(c => c.package),
    })),
    // Captures of matched control packages that fell outside the band and were
    // therefore not measured. Silence here is what made v1.3.0 print 1.02x for a
    // pair that was 11.39x apart, so an empty list is stated rather than omitted.
    outOfCaliper,
    endpointFamily,
    endpointZ: z,
    power: smallestDetectableEffect(primary.cases.members, primary.controls.members, z),
    caseDetail: caseDetailOf(measuredCases),
    contamination: contaminationOf(measuredCases),
    comparisons,
    headline: headlineOf(comparisons, measuredCases),
    opacity: opacityReport(measuredCases, measuredControls, z),
    posthoc: {
      note:
        'The secret-path half of credential_read, repaired after the cases were opened: SECRET_PATHS ' +
        'holds joined paths and real code writes path.join(home, ".aws", "credentials"), whose ' +
        'arguments are three strings none of which is in the list. This is what the repaired ' +
        'definition finds. It is not validated by this run and cannot be — a definition changed after ' +
        'seeing the cases is fitted to them — and it is here so the next confirmed sample can be the ' +
        'test of it rather than the third place it is rediscovered.',
      cases: posthocCases,
      controls: posthocControls,
      capabilities: compareAt(posthocCases, posthocControls, z),
    },
    caveats: caveatsFor(measuredCases, measuredControls, matches),
  }
}

export function measureMember(member: CohortMember, options: { threshold?: LegibilityThreshold; limits?: TarLimits }): MeasuredMember {
  const blank = (failure: string): MeasuredMember => {
    // An archive that was never opened, described as one. Going through
    // scanArchive rather than hand-building the answer keeps one definition of
    // what an unread package answers.
    const unopened: TarReadResult = { entries: [], skipped: [], truncated: true, truncationReason: failure }
    const scan = scanArchive(unopened)
    return {
      member, scan, failure,
      answers: answersOf(scan),
      repaired: answersOf(scan),
      strict: answersOf(scan),
      profile: null,
    }
  }

  if (!existsSync(join(member.ngpackPath, 'manifest.json'))) return blank('no manifest on disk')

  let tarball: Buffer | undefined
  try {
    const source = new NgpackSource(member.ngpackPath)
    if (source.missingTarballs.includes(member.version)) {
      return blank('tarball bytes are no longer in the object store')
    }
    tarball = source.tarballSync(member.version) ?? source.tarballSync() ?? undefined
  } catch (e) {
    return blank(`unreadable snapshot: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (!tarball) return blank('no tarball in the snapshot')

  const archive = readTar(tarball, options.limits ?? DEFAULT_TAR_LIMITS)
  const analysis = analyzeArchive(
    {
      package: member.package,
      version: member.version,
      capturedAt: member.capturedAt,
      ngpackPath: member.ngpackPath,
      label: member.label,
    } as unknown as CorpusSample,
    archive,
    options.threshold
  )

  const scan = scanArchive(archive, { analysis })

  // The post-hoc pass reuses the graph the frozen pass already built. Re-running
  // the analysis would double the cost of the run to change one comparison.
  const repaired = scan.reachability
    ? capabilitiesOf({
        reachability: scan.reachability,
        opaqueExecutable: scan.opaqueExecutable,
        joinPathSegments: true,
      })
    : scan.capabilities

  const strict = strictCapabilitiesOf(scan)

  return {
    member,
    scan,
    answers: answersOf(scan),
    repaired: Object.fromEntries(
      CAPABILITIES.map(c => [c, repaired.answers.find(a => a.capability === c)?.answer ?? 'indeterminate'])
    ) as Record<Capability, Answer>,
    strict: strict
      ? Object.fromEntries(
          CAPABILITIES.map(c => [c, strict.find(a => a.capability === c)?.strictAnswer ?? 'indeterminate'])
        ) as Record<Capability, Answer>
      : answersOf(scan),
    profile: resolutionProfileOf(scan),
  }
}

function answersOf(scan: CapabilityScan): Record<Capability, Answer> {
  return Object.fromEntries(
    CAPABILITIES.map(c => [c, answerFor(scan.capabilities, c)])
  ) as Record<Capability, Answer>
}

// One row per case package, folding every capture of it: the union answer, and
// the sentences the analysis produced for whatever it did find.
export function caseDetailOf(cases: MeasuredMember[]): CapabilityControlReport['caseDetail'] {
  const byPackage = new Map<string, MeasuredMember[]>()
  for (const m of cases) {
    const at = byPackage.get(m.member.package)
    if (at) at.push(m)
    else byPackage.set(m.member.package, [m])
  }

  return [...byPackage.entries()].map(([name, group]) => {
    const sorted = [...group].sort((a, b) => a.member.capturedAt.localeCompare(b.member.capturedAt))
    const evidence = new Set<string>()
    const opaque = new Set<string>()
    for (const m of sorted) {
      for (const answer of m.scan.capabilities.answers) {
        for (const e of answer.evidence) evidence.add(`${answer.capability}: ${e}`)
      }
      for (const kind of m.scan.opaqueKinds) opaque.add(kind)
    }
    return {
      package: name,
      publisher: sorted[0]!.member.publisher,
      captures: sorted.length,
      versions: [...new Set(sorted.map(m => m.member.version))],
      unpackedSize: sorted[0]!.member.unpackedSize,
      opaque: [...opaque],
      refusals: sorted.filter(m => m.scan.refusal !== null).length,
      answers: unionAnswers(sorted.map(m => m.answers)),
      evidence: [...evidence].slice(0, 10),
    }
  }).sort((a, b) => b.captures - a.captures)
}

// Everything on disk that says a package is no longer what it was: npm's own
// 0.0.1-security placeholder, the sweep's record of the same, the deletions the
// change feed reported, the unpublish times the TTR log measured, and every
// capture this project has labelled.
//
// Read from the files rather than from one helper, because the helper reads one
// of the five. On this corpus that difference is 251 names against 573 — and
// every name it misses is a withdrawn package sitting in the control group.
export function withdrawnPackages(
  outputDir: string,
  samples: CorpusSample[]
): { names: Set<string>; bySource: Array<{ source: string; names: number; newHere: number }> } {
  const names = new Set<string>()
  const bySource: Array<{ source: string; names: number; newHere: number }> = []

  const add = (source: string, found: Iterable<string>): void => {
    const list = [...found]
    const before = names.size
    for (const name of list) names.add(name)
    bySource.push({ source, names: new Set(list).size, newHere: names.size - before })
  }

  add('takedown-log (npm published 0.0.1-security)', readLiveTakedowns(outputDir))
  add('takedowns.json (the sweep)', namesIn(join(outputDir, 'takedowns.json'), text => {
    try {
      const parsed = JSON.parse(text) as { takenDown?: Array<{ package?: string }> }
      return (parsed.takenDown ?? []).map(t => t.package).filter((p): p is string => Boolean(p))
    } catch { return [] }
  }))
  add('deletions.ndjson (gone from the registry)', ndjsonNames(outputDir, 'deletions'))
  add('ttr-log.ndjson (a version was unpublished)', ndjsonNames(outputDir, 'ttr-log'))
  add('this corpus (labelled or holding the placeholder)', samples
    .filter(s => s.label === 'confirmed_malicious' || s.version === NPM_SECURITY_HOLDER)
    .map(s => s.package))

  return { names, bySource }
}

function namesIn(path: string, parse: (text: string) => string[]): string[] {
  if (!existsSync(path)) return []
  try { return parse(readFileSync(path, 'utf-8')) } catch { return [] }
}

// Both the live file and the rotated days of it. A log that rotates and a reader
// that only opens the live one is how a denominator silently shrinks to the last
// few hours.
function ndjsonNames(outputDir: string, prefix: string): string[] {
  const found: string[] = []
  let entries: string[]
  try { entries = readdirSync(outputDir) } catch { return found }

  for (const name of entries) {
    if (!name.startsWith(prefix)) continue
    const path = join(outputDir, name)
    try {
      const text = name.endsWith('.gz')
        ? gunzipSync(readFileSync(path)).toString('utf-8')
        : readFileSync(path, 'utf-8')
      for (const line of text.split('\n')) {
        if (!line.trim()) continue
        try {
          const row = JSON.parse(line) as { package?: string }
          if (row.package) found.push(row.package)
        } catch { /* one bad line is one bad line */ }
      }
    } catch { /* an unreadable day is one day short, not a failure */ }
  }
  return found
}

// Whether the two bounds a case package set decided that package's own answer.
// A capability that is indeterminate for several reasons at once does not rest
// on any one of them; one that is indeterminate for exactly the contaminated
// reason does.
export function contaminationOf(cases: MeasuredMember[]): CapabilityControlReport['contamination'] {
  let depthOnly = 0
  let opacityOnly = 0

  for (const m of cases) {
    for (const answer of m.scan.capabilities.answers) {
      if (answer.answer !== 'indeterminate') continue
      const reasons = answer.blindedBy
      if (reasons.length === 0) continue
      if (reasons.every(r => r.startsWith('depth-limit'))) depthOnly++
      if (reasons.every(r => r.startsWith('ships a native binary'))) opacityOnly++
    }
  }

  return {
    declared: NAMED_IN_THE_CODEBASE,
    blindedSolelyByDepthLimit: depthOnly,
    blindedSolelyByOpacity: opacityOnly,
    statement:
      depthOnly === 0 && opacityOnly === 0
        ? 'No capability answer in the case cohort rests on either contaminated bound alone: every ' +
          'indeterminate is indeterminate for at least one other reason as well. The contamination is ' +
          'in the provenance and is declared; it is not in these numbers.'
        : `${depthOnly} capability answers rest on the walk bound alone and ${opacityOnly} on the file ` +
          `classifier alone. Both bounds were set with a case package as the named example, so those ` +
          `answers are the analyser reporting on the sample that configured it. They are not evidence.`,
  }
}

// ---------------------------------------------------------------------------
// What the case arm is, without running the study
// ---------------------------------------------------------------------------

// A5's blocker was never the number of captures. It is the number of distinct
// npm accounts on the case side, because the publisher unit is the primary one
// and its members are the only ones that are independent events. At 3 accounts
// no per-capability difference was claimable and the run said so; the question
// "has that changed" had no answer short of re-deriving the cohort by hand,
// which is how a decision number stops being consulted.
//
// So it is a command. `norte-guard corpus --publishers` calls this, and this
// calls `caseCohortOf` — the same function `runCapabilityControl` calls — so
// the number cannot drift from the one A5 will use.
export interface CasePublisherReport {
  confirmedCaptures: number
  confirmedWithBytes: number
  captures: number
  packages: number
  publishers: number
  // The number that actually bounds the intervals. `publishers` counts accounts
  // and assumes they are independent; this counts operators, which is the same
  // thing with the demonstrated links collapsed. See operator.ts.
  operators: number
  mergedAccounts: Array<{ operator: string; accounts: string[] }>
  breakdown: Array<{ publisher: string; packages: string[]; captures: number }>
  unclassifiable: number
  excludedByName: string[]
  // The other side of the count. Every confirmed removal whose bytes are gone is
  // a case that cannot be measured, and the accounts that appear ONLY here are
  // the ones the object-store sweep cost this study outright.
  lost: {
    captures: number
    packages: number
    publishers: number
    publishersOnlyHere: string[]
  }
  // What the count would have to be, measured against the control arm the last
  // saved run actually had. Null when no run has been saved: the distance to
  // power is a statement about a specific control arm, and inventing one would
  // be the same error as reading a rate off an empty denominator.
  power: PowerDistance | null
  caveats: string[]
}

export interface PowerDistance {
  fromRun: string
  // Control members at the primary unit, before the indeterminate ones are
  // dropped. Reported because it is the number the run's own ceiling statement
  // uses, and because the gap between it and `nDeterminate` below is most of
  // what makes this study hard.
  nControls: number
  z: number
  byCapability: Array<{
    capability: Capability
    controlRate: number
    // The control denominator the comparison ACTUALLY runs on: controls that
    // answered either way. `compareAt` compares overDeterminate against
    // overDeterminate, so a requirement computed against the member count would
    // be a requirement for a comparison this study does not make. On the run of
    // 2026-08-21 that is 49 controls for credential_read, not 125.
    nDeterminate: number
    // Cases that answered either way, over cases. The share the audit's power
    // table indexes on, measured rather than assumed.
    determinateShare: number
    // Publishers needed for a difference of MARGIN to separate AND KEEP
    // separating, at the measured determinate share. Null when no n up to the
    // search bound does it.
    publishersNeeded: number | null
    // The first n that separates at all. Lower than the above whenever rounding
    // makes `separated` non-monotone, which on this data it always does. Printed
    // beside it so the gap is visible: an n between the two is an n where one
    // more account can take the answer away.
    firstSeparating: number | null
    // The largest control rate that could still separate at the CURRENT case n.
    // Per capability, because the denominator is per capability.
    ceiling: number
    controlRateUnderCeiling: boolean
  }>
}

// The effect size the power question is asked about. The audit's table is
// written for +30pp and this keeps that, so the two are comparable: a smaller
// margin would make the requirement larger and look like the study got harder.
export const POWER_MARGIN = 0.30

// Above this the search is answering a question nobody can act on: the case arm
// gains publishers at a few a week.
export const MAX_PUBLISHERS_SEARCHED = 500

// Smallest case-arm publisher count at which a difference of `margin` over the
// control rate separates at the family-adjusted z, given how often a case yields
// a determinate answer at all.
//
// The determinate share is the term that makes this table honest and it is the
// one a reader skips. A case that ships a bytecode blob answers indeterminate to
// all four, and an indeterminate case is not a case with an unknown value — it
// is a case that leaves the denominator. Publishers arrive; determinate
// publishers arrive more slowly, and at the share this corpus shows, most of
// them do not arrive at all.
// It returns the STABLE threshold — the smallest n from which every larger n
// separates too — and not the first n that happens to.
//
// The two are not the same and the gap is wide enough to mislead. Both `n` and
// the reach count are rounded to whole publishers, so `separated` is not
// monotone in n: on the run of 2026-08-21, credential_read first separates at 31
// accounts and then fails again at 33, 34, 39 and 40 before holding from 41.
// external_exec first separates at 49 and fails at 51, 54, 55, 56 and 59 before
// holding from 60. A number that decides when to re-run a study cannot be a
// number where one more account takes the answer away, so the first-separating n
// is reported alongside rather than instead — see `firstSeparatingN`.
export function publishersNeededFor(input: {
  controlRate: number
  nControls: number
  z: number
  determinateShare: number
  margin?: number
}): number | null {
  if (input.determinateShare <= 0) return null

  const separates = separatesAt(input)
  if (!separates(MAX_PUBLISHERS_SEARCHED)) return null

  // Walk down from the bound: the answer is one past the largest n that fails.
  for (let n = MAX_PUBLISHERS_SEARCHED - 1; n >= 1; n--) {
    if (!separates(n)) return n + 1
  }
  return 1
}

// The first n that separates at all. Below the stable threshold it is a coin
// landing the right way up, and it is exported so the distance between the two
// can be printed rather than discovered.
export function firstSeparatingN(input: {
  controlRate: number
  nControls: number
  z: number
  determinateShare: number
  margin?: number
}): number | null {
  if (input.determinateShare <= 0) return null

  const separates = separatesAt(input)
  for (let n = 1; n <= MAX_PUBLISHERS_SEARCHED; n++) {
    if (separates(n)) return n
  }
  return null
}

function separatesAt(input: {
  controlRate: number
  nControls: number
  z: number
  determinateShare: number
  margin?: number
}): (n: number) => boolean {
  const margin = input.margin ?? POWER_MARGIN
  const caseRate = Math.min(1, input.controlRate + margin)
  const controlsReaching = Math.round(input.controlRate * input.nControls)

  return (n: number) => {
    const determinate = Math.round(n * input.determinateShare)
    if (determinate === 0) return false
    const reaching = Math.round(determinate * caseRate)
    return differenceWithCI(reaching, determinate, controlsReaching, input.nControls, input.z).separated
  }
}

// The distance to power, read off the last saved run rather than off a constant.
// The control arm is not fixed — it grew from 49 publishers to 125 when the pool
// did — and a requirement quoted against a control arm this study no longer has
// is a requirement for a different study.
export function powerDistanceFrom(
  report: CapabilityControlReport,
  casePublishers: number
): PowerDistance {
  const primary = report.comparisons.find(c => c.unit === PRIMARY_UNIT)!
  const z = report.endpointZ

  return {
    fromRun: report.ranAt,
    nControls: primary.controls.members,
    z,
    byCapability: CAPABILITIES.map(capability => {
      const cases = primary.cases.byCapability.find(c => c.capability === capability)!
      const controls = primary.controls.byCapability.find(c => c.capability === capability)!
      const controlRate = controls.overDeterminate.rate ?? 0
      const nDeterminate = controls.overDeterminate.n
      const determinateShare = primary.cases.members > 0
        ? (cases.reached + cases.notReached) / primary.cases.members
        : 0

      // The ceiling at the case arm this corpus HAS, not at its member count:
      // a case that answers indeterminate is not a case with an unknown value,
      // it is a case the comparison never sees.
      const caseDeterminate = Math.round(casePublishers * determinateShare)
      const ceiling = smallestDetectableEffect(caseDeterminate, nDeterminate, z)
      const ceilingRate = nDeterminate > 0 ? ceiling.maxControlsReaching / nDeterminate : 0

      return {
        capability,
        controlRate,
        nDeterminate,
        determinateShare,
        publishersNeeded: publishersNeededFor({
          controlRate, nControls: nDeterminate, z, determinateShare,
        }),
        firstSeparating: firstSeparatingN({
          controlRate, nControls: nDeterminate, z, determinateShare,
        }),
        ceiling: ceilingRate,
        controlRateUnderCeiling: caseDeterminate > 0 && controlRate <= ceilingRate,
      }
    }),
  }
}

export function casePublisherReport(input: {
  corpus: LabeledCorpus
  lastRun?: CapabilityControlReport | null
}): CasePublisherReport {
  const cohort = caseCohortOf(input.corpus)
  const breakdown = publisherBreakdown(cohort.members)
  const publishers = breakdown.length
  const packages = new Set(cohort.members.map(m => m.package)).size

  // The lost side is resolved through the same packument read, so a confirmed
  // removal with no bytes still names its account when the packument survived
  // it. That is the whole point of counting it: these are accounts A5 would
  // have had.
  const lostMembers = cohort.withoutBytes
    .map(memberOf)
    .filter((m): m is CohortMember => m !== null)
  const lostPublishers = new Set(lostMembers.map(m => m.publisher ?? '(not recorded)'))
  const present = new Set(breakdown.map(b => b.publisher))

  const power = input.lastRun ? powerDistanceFrom(input.lastRun, publishers) : null

  const caveats: string[] = []
  // Not a hedge. Two of the eight accounts in this arm were shown to be one
  // operator — same payload, same exfil repo, same hardcoded credential, second
  // account's first publication 41 minutes after npm removed the first's. See
  // D8 in docs/audit-a5.md. `publisherOf` resolves an npm account, which is all
  // a packument can support, so the count is an upper bound and says so.
  caveats.push(
    `${publishers} is a count of npm ACCOUNTS and is an UPPER BOUND on the independent events. ` +
    `A packument cannot establish that two accounts are two people, and on this corpus two of ` +
    `them are not: see D8 in docs/audit-a5.md, where a shared payload and a shared credential ` +
    `merge a pair. The same reasoning is why PROMOTION_MIN_TAKEDOWN_PUBLISHERS in watchlist.ts ` +
    `is a floor rather than a measurement.`
  )
  if (cohort.withoutBytes.length > 0) {
    caveats.push(
      `${cohort.withoutBytes.length} confirmed removals have no tarball and cannot enter A5 at any n. ` +
      `They are not a shortage of attacks — see the object store section of docs/audit-a5.md, where a ` +
      `sweep deleted 3,190 still-referenced objects and took 31 labelled captures with them.`
    )
  }
  if (power) {
    const blocked = power.byCapability.filter(c => c.determinateShare < 1)
    if (blocked.length > 0) {
      caveats.push(
        `The publisher count is not the only term. ` +
        `${blocked.length === CAPABILITIES.length ? 'All four capabilities have' : `${blocked.length} of the four capabilities have`} a ` +
        `case-side determinate share below 1 (` +
        blocked.map(c => `${c.capability} ${(100 * c.determinateShare).toFixed(0)}%`).join(', ') +
        `), and an indeterminate case leaves the denominator rather than sitting in it with an unknown ` +
        `value. Waiting for the case arm to become legible is waiting for the thing being studied to ` +
        `stop happening, so the requirement column is not a schedule.`
      )
    }
  } else {
    caveats.push(
      `No saved capability-control run was found, so there is no control arm to state a requirement ` +
      `against. Run \`norte-guard capabilities --control\` first; a distance to power quoted against ` +
      `an invented control n would be arithmetic about a study nobody ran.`
    )
  }

  return {
    confirmedCaptures: cohort.confirmed.length,
    confirmedWithBytes: cohort.withBytes.length,
    captures: cohort.members.length,
    packages,
    publishers,
    operators: collapse(cohort.members.map(m => m.publisher)).operators,
    mergedAccounts: collapse(cohort.members.map(m => m.publisher)).merged,
    breakdown,
    unclassifiable: cohort.unclassifiable,
    excludedByName: cohort.excludedByName,
    lost: {
      captures: cohort.withoutBytes.length,
      packages: new Set(cohort.withoutBytes.map(s => s.package)).size,
      publishers: lostPublishers.size,
      publishersOnlyHere: [...lostPublishers].filter(p => !present.has(p)).sort(),
    },
    power,
    caveats,
  }
}

// The newest saved run, so the distance to power is quoted against a control arm
// that existed. Returns null rather than throwing: a corpus with no run yet is
// the normal state on a fresh checkout, and it is reported as such.
export function readLatestControlRun(resultsDir: string): CapabilityControlReport | null {
  if (!existsSync(resultsDir)) return null
  const files = readdirSync(resultsDir)
    .filter(f => f.startsWith('capability-control-') && f.endsWith('.json'))
    .sort()
  for (const file of files.reverse()) {
    try {
      const parsed = JSON.parse(readFileSync(join(resultsDir, file), 'utf-8')) as CapabilityControlReport
      if (parsed.comparisons?.some(c => c.unit === PRIMARY_UNIT)) return parsed
    } catch { /* try the one before it */ }
  }
  return null
}

// IDEA 1 AND 2, assembled.
//
// Everything here runs at the PRIMARY unit and only at the primary unit. The
// capability tables are printed at five units because the difference between them
// was the whole subject of the 2026-08-19 audit; repeating that here would add
// forty-five more intervals to the family to answer a question that has already
// been answered, and the answer is that the publisher unit is the one whose
// members are independent events.
function opacityReport(
  cases: MeasuredMember[],
  controls: MeasuredMember[],
  z: number
): CapabilityControlReport['opacity'] {
  const atPrimary = (m: MeasuredMember[]): MeasuredMember[] => atUnit(m, PRIMARY_UNIT)
  const caseMembers = atPrimary(cases)
  const controlMembers = atPrimary(controls)

  const caseProfiles = caseMembers.map(m => m.profile).filter((p): p is ResolutionProfile => p !== null)
  const controlProfiles = controlMembers.map(m => m.profile).filter((p): p is ResolutionProfile => p !== null)

  const binary: OpacityComparison[] = [
    compareBinary({
      measure: 'hides any of its own control flow',
      unitOfMeasure: `${PRIMARY_UNIT}s whose archive was opened`,
      cases: caseProfiles, controls: controlProfiles,
      pick: p => p.hasAuthoredOpacity, z,
    }),
    ...AUTHORED_OPACITY.map(reason => compareBinary({
      measure: reason,
      unitOfMeasure: `${PRIMARY_UNIT}s whose archive was opened`,
      cases: caseProfiles, controls: controlProfiles,
      pick: p => p.bySite[reason] > 0, z,
    })),
  ]

  const continuous: ContinuousComparison[] = [
    compareContinuous({
      measure: 'import resolution rate',
      unitOfMeasure: 'resolved modules over resolution attempts',
      cases: caseProfiles.map(p => p.importResolutionRate).filter((x): x is number => x !== null),
      controls: controlProfiles.map(p => p.importResolutionRate).filter((x): x is number => x !== null),
    }),
    compareContinuous({
      measure: 'authored opacity sites per file',
      unitOfMeasure: 'sites / files analysed',
      cases: caseProfiles.map(p => p.authoredOpacityPerFile).filter((x): x is number => x !== null),
      controls: controlProfiles.map(p => p.authoredOpacityPerFile).filter((x): x is number => x !== null),
    }),
    compareContinuous({
      measure: 'analyser bound sites per file — OURS, not theirs',
      unitOfMeasure: 'sites / files analysed',
      cases: caseProfiles.map(p => p.filesAnalysed > 0 ? p.analyserBoundSites / p.filesAnalysed : NaN),
      controls: controlProfiles.map(p => p.filesAnalysed > 0 ? p.analyserBoundSites / p.filesAnalysed : NaN),
    }),
  ]

  const strictCases = summariseGroup({
    name: 'confirmed removals, resolved evidence only',
    unit: PRIMARY_UNIT, members: caseMembers, failures: [], strict: true,
  })
  const strictControls = summariseGroup({
    name: 'size-matched controls, resolved evidence only',
    unit: PRIMARY_UNIT, members: controlMembers, failures: [], strict: true,
  })

  const demotedIn = (members: MeasuredMember[], capability: Capability): number =>
    members.filter(m => m.answers[capability] === 'reached' && m.strict[capability] !== 'reached').length

  return {
    note:
      'The four capabilities saturated, so the walk\'s own record of where it LOST THE TRAIL is ' +
      'read here as a measurement rather than as a reason to answer indeterminate. Only the four ' +
      'AUTHORED kinds are counted against a package — a specifier, an eval, a computed member or a ' +
      'callee that exists only at runtime. The analyser\'s own bounds are counted too and reported ' +
      'apart, because a budget this project chose is not something a package did. ' +
      'TWO CONFOUNDS, NAMED RATHER THAN CONTROLLED. First, the denominator here is publishers whose ' +
      'archive HELD JAVASCRIPT: a member that was never opened has no resolution rate, and scoring ' +
      'it as hiding nothing would put "we did not look" and "it is transparent" in one bucket. The ' +
      'control side loses more members to that than the case side does, so the two arms are not the ' +
      'same denominators the capability tables use, and the counts are printed for both. Second, ' +
      'MINIFICATION PRODUCES AUTHORED OPACITY BY CONSTRUCTION and minification is ordinary practice. ' +
      'A difference on these measures is therefore not yet a difference about malice; it is a ' +
      'difference about legibility, and separating the two needs a minified-only stratum this ' +
      'cohort is too small to cut.',
    unit: PRIMARY_UNIT,
    endpointsAdded: OPACITY_ENDPOINTS,
    binary,
    continuous,
    withoutProfile: {
      cases: caseMembers.length - caseProfiles.length,
      controls: controlMembers.length - controlProfiles.length,
    },
    strict: {
      note:
        'The same four, counting only evidence a reader can check: a module resolved by name, or an ' +
        'ambient call the parser read. A frozen `reached` resting on a lost specifier becomes ' +
        'indeterminate, never not-reached — failing to read a specifier is not evidence that it does ' +
        'not reach. ' +
        'THIS DEFINITION WAS WRITTEN AFTER THE FROZEN RUN SATURATED, WHICH IS THE ONE THING THAT ' +
        'DISQUALIFIES IT AS EVIDENCE FROM THIS RUN. It is reported for exactly the reason the ' +
        'post-hoc credential_read block is: so that the next confirmed sample nobody has opened can ' +
        'be the test of it, rather than the third place it is rediscovered. Whatever it separates ' +
        'here is a HYPOTHESIS THIS RUN GENERATED, not a finding this run established, and the ' +
        'Bonferroni correction over 29 endpoints does not fix that — it covers the intervals inside ' +
        'one run, not the number of times one cohort of 8 publishers has now been looked at.',
      cases: strictCases,
      controls: strictControls,
      capabilities: compareAt(strictCases, strictControls, z),
      demoted: CAPABILITIES.map(capability => ({
        capability,
        cases: demotedIn(caseMembers, capability),
        controls: demotedIn(controlMembers, capability),
      })),
    },
  }
}

function publisherBreakdown(members: CohortMember[]): Array<{ publisher: string; packages: string[]; captures: number }> {
  const byPublisher = new Map<string, { packages: Set<string>; captures: number }>()
  for (const m of members) {
    const key = m.publisher ?? '(not recorded)'
    const at = byPublisher.get(key) ?? { packages: new Set<string>(), captures: 0 }
    at.packages.add(m.package)
    at.captures++
    byPublisher.set(key, at)
  }
  return [...byPublisher.entries()]
    .map(([publisher, v]) => ({ publisher, packages: [...v.packages].sort(), captures: v.captures }))
    .sort((a, b) => b.captures - a.captures)
}

function captureReasonBreakdown(members: CohortMember[]): Array<{ reason: string; packages: number }> {
  const byReason = new Map<string, number>()
  for (const m of members) {
    const reason = m.captureReason ?? 'unrecorded'
    byReason.set(reason, (byReason.get(reason) ?? 0) + 1)
  }
  return [...byReason.entries()]
    .map(([reason, packages]) => ({ reason, packages }))
    .sort((a, b) => b.packages - a.packages)
}

const pct = (n: number, of: number): string => of === 0 ? 'n/a' : `${(100 * n / of).toFixed(0)}%`

// The order the units are PRINTED in, which is not the order they are computed
// in. v1.3.0 printed capture first and publisher third, so the one row that said
// SEPARATES stood at the top of the output and the primary unit's "nothing is
// established" sat below it, with the caveat explaining the difference eleven
// paragraphs further down. Nobody reads that way. The primary unit leads, the
// pseudo-replicated unit goes last, and the reason travels with it.
export const PRINT_ORDER: Unit[] = ['operator', 'publisher', 'publisher-any', 'package', 'package-any', 'capture']

export interface Headline {
  unit: Unit
  nCases: number
  nControls: number
  separated: string[]
  inconclusive: string[]
  notCalculable: string[]
  // Capabilities that separate at some non-primary unit and not at the primary
  // one. This is the sentence the last run buried: a difference that exists only
  // where one operator is counted 36 times is a fact about republishing.
  separatesOnlyElsewhere: Array<{ capability: string; unit: Unit; caseShare: string }>
  statement: string
}

// What the run found, stated before anything that could be mistaken for it.
export function headlineOf(
  comparisons: Array<{ unit: Unit; cases: GroupReport; controls: GroupReport; capabilities: Array<{ capability: Capability; familyAdjusted: { separated: boolean; difference: number | null } }> }>,
  cases: MeasuredMember[]
): Headline {
  const primary = comparisons.find(c => c.unit === PRIMARY_UNIT)!
  const separated: string[] = []
  const inconclusive: string[] = []
  const notCalculable: string[] = []

  for (const c of primary.capabilities) {
    if (c.familyAdjusted.difference === null) notCalculable.push(c.capability)
    else if (c.familyAdjusted.separated) separated.push(c.capability)
    else inconclusive.push(c.capability)
  }

  // The dominant package on the case side, which is what makes the capture unit
  // read differently from every other unit.
  const byPackage = new Map<string, number>()
  for (const c of cases) byPackage.set(c.member.package, (byPackage.get(c.member.package) ?? 0) + 1)
  const biggest = [...byPackage.entries()].sort((a, b) => b[1] - a[1])[0]

  const separatesOnlyElsewhere: Headline['separatesOnlyElsewhere'] = []
  for (const comparison of comparisons) {
    if (comparison.unit === PRIMARY_UNIT) continue
    for (const c of comparison.capabilities) {
      if (!c.familyAdjusted.separated) continue
      if (separated.includes(c.capability)) continue
      if (separatesOnlyElsewhere.some(s => s.capability === c.capability && s.unit === comparison.unit)) continue
      separatesOnlyElsewhere.push({
        capability: c.capability,
        unit: comparison.unit,
        caseShare: biggest ? `${biggest[1]} of ${cases.length} case ${comparison.unit}s are ${biggest[0]}` : 'unknown',
      })
    }
  }

  const parts: string[] = []
  if (separated.length === 0) {
    parts.push(
      `NOTHING IS ESTABLISHED. At the ${PRIMARY_UNIT} unit — ${primary.cases.members} cases against ` +
      `${primary.controls.members} controls, the unit declared before the run because it is the one whose ` +
      `members are independent events — not one of the four capabilities separates the confirmed removals ` +
      `from size-matched packages npm did not remove.`
    )
  } else {
    parts.push(
      `At the ${PRIMARY_UNIT} unit (${primary.cases.members} cases, ${primary.controls.members} controls), ` +
      `${separated.join(' and ')} separates the confirmed removals from size-matched packages npm did not remove.`
    )
  }
  if (notCalculable.length > 0) {
    parts.push(
      `${notCalculable.join(' and ')} ${notCalculable.length === 1 ? 'is' : 'are'} not calculable at all: ` +
      `every case is indeterminate, and a rate over an empty denominator is not a rate.`
    )
  }
  if (inconclusive.length > 0) {
    parts.push(`${inconclusive.join(' and ')} ${inconclusive.length === 1 ? 'is' : 'are'} inconclusive — the interval includes zero.`)
  }
  if (separatesOnlyElsewhere.length > 0) {
    const list = [...new Set(separatesOnlyElsewhere.map(s => s.capability))].join(', ')
    const where = [...new Set(separatesOnlyElsewhere.map(s => s.unit))].join(' and ')
    parts.push(
      `${list} DOES separate at the ${where} unit, and that is not a second measurement of the same thing: ` +
      `${separatesOnlyElsewhere[0]!.caseShare}, so a rate there is a rate of republishing. Read it as a fact ` +
      `about one operator's release count, not about malicious packages.`
    )
  }

  return {
    unit: PRIMARY_UNIT,
    nCases: primary.cases.members,
    nControls: primary.controls.members,
    separated, inconclusive, notCalculable, separatesOnlyElsewhere,
    statement: parts.join(' '),
  }
}

function caveatsFor(cases: MeasuredMember[], controls: MeasuredMember[], matches: Match[]): string[] {
  const caveats: string[] = []

  const publishers = new Set(cases.map(c => c.member.publisher ?? c.member.package))
  const linked = collapse(cases.map(c => c.member.publisher))
  caveats.push(
    `The case side is ${cases.length} captures of ${new Set(cases.map(c => c.member.package)).size} packages ` +
    `published by ${publishers.size} npm accounts, which are ${linked.operators} OPERATORS: ` +
    (linked.merged.length > 0
      ? linked.merged.map(m => `${m.accounts.join(' = ')}`).join('; ') + '. '
      : 'no account has been linked to another. ') +
    `Every interval here assumes independent draws and there are ${linked.operators} independent events ` +
    `in it, not ${publishers.size}, so every one of them is narrower than the truth. The operator-unit rows ` +
    `are the ones to read; the publisher rows are kept so runs before 2026-08-21 stay comparable, and the ` +
    `capture-unit rows are printed to show how much the unit changes the answer, not as a second measurement.`
  )

  // The evidence for each merge, in the output rather than only in the source.
  // Collapsing two accounts into one removes a degree of freedom from every
  // interval in the run, so a reader has to be able to disagree with it here.
  for (const merged of linked.merged) {
    const link = linkFor(merged.accounts[0]!)
    if (link) caveats.push(`${merged.accounts.join(' = ')} are one operator: ${link.because}`)
  }

  const opaque = cases.filter(c => c.scan.opaqueExecutable).length
  if (opaque > 0) {
    caveats.push(
      `${opaque} of the ${cases.length} case captures ship an executable no parser reads — a native ` +
      `binary, WASM, a V8 bytecode cache or unreadable minified code. For those, three of the four ` +
      `capabilities cannot be answered at all, and a two-valued analysis would have recorded them as ` +
      `reaching nothing: the malicious side looking cleaner than the control because it is better hidden.`
    )
  }

  const short = matches.filter(m => m.shortfall > 0)
  if (short.length > 0) {
    caveats.push(
      `${short.length} of the ${matches.length} cases could not be matched at the full ratio ` +
      `(${short.map(m => `${m.case.package}: ${m.controls.length}`).join(', ')}). A size nothing else in the ` +
      `window shares is itself a finding about the case, and it is reported rather than filled by widening ` +
      `the caliper until something fits.`
    )
  }

  caveats.push(
    `The control is drawn through the SAME capture filter as the cases. Both capture reasons are enriched ` +
    `populations — 'quarantine-no-genome' keeps everything matching the three conjuncts of the observed ` +
    `class, 'watcher-threshold' keeps whatever scored high — so this compares the confirmed removals ` +
    `against the rest of what the filter kept, not against npm. A difference here does not transfer to the ` +
    `ecosystem without measuring the filter's own selection, which this run does not do.`
  )

  caveats.push(
    `"Not withdrawn" is as good as the removal record. It unions five records — npm's 0.0.1-security ` +
    `placeholder in the takedown log, the sweep's own list, the deletions the change feed reported, the ` +
    `unpublish times in the TTR log, and every capture this project has labelled — and a package npm ` +
    `removes tomorrow is still in the control today. That error runs against the difference: it puts ` +
    `malicious packages in the control group, so a difference that survives it is not created by it.`
  )

  // Blinded at entry, not just opaque. v1.3.0 quoted only the opacity half and
  // so reported the control side as 15 of 99 when 29 of 99 were unreadable to
  // the analysis: 20 controls were never opened at all — 17 because the archive
  // holds no JavaScript (TypeScript-only, CSS, markdown) and 3 because they are
  // past the size bound — and those answer indeterminate to all four exactly as
  // an opaque one does. Understating the control side's blinding is the
  // direction that flatters the comparison, so it is counted here in full.
  const blindedAtEntry = (members: MeasuredMember[]) =>
    members.filter(m => m.scan.opaqueExecutable || m.scan.refusal !== null).length
  const caseBlinded = blindedAtEntry(cases)
  const controlBlinded = blindedAtEntry(controls)
  const controlOpaque = controls.filter(c => c.scan.opaqueExecutable).length
  const controlRefused = controls.filter(c => c.scan.refusal !== null).length
  const caseRefused = cases.filter(c => c.scan.refusal !== null).length
  caveats.push(
    `Indeterminate is not evenly distributed: ${caseBlinded} of ${cases.length} cases ` +
    `(${pct(caseBlinded, cases.length)}) and ${controlBlinded} of ${controls.length} controls ` +
    `(${pct(controlBlinded, controls.length)}) could not be read at all. That is two different failures ` +
    `counted together, because they have the same consequence: ${opaque} cases and ${controlOpaque} ` +
    `controls ship something no parser reads, and ${caseRefused} cases and ${controlRefused} controls ` +
    `were never opened (no JavaScript in the archive, or past the size bound). Where the two sides are ` +
    `blinded at different rates, the rate over the determinate members is comparing two different subsets ` +
    `and the bounds are the honest reading.`
  )

  caveats.push(...capabilityCaveats())
  return caveats
}
