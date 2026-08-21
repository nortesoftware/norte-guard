// IDEA 1 AND 2 — the opacity as the signal, and reachability that distinguishes a
// route from an ignorance.
//
// A5 measured four capabilities and none of them separates. But every one of those
// answers is produced by a walk that also records WHERE IT LOST THE TRAIL, and
// that record was only ever consumed as a blinder — a reason to answer
// `indeterminate` — never as a measurement in its own right.
//
// The hypothesis this module exists to test: an honest package does not need to
// hide its imports. `require(someVariable)`, a specifier assembled at runtime, a
// member taken by a computed key, `eval` — every one of them is a place the
// analysis stops, and if the case arm stops the analysis more often than a
// size-matched control does, then the inability to resolve IS the discriminant and
// the four capabilities were the wrong endpoint.
//
// The second half is the correction it forces on the capability answers. Today
// `dynamic_code` is `reached` when the walk hit a `dynamic-specifier` lost point —
// which is correct by the definition frozen before the run ("a require/import
// specifier decided at runtime") and is nonetheless two different facts wearing one
// label. A package that reaches `child_process` through an explicit static require
// has demonstrated something. A package whose specifier could not be read has
// demonstrated that it could not be read. Both arms carry the second kind and it
// is what a difference has to be found through.
//
// So this module reports, beside the frozen answer and never in place of it, a
// STRICT answer that counts only resolved evidence. That is the same discipline
// the post-hoc `credential_read` block already follows: a definition that was not
// declared before the run is reported apart, labelled, and is not the finding.

import { CAPABILITIES, moduleKey, type Capability } from './capabilities.js'
import type { CapabilityScan } from './capability-run.js'
import type { LostReason, PackageReachability } from './reachability.js'
import { differenceWithCI, rateWithCI, type DifferenceWithCI, type RateWithCI } from './stats.js'

// The lost reasons that mean "this code declined to say where it was going".
//
// Split from the rest deliberately. `depth-limit`, `origin-bound`, `ambient-bound`
// and `argument-bound` are OUR bounds — they say the analyser gave up, and a
// package cannot be blamed for a budget we chose. These four are the package's own
// doing: a specifier, a callee or a member that only exists at runtime. Counting
// our bounds as the package's opacity would measure the analyser on both arms and
// call the result a property of the malware.
export const AUTHORED_OPACITY: LostReason[] = [
  'dynamic-specifier',
  'dynamic-eval',
  'computed-member',
  'unresolved-callee',
]

// Ours. Counted too, and reported apart, because the comparison is only readable
// if a reader can see that the two move independently.
export const ANALYSER_BOUNDS: LostReason[] = [
  'depth-limit',
  'origin-bound',
  'ambient-bound',
  'argument-bound',
  'unresolved-import',
]

export interface ResolutionProfile {
  // Denominators. Every rate below is over one of these and says which.
  filesAnalysed: number
  sourceBytes: number
  // Distinct modules the walk resolved to a name. The positive side of the
  // resolution rate.
  resolvedModules: number
  // Distinct SITES — file:line — where a specifier could not be resolved. Sites
  // rather than occurrences: a minified bundle repeating one pattern 400 times is
  // one authoring decision, and counting occurrences would let file size decide
  // the answer.
  bySite: Record<LostReason, number>
  authoredOpacitySites: number
  analyserBoundSites: number
  // Relative specifiers that resolve to no file in the tarball. A packaging fact,
  // not an analysis limit, which is why reachability.ts holds it apart and so does
  // this.
  unresolvedLocal: number
  // Explicit calls to eval or Function, from the ambient record. Not a lost point:
  // the analysis read these and knows exactly what they are.
  evalOrFunctionCalls: number
  // process.env reached with the variable name decided somewhere unreadable.
  namelessEnvReads: number

  // ---- the two headline rates ----------------------------------------------

  // resolved / (resolved + unresolvable sites). The fraction of this package's
  // module resolution that a reader can follow. Null when the package resolves
  // nothing and hides nothing, which is not a 0% and not a 100%.
  importResolutionRate: number | null
  // Authored opacity per file analysed. The continuous form, for a cohort whose
  // packages differ in size by four orders of magnitude.
  authoredOpacityPerFile: number | null
  // The binary form: does this package hide ANY of its own control flow. Directly
  // comparable to the capability rates, and the one that needs no normalisation
  // argument.
  hasAuthoredOpacity: boolean
}

export function resolutionProfileOf(scan: CapabilityScan): ResolutionProfile | null {
  // A package nothing could open has no resolution profile, and giving it a zero
  // would put "we never looked" and "it hides nothing" in the same bucket — the
  // exact failure the three-valued answer exists to prevent.
  const r = scan.reachability
  if (!r || scan.refusal !== null) return null

  const bySite = countSites(r)
  const authored = AUTHORED_OPACITY.reduce((n, reason) => n + bySite[reason], 0)
  const bounds = ANALYSER_BOUNDS.reduce((n, reason) => n + bySite[reason], 0)
  const resolved = new Set(r.reachable.map(m => moduleKey(m.module))).size

  // The denominator is resolution ATTEMPTS: what was resolved plus what could not
  // be. `unresolvedLocal` belongs in it — a relative specifier naming no file is a
  // resolution that failed — while our own bounds do not, because they are not
  // attempts the package made.
  const attempts = resolved + bySite['dynamic-specifier'] + r.unresolvedLocal.length

  return {
    filesAnalysed: r.filesAnalysed.length,
    sourceBytes: scan.sourceBytes,
    resolvedModules: resolved,
    bySite,
    authoredOpacitySites: authored,
    analyserBoundSites: bounds,
    unresolvedLocal: r.unresolvedLocal.length,
    evalOrFunctionCalls: r.ambient.filter(a => a.what === 'eval' || a.what === 'Function').length,
    namelessEnvReads: r.ambient.filter(a => a.what === 'process.env' && a.name === null).length,
    importResolutionRate: attempts > 0 ? resolved / attempts : null,
    authoredOpacityPerFile: r.filesAnalysed.length > 0 ? authored / r.filesAnalysed.length : null,
    hasAuthoredOpacity: authored > 0,
  }
}

function countSites(r: PackageReachability): Record<LostReason, number> {
  const seen = new Map<LostReason, Set<string>>()
  for (const point of r.lost) {
    const at = seen.get(point.reason) ?? new Set<string>()
    // file:line, so one authoring decision counts once however many times the
    // walk arrives at it. A point with no location degrades to its detail, which
    // is the most specific thing left.
    at.add(point.line !== null ? `${point.file ?? '?'}:${point.line}` : point.detail)
    seen.set(point.reason, at)
  }

  const out = {} as Record<LostReason, number>
  for (const reason of [...AUTHORED_OPACITY, ...ANALYSER_BOUNDS]) {
    out[reason] = seen.get(reason)?.size ?? 0
  }
  return out
}

// ---------------------------------------------------------------------------
// IDEA 2 — resolved, versus reached because nobody could tell
// ---------------------------------------------------------------------------

// The evidence behind a `reached` answer, split by whether a reader can check it.
//
// `resolvedRoutes` is the number of DISTINCT modules answering this capability
// that the walk resolved by name and reached through a real gate. `fromLostPoint`
// is true when the answer rests on the walk having failed. `strictAnswer` is what
// the capability would say if only the first kind counted.
export interface StrictCapability {
  capability: Capability
  frozenAnswer: 'reached' | 'not-reached' | 'indeterminate'
  resolvedRoutes: number
  ambientCalls: number
  fromLostPoint: boolean
  // reached only on resolved evidence; indeterminate where the frozen answer was
  // reached on a lost point alone, because "we could not read the specifier" is
  // not evidence that it does NOT reach.
  strictAnswer: 'reached' | 'not-reached' | 'indeterminate'
}

// Which modules answer which capability. Duplicated from capabilities.ts rather
// than imported: that table is the frozen definition and this file must not be
// able to change it by editing a shared constant.
const ANSWERING_MODULES: Record<Capability, string[]> = {
  credential_read: ['fs'],
  network_egress: ['net', 'http', 'https', 'dgram'],
  external_exec: ['child_process'],
  dynamic_code: ['vm'],
}

export function strictCapabilitiesOf(scan: CapabilityScan): StrictCapability[] | null {
  const r = scan.reachability
  if (!r || scan.refusal !== null) return null

  const sites = countSites(r)
  const evalCalls = r.ambient.filter(a => a.what === 'eval' || a.what === 'Function').length
  const fetchCalls = r.ambient.filter(a => a.what === 'fetch').length

  return CAPABILITIES.map(capability => {
    const frozen = scan.capabilities.answers.find(a => a.capability === capability)
    const frozenAnswer = frozen?.answer ?? 'indeterminate'

    const resolvedRoutes = ANSWERING_MODULES[capability]
      .filter(m => r.reachable.some(reached => moduleKey(reached.module) === m)).length

    // Ambient evidence is resolved evidence: the analysis read the call site and
    // named the binding. It is not a lost point.
    const ambientCalls =
      capability === 'network_egress' ? fetchCalls
      : capability === 'dynamic_code' ? evalCalls
      : capability === 'credential_read' ? scan.capabilities.tokenEnvRead.length + scan.capabilities.secretPathsReached.length
      : 0

    // Only dynamic_code can be reached by a lost point: capabilities.ts turns
    // `dynamic-specifier` and `dynamic-eval` into positive evidence for it and for
    // nothing else.
    const fromLostPoint = capability === 'dynamic_code'
      && (sites['dynamic-specifier'] > 0 || sites['dynamic-eval'] > 0)

    const hasResolvedEvidence = resolvedRoutes > 0 || ambientCalls > 0

    const strictAnswer: StrictCapability['strictAnswer'] =
      hasResolvedEvidence ? 'reached'
      : frozenAnswer === 'reached' ? 'indeterminate'
      : frozenAnswer

    return { capability, frozenAnswer, resolvedRoutes, ambientCalls, fromLostPoint, strictAnswer }
  })
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

export interface OpacityComparison {
  measure: string
  // What the number is a fraction OF, printed with it. Half the mistakes this
  // project has corrected were a rate whose denominator went unstated.
  unitOfMeasure: string
  cases: RateWithCI
  controls: RateWithCI
  difference: DifferenceWithCI
  familyAdjusted: DifferenceWithCI
  verdict: string
}

export interface ContinuousComparison {
  measure: string
  unitOfMeasure: string
  caseMedian: number | null
  controlMedian: number | null
  caseN: number
  controlN: number
  // Mann-Whitney U as a rank test, because these are counts with a long right
  // tail and a t-test on them would be describing the tail rather than the shift.
  // Reported as the probability a random case exceeds a random control, which is
  // the effect size the U statistic actually is.
  probabilityCaseExceedsControl: number | null
  note: string
}

// A binary measure over profiles, at whatever unit the caller has already reduced
// to. This does no unit reduction of its own on purpose: the unit is A5's problem
// and it is already solved there, and a second implementation of `atUnit` living
// here is how the two would come to disagree.
export function compareBinary(input: {
  measure: string
  unitOfMeasure: string
  cases: ResolutionProfile[]
  controls: ResolutionProfile[]
  pick: (p: ResolutionProfile) => boolean
  z: number
}): OpacityComparison {
  const a = input.cases.filter(input.pick).length
  const b = input.controls.filter(input.pick).length
  const cases = rateWithCI(a, input.cases.length)
  const controls = rateWithCI(b, input.controls.length)
  const difference = differenceWithCI(a, input.cases.length, b, input.controls.length)
  const familyAdjusted = differenceWithCI(a, input.cases.length, b, input.controls.length, input.z)

  return {
    measure: input.measure,
    unitOfMeasure: input.unitOfMeasure,
    cases, controls, difference, familyAdjusted,
    verdict: verdictFor(input.measure, familyAdjusted, input.cases.length, input.controls.length),
  }
}

function verdictFor(measure: string, d: DifferenceWithCI, nCases: number, nControls: number): string {
  const pp = (x: number): string => `${x >= 0 ? '+' : ''}${(x * 100).toFixed(1)}pp`
  if (d.difference === null) {
    return `Not calculable: one side has no members.`
  }
  if (!d.separated) {
    return (
      `INCONCLUSIVE at this n. ${pp(d.difference)}, family-adjusted interval ` +
      `${pp(d.low ?? 0)} to ${pp(d.high ?? 0)}, over ${nCases} cases and ${nControls} controls.`
    )
  }
  return (
    `SEPARATES. ${measure} differs by ${pp(d.difference)} ` +
    `(family-adjusted CI ${pp(d.low ?? 0)} to ${pp(d.high ?? 0)}, excludes zero).`
  )
}

export function compareContinuous(input: {
  measure: string
  unitOfMeasure: string
  cases: number[]
  controls: number[]
}): ContinuousComparison {
  const cases = input.cases.filter(Number.isFinite).sort((x, y) => x - y)
  const controls = input.controls.filter(Number.isFinite).sort((x, y) => x - y)

  return {
    measure: input.measure,
    unitOfMeasure: input.unitOfMeasure,
    caseMedian: median(cases),
    controlMedian: median(controls),
    caseN: cases.length,
    controlN: controls.length,
    probabilityCaseExceedsControl: commonLanguageEffect(cases, controls),
    note:
      cases.length < 10 || controls.length < 10
        ? `Read as a description, not a test: ${cases.length} cases and ${controls.length} controls ` +
          `is not enough for a rank statistic to mean much.`
        : `The probability is the common-language effect size: pick one case and one control at ` +
          `random, this is how often the case is larger. 50% is no difference.`,
  }
}

function median(sortedAsc: number[]): number | null {
  if (sortedAsc.length === 0) return null
  return sortedAsc[Math.floor(sortedAsc.length / 2)]!
}

// P(case > control) + half the ties. The U statistic divided by n*m, which is what
// U means and is more readable than U.
function commonLanguageEffect(cases: number[], controls: number[]): number | null {
  if (cases.length === 0 || controls.length === 0) return null
  let wins = 0
  for (const c of cases) {
    for (const k of controls) {
      if (c > k) wins += 1
      else if (c === k) wins += 0.5
    }
  }
  return wins / (cases.length * controls.length)
}
