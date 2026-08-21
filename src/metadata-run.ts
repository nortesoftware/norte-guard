// IDEAS 3 AND 4, RUN — the comparison that does not open the archive.
//
// A5's control run answers four questions about what a package's code reaches,
// and every one of them needs the tarball. That is why it is a run over 56
// captures: 66.8% of this store kept no artifact, 0 of 42 confirmed removals
// gathered elsewhere kept one, and a question phrased over contents cannot be
// asked of any of them.
//
// This run asks only what the packument answers, so its cohort is every capture
// with a readable packument — 24,307 rather than 56. That is not a better run.
// It is a run over different endpoints, most of which are downstream of the
// filter that selected the corpus, and the report says which ones those are
// before it prints a number for them.
//
// WHAT IT FOUND, so a reader knows what to look for:
//
//   · IDEA 3 DOES NOT SURVIVE THE UNIT. The publication-velocity endpoints
//     separate enormously at the capture unit — "two publications less than five
//     minutes apart", 88.1% of cases against 24.2% of controls, +63.8pp with a
//     family-adjusted interval of +44.2 to +75.4 — and at the publisher unit the
//     same endpoint is 2/5 against 10/37, +13.0pp, interval −27.3 to +60.6,
//     inconclusive. The capture-unit figure is one operator's release loop
//     counted 36 times. It is the same trap the capability run documented for
//     dynamic_code, in a different endpoint, and it is the reason the primary
//     unit is declared before the run rather than chosen from the output.
//
//   · IDEA 4'S NAIVE FORM IS SATURATED, the way idea 1's was. A tight batch —
//     three or more names from one account inside an hour — describes 43.1% of
//     the families in this cohort and 58.9% of those in the whole store, because
//     that is what a monorepo release is: 84 @hive-ui packages in two minutes,
//     120 icon packages in four. The conjunction with all-first-publication is
//     what is rare, at 0.1% of the store's families.
//
//   · WHAT DID SURVIVE is not a rate. One campaign in the store runs a single
//     counter across THREE accounts at a one-minute interval — 17 of 21
//     adjacent-by-number pairs change account — which no per-publisher unit can
//     see, because the coordination is exactly what the grouping key discards.

import { loadCorpus } from './corpus.js'
import {
  INSPIRED_THE_CLASS, MATCH_RATIO, SIZE_CALIPER_LOG10,
  matchOnSize, memberOf, withdrawnPackages,
  type CohortMember,
} from './capability-control.js'
import {
  ENDPOINTS, metadataProfileOf, publisherFor, isTakedownPlaceholder, inObservedClass,
  declarationOf, type Contamination, type MetadataProfile,
} from './metadata-signals.js'
import {
  partitionIntoFamilies, familyProfileOf, numberedSequences,
  publicationsFrom, firstPublicationNames,
  BURST_GAP_MINUTES, TIGHT_BATCH_MINUTES, TIGHT_BATCH_PACKAGES,
  type NumberedSequence, type Publication,
} from './family.js'
import { capturePackument } from './size-control.js'
import { differenceWithCI, rateWithCI, zForFamily, type DifferenceWithCI, type RateWithCI } from './stats.js'
import type { CorpusSample } from './corpus.js'

export interface MetadataRunOptions {
  roots?: string[]
  outputDir: string
  since?: string
  until?: string
  matchRatio?: number
  caliper?: number
  // The same knob the capability run grew in D11: restrict the control pool to
  // one capture reason so both arms come through one filter.
  controlCaptureReason?: string
}

// ---------------------------------------------------------------------------
// The endpoints, as they are read off a profile
// ---------------------------------------------------------------------------

// Binary form for every endpoint that has one, so the rows are comparable with
// the capability rates. `null` means the record cannot answer for this member,
// and such members are held out of BOTH the numerator and the denominator rather
// than counted as a no.
type Pick = (p: MetadataProfile) => boolean | null

const BINARY: Array<{ key: string; label: string; pick: Pick }> = [
  {
    key: 'median_interval_minutes',
    label: 'publishes faster than once an hour (median gap)',
    pick: p => (p.medianIntervalMinutes === null ? null : p.medianIntervalMinutes < 60),
  },
  {
    key: 'fastest_interval_minutes',
    label: 'two publications less than five minutes apart',
    pick: p => (p.fastestIntervalMinutes === null ? null : p.fastestIntervalMinutes < 5),
  },
  {
    key: 'publisher_is_declared_maintainer',
    label: 'publisher is NOT a declared maintainer',
    pick: p => (p.publisherIsDeclaredMaintainer === null ? null : !p.publisherIsDeclaredMaintainer),
  },
  {
    key: 'multi_maintainer',
    label: 'more than one maintainer listed',
    pick: p => p.maintainerCount > 1,
  },
  {
    key: 'dependency_churn',
    label: 'added a dependency against the previous version',
    pick: p => (p.dependencyChurn === null ? null : p.dependencyChurn.added > 0),
  },
  {
    key: 'release_count',
    label: 'more than ten authored releases',
    pick: p => p.releaseCount > 10,
  },
  {
    key: 'releases_per_day',
    label: 'more than five releases a day',
    pick: p => (p.releasesPerDay === null ? null : p.releasesPerDay > 5),
  },
  {
    key: 'version_ahead_of_releases',
    label: 'declared version claims more history than it has',
    pick: p => p.versionAheadOfReleases,
  },
  {
    key: 'name_age_days',
    label: 'name under seven days old (the young conjunct itself)',
    pick: p => (p.nameAgeDays === null ? null : p.nameAgeDays < 7),
  },
  {
    key: 'has_provenance',
    label: 'has npm provenance',
    pick: p => p.hasProvenance,
  },
  {
    key: 'provenance_lost',
    label: 'lost provenance it previously had',
    pick: p => p.provenanceLost,
  },
]

// ---------------------------------------------------------------------------
// The unit
// ---------------------------------------------------------------------------

// The same three units the capability run uses, and for the same reason. 87 case
// captures come from a handful of accounts, and every endpoint here is a
// property of a RELEASE HABIT — "publishes again within five minutes" is what
// one operator's loop does, and counting it once per capture gives that operator
// 36 votes.
//
// The publisher unit is primary. It is the only one whose members are
// independent events: one account deciding how to publish. The capture and
// package rows are printed to show how much the unit changes the answer, which
// on this cohort is the whole answer.
export type MetadataUnit = 'capture' | 'package' | 'publisher'
export const METADATA_UNITS: MetadataUnit[] = ['capture', 'package', 'publisher']
export const PRIMARY_METADATA_UNIT: MetadataUnit = 'publisher'

// One representative per group, earliest capture first. Not a union of answers:
// these endpoints are continuous facts about a release history rather than
// three-valued capability answers, and "the earliest capture of this account"
// is a member, where a union of release rates would be a number no package has.
//
// Profiles with no attributable publisher are dropped at the publisher unit
// rather than pooled under one key — that pooling is exactly the defect the
// registry guard exists to prevent.
export function atMetadataUnit(profiles: MetadataProfile[], unit: MetadataUnit): MetadataProfile[] {
  if (unit === 'capture') return profiles

  const kept = new Map<string, MetadataProfile>()
  for (const p of profiles) {
    const key = unit === 'package' ? p.package : p.publisher
    if (key === null) continue
    const seen = kept.get(key)
    if (!seen || p.capturedAt < seen.capturedAt) kept.set(key, p)
  }
  return [...kept.values()]
}

export interface EndpointComparison {
  key: string
  label: string
  reads: string
  contamination: Contamination
  because: string
  cases: RateWithCI
  controls: RateWithCI
  // Members held out because the record could not answer. Printed, because a
  // rate over a shrinking denominator is a different rate.
  caseHeldOut: number
  controlHeldOut: number
  difference: DifferenceWithCI
  familyAdjusted: DifferenceWithCI
  verdict: string
}

function compareEndpoint(
  spec: { key: string; label: string; pick: Pick },
  cases: MetadataProfile[],
  controls: MetadataProfile[],
  z: number
): EndpointComparison {
  const decl = declarationOf(spec.key)
  const split = (all: MetadataProfile[]): { yes: number; n: number; heldOut: number } => {
    let yes = 0
    let n = 0
    let heldOut = 0
    for (const p of all) {
      const answer = spec.pick(p)
      if (answer === null) { heldOut += 1; continue }
      n += 1
      if (answer) yes += 1
    }
    return { yes, n, heldOut }
  }

  const a = split(cases)
  const b = split(controls)
  const difference = differenceWithCI(a.yes, a.n, b.yes, b.n)
  const familyAdjusted = differenceWithCI(a.yes, a.n, b.yes, b.n, z)

  return {
    key: spec.key,
    label: spec.label,
    reads: decl?.reads ?? '',
    contamination: decl?.contamination ?? 'partial',
    because: decl?.because ?? '',
    cases: rateWithCI(a.yes, a.n, z),
    controls: rateWithCI(b.yes, b.n, z),
    caseHeldOut: a.heldOut,
    controlHeldOut: b.heldOut,
    difference,
    familyAdjusted,
    verdict: verdictFor(spec.label, decl?.contamination ?? 'partial', familyAdjusted, a.n, b.n),
  }
}

function verdictFor(
  label: string,
  contamination: Contamination,
  d: DifferenceWithCI,
  nCases: number,
  nControls: number
): string {
  const pp = (x: number | null): string =>
    x === null ? 'n/a' : `${x >= 0 ? '+' : ''}${(x * 100).toFixed(1)}pp`

  if (d.difference === null) return 'Not calculable: one side has no members that could answer.'

  if (!d.separated) {
    return (
      `INCONCLUSIVE at this n. ${pp(d.difference)}, family-adjusted ${pp(d.low)} to ${pp(d.high)}, ` +
      `over ${nCases} cases and ${nControls} controls.`
    )
  }

  // The whole reason the table carries a contamination column. A separation on
  // an entailed endpoint is the capture filter measuring itself, and printing it
  // in the same voice as a real one is how D11 happened the first time.
  if (contamination === 'entailed') {
    return (
      `SEPARATES, AND IT IS AN ARTIFACT. ${label} is an input to the capture decision, so this ` +
      `${pp(d.difference)} describes the filter and not the packages. Not a finding.`
    )
  }
  if (contamination === 'partial') {
    return (
      `SEPARATES, PARTLY CONSTRAINED. ${pp(d.difference)} (family-adjusted ${pp(d.low)} to ${pp(d.high)}). ` +
      `The class bounds this endpoint without fixing it, so some of the difference is the filter.`
    )
  }
  return (
    `SEPARATES. ${pp(d.difference)} (family-adjusted ${pp(d.low)} to ${pp(d.high)}, excludes zero), ` +
    `on an endpoint nothing in the capture decision constrains.`
  )
}

// ---------------------------------------------------------------------------
// The family half
// ---------------------------------------------------------------------------

export interface FamilyFindings {
  families: number
  cadences: number
  isolated: number
  // The naive endpoint, and its base rate. Printed first because the base rate
  // is the finding: a tight batch is what a monorepo release looks like.
  tightBatches: number
  allFirstPublication: number
  tightAndAllNew: number
  tightAndAllNewWithToken: number
  // Families holding a name this project has labelled confirmed_malicious.
  maliciousFamilies: Array<{
    publisher: string
    packages: string[]
    spanMinutes: number
    tight: boolean
    allNew: boolean
    sharedToken: string | null
  }>
  sequences: NumberedSequence[]
  droppedNoPublisher: number
}

function familyFindings(
  publications: Publication[],
  profiles: MetadataProfile[],
  maliciousNames: Set<string>,
  droppedNoPublisher: number
): FamilyFindings {
  const firstPublications = firstPublicationNames(profiles)
  const { families, cadences, isolated } = partitionIntoFamilies(publications, { firstPublications })
  const shaped = families.map(f => ({ family: f, profile: familyProfileOf(f) }))

  const malicious = families
    .filter(f => f.packages.some(p => maliciousNames.has(p)))
    .map(f => {
      const p = familyProfileOf(f)
      return {
        publisher: f.publisher,
        packages: f.packages,
        spanMinutes: f.spanMinutes,
        tight: p.isTightBatch,
        allNew: p.allFirstPublications,
        sharedToken: f.sharedToken,
      }
    })

  return {
    families: families.length,
    cadences: cadences.length,
    isolated: isolated.length,
    tightBatches: shaped.filter(s => s.profile.isTightBatch).length,
    allFirstPublication: shaped.filter(s => s.profile.allFirstPublications).length,
    tightAndAllNew: shaped.filter(s => s.profile.isTightBatch && s.profile.allFirstPublications).length,
    tightAndAllNewWithToken: shaped.filter(
      s => s.profile.isTightBatch && s.profile.allFirstPublications && s.profile.hasSharedToken
    ).length,
    maliciousFamilies: malicious,
    sequences: numberedSequences(publications),
    droppedNoPublisher,
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface UnitComparison {
  unit: MetadataUnit
  cases: number
  controls: number
  // Case members the publisher unit could not place. Printed rather than
  // silently dropped: at the publisher unit these are removals whose account the
  // record no longer names.
  caseUnattributed: number
  endpoints: EndpointComparison[]
}

export interface MetadataRunReport {
  version: string
  since: string
  until: string
  controlCaptureReason: string | null

  // Cohort sizes at every stage, because the point of this run is that its
  // denominators are not the capability run's.
  capturesScanned: number
  packumentsRead: number
  caseProfiles: number
  caseProfilesWithoutBytes: number
  controlProfiles: number
  unmatchedCases: string[]

  // Every endpoint at every unit. The publisher rows are the ones to read; the
  // capture rows are printed to show what the unit is worth, not as a second
  // measurement.
  units: UnitComparison[]
  z: number
  family: FamilyFindings

  // ---- what the data itself turned out to be wrong about -------------------
  createdAtAfterFirstRelease: number
  registryAttributed: number
  takedownPlaceholders: number
  classDisagreements: number
}

export function runMetadataControl(options: MetadataRunOptions): MetadataRunReport {
  const corpus = loadCorpus(options.roots)

  // Cases: every confirmed removal with a readable packument, WITH OR WITHOUT
  // BYTES. This is the one line that separates this run from the capability run,
  // and it is what makes the external corpus analysable at all.
  const caseSamples = corpus.confirmedMalicious.filter(s => !INSPIRED_THE_CLASS.includes(s.package))

  const times = caseSamples.map(s => s.capturedAt).sort()
  const since = options.since ?? times[0] ?? ''
  const until = options.until ?? times[times.length - 1] ?? ''

  const withdrawn = withdrawnPackages(options.outputDir, corpus.samples)
  const removed = withdrawn.names

  const inWindow = corpus.samples.filter(
    s => !s.contaminated && s.capturedAt >= since && s.capturedAt <= until
  )
  const poolSamples = inWindow.filter(
    s =>
      s.label !== 'confirmed_malicious' &&
      !removed.has(s.package) &&
      (options.controlCaptureReason === undefined || s.captureReason === options.controlCaptureReason)
  )

  // ---- profiles -----------------------------------------------------------

  const caseProfiles: MetadataProfile[] = []
  for (const s of caseSamples) {
    const p = profileFor(s)
    if (p) caseProfiles.push(p)
  }

  const poolProfiles: MetadataProfile[] = []
  const poolMembers: CohortMember[] = []
  for (const s of poolSamples) {
    const p = profileFor(s)
    if (!p) continue
    poolProfiles.push(p)
    const member = memberOf(s)
    if (member) poolMembers.push(member)
  }

  // ---- the match ----------------------------------------------------------
  //
  // Size-matched the same way A5 matches, and for the same reason: size is the
  // strongest confound in this corpus and the cases are tiny. A case whose only
  // capture is the takedown placeholder has no authored size to match on — the
  // placeholder's bytes are npm's — so it is matched out and reported.
  const caseMembers: CohortMember[] = []
  const unmatchedCases: string[] = []
  const casePackages = new Map<string, CorpusSample>()
  for (const s of caseSamples) {
    const seen = casePackages.get(s.package)
    if (!seen || s.capturedAt < seen.capturedAt) casePackages.set(s.package, s)
  }
  for (const s of casePackages.values()) {
    const member = memberOf(s)
    if (member && !isTakedownPlaceholder(member.version) && member.unpackedSize > 0) caseMembers.push(member)
    else unmatchedCases.push(`${s.package}@${s.version}`)
  }

  const poolByPackage = new Map<string, CohortMember>()
  for (const m of poolMembers) {
    const seen = poolByPackage.get(m.package)
    if (!seen || m.capturedAt < seen.capturedAt) poolByPackage.set(m.package, m)
  }

  const matches = matchOnSize(
    caseMembers,
    [...poolByPackage.values()],
    options.matchRatio ?? MATCH_RATIO,
    options.caliper ?? SIZE_CALIPER_LOG10
  )
  const matched = new Set(matches.flatMap(m => m.controls.map(c => c.package)))
  const controlProfiles = poolProfiles.filter(p => matched.has(p.package))

  // ---- the family half, over the WHOLE pool -------------------------------
  //
  // Deliberately not over the matched controls. A family is a property of an
  // operator's whole output, and drawing it from a size-matched subset would cut
  // batches in half and then report their size.
  const publications: Publication[] = []
  let droppedNoPublisher = 0
  const seenPublication = new Set<string>()
  for (const s of [...caseSamples, ...poolSamples]) {
    const packument = capturePackument(s.ngpackPath)
    if (!packument) continue
    const publisher = publisherFor(packument, s.version)
    if (publisher === null) { droppedNoPublisher += 1; continue }
    for (const p of publicationsFrom(packument, publisher)) {
      const key = `${p.package}@${p.version}`
      if (seenPublication.has(key)) continue
      seenPublication.add(key)
      publications.push(p)
    }
  }

  const maliciousNames = new Set(caseSamples.map(s => s.package))
  const allProfiles = [...caseProfiles, ...poolProfiles]

  const z = zForFamily(BINARY.length)

  return {
    version: '1.4.0',
    since,
    until,
    controlCaptureReason: options.controlCaptureReason ?? null,

    capturesScanned: corpus.samples.length,
    packumentsRead: allProfiles.length,
    caseProfiles: caseProfiles.length,
    caseProfilesWithoutBytes: caseSamples.filter(s => !s.tarballPresent).length,
    controlProfiles: controlProfiles.length,
    unmatchedCases,

    units: METADATA_UNITS.map(unit => {
      const cases = atMetadataUnit(caseProfiles, unit)
      const controls = atMetadataUnit(controlProfiles, unit)
      return {
        unit,
        cases: cases.length,
        controls: controls.length,
        caseUnattributed: unit === 'publisher' ? caseProfiles.filter(p => p.publisher === null).length : 0,
        endpoints: BINARY.map(spec => compareEndpoint(spec, cases, controls, z)),
      }
    }),
    z,
    family: familyFindings(publications, allProfiles, maliciousNames, droppedNoPublisher),

    createdAtAfterFirstRelease: allProfiles.filter(p => p.createdAtAfterFirstRelease).length,
    registryAttributed: droppedNoPublisher,
    takedownPlaceholders: allProfiles.filter(p => isTakedownPlaceholder(p.version)).length,
    // Where the repaired age disagrees with the filter's own decision about the
    // class. Each one is a capture that entered on `time.created`.
    classDisagreements: allProfiles.filter(
      p => p.createdAtAfterFirstRelease && !inObservedClass(p)
    ).length,
  }
}

function profileFor(sample: CorpusSample): MetadataProfile | null {
  const packument = capturePackument(sample.ngpackPath)
  if (!packument) return null
  return metadataProfileOf({
    packument,
    version: sample.version,
    capturedAt: sample.capturedAt,
  })
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

export function renderMetadataReport(r: MetadataRunReport): string {
  const out: string[] = []
  const line = (s = ''): void => { out.push(s) }
  const pct = (x: number, n: number): string => (n === 0 ? '   n/a' : `${(100 * x / n).toFixed(1)}%`)

  line(`METADATA, CONTROLLED  norte-guard v${r.version}`)
  line(`  window ${r.since.slice(0, 16)} to ${r.until.slice(0, 16)}`)
  line()
  line('WHAT THIS RUN IS FOR')
  line('  Every endpoint in the capability run needs the tarball, and 0 of the 42')
  line('  confirmed removals collected outside this project still has one. These')
  line('  endpoints need only the packument, which npm keeps after the takedown —')
  line('  including the publication timestamps of versions it has already deleted.')
  line()
  line('  Most of what a packument says about a young package is downstream of the')
  line('  package being young, so every row below carries how it stands to the three')
  line('  conjuncts the capture filter selects on. A separation on an `entailed` row')
  line('  is the filter measuring itself and is labelled as such, not read as a find.')
  line()

  line('THE COHORT')
  line(`  ${r.capturesScanned} captures scanned, ${r.packumentsRead} packuments read`)
  line(`  cases     ${String(r.caseProfiles).padStart(5)}   of which ${r.caseProfilesWithoutBytes} have NO tarball and are analysable here anyway`)
  line(`  controls  ${String(r.controlProfiles).padStart(5)}   size-matched, ${r.controlCaptureReason ?? 'every capture reason'}`)
  if (r.unmatchedCases.length > 0) {
    line(`  ${r.unmatchedCases.length} case package(s) carry no authored size to match on (placeholder only):`)
    line(`    ${r.unmatchedCases.slice(0, 6).join(', ')}${r.unmatchedCases.length > 6 ? ` +${r.unmatchedCases.length - 6}` : ''}`)
  }
  line()

  // The finding, at the unit that decides it, before anything a reader could
  // mistake for it.
  const primary = r.units.find(u => u.unit === PRIMARY_METADATA_UNIT)
  const capture = r.units.find(u => u.unit === 'capture')
  if (primary && capture) {
    line('WHAT THIS RUN FOUND')
    const separating = primary.endpoints.filter(e => e.contamination === 'independent' && e.familyAdjusted.separated)
    if (separating.length === 0) {
      line(`  At the ${PRIMARY_METADATA_UNIT} unit — ${primary.cases} cases against ${primary.controls} controls —`)
      line('  NOT ONE uncontaminated endpoint separates. Every interval includes zero.')
    } else {
      line(`  At the ${PRIMARY_METADATA_UNIT} unit — ${primary.cases} cases against ${primary.controls} controls —`)
      for (const e of separating) line(`    SEPARATES  ${e.label}`)
    }
    line()
    const captureOnly = capture.endpoints.filter(
      e =>
        e.contamination === 'independent' &&
        e.familyAdjusted.separated &&
        !primary.endpoints.find(p => p.key === e.key)?.familyAdjusted.separated
    )
    if (captureOnly.length > 0) {
      line('  These separate at the CAPTURE unit and not at the publisher unit:')
      for (const e of captureOnly) line(`    ${e.label}`)
      line('  A capture-unit rate over this cohort is a rate of REPUBLISHING. One case')
      line('  operator holds 149 releases of one name, and every endpoint here is a')
      line('  property of a release habit, so counting it once per capture gives that')
      line('  operator as many votes as it made releases. Read the publisher rows.')
      line()
    }
  }

  line('='.repeat(74))
  line(`THE ENDPOINTS   ${BINARY.length} comparisons, intervals widened to z=${r.z.toFixed(2)}`)
  line()
  for (const unit of [PRIMARY_METADATA_UNIT, ...METADATA_UNITS.filter(u => u !== PRIMARY_METADATA_UNIT)]) {
    const u = r.units.find(x => x.unit === unit)
    if (!u) continue
    line(`  AT THE ${unit.toUpperCase()} UNIT   ${u.cases} cases, ${u.controls} controls` +
      (unit === PRIMARY_METADATA_UNIT ? '   <- the primary unit, declared before the run' : '') +
      (u.caseUnattributed > 0 ? `   (${u.caseUnattributed} case captures name no account)` : ''))
    line()
    for (const group of ['independent', 'partial', 'entailed'] as Contamination[]) {
      const rows = u.endpoints.filter(e => e.contamination === group)
      if (rows.length === 0) continue
      line(`  ---- ${group.toUpperCase()} of the capture decision ${'-'.repeat(46 - group.length)}`)
      for (const e of rows) {
        line(`  ${e.label}`)
        line(
          `    cases ${e.cases.successes}/${e.cases.n} ${pct(e.cases.successes, e.cases.n).padStart(6)}` +
          `    controls ${e.controls.successes}/${e.controls.n} ${pct(e.controls.successes, e.controls.n).padStart(6)}` +
          (e.caseHeldOut + e.controlHeldOut > 0
            ? `    held out ${e.caseHeldOut}/${e.controlHeldOut} (record cannot answer)`
            : '')
        )
        line(`    ${e.verdict}`)
        if (group !== 'independent' && unit === PRIMARY_METADATA_UNIT) line(`    why: ${e.because}`)
        line()
      }
    }
    line()
  }

  line('='.repeat(74))
  line('THE BATCH AS THE UNIT   (idea 4)')
  const f = r.family
  line(`  ${f.families} families, ${f.cadences} cadences, ${f.isolated} isolated publications`)
  line('  A family is several DISTINCT names from one account inside')
  line(`  ${BURST_GAP_MINUTES} minutes. One name republishing is a cadence and is counted apart:`)
  line('  @siwatfa/yorn is 149 releases of one package and is not a campaign.')
  line()
  line(`  tight batch (>=${TIGHT_BATCH_PACKAGES} names within ${TIGHT_BATCH_MINUTES}min)   ${String(f.tightBatches).padStart(6)}   ${pct(f.tightBatches, f.families)} of families`)
  line(`  every name a first publication         ${String(f.allFirstPublication).padStart(6)}   ${pct(f.allFirstPublication, f.families)}`)
  line(`  BOTH                                   ${String(f.tightAndAllNew).padStart(6)}   ${pct(f.tightAndAllNew, f.families)}`)
  line(`  both, and sharing a lexical token      ${String(f.tightAndAllNewWithToken).padStart(6)}   ${pct(f.tightAndAllNewWithToken, f.families)}`)
  line()
  line('  THE BASE RATE IS THE RESULT. Publishing several names at once is what a')
  line(`  monorepo release is — 84 @hive-ui packages in two minutes — and the tight-`)
  line(`  batch endpoint describes ${pct(f.tightBatches, f.families)} of the families here. It is the conjunction`)
  line('  with all-first-publication that is rare. The naive form of idea 4 is')
  line('  saturated by ordinary practice, exactly the way idea 1 was by minification.')
  line()
  if (f.maliciousFamilies.length > 0) {
    line('  families holding a confirmed_malicious name:')
    for (const m of f.maliciousFamilies) {
      line(
        `    ${m.publisher.padEnd(18)} ${String(m.packages.length).padStart(2)}n ` +
        `${String(Math.round(m.spanMinutes)).padStart(4)}min  tight=${m.tight ? 'Y' : 'n'} allNew=${m.allNew ? 'Y' : 'n'} ` +
        `tok=${m.sharedToken ?? '-'}`
      )
      line(`      ${m.packages.join(', ')}`)
    }
    line()
  }

  if (f.sequences.length > 0) {
    line('  ONE COUNTER, SEVERAL ACCOUNTS')
    line('  A family is keyed by publisher, and that is a ceiling: a campaign that')
    line('  rotates accounts is invisible to every per-publisher unit. What makes it')
    line('  visible is a counter in the name that ascends across the whole set.')
    line()
    for (const s of f.sequences) {
      line(`    shape ${s.shape}   ${s.members.length} names across ${s.publishers.length} accounts`)
      line(`      accounts: ${s.publishers.join(', ')}`)
      line(`      numbers:  ${s.members.map(m => m.number).join(', ')}`)
      line(`      ${s.crossAccountAdjacency} of ${s.adjacentPairs} adjacent-by-number pairs change account`)
      line(`      median gap ${s.medianGapSeconds === null ? 'n/a' : `${s.medianGapSeconds.toFixed(0)}s`}, span ${Math.round(s.spanMinutes)}min`)
    }
    line()
  }

  line('='.repeat(74))
  line('WHAT THE RECORD ITSELF GOT WRONG')
  line(`  ${r.createdAtAfterFirstRelease} packuments declare a \`created\` LATER than their own earliest release.`)
  line('  npm resets it when it republishes a removed name as 0.0.1-security, so a')
  line('  package that lived five days reads as newborn — and `young` is one of the')
  line('  three conjuncts the quarantine filter selects on. Every age in this run is')
  line('  taken from the release timestamps instead.')
  line(`  ${r.classDisagreements} captures carry that defect and are NOT in the class once the age is repaired.`)
  line()
  line(`  ${r.registryAttributed} publications were dropped because the account resolves to npm itself.`)
  line(`  ${r.takedownPlaceholders} captured versions ARE npm's 0.0.1-security placeholder. Attributing those to`)
  line('  the registry would have grouped unrelated removals into one fabricated')
  line('  campaign — the OIDC-bot defect in a second costume, in the direction that')
  line('  manufactures a finding rather than the one that hides it.')
  line()

  line('WHAT THIS CANNOT SAY')
  line('  - The pool is this collector\'s capture filter, not npm. Every base rate')
  line('    here is a rate within an already-enriched population.')
  line('  - The family results are DESCRIPTIVE. With 4 malicious families there is no')
  line('    case arm to test against a control arm, and none is claimed.')
  line('  - `all first publications` is read at capture time. A name captured at its')
  line('    first release may have published again afterwards, and this run would not')
  line('    know. The error inflates the endpoint on both arms.')
  line('  - The hour of publication is recorded and NOT tested. A UTC hour is the')
  line('    publisher\'s longitude before it is anything else, and 8 case accounts')
  line('    is one draw from a timezone distribution.')
  line('  - Nothing here scores. No endpoint contributes a point to any verdict.')

  return out.join('\n')
}
