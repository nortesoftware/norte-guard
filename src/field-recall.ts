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

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { rateWithCI, type RateWithCI } from './stats.js'

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
}

const MATCH_WINDOW_MS = 10 * 60_000

interface ChangeRow {
  package?: string
  score?: number
  regime?: string
  verdict?: string
  seenAt?: string
}

export function computeFieldRecall(outputDir: string): FieldRecallReport {
  const takedownsPath = join(outputDir, 'takedowns.json')
  if (!existsSync(takedownsPath)) {
    return empty('no takedowns.json: run `norte-guard sweep-takedowns --include-observed`')
  }

  let sweep: {
    takenDown?: unknown[]
    preTakedownObservations?: Array<{ package: string; observedVersion: string; observedAt: string }>
  }
  try {
    sweep = JSON.parse(readFileSync(takedownsPath, 'utf-8'))
  } catch {
    return empty('takedowns.json ilegible')
  }

  const observations = sweep.preTakedownObservations ?? []
  const takedownsFound = sweep.takenDown?.length ?? 0

  const byPackage = new Map<string, ChangeRow[]>()
  const logPath = join(outputDir, 'changes-log.ndjson')
  if (existsSync(logPath)) {
    for (const line of readFileSync(logPath, 'utf-8').split('\n')) {
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
      // The gate never blocks a package it has no baseline for, and it is the
      // gate that decides whether CI stops.
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
    statement: `${gateHits}/${scored.length} blocked by the gate, ${auditHits}/${scored.length} by audit`,
  }
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
  }
}
