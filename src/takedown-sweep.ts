// Asks the registry which of the packages this collector has seen have since
// been removed, and — the part that decides whether any of them is a recall
// sample — whether the collector saw them before or after the removal.
//
// The distinction is not a detail. Publishing 0.0.1-security is itself a change
// on the feed, so a collector that starts after an attack observes the
// placeholder, scores the placeholder, and learns nothing about detection. Only
// an observation of the real artifact, made before npm removed it, poses the
// question "would the gate have blocked this".

import { readdirSync, readFileSync, existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import https from 'node:https'
import { NPM_SECURITY_HOLDER, isPreTakedownObservation, type ObservationWindow } from './takedown.js'

export interface SweepResult {
  observed: number
  checked: number
  unreachable: number
  takenDown: TakedownFinding[]
  preTakedownObservations: TakedownFinding[]
  placeholderOnly: TakedownFinding[]
}

export interface TakedownFinding {
  package: string
  observedVersion: string
  observedAt: string
  liveVersions: number
}

// The dist-tag latest as of the newest delta held for each package. That is what
// the collector actually saw.
export function readObservations(outputDir: string): ObservationWindow[] {
  const deltaDir = join(outputDir, 'deltas')
  if (!existsSync(deltaDir)) return []

  const latest = new Map<string, ObservationWindow>()

  const record = (raw: string) => {
    try {
      const delta = JSON.parse(raw) as {
        name?: string
        capturedAt?: string
        distTags?: Record<string, string>
      }
      const name = delta.name
      const observedVersion = delta.distTags?.['latest']
      if (!name || !observedVersion) return

      const at = delta.capturedAt ?? ''
      const existing = latest.get(name)
      if (!existing || at > existing.observedAt) {
        latest.set(name, { package: name, observedVersion, observedAt: at })
      }
    } catch {
      // One unreadable delta is not a reason to abandon the sweep.
    }
  }

  for (const file of readdirSync(deltaDir)) {
    // Both suffixes, and checked in this order: ".ndjson.gz" does not end with
    // ".json.gz", so a single-suffix test silently skipped every consolidated
    // day and cut the sweep's denominator from 15,277 observations to 21.
    const consolidated = file.endsWith('.ndjson.gz')
    if (!consolidated && !file.endsWith('.json.gz')) continue

    try {
      const text = gunzipSync(readFileSync(join(deltaDir, file))).toString()
      // Consolidated days hold one delta per line; the per-change files hold one
      // document. Both are read, so consolidating cannot lose an observation.
      if (consolidated) {
        for (const line of text.split('\n')) {
          if (line.trim()) record(line)
        }
      } else {
        record(text)
      }
    } catch { /* skip */ }
  }

  return [...latest.values()]
}

function fetchAbbreviated(name: string): Promise<{ versions?: Record<string, unknown> } | null> {
  const encoded = name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : name
  return new Promise(resolve => {
    const req = https.get(`https://registry.npmjs.org/${encoded}`, {
      headers: {
        'Accept': 'application/vnd.npm.install-v1+json',
        'User-Agent': 'norte-guard-takedown-sweep/0.1.0',
      },
      timeout: 15_000,
    }, res => {
      if ((res.statusCode ?? 0) >= 400) { res.resume(); return resolve(null) }
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => {
        try { resolve(JSON.parse(body)) } catch { resolve(null) }
      })
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

export async function sweepObserved(outputDir: string, concurrency = 8): Promise<SweepResult> {
  const observations = readObservations(outputDir)
  console.log(`\nObserved packages with a snapshot: ${observations.length}`)
  console.log('Querying the registry for npm\'s removal marker...\n')

  const takenDown: TakedownFinding[] = []
  let checked = 0, unreachable = 0, next = 0

  await Promise.all(Array.from({ length: concurrency }, async () => {
    for (;;) {
      const i = next++
      if (i >= observations.length) return
      const obs = observations[i]!

      const doc = await fetchAbbreviated(obs.package)
      checked++
      if (checked % 1000 === 0) console.log(`  ${checked}/${observations.length}...`)

      if (!doc) { unreachable++; continue }
      if (!doc.versions || !(NPM_SECURITY_HOLDER in doc.versions)) continue

      takenDown.push({
        package: obs.package,
        observedVersion: obs.observedVersion,
        observedAt: obs.observedAt,
        liveVersions: Object.keys(doc.versions).length,
      })
    }
  }))

  const preTakedownObservations = takenDown.filter(t =>
    isPreTakedownObservation({ package: t.package, observedVersion: t.observedVersion, observedAt: t.observedAt })
  )
  const placeholderOnly = takenDown.filter(t => !preTakedownObservations.includes(t))

  const result: SweepResult = {
    observed: observations.length,
    checked,
    unreachable,
    takenDown,
    preTakedownObservations,
    placeholderOnly,
  }

  renderSweep(result)

  const path = join(outputDir, 'takedowns.json')
  writeFileSync(path, JSON.stringify({ sweptAt: new Date().toISOString(), ...result }, null, 2))
  console.log(`\nResult saved to ${path}`)

  return result
}

function renderSweep(r: SweepResult): void {
  const BOLD = '\x1b[1m', DIM = '\x1b[2m', RESET = '\x1b[0m'

  console.log(`${r.checked} queried - ${r.unreachable} unreachable`)
  console.log(`\n${BOLD}${r.takenDown.length} packages removed by npm${RESET}`)
  console.log(
    `  ${r.preTakedownObservations.length} observed BEFORE removal: recall samples`
  )
  console.log(
    `  ${r.placeholderOnly.length} observed only as ${NPM_SECURITY_HOLDER}: a label with no artifact`
  )

  // The collector's own coverage of the event class, separate from anything the
  // detector did with it.
  if (r.takenDown.length > 0) {
    const rate = r.preTakedownObservations.length / r.takenDown.length
    console.log(
      `\n${BOLD}Removal coverage: ${(rate * 100).toFixed(1)}%${RESET} ` +
      `${DIM}(${r.preTakedownObservations.length}/${r.takenDown.length} seen before npm removed them)${RESET}`
    )
  }

  if (r.preTakedownObservations.length > 0) {
    console.log(`\n${BOLD}Usable samples${RESET}`)
    for (const t of r.preTakedownObservations) {
      console.log(`  ${t.package}@${t.observedVersion}  seen ${t.observedAt.slice(0, 19)}`)
    }
  } else {
    console.log(
      `\n${DIM}No usable samples. The collector saw these packages after npm had already\n` +
      `removed them: publishing ${NPM_SECURITY_HOLDER} is itself a change on the feed, and\n` +
      `that change is what was observed. What is needed is observing a real publication\n` +
      `and npm removing it afterwards, which only time provides, not another sweep.${RESET}`
    )
  }
}
