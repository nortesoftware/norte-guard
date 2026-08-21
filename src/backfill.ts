// The one-time pass over what the terminal 404 already cost.
//
// The retry queue fixes this going forward. It does nothing for the 6,892
// packages the change feed announced before it existed, whose packument fetch
// returned 404 once and which were never analysed again. Six of those are known
// to have been removed by npm afterwards, so the population is not noise.
//
// This is a replay, not a new capture rule. Each name is fetched now and run
// through the SAME `analyzePackage` the watcher uses, so a package that is still
// there is judged by the policy that would have judged it at the time. Capturing
// them unconditionally would put 6,892 packages selected by "npm was briefly
// inconsistent about them" into a corpus whose every other member was selected
// by score or by class, and no later analysis could separate the two draws.
//
// What is gone is written to the permanent-loss log with its reason. That record
// is the point as much as the recovery: this project has spent weeks reasoning
// about a corpus without knowing that a fifth of what it announced never reached
// it, and a silent drop is indistinguishable from a registry that had nothing.

import { existsSync, readFileSync, appendFileSync, readdirSync, statSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'
import { join } from 'node:path'
import { fetchPackument } from './packument.js'
import { PERMANENT_LOSS_LOG } from './retry-queue.js'

export interface TerminalFailure {
  package: string
  seq: number | string
  seenAt: string
  reason: string
}

// A publication announced, fetched once, failed, and never analysed afterwards.
//
// "Never afterwards" is the whole definition: 45.5% of the 404s in this store
// are followed by an `analyzed` row for the same name, because the package
// published again and the second announcement worked. Those cost nothing and are
// not in this population.
export function terminalFailures(outputDir: string): TerminalFailure[] {
  const rows = readChangeLog(outputDir)
  const byPackage = new Map<string, Array<Record<string, unknown>>>()
  for (const row of rows) {
    const name = row['package']
    if (typeof name !== 'string') continue
    const list = byPackage.get(name) ?? []
    list.push(row)
    byPackage.set(name, list)
  }

  const out: TerminalFailure[] = []
  for (const [name, list] of byPackage) {
    list.sort((a, b) => String(a['seenAt'] ?? '').localeCompare(String(b['seenAt'] ?? '')))
    const first = list.findIndex(r => r['outcome'] === 'unreachable')
    if (first === -1) continue
    // `malformed` is excluded for the same reason the retry queue excludes it:
    // the document parsed badly and will parse badly again.
    const reason = String(list[first]!['unreachableReason'] ?? 'unknown')
    if (reason === 'malformed') continue
    if (list.slice(first + 1).some(r => r['outcome'] === 'analyzed')) continue

    out.push({
      package: name,
      seq: (list[first]!['seq'] as number | string) ?? 0,
      seenAt: String(list[first]!['seenAt'] ?? ''),
      reason,
    })
  }
  return out.sort((a, b) => a.seenAt.localeCompare(b.seenAt))
}

function readChangeLog(outputDir: string): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = []
  let names: string[]
  try {
    names = readdirSync(outputDir)
  } catch {
    return rows
  }

  for (const name of names) {
    if (!name.startsWith('changes-log')) continue
    const path = join(outputDir, name)
    try {
      if (!statSync(path).isFile()) continue
      // Rotated logs are gzipped and hold most of the history — 5 of the 6 files
      // in this store. Reading only the live one would define the population by
      // which day the rotation last ran.
      const text = name.endsWith('.gz')
        ? gunzipSync(readFileSync(path)).toString('utf-8')
        : readFileSync(path, 'utf-8')
      for (const line of text.split('\n')) {
        if (!line) continue
        try { rows.push(JSON.parse(line) as Record<string, unknown>) } catch { /* a torn line */ }
      }
    } catch { /* unreadable log */ }
  }
  return rows
}

export interface BackfillOutcome {
  package: string
  // 'recovered' — still on the registry and re-analysed under the live policy.
  // 'gone'      — the fetch failed again. Written to the permanent-loss log.
  // 'held'      — already in the corpus; a later capture got it after all.
  state: 'recovered' | 'gone' | 'held'
  captured?: boolean
  reason?: string
}

export function alreadyHeld(capturesDir: string): Set<string> {
  const held = new Set<string>()
  if (!existsSync(capturesDir)) return held
  for (const dir of readdirSync(capturesDir)) {
    if (dir === 'objects') continue
    const meta = join(capturesDir, dir, 'capture-metadata.json')
    if (!existsSync(meta)) continue
    try {
      const parsed = JSON.parse(readFileSync(meta, 'utf-8')) as { package?: string }
      if (parsed.package) held.add(parsed.package)
    } catch { /* unreadable metadata */ }
  }
  return held
}

export interface BackfillOptions {
  outputDir: string
  limit?: number
  // Pacing between requests. The default is the same 250ms the research passes
  // use: this asks the registry about thousands of names it has already been
  // asked about once, and doing it fast would be the least defensible request
  // this project makes.
  delayMs?: number
  dryRun?: boolean
  analyse: (name: string) => Promise<{ outcome: 'analyzed' | 'unreachable'; captured?: boolean }>
  onProgress?: (done: number, total: number, outcome: BackfillOutcome) => void
}

export async function runBackfill(options: BackfillOptions): Promise<BackfillOutcome[]> {
  const failures = terminalFailures(options.outputDir)
  const held = alreadyHeld(join(options.outputDir, 'captures'))
  const pending = failures.filter(f => !held.has(f.package))
  const work = options.limit === undefined ? pending : pending.slice(0, options.limit)

  const results: BackfillOutcome[] = []
  for (const [index, failure] of work.entries()) {
    if (options.dryRun) {
      results.push({ package: failure.package, state: 'gone', reason: 'dry run, nothing fetched' })
      continue
    }

    let outcome: BackfillOutcome
    try {
      // Fetched first so that a name npm no longer serves never reaches the
      // analysis path, where a 404 would be recorded a second time as if it were
      // news.
      await fetchPackument(failure.package)
      const analysis = await options.analyse(failure.package)
      outcome = analysis.outcome === 'analyzed'
        ? { package: failure.package, state: 'recovered', captured: analysis.captured }
        : { package: failure.package, state: 'gone', reason: 'unreachable on the replay too' }
    } catch (e) {
      outcome = { package: failure.package, state: 'gone', reason: String(e) }
    }

    if (outcome.state === 'gone') {
      appendFileSync(
        join(options.outputDir, PERMANENT_LOSS_LOG),
        `${JSON.stringify({
          package: failure.package,
          seq: failure.seq,
          firstSeenAt: failure.seenAt,
          reason: failure.reason,
          gaveUpAt: new Date().toISOString(),
          note:
            'announced by the change feed, unreachable then and unreachable on the one-time ' +
            'backfill. Whatever was published under this name was never fetched by anyone here.',
        })}\n`
      )
    }

    results.push(outcome)
    options.onProgress?.(index + 1, work.length, outcome)
    if (options.delayMs !== 0) await sleep(options.delayMs ?? 250)
  }
  return results
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export function summarise(results: BackfillOutcome[]): string {
  const recovered = results.filter(r => r.state === 'recovered')
  const captured = recovered.filter(r => r.captured)
  const gone = results.filter(r => r.state === 'gone')
  return [
    `  replayed          ${results.length}`,
    `  still on npm      ${recovered.length}  (re-analysed under the live policy)`,
    `  of those captured ${captured.length}`,
    `  gone for good     ${gone.length}  (written to ${PERMANENT_LOSS_LOG})`,
    '',
    '  A recovered package was judged by the same policy that judges a live',
    '  publication, so this adds no new selection to the corpus: it repairs an',
    '  evaluation that a single 404 prevented.',
  ].join('\n')
}
