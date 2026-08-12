// A score cut-off bounds which packages get captured, not how many bytes that
// costs. Seven hours of watching produced 4.6GB — about 16GB a day — with
// nothing in the code that could have stopped it, because nothing was counting.
//
// This counts. The daily budget is a hard stop on downloads; the total cap
// rotates old captures out. Both are about disk, like the score cut-off, and
// neither changes what gets detected.

import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync, gunzipSync } from 'node:zlib'
import type { CaptureLabel } from './ngpack.js'

export const DEFAULT_DAILY_BYTES = 2 * 1024 ** 3
export const DEFAULT_TOTAL_BYTES = 10 * 1024 ** 3

const STATE_FILE = 'capture-budget.json'

interface BudgetState {
  day: string
  bytes: number
  captures: number
  skippedOverBudget: number
}

export function formatBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)}GB`
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(0)}MB`
  if (n >= 1024) return `${(n / 1024).toFixed(0)}KB`
  return `${n}B`
}

// Persisted so a restart cannot reset the day's spend, which is the obvious way
// to spend the budget twice.
export class DailyCaptureBudget {
  private state: BudgetState

  constructor(
    private dir: string,
    readonly dailyBytes = DEFAULT_DAILY_BYTES,
    today = new Date().toISOString().slice(0, 10)
  ) {
    this.state = this.load(today)
  }

  private load(today: string): BudgetState {
    const path = join(this.dir, STATE_FILE)
    if (existsSync(path)) {
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf-8')) as BudgetState
        if (parsed.day === today) return parsed
      } catch { /* a corrupt file resets the day rather than blocking captures */ }
    }
    return { day: today, bytes: 0, captures: 0, skippedOverBudget: 0 }
  }

  private save(): void {
    try {
      writeFileSync(join(this.dir, STATE_FILE), JSON.stringify(this.state, null, 2))
    } catch { /* losing the counter must not take down the watcher */ }
  }

  rollIfNewDay(today = new Date().toISOString().slice(0, 10)): void {
    if (this.state.day !== today) {
      this.state = { day: today, bytes: 0, captures: 0, skippedOverBudget: 0 }
      this.save()
    }
  }

  get spent(): number { return this.state.bytes }
  get remaining(): number { return Math.max(0, this.dailyBytes - this.state.bytes) }
  get captures(): number { return this.state.captures }
  get skipped(): number { return this.state.skippedOverBudget }
  get exhausted(): boolean { return this.state.bytes >= this.dailyBytes }

  recordSkip(): void {
    this.state.skippedOverBudget++
    this.save()
  }

  recordCapture(bytes: number): void {
    this.state.bytes += bytes
    this.state.captures++
    this.save()
  }

  // Resetting is a real decision — the day's spend exists to stop the collector —
  // so it is recorded rather than performed by editing the file. The usual reason
  // is that the spend came from a policy that no longer exists.
  reset(reason: string): { previousBytes: number; previousCaptures: number } {
    const previous = { previousBytes: this.state.bytes, previousCaptures: this.state.captures }

    try {
      writeFileSync(
        join(this.dir, 'budget-log.ndjson'),
        JSON.stringify({
          resetAt: new Date().toISOString(),
          day: this.state.day,
          reason,
          ...previous,
        }) + '\n',
        { flag: 'a' }
      )
    } catch { /* the reset matters more than the audit line */ }

    this.state = { day: this.state.day, bytes: 0, captures: 0, skippedOverBudget: 0 }
    this.save()
    return previous
  }
}

// One consolidated file per day instead of one per change. 22,147 files for
// 181MB is inode overhead, not data: each delta is a few kilobytes and the
// filesystem rounds every one of them up to a block.
export interface DeltaConsolidation {
  days: Array<{ day: string; files: number; bytes: number; compressed: number }>
  skipped: number
}

export function consolidateDeltas(
  deltaDir: string,
  today = new Date().toISOString().slice(0, 10),
  dryRun = false,
  // The current day is normally left alone because it is still being appended
  // to. With tens of thousands of files already on disk, waiting for midnight is
  // its own problem, so today can be swept into a numbered batch and the files
  // written afterwards go into the next one.
  includeToday = false
): DeltaConsolidation {
  const result: DeltaConsolidation = { days: [], skipped: 0 }
  if (!existsSync(deltaDir)) return result

  // Filenames start with the ISO timestamp the delta was written at.
  const byDay = new Map<string, string[]>()
  for (const name of readdirSync(deltaDir)) {
    if (!name.endsWith('.json.gz')) continue
    if (name.startsWith('deltas-')) continue

    const day = name.slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) { result.skipped++; continue }
    if (day === today && !includeToday) continue

    const list = byDay.get(day) ?? []
    list.push(name)
    byDay.set(day, list)
  }

  for (const [day, files] of byDay) {
    let target = join(deltaDir, `deltas-${day}.ndjson.gz`)
    if (existsSync(target)) {
      if (day !== today) { result.skipped += files.length; continue }
      // Today can be consolidated more than once; each pass takes what has
      // accumulated since the last.
      for (let i = 2; existsSync(target); i++) {
        target = join(deltaDir, `deltas-${day}-${i}.ndjson.gz`)
      }
    }

    const lines: string[] = []
    let bytes = 0

    for (const name of files) {
      const path = join(deltaDir, name)
      try {
        const raw = readFileSync(path)
        bytes += raw.length
        lines.push(gunzipSync(raw).toString('utf-8').trim())
      } catch { /* one unreadable delta is not worth losing the day over */ }
    }

    if (lines.length === 0) continue

    const compressed = gzipSync(Buffer.from(lines.join('\n') + '\n'))
    if (!dryRun) {
      writeFileSync(target, compressed)
      for (const name of files) {
        try { rmSync(join(deltaDir, name)) } catch { /* leave it */ }
      }
    }

    result.days.push({ day, files: files.length, bytes, compressed: compressed.length })
  }

  return result
}

export function directorySize(dir: string): number {
  let total = 0
  const walk = (d: string) => {
    let entries: string[]
    try { entries = readdirSync(d) } catch { return }
    for (const name of entries) {
      const p = join(d, name)
      try {
        const st = statSync(p)
        if (st.isDirectory()) walk(p)
        else total += st.size
      } catch { /* a capture deleted mid-walk is not an error */ }
    }
  }
  walk(dir)
  return total
}

// Disk spend and corpus policy were one number, and they pull in opposite
// directions: the score cut-off keeps what looks alarming, while the malware
// that gets taken down is young, tiny and scores 20-26. Under a single threshold
// the loud packages take the disk and the real ones are never kept.
//
// Quarantine is the other half. Every recent package with no genome is captured
// regardless of score and deleted a week later unless something confirms it —
// npm publishing 0.0.1-security over it, or someone labelling it by hand. It
// costs a bounded amount of disk for a bounded time, and it is the only way a
// confirmed sample can ever have an artifact behind it.
export interface QuarantinePolicy {
  enabled: boolean
  // Package age at publication. Older than this and it is not the class this is
  // for, whatever its regime.
  maxAgeDays: number
  retentionDays: number
  // Per-capture ceiling. The class being archived is small; a 200MB package that
  // happens to be new would spend the day's budget on one sample.
  maxBytes: number
}

export const DEFAULT_QUARANTINE: QuarantinePolicy = {
  enabled: true,
  maxAgeDays: 30,
  retentionDays: 7,
  maxBytes: 8 * 1024 ** 2,
}

export interface QuarantineSweep {
  expired: string[]
  kept: number
  promoted: number
}

// Deletes quarantine captures past their retention that nothing confirmed.
// Anything labelled is kept: a promotion is exactly what quarantine exists to
// wait for, and deleting it afterwards would throw away the sample.
export function sweepQuarantine(
  capturesDir: string,
  now = Date.now(),
  dryRun = false
): QuarantineSweep {
  const result: QuarantineSweep = { expired: [], kept: 0, promoted: 0 }
  if (!existsSync(capturesDir)) return result

  for (const name of readdirSync(capturesDir)) {
    const path = join(capturesDir, name)
    const metaPath = join(path, 'capture-metadata.json')
    if (!existsSync(metaPath)) continue

    let meta: { label?: CaptureLabel; captureReason?: string; retainUntil?: string }
    try {
      meta = JSON.parse(readFileSync(metaPath, 'utf-8'))
    } catch { continue }

    if (meta.captureReason !== QUARANTINE_REASON) continue

    if (meta.label && meta.label !== 'unconfirmed') {
      result.promoted++
      continue
    }

    if (!meta.retainUntil || new Date(meta.retainUntil).getTime() > now) {
      result.kept++
      continue
    }

    if (!dryRun) {
      try { rmSync(path, { recursive: true, force: true }) } catch { continue }
    }
    result.expired.push(path)
  }

  return result
}

export const QUARANTINE_REASON = 'quarantine-no-genome'

export interface RotationCandidate {
  path: string
  bytes: number
  capturedAt: string
  label: CaptureLabel
}

export interface RotationResult {
  before: number
  after: number
  deleted: RotationCandidate[]
  protectedCount: number
}

// Deletes oldest first, and only captures still labelled 'unconfirmed'. Anything
// someone has confirmed or cleared is evidence, and rotation must never be the
// reason it disappears.
export function rotateCaptures(
  capturesDir: string,
  maxBytes: number,
  dryRun = false
): RotationResult {
  if (!existsSync(capturesDir)) {
    return { before: 0, after: 0, deleted: [], protectedCount: 0 }
  }

  const candidates: RotationCandidate[] = []
  let protectedCount = 0
  let total = 0

  for (const name of readdirSync(capturesDir)) {
    const path = join(capturesDir, name)
    try {
      if (!statSync(path).isDirectory()) continue
    } catch { continue }

    const bytes = directorySize(path)
    total += bytes

    let label: CaptureLabel = 'unconfirmed'
    let capturedAt = ''
    const metaPath = join(path, 'capture-metadata.json')
    if (existsSync(metaPath)) {
      try {
        const meta = JSON.parse(readFileSync(metaPath, 'utf-8')) as { label?: CaptureLabel; capturedAt?: string }
        label = meta.label ?? 'unconfirmed'
        capturedAt = meta.capturedAt ?? ''
      } catch { /* unreadable metadata is treated as unconfirmed */ }
    }

    if (label !== 'unconfirmed') { protectedCount++; continue }
    candidates.push({ path, bytes, capturedAt, label })
  }

  const before = total
  if (total <= maxBytes) {
    return { before, after: total, deleted: [], protectedCount }
  }

  candidates.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))

  const deleted: RotationCandidate[] = []
  for (const candidate of candidates) {
    if (total <= maxBytes) break
    if (!dryRun) {
      try { rmSync(candidate.path, { recursive: true, force: true }) } catch { continue }
    }
    total -= candidate.bytes
    deleted.push(candidate)
  }

  return { before, after: total, deleted, protectedCount }
}
