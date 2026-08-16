// A score cut-off bounds which packages get captured, not how many bytes that
// costs. Seven hours of watching produced 4.6GB — about 16GB a day — with
// nothing in the code that could have stopped it, because nothing was counting.
//
// This counts. The daily budget is a hard stop on downloads; the total cap
// rotates old captures out. Both are about disk, like the score cut-off, and
// neither changes what gets detected.

import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { gzipSync, gunzipSync } from 'node:zlib'
import type { CaptureLabel, NgpackManifest } from './ngpack.js'
import { deleteObject, listObjects, objectSize, OBJECTS_DIR } from './object-store.js'

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

// A capture is bytes and a record, and only the bytes are expensive.
//
// Both deleters in this file remove `unconfirmed` captures and leave `labelled`
// ones alone, which is the right policy for disk and exactly the wrong one for a
// denominator: the numerator of the precision fraction is protected from
// deletion and the denominator is not, and rotation takes the oldest first —
// the ones closest to the thirty days at which the answer would have arrived.
// Left as it was, precision would climb on its own as the corpus aged, and the
// climb would be the deleter rather than the filter.
//
// Quarantine retention is seven days and a verdict takes thirty, so this is not
// a corner case. It is what happens to every capture that is never labelled.
//
// One line per deleted capture, so the name stays in the denominator after the
// artifact is gone. It is small: no packument, no tarball, just what a
// denominator needs.
export const EXPIRY_LOG = 'expired-captures.ndjson'

export interface ExpiredCapture {
  package: string
  version: string
  capturedAt: string
  captureReason?: string
  deletedAt: string
  // Which deleter took it, because they answer different questions: 'expiry' is
  // the retention policy working as designed, 'rotation' is the disk cap biting
  // and a sign the budget needs revisiting.
  deletedBy: 'expiry' | 'rotation'
}

// Written beside the other ndjson logs rather than inside captures/, which is
// the directory being emptied.
export function recordExpiredCaptures(
  capturesDir: string,
  rows: ExpiredCapture[]
): void {
  if (rows.length === 0) return
  try {
    writeFileSync(
      join(dirname(capturesDir), EXPIRY_LOG),
      rows.map(r => JSON.stringify(r)).join('\n') + '\n',
      { flag: 'a' }
    )
  } catch { /* one lost line does not invalidate the series */ }
}

export function readExpiredCaptures(capturesDir: string): ExpiredCapture[] {
  const path = join(dirname(capturesDir), EXPIRY_LOG)
  if (!existsSync(path)) return []

  const rows: ExpiredCapture[] = []
  for (const line of readFileSync(path, 'utf-8').split('\n')) {
    if (!line.trim()) continue
    try { rows.push(JSON.parse(line) as ExpiredCapture) } catch { /* skip */ }
  }
  return rows
}

// What a directory about to be deleted was, read before it goes.
function describeCapture(
  path: string,
  deletedBy: ExpiredCapture['deletedBy'],
  now: number
): ExpiredCapture | null {
  const metaPath = join(path, 'capture-metadata.json')
  if (!existsSync(metaPath)) return null
  try {
    const meta = JSON.parse(readFileSync(metaPath, 'utf-8')) as {
      package?: string; version?: string; capturedAt?: string; captureReason?: string
    }
    if (!meta.package) return null
    return {
      package: meta.package,
      version: meta.version ?? '',
      capturedAt: meta.capturedAt ?? '',
      captureReason: meta.captureReason,
      deletedAt: new Date(now).toISOString(),
      deletedBy,
    }
  } catch {
    return null
  }
}

export interface QuarantineSweep {
  expired: string[]
  kept: number
  promoted: number
  objectsCollected: number
  objectBytesFreed: number
}

export interface ObjectCollection {
  objects: number
  bytes: number
}

// Mark and sweep over the shared store: an object survives if a capture still
// on disk names it, and goes otherwise. This is the only thing that frees the
// bytes behind an expired capture, since deleting the directory leaves the
// tarball under its hash where every other capture can still reach it.
//
// It is also the repair for anything already leaked, because it asks what the
// store holds rather than what this run deleted.
export function collectOrphanObjects(
  capturesDir: string,
  // Defaults to the captures directory and belongs there, for the same reason
  // rotation no longer follows manifest.objectStore: a store reached by any
  // path other than the one being swept belongs to somebody else.
  storeRoot = capturesDir,
  dryRun = false
): ObjectCollection {
  const collection: ObjectCollection = { objects: 0, bytes: 0 }
  if (!existsSync(capturesDir)) return collection

  const referenced = new Set<string>()
  for (const name of readdirSync(capturesDir)) {
    const manifest = readManifest(join(capturesDir, name))
    if (!manifest) continue
    for (const hash of Object.values(manifest.objects ?? {})) referenced.add(hash)
  }

  for (const hash of listObjects(storeRoot)) {
    if (referenced.has(hash)) continue
    collection.objects++
    collection.bytes += dryRun ? objectSize(storeRoot, hash) : deleteObject(storeRoot, hash)
  }

  return collection
}

// Deletes quarantine captures past their retention that nothing confirmed.
// Anything labelled is kept: a promotion is exactly what quarantine exists to
// wait for, and deleting it afterwards would throw away the sample.
export function sweepQuarantine(
  capturesDir: string,
  now = Date.now(),
  dryRun = false
): QuarantineSweep {
  const result: QuarantineSweep = {
    expired: [], kept: 0, promoted: 0, objectsCollected: 0, objectBytesFreed: 0,
  }
  if (!existsSync(capturesDir)) return result

  const expired: ExpiredCapture[] = []

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

    // Read before the delete, appended after: a record written for a directory
    // that then failed to go would claim a loss that did not happen.
    const record = describeCapture(path, 'expiry', now)

    if (!dryRun) {
      try { rmSync(path, { recursive: true, force: true }) } catch { continue }
    }
    if (record) expired.push(record)
    result.expired.push(path)
  }

  if (!dryRun) recordExpiredCaptures(capturesDir, expired)

  // After the directories, never before: an object is only orphaned once the
  // last capture naming it is gone.
  const collected = collectOrphanObjects(capturesDir, capturesDir, dryRun)
  result.objectsCollected = collected.objects
  result.objectBytesFreed = collected.bytes

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
  // Objects collected because the last capture referencing them was deleted, and
  // the bytes that actually left the disk. Reported separately from the capture
  // directories because that is where nearly all of the size is.
  objectsCollected: number
  objectBytesFreed: number
  // True when every deletable capture is gone and the total is still over the
  // cap: what remains is confirmed evidence, which rotation will not touch. A
  // condition to act on, not one to keep deleting through.
  stillOverCap: boolean
}

// Deletes oldest first, and only captures still labelled 'unconfirmed'. Anything
// someone has confirmed or cleared is evidence, and rotation must never be the
// reason it disappears.
//
// A capture is a directory holding a manifest.json, and that check is not
// cosmetic. The shared object store lives at captures/objects/ — it is a
// directory, it has no capture-metadata.json so it read as 'unconfirmed', it has
// no capturedAt so it sorted first, and it holds nearly every byte under
// captures/. The first rotation therefore deleted the entire object store in one
// rmSync: 3,169 tarballs, 9.25GB, including the artifacts behind captures that
// were labelled confirmed_malicious and that rotation had correctly refused to
// touch. The guarantee was real and the bytes left through the shared store.
export function rotateCaptures(
  capturesDir: string,
  maxBytes: number,
  dryRun = false
): RotationResult {
  const empty: RotationResult = {
    before: 0, after: 0, deleted: [], protectedCount: 0,
    objectsCollected: 0, objectBytesFreed: 0, stillOverCap: false,
  }
  if (!existsSync(capturesDir)) return empty

  const candidates: RotationCandidate[] = []
  // Every capture's objects, and how many captures reference each one. A tarball
  // shared by a platform family is freed by the last of them, not the first.
  const objectsOf = new Map<string, string[]>()
  const references = new Map<string, number>()
  let protectedCount = 0
  let total = 0

  for (const name of readdirSync(capturesDir)) {
    const path = join(capturesDir, name)
    try {
      if (!statSync(path).isDirectory()) continue
    } catch { continue }

    const bytes = directorySize(path)
    total += bytes

    // Counted towards the total — the store is exactly what the cap exists to
    // bound — and never a candidate for deletion. It is collected below, object
    // by object, through the captures that reference them.
    const manifest = readManifest(path)
    if (!manifest) continue

    // Deduplicated per capture: a manifest that names the same bytes for two
    // versions holds one object, and counting it twice would leave it referenced
    // by a capture that no longer exists.
    const hashes = [...new Set(Object.values(manifest.objects ?? {}))]
    objectsOf.set(path, hashes)
    for (const hash of hashes) references.set(hash, (references.get(hash) ?? 0) + 1)

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
    return { ...empty, before, after: total, protectedCount }
  }

  candidates.sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))

  // The store under the directory being rotated, and nowhere else. The manifest
  // records objectStore as the path the watcher was given — "captures/captures",
  // "norte-guard-captures/captures" — relative to wherever it happened to be
  // running, so resolving it points rotation at whatever corpus sits under the
  // current shell's cwd. That is the same failure this change exists to stop,
  // reached by a different route.
  const store = capturesDir

  const deleted: RotationCandidate[] = []
  const expired: ExpiredCapture[] = []
  const deletedAt = Date.now()
  let objectsCollected = 0
  let objectBytesFreed = 0

  for (const candidate of candidates) {
    if (total <= maxBytes) break

    const hashes = objectsOf.get(candidate.path) ?? []
    // Which of this capture's objects nothing else holds. Decided before the
    // deletion, so the accounting below is the bytes that will actually go.
    const orphaned = hashes.filter(h => (references.get(h) ?? 0) <= 1)

    // Read before the delete: afterwards there is nothing left to read it from,
    // and the name is the whole point of the record.
    const record = describeCapture(candidate.path, 'rotation', deletedAt)

    // The directory being deleted goes first, and only then the objects it was
    // the last holder of. A failed rmSync must not leave a capture pointing at
    // bytes that are already gone.
    if (!dryRun) {
      try { rmSync(candidate.path, { recursive: true, force: true }) } catch { continue }
    }
    if (record) expired.push(record)

    let freed = 0
    for (const hash of orphaned) {
      freed += dryRun ? objectSize(store, hash) : deleteObject(store, hash)
    }

    for (const hash of hashes) references.set(hash, (references.get(hash) ?? 1) - 1)
    objectsCollected += orphaned.length
    objectBytesFreed += freed
    // Both were counted: `total` is the sum of the directories under
    // capturesDir, and the store is one of them.
    total -= candidate.bytes + freed
    deleted.push(candidate)
  }

  if (!dryRun) recordExpiredCaptures(capturesDir, expired)

  return {
    before,
    after: total,
    deleted,
    protectedCount,
    objectsCollected,
    objectBytesFreed,
    stillOverCap: total > maxBytes,
  }
}

function readManifest(dir: string): NgpackManifest | null {
  const path = join(dir, 'manifest.json')
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as NgpackManifest
  } catch {
    return null
  }
}

