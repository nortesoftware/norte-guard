// An approval is a signed artifact, not a line of terminal output. It records
// what was approved, against which genome, with which engine version and
// threshold, when, and by whom — then gets committed to the repo. That is what
// makes the next run able to say what changed since you approved, and what turns
// approve from a nice assistant into team infrastructure.

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import type { InspectResult } from './types.js'

export interface ApprovalRecord {
  ngVersion: 1
  approvedAt: string
  approvedBy: string
  // Recorded because a later engine version can reach a different verdict on the
  // same package; without it an old approval cannot be interpreted.
  guardVersion: string
  threshold: number
  mode: 'gate' | 'audit'
  approvals: PackageApproval[]
  // Covers everything above, so editing the file to widen an approval breaks the
  // record instead of silently passing.
  selfHash: string
}

export interface PackageApproval {
  package: string
  version: string
  score: number
  signals: Array<{ type: string; score: number }>
  genomeVersionsAnalyzed: number
  sourceInfo: string   // 'registry' or 'ngpack:<path>'
  approvedAt: string
  // Set when someone approved a package the gate had blocked. The manifest has
  // to show what was overridden, or an override becomes indistinguishable from
  // a package that never tripped anything.
  overrodeVerdict?: InspectResult['verdict']
  justification?: string
}

export function createApprovalRecord(
  results: InspectResult[],
  options: {
    mode?: 'gate' | 'audit'
    threshold?: number
    approvedBy?: string
  } = {}
): ApprovalRecord {
  const now = new Date().toISOString()
  const approver = options.approvedBy
    ?? process.env['NORTE_GUARD_APPROVER']
    ?? process.env['GIT_AUTHOR_EMAIL']
    ?? 'unknown'

  // A bulk pass over a lockfile drops BLOCKs: the file is the set of things this
  // team accepted, and nobody accepts a hundred packages at once without looking.
  // An explicit, named approval is the opposite case and goes through
  // createOverrideApproval below.
  const approvals: PackageApproval[] = results
    .filter(r => r.verdict !== 'BLOCK')
    .map(r => ({
      package: r.package,
      version: r.version,
      score: r.totalScore,
      signals: r.signals.map(s => ({ type: s.type, score: s.score })),
      genomeVersionsAnalyzed: 0,
      sourceInfo: 'registry',
      approvedAt: now,
    }))

  const record: Omit<ApprovalRecord, 'selfHash'> = {
    ngVersion: 1,
    approvedAt: now,
    approvedBy: approver,
    guardVersion: '0.1.0',
    threshold: options.threshold ?? 70,
    mode: options.mode ?? 'gate',
    approvals,
  }

  const selfHash = sha256(JSON.stringify(record))

  return { ...record, selfHash }
}

// The escape hatch. A gate that blocks with no way to say "I looked at this and
// I want it" is a gate that gets switched off entirely, so the override exists —
// but it is per package, it is named, and it records what it overrode.
//
// This is what makes blocking the fabricated-profile class defensible at all:
// somebody typed that dependency into a package.json, and one line gets them
// past it while leaving the decision in the repository.
export function createOverrideApproval(
  result: InspectResult,
  options: {
    justification: string
    existing?: ApprovalRecord
    mode?: 'gate' | 'audit'
    threshold?: number
    approvedBy?: string
  }
): ApprovalRecord {
  const now = new Date().toISOString()
  const approver = options.approvedBy
    ?? process.env['NORTE_GUARD_APPROVER']
    ?? process.env['GIT_AUTHOR_EMAIL']
    ?? 'unknown'

  const entry: PackageApproval = {
    package: result.package,
    version: result.version,
    score: result.totalScore,
    signals: result.signals.map(s => ({ type: s.type, score: s.score })),
    genomeVersionsAnalyzed: 0,
    sourceInfo: 'registry',
    approvedAt: now,
    // Recorded whatever the verdict was, including PASS: the point of the field
    // is that a reader can tell an override from an ordinary approval.
    overrodeVerdict: result.verdict,
    justification: options.justification,
  }

  const kept = (options.existing?.approvals ?? [])
    .filter(a => !(a.package === entry.package && a.version === entry.version))

  const record: Omit<ApprovalRecord, 'selfHash'> = {
    ngVersion: 1,
    approvedAt: now,
    approvedBy: approver,
    guardVersion: '0.1.0',
    threshold: options.threshold ?? 70,
    mode: options.mode ?? 'gate',
    approvals: [...kept, entry],
  }

  return { ...record, selfHash: sha256(JSON.stringify(record)) }
}

export function writeApprovalRecord(record: ApprovalRecord, path: string): void {
  writeFileSync(path, JSON.stringify(record, null, 2) + '\n')
  console.error(`Aprobaciones guardadas en ${path}`)
}

export function readApprovalRecord(path: string): ApprovalRecord {
  if (!existsSync(path)) {
    throw new Error(`${path} not found`)
  }

  const record = JSON.parse(readFileSync(path, 'utf-8')) as ApprovalRecord

  // Recomputed over the record minus its own hash, matching how it was created.
  const { selfHash, ...rest } = record
  const expectedHash = sha256(JSON.stringify(rest))
  if (expectedHash !== selfHash) {
    throw new Error(`${path} was modified: invalid hash. Possible tampering.`)
  }

  return record
}

export function diffApprovalRecords(
  old: ApprovalRecord,
  current: ApprovalRecord
): ApprovalDiff {
  const oldMap = new Map(old.approvals.map(a => [`${a.package}@${a.version}`, a]))
  const curMap = new Map(current.approvals.map(a => [`${a.package}@${a.version}`, a]))

  const added: PackageApproval[] = []
  const removed: PackageApproval[] = []
  const scoreChanged: Array<{ approval: PackageApproval; oldScore: number; newScore: number }> = []
  const unchanged: PackageApproval[] = []

  for (const [key, cur] of curMap) {
    const prev = oldMap.get(key)
    if (!prev) {
      added.push(cur)
    } else if (prev.score !== cur.score) {
      // Same package and version scoring differently means the genome moved
      // underneath it — the case this whole format exists to surface.
      scoreChanged.push({ approval: cur, oldScore: prev.score, newScore: cur.score })
    } else {
      unchanged.push(cur)
    }
  }

  for (const [key, prev] of oldMap) {
    if (!curMap.has(key)) removed.push(prev)
  }

  return { added, removed, scoreChanged, unchanged }
}

export interface ApprovalDiff {
  added: PackageApproval[]
  removed: PackageApproval[]
  scoreChanged: Array<{ approval: PackageApproval; oldScore: number; newScore: number }>
  unchanged: PackageApproval[]
}

export function renderApprovalDiff(diff: ApprovalDiff): string {
  const RED    = '\x1b[31m'
  const GREEN  = '\x1b[32m'
  const YELLOW = '\x1b[33m'
  const BOLD   = '\x1b[1m'
  const DIM    = '\x1b[2m'
  const RESET  = '\x1b[0m'

  const lines: string[] = ['']

  if (diff.added.length === 0 && diff.removed.length === 0 && diff.scoreChanged.length === 0) {
    lines.push(`${GREEN}No changes since the last approval.${RESET}`)
    lines.push('')
    return lines.join('\n')
  }

  lines.push(`${BOLD}Changes since the last approval:${RESET}`)
  lines.push('')

  if (diff.added.length > 0) {
    lines.push(`${GREEN}${BOLD}Nuevos (${diff.added.length}):${RESET}`)
    for (const a of diff.added) {
      lines.push(`  ${GREEN}+${RESET} ${a.package}@${a.version} (score: ${a.score})`)
    }
    lines.push('')
  }

  if (diff.removed.length > 0) {
    lines.push(`${RED}${BOLD}Removidos (${diff.removed.length}):${RESET}`)
    for (const r of diff.removed) {
      lines.push(`  ${RED}-${RESET} ${r.package}@${r.version}`)
    }
    lines.push('')
  }

  if (diff.scoreChanged.length > 0) {
    lines.push(`${YELLOW}${BOLD}Score changed (${diff.scoreChanged.length}):${RESET}`)
    for (const { approval, oldScore, newScore } of diff.scoreChanged) {
      const dir = newScore > oldScore ? `${RED}up` : `${GREEN}down`
      lines.push(`  ${dir}${RESET} ${approval.package}@${approval.version}: ${oldScore} to ${newScore}`)
    }
    lines.push('')
  }

  lines.push(`${DIM}${diff.unchanged.length} paquetes sin cambios.${RESET}`)
  lines.push('')

  return lines.join('\n')
}

function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}
