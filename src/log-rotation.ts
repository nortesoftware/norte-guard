// The append-only logs are raw JSON and grow without a ceiling: 6MB of
// changes-log in the first day, and nothing to stop it. They also compress about
// tenfold, being one repeated shape per line.
//
// So: one file per UTC day, and every closed day gzipped. The current day stays
// raw because it is still being appended to and readers tail it. Nothing is
// deleted here — the enumeration is the cheapest and most valuable thing on
// disk, and losing it is what the whole cursor design exists to avoid.
//
// The tarballs are not touched. They arrive gzipped from the registry, and
// recompressing them gains nothing while breaking the byte-for-byte match
// against dist.integrity.

import { existsSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

export const ROTATABLE_LOGS = [
  'changes-log.ndjson',
  'takedown-log.ndjson',
  'deletions.ndjson',
  'ttr-log.ndjson',
]

export interface RotationOutcome {
  rotated: Array<{ from: string; to: string; bytes: number; compressed: number }>
  alreadyRotated: number
}

function dayOf(path: string): string | null {
  try {
    return new Date(statSync(path).mtime).toISOString().slice(0, 10)
  } catch {
    return null
  }
}

// Called at startup. A log whose last write was on an earlier day is closed, so
// it can be moved aside and compressed without racing an appender.
export function rotateLogs(
  dir: string,
  today = new Date().toISOString().slice(0, 10),
  logs = ROTATABLE_LOGS
): RotationOutcome {
  const outcome: RotationOutcome = { rotated: [], alreadyRotated: 0 }

  for (const name of logs) {
    const path = join(dir, name)
    if (!existsSync(path)) continue

    const day = dayOf(path)
    if (!day || day === today) continue

    const base = name.replace(/\.ndjson$/, '')
    const target = join(dir, `${base}-${day}.ndjson.gz`)

    if (existsSync(target)) {
      // A previous run already archived this day. Appending the current file to
      // it would duplicate lines, so it is left alone and reported.
      outcome.alreadyRotated++
      continue
    }

    try {
      const raw = readFileSync(path)
      const compressed = gzipSync(raw)
      writeFileSync(target, compressed)
      unlinkSync(path)
      outcome.rotated.push({ from: name, to: target, bytes: raw.length, compressed: compressed.length })
    } catch {
      // A log that cannot be rotated keeps growing, which is better than a
      // watcher that will not start.
    }
  }

  return outcome
}

export interface LogFootprint {
  raw: number
  compressed: number
  files: number
}

export function logFootprint(dir: string): LogFootprint {
  const footprint: LogFootprint = { raw: 0, compressed: 0, files: 0 }
  if (!existsSync(dir)) return footprint

  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.ndjson') && !name.endsWith('.ndjson.gz')) continue
    try {
      const size = statSync(join(dir, name)).size
      footprint.files++
      if (name.endsWith('.gz')) footprint.compressed += size
      else footprint.raw += size
    } catch { /* skip */ }
  }

  return footprint
}
