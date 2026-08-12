// Content-addressed storage for captured tarballs.
//
// The same tarball arrives more than once: a package republished under a new
// version number with identical bytes, a platform family whose members share a
// shim, a capture repeated after a restart. Under one directory per capture each
// copy costs full size. Under a hash the second one costs nothing.
//
// The name is the hash, so integrity verification is not a separate step: a file
// that does not hash to its own name is corrupt, and there is nothing else to
// compare it against.
//
// Tarballs are stored exactly as the registry served them. They are already
// gzip; recompressing gains nothing and loses the ability to check the bytes
// against dist.integrity.

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

export const OBJECTS_DIR = 'objects'
export const INDEX_FILE = 'index.ndjson'

export interface StoredObject {
  sha256: string
  bytes: number
  // False when the object was already there, which is the saving being measured.
  written: boolean
}

export interface IndexEntry {
  sha256: string
  package: string
  version: string
  bytes: number
  storedAt: string
  deduped: boolean
}

export function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex')
}

// Sharded by the first two hex characters. A flat directory of hundreds of
// thousands of files is slow to list on every filesystem worth naming.
export function objectPath(root: string, hash: string): string {
  return join(root, OBJECTS_DIR, hash.slice(0, 2), hash)
}

export function hasObject(root: string, hash: string): boolean {
  return existsSync(objectPath(root, hash))
}

export function putObject(root: string, buf: Buffer): StoredObject {
  const hash = sha256(buf)
  const path = objectPath(root, hash)

  if (existsSync(path)) {
    return { sha256: hash, bytes: buf.length, written: false }
  }

  mkdirSync(join(root, OBJECTS_DIR, hash.slice(0, 2)), { recursive: true })
  writeFileSync(path, buf)
  return { sha256: hash, bytes: buf.length, written: true }
}

// Verifies on the way out. A store whose integrity is only checked at write time
// cannot tell the difference between a disk fault and a tampered corpus.
export function getObject(root: string, hash: string): Buffer {
  const path = objectPath(root, hash)
  if (!existsSync(path)) throw new Error(`object missing from the store: ${hash}`)

  const buf = readFileSync(path)
  const actual = sha256(buf)
  if (actual !== hash) {
    throw new Error(`corrupt object: ${hash} holds bytes that hash to ${actual}`)
  }
  return buf
}

export function appendIndex(root: string, entry: IndexEntry): void {
  try {
    mkdirSync(root, { recursive: true })
    writeFileSync(join(root, INDEX_FILE), JSON.stringify(entry) + '\n', { flag: 'a' })
  } catch { /* the object is the record; the index is a convenience over it */ }
}

export interface StoreStats {
  objects: number
  bytes: number
  references: number
  dedupedReferences: number
  bytesSaved: number
}

export function storeStats(root: string): StoreStats {
  const stats: StoreStats = { objects: 0, bytes: 0, references: 0, dedupedReferences: 0, bytesSaved: 0 }
  const indexPath = join(root, INDEX_FILE)
  if (!existsSync(indexPath)) return stats

  const seen = new Set<string>()
  for (const line of readFileSync(indexPath, 'utf-8').split('\n')) {
    if (!line) continue
    try {
      const entry = JSON.parse(line) as IndexEntry
      stats.references++
      if (seen.has(entry.sha256)) {
        stats.dedupedReferences++
        stats.bytesSaved += entry.bytes
      } else {
        seen.add(entry.sha256)
        stats.objects++
        stats.bytes += entry.bytes
      }
    } catch { /* skip */ }
  }

  return stats
}

export function objectSize(root: string, hash: string): number {
  try { return statSync(objectPath(root, hash)).size } catch { return 0 }
}
