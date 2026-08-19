// One archive, four answers. The bridge between the tarball reader and A3.
//
// It exists so that the capability question and the analyzability question are
// asked of ONE read of the bytes. Reading a 26MB tarball twice to answer two
// questions about the same package is the difference between a corpus pass that
// finishes and one that does not.

import { analyzePackage, type PackageReachability } from './reachability.js'
import { classifyFile } from './file-kind.js'
import { capabilitiesOf, type PackageCapabilities } from './capabilities.js'
import type { TarReadResult } from './tarball.js'
import type { CaptureAnalyzability, NonCoverageReason } from './analyzability.js'

// The same bounds reachableModulesOf uses, and for the same measured reason:
// sources are not the cost, the syntax trees built from them are. Duplicated
// rather than imported because analyzability-run.ts imports the corpus loader
// and this module must stay loadable without one.
export const MAX_SOURCE_FILES = 600
export const MAX_SOURCE_BYTES = 16 * 1024 * 1024

// A file that cannot be read is a file that reaches whatever it likes. These are
// the four kinds analyzability already separates, and each one is a package
// whose capability answers cannot be negative.
export const OPAQUE_REASONS: NonCoverageReason[] = ['native-binary', 'wasm', 'bytecode', 'minified']

export interface CapabilityScan {
  capabilities: PackageCapabilities
  reachability: PackageReachability | null
  // Why the analysis could not be run, when it could not. Null when it ran.
  refusal: string | null
  parseableFiles: number
  sourceBytes: number
  opaqueExecutable: boolean
  opaqueKinds: NonCoverageReason[]
}

export interface ScanOptions {
  // The file-level analysis of the same archive, when the caller already has
  // one. Without it the opacity blinder cannot fire and every answer would be
  // one degree more confident than the evidence allows, so a caller that omits
  // it is told so in the refusal rather than quietly given a better number.
  analysis?: CaptureAnalyzability
  maxSourceFiles?: number
  maxSourceBytes?: number
}

export function scanArchive(archive: TarReadResult, options: ScanOptions = {}): CapabilityScan {
  const maxFiles = options.maxSourceFiles ?? MAX_SOURCE_FILES
  const maxBytes = options.maxSourceBytes ?? MAX_SOURCE_BYTES

  const opaqueKinds = options.analysis
    ? OPAQUE_REASONS.filter(reason => Boolean(options.analysis!.byReason[reason]))
    : []
  const opaqueExecutable = opaqueKinds.length > 0

  const blank = (refusal: string): CapabilityScan => ({
    capabilities: capabilitiesOf({
      reachability: EMPTY_REACHABILITY,
      unreadableArchive: refusal.startsWith('archive'),
      analysisRefused: !refusal.startsWith('archive'),
      opaqueExecutable,
    }),
    reachability: null,
    refusal,
    parseableFiles: 0,
    sourceBytes: 0,
    opaqueExecutable,
    opaqueKinds,
  })

  if (archive.entries.length === 0) {
    return blank(`archive holds no members: ${archive.truncationReason ?? 'unknown'}`)
  }

  const files = new Map<string, string>()
  let packageJson: unknown = {}
  let root = 'package'
  let sourceBytes = 0
  let parseableFiles = 0

  for (const entry of archive.entries) {
    if (classifyFile(entry.name, entry.data.subarray(0, 256)).kind === 'javascript') {
      parseableFiles++
      sourceBytes += entry.size
      if (files.size >= maxFiles || sourceBytes > maxBytes) {
        return blank(
          `too large to follow: ${parseableFiles} parseable files and ${sourceBytes} bytes of ` +
          `JavaScript, past the bound of ${maxFiles} files / ${maxBytes} bytes`
        )
      }
      files.set(entry.name, entry.data.toString('utf-8'))
    }
    if (/^[^/]+\/package\.json$/.test(entry.name)) {
      root = entry.name.split('/')[0] ?? 'package'
      try { packageJson = JSON.parse(entry.data.toString('utf-8')) } catch { /* leave it */ }
    }
  }

  if (files.size === 0) {
    // Not the same as an unreadable archive, and the difference decides the
    // answer: a package whose every executable byte is a native binary reaches
    // whatever it likes, and one that ships no executable at all reaches
    // nothing. The opacity flag is what tells them apart, and it comes from the
    // file-level analysis rather than from here.
    return blank('no JavaScript in the archive')
  }

  const reachability = analyzePackage({ files, packageJson, root })

  return {
    capabilities: capabilitiesOf({ reachability, sources: files, opaqueExecutable }),
    reachability,
    refusal: null,
    parseableFiles,
    sourceBytes,
    opaqueExecutable,
    opaqueKinds,
  }
}

const EMPTY_REACHABILITY: PackageReachability = {
  entryPoints: [],
  missingEntryPoints: [],
  filesAnalysed: [],
  reachable: [],
  unresolvedLocal: [],
  lost: [],
  ambient: [],
  callArguments: [],
}
