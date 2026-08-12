// npm 12 disabled install scripts by default on 8 July 2026, which handed every
// JS team the same new chore: decide which packages to re-approve. This command
// answers it from the genome instead of from a maintained allowlist.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fetchPackument } from './packument.js'
import { buildGenome, extractCapabilities } from './genome.js'

interface LockfilePackage {
  name: string
  version: string
  hasInstallScript?: boolean
}

export async function parseLockfile(cwd: string): Promise<LockfilePackage[]> {
  const lockPath = resolve(cwd, 'package-lock.json')

  let lock: Record<string, unknown>
  try {
    lock = JSON.parse(readFileSync(lockPath, 'utf-8'))
  } catch {
    throw new Error(`No package-lock.json found in ${cwd}`)
  }

  const packages: LockfilePackage[] = []
  const pkgs = (lock.packages ?? {}) as Record<string, Record<string, unknown>>

  for (const [path, meta] of Object.entries(pkgs)) {
    if (!path || path === '') continue   // the empty key is the project itself
    if (!meta.hasInstallScript) continue

    const name = path.replace(/^node_modules\//, '')
    const version = (meta.version as string) ?? ''

    packages.push({ name, version, hasInstallScript: true })
  }

  return packages
}

interface ApproveResult {
  package: string
  version: string
  recommendation: 'APPROVE' | 'REVIEW' | 'BLOCK'
  reason: string
  isHistorical: boolean
  historyVersions: number
}

export async function approvePackages(packages: LockfilePackage[]): Promise<ApproveResult[]> {
  const results: ApproveResult[] = []

  // Native-build packages whose install scripts are their entire reason to
  // exist. Short-circuiting them avoids a network round trip per lockfile entry
  // on the cases that would always come back APPROVE.
  const KNOWN_NATIVE = new Set([
    'esbuild', 'sharp', 'better-sqlite3', 'sqlite3', 'canvas',
    'node-gyp', 'fsevents', '@swc/core', 'lightningcss', 'rollup',
    'optionator', 'bcrypt', 'argon2', 'node-sass',
  ])

  for (const pkg of packages) {
    try {
      let recommendation: ApproveResult['recommendation']
      let reason: string
      let isHistorical = false
      let historyVersions = 0

      if (KNOWN_NATIVE.has(pkg.name)) {
        recommendation = 'APPROVE'
        reason = 'Known, legitimate native-build package'
        isHistorical = true
        historyVersions = 999   // sentinel: allowlisted, never measured
      } else {
        const genome = await buildGenome(pkg.name)
        historyVersions = genome.versionsAnalyzed

        const hasHistoricalScript = genome.stableCapabilities.includes('install_script')

        // A long history of the same script is the evidence that it belongs.
        // A short history proves nothing either way, so it goes to a human
        // rather than being waved through.
        if (hasHistoricalScript && historyVersions > 10) {
          recommendation = 'APPROVE'
          reason = `Has had an install script across ${historyVersions} versions: expected behaviour`
          isHistorical = true
        } else if (hasHistoricalScript && historyVersions <= 10) {
          recommendation = 'REVIEW'
          reason = `Short history (${historyVersions} versions) with an install script: check by hand`
          isHistorical = false
        } else {
          recommendation = 'BLOCK'
          reason = `Install script that was NOT in previous versions: critical anomaly`
          isHistorical = false
        }
      }

      results.push({
        package: pkg.name,
        version: pkg.version,
        recommendation,
        reason,
        isHistorical,
        historyVersions,
      })
    } catch {
      // A missing genome is not evidence of safety, so an unreachable package
      // degrades to REVIEW instead of APPROVE.
      results.push({
        package: pkg.name,
        version: pkg.version,
        recommendation: 'REVIEW',
        reason: 'Could not build the genome: review by hand',
        isHistorical: false,
        historyVersions: 0,
      })
    }
  }

  return results
}

export function renderApprove(results: ApproveResult[]): string {
  const lines: string[] = []

  const GREEN  = '\x1b[32m'
  const YELLOW = '\x1b[33m'
  const RED    = '\x1b[31m'
  const BOLD   = '\x1b[1m'
  const DIM    = '\x1b[2m'
  const RESET  = '\x1b[0m'

  const approved = results.filter(r => r.recommendation === 'APPROVE')
  const review   = results.filter(r => r.recommendation === 'REVIEW')
  const blocked  = results.filter(r => r.recommendation === 'BLOCK')

  lines.push('')
  lines.push(`${BOLD}norte-guard approve${RESET}  ${results.length} packages with install scripts`)
  lines.push('')

  if (approved.length > 0) {
    lines.push(`${GREEN}${BOLD}APPROVE (${approved.length})${RESET}`)
    for (const r of approved) {
      lines.push(`  ${GREEN}+${RESET} ${r.package}@${r.version}`)
      lines.push(`    ${DIM}${r.reason}${RESET}`)
    }
    lines.push('')
  }

  if (review.length > 0) {
    lines.push(`${YELLOW}${BOLD}REVIEW (${review.length})${RESET}`)
    for (const r of review) {
      lines.push(`  ${YELLOW}?${RESET} ${r.package}@${r.version}`)
      lines.push(`    ${DIM}${r.reason}${RESET}`)
    }
    lines.push('')
  }

  if (blocked.length > 0) {
    lines.push(`${RED}${BOLD}BLOCK (${blocked.length})${RESET}`)
    for (const r of blocked) {
      lines.push(`  ${RED}-${RESET} ${r.package}@${r.version}`)
      lines.push(`    ${r.reason}`)
    }
    lines.push('')
  }

  lines.push(`${DIM}Add the approved packages to package.json -> allowScripts${RESET}`)
  lines.push('')

  return lines.join('\n')
}
