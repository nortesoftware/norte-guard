// The explainable output is the product. Norte-guard never says "safe" — it
// says what it analyzed, what it found, and what it could not verify.

import type { InspectResult, ThresholdConfig } from './types.js'

const RED    = '\x1b[31m'
const YELLOW = '\x1b[33m'
const GREEN  = '\x1b[32m'
const CYAN   = '\x1b[36m'
const BOLD   = '\x1b[1m'
const DIM    = '\x1b[2m'
const RESET  = '\x1b[0m'

export function renderInspect(result: InspectResult, config: ThresholdConfig): string {
  const lines: string[] = []

  const verdictColor = result.verdict === 'BLOCK' ? RED
                     : result.verdict === 'WARN'  ? YELLOW
                     : result.verdict === 'INSUFFICIENT_HISTORY' ? CYAN
                     : GREEN

  // Text prefixes rather than emoji: this output ends up in CI logs, in files,
  // and in terminals without a unicode font, and a broken glyph in front of a
  // verdict is worse than no glyph at all.

  lines.push('')
  lines.push(
    `${verdictColor}${BOLD}${result.verdict}${RESET}  ` +
    `${BOLD}${result.package}@${result.version}${RESET}  ` +
    `Score: ${result.totalScore}/${config.blockScore}`
  )
  lines.push('')

  if (result.diff.added.length > 0 || result.diff.newInstallScripts.length > 0) {
    lines.push(`${CYAN}${BOLD}What changed:${RESET}`)
    for (const f of result.diff.added.slice(0, 5)) {
      lines.push(`  ${GREEN}+${RESET} ${f} (NEW)`)
    }
    if (result.diff.added.length > 5) {
      lines.push(`  ${DIM}... and ${result.diff.added.length - 5} more files${RESET}`)
    }
    for (const { file, ratio } of result.diff.grown) {
      lines.push(`  ${YELLOW}~${RESET} ${file} (${ratio.toFixed(1)}x larger)`)
    }
    for (const s of result.diff.newInstallScripts) {
      lines.push(`  ${RED}~${RESET} package.json scripts.${s} ADDED`)
    }
    lines.push('')
  }

  if (result.signals.length > 0) {
    lines.push(`${CYAN}${BOLD}Why:${RESET}`)

    // Sorted by magnitude so the reasons that moved the verdict read first,
    // including the negative ones that pulled the score down.
    const sorted = [...result.signals].sort((a, b) => Math.abs(b.score) - Math.abs(a.score))

    for (const signal of sorted) {
      const scoreStr = signal.score >= 0
        ? `${RED}+${signal.score}${RESET}`
        : `${GREEN}${signal.score}${RESET}`

      const hist = signal.isHistorical ? ` ${DIM}(historical)${RESET}` : ''
      lines.push(`  ${scoreStr}  ${signal.description}${hist}`)
    }
    lines.push('')
  }

  // On a block the user still needs somewhere to go, so name the last version
  // that was compared against.
  if (result.verdict === 'BLOCK' && result.baselineVersion) {
    lines.push(`${GREEN}Previous version compared against: ${result.baselineVersion}${RESET}`)
    lines.push('')
  }

  lines.push(`${DIM}Analysis coverage:${RESET}`)
  lines.push(`  ${DIM}[x] Packument signals (${result.coverage.packumentSignals})${RESET}`)

  if (result.coverage.tarballs) {
    lines.push(`  ${DIM}[x] Tarball downloaded and analysed${RESET}`)
  } else {
    lines.push(`  ${DIM}[ ] Tarball NOT analysed (metadata only)${RESET}`)
  }

  if (result.coverage.entryPointAnalyzed) {
    lines.push(`  ${DIM}[x] Entry point analysed (${result.coverage.staticModuleHops} static modules)${RESET}`)
    if (result.coverage.uncoveredDynamicRequires > 0) {
      lines.push(`  ${DIM}[ ] ${result.coverage.uncoveredDynamicRequires} dynamic require() calls not covered${RESET}`)
    }
  } else {
    lines.push(`  ${DIM}[ ] Entry point NOT analysed (import-time unverified)${RESET}`)
  }

  lines.push('')
  lines.push(`  ${DIM}Coverage: ${result.coverage.coveragePercent}% of the known attack surface${RESET}`)

  // Printed whenever the evidence is not today's registry. A verdict on a purged
  // version is only meaningful together with where it was read and as of when,
  // and reading that off a snapshot silently would be the same mistake as
  // reporting a stale number as fresh.
  if (result.source.type !== 'registry') {
    lines.push(
      `  ${DIM}Source: ${result.source.type} ${result.source.location}` +
      (result.source.capturedAt ? `, captured ${result.source.capturedAt}` : '') +
      `${RESET}`
    )
    lines.push(`  ${DIM}Ages measured as of ${result.evaluatedAsOf}, not now${RESET}`)
  }
  lines.push('')

  if (result.verdict === 'INSUFFICIENT_HISTORY') {
    lines.push(
      `${CYAN}Not enough history to compare against${RESET}: this package has no ` +
      `baseline\n(>=10 versions and >=90 days) to measure a capability delta from.`
    )
    lines.push(
      `${DIM}Does not fail the build: lack of context is not evidence of risk. ` +
      `To treat it\nas a failure, use --strict-new-packages.${RESET}`
    )
    lines.push('')
  }

  // A PASS is the absence of the signals we know how to look for, not proof of
  // safety.
  if (result.verdict === 'PASS') {
    lines.push(
      `${DIM}No anomalies in the signals analysed. This is not a certificate of ` +
      `safety: it is the absence of the signals we know how to look for.${RESET}`
    )
    lines.push('')
  }

  return lines.join('\n')
}

export function renderJSON(result: InspectResult): string {
  return JSON.stringify(result, null, 2)
}

// Extracted from the CLI so it can be asserted: "the gate fires" is only true if
// a BLOCK reaches the shell as a non-zero exit. Exit 2 is reserved for tool
// errors, since a crashed analyser is not a clean package.
//
// INSUFFICIENT_HISTORY exits 0. It was 22.6% of a 500-package sample, and a gate
// that stops one build in five on packages it has no baseline for is a gate that
// gets switched off, at which point its recall is zero whatever the benchmark
// says. Lack of context is not evidence of risk. Teams that want the hard
// behaviour ask for it.
export interface ExitOptions {
  // Treat "no baseline to judge against" as a failure. Off by default.
  strictNewPackages?: boolean
}

export function exitCodeForVerdict(
  verdict: InspectResult['verdict'],
  options: ExitOptions = {}
): 0 | 1 {
  if (verdict === 'BLOCK') return 1
  if (verdict === 'INSUFFICIENT_HISTORY' && options.strictNewPackages) return 1
  return 0
}

// Soft-wrap a paragraph to a column, on word boundaries. The headline block is
// the one place in this CLI where a full sentence has to be readable in a
// terminal rather than scanned as a table, and a sentence that runs off the
// right edge is a sentence that gets skipped.
export function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/).filter(Boolean)
  if (words.length === 0) return []

  const lines: string[] = []
  let line = ''
  for (const word of words) {
    if (line.length === 0) line = word
    else if (line.length + 1 + word.length <= width) line += ` ${word}`
    else { lines.push(line); line = word }
  }
  if (line.length > 0) lines.push(line)
  return lines
}
