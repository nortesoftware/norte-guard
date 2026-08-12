// A single ranked list of "signals on blocked packages" misleads by layout:
// long_history is a −15 discount, and printing it beside new_install_script
// suggests it helped cause the block. Every report splits by sign first.

export interface SignalRef {
  type: string
  score: number
}

export interface SignalTally {
  type: string
  count: number
  totalScore: number
}

export interface SignalPartition {
  positive: SignalTally[]
  // Discounts. On a blocked package they mean it blocked despite them.
  negative: SignalTally[]
  // Recorded as evidence, deliberately unscored. See entrypoint_changed.
  informational: SignalTally[]
}

// `count` is packages, not occurrences: a signal firing twice inside one package
// is still one package.
export function tallySignals(perPackage: SignalRef[][]): SignalPartition {
  const tallies = new Map<string, SignalTally>()

  for (const signals of perPackage) {
    const seen = new Set<string>()
    for (const s of signals) {
      const t = tallies.get(s.type) ?? { type: s.type, count: 0, totalScore: 0 }
      if (!seen.has(s.type)) {
        t.count++
        seen.add(s.type)
      }
      t.totalScore += s.score
      tallies.set(s.type, t)
    }
  }

  const all = [...tallies.values()]
  const bySize = (a: SignalTally, b: SignalTally) => Math.abs(b.totalScore) - Math.abs(a.totalScore)

  return {
    positive: all.filter(t => t.totalScore > 0).sort(bySize),
    negative: all.filter(t => t.totalScore < 0).sort(bySize),
    informational: all.filter(t => t.totalScore === 0).sort((a, b) => b.count - a.count),
  }
}

// A negative tally reaching a "why this blocked" section is a bug in the report,
// not in the scorer, so it gets named instead of rendered.
export function reportBugs(partition: SignalPartition): string[] {
  const bugs: string[] = []
  for (const t of partition.negative) {
    bugs.push(
      `REPORTING BUG: "${t.type}" totals ${t.totalScore} pts (it is a discount) and was ` +
      `listed as a cause of BLOCK. Shown below as a discount instead.`
    )
  }
  return bugs
}

const DIM = '\x1b[2m'
const RESET = '\x1b[0m'

const packages = (n: number) => `${n} package${n === 1 ? '' : 's'}`

export function renderPartition(partition: SignalPartition, indent = '  '): string[] {
  const lines: string[] = []
  const row = (t: SignalTally) => {
    const sign = t.totalScore > 0 ? '+' : ''
    return `${indent}  ${t.type.padEnd(32)} ${sign}${t.totalScore} pts  (${packages(t.count)})`
  }

  lines.push(`${indent}positive signals (add to the score)`)
  if (partition.positive.length === 0) lines.push(`${indent}  ${DIM}(none)${RESET}`)
  for (const t of partition.positive) lines.push(row(t))

  if (partition.negative.length > 0) {
    lines.push('')
    lines.push(`${indent}discounts (subtract; never a cause of a BLOCK)`)
    for (const t of partition.negative) lines.push(row(t))
  }

  if (partition.informational.length > 0) {
    lines.push('')
    lines.push(`${indent}informational (0 pts, recorded but not scored)`)
    for (const t of partition.informational) {
      lines.push(`${indent}  ${DIM}${t.type.padEnd(32)} ${packages(t.count)}${RESET}`)
    }
  }

  return lines
}
