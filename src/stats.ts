// Wilson intervals, not the normal approximation. At the rates this project
// measures (2 blocks in 500 packages) the normal approximation puts the lower
// bound below zero.

export interface ConfidenceInterval {
  low: number
  high: number
}

export function wilsonInterval(successes: number, n: number, z = 1.96): ConfidenceInterval {
  if (n === 0) return { low: 0, high: 0 }
  const p = successes / n, z2 = z * z
  const denom = 1 + z2 / n
  const center = (p + z2 / (2 * n)) / denom
  const margin = (z / denom) *
    Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
  return {
    low: Math.max(0, center - margin),
    high: Math.min(1, center + margin),
  }
}

export function pct(x: number, digits = 2): string {
  return `${(x * 100).toFixed(digits)}%`
}

// The interval always travels with the rate. A bare "0.40%" over 500 packages
// invites a precision the sample cannot support.
export function formatRateWithCI(successes: number, n: number, z = 1.96): string {
  if (n === 0) return 'not calculable, n=0'
  const { low, high } = wilsonInterval(successes, n, z)
  return `${pct(successes / n)} (95% Wilson CI: ${pct(low)}-${pct(high)}, n=${n})`
}

export interface ScoreDistribution {
  n: number
  min: number
  p50: number
  p90: number
  p95: number
  p99: number
  max: number
  // A percentile only names a cut point if the distribution has enough grain for
  // one. With three distinct values it does not, and callers need to be able to
  // check that before quoting a p99.
  distinct: number
  histogram: Array<{ score: number; count: number; atOrAbove: number }>
}

// Nearest-rank rather than interpolated: scores are integers, and an
// interpolated p99 of 32.4 is a value no package can have.
export function percentile(sortedAsc: number[], p: number): number {
  if (sortedAsc.length === 0) return 0
  const rank = Math.ceil((p / 100) * sortedAsc.length)
  return sortedAsc[Math.min(sortedAsc.length - 1, Math.max(0, rank - 1))]!
}

export function scoreDistribution(values: number[]): ScoreDistribution | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)

  const counts = new Map<number, number>()
  for (const v of sorted) counts.set(v, (counts.get(v) ?? 0) + 1)

  let remaining = sorted.length
  const histogram = [...counts.entries()]
    .sort(([a], [b]) => a - b)
    .map(([score, count]) => {
      const atOrAbove = remaining
      remaining -= count
      return { score, count, atOrAbove }
    })

  return {
    n: sorted.length,
    min: sorted[0]!,
    p50: percentile(sorted, 50),
    p90: percentile(sorted, 90),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    max: sorted[sorted.length - 1]!,
    distinct: counts.size,
    histogram,
  }
}

export interface RateWithCI {
  successes: number
  n: number
  rate: number | null
  low: number | null
  high: number | null
}

// Null rather than zero at n=0: a rate over an empty sample is undefined, and
// callers have to handle the difference explicitly.
export function rateWithCI(successes: number, n: number, z = 1.96): RateWithCI {
  if (n === 0) return { successes, n, rate: null, low: null, high: null }
  const { low, high } = wilsonInterval(successes, n, z)
  return { successes, n, rate: successes / n, low, high }
}
