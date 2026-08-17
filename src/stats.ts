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

export interface DifferenceWithCI {
  a: RateWithCI
  b: RateWithCI
  // a - b. Null when either side has no sample.
  difference: number | null
  low: number | null
  high: number | null
  // Whether the interval excludes zero. The only thing a comparison of two rates
  // is entitled to say on its own.
  separated: boolean
}

// The interval on the DIFFERENCE between two rates, which is the question a
// controlled comparison actually asks and is not answerable by looking at two
// intervals side by side: two overlapping intervals can still have a difference
// that excludes zero, and reading "they overlap, so it is nothing" off a pair of
// error bars is how a real gap gets thrown away.
//
// Newcombe's hybrid score method (method 10 of Newcombe 1998), which composes
// the two Wilson intervals rather than assuming normality. At the rates here —
// one group is expected near 1.0 — the normal approximation puts a bound past
// 100% and the width stops meaning anything.
export function differenceWithCI(
  successesA: number, nA: number,
  successesB: number, nB: number,
  z = 1.96
): DifferenceWithCI {
  const a = rateWithCI(successesA, nA, z)
  const b = rateWithCI(successesB, nB, z)

  if (nA === 0 || nB === 0) {
    return { a, b, difference: null, low: null, high: null, separated: false }
  }

  const pA = successesA / nA, pB = successesB / nB
  const wa = wilsonInterval(successesA, nA, z)
  const wb = wilsonInterval(successesB, nB, z)

  const low = (pA - pB) - Math.sqrt((pA - wa.low) ** 2 + (wb.high - pB) ** 2)
  const high = (pA - pB) + Math.sqrt((wa.high - pA) ** 2 + (pB - wb.low) ** 2)

  return {
    a, b,
    difference: pA - pB,
    low: Math.max(-1, low),
    high: Math.min(1, high),
    separated: low > 0 || high < 0,
  }
}

// Φ⁻¹, so an interval can be widened for the number of comparisons it is one of.
// A table of 40 module rates each at 95% produces two "significant" rows out of
// noise alone, and the module table is where the last finding came from.
//
// Acklam's rational approximation, absolute error below 1.15e-9 over the whole
// range — far finer than anything a rate over 200 packages can resolve.
export function normalQuantile(p: number): number {
  if (p <= 0) return -Infinity
  if (p >= 1) return Infinity

  const a = [-39.69683028665376, 220.9460984245205, -275.9285104469687,
             138.3577518672690, -30.66479806614716, 2.506628277459239]
  const b = [-54.47609879822406, 161.5858368580409, -155.6989798598866,
             66.80131188771972, -13.28068155288572]
  const c = [-0.007784894002430293, -0.3223964580411365, -2.400758277161838,
             -2.549732539343734, 4.374664141464968, 2.938163982698783]
  const d = [0.007784695709041462, 0.3224671290700398, 2.445134137142996,
             3.754408661907416]

  const low = 0.02425, high = 1 - low

  if (p < low) {
    const q = Math.sqrt(-2 * Math.log(p))
    return (((((c[0]! * q + c[1]!) * q + c[2]!) * q + c[3]!) * q + c[4]!) * q + c[5]!) /
           ((((d[0]! * q + d[1]!) * q + d[2]!) * q + d[3]!) * q + 1)
  }
  if (p > high) {
    const q = Math.sqrt(-2 * Math.log(1 - p))
    return -(((((c[0]! * q + c[1]!) * q + c[2]!) * q + c[3]!) * q + c[4]!) * q + c[5]!) /
            ((((d[0]! * q + d[1]!) * q + d[2]!) * q + d[3]!) * q + 1)
  }

  const q = p - 0.5, r = q * q
  return (((((a[0]! * r + a[1]!) * r + a[2]!) * r + a[3]!) * r + a[4]!) * r + a[5]!) * q /
         (((((b[0]! * r + b[1]!) * r + b[2]!) * r + b[3]!) * r + b[4]!) * r + 1)
}

// The z a family of m comparisons needs for the family to hold at alpha.
// Bonferroni: conservative, and the conservative direction is the right one when
// the alternative is quoting whichever row of a long table came out largest.
export function zForFamily(comparisons: number, alpha = 0.05): number {
  const m = Math.max(1, comparisons)
  return normalQuantile(1 - alpha / (2 * m))
}

// Signed, and with the sign spelled out: "+76.0pp" and "-76.0pp" are opposite
// findings and the minus sign is one character.
export function formatDifference(d: DifferenceWithCI): string {
  if (d.difference === null || d.low === null || d.high === null) {
    return 'not calculable, one side is empty'
  }
  const pp = (x: number) => `${x >= 0 ? '+' : ''}${(x * 100).toFixed(1)}pp`
  return `${pp(d.difference)} (95% CI ${pp(d.low)} to ${pp(d.high)}${d.separated ? ', excludes zero' : ', includes zero'})`
}
