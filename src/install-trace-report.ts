// Aggregates an install-trace run into the compatibility matrix.
//
//   node dist/install-trace-report.js install-trace-results/<run>.ndjson
//
// Two rules carried over from fp-bench, for the same reasons:
//   - every rate travels with its Wilson interval, because a bare percentage
//     over n=20 invites a precision the sample cannot support;
//   - purposive strata are never pooled into the headline denominator. They were
//     chosen because they are unrepresentative, so averaging them in would make
//     the headline number mean nothing.

import { readFileSync } from 'node:fs';
import { formatRateWithCI, rateWithCI, type RateWithCI } from './stats.js';
import type { CellResult } from './install-trace-run.js';
import type { HomeAccessSummary } from './install-trace.js';

export interface PolicyRate {
  policy: string;
  stratum: string;
  packageManager: string;
  n: number;
  passed: number;
  failed: number;
  breakageRate: RateWithCI;
  /** Exit codes seen among failures, with counts — a policy that fails 203
   *  (exec) everywhere is broken differently from one that fails 1 (npm said no). */
  failureModes: Record<string, number>;
}

export interface PrefixRollup {
  prefix: string;
  /** Fixtures whose trace touched this prefix at all. */
  fixtures: number;
  /** Fixtures where a content-bearing open (read or write) SUCCEEDED here. */
  contentFixtures: number;
  reads: number;
  writes: number;
  probes: number;
  mutations: number;
}

export function loadRun(path: string): CellResult[] {
  const out: CellResult[] = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line) as CellResult); } catch { /* truncated tail */ }
  }
  return out;
}

/** Fixtures that fail with no confinement at all fail under every policy too.
 *  Counting them as breakage would credit the policy with a failure it did not
 *  cause — `@oxc-parser/binding-linux-x64-musl` is EBADPLATFORM on a glibc box
 *  whatever you do. The attributable rate conditions on the baseline succeeding. */
export function baselineFailures(rows: CellResult[]): Set<string> {
  const bad = new Set<string>();
  for (const r of rows) {
    if (r.arm === 'policy' && r.policy === 'p0-unconfined' && !r.ok) {
      bad.add(`${r.packageManager}::${r.fixture}`);
    }
  }
  return bad;
}

export function policyRates(rows: CellResult[]): PolicyRate[] {
  const groups = new Map<string, CellResult[]>();
  for (const r of rows) {
    if (r.arm !== 'policy' || !r.policy) continue;
    const key = `${r.packageManager}::${r.policy}::${r.stratum}`;
    const g = groups.get(key) ?? [];
    g.push(r);
    groups.set(key, g);
  }
  const out: PolicyRate[] = [];
  for (const [key, g] of groups) {
    const [packageManager, policy, stratum] = key.split('::');
    const failed = g.filter((r) => !r.ok);
    const modes: Record<string, number> = {};
    for (const f of failed) {
      const k = f.signal ? `signal:${f.signal}` : `exit:${f.exitCode}`;
      modes[k] = (modes[k] ?? 0) + 1;
    }
    out.push({
      policy, stratum, packageManager,
      n: g.length,
      passed: g.length - failed.length,
      failed: failed.length,
      breakageRate: rateWithCI(failed.length, g.length),
      failureModes: modes,
    });
  }
  return out.sort((a, b) =>
    a.stratum.localeCompare(b.stratum) ||
    a.policy.localeCompare(b.policy) ||
    a.packageManager.localeCompare(b.packageManager));
}

export function prefixRollup(rows: CellResult[], stratum?: string, pm?: string): PrefixRollup[] {
  const acc = new Map<string, PrefixRollup>();
  const traces = rows.filter(
    (r) => r.arm === 'trace' && r.homeAccess &&
      (!stratum || r.stratum === stratum) && (!pm || r.packageManager === pm),
  );
  for (const t of traces) {
    for (const h of t.homeAccess as HomeAccessSummary[]) {
      let e = acc.get(h.prefix);
      if (!e) {
        e = { prefix: h.prefix, fixtures: 0, contentFixtures: 0, reads: 0, writes: 0, probes: 0, mutations: 0 };
        acc.set(h.prefix, e);
      }
      e.fixtures++;
      if (h.contentAccessed) e.contentFixtures++;
      e.reads += h.reads;
      e.writes += h.writes;
      e.probes += h.probes;
      e.mutations += h.mutations;
    }
  }
  return [...acc.values()].sort((a, b) => b.fixtures - a.fixtures || b.reads - a.reads);
}

function main(): void {
  const path = process.argv[2];
  if (!path) { console.error('usage: install-trace-report <run.ndjson>'); process.exit(2); }
  const all = loadRun(path);
  const excluded = baselineFailures(all);
  const rows = all.filter((r) => !excluded.has(`${r.packageManager}::${r.fixture}`));
  const traces = rows.filter((r) => r.arm === 'trace');
  const strata = [...new Set(rows.map((r) => r.stratum))];
  if (excluded.size > 0) {
    console.log(`Excluded from every denominator (fail unconfined, so no policy caused it): ${[...excluded].join(', ')}\n`);
  }

  console.log('# Install-time $HOME access — compatibility matrix\n');
  console.log(`cells: ${rows.length}   fixtures traced: ${traces.length}   strata: ${strata.join(', ')}\n`);

  console.log('## Breakage rate by policy\n');
  console.log('Headline stratum is `normal-random` only. Purposive strata are listed');
  console.log('separately and are NOT pooled — they were selected for being hard cases.\n');
  const rates = policyRates(rows);
  for (const st of strata) {
    const inStratum = rates.filter((r) => r.stratum === st);
    if (inStratum.length === 0) continue;
    console.log(`### ${st}\n`);
    console.log('| manager | policy | n | broke | rate (95% Wilson) | failure modes |');
    console.log('|---|---|---|---|---|---|');
    for (const r of inStratum) {
      const modes = Object.entries(r.failureModes).map(([k, v]) => `${k}×${v}`).join(', ') || '—';
      console.log(`| ${r.packageManager} | \`${r.policy}\` | ${r.n} | ${r.failed} | ${formatRateWithCI(r.failed, r.n)} | ${modes} |`);
    }
    console.log('');
  }

  console.log('## $HOME prefixes touched, by manager and stratum\n');
  const managers = [...new Set(rows.map((r) => r.packageManager))].sort();
  for (const pm of managers) for (const st of strata) {
    const roll = prefixRollup(rows, st, pm);
    if (roll.length === 0) continue;
    const nTraces = traces.filter((t) => t.stratum === st && t.packageManager === pm).length;
    console.log(`### ${pm} — ${st}  (n=${nTraces} traced)\n`);
    console.log('| prefix | fixtures touching | content read/written | reads | writes | probes | mutations |');
    console.log('|---|---|---|---|---|---|---|');
    for (const p of roll) {
      console.log(`| \`${p.prefix}\` | ${p.fixtures}/${nTraces} | ${p.contentFixtures}/${nTraces} | ${p.reads} | ${p.writes} | ${p.probes} | ${p.mutations} |`);
    }
    console.log('');
  }
}

if (process.argv[1]?.endsWith('install-trace-report.js')) main();
