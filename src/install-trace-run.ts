// Runner for the install-time $HOME-access measurement.
//
// Two arms per cell:
//   TRACE  — an unconfined install under strace, to learn WHICH $HOME paths are
//            touched, for read or for write.
//   POLICY — the same install under each candidate confinement policy, to learn
//            WHETHER it still completes.
//
// The trace arm answers "what does it need"; the policy arm answers "what breaks".
// Neither answers the other, which is why both exist. The published matrix is the
// policy arm; the trace arm is what makes a failure explicable rather than just a
// non-zero exit code.
//
// Results are written incrementally as NDJSON so a run that dies halfway is still
// worth something, and so a long run can be resumed without repeating cells.

import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, appendFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseTraceLine, summariseHomeAccess, type TraceEvent, type HomeAccessSummary } from './install-trace.js';

export interface Fixture {
  id: string;
  /** `random` cells carry the headline rate; `purposive` cells are named hard
   *  cases and are reported separately, never pooled into the same denominator. */
  stratum: 'normal-random' | 'native-purposive' | 'monorepo-purposive' | 'registry-purposive' | 'gyp-purposive';
  description: string;
  /** What this fixture is expected to reach for outside the project dir. The
   *  trace either confirms it or does not; both are results. */
  hypothesis: string;
  packageJson: Record<string, unknown>;
  /** Extra files to write into the project dir, e.g. a project-level .npmrc. */
  files?: Record<string, string>;
  /** Fixture-specific environment, e.g. forcing a source build. */
  env?: Record<string, string>;
}

export interface Policy {
  id: string;
  description: string;
  /** systemd unit properties. Only properties verified to actually enforce in a
   *  --user unit belong here; see docs/install-trace.md for the control results. */
  props: string[];
  /** Set when the policy is expected to fail for a reason that is not about npm —
   *  e.g. hiding the $HOME-installed Node toolchain. Declared, not discovered. */
  confound?: string;
}

export interface CellResult {
  fixture: string;
  stratum: Fixture['stratum'];
  packageManager: string;
  arm: 'trace' | 'policy';
  policy?: string;
  exitCode: number | null;
  signal: string | null;
  durationMs: number;
  ok: boolean;
  /** Last lines of stderr, for explaining a failure. Truncated; never contains
   *  file contents, only whatever the package manager printed. */
  stderrTail: string;
  homeAccess?: HomeAccessSummary[];
  traceLines?: number;
  eventCount?: number;
}

const HOME = homedir();

export function runCommand(
  argv: string[],
  opts: { cwd: string; env?: NodeJS.ProcessEnv; timeoutMs?: number },
): Promise<{ code: number | null; signal: string | null; stdout: string; stderr: string; ms: number }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(argv[0], argv.slice(1), {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const cap = 200_000;
    child.stdout.on('data', (d) => { if (stdout.length < cap) stdout += d.toString(); });
    child.stderr.on('data', (d) => { if (stderr.length < cap) stderr += d.toString(); });
    const timer = opts.timeoutMs
      ? setTimeout(() => { child.kill('SIGKILL'); }, opts.timeoutMs)
      : null;
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, ms: Date.now() - started });
    });
    child.on('error', () => {
      if (timer) clearTimeout(timer);
      resolve({ code: null, signal: 'SPAWN_ERROR', stdout, stderr, ms: Date.now() - started });
    });
  });
}

export function materialise(fixture: Fixture, dir: string): void {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify(fixture.packageJson, null, 2));
  for (const [name, body] of Object.entries(fixture.files ?? {})) {
    const target = join(dir, name);
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, body);
  }
}

export function parseTraceFile(path: string, cwd: string): { events: TraceEvent[]; lines: number } {
  const text = readFileSync(path, 'utf8');
  const events: TraceEvent[] = [];
  let lines = 0;
  for (const line of text.split('\n')) {
    if (!line) continue;
    lines++;
    events.push(...parseTraceLine(line, { home: HOME, fallbackCwd: cwd }));
  }
  return { events, lines };
}

export interface PackageManager {
  id: string;
  /** argv for a clean install in the current directory. */
  install: string[];
  /** Extra environment, e.g. a pinned store path. */
  env?: Record<string, string>;
  /** Where this manager keeps state under $HOME. Discovered by tracing an
   *  unconfined install, not read from documentation. A policy that allows
   *  "the cache" has to name these, and they differ per manager. */
  homeDirs: string[];
}

export async function runTraceArm(
  pm: PackageManager,
  fixture: Fixture,
  dir: string,
  stracePath: string,
  traceOut: string,
  timeoutMs: number,
): Promise<CellResult> {
  materialise(fixture, dir);
  const argv = [
    stracePath, '-f', '-qq', '-y', '-e', 'trace=file,execve', '-s', '512',
    '-o', traceOut, '--', ...pm.install,
  ];
  const r = await runCommand(argv, {
    cwd: dir,
    // PWD must match cwd. A stale inherited PWD makes GNU make stat() the
    // launching shell's directory, which showed up as a phantom $HOME access in
    // the first run before it was tracked down.
    env: { ...process.env, ...(pm.env ?? {}), PWD: dir },
    timeoutMs,
  });
  let homeAccess: HomeAccessSummary[] | undefined;
  let traceLines: number | undefined;
  let eventCount: number | undefined;
  if (existsSync(traceOut)) {
    const { events, lines } = parseTraceFile(traceOut, dir);
    homeAccess = summariseHomeAccess(events, HOME);
    traceLines = lines;
    eventCount = events.length;
  }
  return {
    fixture: fixture.id,
    stratum: fixture.stratum,
    packageManager: pm.id,
    arm: 'trace',
    exitCode: r.code,
    signal: r.signal,
    durationMs: r.ms,
    ok: r.code === 0,
    stderrTail: tail(r.stderr),
    homeAccess,
    traceLines,
    eventCount,
  };
}

export async function runPolicyArm(
  pm: PackageManager,
  fixture: Fixture,
  policy: Policy,
  dir: string,
  timeoutMs: number,
): Promise<CellResult> {
  materialise(fixture, dir);
  const props: string[] = [];
  for (const p of policy.props) props.push('-p', p);
  const argv = [
    'systemd-run', '--user', '--wait', '--pipe', '--collect', '--quiet',
    ...props,
    `--working-directory=${dir}`,
    `--setenv=HOME=${HOME}`,
    `--setenv=PWD=${dir}`,
    `--setenv=PATH=${pm.env?.PATH ?? process.env.PATH ?? ''}`,
    ...Object.entries(pm.env ?? {}).map(([k, v]) => `--setenv=${k}=${v}`),
    '--', ...pm.install,
  ];
  const r = await runCommand(argv, { cwd: dir, timeoutMs });
  return {
    fixture: fixture.id,
    stratum: fixture.stratum,
    packageManager: pm.id,
    arm: 'policy',
    policy: policy.id,
    exitCode: r.code,
    signal: r.signal,
    durationMs: r.ms,
    ok: r.code === 0,
    stderrTail: tail(r.stderr),
  };
}

function tail(s: string, n = 1200): string {
  const t = s.trim();
  return t.length <= n ? t : '…' + t.slice(-n);
}

export function appendResult(path: string, r: CellResult): void {
  appendFileSync(path, JSON.stringify(r) + '\n');
}

export function loadCompleted(path: string): Set<string> {
  const done = new Set<string>();
  if (!existsSync(path)) return done;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as CellResult;
      done.add(cellKey(r.packageManager, r.fixture, r.arm, r.policy));
    } catch { /* a half-written final line is fine to ignore */ }
  }
  return done;
}

export function cellKey(pm: string, fixture: string, arm: string, policy?: string): string {
  return `${pm}::${fixture}::${arm}::${policy ?? '-'}`;
}
