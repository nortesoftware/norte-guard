// Driver for the install-time $HOME-access measurement.
//
//   node dist/install-trace-main.js --sample <sample.json> --out <run.ndjson>
//
// Sequential by design: package-manager caches are shared mutable state and
// parallel installs would corrupt the very thing being measured.

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  type Fixture, type Policy, type PackageManager,
  runTraceArm, runPolicyArm, appendResult, loadCompleted, cellKey,
} from './install-trace-run.js';

const HOME = homedir();

// Each manager keeps its state somewhere different in $HOME, so "allow the
// cache" is not one policy but four. These lists were DISCOVERED by tracing an
// unconfined install of each, not taken from documentation — the point of the
// exercise is that the documentation does not exist.
export const MANAGERS: PackageManager[] = [
  {
    id: 'npm@10.9.8',
    install: ['npm', 'install', '--no-audit', '--no-fund', '--loglevel', 'error'],
    homeDirs: [`${HOME}/.npm`],
  },
  {
    id: 'pnpm@11.22.0',
    install: ['node', '{{PM}}/pnpm/bin/pnpm.cjs', 'install', '--reporter', 'silent'],
    homeDirs: [`${HOME}/.cache/pnpm`, `${HOME}/.local/state`, `${HOME}/.local/share`, `${HOME}/.config/pnpm`],
  },
  {
    id: 'yarn@1.22.22',
    install: ['node', '{{PM}}/yarn/bin/yarn.js', 'install', '--silent', '--no-progress'],
    homeDirs: [`${HOME}/.cache/yarn`, `${HOME}/.config/yarn`, `${HOME}/.yarn`],
  },
  {
    id: 'bun@1.4.0',
    install: ['{{PM}}/bun-linux-x64/bun', 'install'],
    homeDirs: [`${HOME}/.bun`],
  },
];

// `-` prefixes are deliberate throughout: systemd kills the unit with
// 226/NAMESPACE if a Bind*/Inaccessible path does not exist, which looks exactly
// like a broken install. See docs/install-trace.md.
export function policiesFor(pm: PackageManager): Policy[] {
  const cacheBinds = pm.homeDirs.map((d) => `BindPaths=-${d}`);
  const base = ['ProtectHome=tmpfs', `BindReadOnlyPaths=-${HOME}/.local`];
  return [
    { id: 'p0-unconfined', description: 'No confinement. Control arm.', props: [] },
    {
      id: 'p1-tmpfs-naive',
      description: 'ProtectHome=tmpfs and nothing else.',
      props: ['ProtectHome=tmpfs'],
      confound: 'Node lives under $HOME/.local here, so this fails before the manager runs.',
    },
    {
      id: 'p2-tmpfs-toolchain',
      description: 'tmpfs with the Node toolchain bound back read-only.',
      props: base,
    },
    {
      id: 'p3-tmpfs-toolchain-cache',
      description: "As p2 plus this manager's own $HOME state, writable. ~/.npmrc stays denied.",
      props: [...base, ...cacheBinds],
    },
    {
      id: 'p4-tmpfs-plus-npmrc',
      description: 'As p3 plus ~/.npmrc read-only. Paired with p3 this isolates ~/.npmrc.',
      props: [...base, ...cacheBinds, `BindReadOnlyPaths=-${HOME}/.npmrc`],
    },
    {
      id: 'p5-credentials-only',
      description: 'Surgical: $HOME visible, only the credential set denied.',
      props: [
        `InaccessiblePaths=-${HOME}/.ssh`,
        `InaccessiblePaths=-${HOME}/.gnupg`,
        `InaccessiblePaths=-${HOME}/.mozilla`,
        `InaccessiblePaths=-${HOME}/.aws`,
        `InaccessiblePaths=-${HOME}/.config`,
      ],
    },
    {
      id: 'p6-p3-plus-gyp-cache',
      description: 'As p3 plus a writable ~/.cache/node-gyp — what a source build additionally needs.',
      props: [...base, ...cacheBinds, `BindPaths=-${HOME}/.cache/node-gyp`],
    },
  ];
}

function pkgFixture(name: string, stratum: Fixture['stratum'], hypothesis: string): Fixture {
  return {
    id: `pkg:${name}`,
    stratum,
    description: `Fresh project with a single dependency on ${name}`,
    hypothesis,
    packageJson: {
      name: 'ng-install-trace-fixture', version: '1.0.0', private: true,
      dependencies: { [name]: '*' },
    },
  };
}

export function buildFixtures(sampleNames: string[], only?: Fixture['stratum'][]): Fixture[] {
  const all: Fixture[] = sampleNames.map((n) =>
    pkgFixture(n, 'normal-random', 'Pure-JS utility: expected to need only the manager cache and the toolchain.'),
  );

  for (const [n, h] of [
    ['esbuild', 'postinstall fetches a platform binary.'],
    ['better-sqlite3', 'prebuild-install with a node-gyp fallback.'],
    ['sharp', 'platform-specific optionalDependencies plus prebuilt libvips.'],
    ['node-gyp', 'the tool itself, installed but not invoked.'],
  ] as Array<[string, string]>) all.push(pkgFixture(n, 'native-purposive', h));

  // The cell the first run missed by chance: every native fixture above resolved
  // to a prebuilt binary, so no compiler ever ran. Forcing a source build is the
  // case most likely to need paths outside the manager's own cache.
  all.push({
    id: 'gyp:bufferutil-from-source',
    stratum: 'gyp-purposive',
    description: 'bufferutil with prebuilds refused — forces a real node-gyp compile',
    hypothesis: 'node-gyp downloads Node headers into ~/.cache/node-gyp, a path no manager cache covers.',
    packageJson: {
      name: 'ng-gyp-fixture', version: '1.0.0', private: true,
      dependencies: { bufferutil: '*' },
    },
    env: { npm_config_build_from_source: 'true', PREBUILD_INSTALL_FORCE_BUILD: 'true' },
  });

  all.push({
    id: 'monorepo:npm-workspaces',
    stratum: 'monorepo-purposive',
    description: 'workspaces with two packages',
    hypothesis: 'Workspace resolution is intra-project; $HOME needs should not differ.',
    packageJson: { name: 'ng-monorepo-fixture', version: '1.0.0', private: true, workspaces: ['packages/*'] },
    files: {
      'packages/a/package.json': JSON.stringify({ name: '@ngf/a', version: '1.0.0', dependencies: { 'is-arguments': '*' } }),
      'packages/b/package.json': JSON.stringify({ name: '@ngf/b', version: '1.0.0', dependencies: { hasown: '*' } }),
    },
  });

  for (const [id, hypothesis, files] of [
    ['no-project-npmrc', 'No project .npmrc; user ~/.npmrc carries an authToken.', undefined],
    ['project-registry', 'Project .npmrc pins the default registry.', { '.npmrc': 'registry=https://registry.npmjs.org/\n' }],
    ['project-scoped', 'Project .npmrc maps a scope to a registry.', { '.npmrc': '@ngscope:registry=https://registry.npmjs.org/\n' }],
    ['project-auth', 'Project .npmrc carries always-auth.', { '.npmrc': 'registry=https://registry.npmjs.org/\nalways-auth=false\n' }],
  ] as Array<[string, string, Record<string, string> | undefined]>) {
    all.push({
      id: `npmrc:${id}`, stratum: 'registry-purposive', description: hypothesis,
      hypothesis: 'Does the manager open ~/.npmrc, and for read or for write?',
      packageJson: { name: 'ng-npmrc-fixture', version: '1.0.0', private: true, dependencies: { hasown: '*' } },
      files,
    });
  }

  return only ? all.filter((f) => only.includes(f.stratum)) : all;
}

function arg(name: string, dflt = ''): string {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : dflt;
}

async function main(): Promise<void> {
  const out = arg('--out', 'install-trace-results/run.ndjson');
  const samplePath = arg('--sample');
  const work = arg('--work', '/tmp/ng-install-trace');
  const strace = arg('--strace', 'strace');
  const pmRoot = arg('--pm-root', '');
  const toolchain = arg('--toolchain', '');
  const onlyPm = arg('--managers');
  const onlyStrata = arg('--strata');
  const timeoutMs = Number(arg('--timeout', '420000'));

  if (!samplePath || !existsSync(samplePath)) {
    console.error('need --sample <sample.json>');
    process.exit(2);
  }
  const sample = JSON.parse(readFileSync(samplePath, 'utf8')) as { sample: string[] };
  const strata = onlyStrata ? (onlyStrata.split(',') as Fixture['stratum'][]) : undefined;
  const fixtures = buildFixtures(sample.sample, strata);
  const managers = MANAGERS
    .filter((m) => !onlyPm || onlyPm.split(',').some((p) => m.id.startsWith(p)))
    .map((m) => ({ ...m, install: m.install.map((a) => a.replace('{{PM}}', pmRoot)) }));

  mkdirSync(join(out, '..'), { recursive: true });
  mkdirSync(work, { recursive: true });
  const done = loadCompleted(out);
  const dir = join(work, 'project');
  const traceOut = join(work, 'current.trace');

  // The compiler wrappers live outside $HOME on purpose, so that binding the
  // toolchain back is about Node, not about gcc.
  const basePath = toolchain ? `${toolchain}:${process.env.PATH}` : (process.env.PATH ?? '');

  for (const pm of managers) {
    for (const f of fixtures) {
      const env = { ...(pm.env ?? {}), ...(f.env ?? {}), PATH: basePath };
      const traceKey = cellKey(pm.id, f.id, 'trace');
      if (!done.has(traceKey)) {
        const r = await runTraceArm({ ...pm, env }, f, dir, strace, traceOut, timeoutMs);
        appendResult(out, r);
        console.error(`${pm.id} ${f.id} trace: exit=${r.exitCode} ${r.eventCount ?? 0} ev, ${r.homeAccess?.length ?? 0} prefixes`);
      }
      for (const p of policiesFor(pm)) {
        const key = cellKey(pm.id, f.id, 'policy', p.id);
        if (done.has(key)) continue;
        const r = await runPolicyArm({ ...pm, env }, f, p, dir, timeoutMs);
        appendResult(out, r);
        console.error(`${pm.id} ${f.id} ${p.id}: ${r.ok ? 'OK' : `FAIL exit=${r.exitCode}`}`);
      }
    }
  }

  writeFileSync(join(out, '..', 'policies.json'),
    JSON.stringify(Object.fromEntries(managers.map((m) => [m.id, policiesFor(m)])), null, 2));
  console.error('done');
}

main().catch((e) => { console.error(e); process.exit(1); });
