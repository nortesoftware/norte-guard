# What a package install actually needs from `$HOME`

npm 10.9.8 · pnpm 11.22.0 · yarn 1.22.22 · bun 1.4.0
Measured 2026-08-21/22. 960 cells, 120 traced installs.

## Why this exists

[Prior art](prior-art.md#part-ii--prevention-at-install-time) found that kernel-enforced
read confinement of `npm install` is already built at least eight times — nono, cplt,
mise, Homebrew 6.0.18, safedep/pmg, Sandlock, landrun, and a plain
`systemd-run --user -p ProtectHome=tmpfs` one-liner. The mechanism is not the gap.

The gap is that **every one of them hand-writes its allowlist, and none published the
measurement it was written from.** The consequences are visible in the artefacts:

- firejail's `nodejs-common.profile` names `~/.node-gyp`, `~/.yarn-config` and
  `~/.yarncache` — pre-XDG paths that current node-gyp, yarn and pnpm no longer use.
  (Harmless there, because firejail is blacklist-shaped; fatal in an allowlist.)
- safedep/pmg allows `${HOME}/.npmrc` in its npm profile as a documented trade-off.
- No published allowlist mentions `~/.npm/_tuf`, `~/.local/state`, or `~/.config/pnpm`.
- Every one of them is written for npm, and three of the four managers keep their
  state somewhere else entirely.

The only published compatibility number is Latch's 1.6% false-interruption rate
(ACM ASIA CCS 2022) — four years old, AppArmor, root required, npm only.

This is that measurement. **It is not a ninth implementation.** It is the data the
eight that exist were written without.

## Method

### Machine

Debian 13 trixie, kernel 6.12.94, systemd 257, `landlock` present in
`/sys/kernel/security/lsm`. node v22.23.2.

**Declared confounder: the Node toolchain lives inside `$HOME`**, at
`~/.local/lib/node-v22.23.2-linux-x64`. That is the common case for nvm/fnm/manual
installs, and it means a naive `$HOME`-deny policy fails before the manager runs, for
a reason that has nothing to do with package management. It is a control variable
throughout, not a discovery. It is also the reason bun behaves differently from the
other three: bun is a self-contained binary that was run from outside `$HOME`.

A C/C++ toolchain (gcc/g++/make 14.2.0) was obtained unprivileged via
`apt-get download` + `dpkg-deb -x` and placed **outside** `$HOME`, so that "bind the
toolchain back" means Node, not gcc.

`~/.npmrc` on this machine holds a live plaintext `_authToken`. The tracer records
path arguments only (`strace -e trace=file`), never file contents, and no value from
it appears in any artefact here.

### Tracer coverage — what this observes, and what it does not

`strace -f -qq -y -e trace=file,execve -s 512`.

**Observes**: path arguments to the file syscall family — `open`/`openat`,
`stat`/`statx`/`newfstatat`, `access`/`faccessat`, `readlink`, `mkdir`, `unlink`,
`rename`, `chmod` — across the whole process tree, following forks and execs.

**Does not observe**: accesses through an already-open file descriptor
(`statx(fd, "", AT_EMPTY_PATH, …)`). Excluded deliberately rather than missed —
**Landlock does not re-check an open fd either**, so counting them would overstate
what a policy can reach. Also unobserved: opens issued through `io_uring` rather than
a syscall, and anything a process does after detaching. Neither was seen; neither was
ruled out.

**One parser-level artefact, found and fixed.** The first run showed phantom accesses
to `~/NORTE/Norteguard`. They were real `newfstatat` calls, but caused by a stale
inherited `PWD` environment variable: GNU make `stat()`s `$PWD` to validate it. The
harness now sets `PWD` to match the working directory. Anyone tracing installs should
sanitise the child environment or they will attribute their own shell's cwd to npm.

### Sample

**`normal-random`, n=20.** Systematic draw: every 5th of the first 100 results of

```
https://registry.npmjs.org/-/v1/search?text=keywords:javascript&size=100&popularity=1.0&quality=0.0&maintenance=0.0
```

fetched 2026-08-21, ordered by npm popularity. Frame and draw are in
`install-trace-results/sample-2026-08-21.json`.

**Declared bias**: keyword-restricted and popularity-weighted, so it over-represents
mature, dependency-free utility packages (`hasown`, `is-arguments`, `unbox-primitive`).
That biases toward **less** breakage than a real project mix. Read the rates as a floor.

**Purposive strata** (named hard cases, reported separately, never pooled):
`native-purposive` n=4 (esbuild, better-sqlite3, sharp, node-gyp),
`gyp-purposive` n=1 (forced source build),
`monorepo-purposive` n=1 (workspaces),
`registry-purposive` n=4 (four `.npmrc` shapes).

**Excluded from their manager's denominator** — cells that fail with no confinement at
all, so no policy caused them: `@oxc-parser/binding-linux-x64-musl` under npm
(`EBADPLATFORM` on glibc); `esbuild` and `better-sqlite3` under pnpm; the forced
source build under both pnpm and bun. Those last three are results in themselves and
are discussed below.

**Cache state**: warm, against the real caches. Cold-cache behaviour was not measured.

## Which policies actually enforce

Built first, because a matrix resting on a property that silently does nothing is
worse than no matrix. Each row is a positive control: a read that succeeds unconfined
and must fail under the property. Probes report the errno only, never contents.

| property (`systemd-run --user`) | enforces? | `~/.gitconfig` | `~/.ssh` | `~/.npmrc` |
|---|---|---|---|---|
| `ProtectHome=tmpfs` | **yes** | ENOENT | ENOENT | ENOENT |
| `ProtectHome=yes` | **yes** | EACCES | EACCES | EACCES |
| `ProtectHome=read-only` | **reads not blocked** | OK | OK | OK |
| `InaccessiblePaths=~/.ssh` | **yes, surgical** | OK | EACCES | OK |
| `PrivateNetwork=yes` | **yes** | — | — | — |
| `IPAddressDeny=any` | **NO — silent no-op** | — | — | — |

Three findings worth carrying, independent of anything about npm:

1. **`ProtectHome=read-only` is a trap.** It sounds protective and closes nothing in
   this threat model: every secret stays readable. It blocks writes only (`EROFS`).
2. **`IPAddressDeny=any` is a silent no-op in a user unit.** A connection to
   `registry.npmjs.org:443` succeeded inside it, with no warning from systemd.
3. **`InaccessiblePaths=` on a path that does not exist kills the unit** with
   `226/NAMESPACE` before the command starts. `~/.aws` is absent on this machine, and
   the first version of the surgical policy failed 100% for that reason alone — which
   looks exactly like a broken install. The `-` prefix fixes it. A credential denylist
   that only works when every listed secret happens to exist is not a usable policy.

Overhead of `systemd-run --user`: 56 ms per invocation.

## The policies

| id | what it allows under `$HOME` |
|---|---|
| `p0` | everything (control) |
| `p1` | nothing — `ProtectHome=tmpfs` alone |
| `p2` | the Node toolchain, read-only |
| `p3` | p2 + **this manager's own state dirs**, writable |
| `p4` | p3 + `~/.npmrc` read-only |
| `p5` | everything except `~/.ssh ~/.gnupg ~/.mozilla ~/.aws ~/.config` |
| `p6` | p3 + `~/.cache/node-gyp`, writable |

`p3` is per-manager, because "allow the cache" is four different policies:

| manager | state dirs discovered by tracing |
|---|---|
| npm | `~/.npm` |
| pnpm | `~/.cache/pnpm`, `~/.local/state`, `~/.local/share`, `~/.config/pnpm` |
| yarn | `~/.cache/yarn`, `~/.config/yarn`, `~/.yarn` |
| bun | `~/.bun` |

## The compatibility matrix

Breakage attributable to the policy, conditioned on the install succeeding unconfined.
`normal-random` stratum, n=19–20 per manager.

| policy | npm | pnpm | yarn | bun |
|---|---|---|---|---|
| `p1` nothing | **100%** | **100%** | **100%** | 0% |
| `p2` toolchain | **100%** | 0% | 0% | 0% |
| `p3` + own state | 0% | 0% | 0% | 0% |
| `p4` + `~/.npmrc` | 0% | 0% | 0% | 0% |
| `p5` credentials denied | 0% | **100%** | **100%** | 0% |
| `p6` + node-gyp cache | 0% | 0% | 0% | 0% |

Every 0% carries a 95% Wilson upper bound of about **16%** at this n. Full per-cell
tables with intervals and failure modes are in
`install-trace-results/2026-08-22-matrix.md`.

### The four results in that table

**1. `p5` — a credential denylist containing `~/.config` breaks pnpm and yarn outright.**

```
[ERROR] EACCES: permission denied, open '/home/chris/.config/pnpm/config.yaml'
```

100% of installs, both managers. This is the most practically important finding here,
because `~/.config/gh` — the GitHub CLI token, a prime target of the 2025–26 npm worms —
sits in the same directory as `~/.config/pnpm` and `~/.config/yarn`. **You cannot deny
`~/.config` wholesale.** A credential policy has to name leaf paths, and every such
list is a maintenance burden that goes stale.

Three follow-up experiments pin down how far it goes:

| variant | pnpm | yarn |
|---|---|---|
| deny `~/.config` wholesale | **fails** | **fails** |
| deny only the leaf `~/.config/gh` | OK | OK |
| deny `~/.config` + `XDG_CONFIG_HOME` redirected | OK | **still fails** |

**Denying leaf paths is safe.** A policy naming `~/.config/gh`, `~/.config/gcloud`,
`~/.config/op` breaks neither manager. Only the wholesale denial does.

**yarn 1.x has no workaround, for a reason worth reporting on its own.** Its rc-file
discovery builds a path list containing `$HOME/.config/yarn/config` and
`$HOME/.config/yarn` **hardcoded**, alongside a separate XDG-aware `CONFIG_DIRECTORY`
entry — so `XDG_CONFIG_HOME` adds a path rather than replacing one. Then `parseRcPaths`
catches `ENOENT` and `EISDIR` and returns `{}`, but **rethrows `EACCES`**:

```js
} catch (error) {
  if (error.code === 'ENOENT' || error.code === 'EISDIR') {
    return {};
  } else {
    throw error;      // EACCES reaches here
  }
}
```

That asymmetry decides which sandboxes yarn survives:

- a policy that **hides** the path (mount namespace, `ProtectHome=tmpfs`) yields `ENOENT`
  — yarn swallows it and installs fine. That is the 0% at `p2`-`p4`.
- a policy that **denies** the path (Landlock, `InaccessiblePaths=`) yields `EACCES`
  — yarn crashes before doing any work. That is the 100% at `p5`.

**Landlock produces `EACCES`.** So this hits precisely the mechanism the eight shipped
implementations are built on, and it is invisible to anyone who tested their policy with
a container or a tmpfs overlay instead.

### Narrowing that result against a real Landlock sandbox

`p5` denies `~/.config` with `InaccessiblePaths=`, which masks the directory whether or
not its contents exist. A Landlock allowlist behaves differently: an ungranted path that
**does not exist** can still surface as `ENOENT`, which yarn tolerates. Running cplt
2026.08.17 — a real Landlock sandbox — narrowed the finding:

```
$ cplt exec -- yarn install
error Error: EACCES: permission denied, open '/home/chris/.npmrc'
```

`yarn install` does fail, but on **`~/.npmrc`**, not on `~/.config/yarn` (which does not
exist on this machine and therefore reads as `ENOENT`). Allowing just that one file makes
it pass. So the transferable claim is narrower than `p5` alone suggests: **it is the
EACCES-vs-ENOENT distinction that breaks yarn, applied to whichever denied rc path it
reaches first** — and `~/.npmrc`, which every credential policy denies, is reached early.

Isolating `~/.npmrc` as the only denied path makes the asymmetry exact:

| manager | exit | outcome with `~/.npmrc` → `EACCES` |
|---|---|---|
| npm 10.9.8 | 0 | installs |
| pnpm 11.22.0 | 0 | logs the `EACCES`, continues |
| bun 1.4.0 | 0 | installs |
| **yarn 1.22.22** | **1** | **aborts before resolving anything** |

**A correct credential policy — deny `~/.npmrc`, which this measurement shows costs
nothing for the other three — makes yarn 1 unusable.** That is the reportable finding,
and it is sharper than the `~/.config` framing it replaces.

**2. `p2` — npm is the only manager that hard-fails when `$HOME` is unwritable.**

```
npm error syscall mkdir
npm error path /home/chris/.npm
```

19/19. pnpm, yarn and bun all create their state inside the ephemeral tmpfs and
complete the install; they lose caching, not correctness. npm aborts.

**3. `p1` — bun needs nothing from `$HOME` at all.** 0% breakage with the entire home
directory replaced by an empty tmpfs. It is a self-contained binary run from outside
`$HOME`, and it degrades to an ephemeral cache. The other three fail `203/EXEC`
because `node` itself is inside `$HOME` — the declared confounder, not a real
requirement.

**4. `p3` is not sufficient for a source build.** See below.

### The node-gyp result — the one that changed the conclusion

The first run of this measurement concluded that the only real `$HOME` requirement was
a writable manager cache. That was wrong, and it was wrong by luck of the draw: all
four `native-purposive` fixtures resolved to **prebuilt binaries**, so no compiler ever
ran and `~/.cache/node-gyp` was never touched.

Forcing a source build (`npm_config_build_from_source=true`, `bufferutil`) changes it:

| policy | npm | yarn |
|---|---|---|
| `p3` toolchain + own state | **FAIL** | **FAIL** |
| `p4` + `~/.npmrc` | **FAIL** | **FAIL** |
| `p6` + `~/.cache/node-gyp` | OK | OK |

`p3` and `p6` differ in exactly one bind, so the attribution is clean. node-gyp
downloads the Node headers — **65 MB, 2,726 writes across 3,327 distinct paths** —
into `~/.cache/node-gyp/<version>/`, which no manager's own cache covers.

A source build also probes three paths nothing else touches: `~/.node_modules`,
`~/.node_libraries` and `~/.gyp` (all `ENOENT`, all harmless, none in any published
allowlist).

**So the honest requirement is conditional**: manager cache for a prebuilt install,
*plus* `~/.cache/node-gyp` if anything compiles. A policy written from prebuilt
installs alone — which is what you get if you sample popular packages — will break the
first time a developer installs something without a prebuild for their platform.

**pnpm and bun could not run the build at all, unconfined:**

```
[ERR_PNPM_IGNORED_BUILDS] Ignored build scripts: bufferutil@4.1.0
Run "pnpm approve-builds" to pick which dependencies should be allowed to run scripts.
```

pnpm 11 and bun refuse dependency build scripts by default and exit non-zero. Worth
sitting with: **for this case, the package manager's own allowlist already prevented
the install-time code execution that the sandbox exists to contain.** That is the same
direction npm 12 took (`allowScripts` off by default, see prior-art Part II), and it
narrows what a sandbox is still for — to the scripts developers *do* approve.

## `~/.npmrc`: read by all four, written by none

Across **120 traced installs**, all four managers, every stratum:

| manager | reads | writes | traces |
|---|---|---|---|
| npm | 30 | **0** | 30 |
| pnpm | 30 | **0** | 30 |
| yarn | 30 | **0** | 30 |
| bun | 30 | **0** | 30 |

Opened `O_RDONLY`, exactly once per install, never written — including in all four
`registry-purposive` variants (no project `.npmrc`; project `.npmrc` pinning the
registry; mapping a scope; carrying `always-auth`). npm probes four locations in
precedence order — builtin, project, user, global — and three return `ENOENT`.

At the policy level, `p3` (no `~/.npmrc` at all) and `p4` (`~/.npmrc` bound read-only)
break **identically: zero, for every manager.** Denying the file outright cost nothing.

No manager wrote `~/.npmrc`, and for public-registry installs none needed to read it
either — they read it unconditionally and proceed fine when it is absent.

**A correction to an earlier draft of this document.** It claimed firejail's profile
rested on a contradicted assumption, citing `noblacklist ${HOME}/.npmrc` together with
`ignore read-only ${HOME}/.npmrc`. Checking the actual profile before reporting it
upstream showed that reading was wrong, in three ways. The lines live in
`nodejs-common.profile`, not `node.profile`. The `noblacklist` is *required* — 
`disable-programs.inc:1177` blacklists `~/.npmrc`, so without it npm could not read the
file at all, and reading is exactly what the measurement says npm does. And the
`ignore read-only` is applied uniformly across six node-stack paths — `~/.cache/deno`,
`~/.deno`, `~/.npm-packages`, `~/.npmrc`, `~/.nvm`, `~/.yarnrc` — undoing a blanket
`read-only` inherited from a parent profile, not a per-file judgement that npm writes it.
**firejail's handling is consistent with this measurement, not contradicted by it.**

The honest limit: every fixture resolves from `registry.npmjs.org`. **A private
registry requiring authentication was not exercised** — verdaccio was not set up. There
the token is presumably load-bearing, and this measurement does not speak to it.

## The `$HOME` surface, per manager

Distinct prefixes touched in the `normal-random` stratum:

| manager | count | prefixes |
|---|---|---|
| bun | **3** | `~/.bun/install`, `~/.bunfig.toml`, `~/.npmrc` |
| yarn | 8 | `~/.cache/yarn`, `~/.config/yarn`, `~/.yarn/config`, `~/.yarnrc`, `~/.yarnrc.yml`, `~/.npmrc`, `~/.local/bin`, `~/.local/lib` |
| pnpm | 9 | `~/.cache/pnpm`, `~/.config/pnpm`, `~/.local/share`, `~/.local/state`, `~/.node_modules`, `~/.node_libraries`, `~/.npmrc`, `~/.local/bin`, `~/.local/lib` |
| npm | 10 | `~/.npm/_cacache`, `~/.npm/_logs`, `~/.npm/_update-notifier-last-checked`, `~/.npm`, `~/.npmrc`, `~/.gitconfig`, `~/.local/lib`, `~/.local/bin`, `~/.local`, `~` |

Two things a single-manager measurement would have missed entirely: pnpm writes to
`~/.local/state` and `~/.local/share`, which are XDG directories a policy author would
not think to allow; and yarn reads **five** separate config files, three of which
(`~/.yarnrc`, `~/.yarnrc.yml`, `~/.yarn/config`) are legacy paths that all still get
probed.

`~/.gitconfig` is an npm-only surprise: opened `O_RDONLY` on all 30 npm installs,
including projects with no git dependency of any kind. No other manager reads it.

Probe counts are dominated by the toolchain — 153,654 `stat`-family calls against
`~/.local/lib` versus 14,592 content reads for npm. Sizing a policy from syscall volume
rather than content access will vastly overstate what is needed.

## What this does not establish

- **n=20 per manager.** The 95% upper bound on every "0%" is about **16%**. "Zero
  breakage" means "at most one install in six", not "none".
- **The sample is biased toward easy cases**, as declared.
- **Only yarn 1.22.22 (classic).** Yarn Berry with PnP has no `node_modules` at all and
  a different cache layout; it was not measured.
- **Only one forced source build**, n=1, one package, C not C++. `~/.cache/node-gyp` is
  established as necessary; the full set of paths a heavier native build needs
  (`better-sqlite3` from source, anything using `pkg-config` or system headers) is not.
- **No private registry with authentication.**
- **Warm caches only.**
- **This is mount-namespace enforcement, not Landlock.** What a manager *needs*
  transfers directly to a Landlock policy. The *failure modes* do not, and the yarn
  result above shows that is not hypothetical:
  `ProtectHome=tmpfs` yields `ENOENT` because the path is gone, whereas Landlock yields
  `EACCES` with the path still visible, and yarn lives or dies on the difference.
  `InaccessiblePaths=` was used as the `EACCES` analogue throughout, but **no arm was
  run against a real Landlock ruleset**, so that correspondence is argued from the
  errno rather than measured.
- One machine, one distro, two days.

## Reproducing

```
node dist/install-trace-main.js --sample <sample.json> \
  --out install-trace-results/<run>.ndjson \
  --strace <strace> --pm-root <managers> --toolchain <gcc-wrappers>
node dist/install-trace-report.js install-trace-results/<run>.ndjson
```

`strace` and the C toolchain were both obtained without root via `apt-get download`
plus `dpkg-deb -x`. pnpm and yarn were unpacked from `npm pack` tarballs and bun from
its GitHub release, all outside `$HOME`. Runs are resumable: cells already present in
the NDJSON are skipped.
