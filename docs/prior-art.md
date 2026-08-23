# Prior art

Written on 2026-08-21, after a near miss.

The `ltidi` off-registry dependency mechanism was about to be published as this
project's own finding. It is not. It is **PhantomRaven**, documented by Koi
Security in October 2025 under the name Remote Dynamic Dependencies, and the
eight specific packages already carried public advisories three days before this
project read their tarballs.

Nothing was published, so nothing has to be retracted. But the check should have
happened before the analysis, not after it, and this document exists so that the
next piece is checked first.

**The rule from here: no piece is written up as a finding until prior art has
been searched. Same discipline already applied to the numbers — nothing is
asserted without verification.**

---

## The near miss, in detail

`gunzip-js@99.9.1` was captured on 2026-08-15 at 14:27:57 UTC. The Amazon
Inspector advisory for it was published at **15:31:09 UTC the same day**, about
one hour later, and reads:

> `gunzip-js@99.9.1` is a near-empty npm package (typosquat of the well-known
> gunzip-maybe / gunzip family) whose package.json declares its sole dependency
> `ltidisafe` as an HTTPS tarball URL — `https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.2.tgz`
> — instead of a version resolved from the npm registry. […] the path segment
> `depenconf` mirrors the term dependency-confusion, the version 99.9.1 is the
> classic high-number squat pattern, and the package's own index.js is empty

Every observation in this project's C1 write-up — the empty index, the GCS
bucket, the semver squat, the reading of `depenconf` — was already in that
advisory. It was found by searching for who to report to.

All eight packages have OSV records, all with GHSA aliases, sourced from Amazon
Inspector, OSSF Package Analysis and ghsa-malware:

| package | OSV | GHSA alias (gunzip-js shown) |
|---|---|---|
| `check-audit` | MAL-2026-13976 | |
| `cspell-esm` | MAL-2026-13977 | |
| `eslint-generate-release` | MAL-2026-13980 | |
| `napi-raw` | MAL-2026-13984 | |
| `resolve-audit` | MAL-2026-13987 | |
| `depcruise-baseline` | MAL-2026-14053 | |
| `depcruise-fmt` | MAL-2026-14054 | |
| `gunzip-js` | MAL-2026-14056 | GHSA-2hqf-5jxh-4wp2 |

---

## Classification of every piece

`replication` — the idea is published and this is an independent re-observation.
`extension` — published work exists and this adds a measurement or a variant.
`not found` — no prior publication surfaced in the sources searched. **This is
not a claim of novelty.** It is the result of about a dozen web searches, and
absence of evidence at that depth is weak evidence of absence.

### Off-registry dependencies as a vector — **replication**

Fully published, twice over, and detected by shipping tools.

- **Koi Security, PhantomRaven** (Oct 2025) — "Remote Dynamic Dependencies", 126
  packages, 86,434 downloads, campaign running since August 2025. Names chosen to
  exploit LLM hallucination. ([koi.ai](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies))
- **Sonatype** — 83 further packages, taking the campaign past 200. ([sonatype.com](https://www.sonatype.com/blog/phantomraven-npm-malware))
- **Socket** ships an `HTTP Dependency` alert, **High** severity, supply-chain-risk
  category: *"Contains a dependency which resolves to a remote HTTP URL which
  could be used to inject untrusted code."* It flags both HTTP and HTTPS.
  ([socket.dev](https://socket.dev/alerts/httpDependency))

This project's contribution here is **not the mechanism and not the detection**.

### Concentration: one operator, many names, one off-registry host — **extension**

The concept is published. Socket reported a campaign of **60 packages across at
least three publisher accounts, all sending to the same Discord webhook**, and
treated the shared destination as the thing that establishes one operator.
([socket.dev](https://socket.dev/blog/npm-targeted-by-malware-campaign-mimicking-familiar-library-names))
That is the same idea applied to an exfiltration host rather than a dependency
host.

A prevalence figure also exists: an empirical study of npm dependencies reports
**URL or local-file dependencies at about 2% of all dependencies**, over a
different population and denominator than the publish stream.

What was **not found** is a base-rate distribution of
`(operator, off-registry destination)` pairs over a publish stream — the
measurement that 30 of 33 pairs hold one name, 2 hold two, and one holds eight.
That is the only part of this piece worth writing up, and it is an extension of a
published idea rather than a new one.

### Coordinated campaign / family detection — **replication**

- **Socket**: three accounts, 60 packages, identical host-fingerprinting code,
  eleven-day window, similar email addresses.
- **Socket, burst publishing**: *"one actor published 26 packages in 4 minutes,
  switched accounts, and published 7 more in a 1-minute burst, with the ~14-hour
  overnight gap and unchanged C2 host indicating the same operator."*
- **Panther**: DPRK npm malware factory, 108 packages, 261 versions, 31-day
  campaign wave, cluster analysis. ([panther.com](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave))

`ecosystem.ts`'s `detectFabricatedFamilies`, `family.ts`'s burst partition, and
`operator.ts`'s cross-account linking are all re-observations of this. The Socket
burst description is close to identical to `numberedSequences` in what it
observes; what differs is that this project's version keys on a numeric counter
in the name rather than on a shared C2 host, and that it reports a base rate
(one firing in 12,327 names).

`detectFabricatedFamilies` also has a recall of 0 of 26 here, documented in
`audit-a5.md`, so there is nothing to claim for it in any case.

### Capability genome — capability gain against a package's own history — **replication / extension**

The general form is standard in the literature and in tooling.

- **Practical automated detection of malicious npm packages** (ICSE 2022) —
  rule-based detection over install-script keywords, runtime evaluation, and
  *"whether new files, new dependencies and new hook script entries are
  present"*. ([dl.acm.org](https://dl.acm.org/doi/10.1145/3510003.3510104))
- **Endor Labs** treats *"a package that has not published in two or more years
  releasing a new version that adds optionalDependencies or lifecycle hooks"* as
  a detection heuristic. ([endorlabs.com](https://www.endorlabs.com/learn/mini-shai-hulud-returns-42-malicious-npm-packages-fake-sigstore-badges-in-antv-ecosystem-attack))

The extension, if any, is the three-valued regime handling — `INSUFFICIENT_HISTORY`
as a distinct verdict rather than a pass — and the measurement that 100% of the
observed class returns it. That measurement is in `audit-a5.md` as D14.

### The `young + tiny + !hasRepository` conjunction — **extension**

Component parts are published. Trivial and low-functionality packages are
characterised at scale: **17.92% of npm packages are trivial**, with a rule-based
detector at 94% accuracy, including a "data-only" class with no executable logic
([arXiv:2510.04495](https://arxiv.org/abs/2510.04495)). Repository-presence checks
appear in reproducibility-oriented detectors.

What this project adds is the specific three-way conjunction as a *capture*
filter rather than a detection rule, and — more usefully — the measurement that
it is calibrated for the decoy and not the carrier (D16), and that `fabricatedProfile`
fires on 82.66% of the class it applies to (D14). Both of those are negative
results about the conjunction, not claims for it.

### Share of packages unreadable to static analysis — **extension**

- **Moog et al., CISPA** — statically detecting JavaScript obfuscation and
  minification. ([cispa](https://swag.cispa.saarland/papers/moog2021statically.pdf))
- **Benchmark-driven empirical analysis of npm malicious package detection** —
  of 6,420 malicious packages, **80.3% use no evasion at all**; among the 19.7%
  that do, string obfuscation leads. ([arXiv:2603.27549](https://arxiv.org/pdf/2603.27549))
- Another study puts obfuscation in malicious npm packages near **49%**.

`analyzability.ts` measures something adjacent but not identical: not "is this
obfuscated" but "what fraction of the executable bytes can a conforming parser
read at all", counting native binaries, WASM and V8 bytecode caches as
unreadable. The 1.7%-of-files figure for this corpus is a measurement of that
question, which is why idea 1's opacity endpoints saturated against minification
— a result consistent with the 80.3% figure above.

### Time-to-unpublish / time-to-remediation — **not found**

npm's unpublish policy is documented, and informal figures circulate
("somewhere between six minutes and six weeks"). No formal measurement study
surfaced. The 64-minute median in `ttr-log.ndjson` is over 194 observations from
one collector's window and is not a registry-wide figure.

### `0.0.1-security` as a field ground-truth label — **replication**

Well established. **Phylum** ships an `NPM Security Holding` analytic; Socket,
Snyk, ReversingLabs and libraries.io all surface the placeholder. Using it as a
label source is standard practice, not a contribution — and `audit-a5.md` already
documents that the takedown log built from it over-counts, since 16.3% of a
sample still had real versions.

### Numbered counters crossing accounts — **not found**

The closest published work is Socket's burst-plus-account-switch observation
above, which links accounts by a shared C2 host and by timing rather than by a
counter embedded in package names. No publication surfaced that keys on a numeric
sequence spanning accounts.

Classified `not found` rather than novel, and it is descriptive with n=1 in any
case.

---

## What survives as this project's own

Short, and worth being short.

1. **Eight tarballs** for packages npm removed. The advisories describe them; the
   bytes are held here. Whether anyone else retained them is unknown.
2. **A base-rate distribution** of `(operator, off-registry destination)` pairs
   over a publish stream, with the window analysis. An extension of Socket's
   shared-destination idea, not a new one.
3. **The negative results**, which are the largest part of this work and the part
   least likely to be duplicated: opacity saturating against minification, the
   family endpoint saturating against monorepo releases, metadata velocity
   separating at the capture unit and vanishing at the operator unit,
   `detectFabricatedFamilies` at 0-of-26 recall, `fp-bench` unable to measure any
   class-restricted signal, and D1's style-uniformity idea failing because the
   payloads are not source.

---

## Sources

- [Koi Security — PhantomRaven: NPM Malware Hidden in Invisible Dependencies](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies)
- [Sonatype — PhantomRaven: npm Malware Uses Remote Dynamic Dependencies](https://www.sonatype.com/blog/phantomraven-npm-malware)
- [Socket — HTTP Dependency alert](https://socket.dev/alerts/httpDependency)
- [Socket — npm targeted by malware campaign mimicking familiar library names](https://socket.dev/blog/npm-targeted-by-malware-campaign-mimicking-familiar-library-names)
- [Panther — Inside DPRK's npm Malware Factory](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave)
- [Ohm et al. — Backstabber's Knife Collection](https://arxiv.org/abs/2005.09535)
- [Detecting and Characterizing Low and No Functionality Packages in the NPM Ecosystem](https://arxiv.org/abs/2510.04495)
- [Understanding NPM Malicious Package Detection: A Benchmark-Driven Empirical Analysis](https://arxiv.org/pdf/2603.27549)
- [Moog et al. — Statically Detecting JavaScript Obfuscation and Minification](https://swag.cispa.saarland/papers/moog2021statically.pdf)
- [Practical automated detection of malicious npm packages (ICSE 2022)](https://dl.acm.org/doi/10.1145/3510003.3510104)
- [Endor Labs — Mini Shai-Hulud Returns](https://www.endorlabs.com/learn/mini-shai-hulud-returns-42-malicious-npm-packages-fake-sigstore-badges-in-antv-ecosystem-attack)
- [Phylum — NPM Security Holding](https://docs.phylum.io/analytics/npm_security_holding)
- [OSV — MAL-2026-14056](https://api.osv.dev/v1/vulns/MAL-2026-14056)
- [GHSA-2hqf-5jxh-4wp2](https://github.com/advisories/GHSA-2hqf-5jxh-4wp2)

---
---

# Part II — Prevention at install time

Written on 2026-08-21, **before** building anything. That is the rule from Part I,
applied for the first time in the right order.

## The question

Part I asked "is this package malicious?" and got `INSUFFICIENT_HISTORY` on 100% of
n=1,505. The proposed change of direction asks about the action instead, in three gates:

| gate | question |
|---|---|
| **entrada** | what does `npm install` bring in that was not authorized? off-registry code, install scripts, unpinned resolution, unnamed transitives |
| **lectura** | what secrets can the install process open? `~/.npmrc`, `~/.aws/credentials`, `~/.ssh`, `~/.config/gh`, `GITHUB_TOKEN` |
| **salida** | where does the data leave? every theft ends in a socket |

The thesis was that **lectura** is the gate the attacker cannot route around, that it
should be *enforced* rather than detected, and that Linux Landlock (unprivileged since
5.13) is the mechanism.

## The answer

**The thesis is correct and the idea is already built.** Not once — at least eight
times, by eight independent groups, all shipping, most released within the last week.

| gate | verdict |
|---|---|
| **entrada** | **exists** — and it was absorbed by the package managers themselves in 2026 |
| **lectura** | **exists** — Landlock, unprivileged, deny-by-default, applied to the install process tree, covering this exact file list |
| **salida** | **partial** — nobody has solved per-host egress on Linux; Landlock structurally cannot |

Method: ten parallel search lanes, then adversarial verification of every serious
candidate against primary sources — repository source files, kernel docs, RFC text,
release APIs — not vendor blogs. Then a completeness critic that found three things the
ten lanes missed, one of which changed the verdict. Roughly 1,000 tool calls. Where a
claim below was settled by running something rather than reading something, it says so.

---

## entrada — **exists** (and is now the package manager's job)

This gate closed while the detection work in Part I was being done.

**npm v12.0.0, released 2026-07-08** (RFC 0054, PR #868, merged 2026-06-08) ships three
defaults that between them cover most of the entrada gate:

- `allowScripts` off — dependency lifecycle scripts do not run unless approved
- `--allow-git=none` — git dependencies refused
- `--allow-remote=none` — HTTPS-tarball dependencies refused, **direct and transitive**

A verification agent installed npm 12.0.2 and reproduced the PhantomRaven / `gunzip-js`
pattern from Part I against it. npm refused with `EALLOWREMOTE` before any network
request, for the direct case, the transitive case, and both http and https hosts — and
refused the poisoned lockfile that npm 10 installed without complaint. **The exact
mechanism this project captured eight tarballs of is now a default-off feature of the
package manager.**

The others moved the same way: **pnpm 11.0** (2026-04-28) defaults `minimumReleaseAge`
to 1440 minutes and `blockExoticSubdeps` to true; **Yarn 4.14** flipped `enableScripts`
to false and 4.15 added a 1-day `npmMinimalAgeGate`; **Bun** never ran arbitrary
dependency scripts.

`lockfile-lint` (5.0.1, 2026-08-13, 335k weekly downloads) covers a slice of this
statically. Its six validators inspect the `resolved` URL string and nothing else.
Tested rather than reasoned about: it **would** have caught the PhantomRaven tarball
dependency, including transitively — npm records it in `package-lock.json` v3 with a
`resolved` URL and integrity. What defeats it is timing, not visibility: the install
that writes the lockfile is the same install that runs the payload, so on a laptop it is
a post-mortem. Three further holes, all confirmed empirically: it is blind to
membership (a lockfile entry `package.json` never named passes with "No issues
detected", and its author's source carries the unimplemented `@TODO` for exactly that);
an entry with no `integrity` field passes `--validate-integrity` silently; and every
validator fails open when `resolved` is not URL-parseable.

**Consequence for this project: do not build the entrada gate.** It is redundant with
npm's shipped defaults on every platform, for free.

## lectura — **exists**, comprehensively

This is the finding that matters. Every one of the following is unprivileged, needs no
container, applies to the whole install process tree, and enforces rather than detects.

**`nono`** (nolabs-ai/nono, Apache-2.0, Rust, 3,760★, v0.74.0 released 2026-08-19,
pushed 2026-08-21). Uses the `landlock` crate. Its compiled-in `policy.json` carries a
`deny_credentials` group marked `"required": true` — a unit test asserts no profile can
remove it — listing `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`,
`~/.kube`, `~/.docker`, `~/.git-credentials`, `~/.netrc`, **`~/.npmrc`**, `~/.vault-token`
and twelve more, plus required groups for Linux browser profiles, keyrings, shell
configs and shell history. Its docs say the pitch verbatim: *"when you run npm install
inside a nono sandbox, every postinstall script inherits the same restrictions. A
malicious package cannot read your SSH keys or exfiltrate data — even if its postinstall
script tries to."* There is a `node-dev` profile, a `node_runtime` group, and a
`tool-sandbox-examples/npm/` demo.

**`cplt`** (navikt/cplt — Norwegian Labour and Welfare Administration IT, MIT, Rust,
release 2026-08-17). Landlock + seccomp-BPF, optional bubblewrap layer. `$HOME` appears
in no allow rule, so the credential paths are denied by *absence* from the allowlist,
which is stronger than a denylist. Its Linux integration tests plant real secret files
in a fake `$HOME` and assert the read fails — `landlock_blocks_aws_read`,
`landlock_blocks_ssh_read`, `landlock_blocks_kube_read`. It injects
`npm_config_ignore_scripts=true` by default, documents `cplt exec -- npm install` and
`alias npm="cplt exec -- npm"` in its Quick Start, and its `SECURITY.md` contains a
Shai-Hulud kill-chain table with a per-step verdict column.

**`mise`** (jdx/mise, 32.8k★). Sandbox landed 2026-04-02 (PR #8845), graduated from
experimental 2026-06-13, and PR #10940 (2026-07-11) added persistent `[settings.sandbox]`
deny defaults that apply with no flags — and `src/shims.rs` routes shimmed binaries
through the same code path, so **in shims mode a literally-typed `npm install` is
Landlock-confined.** `ABI::V5` best-effort, `$HOME` in no allowlist, and it fails
*closed*: if Landlock cannot be applied the command errors rather than running
unconfined. Its own docs carry an `npm install` recipe.

**Homebrew 6.0.18** (released 2026-08-17) — found by the completeness critic, missed by
all ten lanes. `Library/Homebrew/extend/os/linux/sandbox/landlock.rb`, first committed
2026-07-21, replaced bubblewrap on 2026-08-04. `formula_installer.rb` calls
`sandbox.deny_read_home` around the build step and again around post-install, **by
default**, plus `deny_all_network unless formula.network_access_allowed?(:build)` — a
capability manifest with kernel enforcement, shipping in a mainstream package manager.
And `brew sandbox-exec . -- npm install` is a shipped, generic, user-facing one-liner
that already implements this project's lectura gate.

**`systemd-run --user -p ProtectHome=tmpfs`** — no install, no root, no Landlock, works
on every systemd distro since ~2015. Verified live on this machine (Debian 13,
systemd 257): `npm install` completed `exit 0` while `cat ~/.aws/credentials`,
`ls ~/.ssh` and `cat ~/.npmrc` all returned *No such file or directory*. Two gotchas
found in the same run: `-p IPAddressDeny=any` silently does nothing in a user unit, and
`ProtectHome=tmpfs` hides a `$HOME`-installed Node toolchain until it is bound back.
**This is the five-second answer, and it means the pitch can never be "there was no way
to do this."**

Also verified as doing the mechanism: **`safedep/pmg`** (Landlock + seccomp-notify,
transparent `pmg npm install` wrapper, cooldown on by default) — though its sandbox is
off by default and its `npm-restrictive.yml` ships `allow_read: [/, ...]`, making it
broad-allow-minus-a-14-entry-denylist rather than deny-by-default, and its `handleOpen`
fails *open* when it cannot read the target's memory. **`Sandlock`** (arXiv 2605.26298,
ASPLOS Agentic-OS workshop, May 2026, Apache-2.0, 354★) — unprivileged Landlock+seccomp,
default-deny home, credential brokering, and its paper names `npm install` as a
motivating workload. Plus `landrun`, `landstrip`, `Fence`, and `senv` for Python/uv.

### The framing is taken too

`projectkennel` (Apache-2.0, pushed 2026-08-19): *"the postinstall script hunting for
credentials, reaches your project and nothing else: not `~/.ssh`"* and *"Confinement, not
detection."* `BX` markets with *"The tools watch what gets written. BX watches what gets
read."* Writing the landing page would mean writing someone else's.

### The academic precedent, and the commercial one that failed

**Latch** — *"Wolf at the Door: Preventing Install-Time Attacks in npm with Latch"*, ACM
ASIA CCS 2022. Install-time confinement of npm enforced by a kernel LSM with a
deny-by-default profile denying `/home/*/.ssh**` and all network. It reports **0.37%
median overhead, 102/102 malicious packages blocked, and 1.6% of installs falsely
interrupted**. That 1.6% is the compatibility bar, already measured four years ago. It
used AppArmor, which needs root to load a profile; the artifact has been dead since
2022-03-03 and its `cli/` submodule is a zero-byte broken reference, so it cannot be run.

**Phylum shipped this commercially and then removed it.** `phylum npm install` wrapped
the package manager in Birdcage, their Rust sandbox. Birdcage used **Landlock from
August 2022 until September 2023**, then deliberately ripped it out — commit 18112cb:
Landlock *"is currently still too limited to build a 'bulletproof' filesystem
sandbox... better suited for best-effort isolation of 'assumed safe' applications,
rather than sandboxing of 'potentially hazardous' software."* Birdcage is archived;
Phylum is a Veracode legacy platform. Two of those 2023 objections have since aged out
(ABI v4 on kernel 6.7 added TCP restrictions), but this is the single most useful
cautionary datum in the whole review. Worth noting separately: `phylum npm` passes
`read: true` to the sandbox, which maps to a read exception on `/` — so the product that
built this never actually armed the lectura gate for npm.

## salida — **partial**, and structurally hard

Landlock's network rules take a **port** as their object, never an address — stated
plainly in the kernel documentation. "Only `registry.npmjs.org`" is inexpressible.
Every implementation therefore lands somewhere unsatisfying:

- **mise**: per-host filtering is unimplemented on Linux. Its docs say `--allow-net`
  falls back to allowing everything; its code actually `bail!`s. So the docs' own
  flagship `npm install` example does not run on Linux at all. It fails closed, but the
  usable choice is still all-or-nothing — and "no network" means "no install".
- **nono, cplt**: egress unrestricted by default; blocklists and proxies are opt-in.
- **`srt` / Claude Code**: solve it properly with `--unshare-net` plus a host-side
  filtering proxy — but via bubblewrap, not Landlock, and requiring `bubblewrap` and
  `socat` to be installed.
- **`senv`** (Python/uv): the best design found — private netns plus **nftables rules
  pinned to resolved addresses**. This is the working answer to the port-only wall.

Two facts make the salida gate look worse, not better. Shai-Hulud's exfil channel was
the **GitHub API** — and every "developer" network profile allowlists `api.github.com`.
And the August 2026 ChainDrop wave resolves its C2 host from an Ethereum contract at run
time, so domain blocklisting is already dead.

---

## What was *not* found

Stated as in Part I: this is the result of ten lanes plus a critic, and absence at that
depth is weak evidence of absence. One lane exhausted its web-search budget partway
through and finished on direct source fetches; its negatives are correspondingly weaker.

1. **No published compatibility matrix** — nobody has released "which real-world npm
   installs break under a strict Landlock read-deny policy, and why." Latch's 1.6% is
   the only number, it is four years old, and it is AppArmor.
2. **No on-by-default posture.** Every tool above is a wrapper you must remember to
   type. mise's shims mode and Homebrew's `deny_read_home` are the only two exceptions,
   and neither covers a bare `npm install` on a normal machine.
3. **Nobody has solved `~/.npmrc`.** firejail — the only distro-shipped npm profile —
   contains `noblacklist ${HOME}/.npmrc` and `ignore read-only ${HOME}/.npmrc`. The
   people who already did this work concluded npm needs read **and write** on the exact
   file the thesis wants to deny. pmg allows it explicitly as a documented trade-off.
   Private-registry auth, scoped tokens and proxy config all live there.
4. **No RFC or standards work on install-time read confinement**, in any ecosystem.
   Searched npm/rfcs, npm/cli, nodejs/node, OpenSSF, OpenJS. Not rejected — absent. The
   closest is `npm/cli#9193`, an AppArmor profile plus a `deny-info-stealer` abstraction
   contributed in April 2026, closed in 15 days with one comment.
5. **No trace data that can answer the `$HOME` question.** See below.

## The measurement question (step 2), re-scoped

Two public datasets record what installs touch: **OSSF package-analysis**
(`ossf-malware-analysis.packages.analysis` in BigQuery, per-phase `Files` with
Path/Read/Write/Delete and a phase literally named `install`) and the **OSPtrack** Zenodo
dump (DOI `10.5281/zenodo.14197378`, 3.3 GB, ~4,645 benign npm packages with raw strace
logs).

**Both are structurally unable to answer the question that matters.** They were produced
by running `npm init --force && npm install <pkg>` **as root inside gVisor with
`HOME=/root`**. No developer dotfiles exist in that environment, so they cannot say
whether a benign install reads `~/.npmrc`, `~/.aws` or `~/.ssh`. They can say what npm
needs from `/usr`, `/tmp`, the cache and the toolchain — which is the part already
answered four times over by hand-tuned allowlists (firejail's `node.profile`, npm/cli
#9193's AppArmor profile, mise's `SYSTEM_READ_PATHS`, cplt's `generate_policy`).

So a real strace run on a real `$HOME` is still necessary — but **scoped to `$HOME`
access only**, not to rediscovering `/usr` and `/tmp`. Every existing hand-written
allowlist is also demonstrably incomplete: none mentions `~/.npm/_tuf` (which npm 10/11
writes for sigstore verification) or `$HOME/.cache/node/corepack`.

The strongest existing proof that a strict policy is achievable comes from Nix, not from
any security project: nixpkgs' `npmConfigHook` runs `npm ci` with `HOME="$TMPDIR"`,
`npm_config_cache` at a prefetched store path, `npm_config_offline=true` and
`npm_config_nodedir` set — npm completes with **zero** access to the real `$HOME`. Those
four environment variables are the escape valves any policy should lean on.

## Three standing objections

- **npm v12 narrowed the window this defends.** With dependency scripts off by default,
  the remaining install-time code is the scripts the developer *approves* — node-gyp,
  sharp, esbuild, puppeteer — which then run with full ambient authority. Malicious code
  migrates to first-`require`, build and test time. A policy scoped strictly to
  `npm install` now guards a door npm has already mostly shut.
- **GoLeash (2025)** argues process-level policy is too coarse and package-level
  granularity is required. Landlock-around-npm is exactly the coarse thing.
- **`Backstabber's Knife Collection`**: 34% of malicious packages are droppers that
  fetch a second stage. That makes salida — the gate nobody has solved on Linux — not
  optional.

## The one argument that survives intact

npm's accepted RFC 0054 looked directly at this gate and walked past it:

> *"Sandboxing install scripts (restricting file system or network access) is worth
> exploring separately, but it is a harder problem with more compatibility risk. An
> allowlist is simpler."*

An allowlist is a policy check in application code, and a forgotten code path bypasses
it. This is not hypothetical: **CVE-2025-69264** (CVSS 8.8) let git dependencies run
`prepare`/`prepublish`/`prepack` through pnpm's fetch phase for a year, because that
path never consulted the `onlyBuiltDependencies` allowlist. npm's own v12 notes name the
analogous "Phantom Gyp" gap, where a bare `binding.gyp` bypassed even `--ignore-scripts`.

A Landlock ruleset is not consulted by the application at all. That is the real argument
for enforcement over allowlisting — and it is an argument for *contributing* the missing
pieces to the tools above, not for building a ninth one.

## Sources

- [nono](https://github.com/nolabs-ai/nono) · [cplt](https://github.com/navikt/cplt) · [mise sandboxing](https://mise.jdx.dev/sandboxing.html)
- [Homebrew `landlock.rb`](https://github.com/Homebrew/brew/blob/master/Library/Homebrew/extend/os/linux/sandbox/landlock.rb) · [`cmd/sandbox-exec.rb`](https://github.com/Homebrew/brew/blob/master/Library/Homebrew/cmd/sandbox-exec.rb)
- [safedep/pmg](https://github.com/safedep/pmg) · [senv](https://github.com/h5i-dev/senv) · [projectkennel](https://github.com/projectkennel/projectkennel) · [landrun](https://github.com/Zouuup/landrun)
- [@anthropic-ai/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [Latch — Wolf at the Door (ASIA CCS 2022)](https://dl.acm.org/doi/10.1145/3488932.3517391) · [artifact](https://github.com/elizabethwyss/Latch)
- [Sandlock (arXiv 2605.26298)](https://arxiv.org/abs/2605.26298) · [Birdcage](https://github.com/phylum-dev/birdcage) (archived)
- [npm RFC 0054](https://github.com/npm/rfcs/blob/main/accepted/0054-install-scripts-allowlist.md) · [npm/cli#9193](https://github.com/npm/cli/issues/9193) · [pnpm#13772](https://github.com/pnpm/pnpm/issues/13772)
- [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html) · [landlock.io integrations](https://landlock.io/integrations/)
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) · [Node.js Permission Model](https://nodejs.org/api/permissions.html) · [Deno security](https://docs.deno.com/runtime/fundamentals/security/)
- [OSSF package-analysis](https://github.com/ossf/package-analysis) · [OSPtrack (Zenodo 14197378)](https://doi.org/10.5281/zenodo.14197378) · [nixpkgs npmConfigHook](https://nixos.org/manual/nixpkgs/stable/#javascript-buildNpmPackage)
