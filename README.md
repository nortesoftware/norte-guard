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

No account, no telemetry, no cloud, zero runtime dependencies.

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

Measured 2026-08-12, engine v0.3.2, over a stratified sample of 500 packages
drawn from the registry by weekly downloads.

| | rate | 95% Wilson CI |
|---|---|---|
| non-PASS in gate mode (BLOCK + WARN) | 0.20% | 0.04%-1.12% |
| BLOCK, the only verdict that fails a build | 0.00% | 0.00%-0.76% |
| unevaluated (`INSUFFICIENT_HISTORY`, exit 0) | 24.60% | 21.03%-28.56% |

**Recall is not calculable.** The corpus holds zero confirmed_malicious samples
with an artifact behind them, and "not calculable" is not "0%": one says the
detector caught nothing, the other says nothing has been put in front of it.

What is measured is **field recall**, over packages npm removed after this
collector had already scored them:

| | |
|---|---|
| packages removed by npm | 73 |
| observed before removal | 4 (5.48%, CI 2.15%-13.26%) |
| with a score recorded at publication | 2 |
| blocked by the gate | **0 of 2** |

Two cases is not an estimate. It is two cases, and both were the class the tool
does not cover. Method and caveats: [docs/benchmark.md](docs/benchmark.md).

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

Details: [docs/methodology.md](docs/methodology.md).

## Why not Socket, Aikido or Snyk

They are cloud services that need an account and see your lockfile, or CVE
databases that cannot see a zero-day. norte-guard runs locally with no
dependencies.

And one thing none of them prints: **what it does not cover.** A tool that
claims everything is a tool you cannot calibrate against, because there is
nothing it would admit to missing.

## Security

norte-guard is a supply-chain tool, so it is also a target. Threat model,
capture handling and the self-verification plan: [SECURITY.md](SECURITY.md).

MIT License - Norte Software <hola@nortesoftware.dev>
