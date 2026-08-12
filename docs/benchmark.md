# Benchmark and calibration

## `bench` — public, reproducible benchmark

```bash
norte-guard bench

no-PASS gate  0.20% (IC 95% Wilson: 0.04%–1.12%, n=500)
              BLOCK 0 (0.00%, exit 1) · WARN 1 (0.20%, exit 0)
unevaluated   24.60% (95% Wilson CI: 21.03%-28.56%, n=500)
              INSUFFICIENT_HISTORY: informational, exit 0, does not fail the build
              source: fp-bench-results/2026-08-12-v0.3.0.json (stratified sampling)
Recall        not calculable, 0 confirmed_malicious samples
              corpus building since 2026-08-12: 30 captures, 0 confirmed
              30 captures excluded from every benchmark (captured with the broken gate)
```

**Two headline numbers, never one.**

`no-PASS` is BLOCK + WARN: findings about the package, and the cost of adopting
the gate. `sin evaluar` is `INSUFFICIENT_HISTORY`: the share of the ecosystem the
tool has no baseline to judge. They are different failures and they get fixed by
different work — the first by calibration, the second by more signal.

Collapsing them into a single "non-PASS" reported a coverage gap as a
false-positive rate. Dropping the second would hide the gap altogether. So both
ship, under their own names, with the exit code each one produces.

Two rules decide what that block can say:

**The malicious corpus is `.ngpack` snapshots, never a list of names.**
`keyv@6.0.0` and the rest were purged from npm within two hours of publication.
A corpus that has to download them is a corpus that cannot run, so the samples
come from local snapshots read through `NgpackSource`. The publicly documented
attacks with no snapshot are printed as a work list — they count neither as a
hit nor as a miss, because a version that cannot be analysed cannot be detected
or missed.

**Recall is computed over `confirmed_malicious` and nothing else.**
Every capture is labelled: `confirmed_malicious`, `confirmed_benign`, or
`unconfirmed`. Promotion requires an external source — an npm advisory, a public
report, or content analysis. A high score is why a capture was kept, not
evidence of what it is: an attack nobody detected also sits quiet.

With zero confirmed samples the output says **`no calculable`**, never `0%`.
Those are different claims. One says the detector caught nothing; the other says
nothing has been put in front of it yet.

**Provenance is part of the sample.** Every capture records which engine selected
it and why. Captures taken while the gate was scoring packages against a genome
they did not have are marked `pre-fix-gate-bug` and held out of every benchmark,
even if an advisory later confirms one of them: a corpus assembled by a detector
with a known bug is a draw from what that bug flagged, not a draw from the
ecosystem, and nothing downstream can correct for a bias it cannot see.

Every rate carries a Wilson interval. The normal approximation puts the lower
bound below zero at exactly the sample sizes this project works with.

```bash
norte-guard corpus                    # what is captured, labelled, and held out
norte-guard label <dir> \             # promotion always needs a source
  --label=confirmed_malicious \
  --source="npm advisory GHSA-xxxx / Aikido 2026-08-04"

norte-guard corpus --backfill \       # retroactive provenance, never overwrites
  --engine-version=0.2.0 --dry-run
```

## `fp-bench` — false positives at scale

```bash
npm run fp-bench                      # top N of the harvested pool
npm run fp-bench -- --stratified      # 50 per download decile
```

The top N is a sample of the best-maintained packages in the ecosystem: long
histories, automated releases, dense genomes. False positives live in the tail,
so `--stratified` samples every decile of the download distribution and reports
the rate per decile. Packages whose download count fails to resolve are excluded
rather than ranked at zero — a failed lookup is not a package nobody installs.

Every run is written to `fp-bench-results/<date>-v<version>.json` with the
keyword pool, n, engine version, thresholds and the per-package, per-signal
result. Calibration is a sequence of deltas, and a delta needs the previous run
to still exist.

The sample is assumed clean and never verified. A compromised package inside it
would be counted as a false positive while being a hit, so the reported rate is
an upper bound on the error, not a measurement of it. That declaration ships in
the output and in the saved artifact.

## Drift

A detector degrades in one direction only: toward passing everything. Each
false-positive fixed lowers a weight, mutes a signal or raises a threshold, and
none of those edits looks wrong on its own. The sum does.

Two things watch for it, because a false-positive benchmark cannot:

**`npx vitest run test/gate-drift.test.ts`** — the sample that must never stop
blocking: `keyv@6.0.0` reduced to what layer 1 can see, an install script that
never existed across 48 versions plus a tarball 25× the historical size. It
currently scores 80 against a threshold of 70, a margin of 10, and the test names
each carrying signal so a future edit that mutes one fails with *which*, not just
"it stopped blocking".

**`BLOCK = 0` prints an alert on every fp-bench run.** Zero blocks on a sample
assumed clean is the outcome this benchmark is designed to reward, and it is
also exactly what a detector that has stopped detecting looks like from here.
The sample cannot tell those apart — only the synthetic one can — so the run
says so instead of leaving the reader to infer it. It is an alert, not a failure,
and it travels in the artifact as well as the terminal.

## Thresholds come out of the distribution, not out of a round number

`fp-bench` reports what clean packages actually score, split by regime, so a
capture or block threshold can be derived instead of chosen:

```
Score distribution, sample assumed clean
  no-genome    n=123   p50=0     p90=0     p95=18    p99=20    max=38
  genome       n=377   p50=-15   p90=15    p95=25    p99=35    max=45
```

It also reports the histogram, because the percentile rule has a precondition
that the distribution has to meet. When the absolute-risk branch had only two
signals the no-genome score took **two** values, 0 and 20 — so `p99 = 20` was not
a 1-in-100 cut point at all: a threshold of 20 captured 7.7% of new packages and
a threshold of 21 captured none. The tool detects that case and says so instead
of handing back a number that merely looks derived.

Widening the branch took the same distribution to **twelve** values from 4 to 37,
which answered the question the histogram existed to ask: the problem was the
number of signals, not the rule.

Then the two signals that fired on 95.6% and 77% of new packages were zeroed, and
the distribution settled at **seven** values with **111 of 123 packages at exactly
0**. That is the honest shape. The earlier spread was manufactured by a constant
offset that carried no information: every new package got the same +10 for being
a new package. Now a score of 0 means nothing notable was found, and any non-zero
score means at least one genuinely uncommon signal fired.

What the same run says about the new signals, measured over the 113 packages
with no genome:

| Signal | Fires on | Weight |
|---|---|---|
| `absolute_no_provenance` | 95.6% | **0** — informational |
| `absolute_single_maintainer` | 77.0% | **0** — informational |
| `absolute_publisher_not_maintainer` | 5.3% | 18 |
| `absolute_install_script` | 3.5% | 20 |
| `absolute_no_repository` | 3.5% | 7 |
| `absolute_typosquat_distance_2` | 0.9% | 12 |
| `absolute_no_readme` | 0.9% | 6 |

The first two are the baseline state of a new npm package, not a finding about
this one. They fire on nineteen and eight packages out of ten respectively, so
they describe the registry rather than the package — and no weight makes a
near-constant discriminate. They are scored at **0** and kept as informational
rather than re-weighted.

The version of the provenance question that does discriminate is its inverse:

**`provenance_lost` (35)** — the previous version was signed and this one is not.
Absence of provenance is the state of 95.6% of the registry; *losing* it is a
break in a run this package had already established. It is what a publish with a
stolen token looks like from the outside, because the credential that publishes
is not the pipeline that mints the attestation. Both versions are already in the
packument, so it costs nothing. It applies under both regimes: "no genome" means
no capability baseline, not necessarily no previous version.

## The watcher has a capture budget, not a detection threshold

The number the watcher runs with is `captureBudgetThreshold`, and the name is the
correction. It decides how much disk and bandwidth the collector spends. It does
not decide what norte-guard detects — that is the scorer and the gate/audit
thresholds in `types.ts`, calibrated against fp-bench.

It is **never derived from the publication stream**, because that is circular: a
campaign in progress raises the scores in the stream, which raises the
percentile, which raises the cut-off. The collector would relax itself on exactly
the day it should not. A percentile of the live stream can only say what is
normal right now, and what is normal right now is the thing an attack changes.

Two attempts got this wrong before the name did. `p99 = 31` was derived from the
fp-bench sample — a different population, sampled by weekly downloads — and
applied to the stream, where it captured **26 of 98 publications (26.5%)** instead
of the predicted 1.4%. Re-deriving it from the stream itself fixed the population
and kept the circularity.

So it is a fixed number chosen for what it costs: **44**, provisional, keeping
captures near 1–2% of publications at the rate measured on 2026-08-12. The
watcher still records the score of every publication to `changes-log.ndjson`, and
`norte-guard scores` reports what each budget would cost — a question about disk,
which is the only one those percentiles can answer.

---
