# Benchmark and calibration

## `bench` — public, reproducible benchmark

```bash
norte-guard bench

non-PASS gate 0.60% (95% Wilson CI: 0.20%-1.75%, n=500)
              BLOCK 0 (0.00%, exit 1) - WARN 3 (0.60%, exit 0)
unevaluated   23.00% (95% Wilson CI: 19.53%-26.89%, n=500)
              INSUFFICIENT_HISTORY: informational, exit 0, does not fail the build
              source: fp-bench-results/2026-08-16-v1.2.0.json (stratified, engine v1.2.0)
              the fabricated-profile rule has no candidate in this sample
Recall        0.00% (95% Wilson CI: 0.00%-32.44%, n=8) - 0/8 confirmed_malicious
              the fabricated-profile rule is opt-in and was off for this run, so
              every sample of that class counts as a miss. Turning it on does not
              raise this number either: their snapshots carry no download count.
Field recall  0/9 blocked by the gate, 0/9 by audit
              as scored at publication, by whatever engine was running that day
  re-graded   not calculable: 9 samples, 7 the rule cannot judge, 2 with no snapshot
```

**A saved rate declares the distance to the engine quoting it.**

`bench` reads the most recent `fp-bench-results/` artifact. For two days it read
one measured on v0.3.2 with the fabricated-profile rule switched off and printed
its 0.20% next to v1.1.0 with the rule on, and nothing in the output said so. A
rate is a measurement of a specific engine under a specific config, so the run
now declares every way the two differ, and says `STALE` when they do.

An artifact saved before a flag existed cannot say what it ran under. Absent is
reported as absent rather than read as `false`: guessing on the file's behalf is
the same error one level down.

**A benchmark also declares what it cannot measure.**

`fp-bench` draws its sample by weekly download rank, which is the right frame for
"what does the gate cost on the dependencies people actually have". It is the
wrong frame for the fabricated-profile conjunction, which fires only on a name
under seven days old with zero weekly downloads — a package that by construction
cannot rank. In the 2026-08-16 run, 0 of 500 packages had a name under seven days
old and 0 had zero downloads, so **no package in the sample could have matched**.
Its 0% is not evidence the rule is safe; it is evidence the sample holds nothing
the rule could fire on, and the run now says so rather than leaving it to be
inferred from a comment.

Measuring that rule needs a sample of *legitimate brand-new packages*. The
quarantine stream already collects exactly that population — see the precision
block below.

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

**Field recall is two numbers.** `computeFieldRecall` grades the decision the
collector made at the time, read out of `changes-log.ndjson`. That is the only
honest answer to "was this caught when it happened", and it is not an answer to
"would this be caught now" — the log line was written by whatever engine ran that
day, under rules that may not have existed. Worse, the collector logs one *audit*
verdict per publication and never passes a download count into the scorer, so the
fabricated-profile rule can never appear on that path: a zero out of that number
is a fact about the log format.

So the second number is computed rather than read. Each sample is re-run through
the engine in this build, against the `.ngpack` captured at the time and dated to
the capture, so what differs between the two numbers is the engine and nothing
else. Samples the rule cannot judge are held out of the fraction, for the same
reason recall holds them out: a rule that declined to apply is not a rule that
was wrong.

**Provenance is part of the sample.** Every capture records which engine selected
it and why. Captures taken while the gate was scoring packages against a genome
they did not have are marked `pre-fix-gate-bug` and held out of every benchmark,
even if an advisory later confirms one of them: a corpus assembled by a detector
with a known bug is a draw from what that bug flagged, not a draw from the
ecosystem, and nothing downstream can correct for a bias it cannot see.

Every rate carries a Wilson interval. The normal approximation puts the lower
bound below zero at exactly the sample sizes this project works with.

## Two criteria, and they are not the same criterion

Two things in this project were both called "the four free conditions":

**The capture filter** — no genome, name under seven days, under 100KB, no
repository. It decides what the collector keeps, and it is what
`captureReason=quarantine-no-genome` records.

**The fabricated-profile rule** — those four *and a fifth*, zero weekly
downloads, which the rule declines to apply without. It is what fails a build.

They were being read as one, and that produced a contradiction that shipped:
`track` reported "8 confirmed removals, PROMOTABLE to default" while `bench`
reported the same eight as unjudgeable. Both were right about their own
criterion. The eight are removals of packages the *filter* kept; whether the
*rule* would have blocked them is unknowable, because their snapshots carry no
download count and npm serves one complete week at a time.

So each record now declares which criterion it is evidence for — `rule-matched`,
`vacuous-zero`, `rule-cleared` or `unverifiable` — and the promotion criterion
counts only removals the rule itself would have caused.

The fourth state is not a refinement. npm answers **404** for a package published
minutes ago, which is what this class is made of, and `downloads.ts` reads that as
zero because for a verdict it is one. Checked against the live endpoint: three of
four freshly published quarantine names return 404, and `async-critical-section`
returns a genuine zero over a week that closed four days before it was published.
Graded as a match, a restarted collector would clear the three-removal promotion
bar out of three 404s inside a day — the same mistake one level down. A zero over
a window the package was not alive for is arithmetic, and it promotes nothing.

**The criterion also has to survive being read early.** npm removes a fabricated
package within hours, so every true positive arrives on day one. A false positive
is *defined* as thirty days alive and installed by somebody, so none can arrive
before day thirty. A criterion that simply counts both therefore reports
PROMOTABLE on day three for any rule at all, including one that blocks nothing
but ordinary new packages. Packages already alive with real usage now count
against promotion before their thirty days are up.

## `corpus` — the precision denominator

A count of confirmed removals is a numerator looking for a denominator. Eight out
of fifty and eight out of fifteen hundred are opposite conclusions about the same
filter, so `corpus` reports the fraction:

```
PRECISION OF THE CAPTURE FILTER (4 conditions, captureReason=quarantine-no-genome)
  marked                          1509 packages in 2329 captures
  removed by npm                  8
  alive with >=10 weekly downloads  4  (of 19 ever queried)
  precision                       0.53% (95% Wilson CI: 0.27%-1.04%, n=1509)
  precision at >=30d               not calculable: 0 of 1509 have reached 30 days
  oldest marked 3.2 days, median 2 days
```

The unit is the **package**, not the capture: the same name is captured again on
every publication, so counting captures multiplies whichever packages publish
most and turns a precision into a publishing-frequency artifact.

The maturity line is not decoration. With the oldest marked package at 3.2 days,
nothing in that denominator has had time to resolve, and for the reason above the
number counts every hit and almost no miss — it is an upper bound that will fall.
The mature fraction is reported separately and says `not calculable` until
packages are old enough for it.

"Alive" is measured only over packages the tracker has actually queried, over its
own denominator, and the output says it must not be scaled up to the rest.

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

## Analyzability — the size of the blind spot

`norte-guard analyzability`, measured over the whole corpus on 2026-08-16, engine
v1.2.0: 1,593 captures, ~20 minutes, offline.

**The first result is about the corpus, not the detector.**

| | |
|---|---|
| uncontaminated captures | 4,855 |
| still holding their tarball | 1,593 |
| **no tarball bytes left** | **3,262 (67.19%)** |
| confirmed_malicious with bytes | 2 of 8 |

Two thirds of what this project calls its corpus is a manifest and a packument
with nothing behind them, and six of the eight confirmed attack samples are among
them. Nothing reported it for weeks because layer 1 analyses the packument and
never asks for the artifact, so a capture whose bytes are gone analyses exactly
like one that still has them. `hasTarball` on `CorpusSample` meant "the manifest
declares a version" and was read as "the bytes are here"; `tarballPresent` is the
one that checks.

**Where the bytes went, and it is a bug.** Four hypotheses were tested against
the ledger the object store keeps:

| | |
|---|---|
| distinct objects ever written | 4,237 |
| gone from disk | **3,169 (9.2 GB)** |
| on disk but absent from the ledger | 0 |

Every capture without bytes declares `objects: {version: hash}` in its manifest,
and `createNgpack` writes that field only after `putObject` has returned — so the
bytes were stored, every time. That rules out the three capture-time
explanations: a streaming mode that keeps only a file list, a daily budget that
runs out and keeps writing metadata, and a silent download failure. It also rules
out the quarantine policy: `quarantine-no-genome` keeps **33.5%** of its bytes
and `watcher-threshold` keeps **33.7%**, which is the same number, so nothing
about quarantine is deciding this.

The loss is a single event, not attrition:

| day objects were written | written | gone | survived |
|---|---|---|---|
| 2026-08-12 | 610 | 610 | 0 |
| 2026-08-13 | 1,761 | 1,761 | 0 |
| 2026-08-14 | 798 | 798 | 0 |
| 2026-08-15 | 883 | 0 | 883 |
| 2026-08-16 | 185 | 0 | 185 |

Everything the store held before 2026-08-15 is gone and everything after it
survives. Rotation deletes oldest-first until it is under a cap and would have
left a partial day; this left none. The 30 oldest captures, which predate the
object store and hold their tarballs inline, are at **100%** — so it is the store
that was emptied, not the captures. `deleteObject` and `listObjects` did not
exist before commit `25d590b` (2026-08-14 23:32), which falls inside the window
between the last deleted write and the first surviving one.

Both deleters protect what a manifest references, so the arithmetic was not
wrong: the reference set came back empty or near-empty and the loop believed it.
`collectOrphanObjects` now refuses outright when more than half the store looks
unreferenced, and says so, because that is the shape of a scan that could not read
the captures rather than of a store full of orphans — and this store is the only
copy, since npm removes these packages within hours.

**Coverage of the executable surface**, over the 1,593 that can be read:

| | |
|---|---|
| by bytes | **9.21%** |
| median capture | **100.00%** |
| fully covered | 921 |
| nothing covered at all | 123 |

Those two headline numbers disagree by a factor of ten and both are correct. The
byte figure is dominated by 10.9 GB of native binaries in 848 files; the median
is one vote per package, and most packages are a handful of small readable
modules. Neither replaces the other, and quoting one as "coverage" without the
other is the error the pair exists to prevent.

```
0%        123      0-50%  269      50-90%  90      90-99.9%  72      100%  921
```

**Why the rest is not covered.** Captures with at least one such file; a file
carries every reason that applies, so the columns overlap and are not a
partition:

| reason | captures | files | bytes |
|---|---|---|---|
| minified | 12.18% (10.66–13.88) | 122,779 | 760.9 MB |
| dynamic-require | 11.11% (9.66–12.75) | 626 | 210.2 MB |
| native-binary | 9.86% (8.49–11.42) | 848 | 10,886.5 MB |
| foreign-script | 9.42% (8.08–10.95) | 3,646 | 36.2 MB |
| dynamic-eval | 7.34% (6.16–8.73) | 327 | 328.5 MB |
| not-javascript | 2.26% (1.64–3.11) | 52 | 0.5 MB |
| bytecode | 1.95% (1.37–2.75) | 31 | 480.1 MB |
| wasm | 1.69% (1.17–2.45) | 105 | 416.2 MB |
| parse-failure | 1.38% (0.91–2.08) | 133 | 0.7 MB |
| too-large | 1.26% (0.81–1.93) | 23 | 408.9 MB |

**The question as asked — what fraction of new npm packages ships a binary, WASM,
bytecode or unreadable minified code:**

> **23.04%** (95% Wilson CI: 21.04%–25.17%, n=1,593)

Close to a quarter of the publish stream carries something layer 1 cannot read at
all. That is the ceiling to declare before building on top of it.

`foreign-script` was 795 files until a shell script with no `#!` line was found
to be falling out of the denominator as "other". An install script is the most
direct way a package runs code on a machine, so the extension counts as well as
the shebang, and 2,851 more executable files came into view. A held-out file is
invisible twice over: it is neither covered nor a reason.

**Parse failure is 1.38%, and it is the number that most needed splitting.**
A file that defeats a conforming parser is broken or built to be. A `.js` that is
really TypeScript, JSON or HTML is a packaging habit — `not-javascript`, 2.26%.
And acorn's own recursion guard gives up past roughly ten thousand nested terms,
which is a limit of this tool and not a property of the package —
`parser-limit`. Collapsing the three would have reported the second and third as
adversarial on the first run.

**The eight confirmed samples.** Six have no bytes. Of the two that remain,
`svelte-goal-vim@1.0.0` is fully covered — three small `.mjs` files — and
`kit-hydration-vim@1.0.0` is **7.22%** covered, because
`package/dist/internal/calc.dat` is 63,616 bytes beginning `\x7fELF`. It is 93%
of that package's executable surface, and it is wearing a data file's extension.
A classifier that read the name would have held it out of the denominator and
called the package fully covered.

So: **1 of 2 analysable, and 1 of 8 in total.** The approach is not dead for this
class, but the corpus can only answer the question for a quarter of it, and the
reason is lost artifacts rather than obfuscation.

## A 2.4MB package that costs 2.2GB to analyse

The corpus pass kept dying. `analyzability --by-class --since=2026-08-15
--sample=250` ended in `FATAL ERROR: Ineffective mark-compacts near heap limit`
— on a 4GB machine, with an input the tar reader had already bounded.

**The capture.** `@async23/chrome-devtools-mcp@1.7.0`: a 2.4MB tarball, 13.2MB
unpacked, 337 files, of which 75 are JavaScript totalling 12.8MB. The
reachability pass bounds itself at 600 files and 16MB of source, so it accepted
this one. Two files carry it: `third_party/index.js` at **7.45MB** and a
Lighthouse bundle at 3.89MB.

**It is not the syntax tree.** Measured one file per process: the 7.45MB file
parses to a **213MB** tree with `locations: true`, 28.6× its source. Large, and
nowhere near a heap limit.

**It is the lost-trail list.** `merge()` in `reachability.ts` unions two Values.
Its `origins` half deduplicates by key and stops at 64 — a fix made earlier,
after a different crash, and documented in a comment right above the function.
Its `lost` half did neither: it appended, on every union, with no dedup and no
cap. A value that loses its trail once and then flows through a chain of
assignments and calls carries a copy per route, and the copies compound. On this
file:

| | |
|---|---|
| lost points actually emitted | 14,853 |
| distinct `(reason, line)` pairs among them | 3,744 |
| entries in the array at the end | **35,110,656** |
| merges, and entries they copied between them | 210,699 / 125,721,046 |
| largest single merge | 2,271,170 entries |

Bisected to the statement: slicing the file at top-level statement boundaries,
the analysis costs 236MB of heap through statement 4,650 and dies past
statement 4,700 — the 127KB in between is a combinator library, where the same
values flow through thousands of call sites. Growth is not gradual. It is
roughly a doubling per statement across that stretch.

**The fix is the one the comment above `originKey` already describes**, applied
to the other half: dedup by `(reason, file, line, detail)`, cap the per-value
list at 64 and the per-module list at 2,000. Deduplication here is lossless —
two lost points with the same reason, file, line and detail are the same fact
recorded twice. Afterwards the same capture analyses in **13 seconds and 118MB**,
with 41 reachable modules and 2,858 lost trails, and the full `--sample=250` pass
completes.

**It is a denial-of-service vector against any static analyser of npm, not just
this one.** 2.4MB of download, published by anyone, forces gigabytes in a
process that only meant to read it — and the shape that triggers it is an
ordinary bundled combinator library, not something built to attack. Every
analyser that propagates a diagnostic list along a dataflow merge has the same
exposure. Note also that the `lost trails` counts printed by earlier runs were
counting copies: they are not counts of distinct lost trails.

## The class is not more legible. That was the size cut reading itself.

`analyzability --by-class` reported the quarantine class at **93.32%** byte
coverage against **9.79%** for the watcher-threshold segment, and
`child_process` reachable in **17.14%** of the class against **36.87%** outside
it. Both numbers are real and neither is a fact about the class.

**The class is defined as "under 100KB unpacked."** A native binary, a WASM
module, a V8 bytecode cache and a webpack bundle do not fit in 100KB. The
comparison segment is selected on a high score, which is enriched for exactly
those. So the first table compares a cut that excludes opaque things against a
cut that concentrates them, and the module table inverts for the same reason:
bigger software reaches more modules.

`analyzability --size-control --since=2026-08-15 --draw=200` asks the question
the other one cannot. Every group is under 100KB, in the same window, matched to
the class's own size distribution decile by decile, and differs from the class in
**one conjunct of its definition**. Run 2026-08-17, v1.2.1:

| group | n | fully legible | ships opaque | coverage by bytes |
|---|---|---|---|---|
| class, from disk (census) | 762 | 85.17% | 4.59% | 91.47% |
| class, from the registry | 152 | 86.84% | 5.26% | 92.98% |
| class **+repository** | 171 | 91.23% | 3.51% | 89.38% |
| class **+age** | 169 | 79.29% | 9.47% | 91.29% |
| **maintained** (genome, old, repo) | 183 | 85.25% | 7.65% | 93.26% |

Ordinary maintained software under 100KB is **85.25%** fully legible. The class
is **85.17%**. The difference is **-0.1pp (95% CI -5.2 to +6.2)**, inside the
±10pp equivalence margin declared before the run.

**Every legibility difference in the table includes zero** once the interval is
widened for the ten endpoint comparisons the run prints (Bonferroni, z=2.81) —
including the two that excluded it at a bare 95%. The finding is withdrawn.

The gap between 93.32% and 9.79% was the 100KB cut. Below 100KB there is very
little to be unable to read, whoever published it.

**The module claim goes with it.** `child_process` differs by +6.9pp against
maintained software (95% CI -6.8 to +15.9, widened for the 708 modules in that
table) — it includes zero in every comparison the run makes. Two module rows do
survive their own adjustment, and only against the far corner: the class reaches
`fs` **+23.0pp** (+8.0 to +33.4) and `os` **+13.7pp** (+1.9 to +20.8) more often
than maintained packages of the same size. Against the one-conjunct neighbours
both include zero. Whatever that is, it is not the thing that was quoted.

**Acquisition was measured rather than assumed.** The class was run through both
paths — the captures taken at publication, and a fresh draw from
`changes-log.ndjson` fetched from npm days later. They agree to **-1.7pp
(-6.9 to +5.0)**, so the corpus is not distorting the class's legibility.

### What did survive the control

npm had already removed part of each group by the time the control ran, and the
attrition is not spread evenly:

| group | gone from npm 1-2 days after publication |
|---|---|
| class | **12 of 200 — 6.0% (3.5-10.2%)** |
| class +repository | 2 of 200 — 1.0% (0.3-3.6%) |
| class +age | 0 of 195 — 0.0% (0.0-1.9%) |
| maintained | 0 of 195 — 0.0% (0.0-1.9%) |

**+6.0pp against maintained (95% CI +2.8 to +10.2, excludes zero)**, at the same
size, in the same window, one conjunct at a time. The class does separate from
the ecosystem — on removals, which is what it was built to select for, and not
on how readable its members are.

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
