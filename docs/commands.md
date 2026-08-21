# Commands

Full reference. `norte-guard --help` prints the same list.

## `inspect` — analyze a package before installing it

```bash
norte-guard inspect keyv@5.6.0
norte-guard inspect keyv@5.6.0 --mode=audit
norte-guard inspect keyv@5.6.0 --json
```

**Exit code 1** when verdict is `BLOCK` — use directly in CI:

```yaml
# GitHub Actions — gate before installing a new dependency
- run: npx norte-guard inspect $PKG@$VERSION
```

**Three possible verdicts:**

`INSUFFICIENT_HISTORY` **exits 0.** It was 22.6% of a 500-package sample, and a
gate that stops one build in five on packages it simply has no baseline for is a
gate that gets switched off — at which point its recall is zero regardless of
what the benchmark says. Lack of context is not evidence of risk. It is reported
as an advisory, not converted into a failure; `--strict-new-packages` gives the
hard behaviour to teams that want it.

| Verdict | Meaning |
|---------|---------|
| `BLOCK` | Clear anomalies in the genome — do not install |
| `INSUFFICIENT_HISTORY` | New package, no history — evaluate manually |
| `PASS` | No anomalies in the analyzed signals |

> norte-guard never says "safe". It says what it analyzed and what it didn't.

## `approve` — solve the task npm 12 created for everyone

npm 12 disabled install scripts by default. You now need to explicitly approve which ones can run. norte-guard reads your lockfile and classifies automatically:

```bash
norte-guard approve

norte-guard approve  47 packages with install scripts

APPROVE (41)
  + esbuild@0.20.0
    install script across 482 historical versions
  + sharp@0.33.0
    known native compilation package

REVIEW (5)
  ? my-package@1.0.0
    short history (3 versions)

BLOCK (1)
  - package-x@2.0.0
    install script that NEVER existed before
```

## `watch` — the collector

The source is the registry's replication cursor, not the RSS feed.

RSS is a fixed 50-entry window polled once a minute. When npm publishes more
than 50 packages inside a poll interval the window rotates completely and
everything that fell off was never seen — not delayed, not retried, gone. In one
54-poll run that happened 17 times. `_changes` is a cursor: every change carries
a sequence number, the server returns everything after the one you hand it, and
the cursor is persisted to `.last_seq` after the work, so a crash replays rather
than skips.

What `replicate.npmjs.com` actually supports, probed rather than assumed:

| Request | Result |
|---|---|
| `_changes?since=<seq>&limit=<n>` | `200` |
| `_changes?feed=continuous` | `400 Bad Request` |
| `_changes?include_docs=true` | `400 Bad Request` |
| `_changes?since=now` | `400 Bad Request` |
| `_changes?heartbeat=...` | `400 Bad Request` |

The engine behind that host is `npm-replicate`, not CouchDB, and it implements
only the paged form — so the default path is a paged cursor with the same
delivery guarantee and poll latency instead of push. The continuous streaming
implementation is kept and selected automatically wherever it does work (a
self-hosted CouchDB mirror, or npm restoring it); the capability probe runs at
startup and prints which one is in use.

Without `include_docs` a naive consumer would fetch a full packument per change —
around 112 a minute, most of them for dist-tag edits. Each change is filtered
first against the abbreviated document, an order of magnitude smaller, and the
full packument is fetched only when the `latest` tag has actually moved. Pages
are processed with bounded concurrency and coalesced per package, which is what
keeps the cursor level with the feed rather than falling steadily behind.

Three things are logged because they are the only observables that would ever
reveal loss: **backlog** (how many sequence numbers behind the tip), **cursor
rewind** (which should be impossible), and the full **enumeration** of every
change to `changes-log.ndjson` — so whatever the analysis skips or fails on, the
record that it happened survives with its sequence number.

## What gets kept, and for how long

Two independent reasons to keep a tarball, because disk spend and corpus policy
pull in opposite directions and one number cannot serve both.

**Capture budget** — a score cut-off, per regime: 50 under `genome`, 20 under
`no-genome`. The two regimes score on different scales, and a single cut-off at
50 kept the loud packages while discarding the class that later turned out to be
malware. It is fixed, chosen for what it costs, and never derived from the stream.

**Quarantine** — everything matching the shape of the removals actually observed:
no genome, name under 7 days old, under 100 KB, no `repository` field. Kept
regardless of score, deleted after 7 days unless something confirms it. An
unfiltered version of this cost 172 MB a minute, almost all of it new packages
that were merely large; large new packages are not the class.

A hard daily download budget (2 GB) stops the collector fetching tarballs when
spent — it keeps enumerating and scoring — and captures rotate out oldest-first
past a total cap. Neither ever deletes a capture someone has labelled.

```bash
norte-guard watch --i-understand-the-risks --total-cap=40 --daily-gb=4
norte-guard budget          # what is on disk, against the cap, without starting anything
norte-guard watch --help    # the collector's flags, and nothing else
```

**The total cap defaults to 10 GB and rotation runs at startup only.** A running
collector never deletes, however far past the cap it goes; the deletion happens
the next time it starts, before the first capture, so a run that begins over the
cap frees space instead of adding to it. That means the moment to think about the
cap is the restart, and `norte-guard budget` prints what that restart would
delete, by name, before it happens.

`--total-cap=<GB>` sets it. `--max-gb=<GB>` is the old name and still works.

### The score path does not download everything it selects

`--max-capture-mb=<n>` (default 8) bounds the largest package the score path
fetches the bytes of, by the **unpacked size the packument declares** — the only
size knowable before paying for the download. Quarantine has its own cap and is
never refused by this one: the class it selects is under 100 KB by definition.

The measurement behind the number: 10% of `watcher-threshold` captures hold 81%
of that segment's bytes, and they are the captures the analyser can read least —
byte coverage 9.79%, 16% shipping a native binary, 34.8% shipping unreadable
minified code. Those are gigabytes of bytes nobody can look at.

**The packument is captured anyway, and that is the condition on the cap rather
than a detail.** An analyser that stops capturing large binaries stops being able
to measure its own blind spot. So a refused capture keeps its packument, its
manifest and its metadata, and records:

```json
"tarballRefused": { "reason": "over-capture-cap", "unpackedSize": 4811350, "capBytes": 8388608 }
```

which is what separates a refusal from a loss. Both are a capture with no
tarball; one is a knowable exclusion carrying the size that caused it, and the
other is a defect.

`analyzability` then reports the headline rate twice — over the captures it could
look at, and bounded over the complete population:

```
SHIPS A BINARY, WASM, BYTECODE OR UNREADABLE MINIFIED CODE
  5.62% (95% Wilson CI: ..., n=445)

  104 captures were refused for size ... Over the complete population of 549:
    at least 4.55% (none of the refused ships one)
    at most  23.50% (all of them do)
```

**The width of that bound is exactly the fraction refused**, so the cap is a
direct trade between disk and how much the corpus can still say. Measured on this
corpus:

| cap | refused | measured over what was kept | bound over everything | bytes saved |
|---|---|---|---|---|
| 8 MB | 18.9% | 5.62% | 4.55%–23.50% | ~96% |
| 16 MB | 13.1% | 8.81% | 7.65%–20.77% | ~87% |
| 32 MB | 8.2% | 12.50% | 11.48%–19.67% | ~67% |
| none | 0% | 19.31% | 19.31% | — |

The refused captures are not unknown — they are known to be large, and large is
strongly associated with the thing being measured: among captures over 8 MB taken
before the cap existed, **78%** ship an opaque executable, against 5.6% of those
under it. That is a calibration, not a measurement, and it decays as the corpus
ages away from the pre-cap sample; `tarballRefused.unpackedSize` is kept so the
refused population can always be re-described by size.

### Retention is written into the capture, not read from the policy

Each quarantine capture carries its own `retainUntil`, computed when it was
taken, and the sweep reads that date rather than today's policy. A capture
carries its own terms — which is right, and has one consequence that cost this
project its corpus clock: **raising `--quarantine-days` does nothing for the
captures already on disk.**

Retention was 7 days. A verdict takes 30 (`VERDICT_AFTER_DAYS`). So no
unconfirmed capture of the observed class ever reached the age at which its
answer arrives, and the n=2 evidence bottleneck was the retention policy rather
than the capture filter. The class costs **12 KB per capture** and 40 MB in
total; the constraint was never disk.

```bash
norte-guard budget --extend-quarantine=45 --reason="why"          # dry-run
norte-guard budget --extend-quarantine=45 --reason="why" --apply  # writes
```

Dry-run by default, unlike its neighbours in `budget`, and deliberately:
`--reset` moves a counter, this changes the terms recorded on evidence. It

  - **measures from the capture, never from now.** A capture taken five days ago
    with 45 days of retention has 40 left. Measuring from now would hand the
    oldest captures — the ones closest to an answer — the longest extension.
  - **never shortens.** A capture already retained longer is counted and left
    alone, so a second run is a no-op and a wrong number cannot delete anything.
  - **records what it did**, one line per capture in `retention-log.ndjson`
    (package, version, from, to, reason, when), and `retainUntilSource` in the
    capture's own metadata — so a snapshot read on its own says why its clock
    does not match the policy that took it.
  - **survives the collector running.** A capture being written while it scans
    reads as half a file; those are counted as unreadable and skipped.

The number the cap compares against is **the bytes under `captures/`** — the
capture directories and the shared object store beneath them. It is not the
total in the object store's index: `index.ndjson` is append-only and records
every object ever written, including the ones a wipe has already taken, so it
reads gigabytes above what is on the disk. On this corpus the two are 12.24 GB
(ledger) against 9.76 GB (disk).

A cap that is not a positive number is refused by both the flag parser and the
rotation itself. `--total-cap=oops` used to parse to `NaN`, and nothing is ever
under a `NaN` cap: the rotation loop would have deleted every unconfirmed
capture on the disk.

Tarballs live in a content-addressed store, `captures/objects/<sha256>`, so the
same bytes captured twice cost nothing the second time and the file name is its
own integrity check. They are stored exactly as the registry served them:
recompressing an already-gzipped tarball gains nothing and breaks the byte match
against `dist.integrity`. The append-only logs are the opposite case — one
repeated shape per line, tenfold compressible — so they rotate daily and closed
days are gzipped.

If the feed fails repeatedly the watcher degrades to RSS and says so in a box
that explains what that costs.

## `analyzability` — what can be looked at at all

Runs before any detector, offline, over the `.ngpack` captures already on disk.
It **detects nothing**. It measures how much of a package a static analyser can
read, because every detector this project has reports PASS on what it could not
read — the correct default for a gate, and a lie about coverage unless somebody
publishes the size of the blind spot.

```bash
norte-guard analyzability                # the whole corpus
norte-guard analyzability --sample=500   # confirmed_malicious always included
norte-guard analyzability --capture=<pkg>  # one package, per-file reasons
norte-guard analyzability --metrics      # re-derive the minification threshold
```

**The denominator is bytes that execute.** JavaScript, native binaries, WASM,
V8 bytecode and foreign scripts. Documentation, images, fonts, source maps and
`.ts` sources ship alongside what runs and are not what runs; they are held out
and printed under their own heading so the exclusion can be argued with rather
than taken on trust.

**What a file is, is decided by its bytes.** Sniffing 200 tarballs from the
corpus found 41 files with no extension at all that were Mach-O or ELF
executables, carrying 847 MB — more than every `.js` file in the sample put
together. And in a package this project has labelled `confirmed_malicious`,
`dist/internal/calc.dat` is 63,616 bytes beginning `\x7fELF`: 93% of that
package's executable surface, wearing a data file's extension. A name-based
classifier holds it out of the denominator and reports the package as fully
covered.

**Fail closed.** A file counts as covered only if it parses, is legible, and
contains no construct that moves behaviour out of the parser's reach. One
`eval()` of a runtime-built string makes the whole file uncovered — not 95%
covered — because the parser cannot bound what the rest of it does. Being wrong
in that direction costs a pessimistic number; being wrong in the other is the
failure the command exists to prevent.

**A file carries every reason that applies.** A minified bundle with a dynamic
`require` appears under both, so the per-reason columns overlap and do not sum to
the uncovered total. They are a prevalence table, never a partition.

**Three failures that look alike and are not.** A file that defeats a conforming
parser is broken or built to be, and that is the severe one. A `.js` that is
really TypeScript, JSON or HTML is a packaging habit. And acorn's own recursion
guard gives up on a deeply nested expression past roughly ten thousand terms —
a limit of this tool, not a property of the package. They get `parse-failure`,
`not-javascript` and `parser-limit` respectively; all three are uncovered,
because nobody read the file either way.

### The minification threshold is derived, not chosen

`--metrics` writes every candidate metric for every parsed file and checks the
current cut against the files that label themselves. The constants in
`analyzability.ts` are the **antimode** of their own distribution, measured over
28,519 parsed files from 700 captures on 2026-08-16:

```
shortIdentifierRatio    5,592 files at 0.00-0.05, 12,933 at 0.65-0.70,
                        minimum of the valley at 0.500 holds 46
bytesPerLine            4,786 files at 20-40, 7,245 at 400-600,
                        minimum of the valley at 130 holds 15
```

Checked a second way, because the first way could have been five packages: five
of the 182 packages hold **52.9%** of those files, so a file-weighted histogram is
largely a picture of whoever ships the most files. Re-derived with one vote per
package, on each package's median, the valley at 100–120 bytes per line holds
**zero** packages and the valley at 0.25–0.30 holds one. The same cut sits in an
empty region under both weightings, and that is the evidence — not the shape of
either histogram alone.

The choice is also insensitive across the whole valley: every cut from
`(100, 0.40)` to `(200, 0.50)` catches the same 12 of the 14 unambiguous
`*.min.js` files and fires on 1.1%–1.7% of the readable ones. It barely matters
where in an empty valley the line falls, because nothing lives there.

What the cut then says — both true, and very different:

| | |
|---|---|
| parsed JavaScript **files** that are minified | 64.6% |
| **packages** shipping at least one minified file | 14.8% |
| **packages** minified in the majority of their files | 6.0% |

The command reports the package-weighted figure, because "what fraction of new
npm packages ships unreadable code" is a question about packages.

Two conditions, not one, and both must hold. A generated-but-readable lookup
table has short identifiers and short lines; a hand-written file with one inlined
data blob has an enormous line and ordinary names. Requiring the layout **and**
the renaming to agree keeps both out — and it is why one of the two `*.min.js`
misses is a file whose mean line is 2,189 bytes but whose identifiers average 7.2
characters. That is a data blob, not renamed code, and the second condition
declines it on purpose.

The self-labelled set has a bias worth stating: `*.min.js` is unambiguous but
rare (14 files), and `sourceMappingURL` turned out to label **readable**
transpiled output rather than minified output — its files have a median
`bytesPerLine` of 40 against 384 for everything else. It is used as the negative
set for that reason, and the positives carry the whole weight of the check.

### Cutting the corpus by class, and why that cut cannot answer the question

```bash
norte-guard analyzability --by-class --since=2026-08-15 --sample=250
```

Splits the corpus by `captureReason` and reports coverage, non-coverage reasons
and reachable modules for each segment. On 2026-08-16, v1.2.1, one day of
captures:

| | quarantine-no-genome | watcher-threshold |
|---|---|---|
| coverage by bytes | **93.32%** | **9.79%** |
| coverage, median package | 100.00% | 45.13% |
| ships a native binary | 0.00% | 16.00% |
| minified | 2.40% | 34.80% |
| reaches `child_process` | 17.14% | 36.87% |

Read as a finding about the class, every row of that table is wrong, and the
reason is arithmetic. **The class is defined as "under 100KB unpacked."** A
native binary, a WASM module, a V8 bytecode cache and a webpack bundle do not
fit in 100KB — so the first column cannot contain them whatever the class is
really like. The second column is selected on a high score, which is enriched
for install scripts and native addons by construction. The module row inverts
for the same reason: bigger software reaches more modules, and `child_process`
appearing *less* often inside the class is what that looks like.

The command says so in its own output, and it is still the wrong comparison to
be printing.

### `--size-control` — the comparison that answers it

```bash
norte-guard analyzability --size-control --since=2026-08-15 --draw=200
```

Holds size fixed and varies the class definition **one conjunct at a time**. The
class is four conditions:

```
no genome  AND  name under 7 days  AND  under 100KB  AND  no repository
```

Every group is under 100KB, drawn from the same window, and matched to the
class's own size distribution decile by decile:

| cell | differs from the class in |
|---|---|
| `class` | — |
| `class +repository` | it has a `repository` field |
| `class +age` | its name is 7 days old or more |
| `maintained` | genome, age and repository all differ |

There is no young-with-genome cell and its absence is a fact about the
definitions, not a gap in the draw: a genome needs ten versions across ninety
days, so a package with one cannot have a name younger than a week.

**Where the groups come from.** The class is measured twice. Once from the
captures on disk, which is a *census* of the class in the window rather than a
sample of it. Once from `changes-log.ndjson` — which records the class markers
for **every** publication the watcher scored, not only the captured ones —
re-fetched from npm now. The three control cells come the second way only,
because nothing on disk selected them.

Measuring the class both ways is not redundancy. A package npm has removed
cannot be fetched, and the class is the population npm removes; the gap between
the two class rows is the size of that survivorship problem, measured instead of
apologised for.

**What the flags do.**

```
--since=<YYYY-MM-DD>   required; both sides on one window or the comparison is
                       between weeks
--until=<ISO>          the far end, when a run has to be reproduced exactly
--draw=<n>             packages to draw and fetch PER CELL. 0 does no network at
                       all and leaves only the on-disk comparison, which is not
                       size-matched and says so
--output=<dir>         where changes-log.ndjson lives (default
                       ./norte-guard-captures)
--results-dir=<dir>    where the artifact lands
```

Requests are one packument and one tarball per package, spaced by 100ms
whatever the outcome — including the failures, so the rate does not go up
exactly when a cell is being taken down.

**What it prints, and what to check first.** The `DID THE MATCH WORK` table
profiles every group inside the **class's** deciles, never inside its own. A
table where each column is cut at its own quantiles reads as a perfect match
whatever the sizes are, and it is the only check that the control worked.

**The rule is declared before the run.** A difference is reported as real only
when the 95% interval on the *difference* excludes zero — Newcombe's hybrid
score method, because two overlapping error bars can still hide a difference
that excludes zero. "No difference" is a claim, not a shrug: it is printed only
when the whole interval lies inside a ±10pp equivalence margin. Otherwise the
verdict is `INCONCLUSIVE at this n`, which is what a small control group
deserves and what affirming the null from 68 packages would otherwise look like.

Module differences are in the same table with intervals widened by Bonferroni
for the number of modules compared. Picking the largest row of a forty-row table
and reading a 95% interval off it is how the `child_process` claim was made in
the first place.

## `capabilities` — what the code can reach, and how often that separates anything

```bash
norte-guard capabilities --capture=leb128x          # one package
norte-guard capabilities --control                  # the comparison
```

Four capabilities, computed over the reachability graph `reachability` already
builds. No new patterns: three of the four are the module being reached, and
reaching it is followed from the gate through renames, destructuring, property
writes and folded concatenations rather than searched for as text.

| capability | reached when |
|---|---|
| `credential_read` | a string naming a secret reached a filesystem or path call, **or** `process.env` was read for a token-shaped variable |
| `network_egress` | `net`, `http`, `https` or `dgram` is reached, or the global `fetch` is called |
| `external_exec` | `child_process` is reached |
| `dynamic_code` | `vm` is reached, or `eval`/`Function` is called, or a specifier is decided at runtime |

**Three answers, never two.** `reached`, `not-reached`, `indeterminate`. The
third is not a hedge, it is the whole point: 37 of the 42 confirmed captures
ship an executable no parser reads — a V8 bytecode cache, a native binary — and
a two-valued analysis records those as reaching nothing at all. The malicious
side would come out cleaner than the control **because it is better hidden.**

Every kind of lost trail is mapped to what it can hide. A specifier decided at
runtime can be any module, so it blinds the three module capabilities — and it
*is* `dynamic_code`, so the same fact that blinds three answers the fourth. A
computed member leaves the module known and the member unknown, so it blinds
only the capability that needs a member. `reached` always beats blinded: a
capability that was found does not need the trail that was lost.

`process.env`, `fetch`, `eval` and `Function` have no gate to arrive through —
nothing imports them — so they are recorded apart from the module list rather
than as a fourth door. A pseudo-module named `fetch` in `reachable` would appear
in every module-prevalence table this project has already published.

### `--control` — the comparison, and its unit

```bash
norte-guard capabilities --control --ratio=10
```

Cases are every `confirmed_malicious` capture that still holds its bytes.
Controls are drawn from the captures the collector already took: **same size**
(nearest neighbour on log unpacked size, within a factor of two), **same days**
(the window is the cases' own span), **not withdrawn** (every name in the
takedown logs, every `confirmed_malicious` label and every `0.0.1-security`
placeholder is excluded).

**The unit is chosen, not inherited from the directory count.** The 42 case
captures are 6 packages published by 3 npm accounts, and one of those accounts
republished 36 times in 38 hours. So every rate is computed five ways:

| unit | what it counts |
|---|---|
| `capture` | every snapshot — a rate of republishing as much as anything else |
| `package` | one per name, represented by its earliest capture |
| `publisher` | one per npm account — **the primary**: the independent events |
| `package-any` | did this package **ever** demonstrate it, over all its captures |
| `publisher-any` | did this operator ever demonstrate it — **read this one for what the code reaches** |

The `-any` rows exist because the earliest-capture rule has a failure mode this
corpus contains: `leb128x@1.0.0` requires `./_perf.js` and does not ship it, and
the payload arrives in `1.0.1`. Both sides are expanded the same way — every
matched control package brings every capture of it in the window — so the union
rule gives the cases and the controls the same number of chances to fire.

**What the run could have found is printed before what it did.** With three
independent cases, the run states up front the largest control rate that would
still leave a difference clear of zero. A rate that could never have separated
is not a null result, and reading one as if it were is the mistake the statement
exists to prevent.

Intervals are Newcombe's hybrid score method on the *difference*, widened by
Bonferroni for every interval the run prints, and the equivalence margin
(±20pp, wider than `--size-control`'s ±10pp because the case side is three
events) is declared in the source before any of it runs.

**Two things the run declares about itself.** Two of the six case packages are
named in this codebase as the reason a bound exists — `@siwatfa/yorn` for the
function-body walk limit, `kit-hydration-vim` for the magic-byte file classifier
— and both bounds blind capability answers. Excluding the packages would not
remove their influence on how every other package is measured, so the run states
them and then measures whether either bound decided its own package's answer.
And the secret-path list is reported twice: as frozen, and repaired after the
cases were opened, under a heading that says the repaired one is fitted to them
and is not evidence from this run.

```
--ratio=<n>            controls drawn per case package (default 10)
--since=<ISO>          widens the window past the cases' own span, and is
                       recorded in the artifact because it decides which
                       controls exist
--until=<ISO>
--output=<dir>         where the takedown logs live (default ./norte-guard-captures)
--results-dir=<dir>    where the artifact lands (default capability-results)
--json                 the whole report
--no-save              print without writing the artifact
```

### `corpus --publishers` — the number that decides whether `--control` can run

```bash
norte-guard corpus --publishers
```

A5's blocker was never the count of captures. It is the count of distinct npm
accounts on the case side, because `publisher` is the primary unit and its
members are the only ones that are independent events. At 3 accounts nothing was
claimable and the run said so — but the question *has that changed* had no answer
short of re-deriving the cohort by hand, which is how a decision number stops
being consulted and starts being remembered wrong.

It calls the same `caseCohortOf` that `runCapabilityControl` calls, so the number
cannot drift from the one A5 will use.

```
THE A5 CASE ARM   8 npm accounts
  87 confirmed_malicious captures, 56 with bytes
  56 captures  ->  15 packages  ->  8 accounts
    siwatfa           36 captures   @siwatfa/yorn
    ...

CONFIRMED, BUT NOT MEASURABLE
  31 captures of 12 packages from 4 accounts have no tarball left
  2 of those accounts appear nowhere else in the case arm, so they are
  accounts A5 would have had: graypin, javonayers999
```

**Three things travel with the count, and none of them is decoration.**

The **lost** block is printed beside the number because these are confirmed
removals that were caught and labelled, and the only reason they are not cases is
that a sweep deleted their bytes (see the object store section of
[audit-a5.md](audit-a5.md)). The case arm is short two accounts for a reason that
is not a shortage of attacks.

The **requirement** table states what the count would have to be, computed
against the control arm of the newest saved run rather than against a constant —
the control arm is not fixed, and it went from 49 accounts to 125 when the pool
grew. Quoting a requirement against a control arm the study no longer has is a
requirement for a different study.

```
  capability        ctrl rate    of  case det   ceiling  accounts needed
  credential_read        6.1%    49       50%     26.5%          41 (31)
  network_egress        24.3%    70       63%     32.9%          56 (52)
  external_exec         32.9%    79       63%     32.9%          60 (49)
  dynamic_code          15.9%    69       75%     36.2%          37 (30)
```

The **second number is the first n that separates at all**, and it is printed
because separation is *not monotone in n*. Both the account count and the reach
count round to whole publishers, so `credential_read` separates at 31 accounts and
then fails again at 33, 34, 39 and 40 before holding from 41; `external_exec`
separates at 49 and fails at 51, 54, 55, 56 and 59 before holding from 60. A
number that decides when to re-run a study cannot be one where a ninth account
takes the answer away, so the headline figure is the threshold from which every
larger n separates.

Every column is **per capability, because the denominator is**. `compareAt`
compares `overDeterminate` against `overDeterminate`, so `credential_read` is a
test on 49 controls and not on 125, and a requirement computed against the member
count would be a requirement for a comparison this study does not make. The
`ceiling` column is the commonest a control rate could be and still separate at
today's account count; a rate above it cannot be separated whatever the cases do.

The **determinate share** is the column a reader skips and the one that makes the
table honest. A case that ships a bytecode blob answers indeterminate to all
four, and an indeterminate case is not a case with an unknown value — it is a
case that leaves the denominator. Accounts arrive; *determinate* accounts arrive
more slowly. So the requirement column is not a schedule: a case arm that became
legible enough to fill it would be a cohort of attackers who had stopped hiding.

And the count is of **accounts, not operators**. Nothing here establishes that
two accounts are two people, which is the same reason
`PROMOTION_MIN_TAKEDOWN_PUBLISHERS` in `watchlist.ts` is a floor rather than a
measurement. Read it as an upper bound on the independent events in the case arm.

```
--results-dir=<dir>    the saved run to state the requirement against
                       (default capability-results)
--json                 the whole report
```

The same three-line summary is printed by bare `norte-guard corpus`, under
`THE A5 CASE ARM`, so the number is visible without knowing the flag exists.

### The opacity endpoints — when the four capabilities saturate

The four capabilities separate nothing at the primary unit, and adding accounts
has not changed that. But every one of those answers comes from a walk that also
records **where it lost the trail**, and until 2026-08-21 that record was consumed
only as a blinder — a reason to answer `indeterminate` — never as a measurement.

The hypothesis: an honest package does not need to hide its imports. A specifier
assembled at runtime, a computed member, a callee that only exists once the
program runs — each is a place the analysis stops, and if the case arm stops it
more often than a size-matched control does, then **the inability to resolve is
the discriminant** and the four capabilities were the wrong endpoint.

**Two kinds of not-knowing, counted apart.** This is the distinction the whole
section rests on:

| counted against the package | counted against this analyser |
|---|---|
| `dynamic-specifier`, `dynamic-eval`, `computed-member`, `unresolved-callee` | `depth-limit`, `origin-bound`, `ambient-bound`, `argument-bound`, `unresolved-import` |

The right-hand column is budgets *this project chose*. A package cannot be blamed
for them, and folding them in would measure the analyser on both arms and report
the result as a property of malware. Both are printed; only the left is the
signal.

Sites are counted **once per `file:line`**, not per occurrence. One construct
reached four hundred times is one authoring decision, and counting occurrences
would let file size decide the answer.

**On resolved evidence alone.** `capabilities.ts` turns a `dynamic-specifier` lost
point into positive evidence for `dynamic_code` — correct by the definition frozen
before the run, and also the analysis reporting its own failure. So a strict
answer is computed beside the frozen one, counting only a module resolved by name
or an ambient call the parser read. A frozen `reached` that rested on a lost
specifier becomes **`indeterminate`, never `not-reached`**: failing to read a
specifier is not evidence that it does not reach. Reported apart from the frozen
answers, exactly as the post-hoc `credential_read` block is.

**The family was widened, and the capabilities paid for it too.** Testing more
endpoints on the same data *because the first four saturated* is the textbook
shape of multiplicity. `OPACITY_ENDPOINTS = 9` (five binary opacity measures, four
strict-capability comparisons) is declared beside the other pre-run constants and
added to the capability family, so the correction covers everything the run
prints. The four capability intervals in this run are therefore **wider** than in
the run before it. That is the cost of having looked at more, and charging it only
to the new endpoints would be helping oneself.

The continuous measures — import resolution rate, opacity sites per file — add
nothing to the family: they are reported as medians and a common-language effect
size, with no interval and no threshold. That is a description and not a test, and
the output says so.

---

## `norte-guard metadata` — the half that does not need the archive

```
norte-guard metadata                                     # the comparison
norte-guard metadata --control-class=quarantine-no-genome  # both arms, one filter
norte-guard metadata --save --results-dir=metadata-results
norte-guard metadata --json
```

Every endpoint in `capabilities --control` is answered by reading bytes, and that
is why it is a run over 56 captures. 66.8% of this store kept no artifact, **0 of
42** confirmed removals collected elsewhere kept one, and a question about
contents cannot be asked of any of them.

This run asks only what the packument answers, so its cohort is **24,307
packuments** and its case arm is 87 captures — **31 of them with no bytes at
all**. npm deletes the versions of a removed package and keeps `time`, so the
whole release cadence of an attack survives its takedown.

It is not a better run. It is a run over different endpoints, most of which are
downstream of the filter that selected the corpus.

### Contamination is a column, not a footnote

D11 established that any endpoint which is an INPUT to the capture decision
separates against the raw pool and vanishes against a class-matched one. Every
endpoint here carries a frozen declaration of its relation to the three conjuncts
(`young`, `tiny`, `!hasRepository`), and the verdict is worded from it:

| status | meaning | verdict wording |
|---|---|---|
| `entailed` | the conjunct forces the answer | `SEPARATES, AND IT IS AN ARTIFACT. Not a finding.` |
| `partial` | the conjunct bounds it without fixing it | `SEPARATES, PARTLY CONSTRAINED.` |
| `independent` | the capture decision does not constrain it | `SEPARATES.` |

Adding a row after seeing a result is what the table exists to make visible, so
it is ordered by contamination and never by outcome.

### The unit decides the answer

Three units, `publisher` primary, declared before the run. On this cohort the
unit is not a detail — it is the whole result. `two publications less than five
minutes apart` reads **+63.8pp (CI +44.2 to +75.4)** at the capture unit and
**+13.0pp (CI −27.3 to +60.6), inconclusive** at the publisher unit, because 36
of the 87 case captures are one operator's release loop.

The report prints the discrepancy itself, naming every endpoint that separates at
the capture unit and not at the primary one, so a reader cannot pick the larger
number without being told what it is.

### The batch, and its base rate

A **family** is several *distinct* names from one account inside 60 minutes. One
name republishing is a **cadence** and is counted apart — `@siwatfa/yorn` is 149
releases of one package, and a unit counting publications would call it the
largest campaign in the corpus.

The base rate is the result: a tight batch (≥3 names in ≤60 min) describes
**58.9%** of the store's families, because that is what a monorepo release is.
Only the conjunction with all-first-publication is rare, at 0.1%. Idea 4's naive
form is saturated by ordinary practice the way opacity was by minification.

The family results are **descriptive**. With 4 malicious families there is no case
arm to test against a control arm, and none is claimed.

### `--control-class`

The same knob `capabilities --control` grew in D11: restrict the control pool to
one capture reason so both arms come through one filter. Both readings agree here
— nothing uncontaminated separates at the publisher unit either way.

### Two things the record itself gets wrong

`time.created` is reset by npm's takedown write, so a removed package reads as
newborn (**D12**: 631 captures affected, 133 flipping the `young` conjunct). Every
age in this run comes from the release timestamps instead.

The takedown write also publishes as `npm` with `npm-support` as maintainer, so
grouping by account attributes every removed package to the registry (**D13**).
The guard is structural and sits in front of `publisherOf`, because after a
takedown *both* halves of its fallback are the registry.

---

## `fp-bench --class-matched` — the arm that can see the observed class

```
node dist/fp-bench.js --class-matched
node dist/fp-bench.js --class-matched --control-class=watcher-threshold --limit=500
```

The default arm harvests by keyword and ranks by weekly downloads. That is the
right population for asking whether the gate is liveable in CI, and the wrong one
for any signal restricted to the observed class: a popular package is not under
seven days old, not under 100KB, and has a repository, so a class-gated signal
scores **0.00% false positives there whatever it does**.

Measured on shipped code — `fabricatedProfile`, which is not switched on:

| arm | n | full conjunction |
|---|---|---|
| popularity-ranked (7 runs, v0.2.0 → v1.2.0) | 500 each | 0.00% |
| `--class-matched` | 1,505 | **82.66%** |

This arm is **offline**. It scores each package from its captured packument, not
from the registry today, because the live document for a package this young has
already changed and for a withdrawn one it is gone. One capture per package, so a
republisher cannot decide the rate.

It also prints a coverage fact the other arm cannot: **100% of the class returns
`INSUFFICIENT_HISTORY` in gate mode** — the gate judges none of it.

Read the rate as an **over-estimate**: "not withdrawn" is not "benign", so a
package npm removes tomorrow counts here as a false positive today. A signal that
looks clean in this arm is clean pessimistically. Results are written to
`fp-bench-results/class-matched-v<engine>.json`, deliberately as a separate file
from the popularity artifacts — the two arms measure different populations and
comparing them as one series would be the defect in a new place.

---

## `norte-guard backfill-404` — the pass over what a terminal 404 cost

```
norte-guard backfill-404                 # dry run: how many, and how long it would take
norte-guard backfill-404 --run           # replay them
norte-guard backfill-404 --run --limit=200
```

The change feed announces a publication and the watcher fetches the packument
about a second later. When that fetch failed, the publication was dropped and
**nothing ever asked again**: 12,852 rows came back 404, and 6,892 of those
packages were never analysed at all. Six were later removed by npm, among them
two that share an operator with three packages already in the corpus.

The window was never tight — `shared-slot-gate` 404ed at 09:30 and npm did not
remove it until 16:19.

Going forward this is handled by a queue inside `watch`: four attempts at **30s /
5min / 30min / 2h**, persisted to `retry-queue.json` so a restart resumes it.
The schedule deliberately spans past npm's 64-minute median time to remediation,
because a schedule that gave up sooner would drop the packages most worth having.
Anything still missing at the end is appended to `lost-publications.ndjson` with
its reason.

`backfill-404` is the one-time pass over the ones that were lost before the queue
existed. **It is a replay, not a new capture rule**: each name goes through the
same `analyzePackage` the watcher uses, so a package still on the registry is
judged by the policy that would have judged it then. Capturing them
unconditionally would add a population selected by "npm was briefly inconsistent"
to a corpus otherwise selected by score or class, and nothing downstream could
tell the two draws apart.

Paced at 250ms per name. The dry run prints the estimate.

---

## Dependencies of what is captured

`watch` now follows the dependencies a captured package declares. The reason is
one package.

On 2026-08-13 five packages were published in four minutes — 3-4KB each, no
repository, hours old, the observed class exactly — and all five were captured.
All five declare **one** dependency and it is the same one: `mutex-forge`, which
was analysed twice while live, scored 10, and rejected for being 664KB with a
repository.

The class describes what a throwaway package looks like. A package built to be
depended upon looks like a library instead, so the conjunction is calibrated for
the decoy and lets the carrier through.

The rule: **a dependency declared by a captured package, which is itself younger
than `YOUNG_NAME_DAYS`, is captured — without consulting its size, repository,
install script or score.** No new threshold; it reuses the conjunct already
frozen in `observed-class.ts`, which `mutex-forge` satisfied.

Measured before it was built: the median capture declares 1 dependency, the
median declared dependency is 1,455 days old, and 1.8% are young. The rule
reaches for about **163** packages across the whole corpus, not the 9,330
distinct names that get declared. Fan-out is capped at 12 per capture (the
corpus maximum is 519) and truncation is logged. Depth is one.

These captures carry `captureReason: 'declared-dependency'`, so they can be
counted apart from the score path and from quarantine — a different draw must
not silently join either denominator.

### What the dependency path does with the tarball

**It keeps it**, unless one of two things is true — and in both cases the
packument is still captured and the refusal recorded, so the package stays in
every population and every denominator and only the bytes are declined.

| condition | `tarballRefused.reason` |
|---|---|
| over the 8MB unpacked cap the score path also applies | `over-capture-cap` |
| published under the **same npm scope** as the package that declared it | `same-scope-sibling` |

Neither is a contradiction of the rule. The rule deliberately ignores a
dependency's **size** and its **provenance** when deciding whether it is
interesting; whether its tarball is worth the disk is a different question, and
answering the second by the first is how `mutex-forge` was lost in the first
place. `mutex-forge` is 664KB and unscoped, so it is unaffected by either.

**Why degrade the same-scope sibling rather than exclude it.** Of the first 219
captures on this path, **203 (92.7%)** were a package declaring another under its
own scope — `@latticeag/adapter-stub` → `@latticeag/bus`,
`@composy/layout-elements` → `@composy/layout-runtime`. That is a monorepo
release, and all four carriers this rule was written for are cross-scope
(`async-critical-section` → `mutex-forge`, `sui-gql-core` → `bcs-core`,
`sui-move-rpc` → `leb128x`, `sui-move-graphql` → `ulebkit`).

Excluding them would have removed the population from the denominator too, and
the question *"does an operator ever use one scope for both the decoy and the
carrier"* would stop being answerable. Degrading leaves it measurable.

The disk argument is the weaker half and is stated as such: over the 219 captures
already taken, the same-scope siblings are **0.66 MB of 0.74 MB — 88.7% of the
path's disk and an absolutely trivial amount**. The saving matters at volume; the
denominator matters now.

Two unscoped names never match: they share no scope, they share nothing, and
treating them as siblings would degrade the `mutex-forge` case itself.

The rule is **not retroactive**. The 203 already on disk keep their tarballs;
deleting bytes that were already fetched is the one thing this project has an
incident about.

### A failed dependency fetch is queued, not dropped

The first version of this path let a `fetchPackument` failure end the matter, on
the reasoning that the retry queue is for publications the *feed* announced and a
name read out of a manifest is not one. That was wrong, and it was D15 in a new
place: if `mutex-forge` had 404ed, the one package the five decoys all pointed at
would have been lost for exactly the reason 6,892 publications were.

Dependency fetches now enter the same queue, carrying `origin: 'dependency'` and
the name of the package that declared them. The origin decides what a retry
**does**: a `feed` entry is replayed through `analyzePackage`, a `dependency`
entry goes back through the dependency path. Sending a dependency through the
score path would reject it for precisely the reasons the rule exists to overrule
— `mutex-forge` scored 10.

### Depth

One. Depth 2 was costed and not built.

Simulated over the packuments already on disk: the 683 confirmable young
dependencies at depth 1 declare 1,731 dependencies between them (811 distinct,
mean 2.53 each), of which **206 — 25.4% — are themselves young**. Scaled to the
~163 packages depth 1 reaches, depth 2 would cost about **412 extra packument
requests for about 49 extra captures**.

Cheap in absolute terms, and a different kind of draw. The 25.4% hit rate at
depth 2 against **1.8%** at depth 1 is not a sign the rule is finding more
malware; it is that new packages depend on new packages, so depth 2 pulls in
monorepo siblings in bulk. The argument for capturing a dependency is that
something already judged interesting points at it, and that argument does not
survive a second hop.
