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
