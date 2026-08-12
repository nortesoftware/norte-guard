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
