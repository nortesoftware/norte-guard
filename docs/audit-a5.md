# Audit of A3/A5 — v1.3.0 reviewed, v1.4.0 published

The capability run of 2026-08-18 (`capability-results/capability-control-2026-08-18-*`)
was audited line by line before any of it was believed. Four independent reviews
— capability semantics, statistics, control construction, leakage and scoring —
raised fourteen findings; each was handed to a separate reviewer instructed to
refute it. **Six survived, eight did not**, and two of the six were the same
defect reached from different directions (D1 below, found by both the control
review and the leakage review) — so the audit produced **five** distinct defects.
The sixth recorded here, D6, did not come from that audit at all: it came out of
asking why 17 flagged packages were still alive, which is a separate
investigation written up further down.

Every number below was re-derived from `capability-results/*.json` or from
`norte-guard-captures/` directly, not read off the prose report.

The reruns are `capability-control-2026-08-19-v1.4.0.json` and its report.

---

## What the run says, now that it says it first

**At the primary unit, nothing is established.** That was true in v1.3.0 too; it
was on page four, under a row that said `SEPARATES`.

| capability | cases r/n/? | controls r/n/? | difference | verdict |
|---|---|---|---|---|
| `credential_read` | 0 / 0 / 3 | 3 / 10 / 36 | — | not calculable |
| `network_egress` | 0 / 0 / 3 | 10 / 11 / 28 | — | not calculable |
| `external_exec` | 1 / 0 / 2 | 12 / 13 / 24 | +52.0pp, CI −41.9 to +77.3 | inconclusive |
| `dynamic_code` | 1 / 0 / 2 | 5 / 13 / 31 | +72.2pp, CI −24.3 to +91.8 | inconclusive |

Two capabilities have no denominator. The other two rest on **one** determined
case. All four control rates (23%, 48%, 48%, 28%) sit above the run's own
pre-registered ceiling of 20.4%, so none of them could have separated whatever
the cases did.

The one `SEPARATES` row in the output is `dynamic_code` at the capture unit,
+78.4pp. All 36 of its reached captures are **one package**, `@siwatfa/yorn`,
from one account — and it is also the only `bytecode`+`minified` member of the
cohort. A cluster bootstrap over the 3 independent publishers gives CI −17.3 to
+92.5, including zero, with 29.2% of resamples ≤ 0 ≈ (2/3)³. The arithmetic was
never wrong; the unit was.

**Report layout changed accordingly.** `headlineOf` in `capability-control.ts`
computes the finding from the comparisons and prints it above them, `PRINT_ORDER`
puts the primary unit first and the capture unit last, and the pseudo-replication
warning is printed inside the capture block instead of waiting for the caveats.

---

## The confirmed defects

### D1 — the primary unit folded 18 control packages into 2 bots
`src/capability-control.ts:195` (fix at `:198-224`)

`publisher: raw._npmUser?.name ?? maintainers?.[0]?.name` — the fallback fires
when `_npmUser` is *missing*, never when it is npm's OIDC trusted-publishing
identity. Measured on the captured version:

```
_npmUser="GitHub Actions"  17 packages -> 10 distinct real maintainer accounts
_npmUser="CircleCI"         1 package  ->  1
38 real publishers + 2 bot identities = the 40 that were reported
```

Worse than a rate: `atUnit` keeps the earliest capture per group, so the merge
**discarded 16 of the 60 measured control packages** from the primary analysis.
The case arm publishes with tokens and never trips it, so the error was
one-sided and shrank the control side alone.

Fixed by `isTrustedPublisherIdentity` / `publisherOf`, keyed on the
`trustedPublisher` object (present on all 18) and on the shared
`npm-oidc-no-reply@github.com` address.

| | v1.3.0 | v1.4.0 |
|---|---|---|
| publisher-unit controls | 40 | **49** |
| detectability ceiling | 8 of 40 (20.0%) | **10 of 49 (20.4%)** |
| `external_exec` | +50.0pp | **+52.0pp** |
| `dynamic_code` | +76.9pp | **+72.2pp** |

### D2 — 12 of 99 control captures were outside the declared caliper
`src/capability-control.ts:727` before the fix, now `:795-825`

The match draws one representative per control package and checks the caliper
there. The measured set is *every* capture of that package in the window, and
the band was never re-checked on it.

```
worst ratio, actual:   11.39x  1.29x  1.01x  6.53x  1.03x  3.79x
worst ratio, printed:   1.02x  1.01x  1.01x  1.04x  1.03x  1.03x
```

`@vanillaskyai/sdk` was matched to `@siwatfa/yorn` at 26,605,866 B and measured
at 2,289,754 B — **11.39×** against a declared 1.995× — inside the one arm
carrying the `SEPARATES` row. The report presented that table as *"where the size
control is checked, and the only place it can be"*.

Fixed: the caliper is re-applied on expansion, dropped captures are listed as
`outOfCaliper`, and `worstRatioOver` computes the printed ratio over the measured
set. Capture-unit controls 99 → **87**; `dynamic_code` +80.8 → **+78.4pp**.

### D3 — 20 of 99 controls were never opened, and the blinding caveat quoted half
`src/capability-control.ts:1337` (caveat), `src/cli.ts:666` (per-unit lines)

`grep -i refus` over the v1.3.0 report returns nothing. In the JSON,
`refusedToAnalyse` was 20 at the capture unit and 13 at the primary one — 17
archives hold no JavaScript at all (TypeScript-only, CSS, markdown) and 3 are
past the size bound. They answer indeterminate to all four exactly as an opaque
member does, and they sit in the denominator of every printed bound.

The differential-blinding caveat said **88% vs 15%**. Counting both failures it
is **88% vs 33%** on the corrected control set. `blindedAtEntry` is now a field
on every group, and the CLI prints opacity, never-opened, and the union as three
separate lines per unit.

### D4 — "three of the four control rates are above that ceiling" — it is four
`docs/methodology.md:192`

The sentence names the publisher unit ("three independent cases and forty
controls") but the three rates it counted were the *capture* unit's, measured
against the *publisher* unit's ceiling. Against their own ceiling of 79.3% none
of them clears it. The one that silently dropped out of the list was
`dynamic_code` — the row the surrounding table highlights. Corrected, and the
paragraph now says why the old count was wrong.

### D5 — three per-module bounds dropped facts without a lost point
`src/reachability.ts:554, 584, 603`

`MAX_MODULE_ORIGINS`, `MAX_AMBIENT_PER_MODULE` and `MAX_CALL_ARGUMENTS_PER_MODULE`
each `return` with no `noteLost`. Past the bound `capabilitiesOf` sees neither
the evidence nor a blinder and answers `not-reached` — the exact failure the
three-valued answer exists to prevent, and the opposite of the contract stated in
the comment above `MAX_AMBIENT_PER_MODULE`. Reproduced on a fixture: `fs.readFileSync('/root/.npmrc')`
after 100 `path.join` calls is `reached`; after 600 it is **`not-reached` with an
empty `blindedBy`**.

**This moved no number in either run** — verified by rerunning the full A5 with
the three guards reverted and diffing all 40 unit×side×capability cells: **0
differ**. What makes it worth fixing is that the exposure is one-sided: **25 of
99 controls saturate a bound, 0 of 42 cases do**. Any future run with a larger or
bundled control cohort depresses control rates and inflates every case-minus-
control difference.

Fixed by blinding **per fact type**, not by folding into `depth-limit` (which
blinds all four and *would* have moved four rows):

| lost reason | blinds |
|---|---|
| `argument-bound` | `credential_read` only — it is the one capability that reads arguments |
| `ambient-bound` | `credential_read`, `network_egress`, `dynamic_code` — `process.env`, `fetch`, `eval`/`Function` |
| `origin-bound` | all four — every capability is answered off the origin list |

### D6 — the promotion gate was reading a frozen sweep
`src/watchlist.ts:353`

`verdictsFromCaptures` required the capture to carry `label: confirmed_malicious`
with an npm-takedown source. Relabelling only ever happened for the six packages
A5 needed. The removal record itself — `takedown-log.ndjson` plus four rotations,
503 rows, **233 distinct removed names** — was never consulted, and neither was
`readLiveTakedowns`, which already reads all of it.

53 of those 233 have a capture; 36 were captured through quarantine; **25 are
captures of npm's own `0.0.1-security` tombstone** and prove nothing; the
remaining **11 are genuine pre-removal observations**:

```
async-critical-section  bcs-core   bcs-mini      keyed-mutex-map  kit-hydration-vim
leb128x  resource-lease-pool  single-flight-lock  sui-gql-core  svelte-goal-vim
try-lock-runner
```

Five of them are five of the six A5 case packages, captured 2.8–6.9 h before
removal. Precision by capture arm, over distinct packages:

| arm | packages | pre-removal TP | precision |
|---|---|---|---|
| `quarantine-no-genome` (the class) | 2,786 | **11** | 0.395% |
| `watcher-threshold` (the score) | 7,374 | 1 (`@siwatfa/yorn`) | 0.014% |

Fixed: `verdictsFromCaptures` now takes the removal-record name set, excludes
tombstone captures explicitly, and the CLI passes `readLiveTakedowns(dir)`.

Note the distinction the codebase already draws and that this does not erase:
these 11 confirm the **capture filter**. The five-condition *rule* still has **0**
verified removals — 8 snapshots carry no download count and 3 carry a vacuous
zero — so nothing here promotes the rule.

---

## What was refuted

Eight findings did not survive. The two worth recording:

- **"The equivalence margin and primary unit were chosen after seeing a number."**
  False. `PRIMARY_UNIT = 'publisher'` and `EQUIVALENCE_MARGIN = 0.20` are fixed
  at `capability-control.ts:100` and `:76`, above any code that runs, and
  `test/capabilities.test.ts` pins both.
- **"`z = 3.02` is the wrong correction."** It is Bonferroni over 20 comparisons
  (4 capabilities × 5 units) at α = 0.05, and reproduces to nine decimal places.
  The family is conservative — the five units are five views of one dataset, not
  independent — and conservative is the safe direction.

---

## The class: `noGenome` was never a condition

`inClass = noGenome && young && tiny && !hasRepository` is now
`young && tiny && !hasRepository`.

`hasGenomeRegime` requires a first analysed version at least
`MIN_AGE_DAYS_FOR_GENOME = 90` days old; `young` is a name under
`YOUNG_NAME_DAYS = 7`. **`young` entails `noGenome`, with 83 days of margin.**

Measured over all 114,545 marked publications in `changes-log*`:

| conjunct | marginal | P(X \| the other three) | rows it removes |
|---|---|---|---|
| **`noGenome`** | 56.12% | **100.0000%** | **0** |
| `young` | 22.96% | 57.19% | 2,732 |
| `tiny` | 33.57% | 48.03% | 3,949 |
| `!hasRepository` | 26.81% | 31.84% | 7,813 |

26,297 rows have `young=true`; **0** of them are under the genome regime. The
class is byte-identical without the conjunct, and
`test/collector.test.ts` now asserts that over every combination the classifier
can produce. `quarantineRejects.withGenome` is kept as the last branch of the
reject chain, where it reads 0 by construction — a standing check that the
entailment has not broken.

**The same redundancy exists one level over**, in `fabricated-profile.ts`: the
rule's "four free conditions" are `noGenome`, `youngName`, `tiny`,
`noRepository`, and the first is entailed by the second there too. That is the
build-failing rule rather than the description, so it was left alone
deliberately and is recorded here as a decision, not an oversight.

---

## The 17 survivors, and why the ceiling was the wrong shape

17 packages the class flagged are alive with ≥10 weekly downloads
(`tracking-log.ndjson`, sweep of 2026-08-18T19:24). All 17 are `T T T` on the
three surviving conjuncts, 14 of 17 scored 17 and passed, **17 of 17 ship a
README**, 16 of 17 are scoped, across 15 distinct maintainers, all flagged inside
one 42-minute window on 2026-08-12. The class describes *a new npm package*.

`PROMOTION_MAX_FALSE_POSITIVES = 1` — an absolute count of false positives, ever
— was measured against the actual flow:

```
6 full days in changes-log*:  19,091 publications/day, class fires on 3.187%
                            =    608 packages flagged per day (range 50-1,136)
```

One false positive for all time against 608 flags a day is not a strict
criterion, it is an unreachable one — and an unreachable bar gets crossed by
somebody lowering it, not by the rule improving. It is replaced by a **rate**
stated the way an operator would state it:

```
PROMOTION_MAX_FALSE_POSITIVES_PER_DAY = 1
PROMOTION_MAX_FALSE_POSITIVE_RATE     = 1 / 608 = 0.164%
```

tested on the **upper 95% Wilson bound**, which the count version could not be:
an observed zero over four packages proves nothing, and on the bound it does not
pass. With 0 observed the rate needs **2,332 tracked packages** to clear; the
gate reports that distance in its own refusal. Added alongside it:
`PROMOTION_MIN_TAKEDOWN_PUBLISHERS = 3`, because 11 true positives from 4
accounts — 6 of them one account publishing near-identical lock/mutex stubs in a
week — is closer to 4 events than to 11.

Where that leaves the gate today, from `norte-guard track`:

> 17 of 33 tracked are false positives — **51.5%**, upper 95% bound 67.5%,
> against a ceiling of 0.164%. At 17 observed this needs 16,548 tracked packages
> to clear, and there are 33.

`test/collector.test.ts` asserts the new criterion **is reachable**: a clean
record at `minimumTrackedFor(0)` with three removals from three accounts
promotes.

---

## `!gitHead` as a fifth conjunct — measured, and rejected

Measured before adoption, on the denominator rather than on the nine samples that
suggested it.

| population | n | `!gitHead` |
|---|---|---|
| all captures | 17,903 | 40.37% |
| class fires | 5,017 | 43.43% |
| class does not fire | 12,886 | 39.17% |

Lift **1.076**. The field is near-independent of the class and close to a coin
flip on everything.

- **12 of 12** genuine pre-removal captures have `!gitHead` (the earlier "9/9"
  undercounted; all 12 were evaluable).
- **6 of 17** survivors have it — and 35.3% is *not* below the class base rate of
  43.43%: one-sided binomial P(X ≤ 6 | n=17, p=0.4343) = **0.337**. The survivor
  side, which is where a useful conjunct would prove itself, is statistically
  silent.
- Volume −56.6% (3.19% → 1.38% of the feed), recall 11/11 retained, precision
  0.376% → 0.795%. **Both are >99% false positive.** A coin-flip field halving
  the denominator would be reportable as a "2.1× precision improvement".
- The 11 class-firing true positives come from **4 npm accounts**. At the honest
  clustering p = 0.036, not 1e-4; Wilson bound on retained recall [51%, 100%].
- **Evasion is free**: `gitHead` is `git rev-parse HEAD` of the publish
  directory. `git init && git commit --allow-empty && npm publish` sets it. The
  corpus already shows the field is not per-publish even for honest publishers —
  one hash appears across 120 different packages.
- Not an OIDC proxy (trusted-publisher captures are 42.2% vs 38.9%, the wrong
  direction for the toolchain story) but it **is** a size proxy: within the class
  it runs 83.9% under 1 KB and 35.7% at 5–20 KB. The class already selects tiny.

**Not adopted.** What would change that: ≥16 consecutive all-`!gitHead` genuine
pre-removal true positives for a 95% lower bound of 80% on retained recall (35
for 90%), from ≥6 independent publisher accounts, and a survivor cohort where
prevalence is significantly below 43.4%. Current: 11 TPs, 4 accounts. Retaining
`_npmVersion` in `normalizePackument` — one line — would make the toolchain
confound testable instead of undecidable.

---

## Still open

- `credential_read` is the one capability carrying hand-written lists
  (`SECRET_PATHS`, `TOKEN_ENV_WORDS`). Its measured exposure is **0 evidence on
  the case side at all five units** and all of it on the control side, so the
  deviation from "no new patterns" pushes the difference *down*. Conservative,
  but real, and named.
- The repaired secret-path definition (`joinPathSegments`) is post-hoc and cannot
  be validated by a run that saw the cases. It stays in the POST HOC block until
  a confirmed sample nobody has opened tests it.
- Both arms still pass through the same enriched capture filter, so this compares
  confirmed removals against the rest of what the filter kept — not against npm.

---

## What is publishable, and what the power table is for

The finding is **descriptive, and it is about opacity**. A count of what the
artifacts contain needs no power calculation — but it does still need a unit, and
"37 of 42 captures" is the capture unit, which is the one this whole audit was
about. The honest statement gives all three:

| unit | cases | controls |
|---|---|---|
| capture | **37 / 42 = 88.1%** | 15 / 87 = 17.2% |
| package | 2 / 6 = 33.3% | 12 / 60 = 20.0% |
| publisher | 2 / 3 = 66.7% | 12 / 49 = 24.5% |

The 37 opaque captures are **two packages**: `@siwatfa/yorn`, which is bytecode
and minified and was captured 36 times, and `kit-hydration-vim`, a native binary
captured once. So the 88% is one operator's republication rate wearing the shape
of a prevalence, exactly as `dynamic_code` was — and stating it as "37 of 42,
n=42" would repeat the error this document exists to correct.

What survives at every unit is the direction, and that is the publishable claim:

> Of the six packages npm removed and this collector caught before the removal,
> **two ship an executable no parser reads** — a V8 bytecode cache with minified
> code, and a native binary. Those two are two of the three operators. In
> size-matched packages npm did not remove, the figure is 12 of 60 packages. The
> counts are small and are given as counts; no interval is claimed.

That is weaker than "88% versus 17%" and it is the one that is true. The strong
version is available only at the unit where one package is counted 36 times.

**The per-capability claim is the one that is not available**, and the power
table is what says so rather than an apology for it:

| case determinate share | 100% | 75% | 50% | 33% | 25% |
|---|---|---|---|---|---|
| `credential_read` (ctrl 23%) | 24 | 30 | 40 | 55 | 72 |
| `network_egress` (ctrl 48%) | 28 | 38 | 55 | 74 | 96 |
| `external_exec` (ctrl 48%) | 28 | 34 | 50 | 76 | 100 |
| `dynamic_code` (ctrl 28%) | 26 | 32 | 40 | 61 | 80 |

Publishers needed for a +30pp difference to separate at the family-adjusted z,
by how often a case yields a determinate answer. Today there are **3**, and the
determinate share is 1/3 for `external_exec` and `dynamic_code` and 0/3 for the
other two.

The temptation is to read that table as a schedule — wait for 61 publishers and
the answer arrives. It is not. Every column but the first assumes the case side
stays partly unreadable, and **the unreadability is the phenomenon**. A cohort
that became legible enough to fill the 100% column would be a cohort of
attackers who had stopped hiding. Waiting for the case arm to become analysable
is waiting for the thing being studied to stop happening.

So the table earns its place by justifying a refusal: at n=3 publishers, with two
of four capabilities returning no determinate case at all, no per-capability
difference is claimable, and no amount of patience at the current arrival rate
changes that within the horizon the corpus covers. The opacity count does not
have that problem, and it is the stronger result anyway.

---

## The object store: 3,190 tarballs deleted while still referenced

Found while asking why two of the five publishers with a genuine pre-removal
capture cannot enter A5. Audited across the whole corpus, at a snapshot of
22,836 captures and 17,447 stored objects.

**Were the bytes ever downloaded?** Yes, provably. The manifest records a
64-hex sha256 per version, written at `ngpack.ts:104` as
`manifest.objects[ver] = stored.sha256` — the return value of
`putObject(buf)`, which hashes the buffer. npm's packument carries `dist.shasum`
(sha1) and `dist.integrity` (sha512) and **no 64-hex string anywhere**, so the
recorded hash cannot have been copied from metadata. Confirmed on a survivor:
for `bcs-core@1.0.0` the stored object is a gzip tarball whose sha256 equals the
manifest hash and whose sha1 equals npm's `dist.shasum`. The bytes were fetched,
hashed and written. They were deleted afterwards.

**Three axes, as the shape of the answer:**

| cut | result |
|---|---|
| by engine / date | **step function** — 0.3.2: 95.7%, 1.0.0: 95.2%, and **0.0% for 1.1.0, 1.2.0, 1.2.1, 1.3.0, 1.4.0** across 17,588 references |
| by size | **flat** — 96.1% under 10KB, 95.7% at 10-100KB, 93.4% at 1-10MB, 93.4% at 10-32MB, 97.9% at ≥32MB. No cliff at the 32MB `--max-capture-mb` bound |
| by position within a run | **flat** — 15.3%, 15.0%, 15.1%, 15.2%, 15.1%, 15.1%, 15.5%, 15.4%, 15.5%, 14.7% by decile. No end-of-run concentration |

Not dispersed across all three, so not a non-transactional write. One historical
episode, bounded in time.

**The mechanism, and why retention is a red herring.** `collectOrphanObjects` is
mark-and-sweep: an object survives if a capture on disk names its hash. It never
reads `retainUntil`. All 3,190 deleted objects **are still named by manifests on
disk** — that is how this audit found them — so the sweep deleted *referenced*
objects, which it can only do if its scan of the captures directory came back
empty or nearly so. Manifests record `objectStore` as a cwd-relative path
(`norte-guard-captures/captures`), and resolving it against the wrong working
directory produces exactly that. Corroborating: of the 1,611 orphans that carry
a `retainUntil`, **1,611 have a `retainUntil` still in the future** — none
expired. Nothing aged out; a scan failed.

**Is it still active?** No, and the reasoning has to be careful, because the
obvious check does not work: of the 3,543 present objects carrying a
`retainUntil`, **zero have reached it**, so "no orphans since 1.1.0" cannot by
itself distinguish "fixed" from "not yet due". What resolves it is that this
failure mode is age-independent — a failed scan deletes referenced objects
whatever their retention date — so 17,588 references surviving over five days of
continuous collection is evidence, not an artifact of youth. A live dry run of
the current sweep against the store confirms it: **0 objects it would delete, 0
bytes, no refusal.**

Two defences now stand: the store root no longer follows `manifest.objectStore`
(v1.1.0), and `ORPHAN_SWEEP_MAX_SHARE = 0.5` refuses any sweep that finds more
than half the store unreferenced (v1.2.1, commit `69bca94`). The second is a
blast-radius bound, not a proof: a *partial* scan failure yielding under 50%
apparent orphans would still delete. A sweep that verified its own scan — refuse
if the referenced set is empty, or if it fell sharply since the last run —
would close that, and is not written.

**The cost, in evidence.** **31 confirmed_malicious captures** lost their bytes,
not six. Six are the pre-removal observations that cost A5 two publishers —
`async-critical-section`, `keyed-mutex-map`, `resource-lease-pool`,
`single-flight-lock`, `try-lock-runner` (all `javonayers999`) and `bcs-mini`
(`graypin`). Five more are the `fabricated_family` tombstones. **The other twenty
are early versions of `@siwatfa/yorn`** — 1.0.1 through 1.0.30 — which is why that
package has 56 captures and only 36 with bytes. The case arm did not just lose
two publishers to this sweep; it lost more than a third of the republication
series of the one package it does have.

That is **two of the five publishers** with a genuine pre-removal capture, and it
is why A5's case arm is 3 publishers rather than 5 — a sweep, not a shortage of
attacks.

**The leak is now reported rather than discovered.** `auditObjectIntegrity` walks
the manifests against the store and the watcher prints the result on the startup
line beside the budget, because the only reason this was ever found is that
somebody went looking, and an object store leaks silently by construction —
nothing reads a tarball until a question is asked of it weeks later. The total is
a scar and stays constant, so what the line emphasises is the delta against the
previous start:

```
Object store: 18647/21837 tarballs present, 3190 MISSING, 2026-08-12..2026-08-14
              — 31 of them labelled (no change since last start)
```

and, when it moves:

```
              — 31 of them labelled  <-- 10 NEW SINCE LAST START
  Bytes that were fetched and hashed are gone. These packages are removed from
  npm within hours, so they cannot be re-fetched at any price. Find what deleted
  them before capturing more.
```

The check costs 829 ms over 21,837 references.

**Write ordering was already correct**, and is now commented so an edit does not
reverse it: `createNgpack` writes every object to the store first and the manifest
last, so a crash mid-capture leaves unreferenced bytes — which the sweep collects
— and never a reference to bytes that were never written, which nothing can
repair. What was missing is that the manifest write was not atomic: a plain
`writeFileSync` truncated by a crash leaves JSON no reader can parse, and a
capture whose manifest does not parse is a capture whose objects look
unreferenced to the sweep — the same store-eating failure through a different
door. `writeJsonAtomic` now writes to a temp file and renames.

---

## Recovery of the six lost tarballs: none, and what survives instead

Attempted against registry.npmjs.org, skimdb, unpkg, jsDelivr (six edges plus
statically.io), Software Heritage, the Wayback Machine, npmmirror, yarnpkg,
Tencent, Huawei, deps.dev and npm's attestations endpoint. **Zero of six
recovered as bytes**, zero as file trees.

Every source returns the same thing: the registry serves the `0.0.1-security`
placeholder and 404s the tarball; skimdb has no stale replication document; every
CDN resolves against live npm and so has nothing; the Wayback Machine has no
captures. Software Heritage is the instructive one — it holds an npm origin for
all six, but **every visit postdates the takedown**. The packages were removed
roughly seven hours after publication (five of the six by `javonayers999` inside
a five-minute window on 2026-08-13, `bcs-mini` by `graypin` the next day), and
SWH's crawler arrived about thirty minutes late. Seven hours is not long enough
to get mirrored.

**Two of the six left per-file metadata behind, and it authenticates.** jsDelivr's
data API still answers for them, and the file list sums exactly to the
`unpackedSize` and `fileCount` in the packument this project captured before the
removal — an independent match on two fields, so the record is genuine:

`single-flight-lock@1.0.0` — 5 files, 3,578 B (packument: 3,578 / 5)

| file | bytes | sha256 (base64) |
|---|---|---|
| `/index.js` | 1277 | `Cj7muW/R6IHavcCgTr0AjNFnnTenRrbsxE82WiZpZaQ=` |
| `/index.d.ts` | 192 | `nH86sOBDIuzOZZJFy80Mhp0TfsK9UDKoLe5JZ8HJ4lk=` |
| `/LICENSE` | 1060 | `F5xyKRWJ6s19SE15pFyJjwcYL+KuYjA5kM41dbM2JV4=` |
| `/package.json` | 519 | `mrhB60oxTh9kJXLEfTb/mZIO/kUK5Pa5gTSif2ked1Y=` |
| `/README.md` | 530 | `Mao1rBZedPvLEWXbWuVZed+zaMiF/3E6wdU04MllYcI=` |

`bcs-mini@1.0.1` — 3 files, 4,607 B (packument: 4,607 / 3)

| file | bytes | sha256 (base64) |
|---|---|---|
| `/index.js` | 3877 | `uWXQT6fUBJJQL761Ny7juvHDOMsOF/xbmHaPYflmt0Q=` |
| `/package.json` | 391 | `Nf+NHVU5tjx+mWAg/56vsM5eSAP2+8Bb/DSaVrl7SWo=` |
| `/README.md` | 339 | `6d+2jbH/QUQfHKlmH466/fuX6otOGCVezLeKUWp7Azc=` |

Transcribed here because jsDelivr will purge it eventually and this file is
version-controlled. If the bytes ever surface, they can be verified file by file.

One thing this metadata already settles without the bytes: **neither package is
opaque.** No `.node`, no `.wasm`, no bytecode — five and three plain source files
respectively. Whatever those two did, they did it in readable JavaScript, so
their absence from the case arm does not bias the opacity count in either
direction.

The full sha256 the project recorded for each lost tarball, kept so a future
match is checkable:

```
async-critical-section@1.0.0  01d51cf18526bbc4c5512fc8f1c34aa465b992b36cb95021674028aca0c933e1
keyed-mutex-map@2.1.2         9086d5deff052c06a8761ddca1958c435acceab0885dc8c0dc545cbcbbe9e663
resource-lease-pool@1.4.2     939525ec2c034dae185d1767190fc3a45807aa5e513afb72563efffe7cd4be18
single-flight-lock@1.0.0      62d7f2aa8bc88eae20a21cd6f7aad6a2e23c1c5c7b03d0254820f009156a1bdd
try-lock-runner@3.2.1         28d5ca79bc3cd7770e8f665d3ac31fbb23c4c408d092ae4ab228e7930d102c75
bcs-mini@1.0.1                848a514a14a54fc5fff9c4312c9580870a2a19073e5eef114c0e7519d0cf64dd
```

A later attempt at `bcs-mini@1.0.1` through unpkg was checked directly and
returns 404 on all three URL forms (`/-/bcs-mini-1.0.1.tgz`, the package root,
and `/browse/`), as do the other five. Nothing was recovered from any source; the
case arm stays at 3 publishers.

Public retrieval is exhausted. What remains is a party that resolved these during
the seven-hour live window — an upstream proxy or CI cache (Verdaccio,
Artifactory, Nexus, a GitHub Actions npm cache) on whatever host ran the original
collector, or npm security, who hold the samples they removed. Neither is
retrieval work.
