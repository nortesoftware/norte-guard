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
