# How it works

## The capability genome

The key signal isn't "has install script" — it's **"gained an install script it never had"**:

```
capabilities(v_n) \ capabilities(v_n-1) = the signal
```

A package with an install script across 48 historical versions doesn't trigger. One that gains it in the new version does — with certainty.

## Two scoring regimes

| Package | Regime | Scoring |
|---------|--------|---------|
| ≥ 10 versions, ≥ 90 days old | `genome` | Capability delta vs history |
| New | `no-genome` | Absolute capability risk |

A package with no genome cannot be diffed against a baseline it does not have,
so in gate mode it returns `INSUFFICIENT_HISTORY` — never `PASS`. `fp-bench`
asserts that invariant on every run and fails loudly if any no-genome package
comes back with a gate verdict.

That regime is not a corner case: it was 113 of 500 packages — 22.6% — in the
run of 2026-08-12. Judging a fifth of the ecosystem needs more than the two
signals it started with, so `absolute-risk.ts` scores what can be said about a
package with no history, all of it from the packument already in hand:

- **provenance** — npm attestations or a trusted publisher. Cheap to have,
  expensive to fake, and the publisher does not control the attesting CI.
- **who published it** — the maintainer count, and whether the account that
  published this version is on the maintainer list at all.
- **age of the name** — from `time.created`, which for a package with no version
  history is the only age there is.
- **metadata completeness** — repository, README, description. Individually
  trivial and trivially faked; together they say whether the package was
  published to be read by people or resolved by a machine.
- **typosquatting** — optimal string alignment distance against the most
  downloaded names, so an adjacent transposition (`axios` to `axois`) costs one
  edit rather than two.
- **dependencies that are themselves new** — computed only when the caller
  supplied dependency ages, since finding out costs one request per dependency.

Two of those cannot be answered from public data, and neither is approximated by
something that is not it. Maintainer **account age** is unavailable: npm's user
endpoint returns 401 without credentials. Dependency ages are skipped by default.
Both are emitted as 0-point signals that name the hole, so a reader of the signal
list can see which checks did not run rather than assume they passed.

## What layer 1 can and cannot price

Layer 1 reads the packument only: one request, no tarballs. Some signals are
visible there but not *decidable* there, and those are recorded at **0 points**
rather than guessed at.

`entrypoint_changed` is the case that matters. A `main`/`exports`/`browser`
delta is exactly the AsyncAPI/Miasma vector — the published files look
unremarkable while the module that actually loads is not the one being read. It
is also what an ordinary ESM migration looks like, and measured against the top
of the ecosystem it fires on roughly a quarter of packages. At layer 1 it is a
proxy for "this package modernised", not for "this package was taken over".

The signal it was trying to be needs both halves of the claim:

> the entry point changed **and** the file it now resolves to carries
> capabilities the previously resolved file did not.

That requires downloading both tarballs, resolving the entry fields to real
files inside each, parsing them, and diffing the reachable capabilities. Only
the conjunction is evidence: a takeover redirects to a file whose behaviour is
new, while a CJS-to-ESM split redirects to a file whose behaviour is identical.
Layer 1 sees the redirect and cannot see the behaviour, so it does not charge
for it. The observation still ships in the JSON and in the capture deltas,
because layer 2 will use exactly this delta as its trigger.

## Three mitigations against genome poisoning

An attacker who knows norte-guard could publish 20 "clean" versions to establish a benign baseline, then activate the payload. norte-guard counters this with:

1. **Sticky acquisition** — a capability a package ever had never regains the "never had it" discount
2. **Minimum baseline age (90 days)** — a capability only provides coverage if it appeared > 90 days ago
3. **Account continuity** — if the maintainer changed, the previous history doesn't cover the new one

## Ghost versions — our unique signal

npm keeps timestamps in `time{}` for **all** versions, including unpublished ones. If a version exists in `time{}` but not in `versions{}`, it was published and removed.

`@qlik/embed-runtime@1.6.4` (Shai-Hulud, August 4, 2026) is still recorded in `time{}` even though it was removed. norte-guard detects it as a recent ghost version. No other tool uses this signal.

---

## Shai-Hulud: real remediation times

Measured from actual packument timestamps:

| Package | Real TTR |
|---------|----------|
| keyv@6.0.0 | 104 min |
| flat-cache@6.1.24 | 32 min |
| file-entry-cache@11.1.6 | 99 min |
| cache-manager@7.2.10 | 57 min |
| cacheable-request@13.0.20 | 28 min |
| **Mean** | **64 min** |

The 24h quarantine (1440 min) would have given **22× margin** against Shai-Hulud.  
norte-guard detects packument anomalies in **< 1 minute** from publication.

---

## A3 — four capabilities, over the graph A1/A2 already builds

`reachability.ts` answers "can this code reach X". It said, in its own header,
that it would not answer whether reaching X is dangerous, because the project
had two confirmed samples with bytes and deciding malice on n=2 is a preference
wearing a measurement's clothes.

There are 42 confirmed captures with bytes now. Four capabilities, fixed before
the run:

| capability | reached when |
|---|---|
| `credential_read` | a string naming a secret reached a filesystem or path call, **or** `process.env` was read for a token-shaped variable |
| `network_egress` | `net`, `http`, `https` or `dgram` is reached, or the global `fetch` is called |
| `external_exec` | `child_process` is reached |
| `dynamic_code` | `vm` is reached, or `eval`/`Function` is called, or a specifier is decided at runtime |

Three of the four are pure reachability and add no patterns. The fourth needs an
argument — nearly every package on npm reaches `fs`, and
`readFileSync('./package.json')` is not a credential read — so two frozen lists
exist, and they are applied only to strings that **demonstrably flowed into a
call on a value the graph was already following**. A literal sitting in a file
nothing calls does not qualify, and every result carries the count of secret
paths only a text search would have found, so the difference between this and
`grep` is measured on every package rather than claimed once.

### The three gates are the three ways a *module* arrives

They are not the three ways a capability arrives. `process.env`, `fetch`, `eval`
and `Function` are ambient: nothing imports them, and there is no origin to
follow back because nothing ever handed them over. They are recorded in their
own field, deliberately **not** in the module list — a pseudo-module named
`fetch` in `reachable` would appear in every module-prevalence table this
project has already published and change comparisons made without it. Measured:
over 132 corpus captures, the six pre-existing fields of the graph are identical
before and after the change, in 132 of 132.

### Three answers, never two

`reached`, `not-reached`, `indeterminate`. Every kind of lost trail is mapped to
what it can hide: a specifier decided at runtime can be any module, so it blinds
the three module capabilities — and it *is* `dynamic_code`, so one fact blinds
three answers and settles the fourth. `reached` always beats blinded.

This is not fastidiousness. **37 of the 42 confirmed captures ship an executable
no parser reads** — `@siwatfa/yorn` puts its entire payload in a 15MB V8
bytecode cache — so a two-valued analysis records them as reaching nothing at
all, and the malicious cohort comes out cleaner than its control **because it is
better hidden.**

## A5 — does any of it separate?

Cases: every `confirmed_malicious` capture that still holds bytes. Controls:
drawn from the collector's own captures, matched **on size** (nearest neighbour
on log unpacked size, within a factor of two — worst measured pair 1.60×), from
the **same days**, and **not withdrawn** by any of five records on disk.

The caliper is re-applied when the match is expanded. The match draws one
representative capture per control package; what gets measured is every capture
of that package in the window, and v1.3.0 never re-checked the band on that
second set. Twelve captures of three packages were outside it, the worst
`@vanillaskyai/sdk` at **11.39×** against a case it was matched to at 1.02× —
inside the one arm that carried the run's only `SEPARATES` row. They are dropped
and listed.

**The 42 are 6 packages published by 3 npm accounts.** One of them republished
36 times in 38 hours. Every rate is therefore computed at five units — capture,
package, publisher, and the two `-any` unions — and the publisher one is
primary. The capture row is printed beside it to show how much the unit changes
the answer:

| unit | `dynamic_code`, cases minus controls |
|---|---|
| capture (n=42 vs 87) | **+78.4pp**, family-adjusted CI +47.0 to +89.6 — excludes zero |
| publisher (n=3 vs 49) | +72.2pp, family-adjusted CI −24.3 to +91.8 — includes zero |

Same packages, same bytes, same analysis. The first row is one operator counted
36 times, and it is printed last for that reason.

**What the run could have found is printed before what it did.** At three
independent cases and forty-nine controls, the most it can establish is "every
case reaches it and at most 10 of 49 controls (20.4%) do". **All four** control
rates at that unit are above that ceiling — 23%, 48%, 48% and 28% — so the run
was never able to separate any of them, whatever the cases did. A rate that
could never have separated is not a null result.

v1.3.0 said "three of the four" here. That count was the capture unit's rates
measured against the publisher unit's ceiling; against their own ceiling of
79.3% none of them clears it. The one that fell out of the list was
`dynamic_code`, which is the row the table above highlights.

The honest summary at the primary unit: **nothing is established.** Two of the
four are not calculable at all — every case is indeterminate, and a rate over an
empty denominator is not a rate.

One thing the run says about a definition rather than a package.
`credential_read` is a disjunction, and the two halves behave nothing alike: of
the 20 controls that reach it, **19 do so by reading a token-shaped environment
variable and 1 by a path that named a secret.** Half of npm's build tooling
reads `*_TOKEN`. Reported apart on every group for that reason, and the obvious
consequence — that these are two capabilities and not one — is left for a phase
that can test it on samples it did not come from.

### What the six actually reach

| package | account | credential | network | exec | dynamic |
|---|---|---|---|---|---|
| `@siwatfa/yorn` (36 captures) | siwatfa | ? | ? | ? | **yes** |
| `leb128x` | ferrousdev | ? | **yes** | ? | ? |
| `kit-hydration-vim` | a_soclav | ? | ? | **yes** | ? |
| `sui-gql-core` | ferrousdev | no | **yes** | no | no |
| `svelte-goal-vim` | a_soclav | ? | no | no | no |
| `bcs-core` | ferrousdev | ? | ? | ? | ? |

`?` is not a shrug. `@siwatfa/yorn` is bytecode; `bcs-core` and `leb128x@1.0.0`
`require('./_perf.js')` and do not ship it — the payload arrives in the next
version, which is why the run also reports every unit as a union over all
captures of it.

### Two things the run declares about itself

**Contamination.** Two of the six case packages are named in this codebase as
the reason a bound exists — `@siwatfa/yorn` for the function-body walk limit,
`kit-hydration-vim` for the magic-byte file classifier — and both bounds blind
capability answers. Excluding the packages would not remove their influence on
how everything else is measured, so the run states them and then measures
whether either bound decided its own package's answer. It did not: **0 answers
rest on either bound alone.**

**A post-hoc definition, held apart.** `SECRET_PATHS` holds joined paths and
real code writes `path.join(home, '.aws', 'credentials')`, whose arguments are
three strings none of which is in the list. The repaired definition reassembles
each `path.join` call site and finds `.aws/credentials` in `leb128x@1.0.1` — a
Sui keystore and AWS credential stealer that exfiltrates over the GitHub API.
That result is printed under its own heading and excluded from the evidence,
because a definition changed after seeing the cases is fitted to them. The next
confirmed sample is the test of it.
