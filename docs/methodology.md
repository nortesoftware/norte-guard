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
