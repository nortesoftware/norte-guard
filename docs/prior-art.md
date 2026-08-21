# Prior art

Written on 2026-08-21, after a near miss.

The `ltidi` off-registry dependency mechanism was about to be published as this
project's own finding. It is not. It is **PhantomRaven**, documented by Koi
Security in October 2025 under the name Remote Dynamic Dependencies, and the
eight specific packages already carried public advisories three days before this
project read their tarballs.

Nothing was published, so nothing has to be retracted. But the check should have
happened before the analysis, not after it, and this document exists so that the
next piece is checked first.

**The rule from here: no piece is written up as a finding until prior art has
been searched. Same discipline already applied to the numbers — nothing is
asserted without verification.**

---

## The near miss, in detail

`gunzip-js@99.9.1` was captured on 2026-08-15 at 14:27:57 UTC. The Amazon
Inspector advisory for it was published at **15:31:09 UTC the same day**, about
one hour later, and reads:

> `gunzip-js@99.9.1` is a near-empty npm package (typosquat of the well-known
> gunzip-maybe / gunzip family) whose package.json declares its sole dependency
> `ltidisafe` as an HTTPS tarball URL — `https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.2.tgz`
> — instead of a version resolved from the npm registry. […] the path segment
> `depenconf` mirrors the term dependency-confusion, the version 99.9.1 is the
> classic high-number squat pattern, and the package's own index.js is empty

Every observation in this project's C1 write-up — the empty index, the GCS
bucket, the semver squat, the reading of `depenconf` — was already in that
advisory. It was found by searching for who to report to.

All eight packages have OSV records, all with GHSA aliases, sourced from Amazon
Inspector, OSSF Package Analysis and ghsa-malware:

| package | OSV | GHSA alias (gunzip-js shown) |
|---|---|---|
| `check-audit` | MAL-2026-13976 | |
| `cspell-esm` | MAL-2026-13977 | |
| `eslint-generate-release` | MAL-2026-13980 | |
| `napi-raw` | MAL-2026-13984 | |
| `resolve-audit` | MAL-2026-13987 | |
| `depcruise-baseline` | MAL-2026-14053 | |
| `depcruise-fmt` | MAL-2026-14054 | |
| `gunzip-js` | MAL-2026-14056 | GHSA-2hqf-5jxh-4wp2 |

---

## Classification of every piece

`replication` — the idea is published and this is an independent re-observation.
`extension` — published work exists and this adds a measurement or a variant.
`not found` — no prior publication surfaced in the sources searched. **This is
not a claim of novelty.** It is the result of about a dozen web searches, and
absence of evidence at that depth is weak evidence of absence.

### Off-registry dependencies as a vector — **replication**

Fully published, twice over, and detected by shipping tools.

- **Koi Security, PhantomRaven** (Oct 2025) — "Remote Dynamic Dependencies", 126
  packages, 86,434 downloads, campaign running since August 2025. Names chosen to
  exploit LLM hallucination. ([koi.ai](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies))
- **Sonatype** — 83 further packages, taking the campaign past 200. ([sonatype.com](https://www.sonatype.com/blog/phantomraven-npm-malware))
- **Socket** ships an `HTTP Dependency` alert, **High** severity, supply-chain-risk
  category: *"Contains a dependency which resolves to a remote HTTP URL which
  could be used to inject untrusted code."* It flags both HTTP and HTTPS.
  ([socket.dev](https://socket.dev/alerts/httpDependency))

This project's contribution here is **not the mechanism and not the detection**.

### Concentration: one operator, many names, one off-registry host — **extension**

The concept is published. Socket reported a campaign of **60 packages across at
least three publisher accounts, all sending to the same Discord webhook**, and
treated the shared destination as the thing that establishes one operator.
([socket.dev](https://socket.dev/blog/npm-targeted-by-malware-campaign-mimicking-familiar-library-names))
That is the same idea applied to an exfiltration host rather than a dependency
host.

A prevalence figure also exists: an empirical study of npm dependencies reports
**URL or local-file dependencies at about 2% of all dependencies**, over a
different population and denominator than the publish stream.

What was **not found** is a base-rate distribution of
`(operator, off-registry destination)` pairs over a publish stream — the
measurement that 30 of 33 pairs hold one name, 2 hold two, and one holds eight.
That is the only part of this piece worth writing up, and it is an extension of a
published idea rather than a new one.

### Coordinated campaign / family detection — **replication**

- **Socket**: three accounts, 60 packages, identical host-fingerprinting code,
  eleven-day window, similar email addresses.
- **Socket, burst publishing**: *"one actor published 26 packages in 4 minutes,
  switched accounts, and published 7 more in a 1-minute burst, with the ~14-hour
  overnight gap and unchanged C2 host indicating the same operator."*
- **Panther**: DPRK npm malware factory, 108 packages, 261 versions, 31-day
  campaign wave, cluster analysis. ([panther.com](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave))

`ecosystem.ts`'s `detectFabricatedFamilies`, `family.ts`'s burst partition, and
`operator.ts`'s cross-account linking are all re-observations of this. The Socket
burst description is close to identical to `numberedSequences` in what it
observes; what differs is that this project's version keys on a numeric counter
in the name rather than on a shared C2 host, and that it reports a base rate
(one firing in 12,327 names).

`detectFabricatedFamilies` also has a recall of 0 of 26 here, documented in
`audit-a5.md`, so there is nothing to claim for it in any case.

### Capability genome — capability gain against a package's own history — **replication / extension**

The general form is standard in the literature and in tooling.

- **Practical automated detection of malicious npm packages** (ICSE 2022) —
  rule-based detection over install-script keywords, runtime evaluation, and
  *"whether new files, new dependencies and new hook script entries are
  present"*. ([dl.acm.org](https://dl.acm.org/doi/10.1145/3510003.3510104))
- **Endor Labs** treats *"a package that has not published in two or more years
  releasing a new version that adds optionalDependencies or lifecycle hooks"* as
  a detection heuristic. ([endorlabs.com](https://www.endorlabs.com/learn/mini-shai-hulud-returns-42-malicious-npm-packages-fake-sigstore-badges-in-antv-ecosystem-attack))

The extension, if any, is the three-valued regime handling — `INSUFFICIENT_HISTORY`
as a distinct verdict rather than a pass — and the measurement that 100% of the
observed class returns it. That measurement is in `audit-a5.md` as D14.

### The `young + tiny + !hasRepository` conjunction — **extension**

Component parts are published. Trivial and low-functionality packages are
characterised at scale: **17.92% of npm packages are trivial**, with a rule-based
detector at 94% accuracy, including a "data-only" class with no executable logic
([arXiv:2510.04495](https://arxiv.org/abs/2510.04495)). Repository-presence checks
appear in reproducibility-oriented detectors.

What this project adds is the specific three-way conjunction as a *capture*
filter rather than a detection rule, and — more usefully — the measurement that
it is calibrated for the decoy and not the carrier (D16), and that `fabricatedProfile`
fires on 82.66% of the class it applies to (D14). Both of those are negative
results about the conjunction, not claims for it.

### Share of packages unreadable to static analysis — **extension**

- **Moog et al., CISPA** — statically detecting JavaScript obfuscation and
  minification. ([cispa](https://swag.cispa.saarland/papers/moog2021statically.pdf))
- **Benchmark-driven empirical analysis of npm malicious package detection** —
  of 6,420 malicious packages, **80.3% use no evasion at all**; among the 19.7%
  that do, string obfuscation leads. ([arXiv:2603.27549](https://arxiv.org/pdf/2603.27549))
- Another study puts obfuscation in malicious npm packages near **49%**.

`analyzability.ts` measures something adjacent but not identical: not "is this
obfuscated" but "what fraction of the executable bytes can a conforming parser
read at all", counting native binaries, WASM and V8 bytecode caches as
unreadable. The 1.7%-of-files figure for this corpus is a measurement of that
question, which is why idea 1's opacity endpoints saturated against minification
— a result consistent with the 80.3% figure above.

### Time-to-unpublish / time-to-remediation — **not found**

npm's unpublish policy is documented, and informal figures circulate
("somewhere between six minutes and six weeks"). No formal measurement study
surfaced. The 64-minute median in `ttr-log.ndjson` is over 194 observations from
one collector's window and is not a registry-wide figure.

### `0.0.1-security` as a field ground-truth label — **replication**

Well established. **Phylum** ships an `NPM Security Holding` analytic; Socket,
Snyk, ReversingLabs and libraries.io all surface the placeholder. Using it as a
label source is standard practice, not a contribution — and `audit-a5.md` already
documents that the takedown log built from it over-counts, since 16.3% of a
sample still had real versions.

### Numbered counters crossing accounts — **not found**

The closest published work is Socket's burst-plus-account-switch observation
above, which links accounts by a shared C2 host and by timing rather than by a
counter embedded in package names. No publication surfaced that keys on a numeric
sequence spanning accounts.

Classified `not found` rather than novel, and it is descriptive with n=1 in any
case.

---

## What survives as this project's own

Short, and worth being short.

1. **Eight tarballs** for packages npm removed. The advisories describe them; the
   bytes are held here. Whether anyone else retained them is unknown.
2. **A base-rate distribution** of `(operator, off-registry destination)` pairs
   over a publish stream, with the window analysis. An extension of Socket's
   shared-destination idea, not a new one.
3. **The negative results**, which are the largest part of this work and the part
   least likely to be duplicated: opacity saturating against minification, the
   family endpoint saturating against monorepo releases, metadata velocity
   separating at the capture unit and vanishing at the operator unit,
   `detectFabricatedFamilies` at 0-of-26 recall, `fp-bench` unable to measure any
   class-restricted signal, and D1's style-uniformity idea failing because the
   payloads are not source.

---

## Sources

- [Koi Security — PhantomRaven: NPM Malware Hidden in Invisible Dependencies](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies)
- [Sonatype — PhantomRaven: npm Malware Uses Remote Dynamic Dependencies](https://www.sonatype.com/blog/phantomraven-npm-malware)
- [Socket — HTTP Dependency alert](https://socket.dev/alerts/httpDependency)
- [Socket — npm targeted by malware campaign mimicking familiar library names](https://socket.dev/blog/npm-targeted-by-malware-campaign-mimicking-familiar-library-names)
- [Panther — Inside DPRK's npm Malware Factory](https://panther.com/blog/inside-dprk%E2%80%99s-npm-malware-factory-108-packages-261-versions-and-a-31-day-campaign-wave)
- [Ohm et al. — Backstabber's Knife Collection](https://arxiv.org/abs/2005.09535)
- [Detecting and Characterizing Low and No Functionality Packages in the NPM Ecosystem](https://arxiv.org/abs/2510.04495)
- [Understanding NPM Malicious Package Detection: A Benchmark-Driven Empirical Analysis](https://arxiv.org/pdf/2603.27549)
- [Moog et al. — Statically Detecting JavaScript Obfuscation and Minification](https://swag.cispa.saarland/papers/moog2021statically.pdf)
- [Practical automated detection of malicious npm packages (ICSE 2022)](https://dl.acm.org/doi/10.1145/3510003.3510104)
- [Endor Labs — Mini Shai-Hulud Returns](https://www.endorlabs.com/learn/mini-shai-hulud-returns-42-malicious-npm-packages-fake-sigstore-badges-in-antv-ecosystem-attack)
- [Phylum — NPM Security Holding](https://docs.phylum.io/analytics/npm_security_holding)
- [OSV — MAL-2026-14056](https://api.osv.dev/v1/vulns/MAL-2026-14056)
- [GHSA-2hqf-5jxh-4wp2](https://github.com/advisories/GHSA-2hqf-5jxh-4wp2)
