# The DataDog npm corpus does not have 1,001 independent observations

DataDog's `malicious-software-packages-dataset` is the standard public corpus for npm
supply-chain research. Its npm `compromised_lib` tree holds **1,001 packages / 1,443
package-versions**, and rates are routinely quoted over those denominators.

They should not be. Measured here, those 1,443 versions carry **56 distinct payload
signatures**. One payload file appears in **448** of them.

**Any per-package or per-version rate published over this corpus has a confidence interval
roughly five times too narrow.** That applies to this project's own numbers first — see the
withdrawn census in [prior-art.md](prior-art.md#the-measurement-that-decides-it) — and to
anyone else's.

## What was measured

Dataset commit `b8378985`, manifest md5 `d4c78defebae89b47f004c2edd50a704`; 1,001 package
directories and 1,443 archives, both counted rather than taken from the README.

For each version, the analysis root is the `package/` directory and nothing above it — the
sibling `package_info-*.json` registry packuments total **1.09 GB** and are dense with
`github.com` URLs, so any tree-wide grep drowns in registry metadata before reaching code.
Documentation and derived files are excluded by extension (`.md .markdown .txt .rst .html
.htm .map .yml .yaml`, plus `LICENSE/NOTICE/CHANGELOG/README` by name), as is
`node_modules/`. A file is *marker-bearing* if it matches any of `trufflehog`,
`Sha1-Hulud`, `Shai-Hulud`, `bun_environment`, `169.254.169.254`,
`metadata.google.internal`, `discord.com/api/webhooks`, `api.telegram.org`, `webhook.site`,
`CreateCommitOnBranch`, `_authToken`.

Each marker-bearing file is keyed by sha256. A version's **signature** is the set of those
hashes. Script and raw output: `de.py`, `design-effect.json`.

| quantity | value |
|---|---|
| package-versions | 1,443 |
| versions carrying ≥1 marker-bearing file | 1,116 |
| **distinct marker-bearing file contents** (sha256) | **64** |
| **distinct version signatures** | **56** |
| signatures appearing in exactly one version | 31 |
| versions sharing the single most common payload file | **448** |
| versions sharing the single most common signature | 402 |
| **design effect** (1,443 / 56) | **25.8** |
| variance inflation (√DE) | **5.1** |

## What it means

The effective sample size is about **56**, not 1,443 and not 1,001. At n = 56 a 95% Wilson
interval near p = 0.5 is **±12.7 percentage points**, and a unanimous result bottoms out at a
**93.6% lower bound**. That is the ceiling on precision this corpus can support. Any claim
needing finer resolution is unavailable from it, at any sample size, because the sample is
not the thing that is large.

Concretely: a published "47.3% of packages" over this corpus is a statement about how many
times roughly a dozen campaigns were republished, wearing a large-*n* disguise. The
inferential unit has to be the payload cluster.

## Robustness, and the direction of the error

The structural numbers were reproduced independently, by two different people running two
different marker sets, and the load-bearing ones are identical: **56** signatures, **448**,
**402**, **DE 25.8**. The marker-sensitive counts moved slightly — 1,116 vs 1,119
marker-bearing versions, 64 vs 66 distinct files, 31 vs 30 singletons — so the conclusion
does not depend on the exact marker list.

**25.8 is a lower bound on the design effect.** Clustering is by byte-identical sha256, so
two builds of the same payload differing in one byte count as two distinct signatures. Any
semantic clustering can only merge signatures further, never split them, which drives the
effective *n* down and the design effect up.

## Limits

- Markers are a heuristic, not ground truth. A payload sharing none of them is invisible to
  this count; 327 of the 1,443 versions carry no marker-bearing file at all and are excluded
  from the clustering entirely rather than assigned to a cluster.
- This is npm `compromised_lib` only — hijacked versions of existing packages. Not
  malicious-intent packages, not PyPI, not the other ecosystems in the dataset.
- DataDog states the corpus was "mostly identified by a single ruleset (GuardDog)", so it
  over-represents what that ruleset detects. That bias compounds the concentration rather
  than offsetting it: a single detector finds campaigns, and campaigns are what cluster.
- Byte-identical clustering is deliberately conservative, per the bound above.

## What to do instead

Report cluster-level counts with the cluster denominator stated, or report raw counts with no
interval at all. If a package- or version-level number is used for exposure — "how many
published artifacts were affected" — say so explicitly and never attach an interval to it,
because for that question the count is the whole answer and inference is not involved.
