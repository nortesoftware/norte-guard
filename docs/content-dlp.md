# Content inspection of install egress catches 1 payload cluster in 43

The last design left standing after host granularity and method granularity both failed was
to stop filtering *where* data goes and filter *what* goes: fingerprint the sensitive files by
rolling window at startup — `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_*`, `~/.config/gcloud`,
`~/.docker/config.json` — inspect the install's egress, and cut on a match. DLP applied to
`npm install`.

**Measured against the payloads that actually exfiltrate, it fires on 1 cluster out of 43 —
2.3%, 95% Wilson [0.4, 12.1].** It dies three more times independently, and the corpus shows
the attackers already past it.

Counts are over **payload clusters**, not packages or versions: this corpus has a design
effect of 25.8 and per-package rates are meaningless
([design-effect.md](design-effect.md)). Denominator 43 = 56 clusters − 8 marker false
positives − 5 that use a token for authentication with no attacker sink.

## The dominant family never sends a credential file

Shai-Hulud generations 1 and 2 are ~19 of 56 clusters and ~841 of 1,443 versions, and **not
one byte of a credential file reaches the wire**:

- `~/.npmrc` is read only through a regex that captures the `_authToken` *value*
  (`bundle.js:2601019`; deobfuscated `bun_environment.js:9384191`).
- the bulk of what it ships is `trufflehog filesystem $HOME --json` **findings**
  (deobfuscated `:9402436`) — a report about secrets, not the secrets' files.
- `~/.aws/credentials` is consumed by the AWS SDK provider chain and SigV4-signed, so the
  secret access key is used as an **HMAC key** and never crosses the wire in any encoding at
  all.

The one family that reads exactly the proposal's file list whole — `env-compat.js:5930` — then
**encrypts it with an RSA-4096 public key shipped in the package**. Its `plaintext_data`
fallback fires only when `public.pem` is absent, and `public.pem` is present in every
clustered version.

So the mechanism has almost nothing to match. The single hit is `nx` s1ngularity, one cluster,
one version, which reads `~/.npmrc` whole and triple-base64s it
(`telemetry.js:4998`, `:6463`).

## The flattering number belongs to a different product

Score windows over the extracted secret *value* rather than the file, after normalisation, and
the rate is **30/43 = 69.8% [54.9, 81.4]**. That is the number a write-up would be tempted to
quote, and it should not be, for two reasons.

First, it is a **secret-value scanner**, not file fingerprinting — a different mechanism with
twenty years of prior art (below). On the taxonomy as literally written, RAW + ENCODED +
COMPRESSED is only **11/43 = 25.6% [14.9, 40.2]**; the 19-cluster gap is payloads that
*restructure* — re-emitting the 40-byte token verbatim inside nested keyless base64. And the
window arithmetic is unforgiving: a 20-byte AWS access key ID survives **zero** 32-byte
windows, while a 16-byte window collides with ordinary text.

Second, and decisively:

## The temporal split, which is what actually decides it

| clusters | dated | envelope | catchable |
|---|---|---|---|
| **30 of 30** | 2025-07 → 2025-12 | keyless | **yes** (Wilson lower bound 88.6) |
| **13 of 13** | 2026-04 → 2026-05 | gzip + AES-256-GCM + RSA-OAEP, or AES-CBC + RSA-4096-OAEP | **no** (lower bound 77.2) |

**No overlap.** A content filter would have caught the 2025 campaigns the industry already has
signatures for, and none of the current ones. Shai-Hulud's own third generation crossed the
line between 2025-12 and 2026-04 — and it cost the attacker nothing structural: `dispatch()`
builds **one** envelope and hands the same ciphertext to the HTTPS sender, the GitHub commit
sender and the Session messenger, so encryption cost them no channel; the RSA harvester ships
`public.pem` in the package and the worm stub propagates it, so key distribution cost them
nothing either.

## It also dies on deployment, before any rate applies

**Forced interception with no opt-in yields zero bytes of body.** Measured: in a netns with a
MITM minting per-SNI leaves from a private CA, every payload-shaped client aborted — bare
`https.request`, bare `fetch`, base64, gzip, aes-gcm — all `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.
The proxy learns `tlsClientError` plus SNI, which the existing SNI rig already produces without
terminating anything.

Content becomes visible only once the trust anchor is in the payload's **inherited
environment** — and that is exactly what the payload controls. Measured with a real
`postinstall`: npm's own `cafile` gave TLS-ABORT and no request at all; `NODE_EXTRA_CA_CERTS`
gave the full 71-byte credential body. Then, from inside the payload:

```js
execFileSync(process.execPath, [...], { env: {} })   // one line — back to ABORT
```

The defender's anchor is one line of child-process env stripping away from gone. (`tls
.getCACertificates('extra').length` is 1 with the CA injected and 0 without, while
`tls.rootCertificates` stays 145 — so the naive check misses the strip and the correct one
catches it.)

And it is not "a CA in five trust stores" but four mechanisms and a trap:

- `git 2.47.3` is libcurl-**GnuTLS** and **ignores `SSL_CERT_FILE` and `SSL_CERT_DIR`
  entirely** — only `GIT_SSL_CAINFO` / `http.sslCAInfo` work.
- `SSL_CERT_FILE` **replaces** the store rather than adding to it: python went from 150 loaded
  CAs to 1, silently destroying public-CA verification.
- mTLS to a private registry breaks under re-origination (`tlsv13 alert certificate required`)
  unless every client key moves into the proxy.
- the proxy can cut but never **redact** — flipping one byte per chunk produced npm tarball
  integrity failures and `Z_DATA_ERROR`, because SRI hashes the bytes.
- untested because absent here: pnpm (`cafile`/`strict-ssl` documented as ignored), yarn berry
  (#7073 open), bun (regressed in 1.3.2), cargo (webpki-roots compiled in, not overridable).

Cost once it works, 40 packages / 8.29 MB, n=7, loopback: 4,374 ms direct → 4,545 ms
terminating with no inspection (+3.9%).

## And the matcher cuts npm's own credential

`~/.npmrc` legitimately contains a registry URL and a token, and npm sends that token to the
registry **on purpose** for private packages. So the filter must exempt "token to its own
registry" — which is a rule about the destination, i.e. the control this design was invented
to escape.

## "The attacker pays a cost" is false

Measured against a raw + base64 + gzip + zlib + hex normaliser: raw, base64, gzip, hex, and a
secret split across two requests all **match**. AES-256-GCM (same fetch, same host, three
extra lines) **sent**. Single-byte XOR (one line) **sent**. 8-byte JSON chunking (one line)
**sent**. Node ships `crypto` and `zlib` in core; the tax is three lines and no lost
capability. The asymmetry runs the other way — the defender pays TLS termination across five
toolchains, a broken mTLS path, an inability to redact, and a false positive on npm's own
credential.

## Prior art: the mechanism is old, and two vendors already declined it

The premise that "nobody did this because everyone came from the sandbox world" is **refuted**.

- The core algorithm — rolling-hash windows over sensitive file contents, matched against
  egress, with partial-content matching — is **Symantec/Broadcom Indexed Document Matching**,
  shipped for ~20 years, and is covered by granted US patent **11,429,589**, whose claim
  language reads like this proposal's diagram. (Noted as a fact to check, not as legal advice.)
- The DLP world *did* arrive: `leakproof`, Pipelock, iron-proxy and Cyberhaven ship an inline
  egress proxy that decodes encodings and blocks on credential content — pointed at LLM agents
  rather than package managers. Pipelock already "decodes base64, hex, and URL encoding before
  pattern matching", so the proposal's normalisation step is this class's standard preprocessing.
- **The strongest signal.** Both parties who already own the CI transport built
  content-capable plumbing and deliberately stopped short of body matching. GitHub's native
  egress firewall terminates TLS in production with ephemeral per-run certificates — and logs
  "the URL without query arguments". StepSecurity's Harden-Runner reads plaintext at
  `SSL_write` via eBPF uprobes, needing **no CA at all** — and extracts only the HTTP method
  and path. Two independent teams holding decrypted bytes, both declining to match on content.
- `safedep/pmg` already installs a CA on developer machines for npm, and explicitly scopes the
  egress leg out.

This also corrects a claim this project made: content inspection does **not** require TLS
termination. It requires *terminate TLS with a CA, **or** be root* — the eBPF path needs
`CAP_BPF`, which is out of reach here for the same reason everything else has been.

## Verdict

**Dead.** Same shape as the two before it: a design that dies on a census-shaped measurement.
What survives is not a DLP but the negative result, plus one thing needing no content
inspection at all — under forced interception the payload aborts and the proxy still learns
the SNI, which the existing rig already gives.

> Content inspection of npm install egress, measured against 43 exfiltrating payload clusters
> of the DataDog corpus (design effect 25.8), catches the sensitive files it fingerprints in
> **1 cluster out of 43 (2.3%, 95% Wilson [0.4, 12.1])** — the dominant Shai-Hulud family
> ships trufflehog findings and a regex-captured token rather than file bytes, and every
> 2026-dated cluster that reaches an attacker sink is RSA-wrapped AES, so a content filter
> would have caught the 2025 campaigns the industry already has signatures for and none of the
> current ones, at the price of terminating TLS for the whole toolchain with a trust anchor
> the payload can strip from its own child process in one line.

## A methodological correction worth more than the proposal

**Grep-based "N% of malware encrypts" figures are floors, and their error is concentrated in
the newest clusters.** Measured today: `router_init.js` — the newest Shai-Hulud generation, 4
clusters / 173 versions — contains **zero** literal occurrences of `createCipheriv`,
`publicEncrypt`, `aes-256-gcm` or `RSA_PKCS1_OAEP`, while provably building an AES-GCM + RSA
envelope. All of it lives behind the obfuscator's string array and is recoverable only after
static deobfuscation.

Three incompatible prevalence figures were produced during this assessment for exactly that
reason — 5/62 files by one grep, 13/64 by another, 13/43 clusters by per-cluster reading after
deobfuscation. **Do not average them; the deobfuscated read is authoritative and both greps
are floors.** This is the same species of correction as [design-effect.md](design-effect.md)
and it applies to anyone counting capabilities in obfuscated payloads by string search.

## Limits

- 327 versions carry no marker-bearing file and sit outside the clustering entirely. They are
  the only thing that could move 2.3% or the encrypted share in either direction.
- The evasion-cost lane of this assessment did not complete; its content came from an adjacent
  lane, so the evasion figures are less independently corroborated than the rest.
- Everything here is static reading. No sample was executed and no host in any sample was
  contacted.
- DataDog's corpus is "mostly identified by a single ruleset (GuardDog)", so it
  over-represents what that ruleset detects — and campaigns are what cluster.
