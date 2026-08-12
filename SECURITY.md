# Security Policy

## Reporting a Vulnerability

**Contact:** security@nortesoftware.dev

**We are two people.** We respond within business days, not hours. No automated triage, no SLA, no bug bounty program.

What we do: read every report, reproduce the issue, ship the fix with credit to the researcher if they want it, and be direct about timelines.

## Scope

In scope:
- norte-guard source code (src/, CLI)
- The .ngpack format and its integrity verification
- The watcher and its handling of malicious tarballs

Out of scope:
- The npm registry itself (report to npm directly)
- Vulnerabilities in packages that norte-guard analyzes

## What we don't do

We don't distribute malware tarballs even for research purposes. .ngpack files captured by the watcher are local to the user running it. We don't upload them to any public repository.

## Coordinated Disclosure

We ask for 90 days before public disclosure. If the fix takes longer, we'll coordinate an extension.
