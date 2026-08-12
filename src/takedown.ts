// npm publishes 0.0.1-security over a package it has removed. That is the
// registry issuing a verdict, not norte-guard labelling its own captures: it is
// external, verifiable by anyone, and reproducible from the packument. It is the
// first thing found that meets the bar for confirmed_malicious.
//
// LABEL ONLY. NEVER A FEATURE.
//
// A takedown happens after the fact. Feeding it to the scorer would let the
// detector recognise packages by the mark left when someone else caught them,
// and the benchmark would then measure that circle instead of detection. Nothing
// in this file is imported by scorer.ts, and a test asserts that no signal type
// derives from it.
//
// The two sides come from different sources on purpose:
//
//   label      the packument as it is NOW, fetched fresh from the registry
//   detection  the packument as it was WHEN CAPTURED, read from the .ngpack
//
// Anything else mixes evidence from after the event into a question about
// before it.

import { sortedVersions, type Packument } from './packument.js'

export const NPM_SECURITY_HOLDER = '0.0.1-security'

export interface TakedownVerdict {
  package: string
  // The version held by the capture, which is the one detection is asked about.
  capturedVersion: string
  takenDown: boolean
  // True when the captured version is itself the placeholder. Those captures
  // hold npm's marker rather than the artifact, so they carry a label and no
  // sample.
  capturedIsHolder: boolean
  // The captured version no longer exists in the registry.
  capturedVersionPurged: boolean
  holderPublishedAt: string | null
  purgedVersions: string[]
  evidence: string
}

export function detectTakedown(
  current: Packument,
  capturedVersion: string
): TakedownVerdict {
  const holder = current.versions[NPM_SECURITY_HOLDER]
  const takenDown = Boolean(holder)

  const purgedVersions = Object.keys(current.time ?? {})
    .filter(v => v !== 'created' && v !== 'modified')
    .filter(v => !(v in current.versions))

  const capturedIsHolder = capturedVersion === NPM_SECURITY_HOLDER
  const capturedVersionPurged =
    !capturedIsHolder &&
    !(capturedVersion in current.versions) &&
    capturedVersion in (current.time ?? {})

  const holderPublishedAt = holder
    ? (current.time?.[NPM_SECURITY_HOLDER] ?? holder.publishedAt ?? null)
    : null

  return {
    package: current.name,
    capturedVersion,
    takenDown,
    capturedIsHolder,
    capturedVersionPurged,
    holderPublishedAt,
    purgedVersions,
    evidence: takenDown
      ? `npm published ${NPM_SECURITY_HOLDER}${holderPublishedAt ? ` on ${holderPublishedAt}` : ''}; ` +
        `${purgedVersions.length} versions removed` +
        (capturedVersionPurged ? `, including the captured ${capturedVersion}` : '')
      : 'no removal marker in the registry',
  }
}

export function takedownLabelSource(verdict: TakedownVerdict): string {
  return `npm-takedown: ${verdict.evidence}`
}

// A takedown is only a recall sample if the collector saw the package before npm
// removed it. Publishing 0.0.1-security is itself a change on the feed, so a
// watcher that started after the attack observes the placeholder and nothing
// else — a label with no artifact and no question to ask the detector.
export interface ObservationWindow {
  package: string
  // The dist-tag latest at the moment the collector saw it.
  observedVersion: string
  observedAt: string
}

export function isPreTakedownObservation(observed: ObservationWindow): boolean {
  return observed.observedVersion !== NPM_SECURITY_HOLDER
}

// A capture is a usable recall sample only when it holds the artifact npm later
// removed. Holding the placeholder proves the takedown and proves nothing about
// detection.
export function isUsableRecallSample(verdict: TakedownVerdict): boolean {
  return verdict.takenDown && !verdict.capturedIsHolder && verdict.capturedVersionPurged
}

// The packument as it stood when `version` was published, with everything
// published later removed.
//
// This is what makes the recall question answerable. Scoring against the
// packument as it is today would let the detector see the takedown, the
// placeholder and every version that came after — none of which existed at the
// moment the gate would have had to decide.
export function packumentAsOf(p: Packument, version: string): Packument {
  const target = p.versions[version]
  const cutoff = target
    ? new Date(target.publishedAt).getTime()
    : new Date(p.time?.[version] ?? '').getTime()

  if (!Number.isFinite(cutoff)) return p

  const versions: Packument['versions'] = {}
  for (const [ver, meta] of Object.entries(p.versions)) {
    const t = new Date(meta.publishedAt).getTime()
    if (Number.isFinite(t) && t <= cutoff) versions[ver] = meta
  }

  const time: Record<string, string> = {}
  for (const [key, ts] of Object.entries(p.time ?? {})) {
    if (key === 'created') { time[key] = ts; continue }
    if (key === 'modified') continue
    const t = new Date(ts).getTime()
    if (Number.isFinite(t) && t <= cutoff) time[key] = ts
  }

  const latest = sortedVersions({ ...p, versions }).at(-1)?.version ?? version

  return {
    ...p,
    versions,
    time,
    distTags: { latest },
  }
}
