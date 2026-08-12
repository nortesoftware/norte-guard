// Vectors the ecosystem does not cover well and that the packument alone is
// enough to detect. Scope-squatting and hallucinated-package detection stay in
// here at low scores because their limits are known and documented below rather
// than hidden behind a confident number.

import type { Packument } from './packument.js'
import type { Signal } from './types.js'

// If `^1.0.0` resolves to `1.999.999`, everyone on that range picks up the
// malicious version on their next install.
//
// Sorted by time{} rather than by version string: 1.10.0 sorts below 1.9.0
// lexically, which would hide exactly the jump this looks for. The thresholds
// are deliberately high so date-based versions (20240101 → 20240102) and repos
// that burn patch numbers on hotfixes do not trip it.
export function detectSemverAbuse(p: Packument): Signal | null {
  const entries = Object.entries(p.time)
    .filter(([v]) => !['created', 'modified'].includes(v) && v in p.versions)
    .sort(([, a], [, b]) => new Date(a as string).getTime() - new Date(b as string).getTime())

  if (entries.length < 5) return null

  const recent = entries.slice(-10)

  for (let i = 1; i < recent.length; i++) {
    const prevVer = recent[i - 1]![0]
    const currVer = recent[i]![0]

    const prev = parseSemver(prevVer)
    const curr = parseSemver(currVer)
    if (!prev || !curr) continue
    if (prev.major !== curr.major) continue   // a major bump is supposed to jump

    const minorJump = curr.minor - prev.minor
    const patchJump = curr.patch - prev.patch

    if (minorJump > 200 || (prev.minor === curr.minor && patchJump > 900)) {
      return {
        type: 'semver_abuse',
        surface: 'install_time',
        score: 35,
        description:
          `Anomalous semver jump: ${prevVer} -> ${currVer} ` +
          `(+${minorJump > 0 ? `${minorJump} minor` : `${patchJump} patch`} en mismo major). ` +
          `Forces resolution through ^${curr.major}.x.x.`,
        isHistorical: false,
      }
    }
  }

  return null
}

function parseSemver(v: string): { major: number; minor: number; patch: number } | null {
  if (/[a-zA-Z]/.test(v)) return null   // pre-releases are not range targets
  const parts = v.split('.').map(Number)
  if (parts.length < 3 || parts.some(isNaN)) return null
  return { major: parts[0]!, minor: parts[1]!, patch: parts[2]! }
}

// The shape of an account takeover and of a hostile maintainer transfer.
//
// Compares maintainers[] against per-version _npmUser because the two answer
// different questions: maintainers[] is who can publish today — the live attack
// surface — while _npmUser is who published each past version. A name in the
// first that never appears in the second is someone who gained publish rights
// without ever having shipped.
export function detectNewMaintainerOnOldPackage(p: Packument): Signal | null {
  const versions = Object.values(p.versions)
  if (versions.length < 10) return null

  const currentMaintainers = new Set(p.maintainers.map(m => m.name))

  // The newest five are excluded so a maintainer added as part of the attack
  // cannot appear in their own baseline.
  const historicalPublishers = new Set(
    versions
      .slice(0, -5)
      .map(v => v.publishedBy)
      .filter(Boolean)
  )

  const newMaintainers = [...currentMaintainers].filter(
    m => !historicalPublishers.has(m)
  )

  if (newMaintainers.length > 0 && historicalPublishers.size > 0) {
    return {
      type: 'new_maintainer_on_old_package',
      surface: 'install_time',
      score: 30,
      description:
        `New maintainer(s) with publish rights: ${newMaintainers.join(', ')}. ` +
        `Paquete con ${versions.length} versiones publicadas por: ` +
        `${[...historicalPublishers].slice(0, 3).join(', ')}.`,
      isHistorical: false,
    }
  }

  return null
}

// Known limitation: without access to the user's private registry, norte-guard
// cannot tell whether @company/pkg collides with something internal. What it can
// see is a brand new public scope, which is why the score stays low and the
// description says so out loud instead of implying certainty.
export function detectScopeSquatting(p: Packument): Signal | null {
  if (!p.name.startsWith('@')) return null

  const scope = p.name.split('/')[0]!
  const versions = Object.values(p.versions)
  const times = Object.entries(p.time)
    .filter(([k]) => !['created', 'modified'].includes(k))

  if (versions.length > 5 || times.length === 0) return null

  const ageDays = (Date.now() - new Date(times[0]![1] as string).getTime()) / 86_400_000

  if (ageDays < 30) {
    return {
      type: 'scope_squatting_candidate',
      surface: 'install_time',
      score: 15,
      description:
        `Scope ${scope} is new (${Math.round(ageDays)}d) with only ${versions.length} version(s). ` +
        `Verificar manualmente que no colisione con dependencias internas. ` +
        `[Limited signal: norte-guard has no access to your private registry]`,
      isHistorical: false,
    }
  }

  return null
}

// Known limitation: a name wordlist is too weak to be a primary detector. The
// real signal would be whether the name appeared in code before it existed on
// npm, which needs GitHub code search — an external API call that would break
// the zero-dependency guarantee. Scored at 10 so it can inform a human without
// ever deciding a verdict on its own.
export function detectHallucinatedPackage(p: Packument): Signal | null {
  const versions = Object.values(p.versions)
  if (versions.length > 3) return null

  const times = Object.entries(p.time)
    .filter(([k]) => !['created', 'modified'].includes(k))
  if (times.length === 0) return null

  const ageDays = (Date.now() - new Date(times[0]![1] as string).getTime()) / 86_400_000
  if (ageDays > 60) return null

  // Drawn from react-codeshift and other observed campaigns rather than invented.
  const hallucinationPatterns = [
    /^react-\w+-\w+$/,
    /^\w+-parser-\w+$/,
    /^@\w+\/\w+-client$/,
  ]

  const matchesPattern = hallucinationPatterns.some(re => re.test(p.name))
  if (!matchesPattern) return null

  return {
    type: 'hallucinated_package_candidate',
    surface: 'install_time',
    score: 10,
    description:
      `Nombre "${p.name}" coincide con patrones de packages hallucinated por LLMs. ` +
      `Created ${Math.round(ageDays)} days ago, ${versions.length} version(s). ` +
      `[Experimental signal: a high false-positive rate is expected]`,
    isHistorical: false,
  }
}

// Complements npm ci rather than replacing it. npm ci already verifies the
// SHA-512; what it does not check is whether `resolved` still points at the
// registry you configured. Lockfile poisoning can swap the host and keep a
// valid hash for a malicious build served from somewhere else.
export interface LockfileEntry {
  name: string
  version: string
  integrity: string
  resolved: string
}

export function detectLockfileUrlAnomaly(
  entries: LockfileEntry[],
  expectedRegistry = 'https://registry.npmjs.org'
): Array<{ entry: LockfileEntry; issue: string }> {
  const anomalies: Array<{ entry: LockfileEntry; issue: string }> = []

  for (const entry of entries) {
    if (!entry.resolved) continue

    if (!entry.resolved.startsWith(expectedRegistry)) {
      anomalies.push({
        entry,
        issue: `resolved apunta a ${new URL(entry.resolved).hostname} en vez de registry configurado`,
      })
    }
  }

  return anomalies
}
