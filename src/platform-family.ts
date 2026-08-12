// napi-rs and its relatives ship one release as N packages: a JS shim plus one
// prebuilt binary per platform, all published within seconds of each other at
// the same version. To this collector they look like N independent publications
// with identical scores, and it captured every one of them.
//
// @tomasmarekk/rootlight spent ~75MB on redundant captures in 80 minutes that
// way. The tarballs differ — different binaries — but the release does not, and
// a corpus with eleven copies of the same event is a corpus with one event and
// ten times the disk.

const PLATFORM_SUFFIX =
  /-(darwin|linux|win32|freebsd|openbsd|sunos|android|universal)(-(arm64|x64|ia32|arm|riscv64|ppc64|s390x|loong64))?(-(gnu|musl|msvc|eabi|eabihf|baseline))?$/

export interface FamilyKey {
  // Scope plus the name with its platform suffix removed, plus the version.
  key: string
  base: string
  platform: string
}

// Returns null for names that carry no platform suffix, which is most of the
// registry. A false positive here would silently drop unrelated packages.
export function platformFamily(name: string, version: string): FamilyKey | null {
  const scope = name.startsWith('@') ? name.slice(0, name.indexOf('/') + 1) : ''
  const bare = scope ? name.slice(scope.length) : name

  const match = PLATFORM_SUFFIX.exec(bare)
  if (!match) return null

  const base = bare.slice(0, match.index)
  // "-linux" alone is a plausible package name; a bare suffix with nothing in
  // front of it is not a family member.
  if (base.length < 2) return null

  return {
    key: `${scope}${base}@${version}`,
    base: `${scope}${base}`,
    platform: match[0].slice(1),
  }
}

export interface FamilyDecision {
  family: FamilyKey | null
  // True when another member of the same family was already captured inside the
  // window, so this one adds disk without adding an event.
  redundant: boolean
  capturedMember?: string
}

// One capture per family per window. The first member seen wins, which is
// arbitrary but stable: they are the same release.
export class PlatformFamilyTracker {
  private captured = new Map<string, { member: string; at: number }>()

  constructor(private windowMs = 60 * 60_000) {}

  decide(name: string, version: string, now: number): FamilyDecision {
    const family = platformFamily(name, version)
    if (!family) return { family: null, redundant: false }

    this.evict(now)

    const seen = this.captured.get(family.key)
    if (seen) return { family, redundant: true, capturedMember: seen.member }

    return { family, redundant: false }
  }

  recordCapture(family: FamilyKey, member: string, now: number): void {
    this.captured.set(family.key, { member, at: now })
  }

  private evict(now: number): void {
    for (const [key, entry] of this.captured) {
      if (now - entry.at > this.windowMs) this.captured.delete(key)
    }
  }

  get size(): number { return this.captured.size }
}
