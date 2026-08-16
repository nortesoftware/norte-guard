/**
 * The collector fixes, with the real cases from the 7-hour log:
 *
 *   classifyGhostReversion classified 100% as "patch" (42 of 42) because it
 *   compared the integrity of two different releases, which always differ.
 *   @tomasmarekk/rootlight burned ~75MB on redundant captures of one napi-rs
 *   release in 80 minutes.
 *   4.6GB in 7h with nothing counting the bytes.
 */

import { describe, it, expect, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, utimesSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { classifyGhostReversion, compareVersions } from '../src/genome.js'
import { platformFamily, PlatformFamilyTracker } from '../src/platform-family.js'
import { DailyCaptureBudget, rotateCaptures, directorySize, formatBytes, sweepQuarantine, QUARANTINE_REASON, consolidateDeltas, collectOrphanObjects } from '../src/capture-budget.js'
import { readObservations } from '../src/takedown-sweep.js'
import { classifyFetchFailure, budgetFor } from '../src/watcher.js'
import { describeComposition, compositionFromNotes } from '../src/corpus.js'
import { classifyPublication } from '../src/observed-class.js'
import { absoluteRiskSignals, impliedHistory } from '../src/absolute-risk.js'
import { putObject, getObject, objectPath } from '../src/object-store.js'
import { rotateLogs } from '../src/log-rotation.js'
import { createApprovalRecord, createOverrideApproval } from '../src/approvals.js'
import {
  assessPromotion, scheduledReview, ruleEvidenceFor, verdictsFromCaptures,
  QUARANTINE_CAPTURE_REASON, REAL_USAGE_DOWNLOADS, VERDICT_AFTER_DAYS,
  type TrackedVerdict, type TrackedStatus, type ClassCapture,
} from '../src/watchlist.js'
import { classPrecision, type CorpusSample } from '../src/corpus.js'
import { fabricatedProfile, matchesLocalConjuncts } from '../src/fabricated-profile.js'
import { scoreWithRegime } from '../src/scorer.js'
import { buildGenomeFromPackument } from '../src/genome.js'
import { exitCodeForVerdict } from '../src/output.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'
import type { Packument, VersionMeta } from '../src/packument.js'

const dirs: string[] = []
const tempDir = (prefix: string) => {
  const d = mkdtempSync(join(tmpdir(), prefix))
  dirs.push(d)
  return d
}
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }) })

describe('compareVersions', () => {
  it('sorts numerically, not lexicographically', () => {
    expect(compareVersions('0.9.2', '0.10.0')).toBe(-1)
    expect(compareVersions('0.10.0', '0.9.2')).toBe(1)
    expect(compareVersions('2.0.1', '2.0.0')).toBe(1)
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0)
  })

  it('a prerelease precedes the final version', () => {
    expect(compareVersions('1.3.3-test.4', '1.3.4')).toBe(-1)
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1)
    expect(compareVersions('1.0.0-rc.2', '1.0.0-rc.10')).toBe(-1)
  })

  it('accepts date-based versions', () => {
    expect(compareVersions('2026.8.10-1-42', '2026.8.3-1-6')).toBe(1)
    expect(compareVersions('20260812.30002.0', '20260812.30001.0')).toBe(1)
  })

  it('returns null instead of guessing when it cannot parse', () => {
    expect(compareVersions('latest', '1.0.0')).toBeNull()
    expect(compareVersions('1.0.0', 'v-raro')).toBeNull()
  })
})

describe('classifyGhostReversion: version order, not integrity', () => {
  function ghostPackument(opts: {
    existing: Array<[string, string]>   // [version, date]
    ghost: [string, string]
    integrity?: string
  }): Packument {
    const versions: Record<string, VersionMeta> = {}
    const time: Record<string, string> = {}

    for (const [ver, ts] of opts.existing) {
      versions[ver] = {
        version: ver, publishedAt: ts, publishedBy: 'x', unpackedSize: 1000,
        hasInstallScript: false, scripts: {}, dependencies: {}, devDependencies: {},
        // Deliberately different on every version: that is how reality looks,
        // and it is what broke the previous classifier.
        dist: { tarball: '', integrity: opts.integrity ?? `sha512-${ver}` },
      }
      time[ver] = ts
    }
    time[opts.ghost[0]] = opts.ghost[1]

    return { name: 'p', distTags: {}, versions, time, maintainers: [] }
  }

  it('pi-mega-compact: ghost 0.10.0 replaced by 0.9.2 is a rollback', () => {
    // The case from the log. The old classifier compared the integrity of 0.9.1
    // against 0.9.2, two different releases that always differ, and said
    // "incident".
    const p = ghostPackument({
      existing: [['0.9.1', '2026-08-01T00:00:00Z'], ['0.9.2', '2026-08-03T00:00:00Z']],
      ghost: ['0.10.0', '2026-08-02T00:00:00Z'],
    })

    const rev = classifyGhostReversion(p, '0.10.0')
    expect(rev.kind).toBe('rollback')
    expect(rev.after).toBe('0.9.2')
    expect(rev.detail).toContain('LOWER')
  })

  it('pgautopilot: ghost 2.0.0 replaced by 2.0.1 is a patch', () => {
    const p = ghostPackument({
      existing: [['1.0.0', '2026-08-01T00:00:00Z'], ['2.0.1', '2026-08-03T00:00:00Z']],
      ghost: ['2.0.0', '2026-08-02T00:00:00Z'],
    })

    const rev = classifyGhostReversion(p, '2.0.0')
    expect(rev.kind).toBe('patch')
    expect(rev.after).toBe('2.0.1')
  })

  it('integrity no longer decides anything: the same hash on both sides is still a patch', () => {
    // This was the only way to get "rollback" out of the old classifier, and in
    // 7 hours of real logging it did not happen once.
    const p = ghostPackument({
      existing: [['1.0.0', '2026-08-01T00:00:00Z'], ['1.2.0', '2026-08-03T00:00:00Z']],
      ghost: ['1.1.0', '2026-08-02T00:00:00Z'],
      integrity: 'sha512-IDENTICO',
    })

    expect(classifyGhostReversion(p, '1.1.0').kind).toBe('patch')
  })

  it('replacement by 0.0.1-security is an npm takedown, not a publisher rollback', () => {
    // Real case, @bikli/bikli: four ghosts replaced by the marker npm publishes
    // over a removed package. The old classifier called them "patch", like
    // everything else.
    const p = ghostPackument({
      existing: [['1.1.4', '2026-08-01T00:00:00Z'], ['0.0.1-security', '2026-08-03T00:00:00Z']],
      ghost: ['1.1.5', '2026-08-02T00:00:00Z'],
    })

    const rev = classifyGhostReversion(p, '1.1.5')
    expect(rev.kind).toBe('takedown')
    expect(rev.detail).toContain('npm removed the package')
  })

  it('with no later version it does not invent a classification', () => {
    const p = ghostPackument({
      existing: [['1.0.0', '2026-08-01T00:00:00Z']],
      ghost: ['1.1.0', '2026-08-02T00:00:00Z'],
    })

    const rev = classifyGhostReversion(p, '1.1.0')
    expect(rev.kind).toBe('unknown')
    expect(rev.detail).toContain('nothing has replaced it')
  })

  it('skips neighbours that are also ghosts', () => {
    const p = ghostPackument({
      existing: [['1.0.0', '2026-08-01T00:00:00Z'], ['0.9.9', '2026-08-04T00:00:00Z']],
      ghost: ['1.1.0', '2026-08-02T00:00:00Z'],
    })
    p.time['1.1.5'] = '2026-08-03T00:00:00Z'

    const rev = classifyGhostReversion(p, '1.1.0')
    expect(rev.after).toBe('0.9.9')
    expect(rev.kind).toBe('rollback')
  })
})

describe('platformFamily', () => {
  it('recognises the napi-rs suffixes', () => {
    expect(platformFamily('@scope/cli-darwin-arm64', '1.0.0')?.base).toBe('@scope/cli')
    expect(platformFamily('@scope/cli-linux-x64-gnu', '1.0.0')?.base).toBe('@scope/cli')
    expect(platformFamily('@scope/cli-win32-x64-msvc', '1.0.0')?.base).toBe('@scope/cli')
    expect(platformFamily('rootlight-linux-x64-musl', '1.0.0')?.base).toBe('rootlight')
  })

  it('a name with no platform suffix is not a family', () => {
    expect(platformFamily('express', '4.0.0')).toBeNull()
    expect(platformFamily('@scope/cli', '1.0.0')).toBeNull()
    // Y un sufijo sin nada delante tampoco: "linux" es un paquete plausible.
    expect(platformFamily('linux', '1.0.0')).toBeNull()
  })

  it('the key includes the version: two releases of the same binary do not mix', () => {
    const a = platformFamily('@scope/cli-darwin-arm64', '1.0.0')!
    const b = platformFamily('@scope/cli-darwin-arm64', '1.0.1')!
    expect(a.key).not.toBe(b.key)
  })
})

describe('PlatformFamilyTracker: one release, one capture', () => {
  it('captures the first member and discards the rest of the family', () => {
    const t = new PlatformFamilyTracker()
    const now = 1_000_000

    const first = t.decide('@tomasmarekk/rootlight-darwin-arm64', '1.0.0', now)
    expect(first.redundant).toBe(false)
    t.recordCapture(first.family!, '@tomasmarekk/rootlight-darwin-arm64@1.0.0', now)

    for (const platform of ['linux-x64-gnu', 'linux-x64-musl', 'win32-x64-msvc', 'darwin-x64']) {
      const next = t.decide(`@tomasmarekk/rootlight-${platform}`, '1.0.0', now + 60_000)
      expect(next.redundant, platform).toBe(true)
      expect(next.capturedMember).toContain('darwin-arm64')
    }
  })

  it('another version of the same package is a different release', () => {
    const t = new PlatformFamilyTracker()
    const first = t.decide('@scope/cli-darwin-arm64', '1.0.0', 0)
    t.recordCapture(first.family!, '@scope/cli-darwin-arm64@1.0.0', 0)

    expect(t.decide('@scope/cli-linux-x64-gnu', '1.0.1', 1000).redundant).toBe(false)
  })

  it('past the window the family stops blocking', () => {
    const t = new PlatformFamilyTracker(60_000)
    const first = t.decide('@scope/cli-darwin-arm64', '1.0.0', 0)
    t.recordCapture(first.family!, 'x', 0)

    expect(t.decide('@scope/cli-linux-x64-gnu', '1.0.0', 30_000).redundant).toBe(true)
    expect(t.decide('@scope/cli-linux-x64-gnu', '1.0.0', 120_000).redundant).toBe(false)
  })

  it('a normal package is never discarded by this rule', () => {
    const t = new PlatformFamilyTracker()
    expect(t.decide('express', '4.0.0', 0).redundant).toBe(false)
    expect(t.decide('express', '4.0.0', 1000).redundant).toBe(false)
  })
})

describe('DailyCaptureBudget', () => {
  it('counts what is spent and stops on reaching the cap', () => {
    const dir = tempDir('ng-budget-')
    const b = new DailyCaptureBudget(dir, 1000, '2026-08-12')

    expect(b.exhausted).toBe(false)
    b.recordCapture(600)
    expect(b.spent).toBe(600)
    expect(b.remaining).toBe(400)
    expect(b.exhausted).toBe(false)

    b.recordCapture(500)
    expect(b.exhausted).toBe(true)
    expect(b.remaining).toBe(0)
  })

  it('survives a restart: the day spend is not reset', () => {
    const dir = tempDir('ng-budget-persist-')
    new DailyCaptureBudget(dir, 1000, '2026-08-12').recordCapture(900)

    // Restarting the watcher was the obvious way to spend the budget twice.
    const reopened = new DailyCaptureBudget(dir, 1000, '2026-08-12')
    expect(reopened.spent).toBe(900)
    expect(reopened.exhausted).toBe(false)
    reopened.recordCapture(200)
    expect(reopened.exhausted).toBe(true)
  })

  it('the next day starts from zero', () => {
    const dir = tempDir('ng-budget-day-')
    new DailyCaptureBudget(dir, 1000, '2026-08-12').recordCapture(1000)

    const nextDay = new DailyCaptureBudget(dir, 1000, '2026-08-13')
    expect(nextDay.spent).toBe(0)
    expect(nextDay.exhausted).toBe(false)
  })
})

describe('rotateCaptures', () => {
  // With a manifest.json, because that is what makes a directory a capture:
  // corpus.ts will not load one without it, and rotation will not delete one
  // without it either. The two definitions have to be the same or rotation
  // deletes things the corpus never counted.
  function capture(root: string, name: string, opts: { bytes: number; at: string; label?: string }) {
    const dir = join(root, name)
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'blob.tgz'), Buffer.alloc(opts.bytes))
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
      version: 1, package: name, capturedAt: opts.at,
      capturedFrom: 'https://registry.npmjs.org',
      versionsIncluded: ['1.0.0'], hashes: {},
    }))
    writeFileSync(join(dir, 'capture-metadata.json'), JSON.stringify({
      package: name, version: '1.0.0', capturedAt: opts.at, score: 50,
      label: opts.label ?? 'unconfirmed', doNotExtract: true,
    }))
    return dir
  }

  it('deletes the oldest first until it drops below the cap', () => {
    const root = tempDir('ng-rot-')
    capture(root, 'vieja', { bytes: 4000, at: '2026-08-01T00:00:00Z' })
    capture(root, 'media', { bytes: 4000, at: '2026-08-05T00:00:00Z' })
    capture(root, 'nueva', { bytes: 4000, at: '2026-08-10T00:00:00Z' })

    const result = rotateCaptures(root, 9000)

    expect(result.deleted).toHaveLength(1)
    expect(result.deleted[0]!.path).toContain('vieja')
    expect(existsSync(join(root, 'vieja'))).toBe(false)
    expect(existsSync(join(root, 'media'))).toBe(true)
    expect(existsSync(join(root, 'nueva'))).toBe(true)
  })

  it('NEVER deletes a labelled capture, however old', () => {
    const root = tempDir('ng-rot-label-')
    capture(root, 'confirmada', { bytes: 8000, at: '2020-01-01T00:00:00Z', label: 'confirmed_malicious' })
    capture(root, 'sin-etiquetar', { bytes: 2000, at: '2026-08-10T00:00:00Z' })

    const result = rotateCaptures(root, 1000)

    expect(result.protectedCount).toBe(1)
    expect(existsSync(join(root, 'confirmada'))).toBe(true)
    expect(result.deleted.map(d => d.path).join()).toContain('sin-etiquetar')
  })

  it('below the cap it deletes nothing', () => {
    const root = tempDir('ng-rot-noop-')
    capture(root, 'a', { bytes: 1000, at: '2026-08-01T00:00:00Z' })

    const result = rotateCaptures(root, 100_000)
    expect(result.deleted).toHaveLength(0)
    expect(existsSync(join(root, 'a'))).toBe(true)
  })

  it('--dry-run measures without deleting', () => {
    const root = tempDir('ng-rot-dry-')
    capture(root, 'a', { bytes: 4000, at: '2026-08-01T00:00:00Z' })

    const result = rotateCaptures(root, 100, true)
    expect(result.deleted.length).toBeGreaterThan(0)
    expect(existsSync(join(root, 'a'))).toBe(true)
  })

  // The store lives inside captures/. It is a directory, it has no
  // capture-metadata.json so it read as unconfirmed, and it has no capturedAt so
  // it sorted first: the first rotation deleted 3,169 tarballs and 9.25GB in one
  // rmSync, including the artifacts behind captures labelled confirmed_malicious
  // that rotation had correctly refused to touch.
  it('NEVER deletes the shared object store, whatever its size or age', () => {
    const root = tempDir('ng-rot-store-')
    const stored = putObject(root, Buffer.alloc(9000, 1))
    capture(root, 'nueva', { bytes: 1000, at: '2026-08-10T00:00:00Z' })

    const result = rotateCaptures(root, 500)

    expect(existsSync(objectPath(root, stored.sha256)), 'the object store was deleted').toBe(true)
    expect(result.deleted.map(d => d.path).join()).not.toContain('objects')
  })

  it('deleting a capture frees its tarball from the store, not just its directory', () => {
    const root = tempDir('ng-rot-gc-')
    const bytes = Buffer.alloc(4000, 7)
    const stored = putObject(root, bytes)

    const dir = capture(root, 'vieja', { bytes: 10, at: '2026-08-01T00:00:00Z' })
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
      version: 1, package: 'vieja', capturedAt: '2026-08-01T00:00:00Z',
      capturedFrom: 'https://registry.npmjs.org',
      versionsIncluded: ['1.0.0'], hashes: {},
      objectStore: root, objects: { '1.0.0': stored.sha256 },
    }))

    const result = rotateCaptures(root, 100)

    expect(existsSync(join(root, 'vieja'))).toBe(false)
    expect(existsSync(objectPath(root, stored.sha256)), 'the orphaned tarball survived').toBe(false)
    expect(result.objectsCollected).toBe(1)
    expect(result.objectBytesFreed).toBe(4000)
  })

  it('an object two captures share survives the first of them', () => {
    const root = tempDir('ng-rot-shared-')
    const stored = putObject(root, Buffer.alloc(4000, 3))

    let oldestBytes = 0
    for (const [name, at] of [['vieja', '2026-08-01T00:00:00Z'], ['nueva', '2026-08-10T00:00:00Z']] as const) {
      const dir = capture(root, name, { bytes: 10, at })
      writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
        version: 1, package: name, capturedAt: at,
        capturedFrom: 'https://registry.npmjs.org',
        versionsIncluded: ['1.0.0'], hashes: {},
        objectStore: root, objects: { '1.0.0': stored.sha256 },
      }))
      if (name === 'vieja') oldestBytes = directorySize(dir)
    }

    // A cap that exactly one deletion satisfies, computed rather than guessed:
    // the point is what happens to the shared object when the first of its two
    // holders goes, and a hardcoded number that takes both proves nothing.
    rotateCaptures(root, directorySize(root) - oldestBytes)

    expect(existsSync(join(root, 'vieja'))).toBe(false)
    expect(existsSync(join(root, 'nueva'))).toBe(true)
    expect(existsSync(objectPath(root, stored.sha256)), 'a shared object went with the first holder').toBe(true)
  })

  it('reports rather than keeps deleting when only confirmed evidence is left', () => {
    const root = tempDir('ng-rot-floor-')
    capture(root, 'confirmada', { bytes: 8000, at: '2020-01-01T00:00:00Z', label: 'confirmed_malicious' })

    const result = rotateCaptures(root, 1000)

    expect(result.deleted).toHaveLength(0)
    expect(result.stillOverCap).toBe(true)
    expect(existsSync(join(root, 'confirmada'))).toBe(true)
  })
})

describe('collectOrphanObjects', () => {
  it('frees what expired quarantine left behind, and nothing a capture still names', () => {
    const root = tempDir('ng-gc-')
    const orphan = putObject(root, Buffer.alloc(3000, 9))
    const held = putObject(root, Buffer.alloc(2000, 4))

    const dir = join(root, 'viva@1.0.0_1')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
      version: 1, package: 'viva', capturedAt: '2026-08-10T00:00:00Z',
      capturedFrom: 'https://registry.npmjs.org',
      versionsIncluded: ['1.0.0'], hashes: {},
      objectStore: root, objects: { '1.0.0': held.sha256 },
    }))

    const result = collectOrphanObjects(root, root)

    expect(result.objects).toBe(1)
    expect(result.bytes).toBe(3000)
    expect(existsSync(objectPath(root, orphan.sha256))).toBe(false)
    expect(existsSync(objectPath(root, held.sha256))).toBe(true)
  })
})

describe('formatBytes / directorySize', () => {
  it('measures a directory recursively', () => {
    const root = tempDir('ng-size-')
    mkdirSync(join(root, 'sub'), { recursive: true })
    writeFileSync(join(root, 'a.bin'), Buffer.alloc(1500))
    writeFileSync(join(root, 'sub', 'b.bin'), Buffer.alloc(500))

    expect(directorySize(root)).toBe(2000)
  })

  it('formatea en unidades legibles', () => {
    expect(formatBytes(512)).toBe('512B')
    expect(formatBytes(2048)).toBe('2KB')
    expect(formatBytes(5 * 1024 ** 3)).toBe('5.00GB')
  })
})

describe('classifyFetchFailure', () => {
  it('separates the four causes', () => {
    expect(classifyFetchFailure(new Error('Package not found: https://…'))).toBe('404')
    expect(classifyFetchFailure(new Error('Timeout fetching: https://…'))).toBe('timeout')
    expect(classifyFetchFailure(new Error('HTTP 503: https://…'))).toBe('http-error')
    expect(classifyFetchFailure(new SyntaxError('Unexpected token < in JSON'))).toBe('malformed')
    expect(classifyFetchFailure(new Error('socket hang up'))).toBe('other')
  })
})

describe('capture composition', () => {
  it('reconstructs the breakdown of old captures from the notes', () => {
    const c = compositionFromNotes(
      'captured at score=61 (budget 44, regime no-genome); ' +
      'signals: absolute_install_script+20, absolute_no_readme+6; recent ghost 0.1.73 (patch)'
    )!

    expect(c.regime).toBe('no-genome')
    expect(c.firstPublication).toBe(true)
    expect(c.signals).toContain('absolute_install_script')
    expect(c.newInstallScript).toBe(true)
    expect(c.ghost).toBe('0.1.73')
    expect(c.ghostKind).toBe('patch')
  })

  it('with unparseable notes it returns undefined instead of inventing', () => {
    expect(compositionFromNotes(undefined)).toBeUndefined()
    expect(compositionFromNotes('anything at all')).toBeUndefined()
  })

  it('aggregates the breakdown that decides whether the disk is corpus or waste', () => {
    const sample = (pkg: string, composition: Partial<import('../src/ngpack.js').CaptureComposition>) => ({
      package: pkg, version: '1.0.0', label: 'unconfirmed' as const,
      ngpackPath: '/x', capturedAt: '2026-08-12T00:00:00Z',
      hasTarball: true, labelAssumed: false, contaminated: false,
      composition: {
        regime: 'no-genome', signals: [], firstPublication: true,
        ghost: null, ghostKind: null, newInstallScript: false, platformFamily: null,
        ...composition,
      },
    })

    const c = describeComposition([
      sample('@scope/cli-darwin-arm64', { platformFamily: '@scope/cli' }),
      sample('@scope/cli-linux-x64-gnu', { platformFamily: '@scope/cli' }),
      sample('otro-linux-x64-musl', {}),
      sample('normal', { firstPublication: false, regime: 'genome', ghost: '1.0.0', ghostKind: 'rollback' }),
      sample('con-script', { newInstallScript: true, signals: ['absolute_install_script'] }),
    ])

    expect(c.total).toBe(5)
    // El sufijo de plataforma cuenta aunque la captura sea vieja y no lo registre.
    expect(c.platformFamilyMembers).toBe(3)
    expect(c.platformFamilies).toBe(2)
    expect(c.firstPublications).toBe(4)
    expect(c.withGhost).toBe(1)
    expect(c.ghostByKind['rollback']).toBe(1)
    expect(c.withNewInstallScript).toBe(1)
    expect(c.byRegime['no-genome']).toBe(4)
    expect(c.topSignals[0]).toEqual({ signal: 'absolute_install_script', count: 1 })
  })
})

describe('per-regime budget', () => {
  it('the no-genome regime has its own, lower cut', () => {
    const budgets = { genome: 50, noGenome: 20 }

    expect(budgetFor(budgets, 'genome')).toBe(50)
    expect(budgetFor(budgets, 'no-genome')).toBe(20)

    // The two observed takedowns scored 26 and 20: below 50, within 20. A single
    // cut consumed the disk and missed exactly that class.
    expect(26).toBeGreaterThanOrEqual(budgetFor(budgets, 'no-genome'))
    expect(20).toBeGreaterThanOrEqual(budgetFor(budgets, 'no-genome'))
    expect(26).toBeLessThan(budgetFor(budgets, 'genome'))
  })

  it('a bare number still applies to both', () => {
    expect(budgetFor(44, 'genome')).toBe(44)
    expect(budgetFor(44, 'no-genome')).toBe(44)
  })
})

describe('cuarentena', () => {
  function quarantined(root: string, name: string, opts: { retainUntil: string; label?: string }) {
    const dir = join(root, name)
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'blob.tgz'), Buffer.alloc(100))
    writeFileSync(join(dir, 'capture-metadata.json'), JSON.stringify({
      package: name, version: '1.0.0', capturedAt: '2026-08-12T00:00:00Z', score: 20,
      label: opts.label ?? 'unconfirmed', captureReason: QUARANTINE_REASON,
      retainUntil: opts.retainUntil, doNotExtract: true,
    }))
    return dir
  }

  const ahora = Date.parse('2026-08-20T00:00:00Z')

  it('deletes what expired with nobody confirming it', () => {
    const root = tempDir('ng-quar-')
    quarantined(root, 'caducada', { retainUntil: '2026-08-19T00:00:00Z' })
    quarantined(root, 'en-ventana', { retainUntil: '2026-08-25T00:00:00Z' })

    const r = sweepQuarantine(root, ahora)

    expect(r.expired).toHaveLength(1)
    expect(r.kept).toBe(1)
    expect(existsSync(join(root, 'caducada'))).toBe(false)
    expect(existsSync(join(root, 'en-ventana'))).toBe(true)
  })

  it('a promotion is kept even past expiry: it is what was being waited for', () => {
    const root = tempDir('ng-quar-promo-')
    quarantined(root, 'promovida', {
      retainUntil: '2026-08-13T00:00:00Z', label: 'confirmed_malicious',
    })

    const r = sweepQuarantine(root, ahora)

    expect(r.promoted).toBe(1)
    expect(r.expired).toHaveLength(0)
    expect(existsSync(join(root, 'promovida'))).toBe(true)
  })

  it('does not touch captures that are not quarantine', () => {
    const root = tempDir('ng-quar-otras-')
    const dir = join(root, 'por-score')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'capture-metadata.json'), JSON.stringify({
      package: 'x', version: '1.0.0', capturedAt: '2020-01-01T00:00:00Z', score: 90,
      label: 'unconfirmed', captureReason: 'watcher-threshold', doNotExtract: true,
    }))

    const r = sweepQuarantine(root, ahora)
    expect(r.expired).toHaveLength(0)
    expect(existsSync(dir)).toBe(true)
  })
})

describe('clase observada', () => {
  function pkg(opts: { ageDays: number; bytes: number; repo?: boolean }): [Packument, VersionMeta] {
    const created = new Date(Date.now() - opts.ageDays * 86_400_000).toISOString()
    const m: VersionMeta = {
      version: '1.0.0', publishedAt: created, publishedBy: 'x', unpackedSize: opts.bytes,
      hasInstallScript: false, scripts: {}, dependencies: {}, devDependencies: {},
      dist: { tarball: '', integrity: '' },
      ...(opts.repo ? { repository: { url: 'git+https://github.com/x/y' } } : {}),
    }
    return [{
      name: 'p', distTags: { latest: '1.0.0' }, versions: { '1.0.0': m },
      time: { created, '1.0.0': created }, maintainers: [], createdAt: created,
    }, m]
  }

  it('both removed packages fall inside the class', () => {
    // prezdentkxheiw: 25KB, name 6 days old, no repository.
    const [p1, m1] = pkg({ ageDays: 6, bytes: 25_875 })
    expect(classifyPublication(p1, m1, 'no-genome').inClass).toBe(true)

    // internallib_v756: 1.4KB, name seconds old, no repository.
    const [p2, m2] = pkg({ ageDays: 0, bytes: 1_406 })
    expect(classifyPublication(p2, m2, 'no-genome').inClass).toBe(true)
  })

  it('a LARGE new package is not the class', () => {
    // What made quarantine cost 172MB/min.
    const [p, m] = pkg({ ageDays: 1, bytes: 5_000_000 })
    const markers = classifyPublication(p, m, 'no-genome')

    expect(markers.tiny).toBe(false)
    expect(markers.inClass).toBe(false)
  })

  it('with a repository or with a genome, out', () => {
    const [pRepo, mRepo] = pkg({ ageDays: 1, bytes: 1000, repo: true })
    expect(classifyPublication(pRepo, mRepo, 'no-genome').inClass).toBe(false)

    const [p, m] = pkg({ ageDays: 1, bytes: 1000 })
    expect(classifyPublication(p, m, 'genome').inClass).toBe(false)
  })

  it('an old name is not the class however small it is', () => {
    const [p, m] = pkg({ ageDays: 400, bytes: 1000 })
    expect(classifyPublication(p, m, 'no-genome').inClass).toBe(false)
  })
})

describe('candidate signals: instrumented, not scored', () => {
  const base = (o: Partial<VersionMeta> = {}): VersionMeta => ({
    version: '1.0.0', publishedAt: '2026-08-12T00:00:00Z', publishedBy: 'x',
    unpackedSize: 1000, hasInstallScript: false, scripts: {},
    dependencies: {}, devDependencies: {}, dist: { tarball: '', integrity: '' }, ...o,
  })

  it('absolute_tiny_size is worth 0 and is informational', () => {
    const m = base({ unpackedSize: 1_406 })
    const p: Packument = {
      name: 'p', distTags: {}, versions: { '1.0.0': m },
      time: { '1.0.0': m.publishedAt }, maintainers: [],
    }
    const signal = absoluteRiskSignals({ packument: p, currentMeta: m })
      .find(s => s.type === 'absolute_tiny_size')

    expect(signal).toBeDefined()
    expect(signal!.score).toBe(0)
    expect(signal!.informational).toBe(true)
  })

  it('version_implies_history: 1.0.7 as the first version', () => {
    const m = base({ version: '1.0.7' })
    const p: Packument = {
      name: 'internallib_v756', distTags: {}, versions: { '1.0.7': m },
      time: { created: m.publishedAt, '1.0.7': m.publishedAt }, maintainers: [],
    }

    expect(impliedHistory(p, '1.0.7')).toBe(7)

    const signal = absoluteRiskSignals({ packument: p, currentMeta: m })
      .find(s => s.type === 'version_implies_history')
    expect(signal!.score).toBe(0)
    expect(signal!.informational).toBe(true)
  })

  it('does not fire on normal first versions nor on real history', () => {
    const single = (v: string): Packument => ({
      name: 'p', distTags: {}, versions: { [v]: base({ version: v }) },
      time: { [v]: '2026-08-12T00:00:00Z' }, maintainers: [],
    })

    for (const v of ['1.0.0', '0.1.0', '2.0.0']) {
      expect(impliedHistory(single(v), v), v).toBeNull()
    }

    // With two published versions the number no longer implies anything time{} denies.
    const withHistory: Packument = {
      name: 'p', distTags: {},
      versions: { '1.0.7': base({ version: '1.0.7' }) },
      time: { '1.0.6': '2026-08-01T00:00:00Z', '1.0.7': '2026-08-12T00:00:00Z' },
      maintainers: [],
    }
    expect(impliedHistory(withHistory, '1.0.7')).toBeNull()
  })

  it('neither of the two moves the score', () => {
    const m = base({ version: '1.0.7', unpackedSize: 1_406 })
    const p: Packument = {
      name: 'p', distTags: {}, versions: { '1.0.7': m },
      time: { created: m.publishedAt, '1.0.7': m.publishedAt }, maintainers: [],
      hasReadme: true,
    }
    const signals = absoluteRiskSignals({ packument: p, currentMeta: m })
    const candidatas = signals.filter(s =>
      s.type === 'absolute_tiny_size' || s.type === 'version_implies_history')

    expect(candidatas).toHaveLength(2)
    expect(candidatas.reduce((a, s) => a + s.score, 0)).toBe(0)
  })
})

describe('content-addressed store', () => {
  it('the same tarball twice occupies one', () => {
    const root = tempDir('ng-store-')
    const buf = Buffer.from('contenido del tarball')

    const first = putObject(root, buf)
    const second = putObject(root, buf)

    expect(first.written).toBe(true)
    expect(second.written).toBe(false)
    expect(second.sha256).toBe(first.sha256)
  })

  it('the name is the hash, so verification is free', () => {
    const root = tempDir('ng-store-verify-')
    const stored = putObject(root, Buffer.from('bytes'))

    expect(getObject(root, stored.sha256).toString()).toBe('bytes')

    // An altered object cannot keep being named after its hash.
    writeFileSync(objectPath(root, stored.sha256), 'other bytes')
    expect(() => getObject(root, stored.sha256)).toThrow(/corrupt/)
  })

  it('a missing object throws instead of returning empty', () => {
    expect(() => getObject(tempDir('ng-store-missing-'), 'a'.repeat(64))).toThrow(/missing/)
  })
})

describe('log rotation', () => {
  it('compresses closed days and leaves the current one raw', () => {
    const dir = tempDir('ng-logs-')
    const lines = Array.from({ length: 200 }, (_, i) =>
      JSON.stringify({ seq: i, package: 'p'.repeat(20), outcome: 'analyzed' })).join('\n')

    writeFileSync(join(dir, 'changes-log.ndjson'), lines)
    utimesSync(join(dir, 'changes-log.ndjson'), new Date('2026-08-10'), new Date('2026-08-10'))
    // Stamped with the day the rotation is being told it is, not left at the
    // real clock. Without this the file is "today's" only while the suite runs
    // on 2026-08-12, and the test starts failing on its own two days later.
    writeFileSync(join(dir, 'deletions.ndjson'), 'de hoy')
    utimesSync(join(dir, 'deletions.ndjson'), new Date('2026-08-12'), new Date('2026-08-12'))

    const r = rotateLogs(dir, '2026-08-12')

    expect(r.rotated).toHaveLength(1)
    expect(r.rotated[0]!.to).toContain('changes-log-2026-08-10.ndjson.gz')
    // El grano repetido comprime mucho: es donde estaba el 10x.
    expect(r.rotated[0]!.compressed).toBeLessThan(r.rotated[0]!.bytes / 5)

    expect(existsSync(join(dir, 'changes-log.ndjson'))).toBe(false)
    expect(existsSync(join(dir, 'deletions.ndjson'))).toBe(true)
  })

  it('does not re-rotate a day already archived', () => {
    const dir = tempDir('ng-logs-dup-')
    writeFileSync(join(dir, 'changes-log.ndjson'), 'linea')
    utimesSync(join(dir, 'changes-log.ndjson'), new Date('2026-08-10'), new Date('2026-08-10'))
    writeFileSync(join(dir, 'changes-log-2026-08-10.ndjson.gz'), 'ya estaba')

    const r = rotateLogs(dir, '2026-08-12')
    expect(r.rotated).toHaveLength(0)
    expect(r.alreadyRotated).toBe(1)
  })
})

describe('fabricatedProfile: a conjunction, not a score', () => {
  function candidate(o: Partial<VersionMeta> = {}, ageDays = 1): [Packument, VersionMeta] {
    const created = new Date(Date.now() - ageDays * 86_400_000).toISOString()
    const m: VersionMeta = {
      version: '1.0.0', publishedAt: created, publishedBy: 'x', unpackedSize: 25_000,
      hasInstallScript: false, scripts: {}, dependencies: {}, devDependencies: {},
      dist: { tarball: '', integrity: '' }, ...o,
    }
    return [{
      name: 'p', distTags: { latest: m.version }, versions: { [m.version]: m },
      time: { created, [m.version]: created }, maintainers: [], createdAt: created,
    }, m]
  }

  it('all five at once, and only then', () => {
    const [p, m] = candidate()
    expect(fabricatedProfile({ packument: p, currentMeta: m, regime: 'no-genome', weeklyDownloads: 0 }).matches).toBe(true)
  })

  it('with downloads it does not fire: the condition that discarded most candidates', () => {
    // 4 of 11 members of the class had between 56 and 332 weekly downloads.
    const [p, m] = candidate()
    for (const downloads of [56, 332, 1]) {
      expect(fabricatedProfile({ packument: p, currentMeta: m, regime: 'no-genome', weeklyDownloads: downloads }).matches, String(downloads)).toBe(false)
    }
  })

  it('unknown downloads NEVER fire: a gate does not block for having failed to check', () => {
    const [p, m] = candidate()
    for (const downloads of [null, undefined]) {
      const r = fabricatedProfile({ packument: p, currentMeta: m, regime: 'no-genome', weeklyDownloads: downloads })
      expect(r.matches).toBe(false)
      expect(r.downloadsChecked).toBe(false)
    }
  })

  it('each missing condition disables the rule', () => {
    const casos: Array<[string, Packument, VersionMeta, string]> = []

    const [pRepo, mRepo] = candidate({ repository: { url: 'git+https://github.com/x/y' } })
    casos.push(['con repository', pRepo, mRepo, 'no-genome'])

    const [pBig, mBig] = candidate({ unpackedSize: 500_000 })
    casos.push(['grande', pBig, mBig, 'no-genome'])

    const [pOld, mOld] = candidate({}, 30)
    casos.push(['nombre viejo', pOld, mOld, 'no-genome'])

    const [pGen, mGen] = candidate()
    casos.push(['con genoma', pGen, mGen, 'genome'])

    for (const [etiqueta, p, m, regime] of casos) {
      expect(fabricatedProfile({ packument: p, currentMeta: m, regime, weeklyDownloads: 0 }).matches, etiqueta).toBe(false)
    }
  })

  it('the 4 local conditions are evaluated without spending the downloads request', () => {
    const [p, m] = candidate()
    expect(matchesLocalConjuncts({ packument: p, currentMeta: m, regime: 'no-genome' })).toBe(true)

    const [pBig, mBig] = candidate({ unpackedSize: 500_000 })
    expect(matchesLocalConjuncts({ packument: pBig, currentMeta: mBig, regime: 'no-genome' })).toBe(false)
  })

  // It was ON by default between 2026-08-14 and 2026-08-16, on four removals
  // that turned out to be evidence about the capture filter rather than about
  // this rule — the two share four conditions and this one needs a fifth that no
  // capture on disk records. types.ts carries the full account. This asserts the
  // current policy in both directions, so flipping it again stays a decision
  // rather than a diff nobody notices.
  it('it is OFF by default: the conjunction is recorded and does not block', () => {
    const [p, m] = candidate()
    const genome = buildGenomeFromPackument('p', p)

    const byDefault = scoreWithRegime({
      packument: p, version: m.version, currentMeta: m, genome,
      weeklyDownloads: 0, config: DEFAULT_THRESHOLDS.gate,
    })
    expect(byDefault.verdict).toBe('INSUFFICIENT_HISTORY')
    expect(exitCodeForVerdict(byDefault.verdict)).toBe(0)
    // The signal is recorded whether or not it blocks, so it can be measured.
    expect(byDefault.signals.some(s => s.type === 'fabricated_package_profile')).toBe(true)

    const enabled = scoreWithRegime({
      packument: p, version: m.version, currentMeta: m, genome,
      weeklyDownloads: 0, config: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: true },
    })
    expect(enabled.verdict).toBe('BLOCK')
    expect(exitCodeForVerdict(enabled.verdict)).toBe(1)
    expect(enabled.signals.some(s => s.type === 'fabricated_package_profile')).toBe(true)
  })

  // Four of the five conditions are free, and they are the ones the prevalence
  // is measured on. The fifth is real only when npm's week overlaps the
  // package's life, and for a name created after that week closed it is
  // arithmetic. Reported rather than silently counted as evidence.
  it('says when zero downloads was measured over a week that predates the package', () => {
    const [p, m] = candidate()

    const vacuous = fabricatedProfile({
      packument: p, currentMeta: m, regime: 'no-genome',
      weeklyDownloads: 0, downloadWindowEnd: '2020-01-01',
    })
    expect(vacuous.matches).toBe(true)
    expect(vacuous.downloadWindowCovers).toBe(false)
    expect(vacuous.reason).toContain('carries no information here')

    const covering = fabricatedProfile({
      packument: p, currentMeta: m, regime: 'no-genome',
      weeklyDownloads: 0, downloadWindowEnd: new Date().toISOString().slice(0, 10),
    })
    expect(covering.downloadWindowCovers).toBe(true)
    expect(covering.reason).not.toContain('carries no information here')

    // Not recorded at all is not the same as recorded and vacuous.
    const unknown = fabricatedProfile({
      packument: p, currentMeta: m, regime: 'no-genome', weeklyDownloads: 0,
    })
    expect(unknown.downloadWindowCovers).toBe(null)
  })

  it('the signal is worth 0: it blocks by conjunction, never by score', () => {
    const [p, m] = candidate()
    const signal = scoreWithRegime({
      packument: p, version: m.version, currentMeta: m,
      genome: buildGenomeFromPackument('p', p),
      weeklyDownloads: 0, config: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: true },
    }).signals.find(s => s.type === 'fabricated_package_profile')

    expect(signal!.score).toBe(0)
  })
})

describe('delta consolidation', () => {
  function delta(dir: string, name: string, body: object) {
    writeFileSync(join(dir, name), gzipSync(Buffer.from(JSON.stringify(body))))
  }

  it('joins the day into a single file and deletes the loose ones', () => {
    const dir = tempDir('ng-delta-')
    delta(dir, '2026-08-10T01-00-00-000Z_a.json.gz', { name: 'a', distTags: { latest: '1.0.0' } })
    delta(dir, '2026-08-10T02-00-00-000Z_b.json.gz', { name: 'b', distTags: { latest: '2.0.0' } })
    delta(dir, '2026-08-12T01-00-00-000Z_c.json.gz', { name: 'c', distTags: { latest: '3.0.0' } })

    const r = consolidateDeltas(dir, '2026-08-12')

    expect(r.days).toHaveLength(1)
    expect(r.days[0]!.files).toBe(2)
    expect(existsSync(join(dir, 'deltas-2026-08-10.ndjson.gz'))).toBe(true)
    // The current day is left alone: it is still being written to.
    expect(existsSync(join(dir, '2026-08-12T01-00-00-000Z_c.json.gz'))).toBe(true)
  })

  it('the consolidated file is still read: the .ndjson.gz suffix does not end in .json.gz', () => {
    // Esta era la trampa: un filtro de un solo sufijo se saltaba el fichero
    // entero y dejaba el barrido de takedowns con 21 observaciones de 15,277.
    const dir = tempDir('ng-delta-read-')
    const captures = join(dir, 'deltas')
    mkdirSync(captures, { recursive: true })

    delta(captures, '2026-08-10T01-00-00-000Z_a.json.gz',
      { name: 'a', capturedAt: '2026-08-10T01:00:00Z', distTags: { latest: '1.0.0' } })
    delta(captures, '2026-08-10T02-00-00-000Z_b.json.gz',
      { name: 'b', capturedAt: '2026-08-10T02:00:00Z', distTags: { latest: '2.0.0' } })

    expect(readObservations(dir)).toHaveLength(2)

    consolidateDeltas(captures, '2026-08-12')

    const after = readObservations(dir)
    expect(after).toHaveLength(2)
    expect(after.map(o => o.package).sort()).toEqual(['a', 'b'])
  })

  it('does not re-consolidate a day already archived', () => {
    const dir = tempDir('ng-delta-dup-')
    delta(dir, '2026-08-10T01-00-00-000Z_a.json.gz', { name: 'a' })
    consolidateDeltas(dir, '2026-08-12')

    delta(dir, '2026-08-10T03-00-00-000Z_z.json.gz', { name: 'z' })
    const second = consolidateDeltas(dir, '2026-08-12')
    expect(second.days).toHaveLength(0)
    expect(second.skipped).toBe(1)
  })
})

describe('budget reset', () => {
  it('requires a reason and leaves it recorded', () => {
    const dir = tempDir('ng-budget-reset-')
    const b = new DailyCaptureBudget(dir, 1000, '2026-08-12')
    b.recordCapture(900)

    const previous = b.reset('spent by unfiltered quarantine, policy withdrawn')

    expect(previous.previousBytes).toBe(900)
    expect(b.spent).toBe(0)
    expect(b.exhausted).toBe(false)

    const log = readFileSync(join(dir, 'budget-log.ndjson'), 'utf-8')
    expect(log).toContain('unfiltered quarantine')
    expect(JSON.parse(log.trim()).previousBytes).toBe(900)
  })
})

describe('escape hatch: approving a blocked package', () => {
  const blocked = (verdict: 'BLOCK' | 'PASS' = 'BLOCK') => ({
    package: 'paquete-bloqueado', version: '1.0.0', analyzedAt: '2026-08-12T00:00:00Z',
    totalScore: 0, signals: [{ type: 'fabricated_package_profile', surface: 'install_time' as const, score: 0, description: 'x', isHistorical: false }],
    newCapabilities: [], historicalCapabilities: [],
    diff: { added: [], removed: [], grown: [], newInstallScripts: [], newBindingGyp: false, newNativeAddon: false },
    coverage: { packumentSignals: 1, tarballs: false, entryPointAnalyzed: false, staticModuleHops: 0, uncoveredDynamicRequires: 0, coveragePercent: 55 },
    baselineVersion: null, verdict, regime: 'no-genome' as const,
  })

  it('a BLOCK CAN be approved by name: without that the gate is unusable', () => {
    // createApprovalRecord drops BLOCKs on purpose for the lockfile sweep. The
    // named exception is the opposite case and has to be allowed.
    const bulk = createApprovalRecord([blocked()])
    expect(bulk.approvals).toHaveLength(0)

    const override = createOverrideApproval(blocked(), { justification: 'I asked for it, it is ours' })
    expect(override.approvals).toHaveLength(1)
    expect(override.approvals[0]!.overrodeVerdict).toBe('BLOCK')
    expect(override.approvals[0]!.justification).toContain('I asked for it')
  })

  it('the manifest shows what was overridden, not only what was accepted', () => {
    const r = createOverrideApproval(blocked(), { justification: 'reason' })
    expect(r.approvals[0]!.overrodeVerdict).toBeDefined()
    // And the hash covers the exception: editing it by hand breaks the record.
    expect(r.selfHash).toBeTruthy()
  })

  it('re-approving the same version replaces rather than duplicates', () => {
    const first = createOverrideApproval(blocked(), { justification: 'primera' })
    const second = createOverrideApproval(blocked(), { justification: 'segunda', existing: first })

    expect(second.approvals).toHaveLength(1)
    expect(second.approvals[0]!.justification).toBe('segunda')
  })
})

describe('promotion criterion and dated review', () => {
  // 'rule-matched' by default: these tests are about counting, and the evidence
  // dimension has its own block below.
  const v = (
    status: TrackedStatus,
    over: Partial<TrackedVerdict> = {}
  ): TrackedVerdict =>
    ({
      package: 'p', addedAt: '2026-08-12T00:00:00Z', daysTracked: 30, status,
      lastDownloads: 0, ruleEvidence: 'rule-matched', detail: '', ...over,
    })

  it('does not promote without the three removals', () => {
    expect(assessPromotion([v('confirmed-takedown'), v('confirmed-takedown')]).promotable).toBe(false)
    expect(assessPromotion([v('confirmed-takedown'), v('confirmed-takedown'), v('confirmed-takedown')]).promotable).toBe(true)
  })

  it('a second confirmed false positive takes it away', () => {
    const tres = [v('confirmed-takedown'), v('confirmed-takedown'), v('confirmed-takedown')]
    expect(assessPromotion([...tres, v('confirmed-false-positive')]).promotable).toBe(true)
    expect(assessPromotion([...tres, v('confirmed-false-positive'), v('confirmed-false-positive')]).promotable).toBe(false)
  })

  // The bug this criterion shipped with: `track` reported PROMOTABLE on eight
  // removals of packages the rule was never shown to match, because the capture
  // filter and the rule were both called "the four free conditions".
  it('a removal the rule cannot be shown to have caused does not promote it', () => {
    const unverifiable = [
      v('confirmed-takedown', { ruleEvidence: 'unverifiable' }),
      v('confirmed-takedown', { ruleEvidence: 'unverifiable' }),
      v('confirmed-takedown', { ruleEvidence: 'unverifiable' }),
    ]
    const a = assessPromotion(unverifiable)

    expect(a.confirmedTakedowns).toBe(3)
    expect(a.verifiedTakedowns).toBe(0)
    expect(a.unverifiableTakedowns).toBe(3)
    expect(a.promotable).toBe(false)
    expect(a.statement).toContain('STAYS OPT-IN')
  })

  it('a removal of something the rule would have cleared is not evidence for it', () => {
    const a = assessPromotion([
      v('confirmed-takedown', { ruleEvidence: 'rule-cleared' }),
      v('confirmed-takedown', { ruleEvidence: 'rule-cleared' }),
      v('confirmed-takedown', { ruleEvidence: 'rule-cleared' }),
    ])
    expect(a.verifiedTakedowns).toBe(0)
    expect(a.unverifiableTakedowns).toBe(0)
    expect(a.promotable).toBe(false)
  })

  // Removals settle in hours, false positives at thirty days. Counting only what
  // has settled makes the criterion say PROMOTABLE on day three for any rule.
  it('a package already installed by somebody counts before its thirty days are up', () => {
    const tres = [v('confirmed-takedown'), v('confirmed-takedown'), v('confirmed-takedown')]
    const emerging = (dl: number) =>
      v('pending', { daysTracked: 3, lastDownloads: dl })

    expect(assessPromotion([...tres, emerging(0)]).promotable).toBe(true)
    expect(assessPromotion([...tres, emerging(9)]).promotable).toBe(true)

    const two = assessPromotion([...tres, emerging(50), emerging(300)])
    expect(two.emergingFalsePositives).toBe(2)
    expect(two.promotable).toBe(false)
    expect(two.blockers.join(' ')).toContain('before their 30 days are up')
  })

  it('both blockers are reported, not only the first', () => {
    const a = assessPromotion([
      v('confirmed-takedown', { ruleEvidence: 'unverifiable' }),
      v('pending', { daysTracked: 3, lastDownloads: 100 }),
      v('pending', { daysTracked: 3, lastDownloads: 100 }),
    ])
    expect(a.blockers).toHaveLength(2)
  })

  it('zero downloads and unknown downloads are different answers', () => {
    expect(ruleEvidenceFor(0, true)).toBe('rule-matched')
    expect(ruleEvidenceFor(1, true)).toBe('rule-cleared')
    expect(ruleEvidenceFor(null, true)).toBe('unverifiable')
    expect(ruleEvidenceFor(undefined, undefined)).toBe('unverifiable')
  })

  // npm answers 404 for a package published minutes ago, downloads.ts reads that
  // as zero because for a verdict it is one, and this class is made of packages
  // published minutes ago. Grading that zero as a match would let a restarted
  // collector clear PROMOTION_MIN_TAKEDOWNS out of three 404s inside a day.
  it('a zero over a week the package did not exist in is not evidence', () => {
    expect(ruleEvidenceFor(0, false)).toBe('vacuous-zero')
    expect(ruleEvidenceFor(0, null)).toBe('vacuous-zero')
    // Absent means the capture predates the field. A build-failing rule does not
    // get the benefit of the doubt from a record that cannot give it.
    expect(ruleEvidenceFor(0, undefined)).toBe('vacuous-zero')
    // A non-zero count is a real observation whatever the window did.
    expect(ruleEvidenceFor(7, false)).toBe('rule-cleared')
  })

  it('a dated review turns waiting into a result', () => {
    const antes = scheduledReview(500, 0, new Date('2026-08-20T00:00:00Z'))
    expect(antes.due).toBe(false)
    expect(antes.verdict).toContain('days to go')

    // Muchas capturas y casi ninguna confirmada es un resultado, no una espera.
    const vencida = scheduledReview(1500, 1, new Date('2026-08-27T00:00:00Z'))
    expect(vencida.due).toBe(true)
    expect(vencida.verdict).toContain('IT IS A RESULT')
  })
})

// The contradiction this suite exists to keep from coming back: `track` reported
// "8 confirmed removals, PROMOTABLE" while `bench` reported the same eight as
// unjudgeable. Both were right about their own criterion and neither said which
// criterion it was.
describe('the capture filter and the rule are different criteria', () => {
  const capture = (over: Partial<ClassCapture> = {}): ClassCapture => ({
    package: 'p',
    version: '1.0.0',
    capturedAt: '2026-08-13T00:00:00Z',
    label: 'confirmed_malicious',
    labelSource: 'npm-takedown: 0.0.1-security',
    captureReason: QUARANTINE_CAPTURE_REASON,
    contaminated: false,
    ...over,
  })

  it('a capture with no recorded count cannot say what the rule would have done', () => {
    const [v] = verdictsFromCaptures([capture()])
    expect(v!.status).toBe('confirmed-takedown')
    expect(v!.ruleEvidence).toBe('unverifiable')
    expect(v!.detail).toContain('capture filter (4 conditions)')
    expect(v!.detail).toContain('unknowable')
  })

  it('a recorded zero over a covered week is the fifth conjunct', () => {
    const [v] = verdictsFromCaptures([
      capture({ weeklyDownloads: 0, downloadWindowCovers: true }),
    ])
    expect(v!.ruleEvidence).toBe('rule-matched')
    expect(v!.detail).toContain('would have blocked it')
  })

  it('a recorded zero over a week that closed first promotes nothing', () => {
    const [v] = verdictsFromCaptures([
      capture({ weeklyDownloads: 0, downloadWindowCovers: false }),
    ])
    expect(v!.status).toBe('confirmed-takedown')
    expect(v!.ruleEvidence).toBe('vacuous-zero')
    expect(v!.detail).toContain('holds vacuously')

    const a = assessPromotion(verdictsFromCaptures(
      Array.from({ length: 5 }, (_, i) =>
        capture({ package: `p${i}`, weeklyDownloads: 0, downloadWindowCovers: false }))
    ))
    expect(a.confirmedTakedowns).toBe(5)
    expect(a.verifiedTakedowns).toBe(0)
    expect(a.vacuousTakedowns).toBe(5)
    expect(a.promotable).toBe(false)
    expect(a.blockers.join(' ')).toContain('arithmetic')
  })

  it('a recorded non-zero says the rule would not have fired, removal or not', () => {
    const [v] = verdictsFromCaptures([capture({ weeklyDownloads: 40 })])
    expect(v!.status).toBe('confirmed-takedown')
    expect(v!.ruleEvidence).toBe('rule-cleared')
    expect(v!.detail).toContain('would NOT have blocked it')
  })

  it('one verdict per package, however many times it was captured', () => {
    const v = verdictsFromCaptures([
      capture({ version: '1.0.0' }),
      capture({ version: '1.0.1' }),
    ])
    expect(v).toHaveLength(1)
  })

  it('eight unverifiable removals do not promote the rule', () => {
    const eight = Array.from({ length: 8 }, (_, i) => capture({ package: `p${i}` }))
    const a = assessPromotion(verdictsFromCaptures(eight))

    expect(a.confirmedTakedowns).toBe(8)
    expect(a.verifiedTakedowns).toBe(0)
    expect(a.promotable).toBe(false)
  })
})

describe('precision of the capture filter', () => {
  const NOW = new Date('2026-08-16T00:00:00Z').getTime()
  const day = 86_400_000

  const sample = (over: Partial<CorpusSample>): CorpusSample => ({
    package: 'p', version: '1.0.0', label: 'unconfirmed',
    ngpackPath: '/dev/null', capturedAt: new Date(NOW - day).toISOString(),
    hasTarball: true, labelAssumed: false,
    captureReason: QUARANTINE_CAPTURE_REASON, contaminated: false,
    ...over,
  })

  const run = (samples: CorpusSample[], removed: string[], downloads?: Map<string, number>) =>
    classPrecision({
      samples,
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages: new Set(removed),
      observedDownloads: downloads,
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      now: NOW,
    })

  it('counts packages, not captures: republishing must not inflate the denominator', () => {
    const p = run([
      sample({ package: 'a', version: '1.0.0' }),
      sample({ package: 'a', version: '1.0.1' }),
      sample({ package: 'a', version: '1.0.2' }),
      sample({ package: 'b' }),
    ], ['a'])

    expect(p.markedCaptures).toBe(4)
    expect(p.markedPackages).toBe(2)
    expect(p.precision!.rate).toBeCloseTo(0.5)
  })

  it('captures from other reasons never enter the denominator', () => {
    const p = run([
      sample({ package: 'a' }),
      sample({ package: 'b', captureReason: 'watcher-threshold' }),
    ], [])
    expect(p.markedPackages).toBe(1)
  })

  // The bound runs upward, not downward. Every marked name enters the
  // denominator when it is marked, whatever becomes of it, so the denominator is
  // already complete for the cohort and only removals still to arrive can move
  // the fraction. The first version of this caveat said "upper bound" and had it
  // exactly backwards.
  it('an immature denominator says so, and says which way the number can move', () => {
    const p = run([sample({ package: 'a' })], [])
    expect(p.maturePackages).toBe(0)
    expect(p.maturePrecision).toBeNull()
    expect(p.caveats.join(' ')).toContain('LOWER bound')
    expect(p.caveats.join(' ')).not.toContain('upper bound')
  })

  // Retention is 7 days and a verdict takes 30, so no unconfirmed capture of
  // this class can ever reach the age its answer needs. "Not yet" would be a
  // caveat that never comes true.
  it('a retention shorter than the verdict clock is named as a policy contradiction', () => {
    const withRetention = classPrecision({
      samples: [sample({ package: 'a' })],
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages: new Set<string>(),
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      retentionDays: 7,
      now: NOW,
    })
    expect(withRetention.caveats.join(' ')).toContain('cannot be rebuilt from surviving captures')

    // Not claimed when retention is long enough for the clock to run.
    const generous = classPrecision({
      samples: [sample({ package: 'a' })],
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages: new Set<string>(),
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      retentionDays: 45,
      now: NOW,
    })
    expect(generous.caveats.join(' ')).not.toContain('cannot be rebuilt')
  })

  // Both deleters keep labelled captures and take unlabelled ones oldest-first:
  // the numerator is protected and the denominator is not. Without the expiry
  // log the fraction would climb on its own as the corpus aged, and the climb
  // would be the deleter rather than the filter.
  it('a deleted capture keeps its place in the denominator', () => {
    const expired = [
      { package: 'gone-1', capturedAt: new Date(NOW - 40 * day).toISOString(), captureReason: QUARANTINE_CAPTURE_REASON },
      { package: 'gone-2', capturedAt: new Date(NOW - 40 * day).toISOString(), captureReason: QUARANTINE_CAPTURE_REASON },
      // A different reason is a different filter and must not be folded in.
      { package: 'other', capturedAt: new Date(NOW - 40 * day).toISOString(), captureReason: 'watcher-threshold' },
    ]

    const withLog = classPrecision({
      samples: [sample({ package: 'a' })],
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages: new Set(['gone-1']),
      expired,
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      now: NOW,
    })

    expect(withLog.markedPackages).toBe(3)     // a, gone-1, gone-2
    expect(withLog.expiredPackages).toBe(2)
    expect(withLog.removed).toBe(1)
    // And they are the only ones old enough for the mature fraction to exist.
    expect(withLog.maturePackages).toBe(2)
    expect(withLog.matureRemoved).toBe(1)
    expect(withLog.caveats.join(' ')).toContain('expiry log')
  })

  it('a name re-captured after its old artifact expired is counted once, from the earlier date', () => {
    const p = classPrecision({
      samples: [sample({ package: 'a', capturedAt: new Date(NOW - day).toISOString() })],
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages: new Set<string>(),
      expired: [
        { package: 'a', capturedAt: new Date(NOW - 40 * day).toISOString(), captureReason: QUARANTINE_CAPTURE_REASON },
      ],
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      now: NOW,
    })

    expect(p.markedPackages).toBe(1)
    expect(p.expiredPackages).toBe(0)
    expect(p.maturePackages).toBe(1)   // the clock runs from the first marking
  })

  // Five lock-family names published inside four minutes and removed inside
  // forty seconds are not five independent draws, and Wilson assumes they are.
  it('removals arriving in campaigns are declared as not independent', () => {
    const many = run(
      Array.from({ length: 10 }, (_, i) => sample({ package: `p${i}` })),
      ['p0', 'p1', 'p2']
    )
    expect(many.caveats.join(' ')).toContain('not 3 independent events')

    const one = run([sample({ package: 'a' }), sample({ package: 'b' })], ['a'])
    expect(one.caveats.join(' ')).not.toContain('independent events')
  })

  it('the mature fraction is computed once packages are old enough for it', () => {
    const old = new Date(NOW - 40 * day).toISOString()
    const p = run([
      sample({ package: 'a', capturedAt: old }),
      sample({ package: 'b', capturedAt: old }),
      sample({ package: 'c' }),
    ], ['a'])

    expect(p.maturePackages).toBe(2)
    expect(p.matureRemoved).toBe(1)
    expect(p.maturePrecision!.rate).toBeCloseTo(0.5)
  })

  it('the clock starts at the first capture, not the last', () => {
    const p = run([
      sample({ package: 'a', capturedAt: new Date(NOW - 40 * day).toISOString() }),
      sample({ package: 'a', capturedAt: new Date(NOW - day).toISOString() }),
    ], [])
    expect(p.maturePackages).toBe(1)
  })

  it('"alive" is measured over what was queried and never scaled to the rest', () => {
    const p = run(
      [sample({ package: 'a' }), sample({ package: 'b' }), sample({ package: 'c' })],
      [],
      new Map([['a', 300]])
    )
    expect(p.observedAlive).toBe(1)
    expect(p.observedAliveWithUsage).toBe(1)
    expect(p.caveats.join(' ')).toContain('must not be scaled up')
  })
})
