/**
 * gate drift regression
 *
 * A detector degrades in one direction only: towards "everything passes". Each
 * false-positive fix lowers a weight, mutes a signal or raises a threshold, and
 * none of those edits looks wrong on its own. The sum does.
 *
 * This is the sample that must never stop blocking: keyv@6.0.0 reduced to what
 * layer 1 can see, an install script that did not exist across 48 versions and a
 * tarball 25x the historical size. If the gate stops emitting BLOCK here, the
 * problem is not this test: it is that the gate is drifting towards blocking
 * nothing.
 *
 * Run after every change to signals or weights.
 */

import { describe, it, expect, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'

import { scoreWithRegime } from '../src/scorer.js'
import { buildGenomeFromPackument } from '../src/genome.js'
import { inspect } from '../src/inspect.js'
import { NgpackSource } from '../src/ngpack.js'
import { exitCodeForVerdict } from '../src/output.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'
import type { Packument, VersionMeta } from '../src/packument.js'

const HISTORICAL_SIZE = 185_000
const SIZE_MULTIPLIER = 25
const CLEAN_VERSIONS = 48

const tempDirs: string[] = []
afterAll(() => { for (const d of tempDirs) rmSync(d, { recursive: true, force: true }) })

function version(overrides: Partial<VersionMeta>): VersionMeta {
  return {
    version: '1.0.0',
    publishedAt: '2020-01-01T00:00:00Z',
    publishedBy: 'jaredwray',
    unpackedSize: HISTORICAL_SIZE,
    hasInstallScript: false,
    scripts: {},
    dependencies: {},
    devDependencies: {},
    dist: { tarball: '', integrity: '' },
    ...overrides,
  }
}

// Reconstructed from public reports (Aikido, Socket, Chainguard, Microsoft,
// 2026-08-04). The tarball was purged from npm; these are the packument fields
// that determine the verdict.
function keyvPackument(): Packument {
  const versions: Record<string, VersionMeta> = {}
  const time: Record<string, string> = { created: '2020-01-01T00:00:00Z' }

  for (let i = 0; i < CLEAN_VERSIONS; i++) {
    const ver = `5.${i}.0`
    const ts = new Date(Date.UTC(2020, 0, 1 + i * 20)).toISOString()
    versions[ver] = version({ version: ver, publishedAt: ts })
    time[ver] = ts
  }

  const attackedAt = '2026-08-04T09:08:00Z'
  versions['6.0.0'] = version({
    version: '6.0.0',
    publishedAt: attackedAt,
    unpackedSize: HISTORICAL_SIZE * SIZE_MULTIPLIER,
    hasInstallScript: true,
    scripts: { preinstall: 'node setup.mjs' },
  })
  time['6.0.0'] = attackedAt

  return {
    name: 'keyv',
    distTags: { latest: '6.0.0' },
    versions,
    time,
    maintainers: [{ name: 'jaredwray', email: 'jaredwray@gmail.com' }],
    createdAt: '2020-01-01T00:00:00Z',
    hasReadme: true,
  }
}

function writeNgpack(packument: Packument): string {
  const dir = mkdtempSync(join(tmpdir(), 'ng-drift-'))
  tempDirs.push(dir)

  mkdirSync(join(dir, 'tarballs'), { recursive: true })
  const raw = JSON.stringify(packument)
  writeFileSync(join(dir, 'packument.json'), raw)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({
    version: 1,
    package: packument.name,
    capturedAt: '2026-08-04T11:00:00.000Z',
    capturedFrom: 'https://registry.npmjs.org',
    versionsIncluded: ['6.0.0'],
    hashes: { 'packument.json': createHash('sha256').update(Buffer.from(raw)).digest('hex') },
  }, null, 2))

  return dir
}

describe('gate drift regression', () => {
  const packument = keyvPackument()
  const genome = buildGenomeFromPackument('keyv', packument)

  const scored = () => scoreWithRegime({
    packument,
    version: '6.0.0',
    currentMeta: packument.versions['6.0.0']!,
    genome,
    config: DEFAULT_THRESHOLDS.gate,
  })

  it('the gate STILL emits BLOCK on the synthetic keyv sample', () => {
    const result = scored()

    expect(
      result.verdict,
      'The gate stopped blocking keyv@6.0.0 (new install script + 25x size). ' +
      'This is not a brittle test, it is drift towards "everything passes". ' +
      'Check the last change to weights or signals.'
    ).toBe('BLOCK')

    expect(result.regime).toBe('genome')
    expect(result.totalScore).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.gate.blockScore)
  })

  it('the two signals carrying it are still alive and still weighted', () => {
    // Named one by one: if a future fix mutes one, the failure says which
    // instead of only "it no longer blocks".
    const byType = new Map(scored().signals.map(s => [s.type, s]))

    const installScript = byType.get('new_install_script')
    expect(installScript, 'new_install_script disappeared').toBeDefined()
    expect(installScript!.score, 'new_install_script lost its weight').toBeGreaterThan(0)

    const sizeAnomaly = byType.get('size_anomaly')
    expect(sizeAnomaly, `size_anomaly did not fire at ${SIZE_MULTIPLIER}x the historical size`).toBeDefined()
    expect(sizeAnomaly!.score, 'size_anomaly lost its weight').toBeGreaterThan(0)
  })

  it('the margin over the threshold is reported, to see drift before it flips', () => {
    const result = scored()
    const margin = result.totalScore - DEFAULT_THRESHOLDS.gate.blockScore

    // No minimum margin is asserted: that would fail on any legitimate
    // recalibration. What is asserted is that the margin is not negative, and
    // the message leaves the number visible to whoever reads the run.
    expect(
      margin,
      `Margen sobre el umbral del gate: ${margin} pts ` +
      `(score ${result.totalScore} vs umbral ${DEFAULT_THRESHOLDS.gate.blockScore}). ` +
      `If this approaches 0 across successive runs, the gate is drifting.`
    ).toBeGreaterThanOrEqual(0)
  })

  it('and it reaches the process: BLOCK through the real path, with exit 1', async () => {
    // Por inspect() y NgpackSource, no por el scorer directamente: la deriva
    // can also arrive through regime routing or the verdict-to-exit-code
    // mapping, not only through the weights.
    const result = await inspect('keyv@6.0.0', {
      mode: 'gate',
      source: new NgpackSource(writeNgpack(packument)),
    })

    expect(result.verdict).toBe('BLOCK')
    expect(exitCodeForVerdict(result.verdict)).toBe(1)
  })

  it('audit, with a lower threshold, cannot be more permissive than gate', async () => {
    const audit = scoreWithRegime({
      packument,
      version: '6.0.0',
      currentMeta: packument.versions['6.0.0']!,
      genome,
      config: DEFAULT_THRESHOLDS.audit,
    })

    expect(audit.verdict).toBe('BLOCK')
    expect(DEFAULT_THRESHOLDS.audit.blockScore).toBeLessThanOrEqual(DEFAULT_THRESHOLDS.gate.blockScore)
  })
})
