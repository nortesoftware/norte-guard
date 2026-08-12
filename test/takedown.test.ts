/**
 * An npm takedown (0.0.1-security) is the first external confirmation that meets
 * the confirmed_malicious definition: the registry issues it, anyone can verify
 * it, and it is reproducible from the packument.
 *
 * And it is a LABEL, NEVER A SIGNAL. It is after the fact: if it enters the
 * scorer, the detector recognises packages by the mark left by whoever caught
 * them first, and the benchmark measures that circle instead of measuring
 * detection. The last block of this file checks that against the source, not
 * against intent.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import {
  detectTakedown,
  isUsableRecallSample,
  isPreTakedownObservation,
  packumentAsOf,
  takedownLabelSource,
  NPM_SECURITY_HOLDER,
} from '../src/takedown.js'
import { scoreWithRegime } from '../src/scorer.js'
import { buildGenomeFromPackument } from '../src/genome.js'
import { DEFAULT_THRESHOLDS } from '../src/types.js'
import type { Packument, VersionMeta } from '../src/packument.js'

function meta(o: Partial<VersionMeta> = {}): VersionMeta {
  return {
    version: '1.0.0', publishedAt: '2026-08-01T00:00:00Z', publishedBy: 'x',
    unpackedSize: 1000, hasInstallScript: false, scripts: {},
    dependencies: {}, devDependencies: {}, dist: { tarball: '', integrity: '' }, ...o,
  }
}

// Un paquete retirado: npm borra todas las versiones reales y publica el
// marcador encima. Las retiradas siguen en time{}.
function takenDownPackument(name = 'malo'): Packument {
  return {
    name,
    distTags: { latest: NPM_SECURITY_HOLDER },
    versions: {
      [NPM_SECURITY_HOLDER]: meta({ version: NPM_SECURITY_HOLDER, publishedAt: '2026-08-10T00:00:00Z', unpackedSize: 430 }),
    },
    time: {
      created: '2026-08-01T00:00:00Z',
      '1.0.0': '2026-08-01T00:00:00Z',
      '1.0.1': '2026-08-02T00:00:00Z',
      [NPM_SECURITY_HOLDER]: '2026-08-10T00:00:00Z',
    },
    maintainers: [],
  }
}

describe('detectTakedown', () => {
  it('the npm marker is external confirmation', () => {
    const v = detectTakedown(takenDownPackument(), '1.0.1')

    expect(v.takenDown).toBe(true)
    expect(v.capturedVersionPurged).toBe(true)
    expect(v.purgedVersions).toEqual(['1.0.0', '1.0.1'])
    expect(v.holderPublishedAt).toBe('2026-08-10T00:00:00Z')
    expect(takedownLabelSource(v)).toContain('npm-takedown')
  })

  it('a live package is not a takedown', () => {
    const p: Packument = {
      name: 'sano', distTags: { latest: '1.0.0' },
      versions: { '1.0.0': meta() }, time: { '1.0.0': '2026-08-01T00:00:00Z' }, maintainers: [],
    }
    expect(detectTakedown(p, '1.0.0').takenDown).toBe(false)
  })

  it('capturing the marker is a label, not a sample', () => {
    // The real case: the collector started after the attack and what it saw
    // published was 0.0.1-security itself. That proves the takedown and says
    // nothing about whether the detector would have caught the attack.
    const v = detectTakedown(takenDownPackument(), NPM_SECURITY_HOLDER)

    expect(v.takenDown).toBe(true)
    expect(v.capturedIsHolder).toBe(true)
    expect(isUsableRecallSample(v)).toBe(false)
  })

  it('capturing the artifact npm later removed IS a sample', () => {
    const v = detectTakedown(takenDownPackument(), '1.0.1')
    expect(isUsableRecallSample(v)).toBe(true)
  })

  it('seeing only the marker is not a pre-takedown observation', () => {
    const previa = { package: 'p', observedVersion: '1.0.1', observedAt: '2026-08-05T00:00:00Z' }
    const posterior = { package: 'p', observedVersion: NPM_SECURITY_HOLDER, observedAt: '2026-08-11T00:00:00Z' }

    expect(isPreTakedownObservation(previa)).toBe(true)
    expect(isPreTakedownObservation(posterior)).toBe(false)
  })
})

describe('packumentAsOf: only what existed at publication', () => {
  function history(): Packument {
    return {
      name: 'p',
      distTags: { latest: NPM_SECURITY_HOLDER },
      versions: {
        '1.0.0': meta({ version: '1.0.0', publishedAt: '2026-08-01T00:00:00Z' }),
        '1.1.0': meta({ version: '1.1.0', publishedAt: '2026-08-05T00:00:00Z' }),
        '2.0.0': meta({ version: '2.0.0', publishedAt: '2026-08-08T00:00:00Z' }),
        [NPM_SECURITY_HOLDER]: meta({ version: NPM_SECURITY_HOLDER, publishedAt: '2026-08-10T00:00:00Z' }),
      },
      time: {
        created: '2026-08-01T00:00:00Z',
        '1.0.0': '2026-08-01T00:00:00Z',
        '1.1.0': '2026-08-05T00:00:00Z',
        '2.0.0': '2026-08-08T00:00:00Z',
        [NPM_SECURITY_HOLDER]: '2026-08-10T00:00:00Z',
      },
      maintainers: [],
    }
  }

  it('erases everything published after the target version', () => {
    const asOf = packumentAsOf(history(), '1.1.0')

    expect(Object.keys(asOf.versions).sort()).toEqual(['1.0.0', '1.1.0'])
    expect(asOf.distTags['latest']).toBe('1.1.0')
  })

  it('the takedown marker is never visible from before', () => {
    // This is the guarantee that makes the recall question answerable: scoring
    // against today's packument would let the detector see npm's own marker.
    const asOf = packumentAsOf(history(), '2.0.0')

    expect(NPM_SECURITY_HOLDER in asOf.versions).toBe(false)
    expect(NPM_SECURITY_HOLDER in asOf.time).toBe(false)
  })

  it('keeps time.created, which is the age of the name', () => {
    expect(packumentAsOf(history(), '1.0.0').time['created']).toBe('2026-08-01T00:00:00Z')
  })

  it('scoring as-of sees no signal derived from the takedown', () => {
    const asOf = packumentAsOf(history(), '2.0.0')
    const result = scoreWithRegime({
      packument: asOf, version: '2.0.0', currentMeta: asOf.versions['2.0.0']!,
      genome: buildGenomeFromPackument('p', asOf), config: DEFAULT_THRESHOLDS.gate,
    })

    const texto = JSON.stringify(result)
    expect(texto).not.toContain(NPM_SECURITY_HOLDER)
    expect(texto.toLowerCase()).not.toContain('takedown')
  })
})

describe('label-only: the takedown cannot enter the detector', () => {
  const src = join(process.cwd(), 'src')

  // Checked against the source, not against intent: if someone imports the
  // module from the scorer the benchmark becomes silently circular, and no
  // behavioural test would notice.
  it('no scoring module imports takedown.ts', () => {
    for (const file of ['scorer.ts', 'absolute-risk.ts', 'genome.ts', 'inspect.ts', 'bench.ts', 'fp-bench.ts']) {
      const code = readFileSync(join(src, file), 'utf-8')
      expect(code, `${file} importa takedown.ts`).not.toMatch(/from '\.\/takedown(-sweep)?\.js'/)
    }
  })

  it('no signal type mentions takedown or the marker', () => {
    for (const file of readdirSync(src).filter(f => f.endsWith('.ts'))) {
      if (file === 'takedown.ts' || file === 'takedown-sweep.ts') continue
      const code = readFileSync(join(src, file), 'utf-8')

      // El watcher usa el marcador para etiquetar capturas, que es su sitio.
      const signalTypes = [...code.matchAll(/type:\s*'([a-z_0-9]+)'/g)].map(m => m[1]!)
      for (const t of signalTypes) {
        expect(t, `${file}: signal "${t}"`).not.toContain('takedown')
        expect(t, `${file}: signal "${t}"`).not.toContain('security')
      }
    }
  })

  it('the corpus accepts the takedown only as a labelSource', () => {
    const v = detectTakedown(takenDownPackument(), '1.0.1')
    const source = takedownLabelSource(v)

    // Va al campo de etiqueta, con una fuente externa citable, que es
    // exactamente el requisito que el corpus impone para confirmar una muestra.
    expect(source.startsWith('npm-takedown')).toBe(true)
    expect(source).toContain(NPM_SECURITY_HOLDER)
  })
})
