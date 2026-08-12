/**
 * Two functions passed every test while never running: scoreWithRegime, which
 * made INSUFFICIENT_HISTORY unreachable, and detectCampaigns, which was written,
 * tested and called by nothing. A unit test proves a function works; it says
 * nothing about whether anything invokes it.
 *
 * So this checks reachability instead: every module under src/ has to be
 * imported by another module, and every exported function has to be named
 * somewhere outside the file that defines it. Tests count as callers for
 * helpers, but not for a whole module — a module only the tests import is a
 * module that does not run.
 */

import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const SRC = join(process.cwd(), 'src')
const TEST = join(process.cwd(), 'test')

const sourceFiles = readdirSync(SRC).filter(f => f.endsWith('.ts'))
const testFiles = readdirSync(TEST).filter(f => f.endsWith('.ts'))

const read = (dir: string, f: string) => readFileSync(join(dir, f), 'utf-8')

const sources = new Map(sourceFiles.map(f => [f, read(SRC, f)]))
const tests = new Map(testFiles.map(f => [f, read(TEST, f)]))

// cli.ts is the binary and watcher.ts is reached through a dynamic import from
// it; neither is imported by name anywhere else, which is correct.
const ENTRY_POINTS = new Set(['cli.ts', 'bench.ts', 'fp-bench.ts'])

// A debt register, not an exemption. Each entry is code that is written and
// tested but reaches no runtime path, with the reason it is still here. Adding
// to this list is a decision; the test exists so it cannot happen by accident.
const UNWIRED_MODULES = new Map([
  ['future-vectors.ts', 'signals designed but not yet scored: semver abuse, scope squatting, hallucinated packages'],
  ['meta-security.ts', 'the v2 Sigstore self-verification contract, stubbed at the call site'],
  ['peer-profile.ts', 'the phase-1.1 analysis tool, run out of band and not yet exposed as a command'],
])

const UNWIRED = new Set<string>([
  // Genome-poisoning mitigations: written and tested, not yet consulted by the
  // scorer, which still uses the plain isHistorical flag.
  'genome.ts:computeEverHadCapabilities',
  'genome.ts:getCapabilitiesOlderThan',
  'genome.ts:findTrustResetIndex',
  'genome.ts:classifyCapability',
  'genome.ts:capabilityDiff',

  // The approval manifest exists and is written by the named override path.
  // `approve` over a lockfile still only prints its recommendations.
  'approvals.ts:createApprovalRecord',
  'approvals.ts:diffApprovalRecords',
  'approvals.ts:renderApprovalDiff',

  'ecosystem.ts:renderCampaignSignals',

  // Point-in-time reconstruction. Field recall uses the score the collector
  // logged at publication instead, which needs no reconstruction.
  'takedown.ts:packumentAsOf',

  // Utilities built alongside their subsystems and not needed by it yet.
  'log-rotation.ts:logFootprint',
  'object-store.ts:hasObject',
  'object-store.ts:objectSize',

  // Compares what npm says about the past against what the watcher recorded.
  // No caller: it needs a command that does not exist.
  'watcher.ts:checkHistoryIntegrity',
])

describe('no dead code', () => {
  it('every module is imported by another module', () => {
    const orphans: string[] = []

    for (const file of sourceFiles) {
      if (ENTRY_POINTS.has(file) || UNWIRED_MODULES.has(file)) continue

      const specifier = `./${file.replace(/\.ts$/, '.js')}`
      const importedBySource = [...sources.entries()]
        .some(([name, code]) => name !== file && code.includes(specifier))

      if (!importedBySource) orphans.push(file)
    }

    expect(orphans, `modules nothing imports: ${orphans.join(', ')}`).toEqual([])
  })

  it('every exported function is referenced somewhere', () => {
    const unused: string[] = []

    for (const [file, code] of sources) {
      if (UNWIRED_MODULES.has(file)) continue
      const exported = [...code.matchAll(/export (?:async )?function (\w+)/g)].map(m => m[1]!)

      for (const name of exported) {
        // Used inside its own module counts: it is reachable, just not part of
        // the public surface. What is dead is an export nothing names at all.
        const inOwnFile = occurrences(code, name) > 1
        const inOtherSource = [...sources.entries()]
          .some(([other, c]) => other !== file && mentions(c, name))
        const inTests = [...tests.values()].some(c => mentions(c, name))

        if (UNWIRED.has(`${file}:${name}`)) continue
        if (!inOwnFile && !inOtherSource && !inTests) unused.push(`${file}:${name}`)
        else if (!inOwnFile && !inOtherSource && inTests) {
          // Tested but never called by anything that runs. This is the shape
          // scoreWithRegime and detectCampaigns had.
          unused.push(`${file}:${name} (only tests reference it)`)
        }
      }
    }

    expect(unused, `exports nothing runs: ${unused.join(', ')}`).toEqual([])
  })

  // The two that got through. Named explicitly so a refactor that unhooks one
  // fails here with its name rather than as a generic count.
  it('the two that were dead before are wired into the runtime path', () => {
    const runtime = [...sources.entries()]
      .filter(([name]) => name !== 'scorer.ts' && name !== 'ecosystem.ts')
      .map(([, code]) => code)
      .join('\n')

    expect(runtime, 'scoreWithRegime is not called from the runtime path')
      .toContain('scoreWithRegime(')
    expect(runtime, 'detectCampaigns is not called from the runtime path')
      .toContain('detectCampaigns(')
  })
})

// Word-boundary match, so `score` does not count as a use of `scoreWithRegime`
// and an import line alone counts as a reference.
function mentions(code: string, name: string): boolean {
  return new RegExp(`\\b${name}\\b`).test(code)
}

function occurrences(code: string, name: string): number {
  return (code.match(new RegExp(`\\b${name}\\b`, 'g')) ?? []).length
}
