import { describe, it, expect } from 'vitest'
import { extractCapabilities, capabilityDiff } from '../src/genome.js'
import type { VersionMeta } from '../src/packument.js'

function makeMeta(overrides: Partial<VersionMeta> = {}): VersionMeta {
  return {
    version: '1.0.0',
    publishedAt: '2024-01-01T00:00:00Z',
    publishedBy: 'test',
    unpackedSize: 100_000,
    hasInstallScript: false,
    scripts: {},
    dependencies: {},
    devDependencies: {},
    dist: { tarball: '', integrity: '' },
    ...overrides,
  }
}

describe('extractCapabilities', () => {
  it('no capabilities for a clean package', () => {
    const caps = extractCapabilities(makeMeta())
    expect(caps.size).toBe(0)
  })

  it('detects install_script', () => {
    const caps = extractCapabilities(makeMeta({
      hasInstallScript: true,
      scripts: { preinstall: 'node setup.js' },
    }))
    expect(caps.has('install_script')).toBe(true)
  })

  it('detects native_addon via node-gyp dependency', () => {
    const caps = extractCapabilities(makeMeta({
      dependencies: { 'node-gyp': '^9.0.0' },
    }))
    expect(caps.has('native_addon')).toBe(true)
  })

  it('detects network via axios dependency', () => {
    const caps = extractCapabilities(makeMeta({
      dependencies: { axios: '^1.0.0' },
    }))
    expect(caps.has('network')).toBe(true)
  })
})

describe('capabilityDiff', () => {
  it('finds new capabilities', () => {
    const prev = new Set(['network'] as const)
    const curr = new Set(['network', 'install_script'] as const)
    const diff = capabilityDiff(curr as Set<import('../src/types.js').Capability>, prev as Set<import('../src/types.js').Capability>)
    expect(diff.new).toContain('install_script')
    expect(diff.removed).toHaveLength(0)
  })

  it('finds removed capabilities', () => {
    const prev = new Set(['network', 'install_script'] as const)
    const curr = new Set(['network'] as const)
    const diff = capabilityDiff(curr as Set<import('../src/types.js').Capability>, prev as Set<import('../src/types.js').Capability>)
    expect(diff.removed).toContain('install_script')
    expect(diff.new).toHaveLength(0)
  })

  it('empty diff when equal', () => {
    const caps = new Set(['network'] as const)
    const diff = capabilityDiff(caps as Set<import('../src/types.js').Capability>, caps as Set<import('../src/types.js').Capability>)
    expect(diff.new).toHaveLength(0)
    expect(diff.removed).toHaveLength(0)
  })
})
