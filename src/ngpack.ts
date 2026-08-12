// An .ngpack is an immutable snapshot of a package: raw packument, tarballs for
// N versions, signed manifest. Norte-guard produces identical output whether it
// reads the registry or an .ngpack, which is what lets keyv@6.0.0 stay
// analysable after npm purged it, keeps the benchmark reproducible years later,
// and lets tests run offline and deterministically.

import { createReadStream, createWriteStream, mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { createHash } from 'node:crypto'
import type { PackageSource, SourceInfo } from './source.js'
import type { Packument } from './packument.js'
import { defaultSource } from './source.js'
import { putObject, getObject, appendIndex } from './object-store.js'

export interface NgpackManifest {
  version: 1
  package: string
  capturedAt: string
  capturedFrom: string
  versionsIncluded: string[]
  hashes: Record<string, string>
  // Version → sha256 when the tarballs live in a shared content-addressed store
  // rather than inside this directory. Absent on captures written before the
  // store existed, which still read from tarballs/.
  objects?: Record<string, string>
  objectStore?: string
  // The signing key lives in the binary, never in the manifest — a manifest that
  // carried its own key could simply lie about itself.
}

export interface NgpackContents {
  manifest: NgpackManifest
  packument: Packument
  tarballs: Record<string, Buffer>
}

export async function createNgpack(
  packageName: string,
  outputPath: string,
  options: {
    versions?: string[]
    source?: PackageSource
    // Shared object store. The same tarball captured twice costs nothing the
    // second time, and the file name is its own integrity check.
    objectStore?: string
  } = {}
): Promise<NgpackContents> {
  const source = options.source ?? defaultSource
  const packument = await source.fetchPackument(packageName)

  // Chronological, so "last 10" means the ten most recently published rather
  // than the ten highest version strings.
  const allVersions = Object.keys(packument.versions)
    .sort((a, b) => {
      const ta = new Date(packument.time[a] ?? '').getTime()
      const tb = new Date(packument.time[b] ?? '').getTime()
      return ta - tb
    })

  const toCapture = options.versions ?? allVersions.slice(-10)

  console.error(`Capturing ${toCapture.length} versions of ${packageName}...`)

  const tarballs: Record<string, Buffer> = {}
  for (const ver of toCapture) {
    if (!packument.versions[ver]) continue
    process.stderr.write(`  ${ver}... `)
    tarballs[ver] = await source.fetchTarball(packageName, ver)
    console.error(`${(tarballs[ver].length / 1024).toFixed(0)}KB`)
  }

  const packumentRaw = JSON.stringify(packument)
  const hashes: Record<string, string> = {
    'packument.json': sha256(Buffer.from(packumentRaw)),
  }
  for (const [ver, buf] of Object.entries(tarballs)) {
    hashes[`tarballs/${ver}.tgz`] = sha256(buf)
  }

  const manifest: NgpackManifest = {
    version: 1,
    package: packageName,
    capturedAt: new Date().toISOString(),
    capturedFrom: 'https://registry.npmjs.org',
    versionsIncluded: Object.keys(tarballs),
    hashes,
  }

  // Written as a plain directory rather than a zip: the layout is the contract,
  // and archiving it can come later without changing any reader.
  mkdirSync(outputPath, { recursive: true })

  if (options.objectStore) {
    manifest.objectStore = options.objectStore
    manifest.objects = {}

    for (const [ver, buf] of Object.entries(tarballs)) {
      const stored = putObject(options.objectStore, buf)
      manifest.objects[ver] = stored.sha256
      appendIndex(options.objectStore, {
        sha256: stored.sha256,
        package: packageName,
        version: ver,
        bytes: stored.bytes,
        storedAt: new Date().toISOString(),
        deduped: !stored.written,
      })
      if (!stored.written) {
        console.error(`  ${ver}: already in the store (${stored.sha256.slice(0, 12)})`)
      }
    }
  } else {
    mkdirSync(join(outputPath, 'tarballs'), { recursive: true })
    for (const [ver, buf] of Object.entries(tarballs)) {
      writeFileSync(join(outputPath, 'tarballs', `${ver}.tgz`), buf)
    }
  }

  writeFileSync(join(outputPath, 'manifest.json'), JSON.stringify(manifest, null, 2))
  writeFileSync(join(outputPath, 'packument.json'), packumentRaw)

  console.error(`\n.ngpack saved to ${outputPath}`)
  return { manifest, packument, tarballs }
}

export class NgpackSource implements PackageSource {
  private contents: NgpackContents
  readonly sourceInfo: SourceInfo

  constructor(ngpackPath: string) {
    const manifestPath = join(ngpackPath, 'manifest.json')
    if (!existsSync(manifestPath)) {
      throw new Error(`Not a valid .ngpack: ${ngpackPath}`)
    }

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as NgpackManifest
    const packument = JSON.parse(
      readFileSync(join(ngpackPath, 'packument.json'), 'utf-8')
    ) as Packument

    // Verified at load time, not on access: a snapshot whose evidence has been
    // altered must fail loudly before anything reads a verdict off it.
    const packumentHash = sha256(Buffer.from(JSON.stringify(packument)))
    if (packumentHash !== manifest.hashes['packument.json']) {
      throw new Error('.ngpack corrupt: packument hash does not match')
    }

    const tarballs: Record<string, Buffer> = {}
    for (const ver of manifest.versionsIncluded) {
      // The store verifies on read, since the file name is the hash.
      if (manifest.objectStore && manifest.objects?.[ver]) {
        try {
          tarballs[ver] = getObject(manifest.objectStore, manifest.objects[ver]!)
        } catch (e) {
          throw new Error(`.ngpack ${ngpackPath}: ${e instanceof Error ? e.message : e}`)
        }
        continue
      }

      const tarPath = join(ngpackPath, 'tarballs', `${ver}.tgz`)
      if (existsSync(tarPath)) {
        const buf = readFileSync(tarPath)
        const hash = sha256(buf)
        if (hash !== manifest.hashes[`tarballs/${ver}.tgz`]) {
          throw new Error(`.ngpack corrupt: tarball hash for ${ver} does not match`)
        }
        tarballs[ver] = buf
      }
    }

    this.contents = { manifest, packument, tarballs }
    this.sourceInfo = {
      type: 'ngpack',
      location: ngpackPath,
      capturedAt: manifest.capturedAt,
    }
  }

  async fetchPackument(_name: string): Promise<Packument> {
    return this.contents.packument
  }

  async fetchTarball(_name: string, version: string): Promise<Buffer> {
    const buf = this.contents.tarballs[version]
    if (!buf) {
      throw new Error(
        `Tarball ${version} is not included in this .ngpack. ` +
        `Available versions: ${Object.keys(this.contents.tarballs).join(', ')}`
      )
    }
    return buf
  }

  get manifest(): NgpackManifest { return this.contents.manifest }
}

// Keeps the test suite off the network entirely, so tests cannot fail because
// npm was slow or a fixture package changed.
export class MockSource implements PackageSource {
  readonly sourceInfo: SourceInfo = {
    type: 'mock',
    location: 'memory',
  }

  constructor(
    private packuments: Record<string, Packument>,
    private tarballs: Record<string, Record<string, Buffer>> = {}
  ) {}

  async fetchPackument(name: string): Promise<Packument> {
    const p = this.packuments[name]
    if (!p) throw new Error(`Mock: package not found: ${name}`)
    return p
  }

  async fetchTarball(name: string, version: string): Promise<Buffer> {
    const buf = this.tarballs[name]?.[version]
    if (!buf) throw new Error(`Mock: tarball not available: ${name}@${version}`)
    return buf
  }
}

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex')
}

// Silence is not the same as a false positive — an attack nobody detects also
// sits quiet for 30 days. Captures therefore default to unconfirmed, and only a
// public report or an npm unpublish promotes a label. Treating silence as
// benign would let the benchmark score itself.
export type CaptureLabel = 'confirmed_malicious' | 'confirmed_benign' | 'unconfirmed'

export interface CaptureComposition {
  regime: string
  signals: string[]
  firstPublication: boolean
  ghost: string | null
  ghostKind: string | null
  newInstallScript: boolean
  // Base name when this capture is one member of a platform family, so a family
  // captured once is still recognisable as a family later.
  platformFamily: string | null
}

export interface CaptureMetadata {
  package: string
  version: string
  capturedAt: string
  score: number
  label: CaptureLabel
  labeledAt?: string
  labelSource?: string
  // Selection is part of the evidence: a capture chosen by a detector with a
  // known bug is a draw from what that bug flagged, and nothing downstream can
  // correct for a bias it cannot see. 'pre-fix-gate-bug' marks the era when the
  // gate scored packages against a genome they did not have.
  captureReason?: string
  engineVersion?: string
  // Quarantine captures delete themselves after this unless something confirms
  // them first.
  retainUntil?: string
  // What kind of capture this is, recorded structurally so the corpus can be
  // broken down by composition. A count of captures cannot say whether the disk
  // holds a corpus or a pile of redundant platform builds.
  composition?: CaptureComposition
  notes?: string
  // Captures can hold live malware; this rides along with every snapshot so the
  // warning survives being copied out of context.
  doNotExtract: true
}

export function writeCaptureMetadata(
  ngpackDir: string,
  metadata: Omit<CaptureMetadata, 'doNotExtract'>
): void {
  const full: CaptureMetadata = { ...metadata, doNotExtract: true }
  writeFileSync(join(ngpackDir, 'capture-metadata.json'), JSON.stringify(full, null, 2))
}

// Promotion out of 'unconfirmed' is the only way a sample enters the recall
// denominator, so it refuses to be convenient: no source, no confirmation. It
// also throws rather than no-opping, which used to let a caller believe it had
// labelled something.
export function labelCapture(
  ngpackDir: string,
  label: CaptureLabel,
  source: string,
  notes?: string
): CaptureMetadata {
  if (label !== 'unconfirmed' && !source.trim()) {
    throw new Error(
      `Labelling as "${label}" requires an external source: an npm advisory, a ` +
      `public report, or content analysis. A high score is not confirmation.`
    )
  }

  const metaPath = join(ngpackDir, 'capture-metadata.json')

  // Captures taken before the watcher wrote metadata still have a manifest, and
  // it carries everything a label needs except the score, which is recorded as
  // unknown rather than invented.
  const meta: CaptureMetadata = existsSync(metaPath)
    ? JSON.parse(readFileSync(metaPath, 'utf-8')) as CaptureMetadata
    : bootstrapMetadata(ngpackDir)
  meta.label = label
  meta.labeledAt = new Date().toISOString()
  meta.labelSource = source
  if (notes) meta.notes = notes

  writeFileSync(metaPath, JSON.stringify(meta, null, 2))
  return meta
}

function bootstrapMetadata(ngpackDir: string): CaptureMetadata {
  const manifestPath = join(ngpackDir, 'manifest.json')
  if (!existsSync(manifestPath)) {
    throw new Error(`No manifest.json in ${ngpackDir}: not a capture`)
  }

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as NgpackManifest
  return {
    package: manifest.package,
    version: manifest.versionsIncluded[0] ?? '',
    capturedAt: manifest.capturedAt,
    score: 0,
    label: 'unconfirmed',
    notes: 'metadata reconstructed from manifest.json: the capture score was never recorded',
    doNotExtract: true,
  }
}
