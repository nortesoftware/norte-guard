// Every package read goes through this interface so the caller never knows
// whether it is talking to the live registry or a local .ngpack snapshot.
// That is what makes verdicts reproducible years after a version is purged.

import type { Packument } from './packument.js'

export interface PackageSource {
  fetchPackument(name: string): Promise<Packument>
  fetchTarball(name: string, version: string): Promise<Buffer>

  // Carried into verdicts so a result can be traced back to its origin.
  readonly sourceInfo: SourceInfo

  // Facts that were true when the snapshot was taken and cannot be recovered
  // afterwards. The weekly download count is the only one so far and it is
  // enough to matter: the fabricated-profile conjunction needs it, npm reports
  // one week at a time, and a count read next year answers a different
  // question. Without this an .ngpack does not reproduce its own verdict, which
  // is the one thing the format exists for.
  capturedFacts?(name: string): CapturedFacts | null
}

export interface CapturedFacts {
  weeklyDownloads?: number | null
  downloadWindowEnd?: string | null
}

export interface SourceInfo {
  type: 'registry' | 'ngpack' | 'mock'
  location: string
  capturedAt?: string   // .ngpack only
}

import { fetchPackument as _fetchPackument } from './packument.js'
import https from 'node:https'

export class RegistrySource implements PackageSource {
  readonly sourceInfo: SourceInfo = {
    type: 'registry',
    location: 'https://registry.npmjs.org',
  }

  fetchPackument(name: string): Promise<Packument> {
    return _fetchPackument(name)
  }

  async fetchTarball(name: string, version: string): Promise<Buffer> {
    const packument = await this.fetchPackument(name)
    const meta = packument.versions[version]
    if (!meta) throw new Error(`Version ${version} not found for ${name}`)

    return downloadTarball(meta.dist.tarball)
  }
}

export const defaultSource = new RegistrySource()

// Exported because a caller that already holds the packument should not fetch it
// again to learn a URL it is looking at, and because the two copies can disagree
// when a package is being republished or taken down while the run is going.
export function downloadTarball(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { 'User-Agent': 'norte-guard/0.1.0' },
      timeout: 30_000,
    }, res => {
      // A 404 body is bytes, and without this check they were being handed back
      // as a tarball: stored under their own hash by the capture path, and read
      // as an archive with no members by the analysis path. Both report a
      // package with nothing in it, which is the wrong answer to "did this
      // download work" and reads downstream as a finding about the package.
      const status = res.statusCode ?? 0
      if (status >= 400) {
        res.resume()
        reject(new Error(`HTTP ${status}: ${url}`))
        return
      }

      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => resolve(Buffer.concat(chunks)))
      res.on('error', reject)
    })
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${url}`)) })
  })
}
