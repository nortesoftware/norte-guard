// Weekly download counts, used by exactly one rule and fetched only when that
// rule's four free conditions already hold.
//
// The distinction between zero and unknown is the whole reason this returns
// null: a package nobody has ever installed and a package whose count could not
// be read look the same to a caller that collapses both to 0, and one of them is
// grounds for blocking a build.

import https from 'node:https'

const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'

export function fetchWeeklyDownloads(name: string, timeoutMs = 10_000): Promise<number | null> {
  const encoded = name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : name

  return new Promise(resolve => {
    const req = https.get(`${DOWNLOADS_URL}/${encoded}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'norte-guard/0.1.0 (security analysis)',
      },
      timeout: timeoutMs,
    }, res => {
      // 404 means npm has no download record for the name. For a package
      // published minutes ago that is the normal answer and it means zero.
      if (res.statusCode === 404) { res.resume(); return resolve(0) }
      if ((res.statusCode ?? 0) >= 400) { res.resume(); return resolve(null) }

      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body) as { downloads?: number }
          resolve(typeof parsed.downloads === 'number' ? parsed.downloads : null)
        } catch {
          resolve(null)
        }
      })
      res.on('error', () => resolve(null))
    })

    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}
