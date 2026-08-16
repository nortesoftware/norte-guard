// Weekly download counts, used by exactly one rule and fetched only when that
// rule's four free conditions already hold.
//
// The distinction between zero and unknown is the whole reason this returns
// null: a package nobody has ever installed and a package whose count could not
// be read look the same to a caller that collapses both to 0, and one of them is
// grounds for blocking a build.

import https from 'node:https'

const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'

export interface WeeklyDownloads {
  downloads: number
  // The week the count covers. npm reports the last COMPLETE week, which today
  // ends around five days back — so for a name created yesterday the answer is
  // zero over a window in which the package did not exist. That is not evidence
  // that nobody installs it, and a caller that treats the two the same is
  // reading a tautology as a finding.
  start: string | null
  end: string | null
  // The count is a 404 read as zero: npm has no record for the name at all.
  // For a package published minutes ago that is the normal answer and it is not
  // a measurement of anything — there is no window, so nothing can be said about
  // whether a download could have happened. Kept because after this object is
  // serialised into a capture nothing else can tell the two zeros apart, and a
  // caller that grades one as evidence for a blocking rule would be
  // manufacturing it.
  synthesizedFrom404: boolean
}

export async function fetchWeeklyDownloads(name: string, timeoutMs = 10_000): Promise<number | null> {
  const result = await fetchWeeklyDownloadsWindow(name, timeoutMs)
  return result ? result.downloads : null
}

export function fetchWeeklyDownloadsWindow(
  name: string,
  timeoutMs = 10_000
): Promise<WeeklyDownloads | null> {
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
      // published minutes ago that is the normal answer, and it is reported as
      // zero-with-no-window rather than as zero: the conjunction may treat it as
      // a match, but nothing downstream may treat it as evidence.
      if (res.statusCode === 404) {
        res.resume()
        return resolve({ downloads: 0, start: null, end: null, synthesizedFrom404: true })
      }
      if ((res.statusCode ?? 0) >= 400) { res.resume(); return resolve(null) }

      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body) as { downloads?: number; start?: string; end?: string }
          resolve(typeof parsed.downloads === 'number'
            ? {
                downloads: parsed.downloads,
                start: parsed.start ?? null,
                end: parsed.end ?? null,
                synthesizedFrom404: false,
              }
            : null)
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
