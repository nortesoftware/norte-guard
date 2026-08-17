/**
 * Two bugs that reached a user, and the invariants that stop them coming back.
 *
 *   `norte-guard watch --help` started the watcher. --help was honoured only as
 *   the first argument, so behind a command it was an unrecognised string and
 *   the watch branch ran: a second collector process writing into ./captures,
 *   from a line that asked for a help page.
 *
 *   `--max-gb=oops` parsed to NaN and became the rotation cap. Nothing is ever
 *   under a NaN cap, so the loop would have deleted every unconfirmed capture
 *   on the disk. The parse and the rotation both refuse it now; this file pins
 *   the parse and collector.test.ts pins the rotation.
 */

import { describe, it, expect } from 'vitest'
import { wantsHelp, helpTopic, parseGigabytes, flagValue, FlagError } from '../src/args.js'

describe('a help flag has no effects', () => {
  it('is recognised anywhere in the line, not only first', () => {
    expect(wantsHelp(['watch', '--help'])).toBe(true)
    expect(wantsHelp(['watch', '--i-understand-the-risks', '--help'])).toBe(true)
    expect(wantsHelp(['watch', '-h'])).toBe(true)
    expect(wantsHelp(['help', 'watch'])).toBe(true)
    expect(wantsHelp(['--help'])).toBe(true)
    expect(wantsHelp([])).toBe(true)
  })

  // The exact line the user ran. It printed the collector's banner and created
  // ./captures.
  it('wins over a command that would otherwise do something', () => {
    expect(wantsHelp(['watch', '--help', '--i-understand-the-risks'])).toBe(true)
  })

  it('does not fire on a flag that merely contains the word', () => {
    expect(wantsHelp(['label', './cap', '--notes=--help was unclear'])).toBe(false)
    expect(wantsHelp(['inspect', 'help-me'])).toBe(false)
    expect(wantsHelp(['track', '--reason=-h is the short form'])).toBe(false)
  })

  it('names the command the help was asked about', () => {
    expect(helpTopic(['watch', '--help'])).toBe('watch')
    expect(helpTopic(['help', 'watch'])).toBe('watch')
    expect(helpTopic(['--help'])).toBeUndefined()
    expect(helpTopic(['help'])).toBeUndefined()
    expect(helpTopic([])).toBeUndefined()
  })
})

describe('a size on the command line', () => {
  it('reads gigabytes as bytes', () => {
    expect(parseGigabytes('40', 'total-cap')).toBe(40 * 1024 ** 3)
    expect(parseGigabytes('0.5', 'total-cap')).toBe(Math.round(0.5 * 1024 ** 3))
  })

  it('is absent when the flag is', () => {
    expect(parseGigabytes(undefined, 'total-cap')).toBeUndefined()
  })

  // Every one of these used to become a cap. `Math.round(parseFloat('oops') *
  // 1024 ** 3)` is NaN, and `total <= NaN` is false for every total.
  it('refuses anything that is not a positive size, by name', () => {
    for (const raw of ['oops', '', '0', '-5', 'NaN', 'Infinity', '10GB']) {
      expect(() => parseGigabytes(raw, 'total-cap'), `--total-cap=${raw}`).toThrow(FlagError)
    }
    expect(() => parseGigabytes('oops', 'total-cap')).toThrow(/--total-cap=oops/)
  })

  it('parses a value that contains an equals sign without losing half of it', () => {
    // split('=')[1] was the old reader, and it truncates. Nothing passes an '='
    // in a size, but the same helper reads --reason= and --notes=.
    expect(flagValue(['--reason=a=b'], 'reason')).toBe('a=b')
    expect(flagValue(['--total-cap=40'], 'total-cap')).toBe('40')
    expect(flagValue(['--other=1'], 'total-cap')).toBeUndefined()
  })
})
