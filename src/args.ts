// Argument handling that must not live in cli.ts.
//
// cli.ts runs main() on import, so anything a test needs to check about how
// arguments are read has to be somewhere a test can import without starting the
// binary. Both functions here exist because of a bug that reached a user:
//
//   `norte-guard watch --help` started the watcher. --help was only honoured as
//   the FIRST argument, so with a command in front of it the flag was simply an
//   unrecognised string, and the watch branch ran: a second collector process,
//   writing captures into ./captures, from a command that asked for a help
//   page. A help flag must have no effects.
//
//   `--max-gb=oops` parsed to NaN and was handed to rotateCaptures as the total
//   cap. `total <= NaN` is false whatever the total, so the rotation loop would
//   have deleted every unconfirmed capture on the disk. A typo must not be a
//   way to wipe the corpus.

export const HELP_FLAGS = new Set(['--help', '-h', 'help'])

// Anywhere in the line, not only first. Exact matches only: `--notes=--help` is
// a note, and a package called `-h` is not something npm will serve.
export function wantsHelp(args: string[]): boolean {
  return args.length === 0 || args.some(a => HELP_FLAGS.has(a))
}

// The command help was asked about, when there is one. `norte-guard watch
// --help` and `norte-guard help watch` are the same question.
export function helpTopic(args: string[]): string | undefined {
  const first = args[0]
  if (first === undefined || first.startsWith('-')) return undefined
  if (HELP_FLAGS.has(first)) {
    const second = args[1]
    return second && !second.startsWith('-') ? second : undefined
  }
  return first
}

export class FlagError extends Error {}

// Gigabytes on the command line, bytes everywhere else. Throws rather than
// returning NaN: every caller of this feeds a byte budget, and a budget that
// cannot be compared against is more dangerous than no budget at all.
export function parseGigabytes(raw: string | undefined, flag: string): number | undefined {
  if (raw === undefined) return undefined

  const value = Number(raw)
  if (!Number.isFinite(value) || value <= 0) {
    throw new FlagError(
      `--${flag}=${raw} is not a size in GB. It has to be a positive number — ` +
      `--${flag}=25 for 25GB, --${flag}=0.5 for 512MB.`
    )
  }

  return Math.round(value * 1024 ** 3)
}

// The value of --flag=value, or undefined. One definition, because reading the
// same flag two different ways in two branches is how --threshold and
// --capture-budget drifted apart.
export function flagValue(args: string[], flag: string): string | undefined {
  const prefix = `--${flag}=`
  const found = args.find(a => a.startsWith(prefix))
  return found === undefined ? undefined : found.slice(prefix.length)
}
