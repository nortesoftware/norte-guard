// Parsing and classification for install-time filesystem traces.
//
// The question this exists to answer is not "is this package malicious" — it is
// "what does a legitimate install actually need to open under $HOME". Nobody has
// published that, which is why every shipped install sandbox (nono, cplt, mise,
// Homebrew, pmg) either hand-writes its allowlist or punts on ~/.npmrc.
// See docs/prior-art.md, Part II.
//
// Input is `strace -f -qq -y -e trace=file,execve`. `trace=file` is deliberate:
// it records path ARGUMENTS and never file contents. The measurement machine has
// a live npm authToken in ~/.npmrc, and a tracer that could capture it would be
// the wrong tool for a project about not leaking credentials.

export type SyscallClass =
  | 'open' // may read or write content
  | 'probe' // stat/access family — existence and metadata only
  | 'mutate' // mkdir/unlink/rename/chmod — changes the tree
  | 'exec' // execve
  | 'traverse'; // chdir and friends

export type AccessMode = 'read' | 'write' | 'readwrite' | 'directory' | 'path' | 'none';

export type Outcome = 'ok' | 'enoent' | 'eacces' | 'eexist' | 'other-error';

export interface TraceEvent {
  pid: number;
  syscall: string;
  klass: SyscallClass;
  path: string; // absolute, resolved against the dirfd annotation
  mode: AccessMode;
  outcome: Outcome;
  errno?: string;
  /** True when the path argument was empty and the target came from an open fd.
   *  Landlock does not re-check an already-open fd, so these are exempt and are
   *  excluded from policy-relevant counts. */
  viaOpenFd: boolean;
}

// Which argument positions hold paths. The dirfd of an *at() syscall renders as
// `AT_FDCWD<...>` or `7</some/path>` — unquoted — so the first quoted string is
// the path for the whole *at() family without special-casing each one.
const TWO_PATH_SYSCALLS = new Set([
  'rename', 'renameat', 'renameat2', 'link', 'linkat', 'symlink', 'symlinkat',
]);

const PROBE_SYSCALLS = new Set([
  'stat', 'lstat', 'fstatat', 'newfstatat', 'statx', 'access', 'faccessat',
  'faccessat2', 'readlink', 'readlinkat', 'statfs', 'getxattr', 'lgetxattr',
  'listxattr', 'llistxattr',
]);

const MUTATE_SYSCALLS = new Set([
  'mkdir', 'mkdirat', 'rmdir', 'unlink', 'unlinkat', 'rename', 'renameat',
  'renameat2', 'link', 'linkat', 'symlink', 'symlinkat', 'chmod', 'fchmodat',
  'chown', 'lchown', 'fchownat', 'truncate', 'utimensat', 'utimes', 'mknod',
  'mknodat', 'setxattr', 'lsetxattr', 'removexattr',
]);

const OPEN_SYSCALLS = new Set(['open', 'openat', 'openat2', 'creat']);

export function classifySyscall(name: string): SyscallClass {
  if (OPEN_SYSCALLS.has(name)) return 'open';
  if (name === 'execve' || name === 'execveat') return 'exec';
  if (MUTATE_SYSCALLS.has(name)) return 'mutate';
  if (PROBE_SYSCALLS.has(name)) return 'probe';
  if (name === 'chdir' || name === 'fchdir') return 'traverse';
  return 'probe';
}

// O_PATH and O_DIRECTORY are called out separately because they are not content
// reads. A directory listing under a deny policy fails differently from a file
// read, and lumping them together would inflate the apparent breakage rate.
export function classifyMode(flags: string, klass: SyscallClass): AccessMode {
  if (klass === 'mutate') return 'write';
  if (klass !== 'open') return 'none';
  if (/\bO_PATH\b/.test(flags)) return 'path';
  if (/\bO_DIRECTORY\b/.test(flags)) return 'directory';
  if (/\bO_RDWR\b/.test(flags)) return 'readwrite';
  if (/\bO_WRONLY\b/.test(flags)) return 'write';
  if (/\bO_CREAT\b|\bO_TRUNC\b|\bO_APPEND\b/.test(flags)) return 'write';
  return 'read'; // O_RDONLY is 0 and often implicit
}

export function classifyOutcome(tail: string): { outcome: Outcome; errno?: string } {
  const m = /=\s*-?\d+\s+([A-Z][A-Z0-9_]+)\b/.exec(tail);
  if (!m) return { outcome: 'ok' };
  const errno = m[1];
  if (errno === 'ENOENT') return { outcome: 'enoent', errno };
  if (errno === 'EACCES' || errno === 'EPERM') return { outcome: 'eacces', errno };
  if (errno === 'EEXIST') return { outcome: 'eexist', errno };
  return { outcome: 'other-error', errno };
}

/** Quoted strings, honouring backslash escapes, in argument order. */
export function quotedArgs(args: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < args.length) {
    if (args[i] === '"') {
      let j = i + 1;
      let buf = '';
      while (j < args.length && args[j] !== '"') {
        if (args[j] === '\\' && j + 1 < args.length) {
          buf += args[j + 1];
          j += 2;
        } else {
          buf += args[j];
          j++;
        }
      }
      out.push(buf);
      i = j + 1;
    } else {
      i++;
    }
  }
  return out;
}

/** The `<...>` annotation strace's -y attaches to a dirfd, if the call has one. */
export function dirfdPath(args: string): string | null {
  const m = /^\s*(?:AT_FDCWD|\d+)<((?:[^<>]|<[^>]*>)*)>/.exec(args);
  return m ? m[1] : null;
}

const LINE = /^(?:\[pid\s+(\d+)\]\s*|(\d+)\s+)?([a-z][a-z0-9_]*)\((.*)$/;

export interface ParseOptions {
  home: string;
  /** Absolute path of the trace's starting cwd, for calls with no -y annotation. */
  fallbackCwd: string;
}

export function parseTraceLine(line: string, opts: ParseOptions): TraceEvent[] {
  const m = LINE.exec(line);
  if (!m) return [];
  const pid = Number(m[1] ?? m[2] ?? 0);
  const syscall = m[3];
  const rest = m[4];

  // Unfinished/resumed lines carry no result; strace reunites them itself when
  // writing to a single -o file, but a truncated tail can still appear.
  if (/<unfinished \.\.\.>\s*$/.test(rest)) return [];

  const klass = classifySyscall(syscall);
  if (klass === 'traverse') return [];

  const args = quotedArgs(rest);
  if (args.length === 0) return [];

  const base = dirfdPath(rest) ?? opts.fallbackCwd;
  const { outcome, errno } = classifyOutcome(rest);

  // Flags are whatever follows the path, before the result.
  const flagsPart = rest.slice(rest.indexOf('"') + 1);
  const flags = flagsPart.slice(flagsPart.indexOf('"') + 1);

  const wanted = TWO_PATH_SYSCALLS.has(syscall) ? args.slice(0, 2) : args.slice(0, 1);
  const events: TraceEvent[] = [];
  for (const raw of wanted) {
    // An empty path with a real dirfd means "operate on the fd itself"
    // (AT_EMPTY_PATH). Landlock does not re-check an open fd, so this is exempt.
    const viaOpenFd = raw === '';
    const abs = viaOpenFd
      ? (dirfdPath(rest) ?? '')
      : raw.startsWith('/')
        ? raw
        : joinPath(base, raw);
    if (!abs) continue;
    events.push({
      pid,
      syscall,
      klass,
      path: normalisePath(abs),
      mode: classifyMode(flags, klass),
      outcome,
      errno,
      viaOpenFd,
    });
  }
  return events;
}

export function joinPath(base: string, rel: string): string {
  if (rel === '.') return base;
  return `${base.replace(/\/+$/, '')}/${rel}`;
}

/** Lexical only. Symlinks are deliberately NOT resolved: a policy is written
 *  against the path the process asks for, which is what the kernel checks. */
export function normalisePath(p: string): string {
  const parts: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return '/' + parts.join('/');
}

/** Collapse a $HOME path to the prefix a policy would actually be written against.
 *  ~/.npm/_cacache/content-v2/sha512/dc/61/08b7... is one policy decision, not
 *  four thousand, so content-addressed fan-out is folded away. */
export function policyPrefix(path: string, home: string): string | null {
  if (path === home) return '~';
  if (!path.startsWith(home + '/')) return null;
  const rel = path.slice(home.length + 1);
  const parts = rel.split('/');

  // Dotfiles directly in $HOME are their own decision (~/.npmrc, ~/.gitconfig).
  if (parts.length === 1) return `~/${parts[0]}`;

  // Two levels is the granularity real policies are written at: ~/.npm/_cacache,
  // ~/.config/gh, ~/.local/share. Deeper is noise.
  return `~/${parts[0]}/${parts[1]}`;
}

export interface HomeAccessSummary {
  prefix: string;
  reads: number;
  writes: number;
  probes: number;
  mutations: number;
  execs: number;
  ok: number;
  enoent: number;
  denied: number;
  /** Distinct full paths under this prefix, capped for reporting. */
  distinctPaths: number;
  /** True if any content-bearing open (read or write) succeeded here. */
  contentAccessed: boolean;
}

export function summariseHomeAccess(
  events: Iterable<TraceEvent>,
  home: string,
): HomeAccessSummary[] {
  const acc = new Map<string, HomeAccessSummary & { paths: Set<string> }>();
  for (const e of events) {
    if (e.viaOpenFd) continue; // Landlock-exempt, see TraceEvent
    const prefix = policyPrefix(e.path, home);
    if (!prefix) continue;
    let s = acc.get(prefix);
    if (!s) {
      s = {
        prefix, reads: 0, writes: 0, probes: 0, mutations: 0, execs: 0,
        ok: 0, enoent: 0, denied: 0, distinctPaths: 0, contentAccessed: false,
        paths: new Set<string>(),
      };
      acc.set(prefix, s);
    }
    s.paths.add(e.path);
    if (e.outcome === 'ok') s.ok++;
    else if (e.outcome === 'enoent') s.enoent++;
    else if (e.outcome === 'eacces') s.denied++;

    if (e.klass === 'open') {
      if (e.mode === 'read') s.reads++;
      else if (e.mode === 'write' || e.mode === 'readwrite') s.writes++;
      else s.probes++; // O_PATH / O_DIRECTORY are not content access
      if (e.outcome === 'ok' && (e.mode === 'read' || e.mode === 'write' || e.mode === 'readwrite')) {
        s.contentAccessed = true;
      }
    } else if (e.klass === 'probe') s.probes++;
    else if (e.klass === 'mutate') s.mutations++;
    else if (e.klass === 'exec') s.execs++;
  }
  return [...acc.values()]
    .map(({ paths, ...rest }) => ({ ...rest, distinctPaths: paths.size }))
    .sort((a, b) => (b.reads + b.writes + b.mutations) - (a.reads + a.writes + a.mutations));
}
