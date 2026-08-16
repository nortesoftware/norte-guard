// What a file in a package actually is, decided by its bytes before its name.
//
// Extension-first classification was tried and is wrong here by a wide margin.
// Sniffing 200 tarballs from the corpus: 41 files with NO extension at all were
// Mach-O or ELF executables, and they carried 847MB — more than every .js file
// in the sample put together. A Go or Rust CLI published to npm ships its binary
// as `bin/toolname`, and a classifier that reads the name sees nothing there at
// all.
//
// So the magic bytes decide, and the extension is the fallback for the formats
// that have no magic worth the name — JavaScript being the obvious one.

export type FileKind =
  // Runs, and a JavaScript parser can read it.
  | 'javascript'
  // Runs, and nothing at this layer can read it.
  | 'native'
  | 'wasm'
  | 'bytecode'
  | 'foreign-script'
  // Ships alongside what runs, and is not what runs. Held out of the
  // denominator, counted and printed so the exclusion is visible.
  | 'typed-source'
  | 'sourcemap'
  | 'data'
  | 'docs'
  | 'asset'
  | 'other'

// The kinds that execute. This is the denominator of every coverage figure in
// analyzability.ts, and the choice is the load-bearing one: a package's risk is
// what it can run, not how many megabytes of font it ships alongside.
export const EXECUTABLE_KINDS: ReadonlySet<FileKind> = new Set<FileKind>([
  'javascript', 'native', 'wasm', 'bytecode', 'foreign-script',
])

export function isExecutableKind(kind: FileKind): boolean {
  return EXECUTABLE_KINDS.has(kind)
}

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx'])
const TYPED_SOURCE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.mts', '.cts', '.svelte', '.vue', '.astro', '.flow',
])
const NATIVE_EXTENSIONS = new Set([
  '.node', '.so', '.dll', '.dylib', '.exe', '.a', '.lib', '.o', '.obj', '.bin',
])
// Executes under something that is not a JavaScript engine. A shebang catches
// most of these, and the extension is here because a shell script invoked from
// package.json "scripts" does not need one — and an install script is the single
// most direct way a package runs code on a machine, so a .sh that fell out of
// the denominator for lacking a `#!` would be the worst possible thing to miss.
const FOREIGN_SCRIPT_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
  '.py', '.rb', '.pl', '.php', '.lua',
])

const DATA_EXTENSIONS = new Set([
  '.json', '.json5', '.yaml', '.yml', '.toml', '.xml', '.xsd', '.csv', '.sql', '.proto', '.graphql',
])
const DOC_EXTENSIONS = new Set(['.md', '.markdown', '.txt', '.rst', '.adoc', '.html', '.htm'])
const ASSET_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.bmp', '.avif',
  '.ttf', '.otf', '.woff', '.woff2', '.eot',
  '.css', '.scss', '.sass', '.less', '.styl',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm',
])

export function extensionOf(name: string): string {
  const base = name.slice(name.lastIndexOf('/') + 1)
  const dot = base.lastIndexOf('.')
  // A leading dot is a dotfile, not an extension: ".gitignore" has none.
  return dot > 0 ? base.slice(dot).toLowerCase() : ''
}

// A .d.ts is a type declaration and never executes. It is not merely
// "typed-source" — it has no runtime form at all — but it lands in the same
// held-out bucket, and calling it out here keeps a reader from assuming the
// classifier missed it.
export function isTypeDeclaration(name: string): boolean {
  return name.endsWith('.d.ts') || name.endsWith('.d.mts') || name.endsWith('.d.cts')
}

export interface Classification {
  kind: FileKind
  // How it was decided, because a measurement that turns on classification has
  // to be auditable when a number looks wrong.
  by: 'magic' | 'shebang' | 'extension' | 'default'
  detail: string
}

export function classifyFile(name: string, head: Buffer): Classification {
  const magic = sniffMagic(head)
  if (magic) return magic

  const shebang = sniffShebang(head)
  if (shebang) return shebang

  const ext = extensionOf(name)

  if (JS_EXTENSIONS.has(ext)) return { kind: 'javascript', by: 'extension', detail: ext }
  if (ext === '.jsc') return { kind: 'bytecode', by: 'extension', detail: 'V8 bytecode (.jsc)' }
  if (ext === '.wasm') return { kind: 'wasm', by: 'extension', detail: ext }
  if (ext === '.map') return { kind: 'sourcemap', by: 'extension', detail: ext }
  if (NATIVE_EXTENSIONS.has(ext)) return { kind: 'native', by: 'extension', detail: ext }
  if (FOREIGN_SCRIPT_EXTENSIONS.has(ext)) return { kind: 'foreign-script', by: 'extension', detail: ext }
  if (TYPED_SOURCE_EXTENSIONS.has(ext)) return { kind: 'typed-source', by: 'extension', detail: ext }
  if (DATA_EXTENSIONS.has(ext)) return { kind: 'data', by: 'extension', detail: ext }
  if (DOC_EXTENSIONS.has(ext)) return { kind: 'docs', by: 'extension', detail: ext }
  if (ASSET_EXTENSIONS.has(ext)) return { kind: 'asset', by: 'extension', detail: ext }

  // Anything left with no extension and no magic. LICENSE and README are most of
  // it in the measured sample; a `.worker` or a `.node`-in-disguise would have
  // been caught by the magic bytes above.
  return { kind: 'other', by: 'default', detail: ext || '(no extension)' }
}

// Only formats whose first bytes are unambiguous. Nothing here guesses: a
// classifier that reads four bytes and calls it JavaScript would put readable
// code in the opaque bucket and make the headline number a fiction.
function sniffMagic(head: Buffer): Classification | null {
  if (head.length < 4) return null

  const b0 = head[0]!, b1 = head[1]!, b2 = head[2]!, b3 = head[3]!

  // \0asm — the WebAssembly binary preamble.
  if (b0 === 0x00 && b1 === 0x61 && b2 === 0x73 && b3 === 0x6d) {
    return { kind: 'wasm', by: 'magic', detail: 'WebAssembly binary' }
  }

  // \x7fELF
  if (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46) {
    return { kind: 'native', by: 'magic', detail: 'ELF executable' }
  }

  // Mach-O, both endiannesses and both widths, plus the fat/universal wrapper.
  const be = (b0 << 24 >>> 0) + (b1 << 16) + (b2 << 8) + b3
  if (be === 0xfeedface || be === 0xfeedfacf || be === 0xcefaedfe || be === 0xcffaedfe) {
    return { kind: 'native', by: 'magic', detail: 'Mach-O executable' }
  }
  if (be === 0xcafebabe || be === 0xbebafeca) {
    // Also the Java class-file magic. Either way it is a compiled artifact this
    // layer cannot read, so the distinction does not change the bucket.
    return { kind: 'native', by: 'magic', detail: 'Mach-O universal or Java class' }
  }

  // MZ — DOS/PE, which is every .exe and .dll.
  if (b0 === 0x4d && b1 === 0x5a) {
    return { kind: 'native', by: 'magic', detail: 'PE/COFF executable' }
  }

  // !<arch>\n — a static library.
  if (head.length >= 8 && head.subarray(0, 8).toString('latin1') === '!<arch>\n') {
    return { kind: 'native', by: 'magic', detail: 'ar archive' }
  }

  return null
}

// A shebang means the file is executed directly, whatever its extension. Which
// interpreter decides whether a JavaScript parser has any business with it.
function sniffShebang(head: Buffer): Classification | null {
  if (head.length < 2 || head[0] !== 0x23 || head[1] !== 0x21) return null

  const line = head.subarray(0, Math.min(head.length, 256)).toString('utf-8').split('\n')[0] ?? ''
  if (/\bnode\b|\bbun\b|\bdeno\b/.test(line)) {
    return { kind: 'javascript', by: 'shebang', detail: line.trim() }
  }
  return { kind: 'foreign-script', by: 'shebang', detail: line.trim() }
}
