#!/usr/bin/env node
import { inspect, parsePackageSpec } from './inspect.js'
import { renderInspect, renderJSON, exitCodeForVerdict } from './output.js'
import { parseLockfile, approvePackages, renderApprove } from './approve.js'
import { runBench } from './bench.js'
import { DEFAULT_THRESHOLDS } from './types.js'
import type { PackageSource } from './source.js'
import type { WatchedPackage } from './watchlist.js'

const args = process.argv.slice(2)
const command = args[0]

async function main(): Promise<void> {
  if (!command || command === '--help' || command === '-h') {
    printHelp()
    return
  }

  if (command === 'inspect') {
    const packageSpec = args[1]
    if (!packageSpec) {
      console.error('Usage: norte-guard inspect <package>[@version]')
      process.exit(1)
    }

    const mode = args.includes('--mode=audit') ? 'audit' : 'gate'
    const json = args.includes('--json')

    // Opt-in: the evidence that switched it on turned out to be evidence about
    // the capture filter rather than about this rule, and types.ts records how.
    // --no-block-fabricated-profile is still accepted so invocations written
    // while it was default-on keep working, and it now asks for what it gets.
    const config = {
      ...DEFAULT_THRESHOLDS[mode],
      blockFabricatedProfile:
        args.includes('--block-fabricated-profile') &&
        !args.includes('--no-block-fabricated-profile'),
    }

    // The versions worth inspecting are the ones npm has already purged, and
    // those answer "Version not found" from the registry. bench has read from
    // .ngpack since it existed; this is the same path for a single package.
    const sourceArg = args.find(a => a.startsWith('--source='))?.slice('--source='.length)

    try {
      let source: PackageSource | undefined
      if (sourceArg) {
        const { openNgpack, findNgpacks } = await import('./ngpack.js')
        const { name, version } = parsePackageSpec(packageSpec)

        const matches = findNgpacks(sourceArg, name, version)
        source = openNgpack(sourceArg, name, version)

        const chosen = matches[0]!
        console.error(
          `Reading ${chosen.path}\n` +
          `  captured ${chosen.capturedAt}, versions ${chosen.versionsIncluded.join(', ') || '(none)'}` +
          (version && !chosen.holdsVersion
            ? `\n  NOTE: no capture holds ${version}; the packument may still carry it`
            : '') +
          // Not "older": the chosen one is the one holding the requested
          // version, which is often not the most recent capture of the name.
          (matches.length > 1 ? `\n  ${matches.length - 1} other capture(s) of the same package not used` : '')
        )
      }

      // Progress goes to stderr so `--json | jq` stays parseable.
      console.error(`Analysing ${packageSpec}...`)
      const result = await inspect(packageSpec, { mode, config, source })

      if (json) {
        console.log(renderJSON(result))
      } else {
        console.log(renderInspect(result, config))
      }

      // Exit 1 on BLOCK so CI fails the step; 2 is reserved for tool errors,
      // which a pipeline should treat differently from a real finding.
      const code = exitCodeForVerdict(result.verdict, {
        strictNewPackages: args.includes('--strict-new-packages'),
      })
      if (code !== 0) process.exit(code)
    } catch (e) {
      console.error(`Error: ${e}`)
      process.exit(2)
    }
    return
  }

  if (command === 'approve') {
    // Named package: the escape from a block. Without an argument it falls
    // through to the bulk lockfile pass below, which is a different operation.
    const named = args[1] && !args[1].startsWith('--') ? args[1] : null

    if (named) {
      const justification = args.find(a => a.startsWith('--reason='))?.slice('--reason='.length)
      if (!justification) {
        console.error(`Usage: norte-guard approve ${named} --reason="why you accept it"`)
        console.error('An exception with no written reason is one nobody can review.')
        process.exit(1)
      }

      const { createOverrideApproval, readApprovalRecord, writeApprovalRecord } =
        await import('./approvals.js')
      const { existsSync } = await import('node:fs')
      const path = args.find(a => a.startsWith('--manifest='))?.split('=')[1] ?? './norte-guard-approvals.json'

      try {
        const result = await inspect(named, {
          mode: 'gate',
          config: { ...DEFAULT_THRESHOLDS.gate, blockFabricatedProfile: true },
        })

        const existing = existsSync(path) ? readApprovalRecord(path) : undefined
        const record = createOverrideApproval(result, { justification, existing })
        writeApprovalRecord(record, path)

        console.log(
          `\n${result.package}@${result.version} approved. The verdict was ${result.verdict}` +
          ` (score ${result.totalScore})`
        )
        console.log(`  reason: ${justification}`)
        console.log(`  recorded in ${path} - ${record.approvals.length} approvals in total`)
        console.log(`\n  Commit the manifest: the exception belongs in the repository, not in someone's head.\n`)
      } catch (e) {
        console.error(`Error: ${e}`)
        process.exit(2)
      }
      return
    }

    const cwd = process.cwd()
    try {
      console.error('Reading the lockfile...')
      const packages = await parseLockfile(cwd)

      if (packages.length === 0) {
        console.log('\nNo packages with install scripts: nothing to approve.\n')
        return
      }

      console.error(`Analysing ${packages.length} packages with install scripts...`)
      const results = await approvePackages(packages)
      console.log(renderApprove(results))

      const blocked = results.filter(r => r.recommendation === 'BLOCK')
      if (blocked.length > 0) process.exit(1)
    } catch (e) {
      console.error(`Error: ${e}`)
      process.exit(2)
    }
    return
  }

  if (command === 'bench') {
    const mode = args.includes('--mode=audit') ? 'audit' : 'gate'
    await runBench({
      mode,
      offline: args.includes('--offline'),
      verbose: args.includes('--verbose'),
    })
    return
  }

  if (command === 'corpus') {
    const { loadCorpus, describeCorpusProgress, describeContamination, backfillCaptureProvenance, PRE_FIX_REASON } =
      await import('./corpus.js')

    // Retroactive provenance for captures taken before the watcher recorded any.
    if (args.includes('--backfill')) {
      const reason = args.find(a => a.startsWith('--reason='))?.split('=')[1] ?? PRE_FIX_REASON
      const engine = args.find(a => a.startsWith('--engine-version='))?.split('=')[1]
      const before = args.find(a => a.startsWith('--before='))?.split('=')[1]
      const dryRun = args.includes('--dry-run')

      if (!engine) {
        console.error('Usage: norte-guard corpus --backfill --engine-version=<v> [--reason=<r>] [--before=<ISO>] [--dry-run]')
        console.error('The engine version that captured them cannot be guessed: pass it explicitly.')
        process.exit(1)
      }

      const results = backfillCaptureProvenance({ reason, engineVersion: engine, before, dryRun })
      const marked = results.filter(r => r.action === 'marked')

      for (const r of results) {
        console.log(`  ${r.action.padEnd(24)} ${r.package}@${r.version}`)
      }
      console.log(
        `\n${dryRun ? '[dry-run] ' : ''}${marked.length} captures marked ` +
        `reason=${reason} engineVersion=${engine}`
      )
      return
    }

    const corpus = loadCorpus()

    console.log(`\nCorpus: ${corpus.roots.join(', ')}`)
    console.log(describeCorpusProgress(corpus))

    const contamination = describeContamination(corpus)
    if (contamination) console.log(`WARNING: ${contamination}`)
    console.log()

    const { describeComposition } = await import('./corpus.js')
    const { directorySize, formatBytes } = await import('./capture-budget.js')
    const c = describeComposition(corpus.samples)

    console.log('COMPOSITION')
    console.log(`  captures                        ${c.total}  (${c.withComposition} with a breakdown)`)
    console.log(`  platform-family members         ${c.platformFamilyMembers} across ${c.platformFamilies} families`)
    console.log(`  first publications              ${c.firstPublications}`)
    console.log(
      `  with a ghost                    ${c.withGhost}` +
      (Object.keys(c.ghostByKind).length > 0
        ? `  (${Object.entries(c.ghostByKind).map(([k, n]) => `${k}:${n}`).join(' ')})`
        : '')
    )
    console.log(`  with a new install script       ${c.withNewInstallScript}`)
    for (const [regime, n] of Object.entries(c.byRegime).sort(([, a], [, b]) => b - a)) {
      console.log(`  regime ${regime.padEnd(24)} ${n}`)
    }
    if (c.topSignals.length > 0) {
      console.log('  most frequent signals')
      for (const { signal, count } of c.topSignals) {
        console.log(`    ${signal.padEnd(34)} ${count}`)
      }
    }

    // The precision of the filter that fills this corpus, which is the number
    // that decides whether any of it can be published. A count of confirmed
    // removals on its own is a numerator looking for a denominator.
    const { classPrecision } = await import('./corpus.js')
    const { QUARANTINE_CAPTURE_REASON, VERDICT_AFTER_DAYS, REAL_USAGE_DOWNLOADS, readObservations } =
      await import('./watchlist.js')
    const { readLiveTakedowns } = await import('./field-recall.js')
    const { readExpiredCaptures, DEFAULT_QUARANTINE } = await import('./capture-budget.js')
    const { formatRateWithCI } = await import('./stats.js')
    const { existsSync: exists, readFileSync: readF } = await import('node:fs')
    const { join: pjoin } = await import('node:path')

    const captureDir = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures'
    const removedPackages = readLiveTakedowns(captureDir)
    // The sweep too: it is frozen at the moment it ran, but a removal it knows
    // and the live log missed is still a removal.
    const sweepPath = pjoin(captureDir, 'takedowns.json')
    if (exists(sweepPath)) {
      try {
        const sweep = JSON.parse(readF(sweepPath, 'utf-8')) as { takenDown?: Array<{ package: string }> }
        for (const t of sweep.takenDown ?? []) removedPackages.add(t.package)
      } catch { /* one source down, not the end of the count */ }
    }

    // The highest count the tracker has ever seen for a package, not the latest:
    // a name that was installed and then stopped being installed was still
    // installed, and that is what decides whether blocking it was a mistake.
    const observedDownloads = new Map<string, number>()
    for (const o of readObservations(captureDir)) {
      const seen = observedDownloads.get(o.package) ?? 0
      observedDownloads.set(o.package, Math.max(seen, o.weeklyDownloads ?? 0))
    }

    const precision = classPrecision({
      samples: corpus.samples,
      captureReason: QUARANTINE_CAPTURE_REASON,
      removedPackages,
      // The names whose artifacts retention or the disk cap has taken. They were
      // marked, so they stay in the denominator.
      expired: readExpiredCaptures(pjoin(captureDir, 'captures')),
      observedDownloads,
      realUsageDownloads: REAL_USAGE_DOWNLOADS,
      matureDays: VERDICT_AFTER_DAYS,
      retentionDays: DEFAULT_QUARANTINE.retentionDays,
    })

    console.log('\nPRECISION OF THE CAPTURE FILTER (4 conditions, captureReason=' + QUARANTINE_CAPTURE_REASON + ')')
    console.log(`  marked                          ${precision.markedPackages} packages in ${precision.markedCaptures} captures`)
    console.log(`  removed by npm                  ${precision.removed}`)
    // Not "alive": nothing has asked the registry about most of these. It is the
    // remainder, and naming it as a remainder is what stops it being read as a
    // count of surviving packages.
    console.log(
      `  not known to be removed         ${precision.markedPackages - precision.removed}` +
      `  (unverified: no source has been asked about most of them)`
    )
    console.log(
      `  alive with >=${REAL_USAGE_DOWNLOADS} weekly downloads  ${precision.observedAliveWithUsage}` +
      `  (of ${precision.observedAlive} ever queried)`
    )
    console.log(
      `  precision                       ` +
      (precision.precision
        ? formatRateWithCI(precision.removed, precision.markedPackages)
        : 'not calculable, nothing marked')
    )
    console.log(
      `  precision at >=${precision.matureDays}d               ` +
      (precision.maturePrecision
        ? formatRateWithCI(precision.matureRemoved, precision.maturePackages)
        : `not calculable: 0 of ${precision.markedPackages} marked packages have reached ${precision.matureDays} days`)
    )
    console.log(
      `  oldest marked ${precision.oldestMarkedDays ?? '-'} days, median ${precision.medianMarkedDays ?? '-'} days`
    )
    for (const caveat of precision.caveats) {
      console.log(`  ! ${caveat}`)
    }
    console.log(
      `  This is the filter that fills the corpus, not the rule that fails builds.\n` +
      `  The rule needs a fifth condition the filter never evaluates.`
    )

    if (!args.includes('--no-size')) {
      for (const root of corpus.roots) {
        const bytes = directorySize(root)
        if (bytes > 0) console.log(`\n  disk: ${formatBytes(bytes)} in ${root}`)
      }
    }
    console.log()

    const usable = corpus.samples.filter(s => !s.contaminated)
    const render = (s: typeof corpus.samples[number]) => {
      const mark = s.label === 'confirmed_malicious' ? '[malicious]'
                 : s.label === 'confirmed_benign' ? '[benign]   '
                 : '[unknown]  '
      console.log(
        `  ${mark} ${`${s.package}@${s.version}`.padEnd(46)} ${s.label.padEnd(20)} ` +
        `${s.labelSource ?? (s.labelAssumed ? '(no metadata)' : '(no source)')}`
      )
    }

    if (usable.length > 0) {
      console.log('USABLE IN BENCHMARKS')
      for (const s of usable) render(s)
      console.log()
    }

    if (corpus.contaminated.length > 0) {
      console.log('EXCLUDED FROM EVERY BENCHMARK')
      for (const s of corpus.contaminated) {
        render(s)
        console.log(`      ${s.contaminationReason}${s.engineVersion ? ` [engine v${s.engineVersion}]` : ''}`)
      }
      console.log()
    }

    console.log(
      `A capture enters the recall denominator only if it is labelled\n` +
      `confirmed_malicious with an external source AND its provenance is not marked\n` +
      `as contaminated. A high score is not confirmation.\n`
    )
    return
  }

  // What a capture budget costs, measured on the stream it is applied to.
  //
  // It does not derive a threshold. A percentile of the live stream says what is
  // normal right now, and an attack is a change in what is normal, so a cut-off
  // recomputed from it rises exactly when it should not. This answers what a
  // budget costs in disk, and refuses the other question.
  // Which modules a package can reach from its entry points, and by what route.
  // It answers "can this reach X?" and refuses the other question: nothing here
  // decides that reaching X is dangerous. That is A3, and A3 needs confirmed
  // samples this corpus does not have — two with bytes, not eight.
  if (command === 'reachability') {
    const { analyzePackage } = await import('./reachability.js')
    const { readTar } = await import('./tarball.js')
    const { classifyFile } = await import('./file-kind.js')
    const { loadCorpus } = await import('./corpus.js')
    const { NgpackSource } = await import('./ngpack.js')

    const target = args.find(a => a.startsWith('--capture='))?.split('=')[1]
    if (!target) {
      console.error('Usage: norte-guard reachability --capture=<package|path>')
      console.error('One capture at a time. Running it over the corpus is a later phase.')
      process.exit(1)
    }

    const corpus = loadCorpus()
    const sample = corpus.samples.find(s => s.package === target || s.ngpackPath === target)
    if (!sample) {
      console.error(`No capture for ${target}`)
      process.exit(1)
    }
    if (!sample.tarballPresent) {
      console.error(`${sample.package}@${sample.version} has no tarball bytes on disk.`)
      console.error('Two thirds of this corpus is in that state; see `norte-guard analyzability`.')
      process.exit(1)
    }

    const source = new NgpackSource(sample.ngpackPath)
    const tarball = source.tarballSync(sample.version) ?? source.tarballSync()
    if (!tarball) {
      console.error('the snapshot holds no tarball')
      process.exit(1)
    }

    const archive = readTar(tarball)
    const files = new Map<string, string>()
    let packageJson: unknown = {}
    let root = 'package'

    for (const entry of archive.entries) {
      const kind = classifyFile(entry.name, entry.data.subarray(0, 256)).kind
      if (kind === 'javascript') files.set(entry.name, entry.data.toString('utf-8'))
      if (/^[^/]+\/package\.json$/.test(entry.name)) {
        root = entry.name.split('/')[0] ?? 'package'
        try { packageJson = JSON.parse(entry.data.toString('utf-8')) } catch { /* leave it empty */ }
      }
    }

    const result = analyzePackage({ files, packageJson, root })

    console.log(`\nREACHABILITY  ${sample.package}@${sample.version}`)
    console.log(`  ${sample.ngpackPath}`)
    console.log(`\nENTRY POINTS`)
    for (const e of result.entryPoints) console.log(`  ${e}`)
    for (const e of result.missingEntryPoints) console.log(`  ${e}   [declared, not in the tarball]`)
    if (result.entryPoints.length === 0) console.log('  (none resolved)')

    console.log(`\nFILES REACHED FROM THEM  ${result.filesAnalysed.length} of ${files.size} parseable`)
    for (const f of result.filesAnalysed) console.log(`  ${f}`)

    console.log(`\nMODULES REACHABLE`)
    if (result.reachable.length === 0) {
      console.log('  (none)')
    } else {
      for (const r of result.reachable) {
        console.log(
          `  ${r.module.padEnd(28)} ${r.gates.join(',').padEnd(16)} via ${r.route.join(' > ')}`
        )
        for (const path of r.paths) console.log(`      .${path.join('.')}`)
        for (const f of r.files) console.log(`      from ${f}`)
      }
    }

    if (result.unresolvedLocal.length > 0) {
      console.log(`\nRELATIVE SPECIFIERS THAT RESOLVE TO NO FILE IN THE PACKAGE`)
      for (const u of result.unresolvedLocal) console.log(`  ${u}`)
    }

    console.log(`\nWHERE THE TRAIL WAS LOST  ${result.lost.length}`)
    for (const l of result.lost) {
      console.log(`  ${l.reason.padEnd(20)} ${(l.file ?? '?')}:${l.line ?? '?'}  ${l.detail}`)
    }
    if (result.lost.length === 0) console.log('  (nowhere)')

    console.log(
      `\nWHAT THIS CANNOT SAY\n` +
      `  It answers "can this reach X", not "is this dangerous". Nothing here\n` +
      `  classifies a module, and nothing scores.\n` +
      `  A lost trail is not an absence. Every line above under "lost" is a place\n` +
      `  something could be reached and this analysis stopped following.\n` +
      `  Only files a JavaScript parser could read were followed; a native binary\n` +
      `  or a WASM module reaches whatever it likes and appears nowhere here.\n`
    )
    return
  }

  // What can be looked at at all, before anything looks. This detects nothing:
  // it measures the size of the blind spot every detector reports PASS into.
  if (command === 'analyzability') {
    const {
      runCorpusAnalyzability, collectMetrics, checkThreshold, analyzeCapture,
    } = await import('./analyzability-run.js')
    const { MINIFIED_THRESHOLD } = await import('./analyzability.js')
    const { engineVersion } = await import('./fp-bench-store.js')
    const { formatRateWithCI, pct } = await import('./stats.js')
    const { writeFileSync: write, mkdirSync } = await import('node:fs')

    const num = (flag: string, fallback: number) => {
      const raw = args.find(a => a.startsWith(`--${flag}=`))?.split('=')[1]
      const parsed = raw === undefined ? NaN : Number(raw)
      return Number.isFinite(parsed) ? parsed : fallback
    }
    const sample = num('sample', 0) || undefined
    const outDir = args.find(a => a.startsWith('--results-dir='))?.split('=')[1] ?? 'analyzability-results'

    // The same cut, with size controlled. --by-class compares two filters
    // against each other and one of them is defined as "under 100KB", so any
    // legibility gap it reports is partly that definition reading itself back.
    // This holds size fixed and varies the class definition one conjunct at a
    // time.
    if (args.includes('--size-control')) {
      const { runSizeControl } = await import('./size-control.js')
      const { formatDifference } = await import('./stats.js')

      const since = args.find(a => a.startsWith('--since='))?.split('=')[1]
      const until = args.find(a => a.startsWith('--until='))?.split('=')[1]
      const output = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures'
      const draw = num('draw', 0)

      if (!since) {
        console.error('Usage: norte-guard analyzability --size-control --since=<YYYY-MM-DD> [--draw=<n per cell>]')
        console.error(
          '\n--since is required and is not a preference. Two thirds of this corpus lost its\n' +
          'tarballs to the object-store wipe, and what survived is everything captured after\n' +
          '2026-08-15. A comparison without a window compares whichever weeks each group\n' +
          'happened to survive in.'
        )
        process.exit(1)
      }

      const report = await runSizeControl({
        outputDir: output,
        threshold: MINIFIED_THRESHOLD,
        engineVersion: engineVersion(),
        since,
        until,
        drawPerCell: draw,
        onProgress: (stage, d, t) => {
          if (d === t || d % 50 === 0) process.stderr.write(`  ${stage}: ${d}/${t}\n`)
        },
      })

      console.log(`\nANALYZABILITY, SIZE CONTROLLED  norte-guard v${report.engineVersion}`)
      console.log(
        `  every group is under ${report.maxBytes / 1000}KB unpacked and was seen on or after ` +
        `${report.window.since}` + (report.window.until ? ` and before ${report.window.until}` : '')
      )
      console.log(
        `\n  The by-class run cannot answer the question it looks like it answers. The\n` +
        `  class is DEFINED as under 100KB, and a binary, a WASM module, a bytecode\n` +
        `  cache and a webpack bundle do not fit in 100KB; the segment it was compared\n` +
        `  against is selected on a high score, which is enriched for exactly those.\n` +
        `  So here size is held fixed and the definition is varied one conjunct at a\n` +
        `  time: +repository, +age, and the far corner where all three differ.`
      )

      console.log(`\nWHAT WAS ON DISK IN THE WINDOW`)
      console.log(
        `  ${report.corpus.inWindow} uncontaminated captures; ${report.corpus.overTheSizeBand} are over the size band ` +
        `and out of this study, ${report.corpus.withBytes} are under it with bytes still on disk`
      )
      if (report.corpus.unclassifiable > 0) {
        console.log(`  ${report.corpus.unclassifiable} could not be classified at all (no packument, a hash that does not match, or the captured version missing from it)`)
      }
      for (const c of report.corpus.byCell) {
        console.log(`    ${c.cell.padEnd(12)} ${String(c.captures).padStart(6)} captures  ${String(c.packages).padStart(6)} packages`)
      }

      console.log(`\nWHAT THE PUBLISH STREAM HELD IN THE SAME WINDOW  (changes-log.ndjson)`)
      console.log(`  ${report.pool.analysedInWindow} publications scored, ${report.pool.tinyInWindow} of them under 100KB`)
      for (const c of report.pool.byCell) {
        console.log(`    ${c.cell.padEnd(12)} ${String(c.packages).padStart(6)} packages`)
      }
      if (draw === 0) {
        console.log(
          `\n  NOTHING WAS DRAWN FROM IT. --draw=0 leaves the on-disk comparison as the only\n` +
          `  one, and that one is NOT size-matched: it is captures the watcher kept for\n` +
          `  scoring high. Re-run with --draw=<n> to draw each cell from the stream above\n` +
          `  and fetch it from npm.`
        )
      }

      console.log(`\nWHAT EACH GROUP IS`)
      for (const g of report.groups) {
        console.log(`  ${g.name}${g.sizeMatched ? '' : '   [NOT size-matched]'}`)
        console.log(`    ${g.definition}`)
        console.log(
          `    ${g.members} packages, ${g.analysed} measured, ${g.scored} scored` +
          (g.failures.length > 0 ? `; ${g.failures.length} could not be measured` : '') +
          (g.unreadable > 0 ? `; ${g.unreadable} unreadable archives` : '') +
          (g.nothingExecutable > 0 ? `; ${g.nothingExecutable} with nothing executable` : '')
        )
        console.log(
          `    median ${g.medianUnpackedSize === null ? 'n/a' : `${(g.medianUnpackedSize / 1000).toFixed(1)}KB`}` +
          `    by day: ` + (g.byDay.map(d => `${d.day.slice(5)}:${d.members}`).join('  ') || '(none)')
        )
        if (g.shortfall.length > 0) {
          console.log(`    the pool could not fill: ` + g.shortfall.map(s => `${s.bucket} ${s.got}/${s.wanted}`).join('  '))
        }
      }

      // The control, checkable. Every group is profiled in the CLASS's deciles,
      // never in its own: a table where each column is cut at its own quantiles
      // reads as a perfect match whatever the sizes are.
      console.log(`\nDID THE MATCH WORK  (share of each group inside the class's own size deciles)`)
      const cols = report.groups.map(g => g.name.split(',')[0]!.slice(0, 10).padStart(11)).join('')
      console.log(`  ${'decile'.padEnd(16)}${cols}`)
      for (let i = 0; i < report.buckets.length; i++) {
        const cells = report.groups
          .map(g => pct(g.sizeProfile[i]?.share ?? 0, 1).padStart(11))
          .join('')
        console.log(`  ${(report.buckets[i]?.label ?? '').padEnd(16)}${cells}`)
      }

      console.log(`\nLEGIBILITY`)
      for (const g of report.groups) {
        console.log(`\n  ${g.name}  (${g.scored} packages with something executable in them)`)
        if (g.scored === 0) { console.log(`    nothing to measure`); continue }
        console.log(`    fully legible           ${formatRateWithCI(g.fullyLegible.successes, g.fullyLegible.n)}`)
        console.log(`    ships opaque executable ${formatRateWithCI(g.shipsOpaqueExecutable.successes, g.shipsOpaqueExecutable.n)}`)
        console.log(`    coverage by bytes       ${g.byteCoverage === null ? 'n/a' : pct(g.byteCoverage)}`)
        console.log(`    coverage, median pkg    ${g.medianCaptureCoverage === null ? 'n/a' : pct(g.medianCaptureCoverage)}`)
        console.log(`    entry point followable  ${g.analysed > 0 ? pct(g.reachabilityAnalysed / g.analysed) : 'n/a'}`)
        const reasons = g.reasons.filter(r => r.captures > 0)
        if (reasons.length > 0) {
          console.log(`    why not covered`)
          for (const r of reasons) {
            console.log(`      ${r.reason.padEnd(18)} ${formatRateWithCI(r.captureRate.successes, r.captureRate.n)}`)
          }
        }
      }

      for (const c of report.comparisons) {
        console.log(`\n${'='.repeat(72)}`)
        console.log(`${c.a}  vs  ${c.b}${c.sizeMatched ? '' : '   [NOT size-matched]'}`)
        for (const e of c.endpoints) {
          console.log(`\n  ${e.endpoint}`)
          console.log(`    ${e.meaning}`)
          console.log(`    ${formatDifference(e.difference)}`)
          if (e.familyAdjusted) {
            console.log(
              `    widened for the ${c.endpointFamily} endpoint comparisons in this run ` +
              `(z=${c.endpointZ?.toFixed(2)}): ${formatDifference(e.familyAdjusted)}`
            )
          }
        }

        const modules = c.modules.filter(m => Math.abs(m.difference.difference ?? 0) > 0).slice(0, 10)
        if (modules.length > 0) {
          console.log(
            `\n  modules reachable, ${c.a} minus ${c.b}\n` +
            `    intervals widened for the ${c.moduleComparisons} modules in this table ` +
            `(Bonferroni, z=${c.moduleZ.toFixed(2)}): picking the largest row of a long\n` +
            `    table and reading a 95% interval off it is how the last module finding was made.`
          )
          for (const m of modules) {
            console.log(`    ${m.module.padEnd(24)} ${formatDifference(m.difference)}`)
          }
        }

        console.log(`\n  ${c.verdict}`)
        console.log(`  Caveat: ${c.caveat}.`)
      }

      console.log(`\nWHAT THIS STILL CANNOT SAY`)
      for (const caveat of report.caveats) {
        console.log(`  - ${caveat}`)
      }

      if (!args.includes('--no-save')) {
        mkdirSync(outDir, { recursive: true })
        const path = `${outDir}/size-control-${new Date().toISOString().slice(0, 10)}-v${report.engineVersion}.json`
        write(path, JSON.stringify(report, null, 2))
        console.log(`\nSaved to ${path}\n`)
      }
      return
    }

    // The corpus cut by class. Descriptive: it compares distributions and does
    // not decide anything about any of them.
    if (args.includes('--by-class')) {
      const { runSegmentedAnalyzability } = await import('./analyzability-run.js')
      const since = args.find(a => a.startsWith('--since='))?.split('=')[1]
      const report = runSegmentedAnalyzability({
        threshold: MINIFIED_THRESHOLD,
        engineVersion: engineVersion(),
        since,
        sample,
        onProgress: (d, t) => { if (d % 100 === 0) process.stderr.write(`  ${d}/${t}\n`) },
      })

      console.log(`\nANALYZABILITY BY CLASS  norte-guard v${report.engineVersion}`)
      if (report.since) console.log(`  restricted to captures on or after ${report.since}`)

      // Printed before any rate, for every segment, because the object store lost
      // 3,169 of the 4,237 objects it ever held and the loss is not spread evenly
      // across the classes. A rate over a segment whose bytes are mostly gone is
      // drawn from whatever survived, and what survived is everything captured
      // after 2026-08-15 — not a random sample of the segment.
      console.log(`\nHOW MUCH OF EACH SEGMENT STILL HAS BYTES`)
      console.log(`  ${'segment'.padEnd(24)} ${'captures'.padStart(9)} ${'with bytes'.padStart(11)}  share`)
      for (const seg of report.segments) {
        console.log(
          `  ${seg.segment.padEnd(24)} ${String(seg.capturesTotal).padStart(9)} ` +
          `${String(seg.capturesWithBytes).padStart(11)}  ` +
          formatRateWithCI(seg.bytesShare.successes, seg.bytesShare.n)
        )
        console.log(
          `    survivors by day: ` +
          (seg.survivorsByDay.map(d => `${d.day.slice(5)}:${d.captures}`).join('  ') || '(none)')
        )
      }
      console.log(
        `  Every rate below this line is computed over the "with bytes" column and\n` +
        `  over nothing else. The captures whose bytes are gone are not missing at\n` +
        `  random: they are every capture taken before 2026-08-15.`
      )

      for (const seg of report.segments) {
        console.log(`\n${'='.repeat(66)}`)
        console.log(`${seg.segment}  n=${seg.analysed} analysed of ${seg.capturesTotal} in the corpus`)
        if (seg.oldestCapturedAt) {
          console.log(`  captured ${seg.oldestCapturedAt.slice(0, 10)} to ${(seg.newestCapturedAt ?? '').slice(0, 10)}`)
        }
        if (seg.analysed === 0) { console.log('  nothing to measure'); continue }

        console.log(`  coverage by bytes             ${seg.byteCoverage === null ? 'n/a' : pct(seg.byteCoverage)}`)
        console.log(`  coverage, median capture      ${seg.medianCaptureCoverage === null ? 'n/a' : pct(seg.medianCaptureCoverage)}`)
        console.log(`  nothing executable            ${seg.nothingExecutable}`)
        console.log(`  distribution  ` + seg.distribution.map(b => `${b.label}:${b.captures}`).join('  '))

        console.log(`  why not covered`)
        for (const r of seg.reasons) {
          if (r.captures === 0) continue
          console.log(
            `    ${r.reason.padEnd(18)} ${formatRateWithCI(r.captureRate.successes, r.captureRate.n)}`
          )
        }

        console.log(`  modules reachable  (over the ${seg.reachabilityAnalysed} captures with a readable entry point)`)
        if (seg.reachabilityAnalysed === 0) {
          console.log(`    none could be followed`)
        } else {
          for (const m of seg.modules.slice(0, 12)) {
            console.log(`    ${m.module.padEnd(24)} ${formatRateWithCI(m.rate.successes, m.rate.n)}`)
          }
          console.log(`    ${seg.lostTrails} lost trails across the segment`)
        }
      }

      console.log(
        `\nWHAT THIS CANNOT SAY\n` +
        `  Descriptive. A rate that separates two populations is a fact about the\n` +
        `  populations, not a classifier: nothing here decides that a segment is\n` +
        `  malicious and nothing scores.\n` +
        `  The segments overlap on purpose — the confirmed captures are also\n` +
        `  quarantine captures — so their columns are not a partition.\n` +
        `  NEITHER SEGMENT IS THE BACKGROUND. quarantine-no-genome selects on "under\n` +
        `  100KB", and small is most of what makes a package readable;\n` +
        `  watcher-threshold selects on a high score, which is enriched for install\n` +
        `  scripts and native addons by construction. So this compares two filters\n` +
        `  against each other, not a class against the publish stream. Measuring\n` +
        `  that needs an unselected sample, and the corpus holds none: everything\n` +
        `  in it is here because a filter kept it.\n` +
        `  Any legibility gap is therefore partly the two selections reading\n` +
        `  themselves back, and how much cannot be established from this corpus.\n` +
        `  THE BYTE LOSS IS NOT SYMMETRIC. Captures taken before the object store\n` +
        `  existed kept their tarballs inline and survived the wipe, and they are\n` +
        `  disproportionately watcher-threshold. Unrestricted, the survivors of the\n` +
        `  two segments come from different weeks, so the comparison is partly a\n` +
        `  comparison of the weeks. --since puts both on one window, and the\n` +
        `  survivors-by-day line above is how to check that it worked.\n` +
        `  Module rates count captures that reach a module at all, by any route.\n` +
        `  A native binary reaches whatever it likes and appears in none of them.\n`
      )

      if (!args.includes('--no-save')) {
        mkdirSync(outDir, { recursive: true })
        const path = `${outDir}/by-class-${new Date().toISOString().slice(0, 10)}-v${report.engineVersion}.json`
        write(path, JSON.stringify(report, null, 2))
        console.log(`Saved to ${path}\n`)
      }
      return
    }

    // The derivation mode. It writes the raw per-file metrics so the threshold
    // in analyzability.ts can be traced to a run instead of to a preference.
    if (args.includes('--metrics')) {
      const rows = collectMetrics({
        sample: sample ?? 500,
        onProgress: (d, t) => { if (d % 50 === 0) process.stderr.write(`  ${d}/${t}\n`) },
      })
      mkdirSync(outDir, { recursive: true })
      const path = `${outDir}/metrics-${new Date().toISOString().slice(0, 10)}.json`
      write(path, JSON.stringify(rows))
      console.log(`${rows.length} parsed files, ${rows.filter(r => r.selfLabelledMinified).length} self-labelled minified`)
      console.log(`written to ${path}`)
      console.log(`\nAgainst the threshold currently in analyzability.ts:`)
      const check = checkThreshold(rows, MINIFIED_THRESHOLD)
      console.log(`  caught ${check.truePositiveRate === null ? 'n/a' : pct(check.truePositiveRate)} of the self-labelled minified files`)
      console.log(`  fired on ${check.falsePositiveRate === null ? 'n/a' : pct(check.falsePositiveRate)} of the rest (an upper bound: some of those are minified and simply unlabelled)`)
      return
    }

    // One capture, with its file list. The aggregate cannot say why a particular
    // package came out at 0%.
    const one = args.find(a => a.startsWith('--capture='))?.split('=')[1]
    if (one) {
      const { loadCorpus } = await import('./corpus.js')
      const corpus = loadCorpus()
      const match = corpus.samples.find(s => s.package === one || s.ngpackPath === one)
      if (!match) {
        console.error(`No capture for ${one}`)
        process.exit(1)
      }
      const result = analyzeCapture(match, { threshold: MINIFIED_THRESHOLD, keepFiles: true })
      console.log(`\n${result.package}@${result.version}  ${result.ngpackPath}`)
      if (result.error) console.log(`  ${result.error}`)
      console.log(
        `  coverage ${result.coverage === null ? 'n/a (nothing executable)' : pct(result.coverage)}` +
        `  ${result.coveredFiles}/${result.executableFiles} files, ` +
        `${result.coveredBytes}/${result.executableBytes} bytes`
      )
      for (const f of result.files) {
        if (f.reasons.length === 0 && f.covered) continue
        if (f.reasons.length === 0) continue
        console.log(`    ${f.reasons.join(',').padEnd(28)} ${String(f.bytes).padStart(9)}  ${f.name}`)
      }
      return
    }

    const started = Date.now()
    const report = runCorpusAnalyzability({
      threshold: MINIFIED_THRESHOLD,
      sample,
      engineVersion: engineVersion(),
      onProgress: (d, t) => { if (d % 100 === 0) process.stderr.write(`  ${d}/${t}\n`) },
    })

    console.log(`\nANALYZABILITY  norte-guard v${report.engineVersion}`)
    console.log(`${report.analysed} captures in ${((Date.now() - started) / 1000).toFixed(0)}s` +
      (sample ? `  (sampled from the corpus, confirmed_malicious always included)` : ''))
    console.log(`  ${report.unreadable} unreadable, ${report.nothingExecutable} with nothing executable in them`)

    // Printed first and on its own, because it is not a coverage figure and it
    // is the largest fact about this corpus. Nothing reported it before: layer 1
    // reads the packument and never asks for the artifact, so a capture whose
    // bytes are gone looks identical to one that still has them.
    if (report.withoutBytes > 0) {
      const share = report.corpusTotal > 0 ? report.withoutBytes / report.corpusTotal : 0
      console.log(
        `\n  ${report.withoutBytes} of ${report.corpusTotal} uncontaminated captures (${pct(share)}) have NO TARBALL BYTES\n` +
        `  left on disk and were excluded before the pass began. They are a manifest and a\n` +
        `  packument with nothing behind them. Everything below is measured on the rest.`
      )
    }

    console.log(`\nCOVERAGE OF THE EXECUTABLE SURFACE`)
    console.log(`  by bytes                        ${report.byteCoverage === null ? 'n/a' : pct(report.byteCoverage)}`)
    console.log(`  median capture                  ${report.medianCaptureCoverage === null ? 'n/a' : pct(report.medianCaptureCoverage)}`)
    console.log(`  fully covered                   ${report.fullyCovered}`)
    console.log(`  nothing covered at all          ${report.fullyOpaque}`)
    console.log(`  distribution`)
    for (const b of report.distribution) {
      console.log(`    ${b.label.padEnd(10)} ${String(b.captures).padStart(6)}`)
    }

    console.log(`\nWHY THE REST IS NOT COVERED  (captures with at least one such file)`)
    for (const r of report.reasons) {
      if (r.captures === 0) continue
      console.log(
        `  ${r.reason.padEnd(18)} ${formatRateWithCI(r.captureRate.successes, r.captureRate.n).padEnd(44)}` +
        ` ${r.files} files, ${(r.bytes / 1e6).toFixed(1)} MB`
      )
    }
    console.log(
      `\n  A file carries every reason that applies, so these columns overlap and do\n` +
      `  not sum to the uncovered total.`
    )

    console.log(`\nSHIPS A BINARY, WASM, BYTECODE OR UNREADABLE MINIFIED CODE`)
    console.log(`  ${formatRateWithCI(report.shipsOpaqueExecutable.successes, report.shipsOpaqueExecutable.n)}`)

    console.log(`\nHELD OUT OF THE DENOMINATOR  (ships alongside what runs, is not what runs)`)
    for (const [kind, totals] of Object.entries(report.heldOut).sort(([, a], [, b]) => b!.bytes - a!.bytes)) {
      console.log(`  ${kind.padEnd(18)} ${String(totals!.files).padStart(7)} files  ${(totals!.bytes / 1e6).toFixed(1)} MB`)
    }

    console.log(`\nCONFIRMED_MALICIOUS`)
    if (report.confirmedTotal === 0) {
      console.log(`  none in the corpus`)
    } else {
      for (const c of report.confirmedMalicious) {
        console.log(
          `  ${`${c.package}@${c.version}`.padEnd(38)} ` +
          `${c.coverage === null ? 'nothing executable' : pct(c.coverage).padStart(7)}` +
          `  ${c.coveredFiles}/${c.executableFiles} files` +
          (c.error ? `  ${c.error}` : '') +
          (Object.keys(c.byReason).length > 0 ? `  [${Object.keys(c.byReason).join(', ')}]` : '')
        )
      }
      const analysable = report.confirmedMalicious.filter(c => (c.coverage ?? 0) >= 0.999).length
      // Both denominators on the same line. "1 of 2 fully analysable" is a
      // sentence somebody quotes, and six of the eight are not in the two.
      console.log(
        `\n  ${analysable} of ${report.confirmedMalicious.length} fully analysable` +
        (report.confirmedWithoutBytes > 0
          ? ` — but that is ${analysable} of ${report.confirmedTotal} confirmed samples in total.\n` +
            `  The other ${report.confirmedWithoutBytes} have no tarball bytes left, so nothing can be read from\n` +
            `  them at any coverage. This corpus can answer the question for ` +
            `${report.confirmedMalicious.length} of ${report.confirmedTotal}.`
          : '.')
      )
    }

    if (MINIFIED_THRESHOLD.bytesPerLine <= 0) {
      console.log(
        `\nNOTE: the minification threshold is unset, so no file is being marked minified.\n` +
        `Derive it with \`norte-guard analyzability --metrics\` and put the result in\n` +
        `analyzability.ts. Until then the "minified" row reads zero because nothing\n` +
        `looked, not because nothing is minified.`
      )
    }

    console.log(
      `\nWHAT THIS CANNOT SAY\n` +
      `  It measures reach, not risk. A fully covered package is one a parser could\n` +
      `  read end to end, which is not a statement that it is safe.\n` +
      `  The denominator is bytes that execute. A package is one 200MB binary and\n` +
      `  3,000 small scripts by turns, so the byte figure and the median capture\n` +
      `  figure disagree on purpose and neither replaces the other.\n` +
      `  Coverage is fail-closed: one eval() of a runtime-built string makes a whole\n` +
      `  file uncovered, because the parser cannot bound what the rest of it does.\n`
    )

    if (!args.includes('--no-save')) {
      mkdirSync(outDir, { recursive: true })
      const path = `${outDir}/${new Date().toISOString().slice(0, 10)}-v${report.engineVersion}.json`
      write(path, JSON.stringify(report, null, 2))
      console.log(`Saved to ${path}\n`)
    }
    return
  }

  if (command === 'scores') {
    const dir = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures'
    const { readFileSync, existsSync } = await import('node:fs')
    const { join } = await import('node:path')
    const { scoreDistribution, pct } = await import('./stats.js')

    const logPath = join(dir, 'changes-log.ndjson')
    if (!existsSync(logPath)) {
      console.error(`No changes-log.ndjson in ${dir}. Run \`norte-guard watch\` first.`)
      process.exit(1)
    }

    const rows = readFileSync(logPath, 'utf-8').trim().split('\n')
      .flatMap(line => { try { return [JSON.parse(line) as Record<string, unknown>] } catch { return [] } })
      .filter(r => typeof r['score'] === 'number')

    if (rows.length === 0) {
      console.error('The log holds no scored publications yet.')
      process.exit(1)
    }

    console.log(`\nScore distribution of the PUBLISH STREAM, n=${rows.length}`)
    console.log(`${dir}/changes-log.ndjson\n`)

    const groups: Array<[string, number[]]> = [
      ['no-genome', rows.filter(r => r['regime'] === 'no-genome').map(r => r['score'] as number)],
      ['genome', rows.filter(r => r['regime'] === 'genome').map(r => r['score'] as number)],
      ['todos', rows.map(r => r['score'] as number)],
    ]

    for (const [label, values] of groups) {
      const d = scoreDistribution(values)
      if (!d) { console.log(`  ${label.padEnd(11)} (no data)`); continue }
      console.log(
        `  ${label.padEnd(11)} n=${String(d.n).padStart(5)} p50=${String(d.p50).padStart(4)} ` +
        `p90=${String(d.p90).padStart(4)} p95=${String(d.p95).padStart(4)} ` +
        `p99=${String(d.p99).padStart(4)} max=${d.max}  (${d.distinct} valores distintos)`
      )
    }

    const all = rows.map(r => r['score'] as number)
    console.log('\nCost of each capture budget:')
    for (const t of [20, 25, 30, 35, 40, 44, 50, 60]) {
      const n = all.filter(s => s >= t).length
      console.log(
        `  ${String(t).padStart(3)}  ${String(n).padStart(5)}/${all.length}  ${pct(n / all.length, 2)}` +
        (t === 50 ? '   <- current budget' : '')
      )
    }

    // Whether quarantine is affordable is a question about how common the class
    // is, not about how long things are kept. At 5% any retention works; at 40%
    // none does.
    const withClass = rows.filter(r => r['class'])
    if (withClass.length > 0) {
      const marker = (key: string) => withClass.filter(r => (r['class'] as Record<string, unknown>)[key]).length
      const inClass = marker('inClass')

      console.log(`\nPrevalence of the observed class, n=${withClass.length} publications`)
      console.log(`  no-genome, <7 days, <100KB, no repo   ${inClass}  ${pct(inClass / withClass.length, 2)}`)
      console.log(`  ${'name under 7 days old'.padEnd(38)} ${marker('young')}  ${pct(marker('young') / withClass.length, 2)}`)
      console.log(`  ${'under 100KB'.padEnd(38)} ${marker('tiny')}  ${pct(marker('tiny') / withClass.length, 2)}`)
      console.log(`  ${'no repository'.padEnd(38)} ${withClass.length - marker('repo')}  ${pct((withClass.length - marker('repo')) / withClass.length, 2)}`)
      console.log(
        `\n  ${inClass / withClass.length < 0.1
          ? 'Below 10%: quarantine is sustainable.'
          : 'Above 10%: no retention holds, the class has to be narrowed.'}`
      )
    }

    console.log(
      `\nThis is cost, not detection. The capture budget decides how much disk and\n` +
      `bandwidth the collector spends; it does not decide what gets detected. That\n` +
      `is the gate/audit thresholds in types.ts, calibrated against fp-bench.\n` +
      `\n` +
      `And it is not derived from these percentiles. That would be circular: a\n` +
      `campaign in progress raises the stream's scores, raises the percentile, and\n` +
      `relaxes the collector on the day it matters most. The budget is a fixed\n` +
      `number chosen for what it costs.\n`
    )
    return
  }

  // Re-reads the registry for every captured package and labels the ones npm has
  // taken down since. The label comes from today's registry; the sample stays the
  // packument captured before it, which is what keeps the two apart.
  if (command === 'sweep-takedowns') {
    const { loadCorpus } = await import('./corpus.js')
    const { detectTakedown, takedownLabelSource, isUsableRecallSample } = await import('./takedown.js')
    const { fetchPackument } = await import('./packument.js')
    const { labelCapture } = await import('./ngpack.js')

    const dryRun = args.includes('--dry-run')
    const corpus = loadCorpus()
    const samples = corpus.samples

    // Every package the collector ever scored, with the version it saw at the
    // time, read from the delta snapshots. Without this the sweep only sees the
    // 400 captures and misses the thousands of publications that were observed
    // and not kept.
    if (args.includes('--include-observed')) {
      const { sweepObserved } = await import('./takedown-sweep.js')
      await sweepObserved(args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures')
      return
    }

    console.log(`\nRevisando ${samples.length} capturas contra el registro actual...`)
    if (dryRun) console.log('[dry-run] no se escribe ninguna etiqueta\n')

    let checked = 0, unreachable = 0
    const takenDown: string[] = []
    const usable: string[] = []
    const holderOnly: string[] = []

    const limit = 6
    let next = 0
    await Promise.all(Array.from({ length: limit }, async () => {
      for (;;) {
        const i = next++
        if (i >= samples.length) return
        const sample = samples[i]!

        let current
        try {
          current = await fetchPackument(sample.package)
        } catch {
          unreachable++
          continue
        }

        checked++
        if (checked % 50 === 0) console.log(`  ${checked}/${samples.length}...`)

        const verdict = detectTakedown(current, sample.version)
        if (!verdict.takenDown) continue

        takenDown.push(`${sample.package}@${sample.version}`)

        if (isUsableRecallSample(verdict)) {
          usable.push(`${sample.package}@${sample.version}`)
          if (!dryRun) {
            try {
              labelCapture(sample.ngpackPath, 'confirmed_malicious', takedownLabelSource(verdict))
            } catch (e) {
              console.error(`  no se pudo etiquetar ${sample.package}: ${e}`)
            }
          }
        } else {
          // The capture holds npm's placeholder, not the artifact. Real takedown,
          // but nothing detection could ever have been asked about.
          holderOnly.push(`${sample.package}@${sample.version}`)
        }
      }
    }))

    console.log(`\n${checked} checked, ${unreachable} unreachable`)
    console.log(`${takenDown.length} packages removed by npm`)
    console.log(`  ${usable.length} with the artifact captured (recall samples)`)
    console.log(`  ${holderOnly.length} where the capture is the marker itself (label only)`)

    for (const p of usable) console.log(`  [sample] ${p}`)
    if (holderOnly.length > 0) {
      console.log(`\nMarker only, no artifact, excluded from recall:`)
      for (const p of holderOnly) console.log(`  ${p}`)
    }

    console.log(
      `\n${dryRun ? '[dry-run] ' : ''}A takedown is a LABEL, never a signal. It does not reach the\n` +
      `scorer: it happens after the fact, and detecting with it would make the\n` +
      `benchmark circular.\n`
    )
    return
  }

  // Phase 0: the collector has to survive. A day's spend from a policy that no
  // longer exists would switch it off exactly when the new one starts to matter.
  if (command === 'budget') {
    const dir = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures'
    const { DailyCaptureBudget, consolidateDeltas, formatBytes, DEFAULT_DAILY_BYTES } =
      await import('./capture-budget.js')
    const { join } = await import('node:path')

    const budget = new DailyCaptureBudget(dir, DEFAULT_DAILY_BYTES)

    if (args.includes('--consolidate-deltas')) {
      const dryRun = args.includes('--dry-run')
      const result = consolidateDeltas(
        join(dir, 'deltas'), undefined, dryRun, args.includes('--include-today')
      )

      for (const d of result.days) {
        console.log(
          `  ${d.day}: ${d.files} files -> 1 (${formatBytes(d.bytes)} -> ${formatBytes(d.compressed)})`
        )
      }
      console.log(
        `\n${dryRun ? '[dry-run] ' : ''}${result.days.reduce((a, d) => a + d.files, 0)} files consolidated ` +
        `across ${result.days.length} days${result.skipped > 0 ? ` - ${result.skipped} skipped` : ''}`
      )
      return
    }

    if (args.includes('--reset')) {
      const reason = args.find(a => a.startsWith('--reason='))?.slice('--reason='.length)
      if (!reason) {
        console.error('Usage: norte-guard budget --reset --reason="why"')
        console.error('The budget exists to stop the collector. Resetting it is justified or not done.')
        process.exit(1)
      }

      const previous = budget.reset(reason)
      console.log(
        `Daily budget reset: ${formatBytes(previous.previousBytes)} across ` +
        `${previous.previousCaptures} captures -> 0`
      )
      console.log(`Reason recorded in ${dir}/budget-log.ndjson: ${reason}`)
      return
    }

    console.log(`\nDaily budget: ${formatBytes(budget.spent)} of ${formatBytes(budget.dailyBytes)}`)
    console.log(`Captures today: ${budget.captures} - skipped over cap: ${budget.skipped}`)
    console.log(`Remaining: ${formatBytes(budget.remaining)}\n`)
    return
  }

  // Phase 1.3 / 2.1: the tracking IS the experiment. Running it every 24h for
  // 30 days turns unconfirmed blocks into labels with no manual work.
  if (command === 'track') {
    const dir = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './norte-guard-captures'
    const wl = await import('./watchlist.js')
    const { fetchWeeklyDownloads } = await import('./downloads.js')
    const { fetchPackument } = await import('./packument.js')
    const { NPM_SECURITY_HOLDER } = await import('./takedown.js')
    const { readFileSync, existsSync } = await import('node:fs')
    const { join } = await import('node:path')

    // Seeds the watchlist from the packages the rule would have blocked, which
    // are recorded on every publication whether or not the rule is switched on.
    if (args.includes('--seed-from-log')) {
      const logPath = join(dir, 'changes-log.ndjson')
      if (!existsSync(logPath)) {
        console.error(`No changes-log.ndjson in ${dir}`)
        process.exit(1)
      }

      const candidates = new Map<string, WatchedPackage>()
      for (const line of readFileSync(logPath, 'utf-8').split('\n')) {
        if (!line) continue
        try {
          const row = JSON.parse(line) as Record<string, any>
          if (!row.class?.inClass) continue
          candidates.set(row.package, {
            package: row.package,
            version: row.version ?? 'observed',
            addedAt: row.seenAt ?? new Date().toISOString(),
            reason: 'fabricated-profile: class observed in the stream',
            observedScore: row.score,
          })
        } catch { /* skip */ }
      }

      const added = wl.addToWatchlist(dir, [...candidates.values()])
      console.log(`${added} added to the watchlist (${candidates.size} candidates, the rest were already there)`)
      return
    }

    // A prediction registered before the outcome exists. The watchlist is
    // already this for names the rule flagged automatically; this is the same
    // record made by hand, for a package suspected on grounds the rule does not
    // encode — belonging to a family whose other members were removed, say.
    //
    // The value is entirely in the timestamp. Saying afterwards that a takedown
    // was expected costs nothing and proves nothing; a dated entry that predates
    // the removal is a claim that could have been wrong.
    const addArg = args.find(a => a.startsWith('--add='))?.slice('--add='.length)
    if (addArg) {
      const reason = args.find(a => a.startsWith('--reason='))?.slice('--reason='.length)
      if (!reason) {
        console.error('Usage: norte-guard track --add=<pkg>[@<version>] --reason="why you expect this to resolve"')
        console.error('A prediction with no stated grounds cannot be scored later.')
        process.exit(1)
      }

      const { name, version } = parsePackageSpec(addArg)
      const at = new Date().toISOString()
      const added = wl.addToWatchlist(dir, [{
        package: name,
        version: version ?? 'observed',
        addedAt: at,
        reason: `prediction: ${reason}`,
      }])

      if (added === 0) {
        console.log(`${name}@${version ?? 'observed'} was already on the watchlist; the original date stands.`)
      } else {
        console.log(`Registered ${name}@${version ?? 'observed'} at ${at}`)
        console.log(`  ${reason}`)
        console.log(`\n  It resolves on its own: npm removing it is a confirmed takedown, and`)
        console.log(`  ${wl.VERDICT_AFTER_DAYS} days alive with >=${wl.REAL_USAGE_DOWNLOADS} weekly downloads is a confirmed false positive.`)
      }
      return
    }

    const list = wl.loadWatchlist(dir)
    if (list.length === 0) {
      console.error('Watchlist is empty. Seed it with: norte-guard track --seed-from-log')
      process.exit(1)
    }

    if (!args.includes('--no-check')) {
      console.log(`Querying the registry for ${list.length} watched packages...\n`)
      for (const entry of list) {
        let exists = true, takenDown = false
        try {
          const p = await fetchPackument(entry.package)
          takenDown = NPM_SECURITY_HOLDER in p.versions
        } catch {
          exists = false
        }
        const downloads = exists ? await fetchWeeklyDownloads(entry.package) : null
        wl.appendObservation(dir, {
          package: entry.package,
          checkedAt: new Date().toISOString(),
          exists, takenDown, weeklyDownloads: downloads,
        })
      }
    }

    const observations = wl.readObservations(dir)
    const tracked = list.map(e => wl.verdictFor(e, observations))

    // Quarantine reached the same kind of verdict without waiting: captures that
    // matched the four free conditions at publication and that npm has since
    // removed. Same class, same authority, already settled.
    const { loadCorpus } = await import('./corpus.js')
    const corpus = loadCorpus([join(dir, 'captures')])
    const fromCaptures = wl.verdictsFromCaptures(
      corpus.samples.map(s => ({
        package: s.package,
        version: s.version,
        capturedAt: s.capturedAt,
        label: s.label,
        labelSource: s.labelSource,
        captureReason: s.captureReason,
        // The fifth conjunct, or the fact that it was never recorded. Without it
        // a removal confirms the capture filter and says nothing about the rule.
        // The window travels with the count: a zero over a week that closed
        // before the name existed is the same zero on disk and not the same
        // fact.
        weeklyDownloads: s.weeklyDownloads,
        downloadWindowCovers: s.downloadWindowCovers,
        contaminated: s.contaminated,
      }))
    )

    // Deduplicated across the two sources. The watchlist is seeded from
    // class.inClass in the changes log, which is the same set quarantine
    // captures, so a package npm removed can arrive here twice — once as a
    // tracked verdict and once as a capture — and the criterion that lets a
    // build-failing rule default on must count removals, not records of them.
    const trackedPackages = new Set(tracked.map(v => v.package))
    const verdicts = [...tracked, ...fromCaptures.filter(v => !trackedPackages.has(v.package))]

    const mark = (s: string) => s === 'confirmed-takedown' ? '[takedown]'
                              : s === 'confirmed-false-positive' ? '[false-pos]'
                              : s === 'vanished' ? '[vanished] ' : '[pending]  '

    console.log('TRACKING')
    for (const v of tracked) {
      console.log(`  ${mark(v.status)} ${v.package.padEnd(38)} ${v.status.padEnd(26)} ${v.detail}`)
    }

    if (fromCaptures.length > 0) {
      console.log('\nCONFIRMED THROUGH QUARANTINE')
      for (const v of fromCaptures) {
        console.log(`  ${mark(v.status)} ${v.package.padEnd(38)} ${v.status.padEnd(26)} ${v.detail}`)
      }
    }

    const assessment = wl.assessPromotion(verdicts)

    // The two criteria, side by side and named, because they were being read as
    // one. The capture filter is what selected everything above; the rule is
    // what would fail somebody's build.
    console.log('\nWHICH CRITERION THE EVIDENCE BELONGS TO')
    console.log(
      `  capture filter (4 conditions)     ${assessment.confirmedTakedowns} removals confirmed by npm`
    )
    console.log(
      `  fabricated-profile rule (5)       ${assessment.verifiedTakedowns} removals of packages the rule itself would have blocked`
    )
    if (assessment.unverifiableTakedowns > 0) {
      console.log(
        `  ${assessment.unverifiableTakedowns} of those removals can never be attributed to the rule: their snapshots carry\n` +
        `  no weekly download count, and npm serves one complete week at a time.`
      )
    }
    console.log(
      `  false positives                   ${assessment.confirmedFalsePositives} confirmed, ` +
      `${assessment.emergingFalsePositives} already alive with >=${wl.REAL_USAGE_DOWNLOADS} weekly downloads ` +
      `before ${wl.VERDICT_AFTER_DAYS} days`
    )

    // Whether the gap is closing or standing still. The criterion can only ever
    // be met by captures taken from here on, so a collector that is not
    // recording the count is not accumulating evidence — it is accumulating
    // captures that will be as unverifiable in a month as they are today.
    const inClass = corpus.samples.filter(s => s.captureReason === wl.QUARANTINE_CAPTURE_REASON)
    const withCount = inClass.filter(s => s.weeklyDownloads !== undefined).length
    const newest = inClass.map(s => s.capturedAt).sort().pop()
    if (inClass.length > 0 && withCount === 0) {
      console.log(
        `\nTHE EVIDENCE GAP IS NOT CLOSING: 0 of ${inClass.length} quarantine captures carry a download\n` +
        `count, including the most recent (${newest?.slice(0, 19) ?? 'unknown'}). The collector records it only if it is\n` +
        `running a build that includes that code. Restart the watcher, then check this line again:\n` +
        `until it moves, every new capture is another record the rule can never be tested against.`
      )
    } else if (inClass.length > 0) {
      console.log(
        `\n${withCount} of ${inClass.length} quarantine captures carry a download count and can be re-judged by the rule.`
      )
    }

    console.log(`\n${assessment.statement}`)

    const review = wl.scheduledReview(
      corpus.samples.length,
      corpus.confirmedMalicious.length + tracked.filter(v => v.status === 'confirmed-takedown').length
    )
    console.log(`\n${review.verdict}`)
    console.log(
      `\nThe criterion lives in watchlist.ts, not in anyone's head: ` +
      `>=${wl.PROMOTION_MIN_TAKEDOWNS} removals the rule\nitself would have caused, and ` +
      `<=${wl.PROMOTION_MAX_FALSE_POSITIVES} false positives counting the ones already visible\n` +
      `but not yet ${wl.VERDICT_AFTER_DAYS} days old.\n`
    )
    return
  }

  if (command === 'label') {
    const dir = args[1]
    const label = args.find(a => a.startsWith('--label='))?.split('=')[1]
    const source = args.find(a => a.startsWith('--source='))?.slice('--source='.length)
    const notes = args.find(a => a.startsWith('--notes='))?.slice('--notes='.length)

    if (!dir || !label) {
      console.error('Usage: norte-guard label <capture-dir> --label=<confirmed_malicious|confirmed_benign|unconfirmed> --source="<advisory/report/analysis>"')
      process.exit(1)
    }

    if (label !== 'confirmed_malicious' && label !== 'confirmed_benign' && label !== 'unconfirmed') {
      console.error(`Unknown label: ${label}`)
      process.exit(1)
    }

    try {
      const { labelCapture } = await import('./ngpack.js')
      const meta = labelCapture(dir, label, source ?? '', notes)
      console.log(`labeled ${meta.package}@${meta.version}: ${meta.label} (${meta.labelSource})`)
    } catch (e) {
      console.error(`Error: ${e instanceof Error ? e.message : e}`)
      process.exit(1)
    }
    return
  }

  if (command === 'watch') {
    const { DEFAULT_CAPTURE_BUDGET } = await import('./watcher.js')
    const output = args.find(a => a.startsWith('--output='))?.split('=')[1] ?? './captures'

    // --threshold stays accepted so existing invocations keep working, but the
    // name is wrong: reading a capture budget as a detection threshold is what
    // made deriving it from the stream look reasonable.
    // Per regime, because the two score on different scales. A single number
    // still works and applies to both.
    const budgetArg = args.find(a => a.startsWith('--capture-budget='))?.split('=')[1]
                   ?? args.find(a => a.startsWith('--threshold='))?.split('=')[1]
    const noGenomeArg = args.find(a => a.startsWith('--capture-budget-no-genome='))?.split('=')[1]

    const captureBudget = budgetArg !== undefined
      ? { genome: parseInt(budgetArg), noGenome: parseInt(noGenomeArg ?? budgetArg) }
      : { ...DEFAULT_CAPTURE_BUDGET, ...(noGenomeArg ? { noGenome: parseInt(noGenomeArg) } : {}) }

    const gb = (flag: string) => {
      const raw = args.find(a => a.startsWith(`--${flag}=`))?.split('=')[1]
      return raw === undefined ? undefined : Math.round(parseFloat(raw) * 1024 ** 3)
    }
    const lagRaw = args.find(a => a.startsWith('--lag-alert='))?.split('=')[1]
    const feed = args.find(a => a.startsWith('--feed='))?.split('=')[1] === 'rss' ? 'rss' as const : 'changes' as const
    const agreed = args.includes('--i-understand-the-risks')

    if (!agreed) {
      const { printMalwareWarning } = await import('./watcher.js')
      printMalwareWarning()
      process.exit(1)
    }

    const { startWatcher } = await import('./watcher.js')
    await startWatcher({
      outputDir: output,
      captureBudgetThreshold: captureBudget,
      verbose: false,
      feed,
      dailyByteBudget: gb('daily-gb'),
      maxCaptureBytes: gb('max-gb'),
      lagAlertThreshold: lagRaw !== undefined ? parseInt(lagRaw) : undefined,
      quarantine: {
        enabled: !args.includes('--no-quarantine'),
        ...(args.find(a => a.startsWith('--quarantine-days='))
          ? { retentionDays: parseInt(args.find(a => a.startsWith('--quarantine-days='))!.split('=')[1]!) }
          : {}),
      },
    })
    return
  }

  console.error(`Unknown command: ${command}`)
  printHelp()
  process.exit(1)
}

function printHelp(): void {
  console.log(`
norte-guard - the npm quarantine copilot

Covers the attack that arrives on its own: a package you already depend on,
hijacked. It does not cover a new malicious package you have to add yourself.

COMMANDS
  inspect <pkg>[@version]   Analyse a package
  approve                   Classify packages with install scripts (npm 12)
  approve <pkg> --reason=   Approve one package, including a blocked one
  bench                     Run the public benchmark
  corpus                    List captures, labels and composition
  analyzability             How much of the corpus can be looked at at all
  reachability              What one capture can reach, and by what route
  scores                    Score distribution of the publish stream
  track                     Follow watched packages until they resolve
  track --add=<pkg>         Register a prediction, dated, before it resolves
  label <dir>               Label a capture (an external source is required)
  budget                    Show, reset or consolidate collector storage
  sweep-takedowns           Ask the registry which observed packages npm removed
  watch                     Monitor the registry and capture suspicious packages

OPTIONS
  --mode=gate       CI gate: high precision, few false positives (default)
  --mode=audit      Forensic: higher recall, false positives acceptable
  --json            JSON output
  --offline         bench without network: local .ngpack corpus only

  analyzability
      Measures reach, not risk, and detects nothing. Of the bytes in a capture
      that can execute, what fraction could a conforming JavaScript parser read
      and follow — and for the rest, which of parse failure, eval of a
      runtime-built string, unresolvable require, native binary, WASM, bytecode
      or minification put it out of reach. Fail closed: one eval makes a whole
      file uncovered, because the parser cannot bound what the rest of it does.
      Offline, over the .ngpack captures already on disk.

      --sample=<n>         analyse n captures instead of all of them. The
                           confirmed_malicious ones are always included.
      --by-class           cut the corpus by captureReason and compare the
                           distributions, with reachable modules per segment.
                           Descriptive: it classifies nothing — and it cannot
                           answer whether the class is unusual, because the
                           class is DEFINED as under 100KB and binaries, WASM
                           and bundles do not fit in 100KB. Use --size-control
                           for that.
      --since=<YYYY-MM-DD> restrict every segment to one date window. The byte
                           loss hit the segments unevenly, so an unrestricted
                           comparison is partly a comparison of dates.
      --size-control       the comparison --by-class cannot make: every group
                           under 100KB, in one window, matched to the class's
                           size distribution decile by decile, and differing
                           from the class in ONE conjunct of its definition.
                           Needs --since.
      --draw=<n>           packages to draw per cell from changes-log.ndjson
                           and fetch from npm (--size-control only). 0, the
                           default, does no network and leaves only the on-disk
                           comparison, which is not size-matched.
      --until=<ISO>        the far end of the window, so a run can be repeated
                           against the same members later
      --capture=<pkg>      one capture, with the per-file reasons
      --metrics            re-derive the minification threshold: writes every
                           per-file metric and checks the current cut against
                           the files that label themselves
      --results-dir=<d>    where the artifact lands (default analyzability-results)
      --no-save            print without writing an artifact
  --output=<dir>    Capture directory (default: ./captures)

  --source=<path>   inspect an .ngpack instead of the registry. Takes either one
                    capture directory or the captures/ root, which is searched
                    for the package. The only way to look at a version npm has
                    purged, which is most of the ones worth looking at. Ages are
                    measured from the capture time, so the verdict is the one
                    that would have been issued then.

  --feed=changes    watch through the _changes cursor, not a window (default)
  --feed=rss        watch through RSS: a 50-entry window that loses publications

  --strict-new-packages
      Treat INSUFFICIENT_HISTORY as a failure (exit 1). By default it does not
      fail the build: lack of context is not evidence of risk, and a gate that
      stops one build in five gets switched off.

  --block-fabricated-profile
      Block the conjunction: no genome, name under 7 days old, under 100KB, no
      repository, zero downloads. OPT-IN. It was on by default between
      2026-08-14 and 2026-08-16, on three things that each looked like a
      measurement: removals that were selected by the capture filter and not by
      this rule, a zero false-positive count that was the 30-day clock rather
      than the rule, and a 0-of-500 from a download-ranked sample that cannot
      contain a package this rule could fire on. See types.ts, and
      norte-guard track for where the criterion currently stands.

  --no-block-fabricated-profile
      Accepted so invocations written while it was on by default keep working.
      The rule blocks a package the developer asked for by name, so refusing it
      is a legitimate policy; approving one package with
      norte-guard approve <pkg> --reason= is the narrower alternative.

  --capture-budget=<n>
      How much disk the collector spends, not what it detects (default: 50).
      A capture budget, NEVER derived from the stream: a campaign in progress
      would raise the percentiles and relax the collector on the day it matters
      most. --threshold=<n> is still accepted as the old name.

  --daily-gb=<n>    Hard download cap per UTC day (default: 2)
  --max-gb=<n>      Size of captures/ before the oldest rotate out (default: 10)
                    Rotation never deletes a labelled capture.
  --lag-alert=<n>   Cursor lag in seq that raises an alert (default: 150)

EXAMPLES
  norte-guard inspect keyv@6.0.0
  norte-guard inspect keyv@6.0.0 --json | jq .verdict
  norte-guard inspect async-critical-section@1.0.0 --block-fabricated-profile \\
    --source=./norte-guard-captures/captures
  norte-guard approve some-package --reason="internal, we publish it"
  norte-guard bench
  norte-guard corpus
  norte-guard track

The genome is reproducible. We do not ask for trust; we make it unnecessary.
MIT License - Norte Software <hola@nortesoftware.dev>
`)
}

main().catch(e => {
  console.error(e)
  process.exit(2)
})
