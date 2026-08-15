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

    // On by default since four confirmed removals and zero false positives; see
    // types.ts for the evidence. --block-fabricated-profile is kept because
    // existing invocations pass it, and it now asks for what it already gets.
    const config = {
      ...DEFAULT_THRESHOLDS[mode],
      blockFabricatedProfile: !args.includes('--no-block-fabricated-profile'),
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
    console.log(`\n${assessment.statement}`)

    const review = wl.scheduledReview(
      corpus.samples.length,
      corpus.confirmedMalicious.length + tracked.filter(v => v.status === 'confirmed-takedown').length
    )
    console.log(`\n${review.verdict}`)
    console.log(
      `\nThe criterion lives in watchlist.ts, not in anyone's head: ` +
      `>=${wl.PROMOTION_MIN_TAKEDOWNS} removals and <=${wl.PROMOTION_MAX_FALSE_POSITIVES} false positives.\n`
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
      repository, zero downloads. ON BY DEFAULT since 2026-08-14 — this flag is
      accepted so existing invocations keep working and now asks for what it
      already gets. Four packages matching it were removed by npm within seven
      hours of publication, no confirmed false positives, and 0 of 500 in
      fp-bench's download-ranked sample can match it.

  --no-block-fabricated-profile
      Turn it back off. The rule blocks a package the developer asked for by
      name, so refusing it is a legitimate policy; approving one package with
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
