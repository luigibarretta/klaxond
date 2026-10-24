#!/usr/bin/env node
// Local CI gate: runs the repository's declared CI steps in order, fail fast,
// with the same entry point locally (dev-01 guards on) and in CI (--ci).
import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { loadManifest, locateManifest } from './ci-local-manifest.mjs'
import { OutputCapture, killActiveChild, lockWrapperProblem, pressureVerdict, substituteEnv } from './ci-local-process.mjs'
import { listJson, selectSteps } from './ci-local-select.mjs'
import { describeStep, executeStep, validateBuiltins } from './ci-local-steps.mjs'

const USAGE = `usage: ci-local [--ci] [--quick] [--only a,b] [--from step] [--no-needs] [--list [--json]]
                [--manifest path] [--log path] [--verbose]`
const EXIT = { ok: 0, failed: 1, usage: 2, blocked: 3, interrupted: 130 }
// Under --ci the dev-01 build-lock wrapper must never wait for CI from inside CI.
const CI_FORCED_ENV = { DEV_IGNORE_CI: '1', QUADRO_IGNORE_CI: '1' }
let interrupted = false

main().then((code) => {
  process.exitCode = code
})

async function main() {
  let options
  try {
    options = parseArguments(process.argv.slice(2))
  } catch (error) {
    process.stderr.write(`ci-local: ${error.message}\n${USAGE}\n`)
    return EXIT.usage
  }
  if (options.help) {
    say(USAGE)
    return EXIT.ok
  }
  const root = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
  let manifestPath, manifest, selection
  try {
    manifestPath = locateManifest(root, options.manifest)
    manifest = loadManifest(manifestPath, validateBuiltins)
    selection = selectSteps(manifest.steps, options)
  } catch (error) {
    process.stderr.write(`ci-local: ${error.message}\n`)
    return EXIT.usage
  }
  if (options.list) return listSteps(manifest, selection.steps, options)
  for (const warning of manifest.warnings) process.stderr.write(`ci-local: manifest warning: ${warning}\n`)
  for (const added of selection.added) say(`ci-local: added needed step ${added.name} (needed by ${added.by}); use --no-needs to skip`)
  return runSteps({ root, manifest, manifestPath, steps: selection.steps, options })
}

function parseArguments(argv) {
  const options = { ci: false, quick: false, only: null, from: null, list: false, json: false, needs: true, verbose: false, help: false }
  const valued = { '--only': 'only', '--from': 'from', '--manifest': 'manifest', '--log': 'log' }
  const flags = { '--ci': 'ci', '--quick': 'quick', '--list': 'list', '--json': 'json', '--verbose': 'verbose', '--help': 'help', '-h': 'help' }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const [flag, inline] = argument.includes('=') ? argument.split(/=(.*)/s) : [argument, undefined]
    if (valued[flag]) {
      const value = inline ?? argv[++index]
      if (!value) throw new Error(`${flag} requires a value`)
      options[valued[flag]] = value
    } else if (flags[argument]) {
      options[flags[argument]] = true
    } else if (argument === '--no-needs') {
      options.needs = false
    } else {
      throw new Error(`unknown argument: ${argument}`)
    }
  }
  if (options.json && !options.list) throw new Error('--json requires --list')
  if (options.only) options.only = options.only.split(',').map((name) => name.trim()).filter(Boolean)
  return options
}

function listSteps(manifest, selected, options) {
  if (options.json) {
    say(JSON.stringify(listJson(manifest, selected), null, 2))
    return EXIT.ok
  }
  const chosen = new Set(selected)
  for (const step of manifest.steps) {
    const flags = [step.quick ? 'quick' : '', step.heavy ? 'heavy' : ''].filter(Boolean).join(',') || '-'
    const mark = chosen.has(step) ? '*' : ' '
    const extras = [
      step.needs.length ? `needs ${step.needs.join(',')}` : '',
      step.fixtures.length ? `fixtures ${step.fixtures.join(',')}` : '',
    ].filter(Boolean).join('; ')
    say(`${mark} ${step.name.padEnd(24)} ${flags.padEnd(11)} ${String(step.timeoutS).padStart(5)}s  ${describeStep(step)}${extras ? `  [${extras}]` : ''}`)
  }
  return EXIT.ok
}

function logPathFor(root, manifest, options) {
  const configured = options.log || process.env.CI_LOCAL_LOG || manifest.log
  if (!configured) return join(process.env.TMPDIR || tmpdir(), `ci-local-${basename(root)}.log`)
  return isAbsolute(configured) ? configured : resolve(root, configured)
}

async function runSteps({ root, manifest, manifestPath, steps, options }) {
  const logPath = logPathFor(root, manifest, options)
  mkdirSync(dirname(logPath), { recursive: true })
  const mode = options.ci ? 'ci' : 'local'
  writeFileSync(logPath, `ci-local ${new Date().toISOString()} mode=${mode} manifest=${relative(root, manifestPath)}\n`)
  for (const warning of manifest.warnings) appendFileSync(logPath, `manifest warning: ${warning}\n`)
  say(`ci-local: ${steps.length} step(s) from ${relative(root, manifestPath)} (mode: ${mode}, log: ${logPath})`)
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      interrupted = true
      killActiveChild()
    })
  }
  const run = {
    root, manifest, options, logPath, stream: options.ci || options.verbose,
    baseEnv: { ...process.env, ...substituteEnv(manifest.defaults.env, root) },
    forcedEnv: { CI_LOCAL_ROOT: root, REPO_TOOLING_ROOT: root, ...(options.ci ? CI_FORCED_ENV : {}) },
  }
  const results = []
  let exitCode = EXIT.ok
  for (const [index, step] of steps.entries()) {
    const result = await runGuardedStep(step, { ...run, label: `[${index + 1}/${steps.length}]` })
    results.push({ step, ...result })
    if (result.status !== 'ok') {
      exitCode = interrupted ? EXIT.interrupted : result.status === 'blocked' ? EXIT.blocked : EXIT.failed
      break
    }
  }
  for (const step of steps.slice(results.length)) results.push({ step, status: 'not-run' })
  writeSummary(results, logPath, exitCode)
  return exitCode
}

async function runGuardedStep(step, run) {
  const blocked = hostGuard(step, run)
  if (blocked) {
    say(`${run.label} ${step.name}: BLOCKED ${blocked}`)
    appendFileSync(run.logPath, `\n== ${step.name}: BLOCKED ${blocked}\n`)
    return { status: 'blocked', detail: blocked, durationMs: 0 }
  }
  // The full output is captured (head + tail bounded); failure excerpts come
  // from this capture, never from a filtered stream.
  const capture = new OutputCapture(run.manifest.logMaxKbPerStep * 1024)
  if (run.stream) say(`== ${run.label} ${step.name}: ${describeStep(step)}`)
  const output = (text) => {
    capture.append(text)
    if (run.stream) process.stdout.write(text)
  }
  const started = Date.now()
  const result = await executeStep(step, {
    root: run.root, ci: run.options.ci, output, say, allSteps: run.manifest.steps, fixtures: run.manifest.fixtures,
    baseEnv: run.baseEnv, forcedEnv: run.forcedEnv, isInterrupted: () => interrupted,
    log: (text) => appendFileSync(run.logPath, text),
  })
  if (interrupted && result.status !== 'ok') Object.assign(result, { status: 'interrupted', detail: 'interrupted' })
  const durationMs = Date.now() - started
  const verdict = `${result.status === 'ok' ? 'ok' : result.status.toUpperCase()}${result.detail ? ` (${result.detail})` : ''}`
  const notices = result.notices ?? []
  appendFileSync(run.logPath, `\n== ${step.name}: ${describeStep(step)}\n${capture.text()}\n` +
    notices.map((notice) => `notice: ${notice}\n`).join('') + `== ${step.name}: ${verdict} ${seconds(durationMs)}\n`)
  say(`${run.label} ${step.name.padEnd(24, '.')} ${verdict} ${seconds(durationMs)}`)
  for (const notice of notices) say(`    notice: ${notice}`)
  if (result.status !== 'ok' && !run.stream) say(indent(result.excerpt ?? capture.lastLines(40)))
  return { ...result, durationMs }
}

// dev-01 rules apply only to heavy steps outside CI: the runner never takes a
// lock itself; it refuses to start when the shared lock wrapper is bypassed or
// when the host is already under memory pressure.
function hostGuard(step, run) {
  if (run.options.ci || !step.heavy) return null
  const lockDir = process.env.CI_LOCAL_LOCK_BIN ?? join(process.env.HOME || '', '.local/dev-build-lock-bin')
  const lockProblem = lockWrapperProblem(lockDir, process.env.PATH)
  if (lockProblem) return `${lockProblem}; run: export PATH=${lockDir}:$PATH`
  const ciWait = waitForIdleCi(lockDir, step, run)
  if (ciWait) return ciWait
  const pressurePath = process.env.CI_LOCAL_PRESSURE_FILE || '/proc/pressure/memory'
  const threshold = process.env.CI_LOCAL_PRESSURE_MAX ? Number(process.env.CI_LOCAL_PRESSURE_MAX) : run.manifest.pressure.maxSomeAvg60
  if (!Number.isFinite(threshold)) return `CI_LOCAL_PRESSURE_MAX is not a number: ${process.env.CI_LOCAL_PRESSURE_MAX}`
  const verdict = pressureVerdict(pressurePath, threshold)
  appendFileSync(run.logPath, `ci-local: ${verdict.message}\n`)
  return verdict.ok ? null : verdict.message
}

// Wait for the host's CI to go idle BEFORE the step's timer starts, without
// holding any lock (dev-wait-ci is the same check the lock wrapper runs). A
// step's timeout then measures its own work: a long CI job on the shared
// runner no longer expires steps that never started.
function waitForIdleCi(lockDir, step, run) {
  if (!lockDir) return null
  const waiter = join(lockDir, 'dev-wait-ci')
  if (!existsSync(waiter)) return null
  appendFileSync(run.logPath, `ci-local: ${step.name}: waiting for CI to go idle before starting the timer\n`)
  const result = spawnSync(waiter, ['true'], { stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8' })
  if (result.stderr) appendFileSync(run.logPath, result.stderr)
  if (result.status === 0) return null
  if (result.status === 124) return 'CI kept building on this host past DEV_WAIT_CI_MAX_SECONDS'
  return `dev-wait-ci failed (${result.status ?? result.signal})`
}

function writeSummary(results, logPath, exitCode) {
  const lines = ['', 'Summary:']
  for (const result of results) {
    const time = result.durationMs === undefined ? '' : seconds(result.durationMs)
    const noticeMark = result.notices?.length ? `  (${result.notices.length} notice(s))` : ''
    lines.push(`  ${result.status.padEnd(11)} ${result.step.name.padEnd(24)} ${time}${noticeMark}`)
  }
  const failed = results.find((result) => result.status !== 'ok' && result.status !== 'not-run')
  lines.push(failed ? `ci-local: FAILED at ${failed.step.name} (exit ${exitCode}; log: ${logPath})` : `ci-local: all ${results.length} step(s) passed (log: ${logPath})`)
  appendFileSync(logPath, `${lines.join('\n')}\n`)
  say(lines.join('\n'))
}

function say(text) {
  process.stdout.write(`${text}\n`)
}

function seconds(ms) {
  return `${(ms / 1000).toFixed(1)}s`
}

function indent(text) {
  return text.split('\n').map((line) => `    ${line}`).join('\n')
}
