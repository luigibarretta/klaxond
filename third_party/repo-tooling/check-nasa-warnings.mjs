#!/usr/bin/env node
// NASA/JPL-inspired warning profile. Warning-only by default; `--ratchet`
// fails when a rule's counter differs from scripts/nasa-baseline.json,
// `--update` lowers (or first records) those counters, `--json` prints the
// report as JSON.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { loadLocPolicy } from './loc-config.mjs'
import { runNasaRatchet, thresholdsOf } from './nasa-baseline.mjs'
import { buildNasaWarningReport } from './nasa-warning-lib.mjs'
import { printNasaWarningReport } from './nasa-warning-output.mjs'
import { today } from './policy-dates.mjs'

const USAGE = 'usage: check-nasa-warnings [--json] [--ratchet | --update]'

function main(argv) {
  const options = parseArguments(argv)
  if (!options) {
    console.error(USAGE)
    return 2
  }
  const repoRoot = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
  const baselinePath = resolve(repoRoot, process.env.LOC_BASELINE || 'scripts/loc-baseline.json')
  const locBaseline = JSON.parse(readFileSync(baselinePath, 'utf8'))
  const presetNasa = loadLocPolicy(locBaseline, { today: today() }).policy.nasa ?? {}
  const policy = {
    fileWarnLines: numberFromEnv('NASA_WARN_FILE_LINES', presetNasa.fileWarnLines ?? 300),
    functionWarnLines: numberFromEnv('NASA_WARN_FUNCTION_LINES', presetNasa.functionWarnLines ?? 60),
    maxParameters: numberFromEnv('NASA_WARN_MAX_PARAMETERS', presetNasa.maxParameters ?? 6),
    outputLimit: numberFromEnv('NASA_WARNINGS_LIMIT', 200),
    fail: process.env.NASA_WARNINGS_FAIL === '1',
    annotations: process.env.NASA_WARNINGS_ANNOTATIONS !== '0' && !options.json,
  }

  const report = buildNasaWarningReport({ repoRoot, locBaseline, policy })
  const problems = [...report.errors]
  if (options.mode) {
    if (report.filesChecked === 0) problems.push('no source files found; the counters would be meaningless')
    problems.push(...envThresholdConflicts(presetNasa, policy))
  }
  if (problems.length) {
    console.error('NASA profile cannot run:')
    for (const problem of problems) console.error('- ' + problem)
    return 1
  }
  const ratchet = options.mode
    ? runNasaRatchet({
      path: resolve(repoRoot, process.env.NASA_BASELINE || 'scripts/nasa-baseline.json'),
      mode: options.mode,
      counters: report.counters,
      thresholds: thresholdsOf(policy),
    })
    : null

  if (options.json) printJson(report, policy, ratchet)
  else printText(report, policy, ratchet)
  if (ratchet && !ratchet.ok) return 1
  return policy.fail && report.totalWarnings > 0 ? 1 : 0
}

// Under --ratchet/--update the preset's thresholds are the contract; a
// session override from the environment must not silently replace them.
function envThresholdConflicts(presetNasa, policy) {
  const pairs = [
    ['NASA_WARN_FILE_LINES', 'fileWarnLines'],
    ['NASA_WARN_FUNCTION_LINES', 'functionWarnLines'],
    ['NASA_WARN_MAX_PARAMETERS', 'maxParameters'],
  ]
  return pairs
    .filter(([name, key]) => presetNasa[key] !== undefined && process.env[name] && policy[key] !== presetNasa[key])
    .map(([name, key]) => `${name}=${policy[key]} contradicts the preset (${presetNasa[key]}); unset it for --ratchet/--update`)
}

function parseArguments(argv) {
  const options = { json: false, mode: null }
  for (const argument of argv) {
    if (argument === '--json') options.json = true
    else if ((argument === '--ratchet' || argument === '--update') && !options.mode) options.mode = argument.slice(2)
    else return null
  }
  return options
}

function printText(report, policy, ratchet) {
  printNasaWarningReport(report, policy)
  if (!ratchet) return
  for (const note of ratchet.notes) console.log('NASA ratchet: ' + note)
  if (ratchet.ok) return
  console.error('NASA ratchet failed:')
  for (const message of ratchet.messages) console.error('- ' + message)
}

function printJson(report, policy, ratchet) {
  const document = {
    schemaVersion: 1,
    thresholds: thresholdsOf(policy),
    counters: report.counters,
    filesChecked: report.filesChecked,
    totalWarnings: report.totalWarnings,
    warnings: { fileLines: report.fileWarnings, functionLines: report.functionWarnings, parameters: report.parameterWarnings },
    ratchet: ratchet ? { ok: ratchet.ok, messages: ratchet.messages, notes: ratchet.notes } : null,
  }
  console.log(JSON.stringify(document, null, 2))
}

function numberFromEnv(name, fallback) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`)
  }
  return value
}

process.exitCode = main(process.argv.slice(2))
