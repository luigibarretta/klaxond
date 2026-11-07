#!/usr/bin/env node
// Repository-aware LOC guard. `--check` (default) validates; `--update`
// lowers allowances and the fragment counter to the current sizes and removes
// entries that are no longer needed. It never raises or adds an allowance.
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { loadLocPolicy } from './loc-config.mjs'
import { applyLocUpdate, evaluateLoc } from './loc-rules.mjs'
import { walkSources } from './loc-scan.mjs'
import { today } from './policy-dates.mjs'

const USAGE = 'usage: check-loc [--check | --update]'

function main(argv) {
  const mode = parseMode(argv)
  if (!mode) {
    console.error(USAGE)
    return 2
  }
  const repoRoot = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
  const baselinePath = resolve(repoRoot, process.env.LOC_BASELINE || 'scripts/loc-baseline.json')
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))
  const { policy, errors, warnings } = loadLocPolicy(baseline, { today: today() })
  const scan = walkSources({ repoRoot, roots: policy.roots, extensions: policy.extensions, ignoredPaths: Object.keys(policy.ignore) })
  for (const root of scan.missingRoots) errors.push('LOC root does not exist: ' + root)
  errors.push(...scan.errors)
  // A preset baseline that checks nothing is a misconfiguration, not a pass.
  if (policy.preset && scan.files.length === 0) errors.push('no source files found under roots with the preset extensions')
  const result = evaluateLoc(policy, scan, repoRoot)

  if (mode === 'update' && errors.length === 0) {
    const changes = applyLocUpdate(baseline, result.edits)
    if (changes.length > 0) {
      writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n')
      for (const change of changes) console.log('updated: ' + change)
    } else {
      console.log('LOC baseline already at the current sizes; nothing to update.')
    }
    return report(errors, warnings, result.violations, [], policy, scan)
  }
  return report(errors, warnings, result.violations, [...result.stale, ...result.ratchet], policy, scan)
}

function parseMode(argv) {
  if (argv.length === 0) return 'check'
  if (argv.length === 1 && argv[0] === '--check') return 'check'
  if (argv.length === 1 && argv[0] === '--update') return 'update'
  return null
}

function report(errors, warnings, violations, cleanup, policy, scan) {
  for (const warning of warnings) console.warn('warning: ' + warning)
  if (errors.length) {
    console.error('LOC baseline is invalid:')
    for (const error of errors) console.error('- ' + error)
  }
  if (violations.length) {
    console.error('LOC guard failed. Split these files or update a documented baseline intentionally:')
    for (const violation of violations) console.error('- ' + violation)
  }
  if (cleanup.length) {
    console.error('LOC baseline cleanup needed:')
    for (const item of cleanup) console.error('- ' + item)
  }
  if (errors.length || violations.length || cleanup.length) return 1
  const preset = policy.preset ? ' (preset ' + policy.preset + (policy.ratchet ? ', ratchet' : '') + ')' : ''
  console.log(
    'LOC guard passed' + preset + ': checked ' + scan.files.length + ' files, max ' + policy.maxLines + ' LOC, '
      + Object.keys(policy.allow).length + ' documented baselines, '
      + Object.keys(policy.ignore).length + ' documented ignores, growth budget ' + policy.allowedGrowthLines + ' LOC.',
  )
  return 0
}

process.exitCode = main(process.argv.slice(2))
