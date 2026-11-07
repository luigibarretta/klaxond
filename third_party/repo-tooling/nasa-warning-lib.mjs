import { readFileSync } from 'node:fs'

import { loadLocPolicy } from './loc-config.mjs'
import { countLines, toRepoPath, walkSources } from './loc-scan.mjs'
import { findFunctions } from './nasa-warning-functions.mjs'
import { today } from './policy-dates.mjs'

// Rule keys shared by the report, the --json output and nasa-baseline.json.
export const RULES = ['fileLines', 'functionLines', 'parameters']

// The source set is the LOC baseline's (roots, extensions, ignore), resolved
// through its preset when it `extends` one. An invalid baseline or an
// unusable root is an error: counting nothing must never pass.
export function nasaSources(repoRoot, locBaseline) {
  const { policy, errors } = loadLocPolicy(locBaseline, { today: today() })
  const scan = walkSources({ repoRoot, roots: policy.roots, extensions: policy.extensions, ignoredPaths: Object.keys(policy.ignore) })
  const problems = [...errors, ...scan.errors, ...scan.missingRoots.map((root) => `root does not exist: ${root}`)]
  return { files: scan.files, presetNasa: policy.nasa, errors: problems }
}

export function buildNasaWarningReport({ repoRoot, locBaseline, policy }) {
  const { files, errors } = nasaSources(repoRoot, locBaseline)
  const report = {
    errors,
    filesChecked: files.length,
    fileWarnings: [],
    functionWarnings: [],
    parameterWarnings: [],
    totalWarnings: 0,
  }

  for (const file of files) {
    const rel = toRepoPath(repoRoot, file)
    const text = readFileSync(file, 'utf8')
    const lines = countLines(text)
    if (lines > policy.fileWarnLines) {
      report.fileWarnings.push(warning(rel, 1, lines, policy.fileWarnLines, `file has ${lines} LOC (NASA/JPL warning target ${policy.fileWarnLines})`))
    }
    collectFunctionWarnings(report, rel, text, policy)
  }

  report.totalWarnings = report.fileWarnings.length + report.functionWarnings.length + report.parameterWarnings.length
  report.counters = {
    fileLines: report.fileWarnings.length,
    functionLines: report.functionWarnings.length,
    parameters: report.parameterWarnings.length,
  }
  return report
}

function collectFunctionWarnings(report, rel, text, policy) {
  for (const fn of findFunctions(rel, text)) {
    if (fn.lines > policy.functionWarnLines) {
      report.functionWarnings.push(warning(rel, fn.startLine, fn.lines, policy.functionWarnLines, `${fn.kind} ${fn.name} has ${fn.lines} lines (NASA/JPL target ${policy.functionWarnLines})`, fn.name))
    }
    if (fn.parameters > policy.maxParameters) {
      report.parameterWarnings.push(warning(rel, fn.startLine, fn.parameters, policy.maxParameters, `${fn.kind} ${fn.name} has ${fn.parameters} parameters (NASA/JPL target ${policy.maxParameters})`, fn.name))
    }
  }
}

function warning(file, line, actual, limit, message, name = '') {
  return { file, line, actual, limit, message, name }
}
