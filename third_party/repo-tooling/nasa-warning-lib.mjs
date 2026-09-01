import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'

import { findFunctions } from './nasa-warning-functions.mjs'

const defaultIgnoredDirs = new Set([
  '.git',
  '.next',
  '.turbo',
  '__pycache__',
  'coverage',
  'dist',
  'node_modules',
  'target',
])

export function buildNasaWarningReport({ repoRoot, locBaseline, policy }) {
  const roots = asStringArray(locBaseline.roots)
  const extensions = new Set(asStringArray(locBaseline.extensions))
  const ignoredRepoPaths = new Set(Object.keys(locBaseline.ignore ?? {}))
  const files = []

  for (const root of roots) {
    const fullPath = join(repoRoot, root)
    if (existsSync(fullPath)) walk(repoRoot, fullPath, files, extensions, ignoredRepoPaths)
  }

  const report = {
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

function walk(repoRoot, dir, out, extensions, ignoredRepoPaths) {
  for (const entry of readdirSync(dir)) {
    if (defaultIgnoredDirs.has(entry)) continue
    const filePath = join(dir, entry)
    const rel = toRepoPath(repoRoot, filePath)
    if (isIgnored(rel, ignoredRepoPaths)) continue
    const stat = statSync(filePath)
    if (stat.isDirectory()) {
      walk(repoRoot, filePath, out, extensions, ignoredRepoPaths)
    } else if (extensions.has(extname(filePath))) {
      out.push(filePath)
    }
  }
}

function warning(file, line, actual, limit, message, name = '') {
  return { file, line, actual, limit, message, name }
}

function asStringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string' && item.length > 0) : []
}

function isIgnored(rel, ignoredRepoPaths) {
  for (const ignored of ignoredRepoPaths) {
    if (rel === ignored || rel.startsWith(ignored + '/')) return true
  }
  return false
}

function toRepoPath(repoRoot, filePath) {
  return relative(repoRoot, filePath).split(sep).join('/')
}

function countLines(text) {
  if (!text) return 0
  return text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length
}
