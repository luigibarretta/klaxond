import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildNasaWarningReport } from './nasa-warning-lib.mjs'
import { printNasaWarningReport } from './nasa-warning-output.mjs'

const repoRoot = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]$/, '')
const locBaseline = JSON.parse(readFileSync(join(repoRoot, 'scripts/loc-baseline.json'), 'utf8'))

const policy = {
  fileWarnLines: numberFromEnv('NASA_WARN_FILE_LINES', 300),
  functionWarnLines: numberFromEnv('NASA_WARN_FUNCTION_LINES', 60),
  maxParameters: numberFromEnv('NASA_WARN_MAX_PARAMETERS', 6),
  outputLimit: numberFromEnv('NASA_WARNINGS_LIMIT', 200),
  fail: process.env.NASA_WARNINGS_FAIL === '1',
  annotations: process.env.NASA_WARNINGS_ANNOTATIONS !== '0',
}

const report = buildNasaWarningReport({ repoRoot, locBaseline, policy })
printNasaWarningReport(report, policy)

if (policy.fail && report.totalWarnings > 0) process.exit(1)

function numberFromEnv(name, fallback) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`)
  }
  return value
}
