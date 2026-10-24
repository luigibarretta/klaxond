// Manifest loading and strict validation for the ci-local runner.
import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'
import { validateFixtures } from './ci-local-fixture.mjs'
import {
  isPlainObject, nonEmptyString, optionalPositiveInt, rejectUnknown, relativePath, stringList, validCommand,
  validateEnvObject,
} from './ci-local-util.mjs'

export const BUILTINS = new Set(['audit-all-lockfiles', 'compare-to-ref', 'loc', 'nasa', 'release-contract'])
export const DEFAULT_MANIFESTS = ['ci-local.json', 'scripts/ci-local.json']
const NAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/
const TOP_KEYS = new Set(['schemaVersion', 'strict', 'log', 'logMaxKbPerStep', 'defaults', 'pressure', 'fixtures', 'steps'])
const COMMON_STEP_KEYS = ['name', 'heavy', 'quick', 'timeout_s', 'env', 'description', 'needs', 'fixtures', 'writes']
const STEP_KEYS = new Set([...COMMON_STEP_KEYS, 'run', 'cwd'])
const BUILTIN_STEP_KEYS = new Set([...COMMON_STEP_KEYS, 'uses', 'with'])
// Piping a step into a filter hides output from the log and, without
// pipefail, the exit status; the runner already captures and excerpts.
const FILTER_PIPE = /(^|[^|])\|(?!\|)&?\s*(grep|egrep|fgrep|head|tail|sed|awk)\b/

export class ManifestError extends Error {
  constructor(path, errors) {
    super(`invalid ci-local manifest ${path}:\n  - ${errors.join('\n  - ')}`)
    this.errors = errors
  }
}

export function locateManifest(root, explicitPath) {
  if (explicitPath) {
    const path = isAbsolute(explicitPath) ? explicitPath : resolve(root, explicitPath)
    if (!existsSync(path)) throw new ManifestError(path, ['manifest file does not exist'])
    return path
  }
  for (const candidate of DEFAULT_MANIFESTS) {
    const path = resolve(root, candidate)
    if (existsSync(path)) return path
  }
  throw new ManifestError(root, [`no manifest found (looked for ${DEFAULT_MANIFESTS.join(', ')})`])
}

// `validateExtra(steps)` lets the runner add built-in checks to the same report.
export function loadManifest(path, validateExtra = () => []) {
  let raw
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    throw new ManifestError(path, [`cannot parse JSON: ${error.message}`])
  }
  const errors = []
  const warnings = []
  const manifest = validateManifest(raw, errors, warnings)
  if (manifest) errors.push(...validateExtra(manifest.steps.filter(Boolean)))
  if (manifest?.strict) errors.push(...warnings.map((warning) => `${warning} (strict)`))
  if (errors.length > 0) throw new ManifestError(path, errors)
  manifest.warnings = manifest.strict ? [] : warnings
  return manifest
}

export function validateManifest(raw, errors, warnings = []) {
  if (!isPlainObject(raw)) {
    errors.push('manifest must be a JSON object')
    return null
  }
  rejectUnknown(raw, TOP_KEYS, 'manifest', errors)
  if (raw.schemaVersion !== 1) errors.push('schemaVersion must equal 1')
  if (raw.strict !== undefined && typeof raw.strict !== 'boolean') errors.push('strict must be a boolean')
  const defaults = validateDefaults(raw.defaults, errors)
  const pressure = validatePressure(raw.pressure, errors)
  const fixtures = validateFixtures(raw.fixtures, errors)
  if (raw.log !== undefined && !nonEmptyString(raw.log)) errors.push('log must be a non-empty string')
  const logMaxKbPerStep = optionalPositiveInt(raw.logMaxKbPerStep, 'logMaxKbPerStep', 256, errors)
  if (!Array.isArray(raw.steps) || raw.steps.length === 0) {
    errors.push('steps must be a non-empty array')
    return null
  }
  const steps = raw.steps.map((step, index) => validateStep(step, index, defaults, errors, warnings))
  validateReferences(steps.filter(Boolean), fixtures, errors)
  return { strict: raw.strict === true, log: raw.log, logMaxKbPerStep, defaults, pressure, fixtures, steps }
}

// `needs` must point at earlier steps so manifest order stays a valid
// execution order; fixtures must be declared at the top level.
function validateReferences(steps, fixtures, errors) {
  const seen = new Set()
  for (const step of steps) {
    if (seen.has(step.name)) errors.push(`duplicate step name: ${step.name}`)
    for (const need of step.needs) {
      if (need === step.name) errors.push(`step ${step.name} needs itself`)
      else if (!seen.has(need)) errors.push(`step ${step.name} needs ${need}, which must be an earlier step`)
    }
    for (const fixture of step.fixtures) {
      if (!fixtures[fixture]) errors.push(`step ${step.name} uses undeclared fixture: ${fixture}`)
    }
    seen.add(step.name)
  }
}

function validateDefaults(raw, errors) {
  const fallback = { timeout_s: 1800, env: {} }
  if (raw === undefined) return fallback
  if (!isPlainObject(raw)) {
    errors.push('defaults must be an object')
    return fallback
  }
  rejectUnknown(raw, new Set(['timeout_s', 'env']), 'defaults', errors)
  return {
    timeout_s: optionalPositiveInt(raw.timeout_s, 'defaults.timeout_s', 1800, errors),
    env: validateEnvObject(raw.env, 'defaults.env', errors),
  }
}

function validatePressure(raw, errors) {
  const fallback = { maxSomeAvg60: 20 }
  if (raw === undefined) return fallback
  if (!isPlainObject(raw)) {
    errors.push('pressure must be an object')
    return fallback
  }
  rejectUnknown(raw, new Set(['maxSomeAvg60']), 'pressure', errors)
  const value = raw.maxSomeAvg60 ?? 20
  if (typeof value !== 'number' || !(value >= 0) || value > 100) {
    errors.push('pressure.maxSomeAvg60 must be a number between 0 and 100')
    return fallback
  }
  return { maxSomeAvg60: value }
}

function validateStep(raw, index, defaults, errors, warnings) {
  const label = `steps[${index}]`
  if (!isPlainObject(raw)) {
    errors.push(`${label} must be an object`)
    return null
  }
  const name = raw.name
  if (typeof name !== 'string' || !NAME_PATTERN.test(name)) errors.push(`${label}.name must match ${NAME_PATTERN}`)
  const where = typeof name === 'string' ? `step ${name}` : label
  const hasUses = raw.uses !== undefined
  if ((raw.run !== undefined) === hasUses) errors.push(`${where} must set exactly one of run or uses`)
  rejectUnknown(raw, hasUses ? BUILTIN_STEP_KEYS : STEP_KEYS, where, errors)
  if (hasUses && !BUILTINS.has(raw.uses)) errors.push(`${where}.uses must be one of: ${[...BUILTINS].join(', ')}`)
  if (!hasUses && raw.with !== undefined) errors.push(`${where}.with is only valid with uses`)
  if (raw.run !== undefined) validateRun(raw.run, where, errors, warnings)
  if (raw.cwd !== undefined && !relativePath(raw.cwd)) errors.push(`${where}.cwd must be a relative path inside the repository`)
  if (raw.with !== undefined && !isPlainObject(raw.with)) errors.push(`${where}.with must be an object`)
  for (const flag of ['heavy', 'quick']) {
    if (raw[flag] !== undefined && typeof raw[flag] !== 'boolean') errors.push(`${where}.${flag} must be a boolean`)
  }
  return {
    name,
    run: raw.run,
    uses: raw.uses,
    with: isPlainObject(raw.with) ? raw.with : {},
    cwd: raw.cwd ?? '.',
    heavy: raw.heavy === true,
    quick: raw.quick === true,
    timeoutS: optionalPositiveInt(raw.timeout_s, `${where}.timeout_s`, defaults.timeout_s, errors),
    env: validateEnvObject(raw.env, `${where}.env`, errors),
    needs: stringList(raw.needs, `${where}.needs`, errors),
    fixtures: stringList(raw.fixtures, `${where}.fixtures`, errors),
    writes: stringList(raw.writes, `${where}.writes`, errors, relativePath),
    description: raw.description,
  }
}

function validateRun(run, where, errors, warnings) {
  if (!validCommand(run)) {
    errors.push(`${where}.run must be a shell string or a non-empty array of non-empty strings`)
    return
  }
  if (typeof run === 'string' && FILTER_PIPE.test(run)) {
    warnings.push(`${where}.run pipes into a filter (${run.match(FILTER_PIPE)[2]}); ` +
      'do not filter in run: the runner captures the full output and shows an excerpt on failure')
  }
}
