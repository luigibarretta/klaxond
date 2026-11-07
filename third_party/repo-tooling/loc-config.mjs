// Loading and strict validation of scripts/loc-baseline.json, including the
// 0.6 `extends` presets. A baseline without `extends` keeps the 0.5 schema
// and semantics; the new rules switch on only through `extends` or explicit
// options (`ratchet`, `fragmentPatterns`, `legacyFragments`).
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkUntil } from './policy-dates.mjs'

export const PRESET_DIR = join(dirname(fileURLToPath(import.meta.url)), 'presets')
export const IGNORE_KINDS = ['generated', 'vendored', 'fixture', 'migration', 'third_party']
export const DEFAULT_FRAGMENT_PATTERNS = ['(^|/)part_\\d+(/|\\.[^/]+$)']
const PRESET_NAME = /^[a-z0-9][a-z0-9-]*$/
const LEGACY_KEYS = ['maxLines', 'allowedGrowthLines', 'roots', 'extensions', 'ignore', 'allow']
const EXPLICIT_KEYS = ['ratchet', 'fragmentPatterns', 'legacyFragments']
const PRESET_MODE_KEYS = new Set(['extends', 'roots', 'ignore', 'allow', 'overrides', 'legacyFragments'])
const OVERRIDABLE = new Set(['maxLines', 'allowedGrowthLines', 'extensions', 'fragmentPatterns'])

// Returns { policy, errors, warnings }. `policy` is always usable for
// reporting, even when `errors` is non-empty.
export function loadLocPolicy(baseline, { today, presetDir = PRESET_DIR }) {
  const errors = []
  const warnings = []
  if (!isObject(baseline)) return { policy: emptyPolicy(), errors: ['baseline must be a JSON object'], warnings }
  const preset = baseline.extends === undefined ? null : loadPreset(baseline.extends, presetDir, errors)
  const presetMode = baseline.extends !== undefined
  const allowed = presetMode ? PRESET_MODE_KEYS : new Set([...LEGACY_KEYS, ...EXPLICIT_KEYS])
  for (const key of Object.keys(baseline)) {
    if (allowed.has(key)) continue
    if (presetMode && OVERRIDABLE.has(key)) errors.push(`${key} comes from preset ${baseline.extends}; set it under overrides with a reason`)
    else if (presetMode && key === 'ratchet') errors.push('ratchet comes from the preset and cannot be turned off')
    else errors.push('unknown top-level baseline key: ' + key)
  }
  const base = preset?.loc ?? {}
  const settings = {
    maxLines: presetMode ? base.maxLines : baseline.maxLines ?? 400,
    allowedGrowthLines: presetMode ? base.allowedGrowthLines : baseline.allowedGrowthLines ?? 0,
    extensions: presetMode ? base.extensions ?? [] : baseline.extensions,
    fragmentPatterns: presetMode ? base.fragmentPatterns ?? DEFAULT_FRAGMENT_PATTERNS : baseline.fragmentPatterns,
  }
  if (presetMode) applyOverrides(baseline.overrides, settings, { base, today, errors, warnings })
  const policy = {
    preset: presetMode ? String(baseline.extends) : null,
    maxLines: integer(settings.maxLines, 'maxLines', errors, 1),
    allowedGrowthLines: integer(settings.allowedGrowthLines, 'allowedGrowthLines', errors, 0),
    roots: stringArray(baseline.roots, 'roots', errors),
    extensions: stringArray(settings.extensions, 'extensions', errors),
    ignore: object(baseline.ignore ?? {}, 'ignore', errors),
    allow: object(baseline.allow ?? {}, 'allow', errors),
    ratchet: presetMode ? base.ratchet === true : baseline.ratchet === true,
    fragmentPatterns: null,
    legacyFragments: null,
    nasa: preset?.nasa ?? null,
  }
  if (!presetMode && baseline.ratchet !== undefined && typeof baseline.ratchet !== 'boolean') errors.push('ratchet must be a boolean')
  validateShape(policy, baseline, errors)
  validateAllow(policy, { presetMode, today, errors, warnings })
  validateIgnore(policy, { requireKind: presetMode && base.requireIgnoreKind === true, errors })
  const fragmentsOn = presetMode || baseline.fragmentPatterns !== undefined || baseline.legacyFragments !== undefined
  if (fragmentsOn) {
    policy.fragmentPatterns = compilePatterns(settings.fragmentPatterns ?? DEFAULT_FRAGMENT_PATTERNS, errors)
    policy.legacyFragments = validateLegacyFragments(baseline.legacyFragments, errors)
  }
  return { policy, errors, warnings }
}

function emptyPolicy() {
  return { preset: null, maxLines: 400, allowedGrowthLines: 0, roots: [], extensions: [], ignore: {}, allow: {}, ratchet: false, fragmentPatterns: null, legacyFragments: null, nasa: null }
}

export function loadPreset(name, presetDir, errors) {
  if (typeof name !== 'string' || !PRESET_NAME.test(name)) {
    errors.push('extends must name a preset such as "fleet-default"')
    return null
  }
  const path = join(presetDir, `${name}.json`)
  if (!existsSync(path)) {
    errors.push(`unknown preset ${name} (no ${path}); vendor the complete dist/ directory`)
    return null
  }
  try {
    const preset = JSON.parse(readFileSync(path, 'utf8'))
    if (preset.schemaVersion !== 1 || !isObject(preset.loc)) throw new Error('unsupported preset schema')
    return preset
  } catch (error) {
    errors.push(`preset ${name} is invalid: ${error.message}`)
    return null
  }
}

// Overrides change a preset value. Every one needs a reason; one that relaxes
// the preset (a higher limit or growth budget, fewer counted extensions,
// fragment patterns that no longer include the preset's) must also expire.
function applyOverrides(raw, settings, { base, today, errors, warnings }) {
  if (raw === undefined) return
  if (!isObject(raw)) {
    errors.push('overrides must be an object')
    return
  }
  for (const [key, entry] of Object.entries(raw)) {
    const label = `override ${key}`
    if (!OVERRIDABLE.has(key)) {
      errors.push(`${label} is not overridable (allowed: ${[...OVERRIDABLE].join(', ')})`)
      continue
    }
    if (!isObject(entry) || !('value' in entry)) {
      errors.push(`${label} must be {"value": ..., "reason": ..., "until"?: "YYYY-MM-DD"}`)
      continue
    }
    for (const field of Object.keys(entry)) {
      if (!['value', 'reason', 'until'].includes(field)) errors.push(`${label} has unknown key: ${field}`)
    }
    if (!nonEmpty(entry.reason)) errors.push(`${label} must include a non-empty reason`)
    if (relaxes(key, entry.value, base) && entry.until === undefined) {
      errors.push(`${label} relaxes the preset and must set until (YYYY-MM-DD) as well as a reason`)
    }
    if (key === 'extensions' && Array.isArray(entry.value) && !entry.value.some((ext) => (base.extensions ?? []).includes(ext))) {
      errors.push(`${label} must keep at least one preset extension`)
    }
    checkUntil(entry.until, label, today, errors, warnings)
    settings[key] = entry.value
  }
}

function relaxes(key, value, base) {
  const notSuperset = (preset) => !Array.isArray(value) || (preset ?? []).some((item) => !value.includes(item))
  if (key === 'maxLines') return !(Number.isInteger(value) && value <= base.maxLines)
  if (key === 'allowedGrowthLines') return !(Number.isInteger(value) && value <= base.allowedGrowthLines)
  if (key === 'extensions') return notSuperset(base.extensions)
  return notSuperset(base.fragmentPatterns ?? DEFAULT_FRAGMENT_PATTERNS)
}

function validateShape(policy, baseline, errors) {
  if (policy.extensions.length === 0) errors.push('extensions must contain at least one extension')
  for (const ext of policy.extensions) {
    if (!ext.startsWith('.')) errors.push('extension ' + ext + ' must start with "."')
  }
  if (!Array.isArray(baseline.roots) || policy.roots.length === 0) errors.push('roots must contain at least one source root')
  for (const root of policy.roots) validateRepoPath(root, 'root ' + root, errors)
  for (const rel of Object.keys(policy.allow)) validateRepoPath(rel, 'allow entry ' + rel, errors)
  for (const rel of Object.keys(policy.ignore)) validateRepoPath(rel, 'ignore entry ' + rel, errors)
}

function validateAllow(policy, { presetMode, today, errors, warnings }) {
  for (const [rel, entry] of Object.entries(policy.allow)) {
    const label = 'allow entry ' + rel
    if (!isObject(entry)) {
      errors.push(label + ' must be an object')
      continue
    }
    if (presetMode) {
      for (const key of Object.keys(entry)) {
        if (!['linesAtBaseline', 'reason', 'until'].includes(key)) errors.push(label + ' has unknown key: ' + key)
      }
    }
    const lines = integer(entry.linesAtBaseline, label + '.linesAtBaseline', errors, 1)
    if (Number.isFinite(policy.maxLines) && Number.isFinite(lines) && lines <= policy.maxLines) {
      errors.push(label + '.linesAtBaseline must be greater than maxLines (' + policy.maxLines + ')')
    }
    if (!nonEmpty(entry.reason)) errors.push(label + ' must include a non-empty reason')
    checkUntil(entry.until, label, today, errors, warnings)
  }
}

function validateIgnore(policy, { requireKind, errors }) {
  for (const [rel, entry] of Object.entries(policy.ignore)) {
    const label = 'ignore entry ' + rel
    if (!isObject(entry)) {
      errors.push(label + ' must be an object')
      continue
    }
    for (const key of Object.keys(entry)) {
      if (!['reason', 'optional', 'kind'].includes(key)) errors.push(label + ' has unknown key: ' + key)
    }
    if (!nonEmpty(entry.reason)) errors.push(label + ' must include a non-empty reason')
    if (entry.optional !== undefined && typeof entry.optional !== 'boolean') errors.push(label + '.optional must be a boolean')
    if (entry.kind !== undefined && !IGNORE_KINDS.includes(entry.kind)) {
      errors.push(`${label}.kind must be one of ${IGNORE_KINDS.join(', ')}`)
    } else if (entry.kind === undefined && requireKind) {
      errors.push(`${label} must declare a kind (${IGNORE_KINDS.join(', ')}) under the preset`)
    }
  }
}

function validateLegacyFragments(raw, errors) {
  if (raw === undefined) return { count: 0 }
  if (!isObject(raw) || Object.keys(raw).some((key) => !['count', 'reason'].includes(key))) {
    errors.push('legacyFragments must be {"count": N, "reason"?: "..."}')
    return { count: 0 }
  }
  return { count: integer(raw.count, 'legacyFragments.count', errors, 0) }
}

function compilePatterns(raw, errors) {
  if (!Array.isArray(raw) || raw.length === 0 || !raw.every(nonEmpty)) {
    errors.push('fragmentPatterns must be a non-empty array of regular expressions')
    return []
  }
  const patterns = []
  for (const source of raw) {
    try {
      patterns.push(new RegExp(source))
    } catch (error) {
      errors.push(`fragmentPatterns entry ${source} is invalid: ${error.message}`)
    }
  }
  return patterns
}

function validateRepoPath(rel, label, errors) {
  if (typeof rel !== 'string' || rel.length === 0) {
    errors.push(label + ' must be a non-empty relative path')
    return
  }
  if (rel.includes('\\')) errors.push(label + ' must use forward slashes')
  if (rel.startsWith('/') || rel.match(/^[A-Za-z]:/)) errors.push(label + ' must be relative to the repository root')
  if (rel.split('/').includes('..')) errors.push(label + ' must not contain .. segments')
}

// JSON integers only: "700", [450] or true are rejected, not coerced.
function integer(value, label, errors, min) {
  if (!Number.isInteger(value) || value < min) {
    errors.push(label + ' must be an integer >= ' + min)
    return Number.NaN
  }
  return value
}

function stringArray(value, label, errors) {
  if (!Array.isArray(value)) {
    errors.push(label + ' must be an array of strings')
    return []
  }
  const normalized = value.filter((item) => typeof item === 'string' && item.trim().length > 0)
  if (normalized.length !== value.length) errors.push(label + ' entries must be non-empty strings')
  return normalized
}

function object(value, label, errors) {
  if (!isObject(value)) {
    errors.push(label + ' must be an object')
    return {}
  }
  return value
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0
}
