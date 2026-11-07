// Counter baseline for the NASA/JPL warning profile (scripts/nasa-baseline.json).
// Each rule's warning count may never rise; `--update` lowers it after an
// improvement and creates the file on first use. The thresholds are recorded
// too, because counters are only comparable under the same thresholds.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { RULES } from './nasa-warning-lib.mjs'

export function thresholdsOf(policy) {
  return { fileLines: policy.fileWarnLines, functionLines: policy.functionWarnLines, parameters: policy.maxParameters }
}

export function readNasaBaseline(path) {
  if (!existsSync(path)) return { baseline: null, errors: [] }
  let raw
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    return { baseline: null, errors: [`cannot parse ${path}: ${error.message}`] }
  }
  const errors = []
  if (raw?.schemaVersion !== 1) errors.push('nasa baseline schemaVersion must equal 1')
  for (const section of ['thresholds', 'counters']) {
    for (const rule of RULES) {
      const value = raw?.[section]?.[rule]
      if (!Number.isInteger(value) || value < 0) errors.push(`nasa baseline ${section}.${rule} must be a non-negative integer`)
    }
  }
  return { baseline: errors.length ? null : raw, errors }
}

// Compares current counters with the baseline. Returns { increased,
// decreased, thresholdChanges } as human-readable lists.
export function compareCounters(baseline, counters, thresholds) {
  const result = { increased: [], decreased: [], thresholdChanges: [] }
  for (const rule of RULES) {
    if (baseline.thresholds[rule] !== thresholds[rule]) {
      result.thresholdChanges.push(`${rule} threshold is ${thresholds[rule]}, baseline was recorded at ${baseline.thresholds[rule]}`)
    }
    const recorded = baseline.counters[rule]
    if (counters[rule] > recorded) result.increased.push(`${rule}: ${recorded} -> ${counters[rule]} warning(s)`)
    if (counters[rule] < recorded) result.decreased.push(`${rule}: ${recorded} -> ${counters[rule]} warning(s)`)
  }
  return result
}

export function writeNasaBaseline(path, counters, thresholds) {
  const document = { schemaVersion: 1, thresholds, counters: Object.fromEntries(RULES.map((rule) => [rule, counters[rule]])) }
  writeFileSync(path, JSON.stringify(document, null, 2) + '\n')
}

// Runs the ratchet and update modes. Returns { ok, messages, notes }.
export function runNasaRatchet({ path, mode, counters, thresholds }) {
  const { baseline, errors } = readNasaBaseline(path)
  if (errors.length) return { ok: false, messages: errors, notes: [] }
  if (!baseline) {
    if (mode !== 'update') return { ok: false, messages: [`no NASA baseline at ${path}; run check-nasa-warnings --update to record the current counters`], notes: [] }
    writeNasaBaseline(path, counters, thresholds)
    return { ok: true, messages: [], notes: [`created ${path} with ${formatCounters(counters)}`] }
  }
  const comparison = compareCounters(baseline, counters, thresholds)
  if (comparison.thresholdChanges.length) {
    return {
      ok: false,
      messages: [...comparison.thresholdChanges, 'thresholds changed: review, delete the baseline and run --update to record new counters'],
      notes: [],
    }
  }
  if (comparison.increased.length) {
    return { ok: false, messages: comparison.increased.map((item) => `counter rose (${item}); fix the new warnings, the baseline never rises`), notes: [] }
  }
  if (comparison.decreased.length === 0) return { ok: true, messages: [], notes: [`NASA counters match the baseline (${formatCounters(counters)})`] }
  if (mode === 'update') {
    writeNasaBaseline(path, counters, thresholds)
    return { ok: true, messages: [], notes: comparison.decreased.map((item) => `lowered ${item}`) }
  }
  return { ok: false, messages: comparison.decreased.map((item) => `counter dropped (${item}); run check-nasa-warnings --update to lock it in`), notes: [] }
}

function formatCounters(counters) {
  return RULES.map((rule) => `${rule} ${counters[rule]}`).join(', ')
}
