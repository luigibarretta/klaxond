// Git-backed checks: declared step writes and the compare-to-ref built-in.
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, realpathSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { isPlainObject, nonEmptyString, rejectUnknown } from './ci-local-util.mjs'

const COMPARE_KEYS = new Set(['file', 'json_pointer', 'path', 'ref', 'on_change', 'on_missing_ref', 'label'])
const POLICIES = new Set(['warn', 'fail'])

// Consumer checkouts may be owned by another account that shares the
// checkout through a group on shared hosts. Trust only the resolved root that
// the caller is already gating (and building), never every repository, and
// disable every repository-configurable program git could run while reading.
const HARDENING = [
  '-c', 'core.fsmonitor=false',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.attributesFile=/dev/null',
  '-c', 'diff.external=',
]

export function git(root, args) {
  let resolved = root
  try { resolved = realpathSync(root) } catch { /* git reports the missing root */ }
  const result = spawnSync('git', ['-c', `safe.directory=${resolved}`, ...HARDENING, '-C', resolved, ...args],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' } })
  return { ok: result.status === 0, stdout: result.stdout ?? '', stderr: (result.stderr ?? '') + (result.error?.message ?? '') }
}

function pathspecs(writes) {
  return writes.map((entry) => `:(glob)${entry}`)
}

// Content hashes of every tracked or untracked (not ignored) file under the
// declared paths, so local runs can report exactly what a step changed.
export function snapshotWrites(root, writes) {
  const listed = git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...pathspecs(writes)])
  if (!listed.ok) return null
  const snapshot = new Map()
  for (const path of new Set(listed.stdout.split('\0').filter(Boolean))) {
    const full = join(root, path)
    snapshot.set(path, existsSync(full) ? createHash('sha256').update(readFileSync(full)).digest('hex') : 'deleted')
  }
  return snapshot
}

export function changedSince(before, after) {
  const changed = []
  for (const [path, hash] of after) if (before.get(path) !== hash) changed.push(path)
  for (const path of before.keys()) if (!after.has(path)) changed.push(path)
  return changed.sort()
}

// CI: the declared outputs must already be committed. Returns null or a
// failure message with the diff stat and untracked files.
export function verifyWritesClean(root, writes) {
  const specs = pathspecs(writes)
  const status = git(root, ['status', '--porcelain', '--untracked-files=all', '--', ...specs])
  if (!status.ok) return `cannot check declared writes with git: ${status.stderr.trim()}`
  if (status.stdout.trim() === '') return null
  const stat = git(root, ['diff', '--no-ext-diff', '--no-textconv', '--stat', 'HEAD', '--', ...specs]).stdout.trim()
  const untracked = status.stdout.split('\n').filter((line) => line.startsWith('??')).map((line) => line.slice(3))
  return [
    'step changed files it declares in writes; regenerate and commit them:',
    stat,
    untracked.length ? `untracked: ${untracked.join(', ')}` : '',
  ].filter(Boolean).join('\n')
}

export function validateCompareConfig(raw, where) {
  const errors = []
  rejectUnknown(raw, COMPARE_KEYS, where, errors)
  if (!nonEmptyString(raw.file)) errors.push(`${where}.file is required`)
  if ((raw.json_pointer === undefined) === (raw.path === undefined)) errors.push(`${where} must set exactly one of json_pointer or path`)
  if (raw.json_pointer !== undefined && !(typeof raw.json_pointer === 'string' && (raw.json_pointer === '' || raw.json_pointer.startsWith('/')))) {
    errors.push(`${where}.json_pointer must be an RFC 6901 pointer such as /route_count`)
  }
  if (raw.path !== undefined && !nonEmptyString(raw.path)) errors.push(`${where}.path must be a dotted path such as totals.routes`)
  for (const key of ['on_change', 'on_missing_ref']) {
    if (raw[key] !== undefined && !POLICIES.has(raw[key])) errors.push(`${where}.${key} must be warn or fail`)
  }
  if (raw.ref !== undefined && !(nonEmptyString(raw.ref) && !raw.ref.startsWith('-'))) errors.push(`${where}.ref must be a git ref`)
  return {
    errors,
    config: {
      file: raw.file,
      segments: typeof raw.json_pointer === 'string' ? pointerSegments(raw.json_pointer) : String(raw.path ?? '').split('.'),
      ref: raw.ref ?? 'HEAD',
      onChange: raw.on_change ?? 'warn',
      onMissingRef: raw.on_missing_ref ?? 'warn',
      label: raw.label ?? raw.file,
    },
  }
}

function pointerSegments(pointer) {
  if (pointer === '') return []
  return pointer.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
}

function extract(text, segments) {
  let value = JSON.parse(text)
  for (const segment of segments) {
    if (!(Array.isArray(value) || isPlainObject(value)) || !Object.hasOwn(value, segment)) {
      throw new Error(`no value at ${segments.join('.')}`)
    }
    value = value[segment]
  }
  return JSON.stringify(value)
}

// Returns { status, detail, notices } like any step.
export function compareToRef(root, config, output) {
  const fullPath = join(root, config.file)
  let current
  try {
    current = extract(readFileSync(fullPath, 'utf8'), config.segments)
  } catch (error) {
    return { status: 'fail', detail: `${config.file}: ${error.message}` }
  }
  // `<rev>:./<path>` resolves the path relative to root, not the git top level.
  const shown = git(root, ['show', '--no-textconv', `${config.ref}:./${config.file}`])
  if (!shown.ok) {
    const message = `${config.label}: ${config.file} not readable at ${config.ref}; current value ${current}`
    output(`${message}\n${shown.stderr}`)
    return config.onMissingRef === 'fail' ? { status: 'fail', detail: message } : { status: 'ok', notices: [message] }
  }
  let previous
  try {
    previous = extract(shown.stdout, config.segments)
  } catch (error) {
    return { status: 'fail', detail: `${config.file} at ${config.ref}: ${error.message}` }
  }
  if (previous === current) {
    output(`${config.label}: unchanged at ${current} (vs ${config.ref})\n`)
    return { status: 'ok', detail: `${config.label} unchanged at ${current}` }
  }
  const message = `${config.label} changed ${previous} -> ${current} (vs ${config.ref})`
  output(`${message}\n`)
  return config.onChange === 'fail' ? { status: 'fail', detail: message } : { status: 'ok', notices: [`${message}; check it is intended`] }
}
