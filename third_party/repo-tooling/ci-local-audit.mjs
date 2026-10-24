// Built-in audit-all-lockfiles step: discover every Cargo.lock and
// package-lock.json in the repository and audit each one, fail closed.
import { existsSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { isPlainObject, nonEmptyString, rejectUnknown, relativePath } from './ci-local-util.mjs'

export const LOCKFILES = { 'Cargo.lock': 'cargo', 'package-lock.json': 'npm' }
export const EXCLUDED_DIR_NAMES = new Set(['target', 'vendor', 'node_modules', 'third_party'])
const AUDIT_KEYS = new Set(['ecosystems', 'exclude', 'include', 'cargo', 'npm'])
const NPM_MODES = new Set(['npm-audit', 'command'])
const AUDIT_LEVELS = new Set(['info', 'low', 'moderate', 'high', 'critical'])

export function validateAuditConfig(raw, where) {
  const errors = []
  rejectUnknown(raw, AUDIT_KEYS, where, errors)
  const ecosystems = raw.ecosystems ?? ['cargo', 'npm']
  if (!Array.isArray(ecosystems) || ecosystems.length === 0 || !ecosystems.every((e) => e === 'cargo' || e === 'npm')) {
    errors.push(`${where}.ecosystems must be a non-empty subset of ["cargo", "npm"]`)
  }
  const exclude = reasonedList(raw.exclude, `${where}.exclude`, 'path', errors)
  const include = raw.include ?? []
  if (!Array.isArray(include) || !include.every(relativePath)) {
    errors.push(`${where}.include must be an array of relative directory paths`)
  }
  const cargo = validateCargo(raw.cargo ?? {}, `${where}.cargo`, errors)
  const npm = validateNpm(raw.npm ?? {}, `${where}.npm`, errors)
  return { errors, config: { ecosystems, exclude, include, cargo, npm } }
}

function validateCargo(raw, where, errors) {
  if (!isPlainObject(raw)) {
    errors.push(`${where} must be an object`)
    return { ignore: [], args: [] }
  }
  rejectUnknown(raw, new Set(['ignore', 'args']), where, errors)
  const ignore = reasonedList(raw.ignore, `${where}.ignore`, 'id', errors)
  const args = stringArray(raw.args, `${where}.args`, errors)
  return { ignore, args }
}

function validateNpm(raw, where, errors) {
  if (!isPlainObject(raw)) {
    errors.push(`${where} must be an object`)
    return { mode: 'npm-audit', auditLevel: 'moderate', args: [] }
  }
  rejectUnknown(raw, new Set(['mode', 'audit_level', 'args', 'command', 'covers']), where, errors)
  const mode = raw.mode ?? 'npm-audit'
  if (!NPM_MODES.has(mode)) errors.push(`${where}.mode must be npm-audit or command`)
  const auditLevel = raw.audit_level ?? 'moderate'
  if (!AUDIT_LEVELS.has(auditLevel)) errors.push(`${where}.audit_level must be one of ${[...AUDIT_LEVELS].join(', ')}`)
  const args = stringArray(raw.args, `${where}.args`, errors)
  if (mode === 'command') {
    const validCommand = nonEmptyString(raw.command) || (Array.isArray(raw.command) && raw.command.length > 0 && raw.command.every(nonEmptyString))
    if (!validCommand) errors.push(`${where}.command is required in command mode (shell string or argv array)`)
    if (!Array.isArray(raw.covers) || !raw.covers.every(relativePath)) {
      errors.push(`${where}.covers must list every package-lock.json the command scans`)
    }
  } else if (raw.command !== undefined || raw.covers !== undefined) {
    errors.push(`${where}.command and covers are only valid in command mode`)
  }
  return { mode, auditLevel, args, command: raw.command, covers: raw.covers ?? [] }
}

function reasonedList(raw, where, key, errors) {
  if (raw === undefined) return []
  const valid = Array.isArray(raw) && raw.every((entry) =>
    isPlainObject(entry) && nonEmptyString(entry[key]) && nonEmptyString(entry.reason) && Object.keys(entry).length === 2)
  if (!valid) errors.push(`${where} entries must be {"${key}": ..., "reason": ...}`)
  return valid ? raw : []
}

function stringArray(raw, where, errors) {
  if (raw === undefined) return []
  if (!Array.isArray(raw) || !raw.every((entry) => typeof entry === 'string')) {
    errors.push(`${where} must be an array of strings`)
    return []
  }
  return raw
}

// Walks the tree without following symlinks. Skips build/vendor directories,
// dot-directories (.git, .claude worktrees, caches) and nested checkouts,
// unless a directory is explicitly listed in `include`.
export function discoverLockfiles(root, include = []) {
  const found = new Set()
  walk(root, root, found, true)
  for (const entry of include) {
    const path = join(root, entry)
    if (!existsSync(path) || !statSync(path).isDirectory()) throw new Error(`include path is not a directory: ${entry}`)
    walk(root, path, found, true)
  }
  return [...found].sort()
}

function walk(root, directory, found, isStart) {
  if (!isStart && existsSync(join(directory, '.git'))) return
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (entry.name.startsWith('.') || EXCLUDED_DIR_NAMES.has(entry.name)) continue
      walk(root, join(directory, entry.name), found, false)
    } else if (entry.isFile() && LOCKFILES[entry.name]) {
      found.add(relative(root, join(directory, entry.name)).split(sep).join('/'))
    }
  }
}

export function partitionLockfiles(lockfiles, exclude) {
  const used = new Set()
  const selected = { cargo: [], npm: [] }
  const excluded = []
  for (const path of lockfiles) {
    const rule = exclude.find((entry) => path === entry.path || path.startsWith(`${entry.path.replace(/\/$/, '')}/`))
    if (rule) {
      used.add(rule)
      excluded.push({ path, reason: rule.reason })
      continue
    }
    selected[LOCKFILES[path.split('/').pop()]].push(path)
  }
  const stale = exclude.filter((entry) => !used.has(entry)).map((entry) => entry.path)
  return { selected, excluded, stale }
}

// Plans the subprocesses; the runner executes them with the step deadline.
export function planAudit(root, config, coveredElsewhere) {
  const problems = []
  const { selected, excluded, stale } = partitionLockfiles(discoverLockfiles(root, config.include), config.exclude)
  for (const path of stale) problems.push(`exclude entry matches no lockfile (stale): ${path}`)
  for (const ecosystem of ['cargo', 'npm']) {
    if (selected[ecosystem].length > 0 && !config.ecosystems.includes(ecosystem) && !coveredElsewhere.has(ecosystem)) {
      problems.push(`${ecosystem} lockfiles found but no audit-all-lockfiles step covers ${ecosystem}: ${selected[ecosystem].join(', ')}`)
    }
  }
  const commands = []
  if (config.ecosystems.includes('cargo')) commands.push(...cargoCommands(selected.cargo, config.cargo))
  if (config.ecosystems.includes('npm')) commands.push(...npmCommands(selected.npm, config.npm, problems))
  return { selected, excluded, problems, commands }
}

// cargo-audit reads `.cargo/audit.toml` relative to its working directory,
// so each lockfile is audited from its own directory; manifest ignores add to
// that file's ignores.
function cargoCommands(lockfiles, cargo) {
  const ignores = cargo.ignore.flatMap((entry) => ['--ignore', entry.id])
  return lockfiles.map((path) => ({
    label: `cargo audit ${path}`,
    argv: ['cargo', 'audit', '--file', 'Cargo.lock', ...ignores, ...cargo.args],
    cwd: dirname(path),
  }))
}

function npmCommands(lockfiles, npm, problems) {
  if (npm.mode === 'command') {
    const declared = new Set(npm.covers)
    const missing = lockfiles.filter((path) => !declared.has(path))
    const extra = npm.covers.filter((path) => !lockfiles.includes(path))
    for (const path of missing) problems.push(`npm lockfile not covered by npm.command: ${path}`)
    for (const path of extra) problems.push(`npm.covers lists a lockfile that was not discovered: ${path}`)
    if (lockfiles.length === 0) return []
    const argv = typeof npm.command === 'string' ? ['bash', '-o', 'pipefail', '-ec', npm.command] : npm.command
    return [{ label: 'npm audit command', argv, cwd: '.', env: { CI_LOCAL_NPM_LOCKFILES: lockfiles.join('\n') } }]
  }
  return lockfiles.map((path) => ({
    label: `npm audit ${path}`,
    argv: ['npm', 'audit', '--package-lock-only', `--audit-level=${npm.auditLevel}`, ...npm.args],
    cwd: dirname(path),
  }))
}
