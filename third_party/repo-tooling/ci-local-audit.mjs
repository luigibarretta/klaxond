// Built-in audit-all-lockfiles step: discover every dependency lockfile in
// the repository and audit each one, fail closed. Cargo and npm are always
// discovered; Go modules and pip requirements only when a step declares them.
import { existsSync, readdirSync, statSync } from 'node:fs'
import { basename, dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isPlainObject, nonEmptyString, rejectUnknown, relativePath } from './ci-local-util.mjs'
import { loadVex, resolveIgnores, vexIdsFor } from './ci-local-vex.mjs'
import { isIsoDate, today } from './policy-dates.mjs'

export const LOCKFILES = { 'Cargo.lock': 'cargo', 'package-lock.json': 'npm', 'go.mod': 'go' }
export const ECOSYSTEMS = ['cargo', 'npm', 'go', 'pip']
export const OPTIONAL_ECOSYSTEMS = new Set(['go', 'pip'])
export const EXCLUDED_DIR_NAMES = new Set(['target', 'vendor', 'node_modules', 'third_party'])
const PIP_REQUIREMENTS = /^requirements(?:[-_.][A-Za-z0-9._-]+)?\.txt$/
const AUDIT_KEYS = new Set(['ecosystems', 'exclude', 'include', 'vex', 'vexProducts', 'cargo', 'npm', 'go', 'pip'])
const NPM_MODES = new Set(['npm-audit', 'command'])
const AUDIT_LEVELS = new Set(['info', 'low', 'moderate', 'high', 'critical'])
const GOVULNCHECK_HELPER = join(dirname(fileURLToPath(import.meta.url)), 'audit-govulncheck.mjs')
// Tools the optional ecosystems need, with an install hint for the failure.
export const TOOL_HINTS = {
  govulncheck: 'go install golang.org/x/vuln/cmd/govulncheck@latest',
  'pip-audit': 'pipx install pip-audit (or pip install pip-audit)',
}

export function ecosystemOf(fileName) {
  if (LOCKFILES[fileName]) return LOCKFILES[fileName]
  return PIP_REQUIREMENTS.test(fileName) ? 'pip' : null
}

export function validateAuditConfig(raw, where) {
  const errors = []
  rejectUnknown(raw, AUDIT_KEYS, where, errors)
  const ecosystems = raw.ecosystems ?? ['cargo', 'npm']
  if (!Array.isArray(ecosystems) || ecosystems.length === 0 || !ecosystems.every((e) => ECOSYSTEMS.includes(e))) {
    errors.push(`${where}.ecosystems must be a non-empty subset of ${JSON.stringify(ECOSYSTEMS)}`)
  }
  const exclude = reasonedList(raw.exclude, `${where}.exclude`, 'path', errors)
  const include = raw.include ?? []
  if (!Array.isArray(include) || !include.every(relativePath)) {
    errors.push(`${where}.include must be an array of relative directory paths`)
  }
  const vex = raw.vex ?? []
  if (!Array.isArray(vex) || !vex.every(relativePath)) errors.push(`${where}.vex must be an array of OpenVEX files or directories`)
  const vexProducts = raw.vexProducts ?? []
  if (!Array.isArray(vexProducts) || !vexProducts.every(nonEmptyString)) errors.push(`${where}.vexProducts must be an array of product ids (package URLs)`)
  const cargo = validateScanner(raw.cargo, `${where}.cargo`, errors)
  const npm = validateNpm(raw.npm ?? {}, `${where}.npm`, errors)
  const go = validateScanner(raw.go, `${where}.go`, errors)
  const pip = validateScanner(raw.pip, `${where}.pip`, errors)
  return { errors, config: { ecosystems, exclude, include, vex, vexProducts, cargo, npm, go, pip } }
}

function validateScanner(raw = {}, where, errors) {
  if (!isPlainObject(raw)) {
    errors.push(`${where} must be an object`)
    return { ignore: [], args: [] }
  }
  rejectUnknown(raw, new Set(['ignore', 'args']), where, errors)
  return { ignore: ignoreList(raw.ignore, `${where}.ignore`, errors), args: stringArray(raw.args, `${where}.args`, errors) }
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

// Advisory ignores: {"id", "reason", "until"?: "YYYY-MM-DD"}.
function ignoreList(raw, where, errors) {
  if (raw === undefined) return []
  const valid = Array.isArray(raw) && raw.every((entry) =>
    isPlainObject(entry) && nonEmptyString(entry.id) && nonEmptyString(entry.reason) &&
    Object.keys(entry).every((key) => ['id', 'reason', 'until'].includes(key)) &&
    (entry.until === undefined || isIsoDate(entry.until)))
  if (!valid) errors.push(`${where} entries must be {"id": ..., "reason": ...} with an optional "until": "YYYY-MM-DD"`)
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
    } else if (entry.isFile() && ecosystemOf(entry.name)) {
      found.add(relative(root, join(directory, entry.name)).split(sep).join('/'))
    }
  }
}

export function partitionLockfiles(lockfiles, exclude) {
  const used = new Set()
  const selected = Object.fromEntries(ECOSYSTEMS.map((ecosystem) => [ecosystem, []]))
  const excluded = []
  for (const path of lockfiles) {
    const rule = exclude.find((entry) => path === entry.path || path.startsWith(`${entry.path.replace(/\/$/, '')}/`))
    if (rule) {
      used.add(rule)
      excluded.push({ path, reason: rule.reason })
      continue
    }
    selected[ecosystemOf(path.split('/').pop())].push(path)
  }
  const stale = exclude.filter((entry) => !used.has(entry)).map((entry) => entry.path)
  return { selected, excluded, stale }
}

// Plans the subprocesses; the runner executes them with the step deadline.
// Go and pip files are considered only when some step declares the ecosystem,
// so manifests written before 0.6 keep their exact coverage rules.
export function planAudit(root, config, coveredElsewhere) {
  const problems = []
  const notices = []
  const declared = new Set([...config.ecosystems, ...coveredElsewhere])
  const discovered = discoverLockfiles(root, config.include)
    .filter((path) => !OPTIONAL_ECOSYSTEMS.has(ecosystemOf(basename(path))) || declared.has(ecosystemOf(basename(path))))
  const { selected, excluded, stale } = partitionLockfiles(discovered, config.exclude)
  for (const path of stale) problems.push(`exclude entry matches no lockfile (stale): ${path}`)
  for (const ecosystem of ECOSYSTEMS) {
    if (selected[ecosystem].length > 0 && !declared.has(ecosystem)) {
      problems.push(`${ecosystem} lockfiles found but no audit-all-lockfiles step covers ${ecosystem}: ${selected[ecosystem].join(', ')}`)
    }
  }
  const vex = loadVex(root, config.vex, config.vexProducts)
  problems.push(...vex.errors)
  notices.push(...vex.notices)
  const ignores = {}
  for (const ecosystem of ['cargo', 'go', 'pip']) {
    const resolved = resolveIgnores(ecosystem, config[ecosystem].ignore, vex.ids, today())
    problems.push(...resolved.problems)
    notices.push(...resolved.notices)
    ignores[ecosystem] = [...new Set([...resolved.ids, ...vexIdsFor(ecosystem, vex.ids)])]
  }
  const commands = []
  if (config.ecosystems.includes('cargo')) commands.push(...cargoCommands(selected.cargo, config.cargo, ignores.cargo))
  if (config.ecosystems.includes('npm')) commands.push(...npmCommands(selected.npm, config.npm, problems))
  if (config.ecosystems.includes('go')) commands.push(...goCommands(selected.go, config.go, ignores.go))
  if (config.ecosystems.includes('pip')) commands.push(...pipCommands(selected.pip, config.pip, ignores.pip))
  return { selected, excluded, problems, notices, commands, vexApplied: vex.applied }
}

// cargo-audit reads `.cargo/audit.toml` relative to its working directory,
// so each lockfile is audited from its own directory; manifest and VEX
// ignores add to that file's ignores.
function cargoCommands(lockfiles, cargo, ids) {
  const ignores = ids.flatMap((id) => ['--ignore', id])
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

// govulncheck has no ignore flag: a helper runs it with JSON output and
// fails only on called vulnerabilities that are not ignored.
function goCommands(modules, go, ids) {
  return modules.map((path) => ({
    label: `govulncheck ${path}`,
    argv: [process.execPath, GOVULNCHECK_HELPER, ...ids.flatMap((id) => ['--ignore', id]), '--', ...go.args],
    cwd: dirname(path),
    requiresTool: 'govulncheck',
  }))
}

function pipCommands(requirements, pip, ids) {
  return requirements.map((path) => ({
    label: `pip-audit ${path}`,
    argv: ['pip-audit', '-r', basename(path), ...ids.flatMap((id) => ['--ignore-vuln', id]), ...pip.args],
    cwd: dirname(path),
    requiresTool: 'pip-audit',
  }))
}
