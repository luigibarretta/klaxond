// Declarative manifest of vendored dependencies (dependencies/vendored.json)
// and the built-in entry for repo-tooling's own vendored dist/.
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { isPlainObject, nonEmptyString, rejectUnknown, relativePath } from './ci-local-util.mjs'
import { validPin, validRemote } from './vendored-dep-lib.mjs'

export const DEFAULT_MANIFEST = 'dependencies/vendored.json'
const DEP_KEYS = new Set(['name', 'path', 'files', 'pin', 'pinFile', 'upstream', 'treeSha256', 'treeSha256File', 'exclude', 'description'])
const UPSTREAM_KEYS = new Set(['checkout', 'url', 'subdir', 'required'])
const NAME = /^[a-z0-9][a-z0-9._-]*$/

// The repo-tooling self-check: third_party/repo-tooling against dist/ of the
// commit in dependencies/repo-tooling.sha, from the first available clone.
export function repoToolingEntry(options) {
  return {
    name: 'repo-tooling',
    path: options.path ?? 'third_party/repo-tooling',
    pinFile: options.pinFile ?? 'dependencies/repo-tooling.sha',
    upstream: {
      checkout: [options.upstream, process.env.REPO_TOOLING_UPSTREAM, 'vendor/repo-tooling', '.ci/repo-tooling'].filter(Boolean),
      url: options.url,
      subdir: 'dist',
      required: true,
    },
  }
}

export function loadVendoredManifest(root, path) {
  const full = resolve(root, path)
  if (!existsSync(full)) throw new Error(`no vendored-dependency manifest at ${path}`)
  let raw
  try {
    raw = JSON.parse(readFileSync(full, 'utf8'))
  } catch (error) {
    throw new Error(`cannot parse ${path}: ${error.message}`)
  }
  const errors = []
  if (!isPlainObject(raw)) throw new Error(`${path} must be a JSON object`)
  rejectUnknown(raw, new Set(['schemaVersion', 'dependencies']), 'manifest', errors)
  if (raw.schemaVersion !== 1) errors.push('schemaVersion must equal 1')
  if (!Array.isArray(raw.dependencies) || raw.dependencies.length === 0) errors.push('dependencies must be a non-empty array')
  const names = new Set()
  for (const [index, dep] of (raw.dependencies ?? []).entries()) {
    validateEntry(dep, `dependencies[${index}]`, errors)
    if (names.has(dep?.name)) errors.push(`duplicate dependency name: ${dep.name}`)
    names.add(dep?.name)
  }
  if (errors.length) throw new Error(`invalid ${path}:\n  - ${errors.join('\n  - ')}`)
  return { raw, path: full }
}

function validateEntry(dep, label, errors) {
  if (!isPlainObject(dep)) return errors.push(`${label} must be an object`)
  const where = NAME.test(dep.name ?? '') ? `dependency ${dep.name}` : label
  if (!NAME.test(dep.name ?? '')) errors.push(`${label}.name must match ${NAME}`)
  rejectUnknown(dep, DEP_KEYS, where, errors)
  if ((dep.path === undefined) === (dep.files === undefined)) errors.push(`${where} must set exactly one of path or files`)
  if (dep.path !== undefined && !relativePath(dep.path)) errors.push(`${where}.path must be a relative path inside the repository`)
  if (dep.files !== undefined) {
    const valid = isPlainObject(dep.files) && Object.keys(dep.files).length > 0 &&
      Object.entries(dep.files).every(([from, to]) => relativePath(from) && relativePath(to))
    if (!valid) errors.push(`${where}.files must map upstream paths to repository paths`)
    if (dep.treeSha256 !== undefined || dep.treeSha256File !== undefined) errors.push(`${where}: a tree digest needs path, not files`)
  }
  if ((dep.pin === undefined) === (dep.pinFile === undefined)) errors.push(`${where} must set exactly one of pin or pinFile`)
  if (dep.pin !== undefined && !validPin(dep.pin)) errors.push(`${where}.pin must be a full commit SHA`)
  if (dep.pinFile !== undefined && !relativePath(dep.pinFile)) errors.push(`${where}.pinFile must be a relative path`)
  if (dep.treeSha256 !== undefined && dep.treeSha256File !== undefined) errors.push(`${where} sets both treeSha256 and treeSha256File`)
  if (dep.treeSha256 !== undefined && !/^[0-9a-f]{64}$/.test(dep.treeSha256)) errors.push(`${where}.treeSha256 must be 64 hex characters`)
  if (dep.treeSha256File !== undefined && !relativePath(dep.treeSha256File)) errors.push(`${where}.treeSha256File must be a relative path`)
  if (dep.exclude !== undefined && !(Array.isArray(dep.exclude) && dep.exclude.every(relativePath))) {
    errors.push(`${where}.exclude must be an array of relative paths`)
  }
  validateUpstream(dep, where, errors)
}

function validateUpstream(dep, where, errors) {
  const hasDigest = dep.treeSha256 !== undefined || dep.treeSha256File !== undefined
  if (dep.upstream === undefined) {
    if (!hasDigest) errors.push(`${where} needs an upstream, a tree digest, or both`)
    return
  }
  if (!isPlainObject(dep.upstream)) return errors.push(`${where}.upstream must be an object`)
  rejectUnknown(dep.upstream, UPSTREAM_KEYS, `${where}.upstream`, errors)
  const checkout = dep.upstream.checkout
  const checkouts = Array.isArray(checkout) ? checkout : [checkout]
  if (!checkouts.length || !checkouts.every(nonEmptyString)) errors.push(`${where}.upstream.checkout must be a path or a list of candidate paths`)
  if (dep.upstream.url !== undefined && !validRemote(dep.upstream.url)) errors.push(`${where}.upstream.url must be a git URL that does not start with "-"`)
  if (dep.upstream.subdir !== undefined && dep.upstream.subdir !== '' && !relativePath(dep.upstream.subdir)) {
    errors.push(`${where}.upstream.subdir must be a relative path`)
  }
  if (dep.upstream.required !== undefined && typeof dep.upstream.required !== 'boolean') errors.push(`${where}.upstream.required must be a boolean`)
}

// Resolves pin and digest files into a uniform entry.
export function resolveEntry(root, dep) {
  const problems = []
  const pin = dep.pin ?? readTrimmed(root, dep.pinFile, problems)
  if (pin !== null && !validPin(pin)) problems.push(`invalid commit pin in ${dep.pinFile}`)
  let digest = dep.treeSha256 ?? null
  if (dep.treeSha256File !== undefined) {
    digest = readTrimmed(root, dep.treeSha256File, problems)
    if (digest !== null && !/^[0-9a-f]{64}$/.test(digest)) problems.push(`invalid sha256 digest in ${dep.treeSha256File}`)
  }
  const upstream = dep.upstream
  const checkouts = upstream ? (Array.isArray(upstream.checkout) ? upstream.checkout : [upstream.checkout]) : []
  return {
    entry: {
      name: dep.name, path: dep.path, files: dep.files, pin, digest, exclude: dep.exclude ?? [],
      checkouts, url: upstream?.url, subdir: upstream?.subdir ?? '',
      upstreamRequired: upstream ? upstream.required ?? digest === null : false,
    },
    problems,
  }
}

function readTrimmed(root, rel, problems) {
  const path = resolve(root, rel)
  if (!existsSync(path)) {
    problems.push(`missing ${rel}`)
    return null
  }
  return readFileSync(path, 'utf8').trim()
}
