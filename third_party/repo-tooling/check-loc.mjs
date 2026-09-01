import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { extname, join, relative, resolve, sep } from 'node:path'
const repoRoot = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
const baselinePath = resolve(repoRoot, process.env.LOC_BASELINE || 'scripts/loc-baseline.json')
const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))

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

const baselineErrors = []
const baselineKeys = new Set(['maxLines', 'allowedGrowthLines', 'roots', 'extensions', 'ignore', 'allow'])
for (const key of Object.keys(baseline)) {
  if (!baselineKeys.has(key)) baselineErrors.push('unknown top-level baseline key: ' + key)
}

const maxLines = asNonNegativeInteger(baseline.maxLines ?? 400, 'maxLines', { min: 1 })
const allowedGrowthLines = asNonNegativeInteger(
  baseline.allowedGrowthLines ?? 0,
  'allowedGrowthLines',
)
const roots = asStringArray(baseline.roots, 'roots')
const extensions = asStringArray(baseline.extensions, 'extensions')
const allow = asObject(baseline.allow ?? {}, 'allow')
const ignore = asObject(baseline.ignore ?? {}, 'ignore')

if (extensions.length === 0) {
  baselineErrors.push('extensions must contain at least one extension')
}
for (const ext of extensions) {
  if (!ext.startsWith('.')) baselineErrors.push('extension ' + ext + ' must start with "."')
}
for (const root of roots) validateRepoPath(root, 'root ' + root)
for (const rel of Object.keys(allow)) validateRepoPath(rel, 'allow entry ' + rel)
for (const rel of Object.keys(ignore)) validateRepoPath(rel, 'ignore entry ' + rel)

for (const [rel, entry] of Object.entries(allow)) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    baselineErrors.push('allow entry ' + rel + ' must be an object')
    continue
  }
  const linesAtBaseline = asNonNegativeInteger(
    entry.linesAtBaseline,
    'allow entry ' + rel + '.linesAtBaseline',
    { min: 1 },
  )
  if (Number.isFinite(maxLines) && Number.isFinite(linesAtBaseline) && linesAtBaseline <= maxLines) {
    baselineErrors.push(
      'allow entry ' + rel + '.linesAtBaseline must be greater than maxLines (' + maxLines + ')',
    )
  }
  if (typeof entry.reason !== 'string' || entry.reason.trim().length === 0) {
    baselineErrors.push('allow entry ' + rel + ' must include a non-empty reason')
  }
}

for (const [rel, entry] of Object.entries(ignore)) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    baselineErrors.push('ignore entry ' + rel + ' must be an object')
    continue
  }
  if (typeof entry.reason !== 'string' || entry.reason.trim().length === 0) {
    baselineErrors.push('ignore entry ' + rel + ' must include a non-empty reason')
  }
}

if (!Array.isArray(baseline.roots) || roots.length === 0) {
  baselineErrors.push('roots must contain at least one source root')
}

function asNonNegativeInteger(value, label, options = {}) {
  const number = Number(value)
  const min = options.min ?? 0
  if (!Number.isInteger(number) || number < min) {
    baselineErrors.push(label + ' must be an integer >= ' + min)
    return Number.NaN
  }
  return number
}

function asStringArray(value, label) {
  if (!Array.isArray(value)) {
    baselineErrors.push(label + ' must be an array of strings')
    return []
  }
  const normalized = []
  for (const item of value) {
    if (typeof item !== 'string' || item.trim().length === 0) {
      baselineErrors.push(label + ' entries must be non-empty strings')
      continue
    }
    normalized.push(item)
  }
  return normalized
}

function asObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    baselineErrors.push(label + ' must be an object')
    return {}
  }
  return value
}

function validateRepoPath(rel, label) {
  if (typeof rel !== 'string' || rel.length === 0) {
    baselineErrors.push(label + ' must be a non-empty relative path')
    return
  }
  if (rel.includes('\\')) baselineErrors.push(label + ' must use forward slashes')
  if (rel.startsWith('/') || rel.match(/^[A-Za-z]:/)) {
    baselineErrors.push(label + ' must be relative to the repository root')
  }
  if (rel.split('/').includes('..')) baselineErrors.push(label + ' must not contain .. segments')
  if (rel !== rel.replace(/\\/g, '/')) baselineErrors.push(label + ' is not normalized')
}

function toRepoPath(filePath) {
  return relative(repoRoot, filePath).split(sep).join('/')
}

function ignoreMatch(rel) {
  for (const ignored of Object.keys(ignore)) {
    if (rel === ignored || rel.startsWith(ignored + '/')) return ignored
  }
  return null
}

function walk(dir, out = [], seenIgnore = new Set()) {
  const rootRel = toRepoPath(dir)
  const ignoredRoot = ignoreMatch(rootRel)
  if (ignoredRoot) {
    seenIgnore.add(ignoredRoot)
    return out
  }

  for (const entry of readdirSync(dir)) {
    if (defaultIgnoredDirs.has(entry)) continue

    const filePath = join(dir, entry)
    const rel = toRepoPath(filePath)
    const ignored = ignoreMatch(rel)
    if (ignored) {
      seenIgnore.add(ignored)
      continue
    }

    const stat = statSync(filePath)
    if (stat.isDirectory()) {
      walk(filePath, out, seenIgnore)
    } else if (extensions.includes(extname(filePath))) {
      out.push(filePath)
    }
  }
  return out
}

function lineCount(filePath) {
  const text = readFileSync(filePath, 'utf8')
  if (!text) return 0
  return text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length
}

const files = []
const seenIgnore = new Set()
for (const root of roots) {
  const fullPath = join(repoRoot, root)
  if (!existsSync(fullPath)) {
    baselineErrors.push('LOC root does not exist: ' + root)
    continue
  }
  walk(fullPath, files, seenIgnore)
}

const violations = []
const stale = []
const seenAllow = new Set()

for (const file of files) {
  const rel = toRepoPath(file)
  const lines = lineCount(file)
  const allowEntry = allow[rel]

  if (allowEntry) {
    seenAllow.add(rel)
    const linesAtBaseline = Number(allowEntry.linesAtBaseline)
    if (lines <= maxLines) {
      stale.push(rel + ' is now ' + lines + ' LOC; remove it from scripts/loc-baseline.json')
    } else if (Number.isFinite(linesAtBaseline) && lines > linesAtBaseline + allowedGrowthLines) {
      violations.push(
        rel + ' grew to ' + lines + ' LOC (baseline ' + linesAtBaseline + ', allowed growth ' + allowedGrowthLines + ')',
      )
    }
    continue
  }

  if (lines > maxLines) violations.push(rel + ' has ' + lines + ' LOC (max ' + maxLines + ')')
}

for (const rel of Object.keys(allow)) {
  if (!seenAllow.has(rel)) {
    stale.push(rel + ' is listed in scripts/loc-baseline.json but no longer exists')
  }
}

for (const rel of Object.keys(ignore)) {
  if (!seenIgnore.has(rel)) {
    stale.push(rel + ' is ignored in scripts/loc-baseline.json but no longer exists')
  }
}

if (baselineErrors.length || violations.length || stale.length) {
  if (baselineErrors.length) {
    console.error('LOC baseline is invalid:')
    for (const error of baselineErrors) console.error('- ' + error)
  }
  if (violations.length) {
    console.error('LOC guard failed. Split these files or update a documented baseline intentionally:')
    for (const violation of violations) console.error('- ' + violation)
  }
  if (stale.length) {
    console.error('LOC baseline cleanup needed:')
    for (const item of stale) console.error('- ' + item)
  }
  process.exit(1)
}

console.log(
  'LOC guard passed: checked ' + files.length + ' files, max ' + maxLines + ' LOC, '
    + Object.keys(allow).length + ' documented baselines, '
    + Object.keys(ignore).length + ' documented ignores, growth budget ' + allowedGrowthLines + ' LOC.',
)
