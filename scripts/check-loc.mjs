import { readFileSync, readdirSync, statSync } from 'node:fs'
import { extname, join, relative } from 'node:path'

const repoRoot = new URL('..', import.meta.url).pathname.replace(/\/$/, '')
const baselinePath = join(repoRoot, 'scripts/loc-baseline.json')
const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))

const maxLines = Number(baseline.maxLines ?? 1000)
const roots = baseline.roots ?? ['src', 'static', 'tests', 'scripts']
const extensions = new Set(baseline.extensions ?? ['.rs', '.js', '.mjs', '.ts', '.css', '.html'])
const excludePrefixes = baseline.excludePrefixes ?? ['static/vendor/']
const excludeSuffixes = baseline.excludeSuffixes ?? ['.min.js']
const allow = baseline.allow ?? {}

function relPath(path) {
  return relative(repoRoot, path).replaceAll('\\', '/')
}

function isExcluded(rel) {
  return excludePrefixes.some((prefix) => rel === prefix.replace(/\/$/, '') || rel.startsWith(prefix))
    || excludeSuffixes.some((suffix) => rel.endsWith(suffix))
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    const rel = relPath(path)
    if (isExcluded(rel)) continue
    const stat = statSync(path)
    if (stat.isDirectory()) {
      walk(path, out)
    } else if (extensions.has(extname(path))) {
      out.push(path)
    }
  }
  return out
}

function lineCount(path) {
  const text = readFileSync(path, 'utf8')
  if (!text) return 0
  return text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length
}

function allowedMax(entry) {
  return Number(entry?.linesAtBaseline ?? maxLines)
}

const files = roots.flatMap((root) => walk(join(repoRoot, root)))
const violations = []
const stale = []
const seen = new Set()

for (const file of files) {
  const rel = relPath(file)
  const lines = lineCount(file)
  const allowed = allow[rel]

  if (allowed) {
    seen.add(rel)
    if (!allowed.reason) {
      violations.push(`${rel} is allowlisted without a reason`)
      continue
    }
    if (lines <= maxLines) {
      stale.push(`${rel} is now ${lines} LOC; remove it from scripts/loc-baseline.json`)
      continue
    }
    const ceiling = allowedMax(allowed)
    if (lines > ceiling) {
      violations.push(`${rel} has grown to ${lines} LOC (baseline ${ceiling})`)
    }
    continue
  }

  if (lines > maxLines) violations.push(`${rel} has ${lines} LOC (max ${maxLines})`)
}

for (const rel of Object.keys(allow)) {
  if (!seen.has(rel)) stale.push(`${rel} is listed in scripts/loc-baseline.json but no longer exists`)
}

if (violations.length || stale.length) {
  if (violations.length) {
    console.error('LOC guard failed. Split these files or add a documented baseline entry:')
    for (const violation of violations) console.error(`- ${violation}`)
  }
  if (stale.length) {
    console.error('LOC baseline cleanup needed:')
    for (const item of stale) console.error(`- ${item}`)
  }
  process.exit(1)
}

console.log(`LOC guard passed: no unbaselined source file exceeds ${maxLines} LOC.`)
