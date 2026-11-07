// Source discovery and physical line counting shared by the LOC guard and the
// NASA/JPL warning profile.
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'

export const DEFAULT_IGNORED_DIRS = new Set([
  '.git',
  '.next',
  '.turbo',
  '__pycache__',
  'coverage',
  'dist',
  'node_modules',
  'target',
])

// A trailing newline ends the last line; an empty file has zero lines.
export function countLines(text) {
  if (!text) return 0
  return text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length
}

export function lineCount(filePath) {
  return countLines(readFileSync(filePath, 'utf8'))
}

export function toRepoPath(repoRoot, filePath) {
  return relative(repoRoot, filePath).split(sep).join('/')
}

export function matchIgnore(rel, ignoredPaths) {
  for (const ignored of ignoredPaths) {
    if (rel === ignored || rel.startsWith(ignored + '/')) return ignored
  }
  return null
}

// Walks every root without following symbolic links (neither directories
// nor files, nor a root that is itself a link), so a link can never pull
// content from outside the repository. Returns absolute file paths, the
// ignore entries that matched something, the roots that do not exist and
// errors (linked roots, unreadable directories).
export function walkSources({ repoRoot, roots, extensions, ignoredPaths }) {
  const state = { repoRoot, extensionSet: new Set(extensions), ignoreList: [...ignoredPaths], files: [], seenIgnore: new Set(), errors: [] }
  const missingRoots = []
  for (const root of roots) {
    const fullPath = join(repoRoot, root)
    if (!existsSync(fullPath) && !isLink(fullPath)) {
      missingRoots.push(root)
      continue
    }
    if (isLink(fullPath)) {
      state.errors.push(`root ${root} is a symbolic link; list the real directory instead`)
      continue
    }
    walk(fullPath, state)
  }
  return { files: state.files, seenIgnore: state.seenIgnore, missingRoots, errors: state.errors }
}

function isLink(path) {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch {
    return false
  }
}

function walk(dir, state) {
  const ignoredRoot = matchIgnore(toRepoPath(state.repoRoot, dir), state.ignoreList)
  if (ignoredRoot) {
    state.seenIgnore.add(ignoredRoot)
    return
  }
  let entries
  try {
    entries = readdirSync(dir).sort()
  } catch (error) {
    state.errors.push(`cannot read ${toRepoPath(state.repoRoot, dir) || '.'}: ${error.code ?? error.message}`)
    return
  }
  for (const entry of entries) {
    if (DEFAULT_IGNORED_DIRS.has(entry)) continue
    const filePath = join(dir, entry)
    const ignored = matchIgnore(toRepoPath(state.repoRoot, filePath), state.ignoreList)
    if (ignored) {
      state.seenIgnore.add(ignored)
      continue
    }
    const stat = lstatSync(filePath)
    if (stat.isSymbolicLink()) continue
    if (stat.isDirectory()) walk(filePath, state)
    else if (stat.isFile() && state.extensionSet.has(extname(filePath))) state.files.push(filePath)
  }
}
