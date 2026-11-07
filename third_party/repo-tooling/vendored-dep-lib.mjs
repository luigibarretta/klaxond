// Verification of vendored copies of other repositories: byte identity with
// the upstream tree at the pinned commit (read from git objects, so any clone
// that contains the commit works) and/or a recorded tree digest.
import { createHash } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { git } from './ci-local-git.mjs'

const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/

export function isExcluded(rel, exclude) {
  return exclude.some((entry) => rel === entry || rel.startsWith(entry.replace(/\/$/, '') + '/'))
}

// Lists regular files and symlinks below `dir` (never following links).
export function listLocalTree(dir, exclude = [], prefix = '', out = []) {
  for (const name of readdirSync(join(dir, prefix)).sort()) {
    const rel = prefix ? `${prefix}/${name}` : name
    if (isExcluded(rel, exclude)) continue
    const stat = lstatSync(join(dir, rel))
    if (stat.isSymbolicLink()) out.push({ rel, kind: 'link' })
    else if (stat.isDirectory()) listLocalTree(dir, exclude, rel, out)
    else if (stat.isFile()) out.push({ rel, kind: 'file' })
  }
  return out
}

// "sha256sum-tree-v1": identical to
//   cd DIR && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
// (regular files only, paths as "./rel", byte order), so existing
// dependencies/*.sha256 files stay valid.
export function treeDigest(dir, exclude = []) {
  const entries = listLocalTree(dir, exclude)
    .filter((entry) => entry.kind === 'file')
    .map((entry) => `./${entry.rel}`)
    .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
  const listing = entries.map((path) => `${sha256(readFileSync(join(dir, path)))}  ${path}\n`).join('')
  return sha256(Buffer.from(listing))
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function blobHash(content, objectHashLength) {
  const algorithm = objectHashLength === 64 ? 'sha256' : 'sha1'
  return createHash(algorithm).update(`blob ${content.length}\0`).update(content).digest('hex')
}

function localContent(path, kind) {
  return kind === 'link' ? Buffer.from(readlinkSync(path)) : readFileSync(path)
}

export function resolveCheckout(root, candidates) {
  for (const candidate of candidates.filter(Boolean)) {
    const path = isAbsolute(candidate) ? candidate : resolve(root, candidate)
    if (ownRepository(path)) return path
  }
  return null
}

// True when `path` is itself a clone, a linked worktree or submodule (whose
// `.git` is a file) or a bare repository, not merely a directory inside
// another repository such as the consumer's own checkout.
export function ownRepository(path) {
  if (!existsSync(path)) return false
  const real = realpathSync(path)
  const top = git(path, ['rev-parse', '--show-toplevel'])
  if (top.ok && top.stdout.trim() !== '') return realpathSync(top.stdout.trim()) === real
  const bare = git(path, ['rev-parse', '--is-bare-repository', '--absolute-git-dir'])
  if (!bare.ok) return false
  const [isBare, gitDir] = bare.stdout.trim().split('\n')
  return isBare === 'true' && gitDir === real
}

// A remote must not be readable as a git option.
export function validRemote(url) {
  return typeof url === 'string' && url.trim() !== '' && !url.startsWith('-')
}

export function hasCommit(checkout, pin) {
  return git(checkout, ['cat-file', '-e', `${pin}^{commit}`]).ok
}

// Fetches only the pinned commit into `checkout`. A clone created here is
// also checked out at the pin (so the upstream's own tests can run from it);
// an existing clone's working tree is never touched.
export function fetchPinned(checkout, url, pin) {
  if (!validRemote(url)) return `refusing remote ${JSON.stringify(url)}: it must not start with "-"`
  if (!validPin(pin)) return `refusing to fetch ${JSON.stringify(pin)}: not a full commit SHA`
  mkdirSync(checkout, { recursive: true })
  const created = !ownRepository(checkout)
  if (created) {
    const init = git(checkout, ['init', '--quiet'])
    if (!init.ok) return `git init ${checkout} failed: ${init.stderr.trim()}`
  }
  const fetch = git(checkout, ['fetch', '--quiet', '--depth=1', '--end-of-options', url, `+${pin}:refs/remotes/origin/pinned`])
  if (!fetch.ok) return `git fetch ${url} ${pin} failed: ${fetch.stderr.trim()}`
  if (!created) return null
  const checkedOut = git(checkout, ['checkout', '--quiet', '--detach', pin])
  return checkedOut.ok ? null : `git checkout ${pin} in ${checkout} failed: ${checkedOut.stderr.trim()}`
}

// Upstream entries at `pin` below `subdir`: Map rel -> { mode, type, hash }.
function upstreamTree(checkout, pin, subdir, exclude, problems) {
  if (!hasCommit(checkout, pin)) {
    problems.push(`pinned commit ${pin} is not in ${checkout}; fetch it (or run with --fetch)`)
    return null
  }
  const prefix = subdir ? subdir.replace(/\/$/, '') + '/' : ''
  const listed = git(checkout, ['ls-tree', '-r', '-z', '--full-tree', pin, ...(prefix ? ['--', prefix] : [])])
  if (!listed.ok) {
    problems.push(`cannot list ${pin} in ${checkout}: ${listed.stderr.trim()}`)
    return null
  }
  const tree = new Map()
  for (const record of listed.stdout.split('\0').filter(Boolean)) {
    const [meta, path] = record.split('\t')
    const [mode, type, hash] = meta.split(' ')
    const rel = path.slice(prefix.length)
    if (!isExcluded(rel, exclude)) tree.set(rel, { mode, type, hash })
  }
  if (tree.size === 0) problems.push(`upstream ${subdir || '/'} is empty at ${pin}`)
  return tree
}

function compareEntry(rel, upstream, localPath, problems) {
  if (!upstream) return problems.push(`${rel}: not in upstream at the pinned commit`)
  if (upstream.type !== 'blob') return problems.push(`${rel}: upstream ${upstream.type} entries are not supported`)
  if (!existsSync(localPath) && !isLink(localPath)) return problems.push(`${rel}: missing from the vendored copy`)
  const kind = isLink(localPath) ? 'link' : 'file'
  if ((upstream.mode === '120000') !== (kind === 'link')) return problems.push(`${rel}: symlink/file mismatch with upstream`)
  if (blobHash(localContent(localPath, kind), upstream.hash.length) !== upstream.hash) problems.push(`${rel}: differs from upstream`)
}

function isLink(path) {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch {
    return false
  }
}

// Byte comparison of a vendored tree (`path`) or of single files (`files`:
// upstream rel -> local rel) with the upstream at `pin`.
export function compareWithUpstream(root, dep, checkout) {
  const problems = []
  const tree = upstreamTree(checkout, dep.pin, dep.subdir, dep.exclude, problems)
  if (!tree) return { problems, count: 0 }
  if (dep.files) {
    for (const [upstreamRel, localRel] of Object.entries(dep.files)) {
      compareEntry(`${localRel} (upstream ${upstreamRel})`, tree.get(upstreamRel), join(root, localRel), problems)
    }
    return { problems, count: Object.keys(dep.files).length }
  }
  const vendored = join(root, dep.path)
  if (!existsSync(vendored)) return { problems: [`vendored path ${dep.path} does not exist`], count: 0 }
  const local = listLocalTree(vendored, dep.exclude)
  for (const { rel } of local) compareEntry(rel, tree.get(rel), join(vendored, rel), problems)
  const localSet = new Set(local.map((entry) => entry.rel))
  for (const rel of tree.keys()) if (!localSet.has(rel)) problems.push(`${rel}: missing from the vendored copy`)
  return { problems, count: tree.size }
}

export function validPin(value) {
  return typeof value === 'string' && COMMIT.test(value)
}
