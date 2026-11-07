#!/usr/bin/env node
// Verifies vendored dependencies: byte identity with the upstream at the
// pinned commit and/or the recorded tree digest. Replaces the per-repository
// check-repo-tooling-sync.sh and check-provider-kit.sh scripts.
import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { compareWithUpstream, fetchPinned, hasCommit, resolveCheckout, treeDigest } from './vendored-dep-lib.mjs'
import { DEFAULT_MANIFEST, loadVendoredManifest, repoToolingEntry, resolveEntry } from './vendored-dep-manifest.mjs'

const USAGE = `usage: check-vendored-dep [--manifest path] [--only a,b] [--require-upstream] [--fetch] [--update-digest]
       check-vendored-dep --repo-tooling [--upstream path] [--path dir] [--pin-file file] [--url url] [--fetch]`

function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    console.error(`check-vendored-dep: ${error.message}\n${USAGE}`)
    return 2
  }
  const root = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
  let deps
  let manifest = null
  try {
    if (options.repoTooling) {
      deps = [repoToolingEntry(options)]
    } else {
      manifest = loadVendoredManifest(root, options.manifest)
      deps = manifest.raw.dependencies.filter((dep) => !options.only || options.only.includes(dep.name))
      const unknown = (options.only ?? []).filter((name) => !manifest.raw.dependencies.some((dep) => dep.name === name))
      if (unknown.length) throw new Error(`unknown dependency: ${unknown.join(', ')}`)
    }
  } catch (error) {
    console.error(`check-vendored-dep: ${error.message}`)
    return 2
  }
  let failed = 0
  for (const dep of deps) {
    const outcome = verify(root, dep, options, manifest)
    for (const note of outcome.notes) console.log(`${dep.name}: ${note}`)
    if (outcome.problems.length === 0) continue
    failed += 1
    console.error(`${dep.name}: vendored copy does not match:`)
    for (const problem of outcome.problems.slice(0, 50)) console.error(`- ${problem}`)
    if (outcome.problems.length > 50) console.error(`- ... ${outcome.problems.length - 50} more`)
  }
  if (failed) return 1
  console.log(`vendored dependencies verified: ${deps.map((dep) => dep.name).join(', ')}`)
  return 0
}

function verify(root, dep, options, manifest) {
  const { entry, problems } = resolveEntry(root, dep)
  const notes = []
  if (problems.length) return { problems, notes }
  if (entry.path && (entry.digest !== null || options.updateDigest)) checkDigest(root, dep, entry, { options, manifest, problems, notes })
  if (entry.checkouts.length === 0) return { problems, notes }
  let checkout = resolveCheckout(root, entry.checkouts)
  if (options.fetch && entry.url && !(checkout && hasCommit(checkout, entry.pin))) {
    const target = checkout ?? resolve(root, entry.checkouts[0])
    const error = fetchPinned(target, entry.url, entry.pin)
    if (error) problems.push(error)
    else checkout = target
  }
  if (!checkout) {
    if (entry.upstreamRequired || options.requireUpstream) {
      problems.push(`upstream checkout is missing (looked for ${entry.checkouts.join(', ')}); clone it at ${entry.pin}` +
        (entry.url ? ' or run with --fetch' : ''))
    } else {
      notes.push(`upstream checkout not available; verified by digest only`)
    }
    return { problems, notes }
  }
  const compared = compareWithUpstream(root, entry, checkout)
  problems.push(...compared.problems)
  if (compared.problems.length === 0) notes.push(`byte-identical to upstream ${entry.pin} (${compared.count} file(s) from ${checkout})`)
  return { problems, notes }
}

function checkDigest(root, dep, entry, { options, manifest, problems, notes }) {
  const actual = treeDigest(join(root, entry.path), entry.exclude)
  if (options.updateDigest) {
    if (dep.treeSha256File) writeFileSync(resolve(root, dep.treeSha256File), actual + '\n')
    else if (manifest) {
      const raw = JSON.parse(readFileSync(manifest.path, 'utf8'))
      raw.dependencies.find((item) => item.name === dep.name).treeSha256 = actual
      writeFileSync(manifest.path, JSON.stringify(raw, null, 2) + '\n')
    }
    notes.push(`recorded tree digest ${actual}`)
    return
  }
  if (actual === entry.digest) notes.push(`tree digest ${actual} matches`)
  else problems.push(`tree digest is ${actual}, expected ${entry.digest} (after an intentional refresh: --update-digest)`)
}

function parseArguments(argv) {
  const options = { manifest: DEFAULT_MANIFEST, only: null, requireUpstream: false, fetch: false, updateDigest: false, repoTooling: false }
  const valued = { '--manifest': 'manifest', '--only': 'only', '--upstream': 'upstream', '--path': 'path', '--pin-file': 'pinFile', '--url': 'url' }
  const flags = { '--require-upstream': 'requireUpstream', '--fetch': 'fetch', '--update-digest': 'updateDigest', '--repo-tooling': 'repoTooling' }
  for (let index = 0; index < argv.length; index += 1) {
    const [flag, inline] = argv[index].includes('=') ? argv[index].split(/=(.*)/s) : [argv[index], undefined]
    if (valued[flag]) {
      const value = inline ?? argv[++index]
      if (!value) throw new Error(`${flag} requires a value`)
      options[valued[flag]] = value
    } else if (flags[flag] && inline === undefined) {
      options[flags[flag]] = true
    } else {
      throw new Error(`unknown argument: ${argv[index]}`)
    }
  }
  if (options.only) options.only = options.only.split(',').map((name) => name.trim()).filter(Boolean)
  const repoOnly = ['upstream', 'path', 'pinFile', 'url'].filter((key) => options[key] !== undefined)
  if (!options.repoTooling && repoOnly.length) throw new Error('--upstream, --path, --pin-file and --url need --repo-tooling')
  if (options.url !== undefined && options.url.startsWith('-')) throw new Error('--url must not start with "-"')
  if (options.repoTooling && (options.only || options.updateDigest)) throw new Error('--only and --update-digest do not apply to --repo-tooling')
  return options
}

process.exitCode = main(process.argv.slice(2))
