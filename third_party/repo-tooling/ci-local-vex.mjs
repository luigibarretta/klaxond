// Advisory ignores for audit-all-lockfiles: OpenVEX `not_affected`
// statements and manifest ignores with a reason and an optional expiry.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { expiryStatus } from './policy-dates.mjs'
import { isPlainObject } from './ci-local-util.mjs'

// OpenVEX v0.2.0 justifications for `not_affected`.
export const VEX_JUSTIFICATIONS = new Set([
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
])

// A statement product matches a declared product exactly or as the same
// package URL with a version (`pkg:cargo/x` matches `pkg:cargo/x@1.2.3`).
export function productMatches(statementProduct, declared) {
  return declared.some((product) => statementProduct === product || statementProduct.startsWith(`${product}@`))
}

// Loads every OpenVEX document named by `paths` (files, or directories whose
// *.openvex.json files are all read). A `not_affected` statement applies
// only when one of its products is among `products` (the step's
// `vexProducts`). Returns { ids, applied, notices, errors } where `ids` maps
// each applied vulnerability name and alias to its document.
export function loadVex(root, paths, products = []) {
  const state = { ids: new Map(), applied: [], notices: [], errors: [], products }
  for (const entry of paths) {
    const full = resolve(root, entry)
    if (!existsSync(full)) {
      state.errors.push(`vex path does not exist: ${entry}`)
      continue
    }
    const files = statSync(full).isDirectory()
      ? readdirSync(full).filter((name) => name.endsWith('.openvex.json')).sort().map((name) => join(entry, name))
      : [entry]
    if (files.length === 0) state.errors.push(`vex directory has no *.openvex.json file: ${entry}`)
    for (const file of files) readVexDocument(root, file, state)
  }
  return state
}

function readVexDocument(root, file, state) {
  let document
  try {
    document = JSON.parse(readFileSync(resolve(root, file), 'utf8'))
  } catch (error) {
    state.errors.push(`cannot parse ${file}: ${error.message}`)
    return
  }
  if (!isPlainObject(document) || !String(document['@context'] ?? '').startsWith('https://openvex.dev/ns') || !Array.isArray(document.statements)) {
    state.errors.push(`${file} is not an OpenVEX document (@context https://openvex.dev/ns/..., statements[])`)
    return
  }
  for (const [index, statement] of document.statements.entries()) readStatement(file, index, statement, state)
}

function readStatement(file, index, statement, state) {
  const name = statement?.vulnerability?.name
  const where = `${file} statements[${index}]`
  if (typeof name !== 'string' || typeof statement.status !== 'string') {
    state.errors.push(`${where} needs vulnerability.name and status`)
    return
  }
  if (statement.status !== 'not_affected') return
  const products = Array.isArray(statement.products) ? statement.products.map((product) => product?.['@id']) : []
  if (products.length === 0 || !products.every((id) => typeof id === 'string' && id !== '')) {
    state.errors.push(`${where} (${name}) is not_affected without products[].@id`)
    return
  }
  if (!VEX_JUSTIFICATIONS.has(statement.justification)) {
    state.errors.push(`${where} (${name}) needs a justification among ${[...VEX_JUSTIFICATIONS].join(', ')}`)
    return
  }
  const matched = products.filter((id) => productMatches(id, state.products))
  if (matched.length === 0) {
    state.notices.push(`VEX ${name} in ${file} not applied: products ${products.join(', ')} are not in vexProducts`)
    return
  }
  const aliases = Array.isArray(statement.vulnerability.aliases) ? statement.vulnerability.aliases.filter((alias) => typeof alias === 'string') : []
  for (const id of [name, ...aliases]) state.ids.set(id, file)
  state.applied.push(`${[name, ...aliases].join('/')} for ${matched.join(', ')} (${statement.justification})`)
}

// Applies expiry and provenance rules to manifest ignores for one ecosystem.
// Returns { ids, problems, notices }: expired ignores are problems (the step
// fails before any audit runs); expiring ones, and ignores backed by neither
// a VEX statement nor an `until`, are notices.
export function resolveIgnores(ecosystem, ignores, vexIds, today) {
  const ids = []
  const problems = []
  const notices = []
  for (const entry of ignores) {
    const label = `${ecosystem} ignore ${entry.id}`
    if (entry.until !== undefined) {
      const status = expiryStatus(entry.until, today)
      if (status.state === 'expired') {
        problems.push(`${label} expired on ${entry.until}; re-assess the advisory and renew or remove the ignore`)
        continue
      }
      if (status.state === 'expiring') notices.push(`${label} expires on ${entry.until} (${status.daysLeft} day(s) left)`)
    } else if (!vexIds.has(entry.id)) {
      notices.push(`${label} has neither a VEX statement nor an until date`)
    }
    ids.push(entry.id)
  }
  return { ids, problems, notices }
}

// Ids the ecosystem's scanner understands; aliases are passed only where the
// scanner matches them (pip-audit and govulncheck do, cargo-audit does not).
export function vexIdsFor(ecosystem, vexIds) {
  const all = [...vexIds.keys()]
  if (ecosystem === 'cargo') return all.filter((id) => id.startsWith('RUSTSEC-'))
  return all
}
