#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs'
import { relative, resolve, sep } from 'node:path'

const repositoryRoot = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
const options = parseArguments(process.argv.slice(2))
const configPath = repositoryPath(
  options.config || process.env.RELEASE_CONTRACT || 'scripts/release-contract.json',
  'release contract',
)
const config = readJson(configPath)
const errors = []

validateObject(config, 'release contract')
rejectUnknownKeys(
  config,
  new Set(['schemaVersion', 'versionSources', 'requiredLiterals', 'tagPrefix']),
  'release contract',
)
if (config.schemaVersion !== 1) errors.push('schemaVersion must equal 1')

const versionSources = arrayValue(config.versionSources, 'versionSources')
if (versionSources.length === 0) errors.push('versionSources must contain at least one source')
const requiredLiterals = arrayValue(config.requiredLiterals ?? [], 'requiredLiterals')
const tagPrefix = stringValue(config.tagPrefix ?? 'v', 'tagPrefix', { allowEmpty: true })

const versions = []
for (const [index, source] of versionSources.entries()) {
  const label = 'versionSources[' + index + ']'
  if (!validateObject(source, label)) continue
  rejectUnknownKeys(source, new Set(['path', 'regex', 'flags', 'label']), label)
  const sourcePath = stringValue(source.path, label + '.path')
  const pattern = stringValue(source.regex, label + '.regex')
  const flags = stringValue(source.flags ?? 'm', label + '.flags', { allowEmpty: true })
  if (!sourcePath || !pattern) continue

  let matcher
  try {
    if (flags.includes('g') || flags.includes('y')) {
      errors.push(label + '.flags must not contain g or y')
      continue
    }
    matcher = new RegExp(pattern, flags)
  } catch (error) {
    errors.push(label + '.regex is invalid: ' + error.message)
    continue
  }

  const fullPath = repositoryPath(sourcePath, label + '.path')
  if (!existsSync(fullPath)) {
    errors.push(label + ' does not exist: ' + sourcePath)
    continue
  }
  const match = readFileSync(fullPath, 'utf8').match(matcher)
  if (!match || match.length !== 2 || !match[1]) {
    errors.push(label + ' must match exactly one non-empty capture group in ' + sourcePath)
    continue
  }
  const value = match[1].trim()
  if (!semanticVersion(value)) {
    errors.push((source.label || sourcePath) + ' produced an invalid semantic version: ' + value)
    continue
  }
  versions.push({ label: source.label || sourcePath, value })
}

const canonicalVersion = versions[0]?.value || ''
for (const version of versions) {
  if (version.value !== canonicalVersion) {
    errors.push(
      version.label + ' reports ' + version.value + ', expected ' + canonicalVersion,
    )
  }
}

for (const [index, literal] of requiredLiterals.entries()) {
  const label = 'requiredLiterals[' + index + ']'
  if (!validateObject(literal, label)) continue
  rejectUnknownKeys(literal, new Set(['path', 'template', 'label']), label)
  const literalPath = stringValue(literal.path, label + '.path')
  const template = stringValue(literal.template, label + '.template')
  if (!literalPath || !template || !canonicalVersion) continue
  if (!template.includes('{version}')) {
    errors.push(label + '.template must contain {version}')
    continue
  }
  const fullPath = repositoryPath(literalPath, label + '.path')
  if (!existsSync(fullPath)) {
    errors.push(label + ' does not exist: ' + literalPath)
    continue
  }
  const expected = template.replaceAll('{version}', canonicalVersion)
  if (!readFileSync(fullPath, 'utf8').includes(expected)) {
    errors.push((literal.label || literalPath) + ' does not contain: ' + expected)
  }
}

const releaseTag = options.tag ?? process.env.RELEASE_CONTRACT_TAG
if (releaseTag !== undefined && canonicalVersion) {
  const expectedTag = tagPrefix + canonicalVersion
  if (releaseTag !== expectedTag) {
    errors.push('release tag is ' + releaseTag + ', expected ' + expectedTag)
  }
}

if (errors.length > 0) {
  console.error('Release contract failed:')
  for (const error of errors) console.error('- ' + error)
  process.exit(1)
}

if (options.printVersion) {
  console.log(canonicalVersion)
} else {
  console.log(
    'Release contract passed: version ' + canonicalVersion + ', '
      + versions.length + ' synchronized source(s), '
      + requiredLiterals.length + ' required literal(s)'
      + (releaseTag === undefined ? '.' : ', tag ' + releaseTag + '.'),
  )
}

function parseArguments(argumentsList) {
  const parsed = { config: '', tag: undefined, printVersion: false }
  while (argumentsList.length > 0) {
    const argument = argumentsList.shift()
    if (argument === '--config' || argument === '--tag') {
      if (argumentsList.length === 0) failUsage('missing value for ' + argument)
      parsed[argument === '--config' ? 'config' : 'tag'] = argumentsList.shift()
    } else if (argument === '--print-version') {
      parsed.printVersion = true
    } else if (argument === '-h' || argument === '--help') {
      usage()
      process.exit(0)
    } else {
      failUsage('unknown argument: ' + argument)
    }
  }
  return parsed
}

function usage() {
  console.log('Usage: check-release-contract.mjs [--config PATH] [--tag vX.Y.Z] [--print-version]')
}

function failUsage(message) {
  console.error(message)
  usage()
  process.exit(2)
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    console.error('Cannot read release contract ' + path + ': ' + error.message)
    process.exit(1)
  }
}

function repositoryPath(path, label) {
  if (typeof path !== 'string' || path.length === 0) {
    console.error(label + ' must be a non-empty repository-relative path')
    process.exit(1)
  }
  const fullPath = resolve(repositoryRoot, path)
  const rel = relative(repositoryRoot, fullPath)
  if (rel === '..' || rel.startsWith('..' + sep) || resolve(path) === path) {
    console.error(label + ' must stay inside the repository root: ' + path)
    process.exit(1)
  }
  return fullPath
}

function validateObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(label + ' must be an object')
    return false
  }
  return true
}

function rejectUnknownKeys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) errors.push(label + ' has unknown key: ' + key)
  }
}

function arrayValue(value, label) {
  if (!Array.isArray(value)) {
    errors.push(label + ' must be an array')
    return []
  }
  return value
}

function stringValue(value, label, options = {}) {
  if (typeof value !== 'string' || (!options.allowEmpty && value.length === 0)) {
    errors.push(label + ' must be ' + (options.allowEmpty ? 'a string' : 'a non-empty string'))
    return ''
  }
  return value
}

function semanticVersion(value) {
  return /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value)
}
