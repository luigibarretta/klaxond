#!/usr/bin/env node
// Keeps .env.example in step with the code (generalized from Quadro's
// scripts/check-env-example.mjs). Configured by scripts/env-example.json:
//   1. every variable the sources read has a `NAME=` entry in the example;
//   2. every example entry (also in extraExamples) is still read by the
//      sources, is a declared runtime variable, or is mentioned by a consumer
//      file (compose files, entrypoints, nginx templates);
//   3. sources never read a variable by a name built at run time.
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { isPlainObject, nonEmptyString, rejectUnknown, relativePath } from './ci-local-util.mjs'
import { toRepoPath, walkSources } from './loc-scan.mjs'

const NAME = '([A-Z][A-Z0-9_]*)'
export const LANGUAGES = {
  rust: { reads: [`env::var(?:_os)?\\(\\s*"${NAME}"`], dynamic: ['env::var(?:_os)?\\(\\s*&?format!'] },
  node: {
    reads: [`process\\.env\\.${NAME}\\b`, `process\\.env\\[\\s*['"]${NAME}['"]\\s*\\]`, `import\\.meta\\.env\\.${NAME}\\b`],
    dynamic: ['process\\.env\\[\\s*(?![\'"\\s])'],
  },
  python: {
    reads: [`os\\.environ\\[\\s*['"]${NAME}['"]`, `os\\.(?:environ\\.get|getenv)\\(\\s*['"]${NAME}['"]`],
    dynamic: ['os\\.(?:environ\\.get|getenv)\\(\\s*f[\'"]', 'os\\.environ\\[\\s*f[\'"]'],
  },
  go: { reads: [`os\\.(?:Getenv|LookupEnv)\\(\\s*"${NAME}"`], dynamic: ['os\\.(?:Getenv|LookupEnv)\\(\\s*[^"\\s)]'] },
}
const TOP_KEYS = new Set(['schemaVersion', 'example', 'extraExamples', 'sources', 'consumers', 'notVariables', 'internalPrefixes', 'runtimeVariables', 'forbidDynamicNames'])
const SOURCE_KEYS = new Set(['roots', 'extensions', 'language', 'patterns', 'excludePattern'])

function main() {
  const root = resolve(process.env.REPO_TOOLING_ROOT || process.cwd())
  const configPath = resolve(root, process.env.ENV_EXAMPLE_CONFIG || 'scripts/env-example.json')
  let config
  try {
    config = loadConfig(configPath)
  } catch (error) {
    console.error(`check-env-example: ${error.message}`)
    return 2
  }
  const problems = []
  const read = new Set()
  for (const source of config.sources) scanSource(root, source, config.forbidDynamicNames, read, problems)
  const required = [...read].filter((name) => !config.notVariables[name] && !config.internalPrefixes.some((prefix) => name.startsWith(prefix)))
  const example = entriesOf(root, config.example, problems)
  for (const name of required.sort()) {
    if (!example.has(name)) problems.push(`${name}: the code reads it; give it a "${name}=" entry in ${config.example}`)
  }
  const consumerText = config.consumers.flatMap((path) => filesUnder(root, path, problems)).map(uncommented).join('\n')
  for (const file of [config.example, ...config.extraExamples]) {
    const names = file === config.example ? example : entriesOf(root, file, problems)
    for (const name of [...names].sort()) {
      const used = read.has(name) || config.runtimeVariables[name] || new RegExp(`\\b${name}\\b`).test(consumerText)
      if (!used) problems.push(`${name}: listed in ${file} but read by nothing`)
    }
  }
  if (problems.length) {
    console.error(`env example drift (${problems.length}):`)
    for (const problem of problems) console.error(`- ${problem}`)
    return 1
  }
  console.log(`${config.example} lists all ${required.length} variable(s) the code reads; every entry is read.`)
  return 0
}

function loadConfig(path) {
  if (!existsSync(path)) throw new Error(`no configuration at ${path}`)
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  const errors = []
  if (!isPlainObject(raw)) throw new Error(`${path} must be a JSON object`)
  rejectUnknown(raw, TOP_KEYS, 'config', errors)
  if (raw.schemaVersion !== 1) errors.push('schemaVersion must equal 1')
  const example = raw.example ?? '.env.example'
  if (!relativePath(example)) errors.push('example must be a relative path')
  const pathList = (value, label) => {
    if (value === undefined) return []
    if (!Array.isArray(value) || !value.every(relativePath)) errors.push(`${label} must be an array of relative paths`)
    return Array.isArray(value) ? value : []
  }
  const reasons = (value, label) => {
    if (value === undefined) return {}
    if (!isPlainObject(value) || !Object.values(value).every(nonEmptyString)) errors.push(`${label} must map names to reasons`)
    return isPlainObject(value) ? value : {}
  }
  if (!Array.isArray(raw.sources) || raw.sources.length === 0) errors.push('sources must be a non-empty array')
  const sources = (raw.sources ?? []).map((source, index) => validateSource(source, `sources[${index}]`, errors))
  const config = {
    example,
    extraExamples: pathList(raw.extraExamples, 'extraExamples'),
    consumers: pathList(raw.consumers, 'consumers'),
    sources,
    notVariables: reasons(raw.notVariables, 'notVariables'),
    runtimeVariables: reasons(raw.runtimeVariables, 'runtimeVariables'),
    internalPrefixes: Array.isArray(raw.internalPrefixes) && raw.internalPrefixes.every(nonEmptyString) ? raw.internalPrefixes : [],
    forbidDynamicNames: raw.forbidDynamicNames !== false,
  }
  if (raw.internalPrefixes !== undefined && config.internalPrefixes !== raw.internalPrefixes) errors.push('internalPrefixes must be an array of strings')
  if (errors.length) throw new Error(`invalid ${path}:\n  - ${errors.join('\n  - ')}`)
  return config
}

function validateSource(source, label, errors) {
  if (!isPlainObject(source)) {
    errors.push(`${label} must be an object`)
    return { roots: [], extensions: [], reads: [], dynamic: [] }
  }
  rejectUnknown(source, SOURCE_KEYS, label, errors)
  if (!Array.isArray(source.roots) || !source.roots.length || !source.roots.every(relativePath)) errors.push(`${label}.roots must list relative paths`)
  if (!Array.isArray(source.extensions) || !source.extensions.every((ext) => /^\.\w+$/.test(ext))) errors.push(`${label}.extensions must list extensions such as ".rs"`)
  const language = source.language === undefined ? null : LANGUAGES[source.language]
  if (source.language !== undefined && !language) errors.push(`${label}.language must be one of ${Object.keys(LANGUAGES).join(', ')}`)
  const custom = source.patterns ?? []
  if (!Array.isArray(custom) || !custom.every(nonEmptyString)) errors.push(`${label}.patterns must be regular expressions with one capture group`)
  if (!language && !custom.length) errors.push(`${label} needs a language or patterns`)
  const compile = (pattern) => {
    try {
      return new RegExp(pattern, 'g')
    } catch (error) {
      errors.push(`${label}: invalid pattern ${pattern}: ${error.message}`)
      return null
    }
  }
  return {
    roots: source.roots ?? [],
    extensions: source.extensions ?? [],
    reads: [...(language?.reads ?? []), ...(Array.isArray(custom) ? custom : [])].map(compile).filter(Boolean),
    dynamic: (language?.dynamic ?? []).map(compile).filter(Boolean),
    exclude: source.excludePattern ? compile(source.excludePattern) : null,
  }
}

function scanSource(root, source, forbidDynamic, read, problems) {
  const { files, missingRoots, errors } = walkSources({ repoRoot: root, roots: source.roots, extensions: source.extensions, ignoredPaths: [] })
  for (const missing of missingRoots) problems.push(`source root does not exist: ${missing}`)
  problems.push(...errors)
  for (const file of files) {
    const rel = toRepoPath(root, file)
    if (source.exclude && new RegExp(source.exclude.source).test(rel)) continue
    const text = readFileSync(file, 'utf8')
    for (const pattern of source.reads) for (const match of text.matchAll(pattern)) if (match[1]) read.add(match[1])
    if (forbidDynamic && source.dynamic.some((pattern) => new RegExp(pattern.source).test(text))) {
      problems.push(`${rel}: reads an environment variable by a built name; use a literal`)
    }
  }
}

function entriesOf(root, rel, problems) {
  const path = join(root, rel)
  if (!existsSync(path)) {
    problems.push(`${rel} does not exist`)
    return new Set()
  }
  return new Set([...readFileSync(path, 'utf8').matchAll(/^#?\s*([A-Z][A-Z0-9_]+)=/gm)].map((match) => match[1]))
}

function filesUnder(root, rel, problems) {
  const path = join(root, rel)
  if (!existsSync(path)) {
    problems.push(`consumer path does not exist: ${rel}`)
    return []
  }
  const stat = lstatSync(path)
  if (stat.isSymbolicLink()) return []
  if (!stat.isDirectory()) return [readFileSync(path, 'utf8')]
  return readdirSync(path).sort().flatMap((name) => filesUnder(root, `${rel}/${name}`, problems))
}

function uncommented(text) {
  return text.split('\n').filter((line) => !line.trimStart().startsWith('#')).join('\n')
}

process.exitCode = main()
