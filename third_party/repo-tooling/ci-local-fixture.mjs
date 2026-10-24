// Fixtures: services or resources a step needs (a backend serving
// /openapi.json, a disposable database). Setup runs before the step, the step
// receives the env the setup exported, and teardown always runs afterwards.
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { OutputCapture, commandArgv, runProcess, spawnService, stopService, substituteEnv, substituteRoot } from './ci-local-process.mjs'
import {
  isPlainObject, nonEmptyString, optionalPositiveInt, optionalPositiveNumber, rejectUnknown, relativePath,
  validCommand, validateEnvObject,
} from './ci-local-util.mjs'

const FIXTURE_KEYS = new Set([
  'setup', 'teardown', 'background', 'ready', 'env_from_setup', 'tmpdir', 'cwd', 'env', 'timeout_s',
  'teardown_timeout_s', 'log_tail_lines', 'description',
])
const ENV_LINE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/

export function validateFixtures(raw, errors) {
  if (raw === undefined) return {}
  if (!isPlainObject(raw)) {
    errors.push('fixtures must be an object keyed by fixture name')
    return {}
  }
  const fixtures = {}
  for (const [name, definition] of Object.entries(raw)) {
    fixtures[name] = validateFixture(definition, `fixtures.${name}`, errors)
  }
  return fixtures
}

function validateFixture(raw, where, errors) {
  if (!isPlainObject(raw)) {
    errors.push(`${where} must be an object`)
    return null
  }
  rejectUnknown(raw, FIXTURE_KEYS, where, errors)
  if (!validCommand(raw.setup)) errors.push(`${where}.setup must be a shell string or argv array`)
  if (raw.teardown !== undefined && !validCommand(raw.teardown)) errors.push(`${where}.teardown must be a shell string or argv array`)
  for (const flag of ['background', 'env_from_setup', 'tmpdir']) {
    if (raw[flag] !== undefined && typeof raw[flag] !== 'boolean') errors.push(`${where}.${flag} must be a boolean`)
  }
  if (raw.cwd !== undefined && !relativePath(raw.cwd)) errors.push(`${where}.cwd must be a relative path`)
  return {
    setup: raw.setup,
    teardown: raw.teardown,
    background: raw.background === true,
    ready: validateReady(raw.ready, `${where}.ready`, errors),
    envFromSetup: raw.env_from_setup === true,
    tmpdir: raw.tmpdir === true,
    cwd: raw.cwd ?? '.',
    env: validateEnvObject(raw.env, `${where}.env`, errors),
    timeoutS: optionalPositiveInt(raw.timeout_s, `${where}.timeout_s`, 300, errors),
    teardownTimeoutS: optionalPositiveInt(raw.teardown_timeout_s, `${where}.teardown_timeout_s`, 60, errors),
    logTailLines: optionalPositiveInt(raw.log_tail_lines, `${where}.log_tail_lines`, 30, errors),
  }
}

function validateReady(raw, where, errors) {
  if (raw === undefined) return null
  if (!isPlainObject(raw)) {
    errors.push(`${where} must be an object`)
    return null
  }
  rejectUnknown(raw, new Set(['url', 'command', 'timeout_s', 'interval_s']), where, errors)
  const hasUrl = raw.url !== undefined
  if (hasUrl === (raw.command !== undefined)) errors.push(`${where} must set exactly one of url or command`)
  if (hasUrl && !(nonEmptyString(raw.url) && /^https?:\/\//.test(raw.url))) errors.push(`${where}.url must be an http(s) URL`)
  if (raw.command !== undefined && !validCommand(raw.command)) errors.push(`${where}.command must be a shell string or argv array`)
  return {
    url: raw.url,
    command: raw.command,
    timeoutS: optionalPositiveNumber(raw.timeout_s, `${where}.timeout_s`, 60, errors),
    intervalS: optionalPositiveNumber(raw.interval_s, `${where}.interval_s`, 1, errors),
  }
}

// Starts fixtures in order. Returns the started instances (always pass them
// to stopFixtures) plus the merged exported env or the first error.
export async function startFixtures(names, context) {
  const started = []
  const env = {}
  for (const name of names) {
    const instance = createInstance(name, context)
    started.push(instance)
    const error = await startInstance(instance, context)
    if (error) return { started, env, error: `fixture ${name}: ${error}`, failed: instance }
    Object.assign(env, instance.exported)
  }
  return { started, env, error: null, failed: null }
}

function createInstance(name, context) {
  const definition = context.fixtures[name]
  const directory = mkdtempSync(join(context.tempRoot || tmpdir(), `ci-local-fixture-${name}-`))
  const envFile = join(directory, 'env')
  return {
    name,
    root: context.root,
    definition,
    directory,
    envFile,
    cwd: definition.tmpdir ? directory : resolve(context.root, definition.cwd),
    env: { ...context.baseEnv, ...substituteEnv(definition.env, context.root), CI_LOCAL_FIXTURE_ENV: envFile, CI_LOCAL_FIXTURE_DIR: directory },
    capture: new OutputCapture(64 * 1024),
    service: null,
    exported: {},
  }
}

async function startInstance(instance, context) {
  const { definition } = instance
  const argv = argvFor(definition.setup, context.root)
  const append = (text) => instance.capture.append(text)
  if (definition.background) {
    instance.service = spawnService({ argv, cwd: instance.cwd, env: instance.env, onOutput: append })
  } else {
    const result = await runProcess({
      argv, cwd: instance.cwd, env: instance.env, timeoutMs: definition.timeoutS * 1000, onOutput: append,
    })
    if (result.timedOut) return `setup timed out after ${definition.timeoutS}s`
    if (result.code !== 0) return `setup failed (exit ${result.code})`
  }
  if (definition.ready) {
    const error = await waitReady(instance, context)
    if (error) return error
  }
  if (definition.envFromSetup) {
    const parsed = parseEnvFile(instance.envFile)
    if (parsed.error) return parsed.error
    instance.exported = parsed.env
  }
  return null
}

async function waitReady(instance, context) {
  const { ready } = instance.definition
  const deadline = Date.now() + ready.timeoutS * 1000
  for (;;) {
    if (context.isInterrupted()) return 'interrupted while waiting for readiness'
    if (instance.service?.exit) return `service exited before it was ready (exit ${instance.service.exit.code})`
    if (await probe(ready, instance, deadline)) return null
    if (Date.now() + ready.intervalS * 1000 > deadline) return `not ready after ${ready.timeoutS}s`
    await new Promise((resolveDelay) => setTimeout(resolveDelay, ready.intervalS * 1000))
  }
}

async function probe(ready, instance, deadline) {
  const budgetMs = Math.max(250, Math.min(deadline - Date.now(), 10000))
  if (ready.url) {
    try {
      const response = await fetch(ready.url, { signal: AbortSignal.timeout(budgetMs) })
      await response.body?.cancel()
      return response.status < 400
    } catch {
      return false
    }
  }
  const result = await runProcess({
    argv: argvFor(ready.command, instance.root), cwd: instance.cwd, env: instance.env, timeoutMs: budgetMs, onOutput: () => {},
  })
  return result.code === 0 && !result.timedOut
}

function argvFor(command, root) {
  return commandArgv(command).map((part) => substituteRoot(part, root))
}

export function parseEnvFile(path) {
  if (!existsSync(path)) return { error: `env_from_setup is set but setup did not write $CI_LOCAL_FIXTURE_ENV`, env: {} }
  const env = {}
  for (const [index, line] of readFileSync(path, 'utf8').split('\n').entries()) {
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue
    const match = line.match(ENV_LINE)
    if (!match) return { error: `invalid KEY=VALUE line ${index + 1} in fixture env file`, env: {} }
    env[match[1]] = match[2]
  }
  return { env, error: null }
}

// Tears down in reverse order. Never throws; returns problems for the report.
export async function stopFixtures(started, context) {
  const problems = []
  for (const instance of [...started].reverse()) {
    const { definition } = instance
    if (definition.teardown) {
      const result = await runProcess({
        argv: argvFor(definition.teardown, instance.root),
        cwd: instance.cwd,
        env: { ...instance.env, ...instance.exported },
        timeoutMs: definition.teardownTimeoutS * 1000,
        onOutput: (text) => instance.capture.append(text),
        track: false,
      })
      if (result.code !== 0 || result.timedOut) problems.push(`fixture ${instance.name}: teardown failed (exit ${result.code})`)
    }
    if (instance.service) await stopService(instance.service)
    context.log(`\n== fixture ${instance.name} log\n${instance.capture.text()}\n`)
    rmSync(instance.directory, { recursive: true, force: true })
  }
  return problems
}

export function fixtureTail(instance) {
  return instance.capture.lastLines(instance.definition.logTailLines)
}
