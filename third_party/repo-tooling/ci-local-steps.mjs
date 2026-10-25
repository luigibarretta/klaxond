// Step execution for the ci-local runner: shell/argv steps, built-ins,
// fixtures around a step and declared-writes checks after it.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { planAudit, validateAuditConfig } from './ci-local-audit.mjs'
import { fixtureTail, startFixtures, stopFixtures } from './ci-local-fixture.mjs'
import { changedSince, compareToRef, snapshotWrites, validateCompareConfig, verifyWritesClean } from './ci-local-git.mjs'
import { commandArgv, runProcess, substituteEnv, substituteRoot } from './ci-local-process.mjs'
import { rejectUnknown } from './ci-local-util.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const TOOL_SCRIPTS = {
  loc: 'check-loc.mjs',
  nasa: 'check-nasa-warnings.mjs',
  'release-contract': 'check-release-contract.mjs',
}

// Validates built-in `with` blocks up front so a typo fails before any step runs.
export function validateBuiltins(steps) {
  const errors = []
  for (const step of steps) {
    if (!step.uses) continue
    const where = `step ${step.name}.with`
    if (step.uses === 'audit-all-lockfiles' || step.uses === 'compare-to-ref') {
      const result = step.uses === 'audit-all-lockfiles' ? validateAuditConfig(step.with, where) : validateCompareConfig(step.with, where)
      errors.push(...result.errors)
      step.config = result.config
      continue
    }
    rejectUnknown(step.with, new Set(['args']), where, errors)
    const args = step.with.args ?? []
    if (!Array.isArray(args) || !args.every((arg) => typeof arg === 'string')) {
      errors.push(`${where}.args must be an array of strings`)
    }
  }
  return errors
}

export function describeStep(step) {
  if (step.uses) return `uses ${step.uses}`
  return typeof step.run === 'string' ? step.run : step.run.join(' ')
}

// context: { root, ci, output, say, log, allSteps, fixtures, baseEnv, forcedEnv, isInterrupted }
export async function executeStep(step, context) {
  if (step.fixtures.length === 0) return executeWithWrites(step, context, {})
  const fixtureContext = { ...context, baseEnv: { ...context.baseEnv, ...context.forcedEnv } }
  const started = await startFixtures(step.fixtures, fixtureContext)
  let result
  if (started.error) {
    context.output(`ci-local: ${started.error}\n`)
    printFixtureTail(started.failed, context)
    result = { status: 'fail', detail: started.error }
  } else {
    result = await executeWithWrites(step, context, started.env)
    if (result.status !== 'ok') started.started.forEach((instance) => printFixtureTail(instance, context))
  }
  const problems = await stopFixtures(started.started, context)
  if (problems.length > 0 && result.status === 'ok') return { status: 'fail', detail: problems.join('; ') }
  return problems.length > 0 ? { ...result, notices: [...(result.notices ?? []), ...problems] } : result
}

function printFixtureTail(instance, context) {
  context.say(`  fixture ${instance.name} log (last ${instance.definition.logTailLines} lines):`)
  context.say(fixtureTail(instance).split('\n').map((line) => `    ${line}`).join('\n'))
}

async function executeWithWrites(step, context, fixtureEnv) {
  const before = step.writes.length > 0 && !context.ci ? snapshotWrites(context.root, step.writes) : null
  const result = await executeBody(step, context, fixtureEnv)
  if (step.writes.length === 0 || result.status !== 'ok') return result
  if (context.ci) {
    const dirty = verifyWritesClean(context.root, step.writes)
    if (!dirty) return result
    context.output(`${dirty}\n`)
    return { status: 'fail', detail: 'declared writes differ from the commit', excerpt: dirty }
  }
  const after = before && snapshotWrites(context.root, step.writes)
  if (!after) return { ...result, notices: [...(result.notices ?? []), 'writes not checked: not a git work tree'] }
  const changed = changedSince(before, after)
  if (changed.length === 0) return result
  return { ...result, notices: [...(result.notices ?? []), `modified ${changed.join(', ')} (review and commit)`] }
}

async function executeBody(step, context, fixtureEnv) {
  const deadline = Date.now() + step.timeoutS * 1000
  if (step.uses === 'audit-all-lockfiles') return executeAudit(step, context, deadline, fixtureEnv)
  if (step.uses === 'compare-to-ref') return compareToRef(context.root, step.config, context.output)
  const argv = step.uses
    ? [process.execPath, join(here, TOOL_SCRIPTS[step.uses]), ...(step.with.args ?? [])]
    : commandArgv(step.run).map((part) => substituteRoot(part, context.root))
  return runOne({ argv, cwd: step.cwd, extraEnv: {} }, step, context, { deadline, fixtureEnv })
}

// Env layering: process env < defaults.env < step env < fixture exports <
// command extras < runner-forced values (CI_LOCAL_ROOT, --ci markers).
export function stepEnvironment(step, context, fixtureEnv = {}, extraEnv = {}) {
  return { ...context.baseEnv, ...substituteEnv(step.env, context.root), ...fixtureEnv, ...extraEnv, ...context.forcedEnv }
}

async function runOne(command, step, context, { deadline, fixtureEnv }) {
  // Outside --ci, the build-lock wrapper reports its waits here so the step's
  // timeout measures its own work (bounded by CI_LOCAL_MAX_LOCK_WAIT_S).
  const waitReport = context.ci ? null : join(mkdtempSync(join(tmpdir(), 'ci-local-wait-')), 'waits')
  const maxWaitS = Number(process.env.CI_LOCAL_MAX_LOCK_WAIT_S ?? 7200)
  const extraEnv = waitReport ? { ...command.extraEnv, DEV_LOCK_WAIT_REPORT: waitReport } : command.extraEnv
  const result = await runProcess({
    argv: command.argv,
    cwd: resolve(context.root, command.cwd),
    env: stepEnvironment(step, context, fixtureEnv, extraEnv),
    timeoutMs: deadline - Date.now(),
    onOutput: context.output,
    waitReport,
    maxWaitExtensionMs: Number.isFinite(maxWaitS) && maxWaitS > 0 ? maxWaitS * 1000 : 0,
  })
  if (waitReport) rmSync(dirname(waitReport), { recursive: true, force: true })
  if (result.timedOut) return { status: 'timeout', detail: `timeout after ${step.timeoutS}s` }
  if (result.code !== 0) return { status: 'fail', detail: result.signal ? `signal ${result.signal}` : `exit ${result.code}` }
  return { status: 'ok' }
}

async function executeAudit(step, context, deadline, fixtureEnv) {
  const coveredElsewhere = new Set()
  for (const other of context.allSteps) {
    if (other.uses === 'audit-all-lockfiles' && other !== step) other.config.ecosystems.forEach((e) => coveredElsewhere.add(e))
  }
  let plan
  try {
    plan = planAudit(context.root, step.config, coveredElsewhere)
  } catch (error) {
    context.output(`audit-all-lockfiles: ${error.message}\n`)
    return { status: 'fail', detail: error.message }
  }
  reportPlan(plan, step.config.ecosystems, context.output)
  if (plan.problems.length > 0) {
    for (const problem of plan.problems) context.output(`audit-all-lockfiles: ERROR ${problem}\n`)
    return { status: 'fail', detail: `${plan.problems.length} lockfile coverage problem(s)` }
  }
  const failed = []
  for (const command of plan.commands) {
    context.output(`\n--- ${command.label}\n`)
    const commandSpec = { argv: command.argv, cwd: command.cwd, extraEnv: command.env ?? {} }
    const result = await runOne(commandSpec, step, context, { deadline, fixtureEnv })
    if (result.status === 'timeout') return result
    if (result.status !== 'ok') failed.push(command.label)
  }
  // Report every vulnerable lockfile in one run instead of one per push.
  if (failed.length > 0) return { status: 'fail', detail: `${failed.length}/${plan.commands.length} audit(s) failed: ${failed.join('; ')}` }
  return { status: 'ok', detail: `${plan.commands.length} audit(s)` }
}

function reportPlan(plan, ecosystems, output) {
  for (const ecosystem of ['cargo', 'npm']) {
    const paths = plan.selected[ecosystem]
    const scope = ecosystems.includes(ecosystem) ? 'audit' : 'covered by another step'
    output(`audit-all-lockfiles: ${ecosystem} ${paths.length} lockfile(s) [${scope}]${paths.length ? ': ' + paths.join(', ') : ''}\n`)
  }
  for (const entry of plan.excluded) output(`audit-all-lockfiles: excluded ${entry.path} (${entry.reason})\n`)
}
