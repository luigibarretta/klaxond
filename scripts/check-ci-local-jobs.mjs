#!/usr/bin/env node
// Asserts that every ci-local manifest step runs in exactly one CI job, so the
// local gate and .gitea/workflows/build.yml cannot drift apart.
//
// A step is assigned to a job when that job calls
// `ci-local.mjs --ci [--no-needs] --only a,b`. Steps pulled in only through
// `needs` do not count as an assignment. The checker also fails when:
// - a `--no-needs` call relies on a step that no earlier call in the job ran;
// - the workflow repeats a manifest step's command outside ci-local;
// - a step described as exactly "npm run <script>" drifted from package.json;
// - the lockfile audit step is missing or skips the Cargo or npm ecosystem.

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const AUDIT_STEP = 'audit-lockfiles'
export const AUDIT_ECOSYSTEMS = ['cargo', 'npm']
const CI_LOCAL_CALL = /ci-local\.mjs((?:\s+--[a-z-]+(?:\s+[\w.][\w.,-]*)?)*)/g
// Shorter commands (e.g. `bash x.sh`) are too generic to flag as duplicates.
const MIN_DUPLICATE_COMMAND = 16

export function commandText(step) {
  if (step.run === null || step.run === undefined) return null
  return Array.isArray(step.run) ? step.run.join(' ') : step.run
}

// Returns [{ job, only: [...], noNeeds }] in workflow order.
export function workflowCalls(workflow) {
  const calls = []
  const problems = []
  let inJobs = false
  let job = null
  for (const line of workflow.split('\n')) {
    if (/^jobs:\s*$/.test(line)) inJobs = true
    const header = inJobs && /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line)
    if (header) job = header[1]
    if (/^\s*#/.test(line)) continue
    for (const match of line.matchAll(CI_LOCAL_CALL)) {
      const args = match[1].trim().split(/\s+/)
      const only = args.indexOf('--only')
      if (!job) problems.push(`ci-local call outside a job: ${line.trim()}`)
      else if (!args.includes('--ci')) problems.push(`job ${job}: ci-local call without --ci: ${line.trim()}`)
      else if (only < 0 || !args[only + 1]) problems.push(`job ${job}: ci-local call without --only: ${line.trim()}`)
      else calls.push({ job, only: args[only + 1].split(','), noNeeds: args.includes('--no-needs') })
    }
  }
  return { calls, problems }
}

function closure(names, byName) {
  const seen = new Set()
  const queue = [...names]
  while (queue.length > 0) {
    const name = queue.shift()
    if (seen.has(name) || !byName.has(name)) continue
    seen.add(name)
    queue.push(...byName.get(name).needs)
  }
  return seen
}

export function checkAssignments({ steps, workflow, packageScripts }) {
  const byName = new Map(steps.map((step) => [step.name, step]))
  const { calls, problems } = workflowCalls(workflow)
  const owners = new Map()
  const available = new Map()
  for (const call of calls) {
    const ready = available.get(call.job) ?? new Set()
    for (const name of call.only) {
      if (!byName.has(name)) problems.push(`job ${call.job}: unknown ci-local step ${name}`)
      else owners.set(name, [...(owners.get(name) ?? []), call.job])
    }
    if (call.noNeeds) problems.push(...missingNeeds(call, byName, ready))
    const ran = call.noNeeds ? new Set(call.only) : closure(call.only, byName)
    available.set(call.job, new Set([...ready, ...ran]))
  }
  for (const step of steps) {
    const jobs = owners.get(step.name) ?? []
    if (jobs.length === 0) problems.push(`step ${step.name} runs in no CI job`)
    if (jobs.length > 1) problems.push(`step ${step.name} runs in ${jobs.length} CI assignments: ${jobs.join(', ')}`)
  }
  problems.push(...duplicatedCommands(steps, workflow))
  problems.push(...checkScriptMirrors(steps, packageScripts))
  problems.push(...checkAuditStep(byName.get(AUDIT_STEP)))
  return problems
}

function missingNeeds(call, byName, ready) {
  const problems = []
  for (const name of call.only.filter((entry) => byName.has(entry))) {
    for (const need of byName.get(name).needs) {
      if (!ready.has(need) && !call.only.includes(need)) {
        problems.push(`job ${call.job}: --no-needs step ${name} needs ${need}, which no earlier ci-local call in the job ran`)
      }
    }
  }
  return problems
}

// CI must run manifest commands through ci-local, not repeat them in YAML.
function duplicatedCommands(steps, workflow) {
  const yaml = workflow.split('\n').filter((line) => !line.includes('ci-local.mjs')).join('\n')
  return steps
    .map((step) => [step.name, commandText(step)])
    .filter(([, command]) => command && command.length >= MIN_DUPLICATE_COMMAND && yaml.includes(command))
    .map(([name, command]) => `workflow repeats the command of step ${name} outside ci-local: "${command}"`)
}

// A run step described as exactly "npm run <script>" must run that script's body.
function checkScriptMirrors(steps, packageScripts) {
  const problems = []
  for (const step of steps) {
    const mirror = /^npm run ([\w:.-]+)$/.exec(step.description ?? '')
    if (!mirror || step.uses) continue
    const script = packageScripts[mirror[1]]
    if (script === undefined) problems.push(`step ${step.name} mirrors missing package script ${mirror[1]}`)
    else if (script !== commandText(step)) problems.push(`step ${step.name} drifted from package script ${mirror[1]}: "${script}"`)
  }
  return problems
}

// ci-local fails closed on a lockfile no audit step covers; this keeps the one
// audit step responsible for both ecosystems klaxond ships.
export function checkAuditStep(audit) {
  if (!audit) return [`step ${AUDIT_STEP} is missing from the manifest`]
  if (audit.uses !== 'audit-all-lockfiles') return [`step ${AUDIT_STEP} must use audit-all-lockfiles`]
  const ecosystems = audit.with?.ecosystems ?? AUDIT_ECOSYSTEMS
  const missing = AUDIT_ECOSYSTEMS.filter((ecosystem) => !ecosystems.includes(ecosystem))
  return missing.length > 0 ? [`step ${AUDIT_STEP} does not audit ${missing.join(',')}`] : []
}

function main() {
  const root = resolve(fileURLToPath(import.meta.url), '../..')
  const read = (path) => readFileSync(resolve(root, path), 'utf8')
  const listed = JSON.parse(execFileSync(process.execPath, ['third_party/repo-tooling/ci-local.mjs', '--list', '--json'], { cwd: root, encoding: 'utf8' }))
  // --list --json omits descriptions and built-in options; merge them from the manifest.
  const manifest = new Map(JSON.parse(read('ci-local.json')).steps.map((step) => [step.name, step]))
  const steps = listed.steps.map((step) => ({ ...step, description: manifest.get(step.name)?.description, with: manifest.get(step.name)?.with }))
  const problems = checkAssignments({
    steps,
    workflow: read('.gitea/workflows/build.yml'),
    packageScripts: JSON.parse(read('package.json')).scripts,
  })
  if (problems.length > 0) {
    for (const problem of problems) console.error(`ci-local jobs: ${problem}`)
    process.exitCode = 1
    return
  }
  console.log(`ci-local jobs: all ${steps.length} manifest steps run in exactly one CI job`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
