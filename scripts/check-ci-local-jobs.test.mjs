import assert from 'node:assert/strict'
import test from 'node:test'

import { checkAssignments, checkAuditStep, workflowCalls } from './check-ci-local-jobs.mjs'

const audit = {
  name: 'audit-lockfiles',
  run: null,
  uses: 'audit-all-lockfiles',
  needs: [],
  with: { ecosystems: ['cargo', 'npm'], npm: { mode: 'npm-audit' } },
}
const auditCall = '      - run: node x/ci-local.mjs --ci --only audit-lockfiles\n'

const step = (name, extra = {}) => ({ name, run: `echo ${name}`, needs: [], ...extra })

function check(steps, jobs, overrides = {}) {
  return checkAssignments({
    steps: [...steps, audit],
    workflow: `jobs:\n  audit:\n${auditCall}${jobs}`,
    packageScripts: {},
    ...overrides,
  })
}

test('every step owned by exactly one job passes', () => {
  const jobs = '  a:\n    steps:\n      - run: node x/ci-local.mjs --ci --only one,two\n'
  assert.deepEqual(check([step('one'), step('two')], jobs), [])
})

test('unassigned, duplicated, and unknown steps fail', () => {
  const jobs = [
    '  a:',
    '      - run: node x/ci-local.mjs --ci --only one,ghost',
    '  b:',
    '      - run: node x/ci-local.mjs --ci --only one',
    '',
  ].join('\n')
  const problems = check([step('one'), step('lost')], jobs)
  assert.ok(problems.includes('job a: unknown ci-local step ghost'))
  assert.ok(problems.includes('step one runs in 2 CI assignments: a, b'))
  assert.ok(problems.includes('step lost runs in no CI job'))
})

test('a step pulled in only through needs is not an assignment', () => {
  const steps = [step('install'), step('build', { needs: ['install'] })]
  const jobs = '  a:\n      - run: node x/ci-local.mjs --ci --only build\n'
  assert.deepEqual(check(steps, jobs), ['step install runs in no CI job'])
})

test('--no-needs requires an earlier call in the same job to run the needs', () => {
  const steps = [step('install'), step('build', { needs: ['install'] }), step('e2e', { needs: ['build'] })]
  const ok = [
    '  a:',
    '      - run: node x/ci-local.mjs --ci --only install',
    '  b:',
    '      - run: node x/ci-local.mjs --ci --only build',
    '      - run: node x/ci-local.mjs --ci --no-needs --only e2e',
    '',
  ].join('\n')
  assert.deepEqual(check(steps, ok), [])
  const otherJob = ok.replace(
    '      - run: node x/ci-local.mjs --ci --only build\n',
    '      - run: node x/ci-local.mjs --ci --only build\n  c:\n',
  )
  assert.ok(check(steps, otherJob).some((problem) => problem.includes('--no-needs step e2e needs build')))
  // A need that ran only through an earlier call's needs closure satisfies
  // --no-needs, but it is still not an assignment.
  const viaClosure = [
    '  a:',
    '      - run: node x/ci-local.mjs --ci --only build',
    '      - run: node x/ci-local.mjs --ci --no-needs --only e2e',
    '',
  ].join('\n')
  assert.deepEqual(check(steps, viaClosure), ['step install runs in no CI job'])
})

test('workflow calls must use --ci and --only', () => {
  const { problems } = workflowCalls('jobs:\n  a:\n      - run: node x/ci-local.mjs --quick\n      - run: node x/ci-local.mjs --only a\n')
  assert.equal(problems.length, 2)
  const commented = workflowCalls('jobs:\n  a:\n      # run `node x/ci-local.mjs --quick` locally\n')
  assert.deepEqual(commented, { calls: [], problems: [] })
})

test('the workflow must not repeat a manifest command outside ci-local', () => {
  const clippy = step('clippy', { run: ['cargo', 'clippy', '--locked', '--', '-D', 'warnings'] })
  const jobs = [
    '  a:',
    '      - run: node x/ci-local.mjs --ci --only clippy',
    '      - run: cargo clippy --locked -- -D warnings',
    '',
  ].join('\n')
  assert.deepEqual(check([clippy], jobs), [
    'workflow repeats the command of step clippy outside ci-local: "cargo clippy --locked -- -D warnings"',
  ])
})

test('steps that mirror a package script must not drift from it', () => {
  const jobs = '  a:\n      - run: node x/ci-local.mjs --ci --only one\n'
  const mirrored = step('one', { description: 'npm run one', run: 'node one.mjs' })
  assert.deepEqual(check([mirrored], jobs, { packageScripts: { one: 'node one.mjs' } }), [])
  assert.deepEqual(check([mirrored], jobs, { packageScripts: { one: 'node two.mjs' } }), [
    'step one drifted from package script one: "node two.mjs"',
  ])
  assert.deepEqual(check([mirrored], jobs), ['step one mirrors missing package script one'])
})

test('the audit step must exist and audit both Cargo and npm lockfiles', () => {
  assert.deepEqual(checkAuditStep(audit), [])
  assert.deepEqual(checkAuditStep({ ...audit, with: {} }), [])
  assert.deepEqual(checkAuditStep({ ...audit, with: { ecosystems: ['cargo'] } }), [
    'step audit-lockfiles does not audit npm',
  ])
  assert.deepEqual(checkAuditStep({ ...audit, uses: undefined, run: 'cargo audit' }), [
    'step audit-lockfiles must use audit-all-lockfiles',
  ])
  assert.deepEqual(checkAuditStep(undefined), ['step audit-lockfiles is missing from the manifest'])
})
