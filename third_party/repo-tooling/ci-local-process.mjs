// Process execution with per-step timeouts, output capture and host guards.
import { spawn } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { delimiter, join, resolve } from 'node:path'

export const KILL_GRACE_MS = 5000
let activeChild = null

// Runs one command in its own process group so a timeout or an interrupt
// can terminate the whole tree (cargo -> rustc, npm -> node, sh -> children).
// `track: false` keeps the process out of interrupt handling (teardowns must
// finish even after Ctrl-C).
// Build-lock waits reported by the dev-01 wrapper (DEV_LOCK_WAIT_REPORT):
// "start <id> <ms>" when a command starts waiting for CI and the lock,
// "end <id> <ms>" once it holds the lock. Returns the total waited time,
// counting still-open waits up to `now`, and whether any wait is open.
export function lockWaitMs(path, now = Date.now()) {
  if (!path || !existsSync(path)) return { waitedMs: 0, open: false }
  const starts = new Map()
  let waitedMs = 0
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const [kind, id, at] = line.trim().split(/\s+/)
    const ms = Number(at)
    if (!id || !Number.isFinite(ms)) continue
    if (kind === 'start' && !starts.has(id)) starts.set(id, ms)
    if (kind === 'end' && starts.has(id)) { waitedMs += Math.max(0, ms - starts.get(id)); starts.delete(id) }
  }
  for (const ms of starts.values()) waitedMs += Math.max(0, now - ms)
  return { waitedMs, open: starts.size > 0 }
}

export function runProcess({ argv, cwd, env, timeoutMs, onOutput, track = true, waitReport = null, maxWaitExtensionMs = 0 }) {
  return new Promise((resolvePromise) => {
    const started = Date.now()
    let timedOut = false
    let grantedMs = 0
    let child
    try {
      child = spawn(argv[0], argv.slice(1), { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
    } catch (error) {
      onOutput(`ci-local: cannot start ${argv[0]}: ${error.message}\n`)
      resolvePromise({ code: 127, signal: null, timedOut, durationMs: 0 })
      return
    }
    if (track) activeChild = child
    child.stdout.on('data', (chunk) => onOutput(chunk.toString()))
    child.stderr.on('data', (chunk) => onOutput(chunk.toString()))
    // Time spent queued for the shared build lock is not the step's own work:
    // at the deadline, extend by the newly reported waits (bounded), and keep
    // re-checking while a wait is still open.
    const onDeadline = () => {
      const { waitedMs, open } = lockWaitMs(waitReport)
      const room = maxWaitExtensionMs - grantedMs
      const extra = Math.min(Math.max(0, waitedMs - grantedMs), room)
      if (room > 0 && (extra > 0 || open)) {
        const delay = Math.max(extra, open ? Math.min(30_000, room) : 0)
        grantedMs += delay
        onOutput(`\nci-local: deadline extended by ${Math.round(delay / 1000)}s for build-lock waits\n`)
        timer = setTimeout(onDeadline, Math.max(1, delay))
        return
      }
      timedOut = true
      onOutput(`\nci-local: timeout after ${Math.round((timeoutMs + grantedMs) / 1000)}s, killing process group\n`)
      killGroup(child)
    }
    let timer = setTimeout(onDeadline, Math.max(1, timeoutMs))
    child.on('error', (error) => onOutput(`ci-local: cannot start ${argv[0]}: ${error.message}\n`))
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      if (activeChild === child) activeChild = null
      resolvePromise({ code: code ?? 128, signal, timedOut, durationMs: Date.now() - started })
    })
  })
}

// Long-running fixture service in its own process group. `exit` is set when
// it stops; `closed` resolves at the same time.
export function spawnService({ argv, cwd, env, onOutput }) {
  const service = { child: null, exit: null, closed: null }
  service.closed = new Promise((resolveClosed) => {
    const finish = (code, signal) => {
      service.exit = service.exit ?? { code: code ?? 128, signal }
      resolveClosed()
    }
    try {
      service.child = spawn(argv[0], argv.slice(1), { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
    } catch (error) {
      onOutput(`ci-local: cannot start ${argv[0]}: ${error.message}\n`)
      finish(127, null)
      return
    }
    service.child.stdout.on('data', (chunk) => onOutput(chunk.toString()))
    service.child.stderr.on('data', (chunk) => onOutput(chunk.toString()))
    service.child.on('error', (error) => {
      onOutput(`ci-local: cannot start ${argv[0]}: ${error.message}\n`)
      finish(127, null)
    })
    service.child.on('close', finish)
  })
  return service
}

export async function stopService(service) {
  // Signal the group even if the leader already exited: children may remain.
  if (service.child) killGroup(service.child)
  await service.closed
}

export function killGroup(child) {
  if (!child || child.pid === undefined) return
  signalGroup(child.pid, 'SIGTERM')
  const escalation = setTimeout(() => signalGroup(child.pid, 'SIGKILL'), KILL_GRACE_MS)
  escalation.unref()
  child.once('close', () => {
    // Children that ignored SIGTERM may outlive the leader; finish them.
    signalGroup(child.pid, 'SIGKILL')
    clearTimeout(escalation)
  })
}

export function killActiveChild() {
  if (activeChild) killGroup(activeChild)
}

function signalGroup(pid, signal) {
  try {
    process.kill(-pid, signal)
  } catch {
    // The group is already gone.
  }
}

export function commandArgv(run) {
  return typeof run === 'string' ? ['bash', '-o', 'pipefail', '-ec', run] : [...run]
}

export function substituteRoot(value, root) {
  return value.split('{root}').join(root)
}

export function substituteEnv(env, root) {
  return Object.fromEntries(Object.entries(env).map(([key, value]) => [key, substituteRoot(value, root)]))
}

// Linux PSI: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0".
export function readMemoryPressure(path) {
  if (!existsSync(path)) return null
  const line = readFileSync(path, 'utf8').split('\n').find((entry) => entry.startsWith('some '))
  const match = line && line.match(/\bavg60=([0-9.]+)/)
  return match ? Number(match[1]) : null
}

export function pressureVerdict(path, maxSomeAvg60) {
  const avg60 = readMemoryPressure(path)
  if (avg60 === null) return { ok: true, message: `memory pressure unavailable at ${path}; gate skipped` }
  if (avg60 > maxSomeAvg60) {
    return { ok: false, message: `memory pressure some avg60=${avg60} exceeds ${maxSomeAvg60} (${path})` }
  }
  return { ok: true, message: `memory pressure some avg60=${avg60} <= ${maxSomeAvg60}` }
}

// The dev-01 build-lock wrapper only works when its directory shadows every
// other cargo/npm/npx on PATH. Returns an error string, or null when safe.
export function lockWrapperProblem(lockDir, pathValue) {
  if (!lockDir || !existsSync(lockDir)) return null
  const wrapped = new Set(readdirSync(lockDir))
  const entries = (pathValue || '').split(delimiter).filter(Boolean).map((entry) => resolve(entry))
  const lockIndex = entries.indexOf(resolve(lockDir))
  if (lockIndex === -1) return `build-lock wrapper ${lockDir} is not on PATH`
  for (const entry of entries.slice(0, lockIndex)) {
    for (const name of ['cargo', 'npm', 'npx']) {
      if (wrapped.has(name) && existsSync(join(entry, name))) {
        return `${join(entry, name)} shadows the build-lock wrapper in ${lockDir}`
      }
    }
  }
  return null
}

// Keeps the head and the tail of a step's output so logs stay small on a
// RAM-backed /tmp while preserving the lines that usually explain a failure.
export class OutputCapture {
  constructor(maxBytes) {
    this.headLimit = Math.floor(maxBytes / 4)
    this.tailLimit = maxBytes - this.headLimit
    this.head = ''
    this.tail = ''
    this.dropped = 0
  }

  append(text) {
    if (this.head.length < this.headLimit) {
      const room = this.headLimit - this.head.length
      this.head += text.slice(0, room)
      text = text.slice(room)
    }
    this.tail += text
    if (this.tail.length > this.tailLimit) {
      const excess = this.tail.length - this.tailLimit
      this.dropped += excess
      this.tail = this.tail.slice(excess)
    }
  }

  text() {
    const marker = this.dropped > 0 ? `\n[ci-local: ${this.dropped} bytes truncated]\n` : ''
    return this.head + marker + this.tail
  }

  lastLines(count) {
    const lines = (this.head + this.tail).trimEnd().split('\n')
    return lines.slice(-count).join('\n')
  }
}
