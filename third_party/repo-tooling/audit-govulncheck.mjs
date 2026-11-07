#!/usr/bin/env node
// Runs `govulncheck -format json ./...` in the current Go module and fails
// only on vulnerabilities whose vulnerable symbols are called, minus ignored
// ids (an OSV id such as GO-2024-1234 or any of its aliases). govulncheck has
// no ignore flag of its own, hence this wrapper.
// usage: audit-govulncheck [--ignore ID]... [-- extra govulncheck args]
import { spawnSync } from 'node:child_process'

function main(argv) {
  const separator = argv.indexOf('--')
  const own = separator < 0 ? argv : argv.slice(0, separator)
  const extra = separator < 0 ? [] : argv.slice(separator + 1)
  const ignored = new Set()
  for (let index = 0; index < own.length; index += 1) {
    if (own[index] !== '--ignore' || !own[index + 1]) {
      console.error(`audit-govulncheck: unknown argument ${own[index]}`)
      return 2
    }
    ignored.add(own[++index])
  }
  const result = spawnSync('govulncheck', ['-format', 'json', ...extra, './...'], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
  if (result.error) {
    console.error(`audit-govulncheck: cannot run govulncheck: ${result.error.message}`)
    return 2
  }
  if (result.status !== 0) {
    process.stderr.write(result.stderr)
    console.error(`audit-govulncheck: govulncheck exited with ${result.status}`)
    return 2
  }
  let messages
  try {
    messages = parseStream(result.stdout)
  } catch (error) {
    console.error(`audit-govulncheck: cannot parse govulncheck output: ${error.message}`)
    return 2
  }
  // Every real run starts with a config message; anything else (no output,
  // a wrapper that printed nothing) must not read as "no vulnerabilities".
  if (!messages.some((message) => message.config)) {
    console.error('audit-govulncheck: govulncheck produced no JSON config message; refusing to treat the output as clean')
    return 2
  }
  return report(messages, ignored)
}

function report(messages, ignored) {
  const aliases = new Map()
  for (const message of messages) {
    if (message.osv?.id) aliases.set(message.osv.id, [message.osv.id, ...(message.osv.aliases ?? [])])
  }
  const called = new Map()
  for (const message of messages) {
    const finding = message.finding
    if (!finding?.osv || !finding.trace?.[0]?.function) continue
    const frame = finding.trace[0]
    called.set(finding.osv, `${frame.module ?? '?'}@${frame.version ?? '?'} ${frame.package ?? ''}.${frame.function}`)
  }
  const failing = []
  for (const [id, where] of called) {
    const names = aliases.get(id) ?? [id]
    if (names.some((name) => ignored.has(name))) console.log(`ignored ${id} (${names.join(', ')}): ${where}`)
    else failing.push(`${id} (${names.slice(1).join(', ') || 'no aliases'}): called via ${where}`)
  }
  if (failing.length === 0) {
    console.log(`govulncheck: no called vulnerabilities (${called.size} ignored or none found)`)
    return 0
  }
  console.error(`govulncheck: ${failing.length} called vulnerability(ies):`)
  for (const line of failing) console.error(`- ${line}`)
  return 1
}

// govulncheck prints a stream of (pretty-printed) JSON objects.
function parseStream(text) {
  const messages = []
  let depth = 0
  let start = -1
  let inString = false
  let escaped = false
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (inString) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === '"') inString = false
      continue
    }
    if (char === '"') inString = true
    else if (char === '{') {
      if (depth === 0) start = index
      depth += 1
    } else if (char === '}') {
      depth -= 1
      if (depth === 0) messages.push(JSON.parse(text.slice(start, index + 1)))
      if (depth < 0) throw new Error('unbalanced braces')
    }
  }
  if (depth !== 0) throw new Error('truncated JSON stream')
  return messages
}

process.exitCode = main(process.argv.slice(2))
