import { extname } from 'node:path'

export function findFunctions(rel, text) {
  const ext = extname(rel)
  if (ext === '.rs') return findRustFunctions(rel, text)
  if (['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(ext)) return findEcmaFunctions(rel, text)
  if (ext === '.py') return findPythonFunctions(rel, text)
  return []
}

function findRustFunctions(rel, text) {
  const results = []
  const regex = /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^;{}()]*>)?\s*\(/g
  collectBraceFunctions(rel, text, regex, 'fn', results)
  return results
}

function findEcmaFunctions(rel, text) {
  const results = []
  const functionRegex = /\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g
  collectBraceFunctions(rel, text, functionRegex, 'function', results)
  collectArrowFunctions(rel, text, results)
  return dedupeFunctions(results)
}

function collectArrowFunctions(rel, text, results) {
  const arrowRegex = /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>/g
  for (const match of text.matchAll(arrowRegex)) {
    const arrowIndex = text.indexOf('=>', match.index)
    const paramsOpen = text.indexOf('(', match.index)
    const paramsClose = paramsOpen >= 0 && paramsOpen < arrowIndex ? findMatching(text, paramsOpen, '(', ')') : -1
    const bodyOpen = text.indexOf('{', arrowIndex)
    if (bodyOpen < 0 || bodyOpen - arrowIndex > 256) continue
    const bodyClose = findMatchingBrace(text, bodyOpen)
    if (bodyClose < 0) continue
    const paramsText = paramsClose > paramsOpen ? text.slice(paramsOpen + 1, paramsClose) : ''
    results.push(buildFunctionResult({ rel, text, startIndex: match.index, endIndex: bodyClose, name: match[1], kind: 'arrow function', paramsText, syntax: 'ecma' }))
  }
}

function collectBraceFunctions(rel, text, regex, kind, results) {
  for (const match of text.matchAll(regex)) {
    const paramsOpen = text.indexOf('(', match.index)
    const paramsClose = paramsOpen >= 0 ? findMatching(text, paramsOpen, '(', ')') : -1
    if (paramsClose < 0) continue
    const bodyOpen = findNextBodyOpen(text, paramsClose)
    if (bodyOpen < 0) continue
    const bodyClose = findMatchingBrace(text, bodyOpen)
    if (bodyClose < 0) continue
    const paramsText = text.slice(paramsOpen + 1, paramsClose)
    const syntax = rel.endsWith('.rs') ? 'rust' : 'ecma'
    results.push(buildFunctionResult({ rel, text, startIndex: match.index, endIndex: bodyClose, name: match[1], kind, paramsText, syntax }))
  }
}

function findPythonFunctions(rel, text) {
  const results = []
  const lines = text.split('\n')
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)/)
    if (!match) continue
    const header = collectPythonHeader(lines, index)
    const paramsText = header.slice(header.indexOf('(') + 1, header.lastIndexOf(')'))
    results.push({
      file: rel,
      name: match[2],
      kind: 'def',
      startLine: index + 1,
      lines: pythonFunctionLength(lines, index, match[1].length),
      parameters: countParameters(paramsText, 'python'),
    })
  }
  return results
}

function pythonFunctionLength(lines, start, indent) {
  let end = start
  for (let cursor = start + 1; cursor < lines.length; cursor += 1) {
    const bodyLine = lines[cursor]
    if (bodyLine.trim() === '') {
      end = cursor
      continue
    }
    const bodyIndent = bodyLine.match(/^\s*/)?.[0].length ?? 0
    if (bodyIndent <= indent) break
    end = cursor
  }
  return end - start + 1
}

function collectPythonHeader(lines, start) {
  let header = ''
  for (let index = start; index < lines.length; index += 1) {
    header += lines[index]
    if (lines[index].includes(':') && balancedParens(header)) break
  }
  return header
}

function buildFunctionResult({ rel, text, startIndex, endIndex, name, kind, paramsText, syntax }) {
  const startLine = lineForIndex(text, startIndex)
  return { file: rel, name, kind, startLine, lines: lineForIndex(text, endIndex) - startLine + 1, parameters: countParameters(paramsText, syntax) }
}

function countParameters(paramsText, syntax) {
  const trimmed = paramsText.trim()
  if (!trimmed) return 0
  const params = splitTopLevel(trimmed).filter((part) => part.trim().length > 0)
  if (syntax === 'rust') return params.filter((part) => !/^(?:mut\s+)?(?:&\s*)?(?:mut\s+)?self\b/.test(part.trim())).length
  if (syntax === 'python') return params.filter((part) => !['self', 'cls'].includes(part.trim().split(/[=:]/)[0].trim())).length
  return params.length
}

function splitTopLevel(text) {
  const parts = []
  let current = ''
  const depth = { paren: 0, bracket: 0, brace: 0, angle: 0 }
  let quote = null
  let escaped = false
  for (const char of text) {
    if (quote) {
      current += char
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === quote) quote = null
      continue
    }
    if (char === '"' || char === "'" || char === '`') {
      quote = char
      current += char
      continue
    }
    updateDepth(depth, char)
    if (char === ',' && isFlat(depth)) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }
  parts.push(current)
  return parts
}

function findNextBodyOpen(text, paramsClose) {
  for (let index = paramsClose + 1; index < text.length; index += 1) {
    if (text[index] === ';') return -1
    if (text[index] === '{') return index
    if (index - paramsClose > 1024) return -1
  }
  return -1
}

function findMatching(text, openIndex, open, close) {
  let depth = 0
  for (let index = openIndex; index < text.length; index += 1) {
    if (text[index] === open) depth += 1
    if (text[index] === close && --depth === 0) return index
  }
  return -1
}

function findMatchingBrace(text, openIndex) {
  let depth = 0
  const state = { mode: 'code', quote: null, escaped: false }
  for (let index = openIndex; index < text.length; index += 1) {
    const consumed = consumeNonCode(text, index, state)
    if (consumed !== null) {
      index = consumed
      continue
    }
    if (text[index] === '{') depth += 1
    else if (text[index] === '}' && --depth === 0) return index
  }
  return -1
}

function consumeNonCode(text, index, state) {
  const char = text[index]
  const next = text[index + 1]
  if (state.mode === 'line-comment') {
    if (char === '\n') state.mode = 'code'
    return index
  }
  if (state.mode === 'block-comment') {
    if (char === '*' && next === '/') {
      state.mode = 'code'
      return index + 1
    }
    return index
  }
  if (state.mode === 'string') {
    if (state.escaped) state.escaped = false
    else if (char === '\\') state.escaped = true
    else if (char === state.quote) state.mode = 'code'
    return index
  }
  if (char === '/' && next === '/') {
    state.mode = 'line-comment'
    return index + 1
  }
  if (char === '/' && next === '*') {
    state.mode = 'block-comment'
    return index + 1
  }
  if (char === '"' || char === "'" || char === '`') {
    state.mode = 'string'
    state.quote = char
    return index
  }
  return null
}

function updateDepth(depth, char) {
  if (char === '(') depth.paren += 1
  if (char === ')') depth.paren -= 1
  if (char === '[') depth.bracket += 1
  if (char === ']') depth.bracket -= 1
  if (char === '{') depth.brace += 1
  if (char === '}') depth.brace -= 1
  if (char === '<') depth.angle += 1
  if (char === '>') depth.angle = Math.max(0, depth.angle - 1)
}

function isFlat(depth) {
  return depth.paren === 0 && depth.bracket === 0 && depth.brace === 0 && depth.angle === 0
}

function lineForIndex(text, index) {
  let line = 1
  for (let cursor = 0; cursor < index; cursor += 1) if (text[cursor] === '\n') line += 1
  return line
}

function balancedParens(text) {
  let depth = 0
  for (const char of text) {
    if (char === '(') depth += 1
    if (char === ')') depth -= 1
  }
  return depth <= 0
}

function dedupeFunctions(functions) {
  const seen = new Set()
  const out = []
  for (const fn of functions) {
    const key = `${fn.file}:${fn.startLine}:${fn.name}`
    if (!seen.has(key)) {
      seen.add(key)
      out.push(fn)
    }
  }
  return out
}
