// LOC rules: file limit, documented allowances, the ratchet that only lets
// allowances go down, and the anti-fragmentation counter.
import { lineCount, toRepoPath } from './loc-scan.mjs'

const MAX_LISTED_FRAGMENTS = 20

// Returns { violations, stale, ratchet, fragments, edits } where `edits`
// describes what `--update` may lower or remove (never raise or add).
export function evaluateLoc(policy, scan, repoRoot) {
  const result = { violations: [], stale: [], ratchet: [], fragments: null, edits: { allow: new Map(), fragmentCount: null } }
  const seenAllow = new Set()
  const repoFiles = scan.files.map((file) => ({ rel: toRepoPath(repoRoot, file), lines: lineCount(file) }))
  for (const { rel, lines } of repoFiles) {
    const entry = policy.allow[rel]
    if (!entry) {
      if (lines > policy.maxLines) result.violations.push(rel + ' has ' + lines + ' LOC (max ' + policy.maxLines + ')')
      continue
    }
    seenAllow.add(rel)
    checkAllowance(rel, lines, Number(entry.linesAtBaseline), policy, result)
  }
  for (const rel of Object.keys(policy.allow)) {
    if (seenAllow.has(rel)) continue
    result.stale.push(rel + ' is listed in scripts/loc-baseline.json but no longer exists' + updateHint(policy))
    result.edits.allow.set(rel, null)
  }
  for (const rel of Object.keys(policy.ignore)) {
    if (!scan.seenIgnore.has(rel) && policy.ignore[rel].optional !== true) {
      result.stale.push(rel + ' is ignored in scripts/loc-baseline.json but no longer exists')
    }
  }
  if (policy.fragmentPatterns) checkFragments(policy, repoFiles, result)
  return result
}

function checkAllowance(rel, lines, linesAtBaseline, policy, result) {
  if (lines <= policy.maxLines) {
    result.stale.push(rel + ' is now ' + lines + ' LOC; remove it from scripts/loc-baseline.json' + updateHint(policy))
    result.edits.allow.set(rel, null)
  } else if (Number.isFinite(linesAtBaseline) && lines > linesAtBaseline + policy.allowedGrowthLines) {
    result.violations.push(
      rel + ' grew to ' + lines + ' LOC (baseline ' + linesAtBaseline + ', allowed growth ' + policy.allowedGrowthLines + ')',
    )
  } else if (Number.isFinite(linesAtBaseline) && lines < linesAtBaseline) {
    result.edits.allow.set(rel, lines)
    if (policy.ratchet) {
      result.ratchet.push(rel + ' shrank to ' + lines + ' LOC (baseline ' + linesAtBaseline + '); run check-loc --update to lower it')
    }
  }
}

// Fragment files (part_NN by default) may never grow in number: the
// recorded legacy count is a ceiling that `--update` lowers.
function checkFragments(policy, repoFiles, result) {
  const files = repoFiles.map((file) => file.rel).filter((rel) => policy.fragmentPatterns.some((pattern) => pattern.test(rel)))
  const recorded = policy.legacyFragments?.count ?? 0
  result.fragments = { count: files.length, recorded }
  if (files.length > recorded) {
    const listed = files.slice(0, MAX_LISTED_FRAGMENTS).join(', ')
    const more = files.length > MAX_LISTED_FRAGMENTS ? ` and ${files.length - MAX_LISTED_FRAGMENTS} more` : ''
    result.violations.push(
      `fragment files grew to ${files.length} (legacyFragments.count ${recorded}); split by responsibility, ` +
        `not into part_NN files: ${listed}${more}`,
    )
  } else if (files.length < recorded) {
    result.edits.fragmentCount = files.length
    result.ratchet.push(`fragment files dropped to ${files.length} (legacyFragments.count ${recorded}); run check-loc --update to lower it`)
  }
}

function updateHint(policy) {
  return policy.ratchet ? ' (check-loc --update removes it)' : ''
}

// Applies the lowering edits to the raw baseline object. Returns a list of
// human-readable changes.
export function applyLocUpdate(baseline, edits) {
  const changes = []
  for (const [rel, lines] of edits.allow) {
    if (!baseline.allow?.[rel]) continue
    if (lines === null) {
      delete baseline.allow[rel]
      changes.push(`removed allow entry ${rel}`)
    } else {
      changes.push(`lowered ${rel} linesAtBaseline ${baseline.allow[rel].linesAtBaseline} -> ${lines}`)
      baseline.allow[rel].linesAtBaseline = lines
    }
  }
  if (edits.fragmentCount !== null) {
    const previous = baseline.legacyFragments?.count ?? 0
    baseline.legacyFragments = { ...(baseline.legacyFragments ?? {}), count: edits.fragmentCount }
    changes.push(`lowered legacyFragments.count ${previous} -> ${edits.fragmentCount}`)
  }
  return changes
}
