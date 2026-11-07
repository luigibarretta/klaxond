// Expiry dates ("until") shared by LOC baselines, overrides and audit ignores.
// An entry is valid through its `until` day (UTC) and expired from the day
// after; within EXPIRY_WARNING_DAYS of its date it is reported as expiring.

export const EXPIRY_WARNING_DAYS = 14
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/
const DAY_MS = 24 * 60 * 60 * 1000

// REPO_TOOLING_TODAY (YYYY-MM-DD) pins "today" for reproducible local runs
// and tests. It is ignored in CI (CI=true or 1), where expiry must use the
// real date; ci-local --ci also clears it for every step.
export function today(env = process.env) {
  const pinned = env.REPO_TOOLING_TODAY
  const inCi = env.CI === 'true' || env.CI === '1'
  if (pinned !== undefined && pinned !== '' && !inCi) {
    if (!isIsoDate(pinned)) throw new Error(`REPO_TOOLING_TODAY must be a YYYY-MM-DD date, got ${pinned}`)
    return pinned
  }
  return new Date().toISOString().slice(0, 10)
}

export function isIsoDate(value) {
  if (typeof value !== 'string') return false
  const match = ISO_DATE.exec(value)
  if (!match) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}

// Returns { state: 'ok' | 'expiring' | 'expired', daysLeft }.
export function expiryStatus(until, todayValue) {
  const daysLeft = Math.round((Date.parse(`${until}T00:00:00Z`) - Date.parse(`${todayValue}T00:00:00Z`)) / DAY_MS)
  if (daysLeft < 0) return { state: 'expired', daysLeft }
  if (daysLeft <= EXPIRY_WARNING_DAYS) return { state: 'expiring', daysLeft }
  return { state: 'ok', daysLeft }
}

// Validates an optional `until` and records an error (expired or malformed)
// or a warning (expiring soon) for `label`.
export function checkUntil(until, label, todayValue, errors, warnings) {
  if (until === undefined) return
  if (!isIsoDate(until)) {
    errors.push(`${label}.until must be a YYYY-MM-DD date`)
    return
  }
  const status = expiryStatus(until, todayValue)
  if (status.state === 'expired') errors.push(`${label} expired on ${until}; fix the cause or renew it with a new reason`)
  else if (status.state === 'expiring') warnings.push(`${label} expires on ${until} (${status.daysLeft} day(s) left)`)
}
