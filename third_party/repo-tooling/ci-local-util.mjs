// Shared validation helpers for the ci-local modules.

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function nonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== ''
}

export function rejectUnknown(object, allowed, label, errors) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) errors.push(`${label} has unknown key: ${key}`)
  }
}

export function optionalPositiveInt(value, label, fallback, errors) {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || value <= 0) {
    errors.push(`${label} must be a positive integer`)
    return fallback
  }
  return value
}

export function optionalPositiveNumber(value, label, fallback, errors) {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !(value > 0)) {
    errors.push(`${label} must be a positive number`)
    return fallback
  }
  return value
}

export function relativePath(value) {
  return nonEmptyString(value) && !value.startsWith('/') && !value.split('/').includes('..')
}

// A command is a shell string or a non-empty argv array of non-empty strings.
export function validCommand(value) {
  if (typeof value === 'string') return value.trim() !== ''
  return Array.isArray(value) && value.length > 0 && value.every(nonEmptyString)
}

export function validateEnvObject(env, where, errors) {
  if (env === undefined) return {}
  if (!isPlainObject(env) || !Object.values(env).every((value) => typeof value === 'string')) {
    errors.push(`${where} must be an object of string values`)
    return {}
  }
  return env
}

export function stringList(value, where, errors, check = nonEmptyString) {
  if (value === undefined) return []
  if (!Array.isArray(value) || !value.every(check)) {
    errors.push(`${where} must be an array of ${check === relativePath ? 'relative paths' : 'non-empty strings'}`)
    return []
  }
  return value
}
