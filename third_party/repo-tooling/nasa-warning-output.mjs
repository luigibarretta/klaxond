export function printNasaWarningReport(report, policy) {
  printSection('File size warnings', report.fileWarnings, policy)
  printSection('Function length warnings', report.functionWarnings, policy)
  printSection('Parameter count warnings', report.parameterWarnings, policy)

  const summary = [
    `NASA/JPL warning profile: ${report.totalWarnings} warning(s)`,
    `files>${policy.fileWarnLines}: ${report.fileWarnings.length}`,
    `functions>${policy.functionWarnLines}: ${report.functionWarnings.length}`,
    `params>${policy.maxParameters}: ${report.parameterWarnings.length}`,
    `checked files: ${report.filesChecked}`,
  ].join(', ')

  if (report.totalWarnings === 0) {
    console.log(summary)
    printPolicyNotice(console.log)
    return
  }

  console.warn(summary)
  console.warn('This is a warning profile, not full NASA/JPL compliance. Set NASA_WARNINGS_FAIL=1 to make it blocking.')
  printPolicyNotice(console.warn)
}

function printPolicyNotice(write) {
  write('NASA/JPL-inspired warnings are review candidates, not refactor orders.')
  write('Preserve idiomatic Rust, domain boundaries, behavior, and test clarity ahead of LOC thresholds.')
}

function printSection(title, warnings, policy) {
  const sorted = warnings.toSorted((a, b) => b.actual - a.actual || a.file.localeCompare(b.file))
  const limit = policy.outputLimit === 0 ? sorted.length : Math.min(policy.outputLimit, sorted.length)
  if (sorted.length === 0) {
    console.log(`${title}: none`)
    return
  }
  console.warn(`${title}: ${sorted.length}`)
  for (let index = 0; index < limit; index += 1) emitWarning(sorted[index], policy)
  if (limit < sorted.length) {
    console.warn(`... ${sorted.length - limit} more ${title.toLowerCase()} hidden; set NASA_WARNINGS_LIMIT=0 to print all.`)
  }
}

function emitWarning(warning, policy) {
  const text = `${warning.file}:${warning.line} ${warning.message}`
  if (policy.annotations) console.warn(`::warning file=${warning.file},line=${warning.line}::${escapeAnnotation(warning.message)}`)
  console.warn('- ' + text)
}

function escapeAnnotation(value) {
  return value.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A')
}
