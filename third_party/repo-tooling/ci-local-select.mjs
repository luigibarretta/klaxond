// Step selection (--only/--from/--quick plus needs closure) and --list --json.

export function selectSteps(steps, options) {
  const byName = new Map(steps.map((step) => [step.name, step]))
  for (const name of [...(options.only ?? []), ...(options.from ? [options.from] : [])]) {
    if (!byName.has(name)) throw new Error(`unknown step: ${name} (known: ${[...byName.keys()].join(', ')})`)
  }
  let selected = steps
  if (options.from) selected = selected.slice(selected.findIndex((step) => step.name === options.from))
  if (options.only) selected = selected.filter((step) => options.only.includes(step.name))
  if (options.quick) selected = selected.filter((step) => step.quick)
  if (selected.length === 0) throw new Error('no steps selected')
  const added = options.needs === false ? [] : addNeeds(selected, byName)
  const chosen = new Set([...selected, ...added.map((entry) => byName.get(entry.name))])
  // Manifest order is a valid execution order because needs point backwards.
  return { steps: steps.filter((step) => chosen.has(step)), added }
}

function addNeeds(selected, byName) {
  const chosen = new Set(selected.map((step) => step.name))
  const added = []
  const queue = [...selected]
  while (queue.length > 0) {
    const step = queue.shift()
    for (const need of step.needs) {
      if (chosen.has(need)) continue
      chosen.add(need)
      added.push({ name: need, by: step.name })
      queue.push(byName.get(need))
    }
  }
  return added
}

export function listJson(manifest, selected) {
  const chosen = new Set(selected)
  return {
    schemaVersion: 1,
    fixtures: Object.keys(manifest.fixtures),
    steps: manifest.steps.map((step) => ({
      name: step.name,
      selected: chosen.has(step),
      kind: step.uses ? 'builtin' : 'run',
      uses: step.uses ?? null,
      run: step.run ?? null,
      cwd: step.cwd,
      heavy: step.heavy,
      quick: step.quick,
      timeout_s: step.timeoutS,
      needs: step.needs,
      fixtures: step.fixtures,
      writes: step.writes,
    })),
  }
}
