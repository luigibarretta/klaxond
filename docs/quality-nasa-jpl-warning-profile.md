# NASA/JPL Warning Profile

Klaxond uses a warning-only profile inspired by the NASA/JPL Power of Ten and
JPL C coding standard. This is not a certification claim and is not full
flight-software compliance. It is a maintainability ratchet that makes risky
shape visible before it becomes a hard gate.

Current warning thresholds:

- Source file over 300 lines.
- Function/method over 60 lines.
- Function/method with more than 6 parameters.

Run locally:

```sh
npm run nasa:warn
```

The command exits successfully by default, even when warnings are present. To
trial a future blocking gate:

```sh
NASA_WARNINGS_FAIL=1 npm run nasa:warn
```

Useful knobs:

- `NASA_WARN_FILE_LINES`: default `300`.
- `NASA_WARN_FUNCTION_LINES`: default `60`.
- `NASA_WARN_MAX_PARAMETERS`: default `6`.
- `NASA_WARNINGS_LIMIT`: default `200` warnings per category; use `0` for all.
- `NASA_WARNINGS_ANNOTATIONS=0`: disable GitHub/Gitea-style warning annotations.

## Refactor Policy

The script measures structural shape; it does not decide architecture. A warning
marks code that deserves review, not code that must be split mechanically.

For Rust code, preserve idiomatic Rust ahead of the line counter:

- Keep cohesive `match` statements and linear control flow when they are clearer
  than a web of tiny helpers.
- Prefer domain boundaries, modules, and structs that name real concepts.
- Use parameter structs when they reduce coupling or make call sites harder to
  misuse; avoid builders or traits that only satisfy the warning profile.
- Extract pure logic when it can be tested directly or reused by another domain.
- Do not split code solely to get below 60 function lines or 300 file lines.
- Accept a warning when a straightforward function is clearer than fragmented
  indirection; document that reason in the PR, commit message, or an allowlist if
  one is introduced.

Good cleanup usually removes duplication, isolates a domain, shrinks a risky
handler, or makes tests easier to target. Low-value cleanup creates helpers whose
only job is to move lines around.

The profile deliberately starts with structural checks only. Other NASA/JPL
ideas such as fixed loop bounds, assertion density, pointer restrictions, and
checked return values require language-specific analysis and should be added as
separate, reviewed rules instead of broad text heuristics.

## Baseline Policy

Historical exceptions must stay explicit. The LOC guard already keeps reasons in
`scripts/loc-baseline.json`; any future NASA warning allowlist should follow the
same pattern with a short reason for each accepted warning. Baselines are for
documented debt, not for hiding new warnings.
