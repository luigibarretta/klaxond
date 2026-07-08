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

The profile deliberately starts with structural checks only. Other NASA/JPL
ideas such as fixed loop bounds, assertion density, pointer restrictions, and
checked return values require language-specific analysis and should be added as
separate, reviewed rules instead of broad text heuristics.
