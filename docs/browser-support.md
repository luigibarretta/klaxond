# Browser support

Klaxond targets the current and previous stable releases of:

- Chrome and Chromium-based Edge;
- Firefox;
- Safari on macOS and iOS.

The automated release gate runs the portable UI suite against Playwright's
Chromium, Firefox and WebKit engines. WebKit is the closest repeatable Linux CI
proxy for Safari, but it is not a substitute for a final smoke test in the
shipping macOS and iOS Safari versions.

## Required release coverage

The following flows must pass on all three automated browser engines:

- first-run redirect and Setup checklist;
- navigation, language and theme preferences;
- Status, flow, delivery history, logs and audit views;
- routing, cascade, noise-control and emergency-policy forms;
- configuration import preview and safe restore;
- local authentication, logout and read-only viewer behavior;
- responsive reflow at a narrow viewport.

Passkey registration and login use platform authenticators. Playwright's
context-scoped virtual authenticator exercises registration, login, dialog
keyboard behavior and deletion in Chromium, Firefox and WebKit as part of
`npm run test:e2e`.

Before a numbered public release, repeat the passkey lifecycle manually in the
current and previous supported macOS Safari versions and smoke test the core
responsive flow on a physical iPhone or iPad. WebKit on Linux remains a useful
regression gate, but is not evidence that the shipping Apple browser, Keychain
and platform authenticator were exercised.

## Compatibility policy

- Internet Explorer and browsers without native ES modules are not supported.
- A browser-specific failure in a core flow blocks a numbered release.
- A platform-authenticator limitation may be documented only when password,
  OIDC or another configured login path remains available.
- Browser tests supplement keyboard, contrast and assistive-technology checks;
  they do not establish complete WCAG conformance.

Report a compatibility problem with the browser name and version, operating
system, affected route, console error if available and a screenshot with
credentials removed.
