# Security policy

## Supported versions

The latest numbered release is supported. Security fixes may require upgrading
directly to the newest release; mutable development tags are not supported.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/luigibarretta/klaxond/security/advisories/new).
Do not open a public issue and do not include production secrets, exported
configuration, database contents, tokens or personal notification payloads.

Include the affected version/digest, deployment shape, minimal reproduction,
expected impact and any relevant sanitized logs. You should receive an initial
acknowledgement within seven days. Disclosure and remediation timing will be
coordinated according to severity and exploitability.

## Deployment boundary

Klaxond processes privileged alert data and holds notification credentials.
Operators must enable authentication before public exposure, configure unique
webhook secrets, retain the loopback-safe default or place the service behind a
reviewed HTTPS reverse proxy, and keep `/data` plus its backups confidential.
