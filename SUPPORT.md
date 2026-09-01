# Support

Klaxond is maintained on a best-effort basis without a commercial support SLA.

- Use [GitHub issues](https://github.com/luigibarretta/klaxond/issues) for
  reproducible bugs and focused feature requests.
- Use [private vulnerability reporting](SECURITY.md) for suspected security
  issues.
- Check the [production deployment guide](docs/production-deployment.md),
  `klaxond doctor --json`, `/healthz` and the redacted application logs before
  opening an operational issue.

Include the Klaxond version or image digest, deployment shape, browser version
for UI problems, sanitized reproduction steps and the expected result. Never
attach `.env`, exported settings bundles, databases, session keys, tokens or
unsanitized alert payloads.
