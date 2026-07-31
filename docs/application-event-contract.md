# Application event contract

Klaxond owns a small language-neutral event contract for applications that send
operator notifications through `/webhook/{severity}`. The canonical SDKs live
under `sdk/rust` and `sdk/go`; consumers must pin an exact Klaxond commit or a
module tag and may vendor that pinned source for hermetic container builds.
The language-neutral source is
[`schemas/application-event-v1.schema.json`](schemas/application-event-v1.schema.json).

The stable event fields are `kind`, `severity`, `status`, `title`, `body`,
`occurred_at`, optional `dedup_key`, optional `runbook_url`, and string labels.
The SDK renders these fields into the Alertmanager-compatible envelope already
understood by Klaxond. Transport credentials, retries, persistence, and
application-specific deduplication remain consumer responsibilities.

Do not construct a second ad-hoc Klaxond JSON shape in an application. Extend
this contract with backward-compatible optional fields and update both SDK
implementations plus their contract tests in the same commit.
