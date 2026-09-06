# ACK and emergency profiles

Klaxond can keep selected incidents active until a signed acknowledgement,
producer recovery, a matching inhibition, the attempt limit, or the real expiry
time. Routing is controlled by ordered profiles so `critical`, `warning`,
`info`, `page`, application-specific severities, sources, events, and labels can
use different retry and escalation behavior.

## Turnkey setup

1. Configure a token-bearing ntfy topic for every severity routed by an enabled
   profile.
2. Configure Telegram, authenticated SMTP, or both. Credentials stay in the
   deployment secret store; the emergency editor contains no channel secrets.
3. Set the canonical HTTPS public origin and keep the database, configuration,
   and ACK signing key on persistent storage.
4. Open **Emergency receipts**, add or edit profiles, inspect the generated
   timelines and routing warnings, then choose the fallback profile.
5. Open **Policy simulator** and test representative source, severity, event,
   and label combinations. Simulation never sends a notification and never
   creates a receipt.
6. Enable durable emergency routing only after the configuration passes the
   on-screen validation and `klaxond doctor`.

The portable Compose example makes profile settings UI/TOML-owned. Legacy
`KLAXOND_EMERGENCY_*` variables are documented but commented out because every
present environment value is an immutable runtime override.

## Profile schema

Profiles have a stable `id`, operator-facing `name`, `enabled` flag, integer
`priority`, matchers, retry lifecycle, and independent channel escalation:

```toml
[emergency]
enabled = true
allow_insecure_public_url = false
allow_ntfy_only = false
exclude_sources = ["api-test"]
fallback_profile = "critical-default"

[[emergency.profiles]]
id = "critical-default"
name = "Critical default"
enabled = true
priority = 100
severities = ["critical"]
sources = []
retry_seconds = 60
expire_seconds = 3600
max_attempts = 50
lease_seconds = 60
notify_on_expiry = true
auto_resolve = true

[emergency.profiles.match]

[emergency.profiles.telegram]
enabled = true
after_attempts = 3

[emergency.profiles.smtp]
enabled = true
after_attempts = 5
```

`severities` and `sources` are accessible chip controls in the UI. Values are
exact, case-insensitive names or the existing `re:` regular-expression syntax.
An empty list means any value. `match` uses the same exact/`re:` syntax for
labels and the special `event`, `alertname`, `severity`, and `source` keys. All
non-empty matcher groups on a profile must match.

Each enabled fallback channel has its own `after_attempts`. Attempt 1 is the
initial delivery; a fallback configured for attempt 1 is included in that
initial broadcast. Later thresholds are attempted once when the receipt reaches
that attempt. ntfy remains the retry channel on every attempt.

The timeline shows initial delivery, retry cadence, each channel escalation,
the reachable attempt limit, and the independent expiry clock. The editor
flags a lease shorter than the sum of enabled sequential channel timeouts plus
the safety margin. The server repeats this validation and refuses to persist an
unsafe policy.

## Deterministic selection

Selection follows this order:

1. When global emergency routing is disabled, delivery remains normal.
2. A globally excluded source never creates an emergency receipt.
3. A recognized `emergency=false` value (`false`, `0`, `no`, or `off`) is an
   explicit bypass.
4. Enabled profiles whose severity, source, and label/event matchers all match
   are ordered by descending priority. The first visible profile wins equal
   priorities.
5. A recognized `emergency=true` value (`true`, `1`, `yes`, or `on`) uses the
   normal matching winner, or the configured enabled fallback when nothing
   matches.
6. Without a match or explicit true value, delivery follows the normal routing
   policy and no receipt is created.

Unknown values of the `emergency` label are ignored; they are not treated as an
opt-out. The editor reports equal priorities, exactly shadowed profiles, and
known severities that have no profile route. The simulator shows the winning
profile, selection reason, every matching profile, channels, and timeline.

## Receipt-safe migration

When `[emergency].profiles` is absent, Klaxond converts the legacy global
fields into the stable `critical-default` profile in memory. Legacy environment
variables continue to override only that fallback profile, preserving existing
deployments while allowing additional TOML profiles where no conflicting
override is present.

Database schema 7 stores `policy_id`, `policy_name`, and a complete non-secret
`policy_snapshot_json` on every receipt. Retry interval, expiry, attempt limit,
lease, channel thresholds, expiry notification, and auto-resolve therefore do
not change when an operator edits or deletes the live profile later. A repeated
event coalescing into an active receipt keeps the original snapshot. During an
upgrade, a transaction materializes the current legacy policy snapshot only for
active receipts that predate schema 7.

Back up and verify the database and configuration before switching ownership or
upgrading. Do not change profile ownership while incompatible active receipts
exist. The maintainer Ansible deployment enforces this gate, seeds the exact
legacy production policy once, and records a marker without overwriting future
UI changes.

## Ownership and export

The editor labels the effective source of truth as `UI`, `environment`, or
`mixed`. Any present environment override remains immutable and is named on the
affected control; an API update that tries to change it returns `409`.

`GET /api/emergency-config/export` downloads canonical, non-secret TOML for the
effective policy. Channel tokens, SMTP credentials, authentication secrets, and
ingest secrets are never included. The complete API schemas and error responses
are in [`openapi.yaml`](openapi.yaml).

The global `allow_insecure_public_url` and `allow_ntfy_only` settings remain
separate unsafe exceptions. Enabling either through the UI requires a danger
confirmation and should be limited to isolated development.

## Rollback

Keep the pre-upgrade database/configuration backup and the previous numbered
image. A rollback restores the matching backup and old image together. Rolling
back only the binary after schema 7 is not the supported path: restore the
verified pre-migration database so the old binary never has to interpret new
receipt columns or policy profiles.
