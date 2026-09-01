# Product definition

## Product promise

Klaxond helps a self-hosted operator notice, understand and act on important
infrastructure events without depending on a single notification channel.

The core need is not "send another webhook". It is:

> When something important changes in my systems, tell me once, in a form I can
> understand on my phone, keep trying when delivery is uncertain, and show me
> what happened afterward.

Klaxond addresses that need by normalizing source-specific events, controlling
repeated noise, routing deliveries through independent channels, keeping an
auditable history and repeating selected emergencies until acknowledgement or
source recovery.

## Primary user persona

The primary persona is a hands-on self-hosted operator, DevOps engineer or SRE
responsible for a personal lab or a small infrastructure estate.

They typically:

- operate several services but do not want the cost or administration of a
  full enterprise incident-management platform;
- already use tools such as Grafana Alertmanager, Uptime Kuma, Healthchecks or
  ntfy;
- receive alerts on a phone and need the title, affected system, severity and
  next action to be clear at a glance;
- care about delivery reliability, duplicate suppression, private deployment
  and inspectable configuration;
- can operate Docker Compose and an HTTPS reverse proxy, but should not need to
  read Klaxond source code to finish setup.

Secondary users are small platform teams and application developers using the
Rust or Go event SDKs. They benefit from Klaxond, but their workflows must not
make the primary operator experience harder.

Klaxond is not intended to be a public multi-tenant notification service, a
consumer messaging application or a replacement for enterprise incident
management with staffing schedules, compliance workflows and contractual
support.

## Jobs to be done

1. Connect at least one existing alert source without exposing an
   unauthenticated webhook.
2. Deliver a readable test notification and know which channel accepted it.
3. Avoid repeated low-value notifications without hiding a real emergency.
4. Continue delivery through an independent fallback when the primary channel
   fails.
5. Keep a critical incident active until it is acknowledged or the producer
   reports recovery.
6. Reconstruct what was received, suppressed, attempted and acknowledged after
   the event.

## Effectiveness criteria

Technical correctness is necessary but is not enough to prove product
effectiveness. A public release should be evaluated against these outcomes:

- a new operator can identify whether Klaxond is a fit from the first screen of
  the README;
- a clean installation reaches its first authenticated dry run and its first
  real notification without undocumented steps;
- Setup always names the next blocking action and never reports production
  readiness while authentication, ingress protection or delivery is missing;
- every delivery attempt has an inspectable result and a successful fallback
  prevents unnecessary upstream retries;
- acknowledgement and source recovery stop future emergency retries;
- the main Setup, Status, Deliveries, Emergencies and test-notification flows
  work with keyboard navigation and on the supported browser matrix;
- failures explain what the operator can do next without exposing credentials.

The repository has strong automated evidence for routing, authentication,
storage, recovery and configuration behavior. Public usability is still a
product hypothesis until first-time operators complete the install and core
flow. Release feedback should therefore record time to first notification,
steps where documentation was needed, unclear labels and failed browser/device
combinations.

## Product priorities

When priorities conflict, use this order:

1. no silent loss of an important event;
2. no unsafe public exposure or secret disclosure;
3. a clear next action for the operator;
4. control of duplicate and low-value noise;
5. advanced customization and deployment flexibility.
