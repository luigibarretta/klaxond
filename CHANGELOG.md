# Klaxond — CHANGELOG

## 0.19.0 — 2026-09-01

- Define the primary self-hosted operator persona, core alert-delivery need,
  product non-goals and outcome-based effectiveness criteria for the public
  project.
- Restore the public GHCR and GitHub release path with native amd64/arm64
  builds, immutable commit-manifest promotion, signed attestations, vulnerability
  gates and a self-verifying Compose bundle.
- Make Chromium, Firefox and WebKit part of both continuous-integration browser
  gates, exercise the full passkey lifecycle in all three engines with a
  context-scoped virtual authenticator, and document the final physical Safari
  and iOS release boundary.
- Replace private-incubation installation guidance with a public numbered-image
  path and add release, support, conduct, issue and pull-request guidance for
  external users and contributors.
- Deliver producer recoveries immediately even when burst deduplication is
  enabled, so a concurrent lower-severity event cannot keep an emergency
  receipt active; document the fail-closed 401/404 ingest contract for every
  supported source.

## 0.18.1 — 2026-08-31

- Treat a Grafana or Alertmanager payload with `status=resolved` as the
  `resolved` delivery severity even when it arrives through a critical webhook
  endpoint. Durable emergency receipts now close on producer recovery instead
  of coalescing the recovery as another firing event.

## 0.18.0 — 2026-08-30

- Add a dedicated, authenticated GitHub ingest source at
  `/github/{severity}`, including bounded issue/comment rendering, repository
  and actor labels, stable comment-ID deduplication, OpenAPI coverage and
  browser/runtime configuration.
- Preserve a direct action to the original GitHub reply and identify events
  already queued for local analysis, preventing the phone copy from being
  analyzed a second time.

## 0.17.2 — 2026-08-29

- Make inbound webhook routes fail closed: configuring a per-source secret now
  both enables and authenticates that source, while unset sources reject
  delivery instead of accepting unauthenticated requests.
- Add dedicated authenticated `pve` and `blackstart` source coverage to setup,
  the routing UI and OpenAPI; `/blackstart/{severity}` preserves Blackstart's
  source identity instead of sharing the generic Grafana authentication slot.
  Existing Blackstart clients using `/webhook/{severity}` are recognized by
  their dedicated token during the rolling migration.
- Count only enabled-and-protected sources in production readiness, so unused
  integrations can remain safely disabled without blocking setup.

## 0.17.1 — 2026-08-29

- Make browser logout navigation atomic so background requests that observe the
  invalidated session cannot replace the deliberate signed-out destination.
- Exercise the real UI logout path in the live Authentik canary before proving
  SSO reuse and back-channel logout.

## 0.17.0 — 2026-08-29

- Replace the passive setup checklist with an ordered production-readiness
  workflow, live channel checks, blocking-step count, next actions and a safe
  first-run redirect to `/setup`.
- Add complete UI and API management for durable emergency policy, including
  per-field environment ownership, bounded validation, unsafe-option warnings
  and prospective production preflight before persistence.
- Add credential-redacted SQLite/PostgreSQL history settings to the setup UI;
  backend cutover preserves runtime authentication state and rolls the config
  file back atomically when validation or store activation fails.
- Make every TOML config mutation transactional on disk and in memory, so a
  rejected reload cannot leave the next restart pointed at an invalid config.
- Replace browser-native prompts and confirmations with a bilingual,
  keyboard-operable modal that traps focus, restores focus and exposes inline
  validation without leaking one-time secrets.
- Expand clean-install, Rust, OpenAPI and Playwright coverage for onboarding,
  readiness, emergency policy, storage boundaries and rollback behavior.
- Return the source repository to private incubation and pause GitHub release
  publication while the production build is validated in the maintainer
  deployment.

## 0.16.1 — 2026-08-29

- Make the turnkey release bundle self-verifying after extraction by recording
  archive-relative filenames in `SHA256SUMS`.

## 0.16.0 — 2026-08-29

- Build amd64 and ARM64 images on GitHub's matching native Linux runners, gate
  each platform independently, and assemble the public manifest only after all
  four backend/frontend jobs succeed.
- Run the release vulnerability gate through an immutable Trivy 0.68.2 image
  and scan both the `linux/amd64` and `linux/arm64` variants of every image.
- Start the exact immutable backend manifest against a fresh volume during the
  public release, then require health, doctor and production fail-closed gates.
- Update the vendored OIDC JWT verifier to `jsonwebtoken` 10.4, above the
  fixed 10.3 security floor reported by GitHub, while retaining the reviewed
  public-key-only verification boundary and full logout-token tests.
- Remove deployment-specific integration fallbacks from portable defaults.
  Uptime Kuma, Healthchecks, WUD, PVE, Shelfmark, Prowlarr and Decypharr action
  roots are now explicit `[render.source_urls]` / `KLAXOND_SOURCE_URL_*`
  settings; invalid or credential-bearing URLs fail startup preflight.
- Make Grafana host extraction and the UI flow diagram deployment-neutral;
  action links now derive from runtime configuration rather than maintainer
  domains.
- Make the source checkout and Docker build standalone by vendoring the reviewed
  authentication crate with immutable provenance and Apache-2.0 licensing.
- Add fail-closed emergency startup validation for canonical HTTPS callbacks,
  token-bearing ntfy routes, an independent Telegram/SMTP fallback and a lease
  long enough for the configured sequential delivery budget.
- Add `klaxond doctor` with human and JSON output, offline/online readiness
  checks, persistence validation and safe public-authentication diagnostics.
- Add a loopback-safe turnkey Compose default, versioned public GHCR images for
  amd64/arm64, SBOM and provenance attestations, keyless Cosign signatures,
  critical-vulnerability scanning and exact-digest release promotion.
- Add clean-install validation and public deployment, security and contribution
  documentation for operators outside the original homelab.

## 0.15.1 — 2026-08-29

- Show only the native one-tap acknowledgement on ntfy emergency pushes,
  while preserving the signed web confirmation fallback for Telegram and SMTP.

## 0.15.0 — 2026-08-29

- Add durable emergency receipts for critical incidents: repeat ntfy delivery
  until a signed acknowledgement, source recovery, expiry or the bounded
  attempt cap, with atomic SQLite/PostgreSQL leases across restarts and replicas.
- Add cross-device one-tap ntfy acknowledgement, a confirmation page for
  Telegram/SMTP, stable ntfy sequence IDs, automatic recovery closure and
  idempotent audited admin actions for acknowledge, retry and cancel.
- Escalate unacknowledged emergencies once to Telegram and SMTP at configurable
  attempt thresholds, retain escalation state, and expose emergency health,
  latency, transition and storage metrics.
- Add the Emergencies operations page, OpenAPI contracts, compose/TOML parity,
  environment validation and storage-migration coverage. Portable deployments
  remain opt-in; production can enable the feature declaratively.

## 0.14.40 — 2026-08-19

- Render a Healthchecks notification's observation timestamp separately from
  a producer-supplied real last-ping timestamp, preventing webhook `$NOW`
  values from being mislabeled as the check's latest successful ping.

## 0.14.39 — 2026-08-15

- Separate persistent session lifecycle, logout cleanup and trusted-proxy
  client IP resolution into focused auth modules without changing session,
  rotation or rate-limit policy.
- Group delivery and routing configuration models by domain while preserving
  their public types and serialized configuration format.
- Split deduplication, cascade and delivery admin mutations behind the existing
  handler facade, retaining payload leniency, validation and API behavior.

## 0.14.38 — 2026-08-15

- Split runtime configuration loading into typed render, routing, channel and
  server domains while preserving environment and TOML precedence.
- Isolate the PostgreSQL command worker from its public history facade without
  changing storage, retry or migration behavior.
- Refactor local, Basic and OIDC authentication into typed validation and
  callback boundaries while preserving API responses, step-up flow and session
  persistence semantics.

## 0.14.37 — 2026-08-14

- Complete Uptime Kuma noise control support across backend defaults, stable
  monitor identity keys, selective UI rules and persisted sidecar migration.
- Run the complete Rust, PostgreSQL persistence and Playwright suites in CI,
  make the RSA security guard independent of Git metadata, and align Cargo and
  OCI package metadata with the Apache-2.0 license.
- Preserve the canonical description, source URL and Apache-2.0 license on
  registry images, and verify those OCI labels after every immutable build.

## 0.14.36 — 2026-08-05

- Classify Uptime Kuma status-less `NOTICE` events as warnings instead of
  inheriting the critical DOWN webhook route. Advisory events such as domain
  registration expiry no longer produce false critical notifications.

## 0.14.35 — 2026-08-01

- Route `resolved` notifications to the informational ntfy topic when no
  dedicated recovery topic is configured, while preserving the distinct
  severity in delivery history, audit records and metrics. This prevents a
  successful Kuma recovery from being misclassified as a failed ntfy tier.

## 0.14.34 — 2026-07-31

- Build each release image only once on `main`, publish it under the immutable
  commit SHA, and promote that exact tested image to SemVer tags. Release tags
  now fail closed when their source image was not produced by the main CI run.
- Add npm dependency caching, bounded job timeouts, and cancellation of
  superseded runs on the same ref.

## 0.14.33 — 2026-07-31

- Normalize hyphens to underscores when deriving per-source ingest-secret
  environment keys, so `uptime-kuma` is protected by
  `KLAXOND_INGEST_SECRET_UPTIME_KUMA` instead of falling back to permissive mode.

## 0.14.32 — 2026-07-31

- Register `/uptime-kuma/*` as machine-to-machine ingress so requests bypass
  interactive OIDC and reach the source-specific token verifier.

## 0.14.31 — 2026-07-31

- Add authenticated `/uptime-kuma/<severity>` ingestion with native Kuma status parsing.
- Convert recovery heartbeats to `resolved`, enrich failures with sanitized monitor context,
  and link notifications to both Uptime Kuma and the Power & UPS correlation timeline.

## 0.14.30 — 2026-07-31

- Reso il timeout di ciascun tier Cascade configurabile dalla UI tra 1 e 60
  secondi, con limiti forniti dall'API e validazione backend rigorosa anziché
  correzioni silenziose.
- Aggiunto un warning persistente e una conferma esplicita quando ntfy viene
  impostato sotto i 15 secondi consigliati, incluso un warning strutturato
  nella risposta API per rendere visibile il rischio di consegne duplicate.

## 0.14.29 — 2026-07-31

- Portato il timeout ntfy predefinito da 5 a 15 secondi: il relay iOS via
  `ntfy.sh` può avere già accettato il messaggio mentre la risposta HTTP è
  ancora pendente, e un timeout troppo corto induceva retry e notifiche
  duplicate.
- Aggiunta `klaxond_delivery_tier_attempts_total`, con esito separato per tier
  e componente, e arricchito l'audit delivery con `tier_results`. Il monitoring
  può ora distinguere un tier fallito da una consegna complessivamente fallita
  ed escludere in modo sicuro il proprio meta-alert.

## 0.14.28 — 2026-07-27

- Resa race-safe la rotazione delle sessioni persistenti: richieste browser
  concorrenti riusano lo stesso successore entro una grace window breve senza
  indebolire logout, revoca di famiglia o scadenze.
- Le notifiche Grafana raggruppate conservano ora fino a 12 riepiloghi
  per-istanza, così alert come Trivy elencano servizi, host, immagini e
  vulnerabilità interessati invece di perdere le annotazioni non comuni.

## 0.14.27 — 2026-07-20

- Spostate le sessioni browser su record opachi persistenti in SQLite o
  PostgreSQL, con idle timeout, durata assoluta, rotazione atomica, limite per
  utente e revoca dell'intera famiglia al logout.
- Aggiunto OIDC Back-Channel Logout replay-safe con revoca per issuer, subject e
  session ID; discovery e refresh provider ora usano il client asincrono
  preparato di `auth-modules`.
- Persistiti lockout e rate state account con chiavi HMAC; i limiti burst per IP
  restano intenzionalmente in memoria.
- Resa atomica la migrazione dello stato auth tra backend history e protetto il
  cambio backend runtime con rollback della configurazione in caso di errore.
- Resa esplicita la trust boundary dei reverse proxy: il default accetta solo
  loopback e `AUTH_TRUSTED_PROXY_CIDRS` consente override deploy-time senza
  sovrascrivere i valori persistiti.

## 0.14.26 — 2026-07-06

- Rimossa la costante runtime hardcoded della versione: login page, status,
  metriche e meta UI ora derivano sempre da `CARGO_PKG_VERSION`.

## 0.14.25 — 2026-07-06

- Documentato il rischio transitive `rsa`/`RUSTSEC-2023-0071` con threat model
  esplicito per OIDC/WebAuthn public-key verification.
- Aggiunto un guard CI che blocca dipendenze dirette `rsa` e API RSA
  private-key/decrypt/signing nel codice Rust di produzione.
- Ottimizzato il frontend con debounce condiviso per le ricerche, TTL cache per
  GET ripetute, coalescing delle richieste identiche, abort delle richieste
  superate e invalidazione cache dopo mutation riuscite.

## 0.14.24 — 2026-07-05

- Aggiunto storico delivery persistente con SQLite di default sotto `/data` e
  backend PostgreSQL opzionale per installazioni multi-backend.
- Aggiunta migrazione CLI `klaxond history-migrate` tra SQLite e PostgreSQL.
- Documentati storage history, variabili compose/TOML, OpenAPI paginata per
  `/api/deliveries` e profilo compose PostgreSQL opzionale.
- Aggiunti esempi repo-local per scrape Prometheus e VictoriaMetrics/vmagent,
  accanto alla dashboard Grafana importabile.

## 0.14.23 — 2026-07-05

- Aggiunto `docker-compose.split.yml` con profili separati per backend,
  frontend e db/state, pensato per deploy multi-host.
- Aggiunta l'immagine `klaxond-frontend` basata su nginx, con proxy verso il
  backend per API, auth, webhook inclusi PVE, immagini renderizzate, metriche,
  OpenAPI e Swagger mantenendo auth e CSRF same-origin.
- Il frontend split preserva host/porta/protocollo inoltrati dai reverse proxy
  e mantiene relativi i redirect legacy `/ui/*`.
- Documentato che Klaxond non usa un DB SQL: il tier db/state e' il bundle
  file-backed sotto `/data`, montabile come volume esterno condiviso.
- Aggiunti test di regressione per copertura env compose split e template nginx.

## 0.14.22 — 2026-07-05

- Aggiunta una matrice testata che garantisce che ogni env applicativa esposta
  dal compose abbia un equivalente TOML o JSON; `KLAXOND_CONFIG` resta l'unica
  variabile bootstrap-only per scegliere il file TOML stesso.
- Aggiunti equivalenti TOML per `PORT`, i path runtime (`[paths]`) e
  `AUTH_SESSION_SECRET` (`[auth].session_secret`, esportabile anche in
  `auth-config.json`).

## 0.14.21 — 2026-07-05

- Allineata la parita' tra compose/TOML/sidecar e UI: i campi runtime
  Telegram, SMTP, render Grafana, URL pubblico e TTL ack sono ora impostabili
  sia da config deploy-time sia dalla UI, con precedenza alle env di compose.
- Estesi `docker-compose.yml`, `.env.example`, README e test per coprire tutte
  le env runtime e i file esportabili dalla UI.

## 0.14.20 — 2026-07-05

- I link legal nella pagina di login ora passano `from=login`, cosi' le pagine
  `/legal/*` possono distinguere il flusso pubblico di login.
- Il selettore lingua sulle pagine `/legal/*` compare solo quando la pagina e'
  stata aperta dalla login; negli altri casi resta valida la lingua gia' scelta
  nell'app.

## 0.14.19 — 2026-07-05

- Sulle pagine pubbliche `/legal/*`, la CTA in alto mostra `Back to app` /
  `Torna all'app` quando la sessione corrente e' gia' valida; resta `Sign in` /
  `Accedi` solo quando serve autenticarsi.

## 0.14.18 — 2026-07-05

- Resi pubblici solo i redirect legacy `/ui/<pagina>` e `/ui/index.html`, in
  modo che i vecchi bookmark vengano canonicalizzati a `/status`,
  `/deliveries`, `/authentication`, ecc. prima dell'eventuale login.

## 0.14.17 — 2026-07-05

- Spostate le pagine pubbliche Privacy, Accessibility, Terms, Cookies e Legal
  notice sotto `/legal/*`, eliminando l'uso user-facing di `/ui/*` per le
  pagine legali.
- Spostate le pagine admin dalla namespace `/ui/*` a route root-level come
  `/status`, `/deliveries`, `/logs` e `/authentication`; `/ui/*` resta solo
  come compatibilita' legacy per bookmark esistenti e asset statici.
- Mantenuti i vecchi path `/ui/privacy`, `/ui/accessibility`, `/ui/terms`,
  `/ui/cookies` e `/ui/legal` solo come redirect legacy verso i nuovi URL.

## 0.14.16 — 2026-07-04

- Allineata la Swagger UI alla convenzione degli altri progetti: route pubbliche
  `/api/docs`, `/api/swagger` e `/api/swagger-ui`.
- Mantenuto `/swagger` come alias legacy deprecato per evitare rotture sui link
  già distribuiti.

## 0.14.15 — 2026-07-04

- Aggiunta Swagger UI self-hosted a `/swagger` e `/api/docs`, servita con asset
  locali `swagger-ui-dist` senza dipendere da CDN esterni.
- Documentate le route Swagger nel contratto OpenAPI e nel README.

## 0.14.14 — 2026-07-03

- Allineata la versione `info.version` dell'OpenAPI alla versione applicativa.
- Aggiunti test anti-drift per verificare che tutte le operation runtime siano
  documentate in OpenAPI e che ogni operation abbia metadati minimi.

## 0.14.13 — 2026-07-03

- Fixata la build Docker della release copiando `docs/openapi.yaml` nello
  stage Rust: il backend embedda il contratto OpenAPI con `include_str!`.

## 0.14.12 — 2026-07-03

- Centralizzata la registry degli endpoint backend per scope, route pubbliche,
  CSRF, reauth/sudo e audit action, rimuovendo duplicazioni da auth e handler.
- Aggiunti test anti-drift tra registry endpoint e OpenAPI per CSRF e
  `ReauthRequired`, includendo il contratto CSRF-exempt di `/api/client-log`.
- Estratta la paginazione delle tabelle finite in `static/table-pager.js`,
  mantenendo le API globali usate dalla UI e dai test E2E.
- Allineata OpenAPI per gli endpoint preview/simulator/test che non richiedono
  CSRF perché non persistono modifiche.

## 0.14.11 — 2026-07-02

- Fixato il refresh diretto di `/ui/flow`: la route iniziale viene attivata
  dopo l'inizializzazione completa del bundle frontend, evitando errori TDZ.
- I toast di errore frontend autenticati vengono inviati a `/api/client-log`
  e compaiono nella pagina Logs come eventi `klaxond::frontend`.
- Il pulsante Sign in delle pagine legali pubbliche prova prima la sessione
  locale esistente e, se serve login, usa il flusso SSO diretto con
  `start=1&return_to=/ui/status`.

## 0.14.10 — 2026-07-02

- Rifinita graficamente la schermata login/signed-out pubblica con logo,
  badge versione, copy piu' leggibile e footer con autore linkato.
- Centralizzati versione, nome autore e URL GitHub in costanti Rust esposte
  al frontend tramite meta pubblico.
- Aggiunta una barra pubblica con selettore lingua IT/EN sulle pagine legali.
- Rafforzata la copertura E2E sui link pubblici privacy/accessibilita'/termini/
  cookie/note legali e sugli asset pubblici mentre l'auth e' attiva.

## 0.14.9 — 2026-07-02

- Rimossi i riferimenti al dominio privato dalle pagine legali, rendendo i
  testi adatti a una distribuzione OSS/self-hosted.
- Aggiunto hyperlink a `https://github.com/luigibarretta` sul nome Luigi
  Barretta nel footer e nelle note legali.
- Aggiunta una schermata login/signed-out locale con link alle pagine legali,
  evitando il rientro SSO automatico immediato dopo logout.
- Documentati nel README i path pubblici privacy/accessibilita'/termini/cookie
  e note legali per le installazioni self-hosted.

## 0.14.8 — 2026-07-02

- Rese pubbliche le pagine footer privacy/accessibilita'/termini/cookie/note
  legali e gli asset statici UI necessari, mantenendo protette le route admin.
- Evitato che le pagine legali pubbliche avviino fetch admin automatiche e
  rimbalzino alla login quando l'autenticazione e' attiva.

## 0.14.7 — 2026-07-02

- Estesa la suite con copertura WebAuthn/passkey, lifecycle API key/PAT,
  restore config negativo, paginazione tabelle admin, persistenza POST/GET
  admin, pagine legali footer e parity parser per
  Beszel/Authentik/PVE/Shelfmark/Decypharr.
- Aggiornato `last_used_at` dei token API/PAT quando un bearer token valido
  viene usato con scope sufficiente, con persistenza debounced per ridurre
  scritture ripetute in caso di polling.
- Rafforzato il restore dei full bundle: file sidecar extra/non supportati ora
  vengono rifiutati invece di essere ignorati silenziosamente.
- Aggiunte pagine footer per privacy/GDPR, accessibilita' WCAG, termini, cookie
  e note legali/contatti, con routing path-based e contenuti IT/EN.

## 0.14.6 — 2026-07-02

- Aggiunto un easter egg nel footer: dopo 7 click sulla versione compare un
  pannello nascosto.
- Il contenuto dell'easter egg dipende solo dalla major version, quindi resta
  stabile tra release minor e patch.

## 0.14.5 — 2026-07-02

- Separata la UI Auth per API Keys e PAT: il tipo del token ora e' scelto da
  segmenti dedicati e la tabella mostra solo il tipo selezionato.
- Mantenuto lo stesso backend token/scopes/revoche, evitando migrazioni dati.

## 0.14.4 — 2026-07-01

- Corretta la gestione delle sessioni UI scadute: le fetch admin ora ricevono
  un 401 machine-readable e il frontend reindirizza alla login una sola volta.
- Evitata la cascata di toast `Failed to fetch` prodotta dai poller quando la
  sessione OIDC scade mentre la pagina resta aperta.

## 0.14.3 — 2026-07-01

- Centralizzata la gestione dei feedback UI con helper condivisi per status
  inline e toast di successo/errore.
- Resi uniformi i toast sulle azioni server-side di salvataggio, cancellazione,
  revoca, registrazione passkey, restore config e aggiornamenti routing/cascade.
- Aggiunto test E2E per verificare che i salvataggi riusciti mostrino sia status
  inline sia toast.

## 0.14.2 — 2026-07-01

- Migrata la UI da hash routing (`/ui/index.html#deliveries`) a path routing
  canonico (`/ui/deliveries`, `/ui/logs`, `/ui/auth`, ecc.).
- Aggiunto fallback server-side per servire l'app su ogni tab path e
  normalizzazione client-side dei vecchi bookmark con `#`.
- Aggiornati link interni, passkey redirect e test E2E per non usare piu' URL
  con frammenti hash.

## 0.14.1 — 2026-07-01

- Rifinita la sidebar: brand con logo, nome nascosto in collapsed e icone per
  ogni voce menu, che restano l'unico elemento visibile della voce collassata.
- Spostati i controlli lingua/tema sotto alla navigazione, sopra alla card
  utente, con lingua IT/EN e tema system/light/dark come tab button.
- Resa la card utente collassata solo-avatar e corretta la vista mobile
  collassata per mantenere logo e hamburger pienamente visibili.
- Conservati badge conteggio e dot dirty come overlay in sidebar collassata,
  con aria-label dinamici che includono conteggi e modifiche non salvate.

## 0.14.0 — 2026-07-01

- Sostituita la top navigation con una sidebar responsive e collassabile,
  con card utente/avatar in fondo e preferenze lingua/tema integrate.
- Aggiunti API key/PAT granulari con scope per endpoint admin, token mostrato
  una sola volta, revoca e autenticazione Bearer con enforcement server-side.
- Aggiunto supporto WebAuthn/passkey: configurazione RP/origin, registrazione
  passkey da utente autenticato, pagina login passkey pubblica e session cookie
  emesso solo dopo verifica WebAuthn.
- Rafforzata la configurazione Auth con guard anti-lockout server-side per
  Basic, OIDC e trusted-proxy.
- Estesa la paginazione client-side a tutte le tabelle admin che possono
  crescere, incluse delivery, inhibition, schedules, cascade, token e passkey.

## 0.13.5 — 2026-07-01

- Estesa la paginazione client-side alle tabelle UI che possono crescere:
  consegne recenti, regole/soppressioni/ack/schedulazioni, render mapping e
  policy/rules delivery.
- Aggiunto un pager riusabile con page size, range corrente e controlli
  prima/precedente/successiva/ultima.
- I controlli di paginazione non marcano piu' i tab come dirty e le righe
  nascoste restano nel DOM per salvataggi, validazioni ed export.

## 0.13.4 — 2026-07-01

- Aggiunta paginazione reale a `/api/logs` con `limit` + `offset` e metadata
  coerenti per evitare liste log troppo lunghe in UI.
- La pagina Logs ora ha page size, controlli prima/precedente/successiva/ultima
  e range visibile dei risultati.
- Aggiunto widget Status "Log buffer" con righe trattenute, WARN/ERROR nel
  buffer corrente e link diretto ai log.

## 0.13.3 — 2026-06-30

- Aggiunto export completo impostazioni (`/api/config/export`) in formato JSON:
  include `klaxond.toml`, sidecar effettivi `render-config.json`,
  `ntfy-topics.json`, `dedup-config.json`, `auth-config.json` e snapshot
  runtime derivato da env/stack, inclusi i segreti.
- Il restore config accetta anche il bundle JSON completo e ripristina TOML +
  sidecar in modo atomico sotto config lock.
- Aggiunto pulsante UI "Export completo" e copertura e2e del round-trip
  export/restore bundle.

## 0.13.2 — 2026-06-30

- Serializzate le write admin di configurazione con lock in-process e lock file
  cross-process, evitando lost update tra salvataggi concorrenti di TOML/JSON
  runtime.
- Reso il restore TOML coerente con i sidecar JSON di render, dedup, auth e
  ntfy quando il TOML ripristinato contiene quelle sezioni.
- Resi univoci i temp file delle write atomiche e i nomi degli auto-backup anche
  con piu' salvataggi nello stesso secondo.
- Aggiunta base Telegram configurabile per test/parita' (`TELEGRAM_API_BASE`),
  mantenendo il default `https://api.telegram.org` in produzione.
- Aggiunti test con servizi fake locali per ntfy, Telegram, render Grafana e
  SMTP, così le integrazioni delivery vengono verificate senza dipendere da
  endpoint esterni reali.

## 0.13.1 — 2026-06-30

- Rafforzata la redazione dei log esposti da `/api/logs` per coprire anche
  variabili stile `*_TOKEN`, `*_SECRET`, `*_PASSWORD` e simili.
- Resa la ricerca log case-insensitive anche per testo Unicode/non ASCII.
- Evitati panic a catena da lock poisonati nei principali stati runtime
  condivisi (config, metriche, inhibition/ack/schedule, immagini renderizzate).
- Aggiunto test e2e che verifica che `/api/logs` richieda auth admin quando
  l'autenticazione e' attiva.

## 0.13.0 — 2026-06-30

- Aggiunta pagina UI Logs con ricerca keyword, filtro livello, limite risultati
  e auto-refresh, alimentata da un ring buffer in-process agganciato a
  `tracing` via endpoint admin `/api/logs`; token, secret e URL sensibili
  vengono redatti prima di essere esposti.
- Uniformata la gestione errori frontend: le failure dei loader, dei salvataggi
  e delle azioni utente mostrano sempre un toast, mantenendo il messaggio inline
  vicino al form quando presente.

## 0.12.1 — 2026-06-30

- Corretto il callback OIDC del backend Rust: `jsonwebtoken` ora viene
  compilato con provider crypto RustCrypto, evitando panic durante la verifica
  dell'`id_token` e il conseguente loop di redirect dopo login Authentik.
- Reso piu' robusto il flusso auth contro cookie sessione duplicati e
  `return_to` non sicuri o puntati a `/auth/*`, prevenendo ulteriori loop.
- Logout rafforzato: cancella varianti plausibili del cookie sessione per
  Path/Domain, evitando sessioni sticky quando il browser ha cookie duplicati.

## 0.12.0 — 2026-06-29

- Aggiunta UI bilingue inglese/italiano con preferenza persistita nel browser
  (`klaxond.lang`) e fallback alla lingua del browser.
- Aggiunto selettore tema `system` / `light` / `dark` con preferenza persistita
  (`klaxond.themeMode`) e migrazione dal vecchio toggle binario.
- Coperti i nuovi controlli con test E2E Playwright per lingua, persistenza e
  theme mode.

## 0.11.2 — 2026-06-29

- Corretto il probe `/api/status` per SMTP: ora risolve hostname DNS come
  `smtp.gmail.com` invece di accettare solo indirizzi IP numerici. Questo
  elimina il falso `SMTP down` nella UI quando il server SMTP e' raggiungibile.

## 0.11.1 — 2026-06-29

- Corretto l'healthcheck Docker del container Rust: usa `127.0.0.1` invece di
  `localhost`, evitando il probe IPv6 `::1` di BusyBox `wget` mentre klaxond
  ascolta su IPv4.
- Ridotto il grafo di compilazione Rust: feature-minimal per `axum`, `tokio` e
  `chrono`; rimosse dipendenze inutili come `axum-macros`, `multer`,
  `parking_lot`, `oldtime` e `wasm-bindgen`.
- Ottimizzato il Docker build con cache BuildKit per registry/git/target e
  contesto piu' piccolo tramite `.dockerignore`.

## 0.11.0 — 2026-06-29

- Backend portato da Python a Rust mantenendo il contratto HTTP/API esistente:
  webhook, UI admin API, auth Basic/OIDC/trusted-proxy, dedup persistente,
  inhibition/ack/schedule, metriche Prometheus, delivery ntfy/Telegram/SMTP,
  render immagini Grafana e static UI.
- Runtime Docker convertito a multi-stage Rust build con immagine finale Alpine
  e binario `/usr/local/bin/klaxond`; Python non è più usato nel container.
- Aggiunti test di parità Rust (`cargo test`) e smoke E2E Playwright
  (`npm run test:e2e`) con server isolato e `/data` temporanea.

## 0.10.2 — 2026-06-15

- Override immagine per-componente: nuova sezione toml `[render.component_image]`
  (`component = "dashboard_uid:panel_id"`) che decide QUALE pannello rendere per
  l'immagine dell'alert, indipendentemente dalla dashboard del bottone. Default:
  `host = "infra-cluster-overview:10"` → l'immagine degli alert host mostra il
  pannello risorse (load1/RAM%/disk per host) invece del pannello logs Loki a cui
  punta il bottone. Senza override, resta l'auto-detect del primo pannello.

## 0.10.1 — 2026-06-15

- Render dashboard images con **d-solo** (singolo pannello) invece della
  dashboard intera: evita il modale d'annuncio "Grafana Assistant" di Grafana
  13 che copriva il render full-dashboard (l'app-shell carica il popup a ogni
  sessione headless), ed è più leggibile in una push mobile. Il pannello è
  auto-rilevato via API Grafana (primo pannello non-row/text, cached per uid);
  fallback alla dashboard intera se il lookup fallisce.

## 0.10.0 — 2026-06-15

- **Immagini dashboard negli alert**: quando il `component` dell'alert è mappato
  in `[render.component_dashboards]`, klaxond rende quella dashboard a PNG via
  l'API `/render` di Grafana (richiede il sidecar `grafana-image-renderer`),
  la ospita su `/img/<token>.png` (path auth-free, token random) e la allega
  alla push ntfy con l'header `Attach`. Render best-effort: se fallisce, la push
  parte comunque (testo + bottoni). Nuove env: `GRAFANA_RENDER_BASE` (URL
  interno Grafana, distinto da `GRAFANA_BASE` pubblico usato per il bottone),
  `GRAFANA_RENDER_TOKEN` (service-account), `RENDER_IMAGE_TTL` (default 900s).
  Il render usa `var-instance` dall'etichetta `instance` dell'alert.

## 0.9.34 — 2026-06-10

- Nuova sorgente `/pve/<severity>`: webhook del notification-system di
  Proxmox VE (body JSON via helper `{{ json … }}`). Parser dedicato, dedup
  per `type` (es. N errori vzdump → 1 gruppo), labels per inhibition
  (host=node, alertname=pve-<type>), cascade sempre on.

## 0.9.33 — 2026-06-07

**Full rename `klaxon` → `klaxond` (product name + runtime identifiers).** Display name unified to "Klaxond" everywhere, plus the load-bearing identifiers:

- Config file `/data/klaxon.toml` → `/data/klaxond.toml`; env var `KLAXON_CONFIG` → `KLAXOND_CONFIG`, `KLAXON_DEFAULT`/`KLAXON_BACKUP_DIR`/`KLAXON_BACKUP_KEEP` likewise.
- Session cookie `klaxon_session` → `klaxond_session` (existing sessions are invalidated → silent re-login via the 0.9.32 self-healing OIDC callback).
- Backup files `klaxon-*.toml` → `klaxond-*.toml`.
- **Migration**: live `/data/klaxon.toml` + backups renamed on deploy. If you run this elsewhere, `mv /data/klaxon.toml /data/klaxond.toml` (and `backups/klaxon-*.toml`) before starting 0.9.33, else the daemon bootstraps a fresh empty config.
- Fixed `alert-klaxond-down.yml`: recovery action referenced container `klaxon` (never existed; it's `klaxond`) → `docker start/restart/logs` now target `klaxond`.

## 0.9.32 — 2026-06-07

**OIDC callback self-healing.** A long-idle browser tab would land on `/auth/callback` and get a 400 "invalid or expired state" ("sessione scaduta"), dead-ending the user; reloading the root URL then worked. Cause: the session cookie (8h) expires while the tab is idle, and/or a klaxond restart (deploy / WUD auto-update) drops the in-memory `_OIDC_STATE_STORE` (10-min TTL) — so the returning `state` is unknown at callback time.

- `oidc_callback`: unknown/expired `state` now 302-redirects to `/` instead of returning 400. This restarts the Authorization Code flow; with the upstream Authentik SSO session still alive the user is re-logged-in silently. No session is issued on this path, so there is no CSRF exposure in the redirect.
- Missing `code`/`state` params still return 400 (malformed request ≠ expired flow).

## 0.9.24 — 2026-06-03

**Decypharr endpoint.** Add `/decypharr/` to ingest sources. Decypharr (cy01/blackhole, the qBit-emulation bridge to Real-Debrid) emits per-torrent webhooks (`download_start`, `download_complete`, `download_fail`) via Callback URL configured in Settings → Notifications. Klaxond parses these and routes via standard cascade.

- `parse_decypharr_payload`: maps `status` ("success"/"failure"/"error") → severity (info/warning/critical), formats title with event verb + torrent name, body from payload `message` field (Decypharr pre-formats).
- Dedup key: `decypharr:<event>:<hash>` — same torrent retry-burst dedupes; different events for same hash get through.
- Frontend: new sample button in Preview tab, DCY node in Mermaid flow, dedup card with help text.
- Dispatch: `/decypharr/<severity>` POST endpoint, body status overrides URL path severity (same pattern as Shelfmark Apprise `type` field).

## 0.9.6 — 2026-06-01

**Source-agnostic inhibition.** Previously only Grafana/Alertmanager alerts
were subject to inhibition rules; Beszel/HC/WUD/Authentik always notified
regardless of cluster state. As of 0.9.6:

- New `_normalize_labels(source, payload)` projects every webhook to a
  canonical `{host, service, job, alertname, status}` dict.
- `apply_inhibition(source, labels)` runs against ALL five sources.
- Source-alert ARMING (the `inhibition_source` label set on Grafana rules)
  still comes only from Grafana — but EVERY source is now subject to
  existing suppressions.
- New `applies_to = ["grafana", "beszel", …]` field on rules to scope
  suppression. Omitted → applies to all sources.

Default rules updated:
- `node-down` (host offline) → suppresses any alert with matching `host`
  label across ALL sources (Beszel CPU alerts from the offline box are
  now correctly muted, ditto WUD container updates).
- `cluster-wide-restart` → suppresses EVERYTHING from EVERY source.
- `traefik-down` / `authentik-down` → scoped to `applies_to=["grafana"]`
  (blackbox job labels are a Grafana-only concept).

UI:
- Inhibitions tab shows new "Applies to" column.
- Flow Mermaid now routes ALL emitters through INH (no more
  "(grafana only)" caveat).

Live-tested in-prod 2026-06-01: node-down host=svr-01 successfully
suppressed Beszel system=svr-01 while letting svr-02 through;
applies_to=[grafana] correctly scoped traefik-down away from Beszel.

## 0.5.6 — 2026-05-27

### Fixed

- **Telegram: switched from Markdown to HTML parse_mode**. Markdown
  parser rejected messages whose body contained stray underscores
  (e.g. "remote_cache", a normal identifier in alerts) — Telegram
  interpreted them as unclosed italic markers and returned 400 Bad
  Request. HTML mode only requires escaping <, >, & in text — much
  safer for free-form alert bodies. Title is now <b>...</b>,
  severity is <code>...</code>.


## 0.5.5 — 2026-05-27

### Fixed

- **Telegram tier: all action URLs now as inline_keyboard buttons**.
  Previously, only the first action URL was appended as a markdown
  link at the tail of the message text — runbook and dashboard URLs
  beyond the first were dropped silently. Now klaxond posts one
  Telegram inline_keyboard button per action (capped at 5 for safety),
  matching what ntfy already showed. So a critical alert on Telegram
  now has tappable "📖 Runbook" / "📊 Dashboard" / "View rule"
  buttons under the message.

  SMTP tier was already including all actions as text lines
  ("label: url") so no change there.


## 0.5.4 — 2026-05-27

### Added

- **Fallback runbook URLs per source** ([render.fallback_runbooks] in
  klaxon.toml). Sources without a per-alert annotation channel (Beszel,
  Healthchecks) now also get a "📖 Runbook" button — the URL is taken
  from the toml config for the source. Grafana alerts continue to use
  the per-rule annotation.runbook_url (which wins over any fallback).

  Healthchecks supports per-payload override too: include
  "runbook_url" in the JSON body and it overrides the toml fallback
  for that specific check.

  Example klaxon.toml:
    [render.fallback_runbooks]
    beszel       = "https://docs.example.com/runbooks/beszel.md"
    healthchecks = "https://docs.example.com/runbooks/hc-deadman.md"

  When empty (the default), no button is shown for that source.


## 0.5.3 — 2026-05-27

### Added

- **Runbook action button** on Grafana-origin notifications. If the
  alert rule sets `annotations.runbook_url`, klaxond prepends a
  "📖 Runbook" button to the ntfy actions array, before the
  existing component-dashboard button. Tapping the push opens the
  runbook directly. ntfy supports up to 3 action buttons; runbook
  + dashboard + rule URL fit comfortably.

  Convention: link to a markdown file in your docs repo (e.g.
  Gitea or Forgejo with mermaid rendering), or to a wiki page —
  whatever your team uses. klaxond does not parse the runbook;
  it just forwards the URL to ntfy.

  No-op for Beszel and Healthchecks endpoints since those sources
  don't have an annotation system. (HC checks already get a
  "Open in HC" button via the "url" body field.)


## 0.5.2 — 2026-05-27

### Fixed

- **Emoji conflict on RESOLVED**. When an alert resolved, the tag list
  still contained the severity literal (`warning`/`critical`), which ntfy
  auto-rendered as the matching Unicode emoji on the phone. Result:
  title showed ✅ (resolved) while tags showed ⚠️ — visually contradictory.
  All three parsers (Grafana, Beszel, Healthchecks) now drop the severity
  literal from the tag list when status is resolved, keeping only the
  resolved checkmark + component tag.

### Added

- **Structured audit log per delivery** (`audit_log_delivery()`). klaxond
  emits one JSON line per delivery attempt with stable schema (audit,
  source, severity, alertname, component, host, tiers_attempted, ok,
  channel, duration_ms, timestamp). Promtail scrapes klaxond stdout to
  Loki; the new Alert health dashboard plus future ad-hoc "who got what
  when" queries consume this stream.


## 0.5.1 — 2026-05-27

### Fixed

- **Emoji consistency across renderers**. Three small drifts that
  added up to confusing UX:
  1. `severity_tag_prefix` from `klaxon.toml` was loaded but never
     applied at runtime — both Grafana and Beszel renderers used a
     hardcoded dict inline. Setting the TOML field had no effect.
  2. `severity_emoji.resolved` was loaded into ICONS but bypassed —
     the literal "✅" was hardcoded in all three parsers.
  3. The new /healthchecks parser used "⚠️" as fallback emoji while
     /webhook and /beszel used "ℹ️".

  All three parsers (Grafana, Beszel, Healthchecks) now read from
  the same ICONS and TAG_PREFIXES globals, so a single edit to
  klaxon.toml under [render.severity_emoji] / [render.severity_tag_prefix]
  flips the rendering for every source.

- **TAG_PREFIXES global** added next to ICONS/PRIORITIES.
  Defaults: info=information_source, warning=warning,
  critical=rotating_light, resolved=white_check_mark — all
  TOML-overridable.


## 0.5.0 — 2026-05-27

### Added

- **`/healthchecks/<sev>` endpoint** for Healthchecks self-hosted webhook
  channels. Accepts the JSON body
  `{check, status, code, last_ping, tags, url}` (HC's substitution
  placeholders) and renders an alert with the same shape as
  `/webhook/` and `/beszel/`. `status: up|ok|resolved` flips the
  rendering to "✅ HC UP" with low priority; anything else (`down`,
  `fail`) renders as "🚨 HC DOWN" with the severity priority from the
  URL path. Cascade is always-on for this source (HC's native
  webhook retry is single-channel).

- **HA-ready** documentation in README.md: how to deploy klaxon
  behind a load balancer with shared `/data` storage, what state is
  file-backed vs in-memory, and the self-monitoring pattern that
  works whether you run one instance or many. No code changes
  needed — both config files are already atomically written and
  read on every relevant request, so NFS/Ceph just works.


## 0.2.0 — 2026-05-26

### Changed
- **Renamed binary/image/repo from `klaxon` to `klaxond`** (Unix daemon
  convention). Product display name remains "Klaxon". docker-compose.yml,
  container name, image labels and source file headers updated.

### Added
- Gitea Actions workflow `.gitea/workflows/build.yml` for multi-arch
  Docker image build (`linux/amd64` + `linux/arm64`) on `v*` tag push.
  Image pushed to `git.luigibarretta.com/luigibarretta/klaxond:<tag>`
  and `:latest`.

## 0.1.0 — 2026-05-26

First versioned release.

### Features

- HTTP webhook bridge: `/webhook/<sev>` (Grafana Alertmanager-shape JSON) +
  `/beszel/<sev>` (Beszel-shape JSON) on port 8181.
- ntfy push rendering: severity emoji in title (RFC 2047 base64-encoded),
  priority + tag mapping per severity, up to 2 action buttons via
  `component` label.
- Cascade fallback (ntfy → Telegram → SMTP) with per-tier timeouts.
  Always on for `/beszel/*`; gated for `/webhook/*` (default off, since
  Grafana has its own retries).
- In-memory inhibition rules as safety net for direct posts
  (Alertmanager owns the canonical layer).
- TOML bootstrap (`klaxon.toml`) for cascade tiers, render config,
  inhibition rules. Bootstrapped on first run from bundled default.
- Admin UI (vanilla HTML+JS, no framework) at `/ui/` with 6 tabs:
  Status, Inhibitions, Recent deliveries, Render config CRUD, Render
  preview, Send test.
- JSON API endpoints for the UI: `/api/status`, `/api/inhibitions`,
  `/api/deliveries`, `/api/render-config` (GET+POST),
  `/api/render-preview`, `/api/test/<sev>`, `/api/cascade/toggle`.
- Compose-bootstrappable Docker image:
  `docker compose up -d` is enough — no Ansible required.

### Stack

- Python 3.13 stdlib only (no third-party deps).
- Image: `python:3.13-alpine` base, ~50 MB total.
- Persistent state: `/data` (klaxon.toml + render-config.json).
