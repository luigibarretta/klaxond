import { expect, test } from "@playwright/test";
import {
  APP_VERSION, AUTHOR_NAME, AUTHOR_URL, BASIC_AUTH, BASIC_PASSWORD, BASIC_USER, LOCAL_ORIGIN,
  addVirtualAuthenticator, assertTablePagerWorks, createAdminBearer, enableBasicAuth,
  exportConfigBundle, exportConfigBundleWithAuthFallback, requestWithAuthFallback,
  restoreConfigBundle, revealVersionEgg, totp,
} from "./klaxond-helpers";

test("render-preview returns ntfy-compatible headers without delivery", async ({ request }) => {
  const res = await request.post("/api/render-preview", {
    data: {
      severity: "critical",
      payload: {
        status: "firing",
        commonLabels: {
          alertname: "HostLoadHigh",
          component: "host",
          host: "it1-prd-dev-01"
        },
        commonAnnotations: {
          summary: "load average above threshold"
        },
        alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
      }
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.url).toBe("http://127.0.0.1:9/critical-topic");
  expect(body.headers["Title (raw)"]).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
  expect(body.headers.Tags).toBe("rotating_light,critical,grafana,host");
  expect(body.headers.Priority).toBe("urgent");
});

test("webhook dry-run exercises ingest pipeline without sending", async ({ request }) => {
  const res = await request.post("/webhook/critical?dry_run=1", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: "HostLoadHigh",
        component: "host",
        host: "it1-prd-dev-01"
      },
      commonAnnotations: {
        summary: "load average above threshold"
      },
      alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.dry_run).toBe(true);
  expect(body.would_send).toBe(true);
  expect(body.source).toBe("grafana");
  expect(body.severity).toBe("critical");
  expect(body.parsed.title).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
});

test("inhibition rule simulator reports source and suppression matches", async ({ request }) => {
  const source = await request.post("/api/inhibition-rules/test", {
    data: {
      source: "grafana",
      labels: { alertname: "NodeDown", inhibition_source: "node-down", host: "dev-01" }
    }
  });
  await expect(source).toBeOK();
  expect(await source.json()).toMatchObject({
    would_send: true,
    reason: "source",
    matched_rule: "node-down",
    would_arm_suppression: true
  });
});

test("full config export includes TOML sidecars and runtime settings", async ({ page, request }) => {
  await page.goto("/status");
  await expect(page.locator("#cfg-backup-download")).toHaveAttribute("href", "/api/config/backup");
  await expect(page.locator("#cfg-full-export-download")).toHaveAttribute("href", "/api/config/export");

  const exported = await request.get("/api/config/export");
  await expect(exported).toBeOK();
  expect(exported.headers()["content-type"]).toContain("application/json");
  expect(exported.headers()["content-disposition"]).toContain("klaxond-full-settings-");

  const bundle = await exported.json();
  expect(bundle).toMatchObject({
    kind: "klaxond.full-settings",
    format_version: 1,
    includes_secrets: true,
    files_are_effective: true
  });
  expect(Object.keys(bundle.files)).toEqual(expect.arrayContaining([
    "klaxond.toml",
    "render-config.json",
    "ntfy-topics.json",
    "dedup-config.json",
    "auth-config.json"
  ]));
  expect(JSON.parse(bundle.files["render-config.json"]).component_dashboards).toBeTruthy();
  expect(JSON.parse(bundle.files["ntfy-topics.json"]).topics.length).toBeGreaterThan(0);
  expect(bundle.effective_runtime).toHaveProperty("telegram");
  expect(bundle.effective_runtime).toHaveProperty("smtp");
  expect(bundle.effective_runtime).toHaveProperty("grafana");

  const restored = await request.post("/api/config/restore", {
    data: JSON.stringify(bundle),
    headers: { "Content-Type": "application/json" }
  });
  await expect(restored).toBeOK();
  expect(await restored.json()).toMatchObject({
    ok: true,
    source_kind: "full-bundle",
    restored_sidecars: [
      "render-config.json",
      "ntfy-topics.json",
      "dedup-config.json",
      "auth-config.json"
    ]
  });
});

test("operational readiness endpoints cover import preview, audit, setup, channel matrix and policy simulation", async ({ request }) => {
  const bundle = await exportConfigBundle(request);

  const preview = await request.post("/api/config/import-preview", {
    headers: { "Content-Type": "application/json" },
    data: bundle
  });
  await expect(preview).toBeOK();
  expect(await preview.json()).toMatchObject({
    ok: true,
    source_kind: "full-bundle",
    backup_will_be_created: true,
    would_restore: [
      "klaxond.toml",
      "render-config.json",
      "ntfy-topics.json",
      "dedup-config.json",
      "auth-config.json"
    ]
  });

  await restoreConfigBundle(request, bundle);
  const audit = await request.get("/api/audit?limit=10&q=config.restore");
  await expect(audit).toBeOK();
  const auditBody = await audit.json();
  expect(auditBody.entries[0]).toMatchObject({
    action: "config.restore",
    outcome: "ok"
  });

  const setup = await request.get("/api/setup-status");
  await expect(setup).toBeOK();
  const setupBody = await setup.json();
  expect(setupBody.items).toEqual(expect.arrayContaining([
    expect.objectContaining({ key: "auth" }),
    expect.objectContaining({ key: "ingest_auth" }),
    expect.objectContaining({ key: "channels" }),
    expect.objectContaining({ key: "backups" })
  ]));

  const matrix = await request.get("/api/channel-test-matrix");
  await expect(matrix).toBeOK();
  expect(await matrix.json()).toMatchObject({
    dry_run: true,
    channels: expect.arrayContaining([
      expect.objectContaining({ name: "ntfy" }),
      expect.objectContaining({ name: "telegram" }),
      expect.objectContaining({ name: "smtp" })
    ])
  });

  const simulated = await request.post("/api/policy-simulate", {
    data: {
      source: "grafana",
      severity: "critical",
      labels: {
        alertname: "HostLoadHigh",
        component: "host",
        host: "it1-prd-dev-01"
      }
    }
  });
  await expect(simulated).toBeOK();
  expect(await simulated.json()).toMatchObject({
    source: "grafana",
    severity: "critical",
    inhibition: expect.objectContaining({ would_send: expect.any(Boolean) }),
    delivery: expect.objectContaining({ policy: expect.any(String), tiers: expect.any(Array) }),
    dedup: expect.objectContaining({ enabled: expect.any(Boolean) })
  });
});

test("operational readiness tabs render diagnostics, simulator and audit views", async ({ page, request }) => {
  await request.get("/api/setup-status");

  await page.goto("/setup");
  await expect(page.locator("#tab-setup")).toHaveClass(/active/);
  await expect(page.locator('[data-tab="setup"]')).toBeVisible();
  await expect(page.locator("#setup-checklist")).toBeVisible();

  await page.goto("/simulator");
  await expect(page.locator("#tab-simulator")).toHaveClass(/active/);
  await expect(page.locator("#policy-sim-run")).toBeVisible();

  await page.goto("/audit");
  await expect(page.locator("#tab-audit")).toHaveClass(/active/);
  await expect(page.locator("#audit-filter")).toBeVisible();
});

test("config restore rejects bad bundles without changing current settings", async ({ request }) => {
  const beforeBundle = await exportConfigBundle(request);

  const unsupportedVersion = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 999,
      files: {
        "klaxond.toml": beforeBundle.files["klaxond.toml"]
      }
    }
  });
  expect(unsupportedVersion.status()).toBe(400);
  expect(await unsupportedVersion.text()).toContain("unsupported config bundle format_version");

  const unsupportedSidecar = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 1,
      files: {
        ...beforeBundle.files,
        "not-a-sidecar.json": "{}"
      }
    }
  });
  expect(unsupportedSidecar.status()).toBe(400);
  expect(await unsupportedSidecar.text()).toContain("unsupported sidecar");

  const invalidSidecarJson = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 1,
      files: {
        ...beforeBundle.files,
        "render-config.json": "{not json"
      }
    }
  });
  expect(invalidSidecarJson.status()).toBe(400);
  expect(await invalidSidecarJson.text()).toContain("invalid render-config.json");

  const afterBundle = await exportConfigBundle(request);
  expect(afterBundle.files["klaxond.toml"]).toBe(beforeBundle.files["klaxond.toml"]);
  expect(afterBundle.files["render-config.json"]).toBe(beforeBundle.files["render-config.json"]);
  expect(afterBundle.files["auth-config.json"]).toBe(beforeBundle.files["auth-config.json"]);
});

test("admin config POST endpoints persist through their read APIs", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);

  try {
    const renderUpdate = await request.post("/api/render-config", {
      data: {
        settings: {
          grafana_base: "https://grafana-e2e.example.test",
          grafana_render_base: "https://render-e2e.example.test",
          grafana_render_token: "render-secret-e2e",
          render_image_ttl: 123,
          public_url: "https://klaxond-e2e.example.test",
          ack_default_ttl: 2345
        },
        component_dashboards: {
          e2e_component: ["E2E dashboard", "/d/e2e-dashboard"]
        }
      }
    });
    await expect(renderUpdate).toBeOK();
    const renderRead = await request.get("/api/render-config");
    await expect(renderRead).toBeOK();
    const renderPayload = await renderRead.json();
    expect(renderPayload.component_dashboards.e2e_component).toEqual(["E2E dashboard", "/d/e2e-dashboard"]);
    expect(renderPayload.settings).toMatchObject({
      grafana_base: "https://grafana-e2e.example.test",
      grafana_render_base: "https://render-e2e.example.test",
      grafana_render_token_configured: true,
      render_image_ttl: 123,
      public_url: "https://klaxond-e2e.example.test",
      ack_default_ttl: 2345
    });

    const channelUpdate = await request.post("/api/channel-config", {
      data: {
        ntfy: { url: "https://push-e2e.example.test" },
        telegram: {
          chat_id: "e2e-chat",
          api_base: "https://telegram-e2e.example.test",
          bot_token: "telegram-secret-e2e"
        },
        smtp: {
          host: "smtp-e2e.example.test",
          port: 2525,
          starttls: false,
          from_addr: "from-e2e@example.test",
          to_addr: "to-e2e@example.test",
          user: "smtp-user-e2e",
          password: "smtp-secret-e2e"
        }
      }
    });
    await expect(channelUpdate).toBeOK();
    const channelRead = await request.get("/api/channel-config");
    await expect(channelRead).toBeOK();
    expect(await channelRead.json()).toMatchObject({
      ntfy: { url: "http://127.0.0.1:9", url_from_env: true },
      telegram: {
        chat_id: "e2e-chat",
        api_base: "https://telegram-e2e.example.test",
        bot_token_configured: true
      },
      smtp: {
        host: "smtp-e2e.example.test",
        port: 2525,
        starttls: false,
        from_addr: "from-e2e@example.test",
        to_addr: "to-e2e@example.test",
        user: "smtp-user-e2e",
        user_configured: true,
        password_configured: true
      }
    });

    const topicsUpdate = await request.post("/api/ntfy-topics", {
      data: {
        topics: [
          { name: "e2e-info-topic", token: "secret-info", handles: ["info"] },
          { name: "e2e-page-topic", token: "secret-page", handles: ["critical", "page"] }
        ]
      }
    });
    await expect(topicsUpdate).toBeOK();
    const topicsRead = await request.get("/api/ntfy-topics");
    await expect(topicsRead).toBeOK();
    const topicsPayload = await topicsRead.json();
    expect(topicsPayload.topics).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "e2e-info-topic", token: "***SET***", handles: ["info"] }),
      expect.objectContaining({ name: "e2e-page-topic", token: "***SET***", handles: ["critical", "page"] })
    ]));

    const dedupUpdate = await request.post("/api/dedup-config", {
      data: {
        settings: {
          grafana: { enabled: true, window_s: 42, strategy: "time", override_critical: true }
        }
      }
    });
    await expect(dedupUpdate).toBeOK();
    const dedupRead = await request.get("/api/dedup-config");
    await expect(dedupRead).toBeOK();
    expect((await dedupRead.json()).settings.grafana).toMatchObject({
      enabled: true,
      window_s: 42,
      strategy: "time",
      override_critical: true
    });

    const deliveryUpdate = await request.post("/api/delivery-config", {
      data: {
        default_policy: "e2e-broadcast",
        policies: [
          {
            name: "e2e-broadcast",
            mode: "broadcast",
            tiers: [{ name: "ntfy", timeout_seconds: 3 }, { name: "smtp", timeout_seconds: 4 }]
          }
        ],
        rules: [{ match: { component: "e2e_component" }, policy: "e2e-broadcast" }]
      }
    });
    await expect(deliveryUpdate).toBeOK();
    const deliveryRead = await request.get("/api/delivery-config");
    await expect(deliveryRead).toBeOK();
    expect(await deliveryRead.json()).toMatchObject({
      default_policy: "e2e-broadcast",
      policies: [expect.objectContaining({ name: "e2e-broadcast", mode: "broadcast" })],
      rules: [expect.objectContaining({ match: { component: "e2e_component" }, policy: "e2e-broadcast" })]
    });

    const ingestUpdate = await request.post("/api/ingest-auth", {
      data: { source: "beszel", action: "set", secret: "abcdefghijklmnop" }
    });
    await expect(ingestUpdate).toBeOK();
    const ingestRead = await request.get("/api/ingest-auth");
    await expect(ingestRead).toBeOK();
    expect((await ingestRead.json()).sources.beszel).toMatchObject({ configured: true, from: "toml" });

    const schedulesUpdate = await request.post("/api/schedules", {
      data: {
        schedules: [{
          name: "e2e-maintenance",
          cron: "0 3 * * *",
          duration_minutes: 45,
          match: { component: "e2e_component" },
          applies_to: ["grafana"]
        }]
      }
    });
    await expect(schedulesUpdate).toBeOK();
    const schedulesRead = await request.get("/api/schedules");
    await expect(schedulesRead).toBeOK();
    expect((await schedulesRead.json()).schedules).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "e2e-maintenance", cron: "0 3 * * *", duration_minutes: 45 })
    ]));
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});
