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

test("ingest routes are fail-closed and Blackstart has a dedicated identity", async ({ request }) => {
  const payload = {
    status: "firing",
    commonLabels: {
      alertname: "BlackstartPolicyEvent",
      component: "blackstart",
      host: "it1-prd-mgmt-01"
    },
    commonAnnotations: { summary: "dry-run policy event" },
    alerts: [{ generatorURL: "https://blackstart.example/events/1" }]
  };

  const missingGrafanaToken = await request.post("/webhook/warning?dry_run=1", {
    data: payload
  });
  expect(missingGrafanaToken.status()).toBe(401);

  const disabledSource = await request.post("/beszel/warning?dry_run=1", {
    headers: { Authorization: "Bearer any-token-is-rejected" },
    data: payload
  });
  expect(disabledSource.status()).toBe(404);

  const dedicated = await request.post("/blackstart/warning?dry_run=1", {
    headers: { Authorization: "Bearer e2e-blackstart-secret" },
    data: payload
  });
  await expect(dedicated).toBeOK();
  expect(await dedicated.json()).toMatchObject({
    dry_run: true,
    source: "blackstart",
    severity: "warning"
  });

  const rollingCompatibility = await request.post("/webhook/warning?dry_run=1", {
    headers: { Authorization: "Bearer e2e-blackstart-secret" },
    data: payload
  });
  await expect(rollingCompatibility).toBeOK();
  expect(await rollingCompatibility.json()).toMatchObject({
    dry_run: true,
    source: "blackstart"
  });
});

test("GitHub issue replies use their dedicated authenticated source", async ({ request }) => {
  const payload = {
    event: "issue_comment",
    repository: "owner/project",
    issue_number: 42,
    issue_title: "Concurrent client close can panic",
    issue_url: "https://github.com/owner/project/issues/42",
    comment_id: 1234,
    comment_author: "maintainer",
    comment_body: "Fixed on main and scheduled for the next release.",
    comment_url: "https://github.com/owner/project/issues/42#issuecomment-1234"
  };

  const anonymous = await request.post("/github/info?dry_run=1", { data: payload });
  expect(anonymous.status()).toBe(401);

  const res = await request.post("/github/info?dry_run=1", {
    headers: { Authorization: "Bearer e2e-github-secret" },
    data: payload
  });
  await expect(res).toBeOK();
  const body = await res.json();
  expect(body).toMatchObject({ dry_run: true, source: "github", severity: "info" });
  expect(body.parsed.title).toBe("ℹ️ GitHub: owner/project#42 — reply from maintainer");
  expect(body.parsed.body).toContain("Fixed on main");
  expect(body.parsed.actions).toEqual([
    ["view", "Open reply", "https://github.com/owner/project/issues/42#issuecomment-1234"]
  ]);
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
  await expect(page.locator("#setup-ready-label")).toHaveText("Action required");
  await expect(page.locator("#setup-next")).toHaveAttribute("href", "/authentication");
  await expect(page.locator('.setup-item a[href="/routing"]')).toHaveCount(2);
  await page.locator("#setup-next").click();
  await expect(page).toHaveURL(/\/authentication$/);
  await expect(page.locator("#tab-auth")).toHaveClass(/active/);

  await page.goto("/simulator");
  await expect(page.locator("#tab-simulator")).toHaveClass(/active/);
  await expect(page.locator("#policy-sim-run")).toBeVisible();

  await page.goto("/audit");
  await expect(page.locator("#tab-audit")).toHaveClass(/active/);
  await expect(page.locator("#audit-filter")).toBeVisible();
});
