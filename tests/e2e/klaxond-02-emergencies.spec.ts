import { expect, test } from "@playwright/test";

test("emergency metric families exist before the first incident", async ({ request }) => {
  const response = await request.get("/metrics");
  expect(response.ok()).toBeTruthy();
  const body = await response.text();
  expect(body).toContain("klaxond_emergencies_active 0");
  expect(body).toContain("klaxond_emergency_oldest_active_age_seconds 0");
  expect(body).toContain("klaxond_emergency_storage_errors_total{operation=\"register\"} 0");
});

test("emergency console renders durable receipts and dispatches audited actions", async ({ page }) => {
  let state = "active";
  let action = "";
  let policyUpdate: Record<string, unknown> = {};
  let settings = {
    enabled: true,
    allow_insecure_public_url: false,
    allow_ntfy_only: false,
    exclude_sources: ["api-test"],
    fallback_profile: "critical-default",
    profiles: [{
      id: "critical-default",
      name: "Critical default",
      enabled: true,
      priority: 100,
      severities: ["critical"],
      sources: [],
      match: {},
      retry_seconds: 60,
      expire_seconds: 3600,
      max_attempts: 50,
      lease_seconds: 60,
      telegram: { enabled: true, after_attempts: 3 },
      smtp: { enabled: true, after_attempts: 5 },
      notify_on_expiry: true,
      auto_resolve: true,
    }],
  };
  const incident = () => ({
    receipt_id: "receipt-e2e-1234567890",
    fingerprint: "fingerprint-e2e",
    source: "grafana",
    severity: "critical",
    title: "Production emergency probe",
    payload_json: "{}",
    policy_id: "critical-default",
    policy_name: "Critical default",
    policy_snapshot_json: "{}",
    state,
    created_at: Date.now() / 1000 - 45,
    updated_at: Date.now() / 1000,
    next_retry_at: Date.now() / 1000 + 15,
    expires_at: Date.now() / 1000 + 1800,
    last_sent_at: Date.now() / 1000 - 15,
    terminal_at: state === "active" ? null : Date.now() / 1000,
    terminal_by: state === "active" ? "" : "e2e-admin",
    attempts: 2,
    max_attempts: 50,
    telegram_escalated_at: null,
    smtp_escalated_at: null,
    last_error: "",
    reserved_until: 0,
    reservation_token: "",
  });

  await page.route(/\/api\/emergencies\?/, async route => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ incidents: [incident()], limit: 500 }),
    });
  });
  await page.route("**/api/emergency-config", async route => {
    if (route.request().method() === "POST") {
      policyUpdate = route.request().postDataJSON();
      settings = { ...settings, ...policyUpdate };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        settings,
        source_of_truth: "ui",
        known_severities: ["critical", "info", "warning"],
        known_sources: ["grafana", "api-test"],
        channel_timeouts: { ntfy: 15, telegram: 8, smtp: 10, lease_margin: 5 },
        diagnostics: { shadowed_profiles: [], unrouted_severities: ["info", "warning"], equal_priorities: [] },
        managed_fields: {},
        managed_by_environment: false,
        writeable: true,
      }),
    });
  });
  await page.route("**/api/emergencies/receipt-e2e-1234567890/ack", async route => {
    action = route.request().method();
    state = "acknowledged";
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ok: true, incident: incident() }),
    });
  });

  await page.goto("/emergencies");
  await expect(page.locator('[data-tab="emergencies"]')).toBeVisible();
  await expect(page.locator("#tab-emergencies")).toHaveClass(/active/);
  await expect(page.locator("#emergency-policy")).toHaveText("1 enabled profile(s)");
  await expect(page.locator("#emergency-active")).toHaveText("1");
  await expect(page.locator("#t-emergencies tbody")).toContainText("Production emergency probe");
  await expect(page.locator('[data-emergency-action="ack"]')).toBeVisible();

  await page.locator("#emergency-policy-editor > summary").click();
  await page.locator("[data-profile-index='0'] [data-profile-field='retry_seconds']").fill("90");
  await page.locator("#emergency-policy-save").click();
  await expect.poll(() => (policyUpdate.profiles as Array<{ retry_seconds: number }>)[0].retry_seconds).toBe(90);
  await expect(page.locator(".toast-success").last()).toContainText("Emergency policy saved");
  await expect(page.locator("#emergency-policy")).toHaveText("1 enabled profile(s)");

  await page.click('[data-emergency-action="ack"]');
  await page.locator(".app-dialog .primary").click();
  await expect.poll(() => action).toBe("POST");
  await expect(page.locator("#t-emergencies tbody")).toContainText("acknowledged");
  await expect(page.locator("#emergency-active")).toHaveText("0");
  await expect(page.locator(".toast-success").last()).toBeVisible();
});

test("emergency profile editor is keyboard operable and reflows at 320 and 390 px", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await page.goto("/emergencies");
  await expect(page.locator("#emergency-policy-editor")).toBeVisible();
  await page.locator("#emergency-policy-editor > summary").click();
  await expect(page.locator("#emergency-owner")).toBeVisible();
  await expect(page.locator("#emergency-export")).toHaveAttribute("href", "/api/emergency-config/export");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);

  const severityInput = page.locator("#profile-severities-0 input");
  await severityInput.focus();
  await severityInput.fill("page");
  await severityInput.press("Enter");
  await expect(page.locator("#profile-severities-0 .chip", { hasText: "page" })).toBeVisible();
  await expect(page.locator("[data-profile-index='0'] [data-profile-timeline]")).toContainText("Real expiry");

  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});
