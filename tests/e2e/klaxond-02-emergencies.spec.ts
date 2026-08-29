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
  const incident = () => ({
    receipt_id: "receipt-e2e-1234567890",
    fingerprint: "fingerprint-e2e",
    source: "grafana",
    severity: "critical",
    title: "Production emergency probe",
    payload_json: "{}",
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
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        settings: {
          enabled: true,
          retry_seconds: 60,
          expire_seconds: 3600,
          max_attempts: 50,
          telegram_after_attempts: 3,
          smtp_after_attempts: 5,
        },
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
  await expect(page.locator("#emergency-policy")).toHaveText("60s × 50; 60m");
  await expect(page.locator("#emergency-active")).toHaveText("1");
  await expect(page.locator("#t-emergencies tbody")).toContainText("Production emergency probe");
  await expect(page.locator('[data-emergency-action="ack"]')).toBeVisible();

  await page.click('[data-emergency-action="ack"]');
  await expect.poll(() => action).toBe("POST");
  await expect(page.locator("#t-emergencies tbody")).toContainText("acknowledged");
  await expect(page.locator("#emergency-active")).toHaveText("0");
  await expect(page.locator(".toast-success").last()).toBeVisible();
});
