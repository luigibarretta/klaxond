import { expect, test } from "@playwright/test";
import { exportConfigBundle, restoreConfigBundle } from "./klaxond-helpers";

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

test("operational readiness tabs render diagnostics, simulator and audit views", async ({ page, request }) => {
  await request.get("/api/setup-status");

  await page.goto("/setup");
  await expect(page.locator("#tab-setup")).toHaveClass(/active/);
  await expect(page.locator('[data-tab="setup"]')).toBeAttached();
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
