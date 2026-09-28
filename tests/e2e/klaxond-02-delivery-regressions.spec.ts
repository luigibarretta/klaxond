import { expect, test } from "@playwright/test";
import { deliveryConfig, mockDeliveryConfig } from "./klaxond-delivery-helpers";

test("delivery rules can be reordered and deleted without runtime errors", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("pageerror", error => browserErrors.push(error.message));
  await mockDeliveryConfig(page);
  await page.goto("/delivery");

  await page.locator("#btn-rule-add").click();
  const rows = page.locator("#t-rules tbody tr");
  await expect(rows).toHaveCount(2);
  await rows.last().locator('[data-f="match"]').fill("source=grafana");
  await rows.last().locator('[data-action="rule-up"]').click();
  await expect(rows.first().locator('[data-f="match"]')).toHaveValue("source=grafana");
  await expect(page.locator("#delivery-status")).toContainText("position 1");

  await rows.first().locator('[data-action="rule-delete"]').click();
  await expect(page.locator(".app-dialog")).toContainText("Remove rule 1");
  await page.locator(".app-dialog-actions .danger").click();
  await expect(rows).toHaveCount(1);
  expect(browserErrors).toEqual([]);
});

test("clicking the active Delivery navigation keeps unsaved drafts", async ({ page }) => {
  await mockDeliveryConfig(page);
  await page.goto("/delivery");

  const match = page.locator('#t-rules [data-f="match"]').first();
  await match.fill("severity=warning");
  const deliveryNav = page.locator('.tab[data-tab="delivery"]');
  if (!await deliveryNav.isVisible()) await page.locator("#sidebar-toggle").click();
  await deliveryNav.click();

  await expect(match).toHaveValue("severity=warning");
  await expect(page.locator("#tab-delivery")).toHaveClass(/active/);
});

test("late delivery reloads cannot overwrite edits made after the request started", async ({ page }) => {
  let getCount = 0;
  let releaseReload!: () => void;
  let markReloadStarted!: () => void;
  const reloadGate = new Promise<void>(resolve => { releaseReload = resolve; });
  const reloadStarted = new Promise<void>(resolve => { markReloadStarted = resolve; });
  await page.route("**/api/delivery-config", async route => {
    if (route.request().method() === "POST") {
      return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    }
    getCount += 1;
    if (getCount > 1) {
      markReloadStarted();
      await reloadGate;
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(deliveryConfig),
    });
  });
  await page.goto("/delivery");

  await page.evaluate(() => {
    (window as Window & { lateDeliveryLoad?: Promise<void> }).lateDeliveryLoad =
      import("/ui/app-delivery-grouping.js").then(module => module.loadDelivery({ force: true }));
  });
  await reloadStarted;
  const match = page.locator('#t-rules [data-f="match"]').first();
  await match.fill("severity=warning");
  releaseReload();
  await page.evaluate(() =>
    (window as Window & { lateDeliveryLoad?: Promise<void> }).lateDeliveryLoad
  );

  await expect(match).toHaveValue("severity=warning");
});
