import { expect, test } from "@playwright/test";

test("flow opens at a readable scale and exposes a true fit control", async ({ page }) => {
  await page.goto("/flow");
  await expect(page.locator("#flow-diagram svg")).toBeVisible();
  const zoom = page.locator("#flow-zoom-level");
  const percentage = async () => Number((await zoom.textContent())?.replace("%", ""));
  const initial = await percentage();
  expect(initial).toBeGreaterThanOrEqual(80);

  await page.locator("#flow-zoom-fit").click();
  const fitted = await percentage();
  expect(fitted).toBeLessThanOrEqual(100);
  expect(fitted).toBeLessThanOrEqual(initial);

  await page.locator("#flow-zoom-in").click();
  expect(await percentage()).toBeGreaterThan(fitted);
});

test("flow refresh preserves focused route step", async ({ page }) => {
  await page.goto("/flow");
  const selector = page.locator('[data-flow-step="policy-selector"]');
  await selector.focus();
  await expect(selector).toBeFocused();

  await page.evaluate(() => {
    document.dispatchEvent(new CustomEvent("klaxond:languagechange", { detail: { lang: "en" } }));
  });
  await expect.poll(() => page.evaluate(() => (
    (document.activeElement as HTMLElement | null)?.dataset.flowStep || ""
  ))).toBe("policy-selector");
});

test("flow exposes selected step details next to the control on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/flow");
  const selector = page.locator('[data-flow-step="policy-selector"]');
  await selector.click();
  const item = selector.locator("xpath=..");
  await expect(item.locator(".flow-step-mobile-detail")).toBeVisible();
  const settingsLink = item.locator(".flow-step-mobile-detail a");
  await expect(settingsLink).toHaveAttribute("href", "/delivery");
  await settingsLink.focus();
  await expect(settingsLink).toBeFocused();
  await page.evaluate(async () => {
    const { loadFlow } = await import("/ui/app-flow.js");
    await loadFlow({ preserveViewport: true });
  });
  await expect(item.locator(".flow-step-mobile-detail a")).toBeFocused();
  await expect(page.locator("#flow-step-inspector")).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
});

test("flow still renders configuration when delivery statistics are unavailable", async ({ page }) => {
  await page.route("**/api/status/activity?hours=24", route => route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({ error: "activity unavailable" }),
  }));
  await page.goto("/flow");
  await expect(page.locator("#flow-route-list .flow-route-step").first()).toBeVisible();
  await expect(page.locator("#flow-route-list .flow-route-step").first()).toContainText("Delivery statistics unavailable");
  await expect(page.locator("#flow-diagram svg")).toBeVisible();
  await expect(page.locator(".toast-error", { hasText: "flow-config" })).toHaveCount(0);
});

test("flow keeps colliding policy names distinct and mirrors cascade fallback semantics", async ({ page }) => {
  await page.route("**/api/ingest-auth", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ sources: { github: { configured: true } } }),
  }));
  await page.route("**/api/delivery-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      default_policy: "ops-mail",
      policies: [
        { name: "ops-mail", mode: "cascade", tiers: [] },
        { name: "ops_mail", mode: "cascade", tiers: [{ name: "smtp", timeout_seconds: 10 }] },
      ],
      rules: [{ match: { severity: "critical" }, policy: "ops_mail" }],
      legacy_cascade_tiers: [{ name: "smtp", timeout_seconds: 10 }],
    }),
  }));
  await page.goto("/flow");
  await expect(page.locator("#flow-source")).toContainText("POL_1_OPS_MAIL_NTFY");
  await expect(page.locator("#flow-source")).toContainText("POL_2_OPS_MAIL_SMTP");
  await expect(page.locator('[data-flow-step="policy-1"]')).toContainText("Default policy · ops-mail");
  await expect(page.locator('[data-flow-step="policy-2"]')).toContainText("Policy · ops_mail");
});

test("flow marks cascade fallbacks inactive for a Grafana-only route", async ({ page }) => {
  await page.route("**/api/ingest-auth", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ sources: { grafana: { configured: true } } }),
  }));
  await page.route("**/api/cascade-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      default_enabled_for_webhook: false,
      runtime_enabled: false,
      tiers: [
        { name: "ntfy", timeout_seconds: 15 },
        { name: "smtp", timeout_seconds: 10 },
      ],
    }),
  }));
  await page.route("**/api/delivery-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      default_policy: "cascade",
      policies: [],
      rules: [],
      legacy_cascade_tiers: [
        { name: "ntfy", timeout_seconds: 15 },
        { name: "smtp", timeout_seconds: 10 },
      ],
    }),
  }));
  await page.goto("/flow");
  await expect(page.locator("#flow-source")).toContainText("fallback tier 2 · inactive for Grafana");
  await expect(page.locator('[data-flow-step="policy-0"]')).toContainText("Fallback tiers are inactive");
});
