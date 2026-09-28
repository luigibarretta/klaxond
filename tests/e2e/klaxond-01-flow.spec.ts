import { expect, test } from "@playwright/test";
import { clickSidebarTab, revealVersionEgg } from "./klaxond-helpers";

test("direct flow refresh initializes without frontend TDZ errors", async ({ page, request }) => {
  const seeded = await request.post("/webhook/warning?dry_run=1", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: "FlowDeliveryTimestampProbe",
        component: "host",
        host: "flow-probe"
      }
    }
  });
  await expect(seeded).toBeOK();

  await page.goto("/flow");
  await expect(page).toHaveURL(/\/flow$/);
  await expect(page.locator("#tab-flow")).toHaveClass(/active/);
  await expect(page.locator(".toast-error")).toHaveCount(0);
  await expect(page.locator("#flow-source")).toContainText("SRC_GITHUB");
  await expect(page.locator("#flow-source")).toContainText("SRC_BLACKSTART");
  await expect(page.locator("#flow-source")).toContainText("SRC_REVAULTER");
  await expect(page.locator("#flow-source")).not.toContainText("SRC_DECYPHARR");
  await expect(page.locator("#flow-config-summary")).toContainText("Enabled sources: 4");
  await expect(page.locator("#flow-config-summary")).toContainText("Delivery policies:");
  await expect(page.locator("#flow-route-list .flow-route-step").first()).toContainText("Inbound sources (4)");
  await page.click('[data-flow-step="policy-selector"]');
  await expect(page.locator("#flow-step-inspector")).toContainText("Delivery policy selection");
  await expect(page.locator("#flow-step-inspector a")).toHaveAttribute("href", "/delivery");

  await page.click("#flow-zoom-fit");
  const initialZoom = Number((await page.locator("#flow-zoom-level").textContent())?.replace("%", ""));
  await page.click("#flow-zoom-in");
  await expect.poll(async () =>
    Number((await page.locator("#flow-zoom-level").textContent())?.replace("%", "")),
  ).toBeGreaterThan(initialZoom);
  await page.click("#flow-animate");
  await page.click("#flow-autorefresh");
  await page.click("#flow-show-source");
  await clickSidebarTab(page, "inhibitions");
  await expect(page).toHaveURL(/\/inhibitions$/);
  await expect(page.locator(".app-dialog-overlay")).toHaveCount(0);

  await page.evaluate(() => notifyError("e2e-client-error", new Error("ClientSideProbe")));
  await expect(page.locator(".toast-error").last()).toContainText("e2e-client-error");
  await expect.poll(async () => {
    const res = await request.get("/api/logs?q=e2e-client-error&level=ERROR&limit=5");
    const payload = await res.json();
    return payload.entries.some((entry: any) => entry.message.includes("frontend error"));
  }).toBe(true);
});

test("flow topology follows enabled sources and configured delivery tiers", async ({ page }) => {
  await page.route("**/api/ingest-auth", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ sources: { github: { configured: true }, grafana: { configured: false } } }),
  }));
  await page.route("**/api/cascade-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ runtime_enabled: true, tiers: [{ name: "smtp", timeout_seconds: 10 }] }),
  }));
  await page.route("**/api/channel-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ ntfy: {}, telegram: {}, smtp: { host: "mail.example.test", port: 587 } }),
  }));
  await page.route("**/api/ntfy-topics", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ topics: [] }),
  }));
  await page.route("**/api/delivery-config", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      default_policy: "broadcast-all",
      policies: [{
        name: "broadcast-all",
        mode: "broadcast",
        tiers: [
          { name: "smtp", timeout_seconds: 10 },
          { name: "telegram", timeout_seconds: 8 },
        ],
      }],
      rules: [{ match: { severity: "critical" }, policy: "cascade" }],
      legacy_cascade_tiers: [{ name: "ntfy", timeout_seconds: 15 }],
    }),
  }));

  await page.goto("/flow");
  await expect(page.locator("#flow-source")).toContainText("SRC_GITHUB");
  await expect(page.locator("#flow-source")).not.toContainText("SRC_GRAFANA");
  await expect(page.locator("#flow-source")).toContainText(/POL_1_BROADCAST_ALL -->\|fan-out 1\| POL_1_BROADCAST_ALL_SMTP/);
  await expect(page.locator("#flow-source")).toContainText(/POL_0_CASCADE -->\|tier 1\| POL_0_CASCADE_NTFY/);
  await expect(page.locator("#flow-config-summary")).toContainText("Enabled sources: 1");
  await expect(page.locator('[data-flow-step="policy-1"]')).toContainText("Default policy · broadcast-all");
  await expect(page.locator('[data-flow-step="policy-1"]')).toContainText("Broadcast fan-out: SMTP → Telegram");
  await expect(page.locator('[data-flow-step="policy-0"]')).toContainText("Selected by rules 1");
});

test("delivery view controls never create unsaved configuration state", async ({ page }) => {
  await page.goto("/deliveries");
  await page.click("#deliv-show-suppressed");
  await clickSidebarTab(page, "status");
  await expect(page).toHaveURL(/\/status$/);
  await expect(page.locator(".app-dialog-overlay")).toHaveCount(0);
});

test("footer version reveals a major-version easter egg", async ({ page, request }) => {
  const status = await request.get("/api/status");
  await expect(status).toBeOK();
  const baseStatus = await status.json();
  let version = "0.14.6";

  await page.route("**/api/status", async route => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ...baseStatus, version }),
    });
  });

  await page.goto("/status");
  await expect(page.locator("#footer-version")).toHaveText("v0.14.6");
  for (let i = 0; i < 6; i++) {
    await page.click("#footer-version");
  }
  await expect(page.locator("#version-easter-egg")).toBeHidden();
  await page.click("#footer-version");
  await expect(page.locator("#version-easter-egg")).toBeVisible();
  await expect(page.locator("#version-easter-egg")).toHaveAttribute("data-major", "0");
  const majorZeroEgg = await page.locator("#version-easter-egg").textContent();

  version = "0.99.0";
  await page.reload();
  await expect(page.locator("#footer-version")).toHaveText("v0.99.0");
  await revealVersionEgg(page);
  await expect(page.locator("#version-easter-egg")).toBeVisible();
  expect(await page.locator("#version-easter-egg").textContent()).toBe(majorZeroEgg);

  version = "1.0.0";
  await page.reload();
  await expect(page.locator("#footer-version")).toHaveText("v1.0.0");
  await revealVersionEgg(page);
  await expect(page.locator("#version-easter-egg")).toHaveAttribute("data-major", "1");
  expect(await page.locator("#version-easter-egg").textContent()).not.toBe(majorZeroEgg);
  await expect(page.locator("#version-egg-close")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator("#version-easter-egg")).toBeHidden();
  await expect(page.locator("#footer-version")).toBeFocused();
});
