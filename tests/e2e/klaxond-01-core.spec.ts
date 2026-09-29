import { expect, test } from "@playwright/test";
import { isMobileViewport, openSidebar, revealVersionEgg } from "./klaxond-helpers";

test("serves health and admin UI", async ({ page, request }) => {
  const health = await request.get("/healthz");
  await expect(health).toBeOK();
  expect(await health.text()).toBe("OK");

  for (const path of ["/openapi.yaml", "/api/openapi.yaml"]) {
    const spec = await request.get(path);
    await expect(spec).toBeOK();
    expect(spec.headers()["content-type"]).toContain("application/yaml");
    const body = await spec.text();
    expect(body).toContain("openapi: 3.1.0");
    expect(body).toContain("title: klaxond API");
    expect(body).toContain("/api/auth/totp/setup/start:");
  }
  for (const path of ["/api/docs", "/api/swagger", "/api/swagger-ui", "/swagger"]) {
    const swagger = await request.get(path);
    await expect(swagger).toBeOK();
    expect(swagger.headers()["content-type"]).toContain("text/html");
    const body = await swagger.text();
    expect(body).toContain("SwaggerUIBundle");
    expect(body).toContain('url: "/openapi.yaml"');
  }
  for (const path of [
    "/ui/vendor/swagger-ui/swagger-ui.css",
    "/ui/vendor/swagger-ui/swagger-ui-bundle.js",
    "/ui/vendor/swagger-ui/swagger-ui-standalone-preset.js",
    "/ui/vendor/lucide/lucide.min.js"
  ]) {
    const asset = await request.get(path);
    await expect(asset).toBeOK();
  }

  const initialUi = await request.get("/status", { headers: { Accept: "text/html" } });
  await expect(initialUi).toBeOK();
  expect(await initialUi.text()).toContain(
    '<span class="tab-label" data-i18n="tab.grouping">Noise control</span>'
  );

  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.locator("#tab-setup")).toHaveClass(/active/);
  await expect(page.locator("h1")).toContainText("Klaxond");
  const mobile = isMobileViewport(page);
  if (mobile) await openSidebar(page);
  await expect(page.locator('[data-tab="status"]')).toBeVisible();
  await expect(page.locator('[data-tab="logs"]')).toBeHidden();
  await expect(page.locator('[data-tab="preview"]')).toBeHidden();
  await page.click('[data-group="activity"] .tab-group-toggle');
  await page.click('[data-group="inspect"] .tab-group-toggle');
  await expect(page.locator('[data-tab="logs"]')).toBeVisible();
  await expect(page.locator('[data-tab="preview"]')).toBeVisible();
  await expect(page.locator(".brand-logo")).toBeVisible();
  await expect(page.locator(".brand-name")).toHaveText("Klaxond");
  await expect(page.locator('[data-tab="status"] .tab-icon')).toBeVisible();
  await expect(page.locator('[data-tab="status"] .tab-label')).toHaveText("Overview");
  await expect(page.locator('.sidebar [data-language-option="it"]')).toHaveCount(0);
  await expect(page.locator('.app-footer [data-language-option="it"]')).toBeVisible();
  await expect(page.locator('[data-theme-mode-option="system"]')).toBeVisible();
  await expect(page.locator("#sidebar-user-card")).toBeVisible();
  const expandedTabs = page.locator(".sidebar nav.tabs .tab:visible");
  await expect(expandedTabs).not.toHaveCount(0);
  const expandedAlignment = await expandedTabs.evaluateAll(tabs => tabs.map(tab => {
    const icon = tab.querySelector(".tab-icon");
    const label = tab.querySelector(".tab-label");
    return {
      tab: tab.getAttribute("data-tab"),
      justifyContent: getComputedStyle(tab).justifyContent,
      iconLeft: icon?.getBoundingClientRect().left,
      labelLeft: label?.getBoundingClientRect().left,
    };
  }));
  const expectedIconLeft = expandedAlignment[0].iconLeft;
  const expectedLabelLeft = expandedAlignment[0].labelLeft;
  for (const item of expandedAlignment) {
    expect(item.justifyContent, `${item.tab} should be left aligned`).toBe("flex-start");
    expect(item.iconLeft, `${item.tab} icon alignment`).toBeCloseTo(expectedIconLeft, 0);
    expect(item.labelLeft, `${item.tab} label alignment`).toBeCloseTo(expectedLabelLeft, 0);
  }
  await page.evaluate(() => {
    const w = window as unknown as {
      setTabBadge: (tabId: string, count: number, kind?: string) => void;
      _markTabDirty: (tabId: string, dirty?: boolean) => void;
    };
    w.setTabBadge("logs", 7, "warn");
    w._markTabDirty("routing", true);
  });
  if (!mobile) {
    await page.click("#sidebar-toggle");
    await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
    await expect(page.locator('[data-tab="status"]')).toHaveCSS("justify-content", "center");
    await expect(page.locator(".brand-logo")).toBeVisible();
    await expect(page.locator(".brand-name")).toBeHidden();
    await expect(page.locator('[data-tab="status"] .tab-icon')).toBeVisible();
    await expect(page.locator('[data-tab="status"] .tab-label')).toBeHidden();
    await expect(page.locator('[data-tab="logs"] .tab-badge')).toBeVisible();
    await expect(page.locator('[data-tab="logs"] .tab-badge')).toHaveText("7");
    await expect(page.locator('[data-tab="logs"]')).toHaveAttribute("aria-label", /Logs, 7 active indicator/);
    await expect(page.locator('[data-tab="routing"] .tab-dirty')).toBeVisible();
    await expect(page.locator('[data-tab="routing"]')).toHaveAttribute("aria-label", /Sources & channels, Unsaved changes/);
    await expect(page.locator("#sidebar-avatar")).toBeVisible();
    await expect(page.locator(".sidebar-user-meta")).toBeHidden();
    await page.click("#sidebar-toggle");
    await expect(page.locator("body")).not.toHaveClass(/sidebar-collapsed/);
  }
  await page.click('[data-tab="deliveries"]');
  await expect(page).toHaveURL(/\/deliveries$/);
  await expect(page.locator("#tab-deliveries")).toHaveClass(/active/);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator("#stat-log-retained")).toContainText(/\/500/);
  await expect(page.locator("#stat-log-severity")).toContainText(/WARN \d+ \/ ERROR \d+/);
});

test("setup separates release blockers from recommended hardening", async ({ page, request }) => {
  const setup = await request.get("/api/setup-status");
  await expect(setup).toBeOK();
  const payload = await setup.json();
  expect(payload.summary.required).toBe(6);

  await page.goto("/setup");
  await expect(page.locator('[data-setup-group="required"] .setup-item')).toHaveCount(6);
  await expect(page.locator('[data-setup-group="recommended"] .setup-item')).toHaveCount(2);
  await expect(page.locator('[data-setup-group="required"] .setup-step-number')).toHaveCount(6);
  await expect(page.locator('[data-setup-group="recommended"] .setup-step-label')).toHaveCount(2);
  await expect(page.locator('[data-setup-group="required"] .log-level').first()).not.toHaveText(/^(ok|warn|error|partial|info)$/);
  await expect(page.locator('.setup-item.is-ok .setup-status-badge.success').first()).toContainText(/Complete|Complet/);
  await expect(page.locator("#setup-next")).toBeVisible();
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await page.goto("/setup");
    await expect(page.locator(".setup-item")).toHaveCount(8);
    const overflowingCards = await page.locator(".setup-item").evaluateAll((cards) =>
      cards.filter((card) => card.scrollWidth > card.clientWidth + 1).length,
    );
    expect(overflowingCards).toBe(0);
  }
});

test("unconfigured channels are neutral and the empty delivery state has next actions", async ({ page, request }) => {
  const status = await request.get("/api/status");
  await expect(status).toBeOK();
  const payload = await status.json();
  expect(payload.channel_configured).toEqual({ ntfy: true, telegram: false, smtp: false });

  await page.goto("/status");
  await expect(page.locator("#operational-summary-title")).not.toHaveText("Checking delivery path…");
  await expect(page.locator("#ch-telegram .dot")).toHaveClass(/unknown/);
  await expect(page.locator("#ch-telegram .ch-status-text")).toHaveText("not configured");
  await expect(page.locator("#ch-smtp .dot")).toHaveClass(/unknown/);
  await expect(page.locator("#ch-smtp .ch-action")).toHaveAttribute("href", "/routing");

  await page.route("**/api/deliveries*", async route => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
  await page.goto("/deliveries");
  await expect(page.locator(".table-empty-state")).toBeVisible();
  await expect(page.locator('.table-empty-state a[href="/test"]')).toBeVisible();
  await expect(page.locator('.table-empty-state a[href="/setup"]')).toBeVisible();
});

test("status failure replaces a previous readiness result with an unknown state", async ({ page }) => {
  await page.goto("/status");
  await expect(page.locator("#operational-summary-title")).not.toHaveText("Checking delivery path…");
  await page.route("**/api/status", route => route.fulfill({ status: 503, body: "forced status failure" }));

  await page.evaluate(async () => {
    const { loadStatus } = await import("/ui/app-status.js");
    await loadStatus({ force: true });
  });

  await expect(page.locator("#operational-summary")).toHaveAttribute("data-state", "unknown");
  await expect(page.locator("#operational-summary-title")).toHaveText("Channel state is unavailable");
  await expect(page.locator("#status-active-emergencies")).toHaveText("—");
});

test("legacy UI URLs and hash URLs migrate to path routes", async ({ page, request }) => {
  const tabRoute = await request.get("/ui/deliveries", { maxRedirects: 0 });
  expect(tabRoute.status()).toBe(302);
  expect(tabRoute.headers().location).toBe("/deliveries");

  const indexRoute = await request.get("/ui/index.html", { maxRedirects: 0 });
  expect(indexRoute.status()).toBe(302);
  expect(indexRoute.headers().location).toBe("/status");

  const rootRoute = await request.get("/deliveries", { headers: { Accept: "text/html" } });
  await expect(rootRoute).toBeOK();
  expect(await rootRoute.text()).toContain("klaxond");

  const asset = await request.get("/ui/style.css");
  await expect(asset).toBeOK();

  const missing = await request.get("/ui/not-a-tab");
  expect(missing.status()).toBe(404);

  await page.goto("/status#logs");
  await expect(page).toHaveURL(/\/logs$/);
  await expect(page.locator("#tab-logs")).toHaveClass(/active/);

  await page.goto("/status#deliveries");
  await expect(page).toHaveURL(/\/deliveries$/);
  await expect(page.locator("#tab-deliveries")).toHaveClass(/active/);
});
