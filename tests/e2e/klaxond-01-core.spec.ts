import { expect, test } from "@playwright/test";
import {
  APP_VERSION, AUTHOR_NAME, AUTHOR_URL, BASIC_AUTH, BASIC_PASSWORD, BASIC_USER, LOCAL_ORIGIN,
  addVirtualAuthenticator, assertTablePagerWorks, createAdminBearer, enableBasicAuth,
  exportConfigBundle, exportConfigBundleWithAuthFallback, requestWithAuthFallback,
  restoreConfigBundle, revealVersionEgg, totp,
} from "./klaxond-helpers";

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
    "/ui/vendor/swagger-ui/swagger-ui-standalone-preset.js"
  ]) {
    const asset = await request.get(path);
    await expect(asset).toBeOK();
  }

  await page.goto("/");
  await expect(page).toHaveURL(/\/status$/);
  await expect(page.locator("h1")).toContainText("klaxond");
  await expect(page.locator('[data-tab="status"]')).toBeVisible();
  await expect(page.locator('[data-tab="logs"]')).toBeVisible();
  await expect(page.locator('[data-tab="preview"]')).toBeVisible();
  await expect(page.locator(".brand-logo")).toBeVisible();
  await expect(page.locator(".brand-name")).toHaveText("klaxond");
  await expect(page.locator('[data-tab="status"] .tab-icon')).toBeVisible();
  await expect(page.locator('[data-tab="status"] .tab-label')).toHaveText("Status");
  await expect(page.locator('[data-language-option="it"]')).toBeVisible();
  await expect(page.locator('[data-theme-mode-option="system"]')).toBeVisible();
  await expect(page.locator("#sidebar-user-card")).toBeVisible();
  await page.evaluate(() => {
    const w = window as unknown as {
      setTabBadge: (tabId: string, count: number, kind?: string) => void;
      _markTabDirty: (tabId: string, dirty?: boolean) => void;
    };
    w.setTabBadge("logs", 7, "warn");
    w._markTabDirty("routing", true);
  });
  await page.click("#sidebar-toggle");
  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await expect(page.locator(".brand-logo")).toBeVisible();
  await expect(page.locator(".brand-name")).toBeHidden();
  await expect(page.locator('[data-tab="status"] .tab-icon')).toBeVisible();
  await expect(page.locator('[data-tab="status"] .tab-label')).toBeHidden();
  await expect(page.locator('[data-tab="logs"] .tab-badge')).toBeVisible();
  await expect(page.locator('[data-tab="logs"] .tab-badge')).toHaveText("7");
  await expect(page.locator('[data-tab="logs"]')).toHaveAttribute("aria-label", /Logs, 7 active indicator/);
  await expect(page.locator('[data-tab="routing"] .tab-dirty')).toBeVisible();
  await expect(page.locator('[data-tab="routing"]')).toHaveAttribute("aria-label", /Routing, Unsaved changes/);
  await expect(page.locator("#sidebar-avatar")).toBeVisible();
  await expect(page.locator(".sidebar-user-meta")).toBeHidden();
  await page.click("#sidebar-toggle");
  await expect(page.locator("body")).not.toHaveClass(/sidebar-collapsed/);
  await page.click('[data-tab="deliveries"]');
  await expect(page).toHaveURL(/\/deliveries$/);
  await expect(page.locator("#tab-deliveries")).toHaveClass(/active/);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator("#stat-log-retained")).toContainText(/\/500/);
  await expect(page.locator("#stat-log-severity")).toContainText(/WARN \d+ \/ ERROR \d+/);
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

  await page.evaluate(() => notifyError("e2e-client-error", new Error("ClientSideProbe")));
  await expect(page.locator(".toast-error").last()).toContainText("e2e-client-error");
  await expect.poll(async () => {
    const res = await request.get("/api/logs?q=e2e-client-error&level=ERROR&limit=5");
    const payload = await res.json();
    return payload.entries.some((entry: any) => entry.message.includes("frontend error"));
  }).toBe(true);
});

test("footer legal pages are routeable, localized and bottom-aligned", async ({ page, request }) => {
  test.setTimeout(60_000);
  const legalRoutes = [
    ["privacy", "privacy"],
    ["accessibility", "accessibility"],
    ["terms", "terms"],
    ["cookies", "cookies"],
    ["notice", "legal"]
  ] as const;
  for (const [route, tab] of legalRoutes) {
    const res = await request.get(`/legal/${route}`);
    await expect(res).toBeOK();
    const html = await res.text();
    expect(html).toContain(`id="tab-${tab}"`);
    expect(html).not.toContain("klaxond.luigibarretta.com");
  }
  for (const [legacy, canonical] of [
    ["privacy", "/legal/privacy"],
    ["accessibility", "/legal/accessibility"],
    ["terms", "/legal/terms"],
    ["cookies", "/legal/cookies"],
    ["legal", "/legal/notice"]
  ] as const) {
    const res = await request.get(`/ui/${legacy}`, { maxRedirects: 0 });
    expect(res.status()).toBe(302);
    expect(res.headers().location).toBe(canonical);
  }

  await page.goto("/legal/privacy");
  await expect(page).toHaveURL(/\/legal\/privacy$/);
  await expect(page.locator("body")).toHaveClass(/public-info-route/);
  await expect(page.locator("#public-legal-bar")).toBeVisible();
  await expect(page.locator(".sidebar")).toBeHidden();
  await expect(page.locator("#tab-privacy")).toHaveClass(/active/);
  await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toBeHidden();
  await expect(page.locator(".public-login-link")).toHaveText("Back to app");
  await expect(page.locator(".public-login-link")).toHaveAttribute("href", "/status");
  await page.click(".public-login-link");
  await expect(page).toHaveURL(/\/status$/);

  await page.goto("/legal/privacy");
  await expect(page.locator(".app-footer")).toContainText("klaxond");
  await expect(page.locator(".app-footer")).toContainText(`by ${AUTHOR_NAME}`);
  await expect(page.locator(".footer-meta a", { hasText: AUTHOR_NAME })).toHaveAttribute("href", AUTHOR_URL);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator('.footer-links a[href="/legal/accessibility"]')).toHaveText("Accessibility");
  await expect(page.locator('.footer-links a[href^="/ui/"]')).toHaveCount(0);

  await page.click('.footer-links a[href="/legal/accessibility"]');
  await expect(page).toHaveURL(/\/legal\/accessibility$/);
  await expect(page.locator("#tab-accessibility")).toHaveClass(/active/);

  await page.evaluate(() => (window as any).klaxondI18n.setLanguage("it"));
  await expect(page.locator("#tab-accessibility h2")).toHaveText("Dichiarazione di accessibilita'");
  await expect(page.locator(".public-login-link")).toHaveText("Torna all'app");
  await expect(page.locator('.footer-links a[href="/legal/notice"]')).toHaveText("Note legali");
  await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toBeHidden();

  await page.click('.footer-links a[href="/legal/notice"]');
  await expect(page).toHaveURL(/\/legal\/notice$/);
  await expect(page.locator("#tab-legal a", { hasText: AUTHOR_NAME })).toHaveAttribute("href", AUTHOR_URL);
  await expect(page.locator("#tab-legal")).not.toContainText("klaxond.luigibarretta.com");

  await page.evaluate(() => (window as any).klaxondI18n.setLanguage("en"));
  await page.goto("/legal/accessibility?from=login");
  await expect(page).toHaveURL(/\/legal\/accessibility\?from=login$/);
  await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toBeVisible();
  await page.click('#public-legal-bar [data-public-language-option="it"]');
  await expect(page.locator("#tab-accessibility h2")).toHaveText("Dichiarazione di accessibilita'");
  await expect(page.locator('.footer-links a[href="/legal/notice?from=login"]')).toHaveText("Note legali");
  await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toHaveAttribute("aria-pressed", "true");
  await page.click('.footer-links a[href="/legal/notice?from=login"]');
  await expect(page).toHaveURL(/\/legal\/notice\?from=login$/);

  const footerBottomGap = await page.locator(".app-footer").evaluate(el =>
    Math.round(window.innerHeight - el.getBoundingClientRect().bottom)
  );
  expect(Math.abs(footerBottomGap)).toBeLessThanOrEqual(2);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/legal/notice");
  await expect(page.locator("body")).toHaveClass(/public-info-route/);
  await expect(page.locator("#public-legal-bar")).toBeVisible();
  const mobileFooterBottomGap = await page.locator(".app-footer").evaluate(el =>
    Math.round(window.innerHeight - el.getBoundingClientRect().bottom)
  );
  expect(Math.abs(mobileFooterBottomGap)).toBeLessThanOrEqual(2);

  const originalBundle = await exportConfigBundle(request);
  const cleanupBearer = await createAdminBearer(request, "e2e-legal-cleanup");
  try {
    await enableBasicAuth(request);
    for (const [route] of legalRoutes) {
      const publicLegal = await request.get(`/legal/${route}`, { maxRedirects: 0 });
      await expect(publicLegal).toBeOK();
    }

    const publicAsset = await request.get("/ui/style.css", { maxRedirects: 0 });
    await expect(publicAsset).toBeOK();
    const publicMeta = await request.get("/ui/meta.js", { maxRedirects: 0 });
    await expect(publicMeta).toBeOK();
    const metaJs = await publicMeta.text();
    expect(metaJs).toContain("window.KLAXOND_META");
    expect(metaJs).toContain(`version:"${APP_VERSION}"`);
    expect(metaJs).toContain(AUTHOR_URL);

    const loginPage = await request.get("/api/auth/login?return_to=%2Fstatus", { maxRedirects: 0 });
    await expect(loginPage).toBeOK();
    const loginHtml = await loginPage.text();
    expect(loginHtml).toContain('href="/legal/privacy?from=login"');
    expect(loginHtml).toContain('href="/legal/accessibility?from=login"');
    expect(loginHtml).toContain('href="/legal/notice?from=login"');
    expect(loginHtml).not.toContain('href="/ui/privacy"');
    expect(loginHtml).not.toContain('href="/ui/legal"');
    expect(loginHtml).toContain('class="login-logo" src="/ui/favicon.svg"');
    expect(loginHtml).toContain(`class="login-version">v${APP_VERSION}</span>`);
    expect(loginHtml).toContain(AUTHOR_URL);
    expect(loginHtml).not.toContain("klaxond.luigibarretta.com");

    const logout = await request.post("/api/auth/logout");
    expect(logout.status()).toBe(200);
    expect(await logout.json()).toEqual({ ok: true });

    const legacyAdmin = await request.get("/ui/deliveries", { maxRedirects: 0 });
    expect(legacyAdmin.status()).toBe(302);
    expect(legacyAdmin.headers().location).toBe("/deliveries");

    const protectedAdmin = await request.get("/status", { maxRedirects: 0 });
    expect(protectedAdmin.status()).toBe(401);

    await page.goto("/legal/privacy");
    await expect(page).toHaveURL(/\/legal\/privacy$/);
    await expect(page.locator("#tab-privacy")).toHaveClass(/active/);
    await expect(page.locator(".public-login-link")).toHaveText(/Sign in|Accedi/);
    await expect(page.locator(".public-login-link")).toHaveAttribute("href", "/api/auth/login?start=1&return_to=%2Fstatus");
    await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toBeHidden();
    await expect(page.locator("#tab-privacy h2")).toContainText(/Privacy notice|Informativa privacy/);

    await page.goto("/legal/privacy?from=login");
    await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toBeVisible();
    await expect(page.locator('.footer-links a[href="/legal/terms?from=login"]')).toBeVisible();
  } finally {
    await restoreConfigBundle(request, originalBundle, { Authorization: cleanupBearer });
  }
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
