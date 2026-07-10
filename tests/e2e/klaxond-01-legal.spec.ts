import { expect, test } from "@playwright/test";
import {
  APP_VERSION,
  AUTHOR_NAME,
  AUTHOR_URL,
  createAdminBearer,
  enableBasicAuth,
  exportConfigBundle,
  restoreConfigBundle,
} from "./klaxond-helpers";

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
  await expect(page.locator("body")).toHaveClass(/public-info-route/, { timeout: 10_000 });
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
  await expect(page.locator("body")).toHaveClass(/public-info-route/, { timeout: 10_000 });
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
