import { expect, test } from "@playwright/test";
import {
  BASIC_AUTH,
  BASIC_USER,
  LOCAL_ORIGIN,
  addVirtualAuthenticator,
  createAdminBearer,
  enableBasicAuth,
  exportConfigBundle,
  restoreConfigBundle,
} from "./klaxond-helpers";

test("authentication separates API keys and PATs", async ({ page }) => {
  await page.goto("/authentication");
  await expect(page.locator('[data-token-kind-option="api-key"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#token-kind")).toHaveValue("api-key");
  await expect(page.locator("#token-create")).toHaveText("Create API key");
  await expect(page.locator("#token-table-title")).toHaveText("API Keys");
  await expect(page.locator("#t-tokens tbody")).toContainText("No API keys.");

  await page.click('[data-token-kind-option="pat"]');
  await expect(page.locator('[data-token-kind-option="pat"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#token-kind")).toHaveValue("pat");
  await expect(page.locator("#token-create")).toHaveText("Create PAT");
  await expect(page.locator("#token-table-title")).toHaveText("PATs");
  await expect(page.locator("#t-tokens tbody")).toContainText("No PATs.");
});

test("API keys and PATs support prefixes, last-use tracking, revocation and scope denial", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);
  const adminBearer = await createAdminBearer(request, "e2e-token-admin");
  const pat = await request.post("/api/auth/tokens", {
    data: { name: "e2e-logs-reader", kind: "pat", scopes: ["logs:read"] }
  });
  await expect(pat).toBeOK();
  const patPayload = await pat.json();
  expect(patPayload.token).toMatch(/^klx_pat_/);
  expect(patPayload.record).toMatchObject({
    name: "e2e-logs-reader",
    kind: "pat",
    prefix: patPayload.token.slice(0, 18),
    enabled: true,
    last_used_at: null
  });

  const apiKey = await request.post("/api/auth/tokens", {
    data: { name: "e2e-status-only", kind: "api-key", scopes: ["status:read"], expires_in_days: 1 }
  });
  await expect(apiKey).toBeOK();
  const apiKeyPayload = await apiKey.json();
  expect(apiKeyPayload.token).toMatch(/^klx_key_/);
  expect(apiKeyPayload.record.kind).toBe("api-key");
  expect(apiKeyPayload.record.expires_at).toBeGreaterThan(apiKeyPayload.record.created_at);

  try {
    await enableBasicAuth(request);

    const cascadeBefore = await request.get("/api/cascade-config", {
      headers: { Authorization: adminBearer }
    });
    await expect(cascadeBefore).toBeOK();
    const cascadeBeforePayload = await cascadeBefore.json();
    const desiredRuntime = !cascadeBeforePayload.default_enabled_for_webhook;
    const basicMutationDenied = await request.post("/api/cascade/toggle", {
      headers: { Authorization: BASIC_AUTH },
      data: { enabled: desiredRuntime }
    });
    expect(basicMutationDenied.status()).toBe(403);
    expect(await basicMutationDenied.text()).toContain("CSRF");

    const cascadeToggle = await request.post("/api/cascade/toggle", {
      headers: { Authorization: adminBearer },
      data: { enabled: desiredRuntime }
    });
    await expect(cascadeToggle).toBeOK();

    const bearerAllowed = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${patPayload.token}` }
    });
    await expect(bearerAllowed).toBeOK();

    const cascadeAfter = await request.get("/api/cascade-config", {
      headers: { Authorization: adminBearer }
    });
    await expect(cascadeAfter).toBeOK();
    expect((await cascadeAfter.json()).runtime_enabled).toBe(desiredRuntime);

    const afterUse = await request.get("/api/auth/tokens", {
      headers: { Authorization: adminBearer }
    });
    await expect(afterUse).toBeOK();
    const usedRecord = (await afterUse.json()).tokens.find((token: { id: string }) => token.id === patPayload.record.id);
    expect(usedRecord.last_used_at).toEqual(expect.any(Number));
    expect(usedRecord.last_used_at).toBeGreaterThanOrEqual(patPayload.record.created_at);

    const bearerDeniedByScope = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${apiKeyPayload.token}` }
    });
    expect(bearerDeniedByScope.status()).toBe(403);

    const revoke = await request.delete(`/api/auth/tokens/${encodeURIComponent(patPayload.record.id)}`, {
      headers: { Authorization: adminBearer },
    });
    await expect(revoke).toBeOK();

    const bearerRevoked = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${patPayload.token}` }
    });
    expect(bearerRevoked.status()).toBe(401);
  } finally {
    await restoreConfigBundle(request, originalBundle, { Authorization: adminBearer });
  }
});

test("passkeys can be registered, used for login, and deleted", async ({ page, request }) => {
  const originalBundle = await exportConfigBundle(request);
  const cleanupBearer = await createAdminBearer(request, "e2e-passkey-cleanup");
  let cleanupAuthenticator: (() => Promise<void>) | undefined;

  try {
    await enableBasicAuth(request);
    await page.setExtraHTTPHeaders({ Authorization: BASIC_AUTH });
    cleanupAuthenticator = await addVirtualAuthenticator(page);

    await page.goto(`${LOCAL_ORIGIN}/authentication`);
    await expect(page.locator("#auth-current-user")).toContainText("admin (mode=basic)");
    await page.fill("#passkey-name", "e2e virtual key");
    await page.click("#passkey-register");
    await expect(page.locator("#t-passkeys tbody")).toContainText("e2e virtual key");
    await expect(page.locator(".toast-success").last()).toContainText("Passkey registered");

    await page.setExtraHTTPHeaders({});
    await page.goto(`${LOCAL_ORIGIN}/api/auth/passkey/login`);
    await page.fill("#user", BASIC_USER);
    await page.click("#login");
    await expect(page).toHaveURL(/\/status$/);
    const passkeyUser = await page.evaluate(() => fetch("/api/auth/me").then(r => r.json()));
    expect(passkeyUser).toMatchObject({ sub: BASIC_USER, mode: "passkey" });

    await page.goto(`${LOCAL_ORIGIN}/authentication`);
    await expect(page.locator("#auth-current-user")).toContainText("admin (mode=passkey)");
    await page.once("dialog", dialog => dialog.accept());
    await page.locator("#t-passkeys tbody tr", { hasText: "e2e virtual key" }).locator("[data-passkey-del]").click();
    await expect(page.locator("#t-passkeys tbody")).toContainText("No passkeys registered.");
  } finally {
    await cleanupAuthenticator?.();
    await restoreConfigBundle(request, originalBundle, { Authorization: cleanupBearer });
    await page.setExtraHTTPHeaders({});
  }
});

test("supports Italian and English plus system/light/dark theme modes", async ({ page }) => {
  await page.goto("/healthz");
  await page.evaluate(() => {
    localStorage.setItem("klaxond.theme", "light");
    localStorage.removeItem("klaxond.themeMode");
  });

  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("#gbase")).toHaveText("https://grafana.luigibarretta.com");

  await page.click('[data-language-option="it"]');
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await expect(page.locator('[data-tab="status"] .tab-label')).toHaveText("Stato");
  await expect(page.locator('[data-tab="deliveries"]')).toContainText("Consegne recenti");
  await expect(page).toHaveTitle(/demone notifiche/);
  await expect(page.locator("#gbase")).toHaveText("https://grafana.luigibarretta.com");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.lang"))).toBe("it");
  await expect(page.locator('[data-language-option="it"]')).toHaveAttribute("aria-pressed", "true");

  await page.click('[data-theme-mode-option="light"]');
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator('[data-theme-mode-option="light"]')).toHaveAttribute("aria-pressed", "true");

  await page.click('[data-theme-mode-option="dark"]');
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('[data-theme-mode-option="dark"]')).toHaveAttribute("aria-pressed", "true");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.themeMode"))).toBe("dark");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.theme"))).toBeNull();

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await expect(page.locator('[data-tab="status"] .tab-label')).toHaveText("Stato");
  await expect(page.locator('[data-theme-mode-option="dark"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.click('[data-theme-mode-option="system"]');
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "system");
  await expect(page.locator("html")).toHaveAttribute("data-theme", /^(light|dark)$/);

  await page.click('[data-language-option="en"]');
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.locator('[data-tab="status"] .tab-label')).toHaveText("Status");
  await expect(page.locator('[data-language-option="en"]')).toHaveAttribute("aria-pressed", "true");
});
