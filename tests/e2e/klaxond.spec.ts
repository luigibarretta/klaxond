import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const LOCAL_ORIGIN = "http://localhost:18181";
const BASIC_USER = "admin";
const BASIC_PASSWORD = "test-password";
const BASIC_AUTH = `Basic ${Buffer.from(`${BASIC_USER}:${BASIC_PASSWORD}`).toString("base64")}`;
const AUTHOR_NAME = "Luigi Barretta";
const AUTHOR_URL = "https://github.com/luigibarretta";

async function revealVersionEgg(page: Page) {
  for (let i = 0; i < 7; i++) {
    await page.click("#footer-version");
  }
}

async function enableBasicAuth(request: APIRequestContext) {
  const res = await request.post("/api/auth-config", {
    headers: { Authorization: BASIC_AUTH },
    data: {
      settings: {
        mode: "basic",
        basic: {
          username: BASIC_USER,
          password: BASIC_PASSWORD,
          realm: "klaxond"
        },
        webauthn: {
          enabled: true,
          origin: LOCAL_ORIGIN,
          rp_id: "localhost"
        }
      }
    }
  });
  await expect(res).toBeOK();
}

async function exportConfigBundle(request: APIRequestContext) {
  const res = await request.get("/api/config/export");
  await expect(res).toBeOK();
  return res.json();
}

async function restoreConfigBundle(request: APIRequestContext, bundle: unknown, headers: Record<string, string> = {}) {
  const res = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json", ...headers },
    data: bundle
  });
  await expect(res).toBeOK();
}

async function addVirtualAuthenticator(page: Page) {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true
    }
  });
  return async () => {
    await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
    await client.send("WebAuthn.disable").catch(() => {});
  };
}

async function countPagerRows(page: Page, tableId: string) {
  return page.locator(`#${tableId} tbody tr`).evaluateAll(rows =>
    rows.filter(row => (row as HTMLElement).style.display !== "none").length
  );
}

async function assertTablePagerWorks(page: Page, tab: string, tableId: string) {
  await page.goto(`/ui/${tab}`);
  if (tab === "auth") {
    await expect(page.locator("#auth-current-user")).not.toHaveText("—");
  }
  await page.evaluate(id => {
    const table = document.getElementById(id) as HTMLTableElement | null;
    if (!table?.tBodies[0]) throw new Error(`missing table ${id}`);
    const cols = Math.max(1, table.tHead?.querySelectorAll("th").length || 1);
    table.tBodies[0].innerHTML = "";
    for (let i = 0; i < 12; i++) {
      const row = document.createElement("tr");
      row.className = "pager-probe-row";
      for (let c = 0; c < cols; c++) {
        const cell = document.createElement("td");
        cell.textContent = `${id} row ${i + 1}`;
        row.appendChild(cell);
      }
      table.tBodies[0].appendChild(row);
    }
    (window as unknown as { applyTablePager: (id: string, opts?: unknown) => void }).applyTablePager(id, { reset: true });
  }, tableId);

  const pager = page.locator(`[data-table-pager="${tableId}"]`);
  await expect(pager).toBeVisible();
  await page.selectOption(`[data-table-pager="${tableId}"] [data-pager-size]`, "10");
  await expect(pager.locator("[data-pager-range]")).toContainText("1-10 / 12");
  expect(await countPagerRows(page, tableId)).toBe(10);
  await expect(pager.locator("[data-pager-next]")).toBeEnabled();
  await pager.locator("[data-pager-next]").click();
  await expect(pager.locator("[data-pager-range]")).toContainText("11-12 / 12");
  expect(await countPagerRows(page, tableId)).toBe(2);
}

test("serves health and admin UI", async ({ page, request }) => {
  const health = await request.get("/healthz");
  await expect(health).toBeOK();
  expect(await health.text()).toBe("OK");

  await page.goto("/ui/");
  await expect(page).toHaveURL(/\/ui\/status$/);
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
  await expect(page).toHaveURL(/\/ui\/deliveries$/);
  await expect(page.locator("#tab-deliveries")).toHaveClass(/active/);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator("#stat-log-retained")).toContainText(/\/500/);
  await expect(page.locator("#stat-log-severity")).toContainText(/WARN \d+ \/ ERROR \d+/);
});

test("legacy hash UI URLs migrate to path routes", async ({ page, request }) => {
  const tabRoute = await request.get("/ui/deliveries");
  await expect(tabRoute).toBeOK();
  expect(await tabRoute.text()).toContain("klaxond");

  const asset = await request.get("/ui/style.css");
  await expect(asset).toBeOK();

  const missing = await request.get("/ui/not-a-tab");
  expect(missing.status()).toBe(404);

  await page.goto("/ui/index.html#logs");
  await expect(page).toHaveURL(/\/ui\/logs$/);
  await expect(page.locator("#tab-logs")).toHaveClass(/active/);

  await page.goto("/ui/status#deliveries");
  await expect(page).toHaveURL(/\/ui\/deliveries$/);
  await expect(page.locator("#tab-deliveries")).toHaveClass(/active/);
});

test("direct flow refresh initializes without frontend TDZ errors", async ({ page, request }) => {
  await page.goto("/ui/flow");
  await expect(page).toHaveURL(/\/ui\/flow$/);
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
  for (const route of ["privacy", "accessibility", "terms", "cookies", "legal"]) {
    const res = await request.get(`/ui/${route}`);
    await expect(res).toBeOK();
    const html = await res.text();
    expect(html).toContain(`id="tab-${route}"`);
    expect(html).not.toContain("klaxond.luigibarretta.com");
  }

  await page.goto("/ui/privacy");
  await expect(page).toHaveURL(/\/ui\/privacy$/);
  await expect(page.locator("body")).toHaveClass(/public-info-route/);
  await expect(page.locator("#public-legal-bar")).toBeVisible();
  await expect(page.locator(".sidebar")).toBeHidden();
  await expect(page.locator("#tab-privacy")).toHaveClass(/active/);
  await expect(page.locator(".public-login-link")).toHaveAttribute("href", "/auth/login?start=1&return_to=%2Fui%2Fstatus");
  await page.click(".public-login-link");
  await expect(page).toHaveURL(/\/ui\/status$/);

  await page.goto("/ui/privacy");
  await expect(page.locator(".app-footer")).toContainText("klaxond");
  await expect(page.locator(".app-footer")).toContainText(`by ${AUTHOR_NAME}`);
  await expect(page.locator(".footer-meta a", { hasText: AUTHOR_NAME })).toHaveAttribute("href", AUTHOR_URL);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator('.footer-links a[href="/ui/accessibility"]')).toHaveText("Accessibility");

  await page.click('.footer-links a[href="/ui/accessibility"]');
  await expect(page).toHaveURL(/\/ui\/accessibility$/);
  await expect(page.locator("#tab-accessibility")).toHaveClass(/active/);

  await page.click('#public-legal-bar [data-public-language-option="it"]');
  await expect(page.locator("#tab-accessibility h2")).toHaveText("Dichiarazione di accessibilita'");
  await expect(page.locator('.footer-links a[href="/ui/legal"]')).toHaveText("Note legali");
  await expect(page.locator('#public-legal-bar [data-public-language-option="it"]')).toHaveAttribute("aria-pressed", "true");

  await page.click('.footer-links a[href="/ui/legal"]');
  await expect(page).toHaveURL(/\/ui\/legal$/);
  await expect(page.locator("#tab-legal a", { hasText: AUTHOR_NAME })).toHaveAttribute("href", AUTHOR_URL);
  await expect(page.locator("#tab-legal")).not.toContainText("klaxond.luigibarretta.com");
  const footerBottomGap = await page.locator(".app-footer").evaluate(el =>
    Math.round(window.innerHeight - el.getBoundingClientRect().bottom)
  );
  expect(Math.abs(footerBottomGap)).toBeLessThanOrEqual(2);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/ui/legal");
  await expect(page.locator("body")).toHaveClass(/public-info-route/);
  await expect(page.locator("#public-legal-bar")).toBeVisible();
  const mobileFooterBottomGap = await page.locator(".app-footer").evaluate(el =>
    Math.round(window.innerHeight - el.getBoundingClientRect().bottom)
  );
  expect(Math.abs(mobileFooterBottomGap)).toBeLessThanOrEqual(2);

  const originalBundle = await exportConfigBundle(request);
  try {
    await enableBasicAuth(request);
    for (const route of ["privacy", "accessibility", "terms", "cookies", "legal"]) {
      const publicLegal = await request.get(`/ui/${route}`, { maxRedirects: 0 });
      await expect(publicLegal).toBeOK();
    }

    const publicAsset = await request.get("/ui/style.css", { maxRedirects: 0 });
    await expect(publicAsset).toBeOK();
    const publicMeta = await request.get("/ui/meta.js", { maxRedirects: 0 });
    await expect(publicMeta).toBeOK();
    const metaJs = await publicMeta.text();
    expect(metaJs).toContain("window.KLAXOND_META");
    expect(metaJs).toContain(AUTHOR_URL);

    const loginPage = await request.get("/auth/login?return_to=%2Fui%2Fstatus", { maxRedirects: 0 });
    await expect(loginPage).toBeOK();
    const loginHtml = await loginPage.text();
    expect(loginHtml).toContain('href="/ui/privacy"');
    expect(loginHtml).toContain('href="/ui/accessibility"');
    expect(loginHtml).toContain('href="/ui/legal"');
    expect(loginHtml).toContain('class="login-logo" src="/ui/favicon.svg"');
    expect(loginHtml).toContain('class="login-version">v0.14.11</span>');
    expect(loginHtml).toContain(AUTHOR_URL);
    expect(loginHtml).not.toContain("klaxond.luigibarretta.com");

    const logout = await request.get("/auth/logout", { maxRedirects: 0 });
    expect(logout.status()).toBe(302);
    expect(logout.headers().location).toBe("/auth/login?logged_out=1");

    const protectedAdmin = await request.get("/ui/status", { maxRedirects: 0 });
    expect(protectedAdmin.status()).toBe(401);

    await page.goto("/ui/privacy");
    await expect(page).toHaveURL(/\/ui\/privacy$/);
    await expect(page.locator("#tab-privacy")).toHaveClass(/active/);
    await expect(page.locator("#tab-privacy h2")).toContainText(/Privacy notice|Informativa privacy/);
  } finally {
    await restoreConfigBundle(request, originalBundle, { Authorization: BASIC_AUTH });
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

  await page.goto("/ui/status");
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

test("backend logs page searches captured errors", async ({ page, request }) => {
  const bad = await request.post("/webhook/warning", {
    data: {
      status: "firing",
      commonLabels: { alertname: "UnauthorizedProbe" }
    }
  });
  expect(bad.status()).toBe(401);

  const logs = await request.get("/api/logs?q=auth%20rejected&level=WARN&limit=10");
  await expect(logs).toBeOK();
  const payload = await logs.json();
  expect(payload.entries.length).toBeGreaterThan(0);
  expect(payload.entries[0].message).toContain("webhook auth rejected");

  await page.goto("/ui/logs");
  await page.fill("#logs-filter", "auth rejected");
  await page.selectOption("#logs-level", "WARN");
  await expect(page.locator("#t-logs tbody tr").first()).toContainText("webhook auth rejected");
  await expect(page.locator("#logs-count")).toContainText(/\d+-\d+ \/ \d+ log line/);
});

test("backend logs are paginated in the UI and API", async ({ page, request }) => {
  for (let i = 0; i < 32; i++) {
    const bad = await request.post("/webhook/warning", {
      data: {
        status: "firing",
        commonLabels: { alertname: `UnauthorizedPaginationProbe${i}` }
      }
    });
    expect(bad.status()).toBe(401);
  }

  const apiPage = await request.get("/api/logs?q=auth%20rejected&level=WARN&limit=5&offset=5");
  await expect(apiPage).toBeOK();
  const payload = await apiPage.json();
  expect(payload.limit).toBe(5);
  expect(payload.offset).toBe(5);
  expect(payload.entries.length).toBe(5);
  expect(payload.total).toBeGreaterThanOrEqual(32);

  await page.goto("/ui/logs");
  await page.fill("#logs-filter", "auth rejected");
  await page.selectOption("#logs-level", "WARN");
  await page.selectOption("#logs-limit", "25");
  await expect(page.locator("#logs-page-info")).toContainText(/Page 1 \/ [2-9]\d*/);
  await expect(page.locator("#logs-count")).toContainText(/1-25 \/ \d+ log line/);
  await expect(page.locator("#logs-next")).toBeEnabled();

  await page.click("#logs-next");
  await expect(page.locator("#logs-page-info")).toContainText(/Page 2 \/ [2-9]\d*/);
  await expect(page.locator("#logs-count")).toContainText(/26-\d+ \/ \d+ log line/);
  await expect(page.locator("#logs-prev")).toBeEnabled();

  await page.click("#logs-prev");
  await expect(page.locator("#logs-page-info")).toContainText(/Page 1 \/ [2-9]\d*/);
});

test("recent deliveries are paginated", async ({ page, request }) => {
  for (let i = 0; i < 32; i++) {
    const res = await request.post("/webhook/warning?dry_run=1", {
      headers: { Authorization: "bearer e2e-secret" },
      data: {
        status: "firing",
        commonLabels: {
          alertname: `DeliveryPaginationProbe${i}`,
          component: "host",
          host: `dev-${i}`
        }
      }
    });
    await expect(res).toBeOK();
  }

  await page.goto("/ui/deliveries");
  const pager = page.locator('[data-table-pager="t-deliv"]');
  await expect(pager).toBeVisible();
  await page.selectOption('[data-table-pager="t-deliv"] [data-pager-size]', "10");
  await expect(pager.locator("[data-pager-range]")).toContainText(/1-10 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(pager.locator("[data-pager-next]")).toBeEnabled();

  await pager.locator("[data-pager-next]").click();
  await expect(pager.locator("[data-pager-range]")).toContainText(/11-20 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(pager.locator("[data-pager-prev]")).toBeEnabled();
});

test("all configured finite admin tables use the shared pager", async ({ page }) => {
  const tables = [
    ["inhibitions", "t-inhib-rules"],
    ["inhibitions", "t-inhib"],
    ["inhibitions", "t-acks"],
    ["inhibitions", "t-schedules"],
    ["render", "t-rc"],
    ["cascade", "t-cas"],
    ["delivery", "t-pol"],
    ["delivery", "t-rules"],
    ["auth", "t-tokens"],
    ["auth", "t-passkeys"]
  ] as const;

  for (const [tab, tableId] of tables) {
    await assertTablePagerWorks(page, tab, tableId);
  }
});

test("backend logs fetch failure clears stale count", async ({ page }) => {
  await page.goto("/ui/logs");
  await expect(page.locator("#logs-count")).toContainText(/log line/);

  await page.route(/\/api\/logs\?/, async route => {
    await route.fulfill({ status: 500, body: "forced logs failure" });
  });

  await page.click("#logs-refresh");
  await expect(page.locator("#t-logs tbody tr").first()).toContainText("500 Internal Server Error");
  await expect(page.locator("#logs-count")).toHaveText("");
});

test("expired UI session redirects to login without toast storm", async ({ page }) => {
  await page.route("**/auth/login?**", async route => {
    await route.fulfill({ status: 200, contentType: "text/html", body: "<title>login</title>" });
  });
  await page.route("**/api/status", async route => {
    await route.fulfill({
      status: 401,
      headers: { "X-Klaxond-Login": "/auth/login?return_to=%2Fapi%2Fstatus" },
      body: "",
    });
  });

  await page.goto("/ui/status");
  await expect(page).toHaveURL(/\/auth\/login\?return_to=%2Fui%2Fstatus/);
  await expect(page.locator(".toast-error")).toHaveCount(0);
});

test("save errors show both inline status and toast", async ({ page }) => {
  await page.route("**/api/render-config", async route => {
    if (route.request().method() === "POST") {
      await route.fulfill({ status: 500, body: "forced render-config failure" });
      return;
    }
    await route.continue();
  });

  await page.goto("/ui/render");
  await page.click("#btn-rc-save");
  await expect(page.locator("#rc-status")).toContainText("500");
  await expect(page.locator(".toast-error")).toContainText("render-config-save");
});

test("save successes show both inline status and toast", async ({ page }) => {
  await page.goto("/ui/render");
  await page.click("#btn-rc-save");
  await expect(page.locator("#rc-status")).toContainText("Saved");
  await expect(page.locator(".toast-success").last()).toContainText("Saved");
});

test("reload-backed editor saves keep inline success visible", async ({ page }) => {
  await page.route("**/api/schedules", async route => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ count: 0 }),
      });
      return;
    }
    await route.continue();
  });
  await page.route("**/api/inhibition-rules", async route => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ count: 0, cleared_suppressions: 0 }),
      });
      return;
    }
    await route.continue();
  });

  await page.goto("/ui/inhibitions");
  await page.click("#sched-save");
  await expect(page.locator("#sched-save-status")).toContainText("Saved");
  await expect(page.locator(".toast-success").last()).toContainText("Saved");

  await page.click("#inhib-save");
  await expect(page.locator("#inhib-save-status")).toContainText("Saved");
  await expect(page.locator(".toast-success").last()).toContainText("Saved");
});

test("inhibition applies-to checkboxes stay compact and aligned", async ({ page }) => {
  await page.goto("/ui/inhibitions");
  const firstCheckbox = page.locator('#t-inhib-rules [data-k="applies_to"] input[type="checkbox"]').first();
  await expect(firstCheckbox).toBeVisible();

  const box = await firstCheckbox.boundingBox();
  expect(box?.width).toBeLessThanOrEqual(20);
  await expect(firstCheckbox.locator("xpath=..")).toHaveCSS("align-items", "center");
});

test("authentication separates API keys and PATs", async ({ page }) => {
  await page.goto("/ui/auth");
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
      headers: { Authorization: BASIC_AUTH }
    });
    await expect(cascadeBefore).toBeOK();
    const cascadeBeforePayload = await cascadeBefore.json();
    const desiredRuntime = !cascadeBeforePayload.default_enabled_for_webhook;
    const cascadeToggle = await request.post("/api/cascade/toggle", {
      headers: { Authorization: BASIC_AUTH },
      data: { enabled: desiredRuntime }
    });
    await expect(cascadeToggle).toBeOK();

    const bearerAllowed = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${patPayload.token}` }
    });
    await expect(bearerAllowed).toBeOK();

    const cascadeAfter = await request.get("/api/cascade-config", {
      headers: { Authorization: BASIC_AUTH }
    });
    await expect(cascadeAfter).toBeOK();
    expect((await cascadeAfter.json()).runtime_enabled).toBe(desiredRuntime);

    const afterUse = await request.get("/api/auth/tokens", {
      headers: { Authorization: BASIC_AUTH }
    });
    await expect(afterUse).toBeOK();
    const usedRecord = (await afterUse.json()).tokens.find((token: { id: string }) => token.id === patPayload.record.id);
    expect(usedRecord.last_used_at).toEqual(expect.any(Number));
    expect(usedRecord.last_used_at).toBeGreaterThanOrEqual(patPayload.record.created_at);

    const bearerDeniedByScope = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${apiKeyPayload.token}` }
    });
    expect(bearerDeniedByScope.status()).toBe(403);

    const revoke = await request.post("/api/auth/tokens/revoke", {
      headers: { Authorization: BASIC_AUTH },
      data: { id: patPayload.record.id }
    });
    await expect(revoke).toBeOK();

    const bearerRevoked = await request.get("/api/logs?limit=1", {
      headers: { Authorization: `Bearer ${patPayload.token}` }
    });
    expect(bearerRevoked.status()).toBe(401);
  } finally {
    await restoreConfigBundle(request, originalBundle, { Authorization: BASIC_AUTH });
  }
});

test("passkeys can be registered, used for login, and deleted", async ({ page, request }) => {
  const originalBundle = await exportConfigBundle(request);
  let cleanupAuthenticator: (() => Promise<void>) | undefined;

  try {
    await enableBasicAuth(request);
    await page.setExtraHTTPHeaders({ Authorization: BASIC_AUTH });
    cleanupAuthenticator = await addVirtualAuthenticator(page);

    await page.goto(`${LOCAL_ORIGIN}/ui/auth`);
    await expect(page.locator("#auth-current-user")).toContainText("admin (mode=basic)");
    await page.fill("#passkey-name", "e2e virtual key");
    await page.click("#passkey-register");
    await expect(page.locator("#t-passkeys tbody")).toContainText("e2e virtual key");
    await expect(page.locator(".toast-success").last()).toContainText("Passkey registered");

    await page.goto(`${LOCAL_ORIGIN}/auth/passkey`);
    await page.fill("#user", BASIC_USER);
    await page.click("#login");
    await expect(page).toHaveURL(/\/ui\/status$/);
    const passkeyUser = await page.evaluate(() => fetch("/auth/me").then(r => r.json()));
    expect(passkeyUser).toMatchObject({ sub: BASIC_USER, mode: "passkey" });

    await page.goto(`${LOCAL_ORIGIN}/ui/auth`);
    await expect(page.locator("#auth-current-user")).toContainText("admin (mode=passkey)");
    await page.once("dialog", dialog => dialog.accept());
    await page.locator("#t-passkeys tbody tr", { hasText: "e2e virtual key" }).locator("[data-passkey-del]").click();
    await expect(page.locator("#t-passkeys tbody")).toContainText("No passkeys registered.");
  } finally {
    await cleanupAuthenticator?.();
    await restoreConfigBundle(request, originalBundle, { Authorization: BASIC_AUTH });
    await page.setExtraHTTPHeaders({});
  }
});

test("supports Italian and English plus system/light/dark theme modes", async ({ page }) => {
  await page.goto("/healthz");
  await page.evaluate(() => {
    localStorage.setItem("klaxond.theme", "light");
    localStorage.removeItem("klaxond.themeMode");
  });

  await page.goto("/ui/");
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

test("render-preview returns ntfy-compatible headers without delivery", async ({ request }) => {
  const res = await request.post("/api/render-preview", {
    data: {
      severity: "critical",
      payload: {
        status: "firing",
        commonLabels: {
          alertname: "HostLoadHigh",
          component: "host",
          host: "it1-prd-dev-01"
        },
        commonAnnotations: {
          summary: "load average above threshold"
        },
        alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
      }
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.url).toBe("http://127.0.0.1:9/critical-topic");
  expect(body.headers["Title (raw)"]).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
  expect(body.headers.Tags).toBe("rotating_light,critical,grafana,host");
  expect(body.headers.Priority).toBe("urgent");
});

test("webhook dry-run exercises ingest pipeline without sending", async ({ request }) => {
  const res = await request.post("/webhook/critical?dry_run=1", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: "HostLoadHigh",
        component: "host",
        host: "it1-prd-dev-01"
      },
      commonAnnotations: {
        summary: "load average above threshold"
      },
      alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.dry_run).toBe(true);
  expect(body.would_send).toBe(true);
  expect(body.source).toBe("grafana");
  expect(body.severity).toBe("critical");
  expect(body.parsed.title).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
});

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

test("full config export includes TOML sidecars and runtime settings", async ({ page, request }) => {
  await page.goto("/ui/status");
  await expect(page.locator("#cfg-backup-download")).toHaveAttribute("href", "/api/config/backup");
  await expect(page.locator("#cfg-full-export-download")).toHaveAttribute("href", "/api/config/export");

  const exported = await request.get("/api/config/export");
  await expect(exported).toBeOK();
  expect(exported.headers()["content-type"]).toContain("application/json");
  expect(exported.headers()["content-disposition"]).toContain("klaxond-full-settings-");

  const bundle = await exported.json();
  expect(bundle).toMatchObject({
    kind: "klaxond.full-settings",
    format_version: 1,
    includes_secrets: true,
    files_are_effective: true
  });
  expect(Object.keys(bundle.files)).toEqual(expect.arrayContaining([
    "klaxond.toml",
    "render-config.json",
    "ntfy-topics.json",
    "dedup-config.json",
    "auth-config.json"
  ]));
  expect(JSON.parse(bundle.files["render-config.json"]).component_dashboards).toBeTruthy();
  expect(JSON.parse(bundle.files["ntfy-topics.json"]).topics.length).toBeGreaterThan(0);
  expect(bundle.effective_runtime).toHaveProperty("telegram");
  expect(bundle.effective_runtime).toHaveProperty("smtp");
  expect(bundle.effective_runtime).toHaveProperty("grafana");

  const restored = await request.post("/api/config/restore", {
    data: JSON.stringify(bundle),
    headers: { "Content-Type": "application/json" }
  });
  await expect(restored).toBeOK();
  expect(await restored.json()).toMatchObject({
    ok: true,
    source_kind: "full-bundle",
    restored_sidecars: [
      "render-config.json",
      "ntfy-topics.json",
      "dedup-config.json",
      "auth-config.json"
    ]
  });
});

test("config restore rejects bad bundles without changing current settings", async ({ request }) => {
  const beforeBundle = await exportConfigBundle(request);

  const unsupportedVersion = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 999,
      files: {
        "klaxond.toml": beforeBundle.files["klaxond.toml"]
      }
    }
  });
  expect(unsupportedVersion.status()).toBe(400);
  expect(await unsupportedVersion.text()).toContain("unsupported config bundle format_version");

  const unsupportedSidecar = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 1,
      files: {
        ...beforeBundle.files,
        "not-a-sidecar.json": "{}"
      }
    }
  });
  expect(unsupportedSidecar.status()).toBe(400);
  expect(await unsupportedSidecar.text()).toContain("unsupported sidecar");

  const invalidSidecarJson = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json" },
    data: {
      kind: "klaxond.full-settings",
      format_version: 1,
      files: {
        ...beforeBundle.files,
        "render-config.json": "{not json"
      }
    }
  });
  expect(invalidSidecarJson.status()).toBe(400);
  expect(await invalidSidecarJson.text()).toContain("invalid render-config.json");

  const afterBundle = await exportConfigBundle(request);
  expect(afterBundle.files["klaxond.toml"]).toBe(beforeBundle.files["klaxond.toml"]);
  expect(afterBundle.files["render-config.json"]).toBe(beforeBundle.files["render-config.json"]);
  expect(afterBundle.files["auth-config.json"]).toBe(beforeBundle.files["auth-config.json"]);
});

test("admin config POST endpoints persist through their read APIs", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);

  try {
    const renderUpdate = await request.post("/api/render-config", {
      data: {
        component_dashboards: {
          e2e_component: ["E2E dashboard", "/d/e2e-dashboard"]
        }
      }
    });
    await expect(renderUpdate).toBeOK();
    const renderRead = await request.get("/api/render-config");
    await expect(renderRead).toBeOK();
    expect((await renderRead.json()).component_dashboards.e2e_component).toEqual(["E2E dashboard", "/d/e2e-dashboard"]);

    const topicsUpdate = await request.post("/api/ntfy-topics", {
      data: {
        topics: [
          { name: "e2e-info-topic", token: "secret-info", handles: ["info"] },
          { name: "e2e-page-topic", token: "secret-page", handles: ["critical", "page"] }
        ]
      }
    });
    await expect(topicsUpdate).toBeOK();
    const topicsRead = await request.get("/api/ntfy-topics");
    await expect(topicsRead).toBeOK();
    const topicsPayload = await topicsRead.json();
    expect(topicsPayload.topics).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "e2e-info-topic", token: "***SET***", handles: ["info"] }),
      expect.objectContaining({ name: "e2e-page-topic", token: "***SET***", handles: ["critical", "page"] })
    ]));

    const dedupUpdate = await request.post("/api/dedup-config", {
      data: {
        settings: {
          grafana: { enabled: true, window_s: 42, strategy: "time", override_critical: true }
        }
      }
    });
    await expect(dedupUpdate).toBeOK();
    const dedupRead = await request.get("/api/dedup-config");
    await expect(dedupRead).toBeOK();
    expect((await dedupRead.json()).settings.grafana).toMatchObject({
      enabled: true,
      window_s: 42,
      strategy: "time",
      override_critical: true
    });

    const deliveryUpdate = await request.post("/api/delivery-config", {
      data: {
        default_policy: "e2e-broadcast",
        policies: [
          {
            name: "e2e-broadcast",
            mode: "broadcast",
            tiers: [{ name: "ntfy", timeout_seconds: 3 }, { name: "smtp", timeout_seconds: 4 }]
          }
        ],
        rules: [{ match: { component: "e2e_component" }, policy: "e2e-broadcast" }]
      }
    });
    await expect(deliveryUpdate).toBeOK();
    const deliveryRead = await request.get("/api/delivery-config");
    await expect(deliveryRead).toBeOK();
    expect(await deliveryRead.json()).toMatchObject({
      default_policy: "e2e-broadcast",
      policies: [expect.objectContaining({ name: "e2e-broadcast", mode: "broadcast" })],
      rules: [expect.objectContaining({ match: { component: "e2e_component" }, policy: "e2e-broadcast" })]
    });

    const ingestUpdate = await request.post("/api/ingest-auth", {
      data: { source: "beszel", action: "set", secret: "abcdefghijklmnop" }
    });
    await expect(ingestUpdate).toBeOK();
    const ingestRead = await request.get("/api/ingest-auth");
    await expect(ingestRead).toBeOK();
    expect((await ingestRead.json()).sources.beszel).toMatchObject({ configured: true, from: "toml" });

    const schedulesUpdate = await request.post("/api/schedules", {
      data: {
        schedules: [{
          name: "e2e-maintenance",
          cron: "0 3 * * *",
          duration_minutes: 45,
          match: { component: "e2e_component" },
          applies_to: ["grafana"]
        }]
      }
    });
    await expect(schedulesUpdate).toBeOK();
    const schedulesRead = await request.get("/api/schedules");
    await expect(schedulesRead).toBeOK();
    expect((await schedulesRead.json()).schedules).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "e2e-maintenance", cron: "0 3 * * *", duration_minutes: 45 })
    ]));
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});

test("backend logs require admin auth when auth is enabled", async ({ request }) => {
  const unsafeBasic = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "basic",
        basic: { username: "", password: "test-password" }
      }
    }
  });
  expect(unsafeBasic.status()).toBe(400);
  expect(await unsafeBasic.text()).toContain("username");

  const unsafeOidc = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "oidc",
        oidc: {
          issuer: "https://idp.example.test",
          client_id: "klaxond",
          redirect_path: "/custom/callback"
        }
      }
    }
  });
  expect(unsafeOidc.status()).toBe(400);
  expect(await unsafeOidc.text()).toContain("/auth/callback");

  const unsafeTrustedProxy = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "trusted-proxy",
        trusted_proxy: {
          user_header: "X-Forwarded-User",
          trusted_cidrs: ["127.0.0.1/32"]
        }
      }
    }
  });
  expect(unsafeTrustedProxy.status()).toBe(400);
  expect(await unsafeTrustedProxy.text()).toContain("X-Forwarded-User");

  const scopedToken = await request.post("/api/auth/tokens", {
    data: {
      name: "logs-reader",
      kind: "pat",
      scopes: ["logs:read"]
    }
  });
  await expect(scopedToken).toBeOK();
  const scopedPayload = await scopedToken.json();
  expect(scopedPayload.token).toMatch(/^klx_pat_/);
  expect(JSON.stringify(scopedPayload.record)).not.toContain("token_hash");

  const wrongToken = await request.post("/api/auth/tokens", {
    data: {
      name: "status-only",
      kind: "api-key",
      scopes: ["status:read"]
    }
  });
  await expect(wrongToken).toBeOK();
  const wrongPayload = await wrongToken.json();

  const update = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "basic",
        basic: {
          username: "admin",
          password: "test-password"
        }
      }
    }
  });
  await expect(update).toBeOK();
  const updatedAuth = await update.json();
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("token_hash");
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("credential");

  const denied = await request.get("/api/logs?limit=1");
  expect(denied.status()).toBe(401);
  expect(denied.headers()["www-authenticate"]).toContain("Basic");

  const token = Buffer.from("admin:test-password").toString("base64");
  const allowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Basic ${token}` }
  });
  await expect(allowed).toBeOK();

  const bearerAllowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${scopedPayload.token}` }
  });
  await expect(bearerAllowed).toBeOK();

  const bearerDenied = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${wrongPayload.token}` }
  });
  expect(bearerDenied.status()).toBe(403);
});
