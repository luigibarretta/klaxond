import { expect, test } from "@playwright/test";
import {
  APP_VERSION, AUTHOR_NAME, AUTHOR_URL, BASIC_AUTH, BASIC_PASSWORD, BASIC_USER, LOCAL_ORIGIN,
  addVirtualAuthenticator, assertTablePagerWorks, createAdminBearer, enableBasicAuth,
  exportConfigBundle, exportConfigBundleWithAuthFallback, requestWithAuthFallback,
  restoreConfigBundle, revealVersionEgg, totp,
} from "./klaxond-helpers";

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

  await page.goto("/logs");
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

  await page.goto("/logs");
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

test("backend log search is debounced in the UI", async ({ page }) => {
  await page.goto("/logs");
  await expect(page.locator("#logs-count")).toContainText(/log line/);

  const logQueries: string[] = [];
  await page.route("**/api/logs?**", async route => {
    logQueries.push(new URL(route.request().url()).searchParams.get("q") || "");
    await route.continue();
  });

  await page.fill("#logs-filter", "a");
  await page.fill("#logs-filter", "auth");
  await page.fill("#logs-filter", "auth rejected");

  await expect.poll(() => logQueries.filter(Boolean).length, { timeout: 2_000 }).toBe(1);
  await page.waitForTimeout(450);
  expect(logQueries.filter(Boolean)).toEqual(["auth rejected"]);
});

test("frontend query cache reuses status GETs and invalidates after mutations", async ({ page }) => {
  await page.goto("/status");
  await expect(page.locator("#ch-ntfy .dot")).toBeVisible();

  let statusCalls = 0;
  await page.route("**/api/status", async route => {
    statusCalls += 1;
    await route.continue();
  });

  await page.evaluate(async () => {
    const w = window as unknown as {
      KlaxondQuery: { invalidate: (match?: string) => void };
      loadStatus: (opts?: { force?: boolean }) => Promise<void>;
    };
    w.KlaxondQuery.invalidate("/api/status");
    await w.loadStatus({ force: true });
    await w.loadStatus();
  });
  expect(statusCalls).toBe(1);

  await page.evaluate(async () => {
    const w = window as unknown as {
      apiFetch: (url: string, opts?: RequestInit) => Promise<Response>;
      loadStatus: (opts?: { force?: boolean }) => Promise<void>;
    };
    const res = await w.apiFetch("/api/client-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        level: "info",
        key: "e2e-query-cache",
        message: "mutation invalidates frontend query cache",
        path: location.pathname,
        stack: "",
        userAgent: navigator.userAgent,
      }),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    await w.loadStatus();
  });
  expect(statusCalls).toBe(2);
});
