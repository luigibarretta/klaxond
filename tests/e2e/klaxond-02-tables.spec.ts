import { expect, test } from "@playwright/test";
import { assertTablePagerWorks } from "./klaxond-helpers";

test("recent deliveries are paginated", async ({ page, request }, testInfo) => {
  const runId = `${testInfo.project.name}-${Date.now()}`;
  const realProbe = `DeliveryRealHistoryProbe-${runId}`;
  const paginationProbe = `DeliveryPaginationProbe-${runId}-`;
  const real = await request.post("/webhook/warning", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: realProbe,
        component: "host",
        host: "real-history"
      }
    }
  });
  expect(real.status()).toBe(502);
  await expect.poll(async () => {
    const res = await request.get("/api/deliveries?limit=5");
    await expect(res).toBeOK();
    const payload = await res.json();
    return payload.entries.some((entry: any) =>
      entry.title.includes(realProbe) && entry.channel.includes("failed")
    );
  }).toBe(true);

  for (let i = 0; i < 32; i++) {
    const res = await request.post("/webhook/warning?dry_run=1", {
      headers: { Authorization: "bearer e2e-secret" },
      data: {
        status: "firing",
        commonLabels: {
          alertname: `${paginationProbe}${i}`,
          component: "host",
          host: `dev-${i}`
        }
      }
    });
    await expect(res).toBeOK();
  }

  const deliveryRequestUrls: string[] = [];
  page.on("request", req => {
    if (new URL(req.url()).pathname === "/api/deliveries") deliveryRequestUrls.push(req.url());
  });
  await page.goto("/deliveries");
  await page.fill("#deliv-filter", paginationProbe);
  await expect(page.locator("#deliv-storage")).toContainText(/retained|serialized/i);
  const pagers = page.locator("[data-deliveries-pager]");
  await expect(pagers).toHaveCount(2);
  const pager = pagers.last();
  await expect(pager.locator("[data-deliv-range]")).toContainText("1-25 of 32");
  await expect(page.locator("#t-deliv tbody tr.deliv-row")).toHaveCount(25);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible").first()).toContainText(`${paginationProbe}31`);
  await expect(pager.locator('[data-deliv-page="next"]')).toBeEnabled();

  await pager.locator('[data-deliv-page="next"]').click();
  await expect(pager.locator("[data-deliv-range]")).toContainText("26-32 of 32");
  await expect(page.locator("#t-deliv tbody tr.deliv-row")).toHaveCount(7);
  await expect(pager.locator('[data-deliv-page="prev"]')).toBeEnabled();
  expect(deliveryRequestUrls.some(url => new URL(url).searchParams.get("q") === paginationProbe)).toBe(true);
  expect(deliveryRequestUrls.every(url => new URL(url).searchParams.get("limit") !== "10000")).toBe(true);

  let releaseExport!: () => void;
  const exportRelease = new Promise<void>(resolve => { releaseExport = resolve; });
  const exportUrls: string[] = [];
  await page.route(/\/api\/deliveries\?.*/, async route => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("limit") !== "10000") return route.continue();
    exportUrls.push(url.toString());
    await exportRelease;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total: 1, limit: 10000, offset: 0, entries: [{
        ts: Date.now() / 1000,
        source: "grafana",
        severity: "warning",
        title: `${paginationProbe}31`,
        channel: "dry-run",
        suppressed_by: "",
      }] }),
    });
  });
  const download = page.waitForEvent("download");
  await page.locator("#deliv-export-csv").click();
  await expect.poll(() => exportUrls.length).toBe(1);
  await page.fill("#deliv-filter", "changed while exporting");
  releaseExport();
  await download;
  expect(new URL(exportUrls[0]).searchParams.get("q")).toBe(paginationProbe);
  expect(exportUrls).toHaveLength(1);

  const suppressedRequest = page.waitForRequest(req => {
    const url = new URL(req.url());
    return url.pathname === "/api/deliveries"
      && url.searchParams.get("suppressed") === "only";
  });
  await page.selectOption("#deliv-channel", "__suppressed__");
  const suppressedUrl = new URL((await suppressedRequest).url());
  expect(suppressedUrl.searchParams.has("channel")).toBe(false);
  await expect(page.locator("#deliv-show-suppressed")).toBeChecked();
  await expect(page.locator("#deliv-show-suppressed")).toBeDisabled();

  const excludedRequest = page.waitForRequest(req => {
    const url = new URL(req.url());
    return url.pathname === "/api/deliveries"
      && url.searchParams.get("channel") === "ntfy"
      && url.searchParams.get("suppressed") === "exclude";
  });
  await page.selectOption("#deliv-channel", "ntfy");
  await expect(page.locator("#deliv-show-suppressed")).toBeEnabled();
  await page.uncheck("#deliv-show-suppressed");
  await excludedRequest;

  const suppressedAgainRequest = page.waitForRequest(req => {
    const url = new URL(req.url());
    return url.pathname === "/api/deliveries"
      && url.searchParams.get("suppressed") === "only";
  });
  await page.selectOption("#deliv-channel", "__suppressed__");
  await suppressedAgainRequest;
  await expect(page.locator("#deliv-show-suppressed")).toBeChecked();
  await expect(page.locator("#deliv-show-suppressed")).toBeDisabled();
});

test("delivery export validates the current filters instead of a stale page count", async ({ page }) => {
  const exportQueries: string[] = [];
  await page.route(/\/api\/deliveries\?.*/, async route => {
    const url = new URL(route.request().url());
    const query = url.searchParams.get("q") || "";
    const limit = url.searchParams.get("limit");
    if (limit === "10000") {
      exportQueries.push(query);
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ total: 1, limit: 10000, offset: 0, entries: [{
          ts: Date.now() / 1000,
          source: "grafana",
          severity: "warning",
          title: "Exportable",
          channel: "dry-run",
          suppressed_by: "",
        }] }),
      });
    }
    const total = query === "no-results" ? 0 : query === "too-many" ? 10_001 : 1;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total, limit: 25, offset: 0, entries: [] }),
    });
  });

  await page.goto("/deliveries");
  await page.fill("#deliv-filter", "no-results");
  await expect(page.locator("#deliv-count")).toContainText("0");
  await page.fill("#deliv-filter", "exportable-after-empty");
  await Promise.all([
    page.waitForEvent("download"),
    page.locator("#deliv-export-csv").click(),
  ]);

  await page.fill("#deliv-filter", "too-many");
  await expect(page.locator("#deliv-count")).toContainText("10001");
  await page.fill("#deliv-filter", "exportable-after-large");
  await Promise.all([
    page.waitForEvent("download"),
    page.locator("#deliv-export-csv").click(),
  ]);

  expect(exportQueries).toEqual(["exportable-after-empty", "exportable-after-large"]);
});

test("all configured finite admin tables use the shared pager", async ({ page }) => {
  test.setTimeout(60_000);
  const tables = [
    ["inhibitions", "t-inhib-rules"],
    ["inhibitions", "t-inhib"],
    ["inhibitions", "t-acks"],
    ["inhibitions", "t-schedules"],
    ["render", "t-rc"],
    ["cascade", "t-cas"],
    ["delivery", "t-pol"],
    ["delivery", "t-rules"],
    ["grouping", "t-repeat-suppressed"],
    ["auth", "t-tokens"],
    ["auth", "t-passkeys"]
  ] as const;

  for (const [tab, tableId] of tables) {
    await assertTablePagerWorks(page, tab, tableId);
  }
});

test("cascade timeout editor explains and highlights unsafe ntfy values", async ({ page }) => {
  let savedDefault: boolean | undefined;
  await page.route("**/api/cascade-config", async route => {
    if (route.request().method() === "POST") {
      savedDefault = (await route.request().postDataJSON()).default_enabled_for_webhook;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        tiers: [{ name: "ntfy", timeout_seconds: 15 }],
        default_enabled_for_webhook: false,
        runtime_enabled: true,
        timeout_policy: {
          min_seconds: 1,
          max_seconds: 60,
          recommended_seconds: { ntfy: 15, telegram: 8, smtp: 10 },
          warning_below_seconds: { ntfy: 15 },
        },
      }),
    });
  });

  await page.goto("/cascade");
  await expect(page.locator("#cas-default")).not.toBeChecked();
  await page.locator("#cas-default").check();
  await page.locator("#btn-cas-save").click();
  await expect.poll(() => savedDefault).toBe(true);
  await expect(page.locator('[id="cas-default"]')).toHaveCount(1);
  await expect(page.locator("#cas-timeout-help")).toContainText("at least 15 seconds");
  const timeout = page.locator('#t-cas [data-f="timeout"]').first();
  await timeout.fill("5");
  await expect(timeout).toHaveClass(/input-warning/);
  await expect(page.locator("#cas-timeout-risk")).toContainText("duplicate notifications");
});

test("backend logs fetch failure clears stale count", async ({ page }) => {
  await page.goto("/logs");
  await expect(page.locator("#logs-count")).toContainText(/log line/);

  await page.route(/\/api\/logs\?/, async route => {
    await route.fulfill({ status: 500, body: "forced logs failure" });
  });

  await page.click("#logs-refresh");
  await expect(page.locator("#t-logs tbody tr").first()).toContainText("500 Internal Server Error");
  await expect(page.locator("#logs-count")).toHaveText("");
});

test("expired UI session redirects to login without toast storm", async ({ page }) => {
  await page.route("**/api/auth/login?**", async route => {
    await route.fulfill({ status: 200, contentType: "text/html", body: "<title>login</title>" });
  });
  await page.route("**/api/status", async route => {
    await route.fulfill({
      status: 401,
      headers: { "X-Klaxond-Login": "/api/auth/login?return_to=%2Fapi%2Fstatus" },
      body: "",
    });
  });

  await page.goto("/status");
  await expect(page).toHaveURL(/\/api\/auth\/login\?return_to=%2Fstatus/);
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

  await page.goto("/render");
  await page.click("#btn-rc-save");
  await expect(page.locator("#rc-status")).toContainText("500");
  await expect(page.locator(".toast-error")).toContainText("render-config-save");
});

test("save successes show both inline status and toast", async ({ page }) => {
  await page.goto("/render");
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

  await page.goto("/inhibitions");
  await page.click("#sched-save");
  await expect(page.locator("#sched-save-status")).toContainText("Saved");
  await expect(page.locator(".toast-success").last()).toContainText("Saved");

  await page.click("#inhib-save");
  await expect(page.locator("#inhib-save-status")).toContainText("Saved");
  await expect(page.locator(".toast-success").last()).toContainText("Saved");
});

test("inhibition applies-to checkboxes stay compact and aligned", async ({ page }) => {
  await page.goto("/inhibitions");
  const firstCheckbox = page.locator('#t-inhib-rules [data-k="applies_to"] input[type="checkbox"]').first();
  await expect(firstCheckbox).toBeVisible();

  const box = await firstCheckbox.boundingBox();
  expect(box?.width).toBeLessThanOrEqual(20);
  await expect(firstCheckbox.locator("xpath=..")).toHaveCSS("align-items", "center");

  await page.setViewportSize({ width: 1920, height: 1080 });
  const regex = page.locator('#t-inhib-rules [data-k="match_regex"]:visible').first();
  await expect(regex).toBeVisible();
  expect((await regex.boundingBox())?.width).toBeGreaterThanOrEqual(180);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator("#t-inhib-rules .inhib-rule-row").first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
});

test("delivery history exposes keyboard details and ACK only for an active receipt", async ({ page }) => {
  let acknowledged = false;
  await page.route(/\/api\/deliveries\?.*/, route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      total: 1,
      limit: 25,
      offset: 0,
      entries: [{
        ts: Date.now() / 1000,
        source: "grafana",
        severity: "critical",
        title: "Database unavailable",
        channel: "ntfy",
        suppressed_by: "",
        emergency_receipt_id: "receipt-delivery-e2e",
      }],
    }),
  }));
  await page.route("**/api/emergencies?state=active&limit=500", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ incidents: [{ receipt_id: "receipt-delivery-e2e" }] }),
  }));
  await page.route("**/api/emergencies/receipt-delivery-e2e/ack", route => {
    acknowledged = true;
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
  });

  await page.goto("/deliveries");
  const details = page.locator("[data-delivery-details]");
  await details.focus();
  await details.press("Enter");
  await expect(details).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator(".deliv-detail")).toContainText("receipt-delivery-e2e");

  await page.click("[data-delivery-ack]");
  await page.locator(".app-dialog .primary").click();
  await expect.poll(() => acknowledged).toBe(true);
});
