import { expect, test } from "@playwright/test";
import { assertTablePagerWorks } from "./klaxond-helpers";

test("recent deliveries are paginated", async ({ page, request }) => {
  const real = await request.post("/webhook/warning", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: "DeliveryRealHistoryProbe",
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
      entry.title.includes("DeliveryRealHistoryProbe") && entry.channel.includes("failed")
    );
  }).toBe(true);

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

  await page.goto("/deliveries");
  const pager = page.locator('[data-table-pager="t-deliv"]');
  await expect(pager).toBeVisible();
  await page.selectOption('[data-table-pager="t-deliv"] [data-pager-size]', "10");
  await expect(pager.locator("[data-pager-range]")).toContainText(/1-10 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible").first()).toContainText("DeliveryPaginationProbe31");
  await expect(pager.locator("[data-pager-next]")).toBeEnabled();

  await pager.locator("[data-pager-next]").click();
  await expect(pager.locator("[data-pager-range]")).toContainText(/11-20 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(pager.locator("[data-pager-prev]")).toBeEnabled();
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
  await page.route("**/api/cascade-config", async route => {
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
});
