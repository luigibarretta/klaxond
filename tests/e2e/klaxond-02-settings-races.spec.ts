import { expect, test } from "@playwright/test";
import { clickSidebarTab } from "./klaxond-helpers";

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test("late settings reloads preserve edits made after the request started", async ({ page }) => {
  await page.goto("/status");
  const authStarted = deferred();
  const releaseAuth = deferred();
  const authCompleted = deferred();
  await page.route("**/api/auth/config", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    authStarted.resolve();
    await releaseAuth.promise;
    await route.fulfill({ response: await route.fetch() });
    authCompleted.resolve();
  });

  await page.evaluate(() => (window as any).activateTab("auth"));
  await authStarted.promise;
  const sessionHours = page.locator("#auth-session-h");
  await sessionHours.fill("11");
  releaseAuth.resolve();
  await authCompleted.promise;
  await page.waitForTimeout(100);
  await expect(sessionHours).toHaveValue("11");
  await expect(page.locator("#auth-save")).toBeEnabled();

  await page.unroute("**/api/auth/config");
  await page.goto("/routing");
  await expect(page.locator(".ntfy-t-name").first()).toBeVisible();
  await page.evaluate(() => (window as any).KlaxondQuery.invalidate());

  const channelsStarted = deferred();
  const topicsStarted = deferred();
  const releaseRouting = deferred();
  const channelsCompleted = deferred();
  const topicsCompleted = deferred();
  await page.route("**/api/channel-config", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    channelsStarted.resolve();
    await releaseRouting.promise;
    await route.fulfill({ response: await route.fetch() });
    channelsCompleted.resolve();
  });
  await page.route("**/api/ntfy-topics", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    topicsStarted.resolve();
    await releaseRouting.promise;
    await route.fulfill({ response: await route.fetch() });
    topicsCompleted.resolve();
  });

  await page.evaluate(() => (window as any).activateTab("status"));
  await page.evaluate(() => (window as any).activateTab("routing"));
  await Promise.all([channelsStarted.promise, topicsStarted.promise]);
  const ntfyUrl = page.locator("#r-ntfy-url");
  const topicName = page.locator(".ntfy-t-name").first();
  await ntfyUrl.fill("https://ntfy.example.test/late-draft");
  await topicName.fill("late-topic-draft");
  releaseRouting.resolve();
  await Promise.all([channelsCompleted.promise, topicsCompleted.promise]);
  await page.waitForTimeout(100);

  await expect(ntfyUrl).toHaveValue("https://ntfy.example.test/late-draft");
  await expect(topicName).toHaveValue("late-topic-draft");
  await expect(page.locator("#btn-routing-save")).toBeEnabled();
  await expect(page.locator("#ntfy-topics-save")).toBeEnabled();
});

test("inventory and discard reloads preserve newer authentication edits", async ({ page }) => {
  await page.goto("/authentication");
  const sessionHours = page.locator("#auth-session-h");
  await sessionHours.fill("9");

  await page.route("**/api/auth/tokens", async route => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ token: "klx_test_once" }),
      });
      return;
    }
    await route.continue();
  });
  const inventoryStarted = deferred();
  const releaseInventory = deferred();
  const inventoryCompleted = deferred();
  await page.route("**/api/auth/config", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    inventoryStarted.resolve();
    await releaseInventory.promise;
    await route.fulfill({ response: await route.fetch() });
    inventoryCompleted.resolve();
  });

  await page.locator("#token-name").fill("inventory-race");
  await page.locator("#token-create").click();
  await inventoryStarted.promise;
  await sessionHours.fill("10");
  releaseInventory.resolve();
  await inventoryCompleted.promise;
  await page.waitForTimeout(100);
  await expect(sessionHours).toHaveValue("10");
  await expect(page.locator("#auth-save")).toBeEnabled();

  await page.unroute("**/api/auth/config");
  const discardStarted = deferred();
  const releaseDiscard = deferred();
  const discardCompleted = deferred();
  await page.route("**/api/auth/config", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    discardStarted.resolve();
    await releaseDiscard.promise;
    await route.fulfill({ response: await route.fetch() });
    discardCompleted.resolve();
  });

  await page.locator("#auth-discard").click();
  await page.locator(".app-dialog .danger").click();
  await discardStarted.promise;
  await sessionHours.fill("12");
  releaseDiscard.resolve();
  await discardCompleted.promise;
  await page.waitForTimeout(100);
  await expect(sessionHours).toHaveValue("12");
  await expect(page.locator("#auth-save")).toBeEnabled();
});

test("discarding navigation invalidates unsent Save All steps", async ({ page }) => {
  let topicsSaveCount = 0;
  const channelsStarted = deferred();
  const releaseChannels = deferred();
  await page.route("**/api/channel-config", async route => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    channelsStarted.resolve();
    await releaseChannels.promise;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
  });
  await page.route("**/api/ntfy-topics", async route => {
    if (route.request().method() === "POST") topicsSaveCount += 1;
    await route.continue();
  });

  await page.goto("/routing");
  await page.locator("#r-ntfy-url").fill("https://ntfy.example.test/save-all");
  await page.locator(".ntfy-t-handles").first().fill("info, queued-topic");
  await page.locator("#routing-save-all").click();
  await channelsStarted.promise;
  await expect(page.locator("#ntfy-topics-save")).toBeDisabled();
  await page.locator("#ntfy-topics-save").evaluate((button: HTMLButtonElement) => {
    button.disabled = false;
    button.click();
  });
  await page.waitForTimeout(100);
  expect(topicsSaveCount).toBe(0);

  await clickSidebarTab(page, "status");
  await page.locator(".app-dialog .danger").click();
  await expect(page).toHaveURL(/\/status$/);
  releaseChannels.resolve();
  await page.waitForTimeout(200);
  expect(topicsSaveCount).toBe(0);
});

test("a pre-mutation GET cannot repopulate routing cache with stale data", async ({ page }) => {
  await page.goto("/routing");
  await page.evaluate(() => (window as any).KlaxondQuery.invalidate());

  const staleCaptured = deferred();
  const releaseStale = deferred();
  const freshGetSeen = deferred();
  const savePosted = deferred();
  let firstGet = true;
  let staleConfig: any = null;
  let savedConfig: any = null;
  await page.route("**/api/channel-config", async route => {
    const method = route.request().method();
    if (method === "POST") {
      const body = route.request().postDataJSON() as any;
      savedConfig = {
        ...staleConfig,
        ntfy: { ...staleConfig.ntfy, ...body.ntfy },
        telegram: { ...staleConfig.telegram, ...body.telegram },
        smtp: { ...staleConfig.smtp, ...body.smtp },
      };
      savePosted.resolve();
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
      return;
    }
    if (method !== "GET") {
      await route.continue();
      return;
    }
    if (firstGet) {
      firstGet = false;
      const response = await route.fetch();
      staleConfig = await response.json();
      staleCaptured.resolve();
      await releaseStale.promise;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(staleConfig) });
      return;
    }
    freshGetSeen.resolve();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(savedConfig || staleConfig),
    });
  });

  await page.evaluate(() => (window as any).activateTab("status"));
  await page.evaluate(() => (window as any).activateTab("routing"));
  await staleCaptured.promise;
  const savedUrl = "https://ntfy.example.test/cache-generation";
  await page.locator("#r-ntfy-url").fill(savedUrl);
  await page.locator("#btn-routing-save").click();
  await savePosted.promise;
  await expect(page.locator("#btn-routing-save")).toBeDisabled();

  releaseStale.resolve();
  await freshGetSeen.promise;
  await page.evaluate(() => (window as any).activateTab("status"));
  await page.evaluate(() => (window as any).activateTab("routing"));
  await expect(page.locator("#r-ntfy-url")).toHaveValue(savedUrl);
  await expect(page.locator("#btn-routing-save")).toBeDisabled();
});

test("passkey pagination does not dirty authentication configuration", async ({ page }) => {
  await page.route("**/api/auth/config", async route => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    body.settings.passkeys = Array.from({ length: 11 }, (_, index) => ({
      id: `passkey-${index}`,
      name: `Test passkey ${index + 1}`,
      user_name: "e2e-user",
      created_at: 1_700_000_000 + index,
      last_used_at: null,
    }));
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });

  await page.goto("/authentication");
  const pager = page.locator('[data-table-pager="t-passkeys"]');
  await expect(pager).toBeVisible();
  await pager.locator("[data-pager-size]").selectOption("25");
  await expect(page.locator("#auth-save")).toBeDisabled();
  await expect(page.locator("#auth-discard")).toBeDisabled();
  await expect(page.locator("#auth-dirty-status")).toHaveText("No unsaved changes");
});
