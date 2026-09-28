import { expect, test } from "@playwright/test";

test("authentication separates configuration drafts from operational actions", async ({ page }) => {
  await page.goto("/authentication");
  const save = page.locator("#auth-save");
  await expect(save).toBeDisabled();
  await expect(page.locator("#auth-dirty-status")).toHaveText("No unsaved changes");

  await page.locator("#token-name").fill("automation-token-draft");
  await expect(save).toBeDisabled();

  const sessionHours = page.locator("#auth-session-h");
  const original = await sessionHours.inputValue();
  await sessionHours.fill(original === "8" ? "9" : "8");
  await expect(save).toBeEnabled();
  await expect(page.locator("#auth-dirty-status")).toContainText("1 section");

  await page.locator("#auth-discard").click();
  await page.locator(".app-dialog .danger").click();
  await expect(sessionHours).toHaveValue(original);
  await expect(save).toBeDisabled();

  await page.getByRole("button", { name: "MFA / step-up", exact: true }).click();
  await expect(page.locator("#auth-mfa-section")).toBeFocused();
});

test("routing tracks channel and topic drafts independently", async ({ page }) => {
  await page.route("**/api/ntfy-topics", async route => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    const body = route.request().postDataJSON() as { topics: Array<{ handles?: string[] }> };
    const knownSeverities = [...new Set(body.topics.flatMap(topic => topic.handles || []))];
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        topics: body.topics,
        known_severities: knownSeverities,
        note: "",
        writeable: true,
      }),
    });
  });

  await page.goto("/routing");
  const saveAll = page.locator("#routing-save-all");
  const saveChannels = page.locator("#btn-routing-save");
  const saveTopics = page.locator("#ntfy-topics-save");
  await expect(saveAll).toBeDisabled();
  await expect(saveChannels).toBeDisabled();
  await expect(saveTopics).toBeDisabled();

  const ntfyUrl = page.locator("#r-ntfy-url");
  const originalUrl = await ntfyUrl.inputValue();
  const draftUrl = `${originalUrl || "https://ntfy.example.test"}/draft`;
  await ntfyUrl.fill(draftUrl);
  await expect(saveChannels).toBeEnabled();
  await expect(saveTopics).toBeDisabled();

  await page.locator('.tab[data-tab="routing"]').click();
  await expect(ntfyUrl).toHaveValue(draftUrl);
  await expect(saveChannels).toBeEnabled();

  const handles = page.locator(".ntfy-t-handles").first();
  await expect(handles).toBeVisible();
  await handles.fill(`${await handles.inputValue()}, e2e-draft`);
  await expect(saveTopics).toBeEnabled();
  await expect(page.locator("#routing-dirty-status")).toContainText("2 section");

  await saveTopics.click();
  await expect(saveTopics).toBeDisabled();
  await expect(saveChannels).toBeEnabled();
  await expect(saveAll).toBeEnabled();
  await expect(page.locator("#routing-dirty-status")).toContainText("1 section");

  await page.locator("#routing-discard").click();
  await page.locator(".app-dialog .danger").click();
  await expect(ntfyUrl).toHaveValue(originalUrl);
  await expect(saveAll).toBeDisabled();
  await expect(saveChannels).toBeDisabled();

  await page.getByRole("button", { name: "Inbound sources", exact: true }).click();
  await expect(page.locator("#routing-ingest-section")).toBeFocused();

  await ntfyUrl.fill(draftUrl);
  await page.locator('.tab[data-tab="status"]').click();
  await page.locator(".app-dialog .danger").click();
  await expect(page).toHaveURL(/\/status$/);
  await page.locator('.tab[data-tab="routing"]').click();
  await expect(ntfyUrl).toHaveValue(originalUrl);
  await expect(saveChannels).toBeDisabled();
});

test("settings saves keep edits made while requests are in flight", async ({ page }) => {
  let authSaveCount = 0;
  let releaseAuthSave = () => {};
  let authSaveStarted = () => {};
  const authStarted = new Promise<void>(resolve => { authSaveStarted = resolve; });
  const authReleased = new Promise<void>(resolve => { releaseAuthSave = resolve; });
  await page.route("**/api/auth/config", async route => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    authSaveCount += 1;
    authSaveStarted();
    await authReleased;
    const body = route.request().postDataJSON() as { settings: Record<string, unknown> };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ok: true, settings: body.settings }),
    });
  });

  await page.goto("/authentication");
  const sessionHours = page.locator("#auth-session-h");
  await sessionHours.fill("9");
  await page.locator("#auth-save").click();
  await authStarted;
  await sessionHours.fill("10");
  await expect(page.locator("#auth-save")).toBeDisabled();
  await page.keyboard.press("Control+s");
  await page.waitForTimeout(100);
  expect(authSaveCount).toBe(1);
  releaseAuthSave();
  await expect(page.locator("#auth-status")).toContainText("Newer edits are still pending");
  await expect(sessionHours).toHaveValue("10");
  await expect(page.locator("#auth-save")).toBeEnabled();
  await page.locator("#auth-save").click();
  await expect.poll(() => authSaveCount).toBe(2);
  await expect(page.locator("#auth-save")).toBeDisabled();

  let routingSaveCount = 0;
  let releaseRoutingSave = () => {};
  let routingSaveStarted = () => {};
  const routingStarted = new Promise<void>(resolve => { routingSaveStarted = resolve; });
  const routingReleased = new Promise<void>(resolve => { releaseRoutingSave = resolve; });
  await page.route("**/api/channel-config", async route => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    routingSaveCount += 1;
    routingSaveStarted();
    await routingReleased;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
  });
  let topicsSaveCount = 0;
  let releaseTopicsSave = () => {};
  let topicsSaveStarted = () => {};
  const topicsStarted = new Promise<void>(resolve => { topicsSaveStarted = resolve; });
  const topicsReleased = new Promise<void>(resolve => { releaseTopicsSave = resolve; });
  await page.route("**/api/ntfy-topics", async route => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    topicsSaveCount += 1;
    topicsSaveStarted();
    await topicsReleased;
    const body = route.request().postDataJSON() as { topics: Array<{ handles?: string[] }> };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        topics: body.topics,
        known_severities: [...new Set(body.topics.flatMap(topic => topic.handles || []))],
        note: "",
        writeable: true,
      }),
    });
  });

  await page.goto("/routing");
  const topicName = page.locator(".ntfy-t-name").first();
  const originalTopicName = await topicName.inputValue();
  await page.locator(".ntfy-t-handles").first().fill("info, submitted");
  await page.locator("#ntfy-topics-save").click();
  await topicsStarted;
  await topicName.fill(`${originalTopicName}-newer`);
  await expect(page.locator("#ntfy-topics-save")).toBeDisabled();
  await page.locator("#ntfy-topics-save").evaluate((button: HTMLButtonElement) => {
    button.disabled = false;
    button.click();
  });
  await page.waitForTimeout(100);
  expect(topicsSaveCount).toBe(1);
  releaseTopicsSave();
  await expect(page.locator("#ntfy-topics-status")).toContainText("Newer edits are still pending");
  await expect(topicName).toHaveValue(`${originalTopicName}-newer`);
  await expect(page.locator("#ntfy-topics-save")).toBeEnabled();

  const ntfyUrl = page.locator("#r-ntfy-url");
  await ntfyUrl.fill("https://ntfy.example.test/submitted");
  await page.locator("#btn-routing-save").click();
  await routingStarted;
  await ntfyUrl.fill("https://ntfy.example.test/newer");
  await expect(page.locator("#btn-routing-save")).toBeDisabled();
  await page.locator("#btn-routing-save").evaluate((button: HTMLButtonElement) => {
    button.disabled = false;
    button.click();
  });
  await page.waitForTimeout(100);
  expect(routingSaveCount).toBe(1);
  releaseRoutingSave();
  await expect(page.locator("#routing-msg")).toContainText("Newer edits are still pending");
  await expect(ntfyUrl).toHaveValue("https://ntfy.example.test/newer");
  await expect(page.locator("#btn-routing-save")).toBeEnabled();
});

test("topic structural edits preserve the current draft", async ({ page }) => {
  await page.goto("/routing");
  const firstName = page.locator(".ntfy-t-name").first();
  await firstName.fill("edited-before-structure-change");

  await page.locator("#ntfy-topic-add").click();
  await expect(firstName).toHaveValue("edited-before-structure-change");

  await page.locator(".ntfy-t-delete").last().click();
  await expect(firstName).toHaveValue("edited-before-structure-change");
  await expect(page.locator("#ntfy-topics-save")).toBeEnabled();
});

test("clean settings shortcuts never trigger operational actions", async ({ page }) => {
  const operationalMutations: string[] = [];
  page.on("request", request => {
    if (request.method() === "GET") return;
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/auth/totp") || path === "/api/auth/tokens" || path === "/api/ingest-auth") {
      operationalMutations.push(path);
    }
  });

  await page.goto("/authentication");
  await page.keyboard.press("Control+s");
  await expect(page.locator(".app-dialog")).toHaveCount(0);
  await page.waitForTimeout(100);
  expect(operationalMutations).toEqual([]);

  await page.goto("/routing");
  await page.keyboard.press("Control+s");
  await expect(page.locator(".app-dialog")).toHaveCount(0);
  await page.waitForTimeout(100);
  expect(operationalMutations).toEqual([]);
});

test("mobile section navigation reveals headings below sticky actions", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/authentication");
  await page.getByRole("button", { name: "Access tokens", exact: true }).click();
  await expect(page.locator("#auth-tokens-section")).toBeFocused();
  await expect.poll(async () => {
    const actions = await page.locator("#tab-auth .settings-actions").boundingBox();
    const heading = await page.locator("#auth-tokens-section").boundingBox();
    return actions && heading ? Math.floor(heading.y - (actions.y + actions.height)) : -1;
  }).toBeGreaterThanOrEqual(8);

  await page.goto("/routing");
  await page.getByRole("button", { name: "Inbound sources", exact: true }).click();
  await expect(page.locator("#routing-ingest-section")).toBeFocused();
  await expect.poll(async () => {
    const actions = await page.locator("#tab-routing .settings-actions").boundingBox();
    const heading = await page.locator("#routing-ingest-section").boundingBox();
    return actions && heading ? Math.floor(heading.y - (actions.y + actions.height)) : -1;
  }).toBeGreaterThanOrEqual(8);
});
