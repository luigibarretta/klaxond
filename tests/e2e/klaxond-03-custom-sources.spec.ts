import { expect, test } from "@playwright/test";
import { exportConfigBundle, restoreConfigBundle } from "./klaxond-helpers";

test("custom JSON sources work end-to-end from the routing UI", async ({ page, request }) => {
  const originalBundle = await exportConfigBundle(request);
  const browserErrors: string[] = [];
  page.on("console", message => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", error => browserErrors.push(error.message));

  try {
    await page.goto("/routing");
    await expect(page.locator("#ingest-source-add")).toBeVisible();
    await page.locator("#ingest-source-add").click();
    await page.locator('.app-dialog-overlay input[name="value"]').fill("home-assistant");
    await page.locator(".app-dialog-overlay .btn.primary").click();
    await page.locator('.app-dialog-overlay input[name="value"]').fill("Home Assistant");
    await page.locator(".app-dialog-overlay .btn.primary").click();

    const secretDialog = page.locator(".app-dialog-overlay");
    await expect(secretDialog).toContainText("/ingest/home-assistant/{severity}");
    const secret = await secretDialog.locator("textarea").inputValue();
    expect(secret).toMatch(/^[a-f0-9]{64}$/);
    await secretDialog.locator(".btn.primary").click();

    const sourceRow = page.locator("#t-ingest-auth tr", { hasText: "home-assistant" });
    await expect(sourceRow).toContainText("Home Assistant");
    await expect(sourceRow).toContainText("/ingest/home-assistant/{severity}");

    const ingest = await request.post("/ingest/home-assistant/warning?dry_run=1", {
      headers: { Authorization: `Bearer ${secret}` },
      data: {
        title: "Front door open",
        message: "The entry sensor has remained open",
        labels: { component: "security", host: "home" },
        url: "https://home.example.test"
      }
    });
    await expect(ingest).toBeOK();
    expect(await ingest.json()).toMatchObject({
      dry_run: true,
      source: "home-assistant",
      parsed: {
        title: expect.stringContaining("Home Assistant: Front door open"),
        body: "The entry sensor has remained open"
      }
    });

    const noise = await request.get("/api/dedup-config");
    await expect(noise).toBeOK();
    expect((await noise.json()).sources).toContain("home-assistant");

    await page.goto("/flow");
    await expect(page.locator("#flow-source")).toContainText("SRC_HOME_ASSISTANT");
    await expect(page.locator("#flow-source")).toContainText("POST /ingest/home-assistant/sev");

    await page.goto("/routing");
    await sourceRow.locator('[data-act="remove"]').click();
    await page.locator(".app-dialog-overlay .btn.danger").click();
    await expect(sourceRow).toHaveCount(0);
    const removed = await request.post("/ingest/home-assistant/warning?dry_run=1", {
      headers: { Authorization: `Bearer ${secret}` },
      data: { title: "Must not be accepted" }
    });
    expect(removed.status()).toBe(404);
    expect(browserErrors).toEqual([]);
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});
