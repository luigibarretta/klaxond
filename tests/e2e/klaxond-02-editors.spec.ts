import { expect, test } from "@playwright/test";

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
