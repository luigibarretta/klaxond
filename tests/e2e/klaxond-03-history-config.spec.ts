import { expect, test } from "@playwright/test";
import { exportConfigBundle, restoreConfigBundle } from "./klaxond-helpers";

test("history storage is configurable without exposing credentials or shadowing env owners", async ({ page, request }) => {
  const originalBundle = await exportConfigBundle(request);
  try {
    const initial = await request.get("/api/history-config");
    await expect(initial).toBeOK();
    expect(await initial.json()).toMatchObject({
      settings: {
        backend: "sqlite",
        postgres_url_configured: false,
        retention: 5000,
        default_limit: 500
      },
      managed_fields: {
        backend: "KLAXOND_HISTORY_BACKEND",
        sqlite_path: "KLAXOND_SQLITE_PATH"
      },
      restart_required: false
    });

    const update = await request.post("/api/history-config", {
      data: { retention: 6000, default_limit: 250 }
    });
    await expect(update).toBeOK();
    const afterUpdate = await request.get("/api/history-config");
    expect((await afterUpdate.json()).settings).toMatchObject({ retention: 6000, default_limit: 250 });

    const envConflict = await request.post("/api/history-config", {
      data: { backend: "postgres", postgres_url: "postgres://db.example.test/klaxond" }
    });
    expect(envConflict.status()).toBe(409);
    expect(await envConflict.text()).toContain("KLAXOND_HISTORY_BACKEND");

    const beforeRejected = await exportConfigBundle(request);
    const invalid = await request.post("/api/history-config", { data: { retention: 99 } });
    expect(invalid.status()).toBe(400);
    const afterRejected = await exportConfigBundle(request);
    expect(afterRejected.files["klaxond.toml"]).toBe(beforeRejected.files["klaxond.toml"]);

    await page.goto("/setup");
    await expect(page.locator("#history-backend")).toBeDisabled();
    await expect(page.locator("#history-sqlite-path")).not.toHaveValue("");
    await expect(page.locator("#history-retention")).toHaveValue("6000");
    await page.locator("#history-retention").fill("7000");
    await page.locator("#history-save").click();
    await expect(page.locator(".toast-success").last()).toContainText("History storage configuration saved");
    expect((await (await request.get("/api/history-config")).json()).settings.retention).toBe(7000);
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});
