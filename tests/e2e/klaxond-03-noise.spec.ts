import { expect, test } from "@playwright/test";
import { exportConfigBundle, openSidebar, restoreConfigBundle } from "./klaxond-helpers";

test("noise-control page configures grouping and repeat suppression with human durations", async ({ page, request }) => {
  const originalBundle = await exportConfigBundle(request);
  const browserErrors: string[] = [];
  page.on("console", message => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", error => browserErrors.push(error.message));

  try {
    const update = await request.post("/api/dedup-config", {
      data: {
        settings: {
          grafana: {
            enabled: true,
            window_s: 300,
            strategy: "key",
            override_critical: false,
            repeat_suppression_enabled: true,
            repeat_window_s: 7200,
            repeat_override_critical: false,
            rules: []
          }
        }
      }
    });
    await expect(update).toBeOK();

    await page.goto("/grouping");
    await expect(page.locator("#tab-grouping")).toHaveClass(/active/);
    await expect(page.locator("#tab-grouping h2")).toHaveText("Notification noise control");
    const dedupConfig = await request.get("/api/dedup-config");
    await expect(dedupConfig).toBeOK();
    const configuredSources = (await dedupConfig.json()).sources as string[];
    expect(configuredSources).toContain("uptime-kuma");
    const grafana = page.locator('#dedup-cards [data-src="grafana"]');
    await expect(grafana.locator(".d-mode")).toHaveValue("group_suppress");
    await expect(grafana.locator(".d-window")).toHaveValue("300");
    await expect(grafana.locator(".d-repeat-window")).toHaveValue("7200");
    await expect(grafana.locator(".d-repeat-window option:checked")).toHaveText("2 hours");
    const selectiveRules = page.locator("#dedup-rules [data-noise-rule]");
    const saveButtons = page.locator("[data-dedup-save]");
    await expect(selectiveRules).toHaveCount(0);
    await expect(page.locator(".noise-rules-empty")).toBeVisible();
    await expect(page.locator("#t-repeat-suppressed")).toBeVisible();
    await expect(saveButtons).toHaveCount(2);
    await expect(saveButtons.first()).toBeDisabled();
    await expect(saveButtons.last()).toBeDisabled();

    await page.locator("#dedup-rule-add").click();
    await expect(saveButtons.first()).toBeEnabled();
    await expect(saveButtons.last()).toBeEnabled();
    const suppressRule = selectiveRules.last();
    await suppressRule.locator('[data-rule-field="name"]').fill("Filesystem repeats");
    await suppressRule.locator('[data-rule-field="pattern"]').fill("filesystem");
    await page.locator("#dedup-rule-add").click();
    const bypassRule = selectiveRules.last();
    await bypassRule.locator('[data-rule-field="name"]').fill("Never suppress database alerts");
    await bypassRule.locator('[data-rule-field="field"]').selectOption("label");
    await expect(bypassRule.locator("[data-rule-label-name]")).toBeVisible();
    await bypassRule.locator('[data-rule-field="label"]').fill("alertname");
    await bypassRule.locator('[data-rule-field="operator"]').selectOption("regex");
    await bypassRule.locator('[data-rule-field="pattern"]').fill("^Database.*");
    await bypassRule.locator('[data-rule-field="action"]').selectOption("bypass");
    await expect(bypassRule.locator("[data-rule-cooldown]")).toBeHidden();
    await bypassRule.locator('[data-rule-action="up"]').click();
    await expect(selectiveRules.first().locator('[data-rule-field="name"]')).toHaveValue("Never suppress database alerts");

    await page.locator("#dedup-rule-add").click();
    const uptimeRule = selectiveRules.last();
    await uptimeRule.locator('[data-rule-field="source"]').selectOption("uptime-kuma");
    await uptimeRule.locator('[data-rule-field="name"]').fill("Repeat Kuma certificate reminder");
    await uptimeRule.locator('[data-rule-field="pattern"]').fill("certificate");

    await grafana.locator(".d-mode").selectOption("suppress");
    await grafana.locator(".d-repeat-window").selectOption("21600");
    await page.locator("#dedup-save").click();
    await expect(page.locator(".toast-success").last()).toContainText("Noise controls saved");
    await expect(saveButtons.first()).toBeDisabled();
    await expect(saveButtons.last()).toBeDisabled();

    const saved = await request.get("/api/dedup-config");
    await expect(saved).toBeOK();
    const savedSettings = (await saved.json()).settings;
    expect(savedSettings.grafana).toMatchObject({
      enabled: false,
      strategy: "none",
      repeat_suppression_enabled: true,
      repeat_window_s: 21600,
      rules: [
        expect.objectContaining({
          name: "Never suppress database alerts",
          field: "label",
          label: "alertname",
          operator: "regex",
          pattern: "^Database.*",
          action: "bypass"
        }),
        expect.objectContaining({ name: "Filesystem repeats", action: "suppress", cooldown_s: 7200 })
      ]
    });
    expect(savedSettings["uptime-kuma"]).toMatchObject({
      rules: [expect.objectContaining({
        name: "Repeat Kuma certificate reminder",
        pattern: "certificate",
        action: "suppress",
        cooldown_s: 7200
      })]
    });

    await openSidebar(page);
    await page.locator('[data-language-option="it"]').click();
    await expect(page.locator("#tab-grouping h2")).toHaveText("Controllo rumore notifiche");
    await expect(grafana.locator(".d-repeat-window option:checked")).toHaveText("6 ore");
    await expect(selectiveRules.first().locator('[data-rule-field="action"] option:checked')).toHaveText("Invia sempre");

    await page.setViewportSize({ width: 375, height: 812 });
    await page.reload();
    await expect(page.locator(".noise-card")).toHaveCount(configuredSources.length);
    const layout = await page.evaluate(() => ({
      viewport: window.innerWidth,
      body: document.documentElement.scrollWidth,
      cardsFit: [...document.querySelectorAll<HTMLElement>(".noise-card, .noise-rule")]
        .every(card => card.getBoundingClientRect().right <= window.innerWidth + 1)
    }));
    expect(layout.body).toBeLessThanOrEqual(layout.viewport);
    expect(layout.cardsFit).toBe(true);
    expect(browserErrors).toEqual([]);
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});
