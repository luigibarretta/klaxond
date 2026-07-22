import { expect, test } from "@playwright/test";
import {
  APP_VERSION, AUTHOR_NAME, AUTHOR_URL, BASIC_AUTH, BASIC_PASSWORD, BASIC_USER, LOCAL_ORIGIN,
  addVirtualAuthenticator, assertTablePagerWorks, createAdminBearer, enableBasicAuth,
  exportConfigBundle, exportConfigBundleWithAuthFallback, requestWithAuthFallback,
  restoreConfigBundle, revealVersionEgg, totp,
} from "./klaxond-helpers";

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
        settings: {
          grafana_base: "https://grafana-e2e.example.test",
          grafana_render_base: "https://render-e2e.example.test",
          grafana_render_token: "render-secret-e2e",
          render_image_ttl: 123,
          public_url: "https://klaxond-e2e.example.test",
          ack_default_ttl: 2345
        },
        component_dashboards: {
          e2e_component: ["E2E dashboard", "/d/e2e-dashboard"]
        }
      }
    });
    await expect(renderUpdate).toBeOK();
    const renderRead = await request.get("/api/render-config");
    await expect(renderRead).toBeOK();
    const renderPayload = await renderRead.json();
    expect(renderPayload.component_dashboards.e2e_component).toEqual(["E2E dashboard", "/d/e2e-dashboard"]);
    expect(renderPayload.settings).toMatchObject({
      grafana_base: "https://grafana-e2e.example.test",
      grafana_render_base: "https://render-e2e.example.test",
      grafana_render_token_configured: true,
      render_image_ttl: 123,
      public_url: "https://klaxond-e2e.example.test",
      ack_default_ttl: 2345
    });

    const channelUpdate = await request.post("/api/channel-config", {
      data: {
        ntfy: { url: "https://push-e2e.example.test" },
        telegram: {
          chat_id: "e2e-chat",
          api_base: "https://telegram-e2e.example.test",
          bot_token: "telegram-secret-e2e"
        },
        smtp: {
          host: "smtp-e2e.example.test",
          port: 2525,
          starttls: false,
          from_addr: "from-e2e@example.test",
          to_addr: "to-e2e@example.test",
          user: "smtp-user-e2e",
          password: "smtp-secret-e2e"
        }
      }
    });
    await expect(channelUpdate).toBeOK();
    const channelRead = await request.get("/api/channel-config");
    await expect(channelRead).toBeOK();
    expect(await channelRead.json()).toMatchObject({
      ntfy: { url: "http://127.0.0.1:9", url_from_env: true },
      telegram: {
        chat_id: "e2e-chat",
        api_base: "https://telegram-e2e.example.test",
        bot_token_configured: true
      },
      smtp: {
        host: "smtp-e2e.example.test",
        port: 2525,
        starttls: false,
        from_addr: "from-e2e@example.test",
        to_addr: "to-e2e@example.test",
        user: "smtp-user-e2e",
        user_configured: true,
        password_configured: true
      }
    });

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
          grafana: {
            enabled: true,
            window_s: 42,
            strategy: "time",
            override_critical: true,
            repeat_suppression_enabled: true,
            repeat_window_s: 7200,
            repeat_override_critical: false,
            rules: [{
              name: "E2E filesystem noise",
              enabled: true,
              field: "label",
              label: "alertname",
              operator: "regex",
              pattern: "^(Disk|Filesystem)",
              case_sensitive: false,
              action: "suppress",
              cooldown_s: 21600,
              include_critical: false
            }]
          }
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
      override_critical: true,
      repeat_suppression_enabled: true,
      repeat_window_s: 7200,
      repeat_override_critical: false,
      rules: [expect.objectContaining({
        name: "E2E filesystem noise",
        field: "label",
        operator: "regex",
        cooldown_s: 21600
      })]
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

    await grafana.locator(".d-mode").selectOption("suppress");
    await grafana.locator(".d-repeat-window").selectOption("21600");
    await page.locator("#dedup-save").click();
    await expect(page.locator(".toast-success").last()).toContainText("Noise controls saved");
    await expect(saveButtons.first()).toBeDisabled();
    await expect(saveButtons.last()).toBeDisabled();

    const saved = await request.get("/api/dedup-config");
    await expect(saved).toBeOK();
    expect((await saved.json()).settings.grafana).toMatchObject({
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

    await page.locator('[data-language-option="it"]').click();
    await expect(page.locator("#tab-grouping h2")).toHaveText("Controllo rumore notifiche");
    await expect(grafana.locator(".d-repeat-window option:checked")).toHaveText("6 ore");
    await expect(selectiveRules.first().locator('[data-rule-field="action"] option:checked')).toHaveText("Invia sempre");

    await page.setViewportSize({ width: 375, height: 812 });
    await page.reload();
    await expect(page.locator(".noise-card")).toHaveCount(8);
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
