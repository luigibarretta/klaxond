import { expect, test } from "@playwright/test";

test("serves health and admin UI", async ({ page, request }) => {
  const health = await request.get("/healthz");
  await expect(health).toBeOK();
  expect(await health.text()).toBe("OK");

  await page.goto("/ui/");
  await expect(page).toHaveURL(/\/ui\/index\.html$/);
  await expect(page.locator("h1")).toContainText("klaxond");
  await expect(page.locator('[data-tab="status"]')).toBeVisible();
  await expect(page.locator('[data-tab="logs"]')).toBeVisible();
  await expect(page.locator('[data-tab="preview"]')).toBeVisible();
  await expect(page.locator("#sidebar-user-card")).toBeVisible();
  await page.click("#sidebar-toggle");
  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await page.click("#sidebar-toggle");
  await expect(page.locator("body")).not.toHaveClass(/sidebar-collapsed/);
  await expect(page.locator("#footer-version")).toContainText(/^v0\.\d+\./);
  await expect(page.locator("#stat-log-retained")).toContainText(/\/500/);
  await expect(page.locator("#stat-log-severity")).toContainText(/WARN \d+ \/ ERROR \d+/);
});

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

  await page.goto("/ui/index.html#logs");
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

  await page.goto("/ui/index.html#logs");
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

test("recent deliveries are paginated", async ({ page, request }) => {
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

  await page.goto("/ui/index.html#deliveries");
  const pager = page.locator('[data-table-pager="t-deliv"]');
  await expect(pager).toBeVisible();
  await page.selectOption('[data-table-pager="t-deliv"] [data-pager-size]', "10");
  await expect(pager.locator("[data-pager-range]")).toContainText(/1-10 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(pager.locator("[data-pager-next]")).toBeEnabled();

  await pager.locator("[data-pager-next]").click();
  await expect(pager.locator("[data-pager-range]")).toContainText(/11-20 \/ \d+/);
  await expect(page.locator("#t-deliv tbody tr.deliv-row:visible")).toHaveCount(10);
  await expect(pager.locator("[data-pager-prev]")).toBeEnabled();
});

test("backend logs fetch failure clears stale count", async ({ page }) => {
  await page.goto("/ui/index.html#logs");
  await expect(page.locator("#logs-count")).toContainText(/log line/);

  await page.route(/\/api\/logs\?/, async route => {
    await route.fulfill({ status: 500, body: "forced logs failure" });
  });

  await page.click("#logs-refresh");
  await expect(page.locator("#t-logs tbody tr").first()).toContainText("500 Internal Server Error");
  await expect(page.locator("#logs-count")).toHaveText("");
});

test("save errors show both inline status and toast", async ({ page }) => {
  await page.route("**/api/render-config", async route => {
    if (route.request().method() === "POST") {
      await route.fulfill({ status: 500, body: "forced render-config failure" });
      return;
    }
    await route.continue();
  });

  await page.goto("/ui/index.html#render");
  await page.click("#btn-rc-save");
  await expect(page.locator("#rc-status")).toContainText("500");
  await expect(page.locator(".toast-error")).toContainText("render-config-save");
});

test("inhibition applies-to checkboxes stay compact and aligned", async ({ page }) => {
  await page.goto("/ui/index.html#inhibitions");
  const firstCheckbox = page.locator('#t-inhib-rules [data-k="applies_to"] input[type="checkbox"]').first();
  await expect(firstCheckbox).toBeVisible();

  const box = await firstCheckbox.boundingBox();
  expect(box?.width).toBeLessThanOrEqual(20);
  await expect(firstCheckbox.locator("xpath=..")).toHaveCSS("align-items", "center");
});

test("supports Italian and English plus system/light/dark theme modes", async ({ page }) => {
  await page.goto("/healthz");
  await page.evaluate(() => {
    localStorage.setItem("klaxond.theme", "light");
    localStorage.removeItem("klaxond.themeMode");
  });

  await page.goto("/ui/");
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("#gbase")).toHaveText("https://grafana.luigibarretta.com");

  await page.selectOption("#language-select", "it");
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await expect(page.locator('[data-tab="status"]')).toHaveText("Stato");
  await expect(page.locator('[data-tab="deliveries"]')).toContainText("Consegne recenti");
  await expect(page).toHaveTitle(/demone notifiche/);
  await expect(page.locator("#gbase")).toHaveText("https://grafana.luigibarretta.com");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.lang"))).toBe("it");

  await page.selectOption("#theme-mode", "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await page.selectOption("#theme-mode", "dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.themeMode"))).toBe("dark");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("klaxond.theme"))).toBeNull();

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await expect(page.locator('[data-tab="status"]')).toHaveText("Stato");
  await expect(page.locator("#theme-mode")).toHaveValue("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.selectOption("#theme-mode", "system");
  await expect(page.locator("html")).toHaveAttribute("data-theme-mode", "system");
  await expect(page.locator("html")).toHaveAttribute("data-theme", /^(light|dark)$/);

  await page.selectOption("#language-select", "en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.locator('[data-tab="status"]')).toHaveText("Status");
});

test("render-preview returns ntfy-compatible headers without delivery", async ({ request }) => {
  const res = await request.post("/api/render-preview", {
    data: {
      severity: "critical",
      payload: {
        status: "firing",
        commonLabels: {
          alertname: "HostLoadHigh",
          component: "host",
          host: "it1-prd-dev-01"
        },
        commonAnnotations: {
          summary: "load average above threshold"
        },
        alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
      }
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.url).toBe("http://127.0.0.1:9/critical-topic");
  expect(body.headers["Title (raw)"]).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
  expect(body.headers.Tags).toBe("rotating_light,critical,grafana,host");
  expect(body.headers.Priority).toBe("urgent");
});

test("webhook dry-run exercises ingest pipeline without sending", async ({ request }) => {
  const res = await request.post("/webhook/critical?dry_run=1", {
    headers: { Authorization: "bearer e2e-secret" },
    data: {
      status: "firing",
      commonLabels: {
        alertname: "HostLoadHigh",
        component: "host",
        host: "it1-prd-dev-01"
      },
      commonAnnotations: {
        summary: "load average above threshold"
      },
      alerts: [{ generatorURL: "https://grafana.example/rule/1" }]
    }
  });

  await expect(res).toBeOK();
  const body = await res.json();
  expect(body.dry_run).toBe(true);
  expect(body.would_send).toBe(true);
  expect(body.source).toBe("grafana");
  expect(body.severity).toBe("critical");
  expect(body.parsed.title).toBe("🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
});

test("inhibition rule simulator reports source and suppression matches", async ({ request }) => {
  const source = await request.post("/api/inhibition-rules/test", {
    data: {
      source: "grafana",
      labels: { alertname: "NodeDown", inhibition_source: "node-down", host: "dev-01" }
    }
  });
  await expect(source).toBeOK();
  expect(await source.json()).toMatchObject({
    would_send: true,
    reason: "source",
    matched_rule: "node-down",
    would_arm_suppression: true
  });
});

test("full config export includes TOML sidecars and runtime settings", async ({ page, request }) => {
  await page.goto("/ui/index.html#status");
  await expect(page.locator("#cfg-backup-download")).toHaveAttribute("href", "/api/config/backup");
  await expect(page.locator("#cfg-full-export-download")).toHaveAttribute("href", "/api/config/export");

  const exported = await request.get("/api/config/export");
  await expect(exported).toBeOK();
  expect(exported.headers()["content-type"]).toContain("application/json");
  expect(exported.headers()["content-disposition"]).toContain("klaxond-full-settings-");

  const bundle = await exported.json();
  expect(bundle).toMatchObject({
    kind: "klaxond.full-settings",
    format_version: 1,
    includes_secrets: true,
    files_are_effective: true
  });
  expect(Object.keys(bundle.files)).toEqual(expect.arrayContaining([
    "klaxond.toml",
    "render-config.json",
    "ntfy-topics.json",
    "dedup-config.json",
    "auth-config.json"
  ]));
  expect(JSON.parse(bundle.files["render-config.json"]).component_dashboards).toBeTruthy();
  expect(JSON.parse(bundle.files["ntfy-topics.json"]).topics.length).toBeGreaterThan(0);
  expect(bundle.effective_runtime).toHaveProperty("telegram");
  expect(bundle.effective_runtime).toHaveProperty("smtp");
  expect(bundle.effective_runtime).toHaveProperty("grafana");

  const restored = await request.post("/api/config/restore", {
    data: JSON.stringify(bundle),
    headers: { "Content-Type": "application/json" }
  });
  await expect(restored).toBeOK();
  expect(await restored.json()).toMatchObject({
    ok: true,
    source_kind: "full-bundle",
    restored_sidecars: [
      "render-config.json",
      "ntfy-topics.json",
      "dedup-config.json",
      "auth-config.json"
    ]
  });
});

test("backend logs require admin auth when auth is enabled", async ({ request }) => {
  const unsafeBasic = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "basic",
        basic: { username: "admin" }
      }
    }
  });
  expect(unsafeBasic.status()).toBe(400);
  expect(await unsafeBasic.text()).toContain("password");

  const unsafeOidc = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "oidc",
        oidc: {
          issuer: "https://idp.example.test",
          client_id: "klaxond",
          redirect_path: "/custom/callback"
        }
      }
    }
  });
  expect(unsafeOidc.status()).toBe(400);
  expect(await unsafeOidc.text()).toContain("/auth/callback");

  const unsafeTrustedProxy = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "trusted-proxy",
        trusted_proxy: {
          user_header: "X-Forwarded-User",
          trusted_cidrs: ["127.0.0.1/32"]
        }
      }
    }
  });
  expect(unsafeTrustedProxy.status()).toBe(400);
  expect(await unsafeTrustedProxy.text()).toContain("X-Forwarded-User");

  const scopedToken = await request.post("/api/auth/tokens", {
    data: {
      name: "logs-reader",
      kind: "pat",
      scopes: ["logs:read"]
    }
  });
  await expect(scopedToken).toBeOK();
  const scopedPayload = await scopedToken.json();
  expect(scopedPayload.token).toMatch(/^klx_pat_/);
  expect(JSON.stringify(scopedPayload.record)).not.toContain("token_hash");

  const wrongToken = await request.post("/api/auth/tokens", {
    data: {
      name: "status-only",
      kind: "api-key",
      scopes: ["status:read"]
    }
  });
  await expect(wrongToken).toBeOK();
  const wrongPayload = await wrongToken.json();

  const update = await request.post("/api/auth-config", {
    data: {
      settings: {
        mode: "basic",
        basic: {
          username: "admin",
          password: "test-password"
        }
      }
    }
  });
  await expect(update).toBeOK();
  const updatedAuth = await update.json();
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("token_hash");
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("credential");

  const denied = await request.get("/api/logs?limit=1");
  expect(denied.status()).toBe(401);
  expect(denied.headers()["www-authenticate"]).toContain("Basic");

  const token = Buffer.from("admin:test-password").toString("base64");
  const allowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Basic ${token}` }
  });
  await expect(allowed).toBeOK();

  const bearerAllowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${scopedPayload.token}` }
  });
  await expect(bearerAllowed).toBeOK();

  const bearerDenied = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${wrongPayload.token}` }
  });
  expect(bearerDenied.status()).toBe(403);
});
