import { expect, test } from "@playwright/test";
import { exportConfigBundle, restoreConfigBundle } from "./klaxond-helpers";

test("emergency policy updates are partial, validated and transactional", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);
  try {
    const update = await request.post("/api/emergency-config", {
      data: {
        enabled: false,
        fallback_profile: "page",
        profiles: [{
          id: "PAGE",
          name: "Page operator",
          enabled: true,
          priority: 200,
          severities: [" Critical ", "critical", "PAGE"],
          sources: ["grafana"],
          match: { team: "platform" },
          retry_seconds: 75,
          expire_seconds: 3600,
          max_attempts: 20,
          lease_seconds: 60,
          telegram: { enabled: true, after_attempts: 3 },
          smtp: { enabled: false, after_attempts: 5 },
          notify_on_expiry: true,
          auto_resolve: true
        }],
        exclude_sources: [" API-Test ", "maintenance"]
      }
    });
    await expect(update).toBeOK();

    const read = await request.get("/api/emergency-config");
    await expect(read).toBeOK();
    expect(await read.json()).toMatchObject({
      settings: {
        enabled: false,
        fallback_profile: "page",
        profiles: [expect.objectContaining({
          id: "page",
          severities: ["critical", "page"],
          sources: ["grafana"],
          match: { team: "platform" },
          retry_seconds: 75,
          max_attempts: 20,
          telegram: { enabled: true, after_attempts: 3 },
          smtp: { enabled: false, after_attempts: 5 }
        })],
        exclude_sources: ["api-test", "maintenance"]
      },
      managed_fields: {},
      managed_by_environment: false,
      source_of_truth: "ui",
      writeable: true
    });

    const beforeRejected = await exportConfigBundle(request);
    const invalid = await request.post("/api/emergency-config", {
      data: {
        profiles: [{
          id: "page", name: "Page operator", enabled: true, priority: 200,
          severities: ["page"], sources: [], match: {},
          retry_seconds: 300, expire_seconds: 60, max_attempts: 20,
          lease_seconds: 60,
          telegram: { enabled: true, after_attempts: 3 },
          smtp: { enabled: false, after_attempts: 5 },
          notify_on_expiry: true, auto_resolve: true
        }]
      }
    });
    expect(invalid.status()).toBe(400);
    expect(await invalid.text()).toContain("expiry");
    const afterRejected = await exportConfigBundle(request);
    expect(afterRejected.files["klaxond.toml"]).toBe(beforeRejected.files["klaxond.toml"]);

    const unknown = await request.post("/api/emergency-config", {
      data: { enabled: false, unexpected: true }
    });
    expect(unknown.status()).toBe(400);
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});

test("policy simulator selects the emergency fallback without creating a receipt", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);
  try {
    const enable = await request.post("/api/emergency-config", {
      data: {
        enabled: true,
        allow_insecure_public_url: true,
        allow_ntfy_only: true
      }
    });
    await expect(enable).toBeOK();

    const beforeResponse = await request.get("/api/emergencies?state=active&limit=1000");
    await expect(beforeResponse).toBeOK();
    const before = (await beforeResponse.json()).incidents.length;

    const simulation = await request.post("/api/policy-simulate", {
      data: {
        source: "custom-source",
        severity: "page",
        event: "DatabaseLeaderLost",
        labels: { emergency: "true", team: "platform" }
      }
    });
    await expect(simulation).toBeOK();
    expect(await simulation.json()).toMatchObject({
      source: "custom-source",
      severity: "page",
      event: "DatabaseLeaderLost",
      emergency: {
        managed: true,
        reason: "explicit-emergency-true→fallback:critical-default",
        forced: true,
        profile: { id: "critical-default" },
        channels: {
          ntfy: { enabled: true, attempt: 1 },
          telegram: { enabled: true, after_attempts: 3 },
          smtp: { enabled: true, after_attempts: 5 }
        },
        timeline: expect.any(Array)
      }
    });

    const afterResponse = await request.get("/api/emergencies?state=active&limit=1000");
    await expect(afterResponse).toBeOK();
    expect((await afterResponse.json()).incidents).toHaveLength(before);
  } finally {
    await restoreConfigBundle(request, originalBundle);
  }
});
