import { expect, test } from "@playwright/test";
import { exportConfigBundle, restoreConfigBundle } from "./klaxond-helpers";

test("emergency policy updates are partial, validated and transactional", async ({ request }) => {
  const originalBundle = await exportConfigBundle(request);
  try {
    const update = await request.post("/api/emergency-config", {
      data: {
        enabled: false,
        severities: [" Critical ", "critical", "PAGE"],
        retry_seconds: 75,
        expire_seconds: 3600,
        max_attempts: 20,
        lease_seconds: 60,
        telegram_after_attempts: 3,
        smtp_after_attempts: 5,
        notify_on_expiry: true,
        auto_resolve: true,
        exclude_sources: [" API-Test ", "maintenance"]
      }
    });
    await expect(update).toBeOK();

    const read = await request.get("/api/emergency-config");
    await expect(read).toBeOK();
    expect(await read.json()).toMatchObject({
      settings: {
        enabled: false,
        severities: ["critical", "page"],
        retry_seconds: 75,
        max_attempts: 20,
        exclude_sources: ["api-test", "maintenance"]
      },
      managed_fields: {},
      managed_by_environment: false,
      writeable: true
    });

    const beforeRejected = await exportConfigBundle(request);
    const invalid = await request.post("/api/emergency-config", {
      data: { retry_seconds: 300, expire_seconds: 60 }
    });
    expect(invalid.status()).toBe(400);
    expect(await invalid.text()).toContain("expire_seconds");
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
