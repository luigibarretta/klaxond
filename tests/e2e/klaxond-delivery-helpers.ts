import type { Page, Route } from "@playwright/test";

export const deliveryConfig = {
  default_policy: "ops",
  policies: [
    {
      name: "ops",
      mode: "cascade",
      tiers: [
        { name: "ntfy", timeout_seconds: 15 },
        { name: "telegram", timeout_seconds: 8 },
      ],
    },
    {
      name: "all-channels",
      mode: "broadcast",
      tiers: [
        { name: "ntfy", timeout_seconds: 15 },
        { name: "smtp", timeout_seconds: 10 },
      ],
    },
  ],
  rules: [{ match: { severity: "critical" }, policy: "ops" }],
  available_tiers: ["ntfy", "telegram", "smtp"],
  legacy_cascade_tiers: [
    { name: "ntfy", timeout_seconds: 15 },
    { name: "telegram", timeout_seconds: 8 },
    { name: "smtp", timeout_seconds: 10 },
  ],
};

type PostResult = { status: number; body: string } | void;

export async function mockDeliveryConfig(
  page: Page,
  onPost?: (payload: unknown) => PostResult,
) {
  await page.route("**/api/delivery-config", async (route: Route) => {
    if (route.request().method() === "POST") {
      const result = onPost?.(await route.request().postDataJSON());
      return route.fulfill({
        status: result?.status || 200,
        contentType: result ? "text/plain" : "application/json",
        body: result?.body || "{}",
      });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(deliveryConfig),
    });
  });
}
