import { expect, test } from "@playwright/test";

test("delivery history exposes keyboard details and ACK only for an active receipt", async ({ page }) => {
  let acknowledged = false;
  await page.route(/\/api\/deliveries\?.*/, route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      total: 1,
      limit: 25,
      offset: 0,
      entries: [{
        ts: Date.now() / 1000,
        source: "grafana",
        severity: "critical",
        title: "Database unavailable",
        channel: "ntfy",
        suppressed_by: "",
        emergency_receipt_id: "receipt-delivery-e2e",
      }],
    }),
  }));
  await page.route("**/api/emergencies?state=active&limit=500", route => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ incidents: [{ receipt_id: "receipt-delivery-e2e" }] }),
  }));
  await page.route("**/api/emergencies/receipt-delivery-e2e/ack", route => {
    acknowledged = true;
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
  });

  await page.goto("/deliveries");
  const details = page.locator("[data-delivery-details]");
  await details.focus();
  await details.press("Enter");
  await expect(details).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator(".deliv-detail")).toContainText("receipt-delivery-e2e");

  await page.click("[data-delivery-ack]");
  await page.locator(".app-dialog .primary").click();
  await expect.poll(() => acknowledged).toBe(true);
});
