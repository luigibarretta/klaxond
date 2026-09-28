import { expect, test } from "@playwright/test";
import { deliveryConfig, mockDeliveryConfig } from "./klaxond-delivery-helpers";

test("delivery policy rules validate input and protect referenced policies", async ({ page }) => {
  const posts: unknown[] = [];
  let clientErrorReports = 0;
  await page.route("**/api/client-log", route => {
    clientErrorReports += 1;
    return route.fulfill({ status: 204, body: "" });
  });
  await mockDeliveryConfig(page, payload => {
    posts.push(payload);
    const host = (payload as { rules?: Array<{ match?: { host?: string } }> }).rules?.[0]?.match?.host;
    if (host === "re:[") {
      return { status: 400, body: "delivery rule 1 label 'host' has invalid regex: unclosed character class" };
    }
  });
  await page.goto("/delivery");

  const rule = page.locator("#t-rules tbody tr").first();
  const rulePolicy = rule.locator('[data-f="policy"]');
  await page.locator("#d-default-policy").selectOption("cascade");
  const opsRow = page.locator('#t-pol tr[data-policy-custom]:has(input[value="ops"])');
  await opsRow.locator('[data-action="delete-policy"]').click();
  await expect(page.locator(".app-dialog")).toHaveCount(0);
  await expect(opsRow).toHaveCount(1);
  await expect(page.locator("#delivery-status")).toContainText("still used");
  await expect(rulePolicy).toBeFocused();
  await page.locator("#d-default-policy").selectOption("ops");

  const spareRow = page.locator('#t-pol tr[data-policy-custom]:has(input[value="all-channels"])');
  await spareRow.locator('[data-action="delete-policy"]').click();
  await expect(page.locator(".app-dialog")).toContainText("Remove policy all-channels");
  await page.locator(".app-dialog-actions .danger").click();
  await expect(spareRow).toHaveCount(0);

  const match = rule.locator('[data-f="match"]');
  await match.fill("severity");
  await page.locator("#btn-delivery-save").click();
  await expect(rule.locator("[data-rule-error]")).toContainText("label=value");
  expect(posts).toHaveLength(0);

  await match.fill("severity=critical\nseverity=warning");
  await page.locator("#btn-delivery-save").click();
  await expect(rule.locator("[data-rule-error]")).toContainText("duplicated");
  expect(posts).toHaveLength(0);

  await match.fill("host=re:(?i)^prod-");
  await page.locator("#btn-delivery-save").click();
  await expect.poll(() => posts.length).toBe(1);
  await expect(rule.locator("[data-rule-error]")).toBeHidden();

  await match.fill("host=re:[");
  await page.locator("#btn-delivery-save").click();
  await expect.poll(() => posts.length).toBe(2);
  await expect(rule.locator("[data-rule-error]")).toContainText("invalid regex");
  await expect(match).toBeFocused();

  await match.fill("severity=critical\nhost=re:^prod-");
  await page.locator("#btn-delivery-save").click();
  await expect.poll(() => posts.length).toBe(3);
  expect(posts[2]).toMatchObject({
    default_policy: "ops",
    policies: [expect.objectContaining({ name: "ops", mode: "cascade" })],
    rules: [{ match: { severity: "critical", host: "re:^prod-" }, policy: "ops" }],
  });
  expect(clientErrorReports).toBe(0);
});

test("policy rename keeps default and rule references stable", async ({ page }) => {
  await mockDeliveryConfig(page);
  await page.goto("/delivery");

  const policyName = page.locator('#t-pol tr[data-policy-custom]:has(input[value="ops"]) [data-f="name"]');
  const defaultPolicy = page.locator("#d-default-policy");
  const rulePolicy = page.locator('#t-rules [data-f="policy"]').first();

  await policyName.fill("");
  await policyName.press("Tab");
  await page.locator("#btn-pol-add").click();
  await expect(defaultPolicy).toHaveValue("ops");
  await expect(rulePolicy).toHaveValue("ops");

  await policyName.fill("renamed-ops");
  await policyName.press("Tab");
  await expect(defaultPolicy).toHaveValue("renamed-ops");
  await expect(rulePolicy).toHaveValue("renamed-ops");
});

test("delivery save preserves newer edits made while the request is in flight", async ({ page }) => {
  let releasePost!: () => void;
  let markPostStarted!: () => void;
  const postGate = new Promise<void>(resolve => { releasePost = resolve; });
  const postStarted = new Promise<void>(resolve => { markPostStarted = resolve; });
  await page.route("**/api/delivery-config", async route => {
    if (route.request().method() === "POST") {
      markPostStarted();
      await postGate;
      return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(deliveryConfig),
    });
  });
  await page.goto("/delivery");

  const save = page.locator("#btn-delivery-save");
  await save.click();
  await postStarted;
  await expect(save).toBeDisabled();
  await page.locator('#t-rules [data-f="match"]').first().fill("severity=warning");
  releasePost();

  await expect(save).toBeEnabled();
  await expect(page.locator("#delivery-status")).toContainText("Newer edits are still unsaved");
});

test("cascade save preserves newer edits made while the request is in flight", async ({ page }) => {
  let releasePost!: () => void;
  let markPostStarted!: () => void;
  const postGate = new Promise<void>(resolve => { releasePost = resolve; });
  const postStarted = new Promise<void>(resolve => { markPostStarted = resolve; });
  await mockDeliveryConfig(page);
  await page.route("**/api/cascade-config", async route => {
    if (route.request().method() === "POST") {
      markPostStarted();
      await postGate;
      return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        tiers: deliveryConfig.legacy_cascade_tiers,
        default_enabled_for_webhook: false,
      }),
    });
  });
  await page.goto("/delivery");

  const save = page.locator("#btn-cas-save");
  await save.click();
  await postStarted;
  await expect(save).toBeDisabled();
  await page.locator('#t-cas [data-f="timeout"]').last().fill("11");
  releasePost();

  await expect(save).toBeEnabled();
  await expect(page.locator("#cas-status")).toContainText("Newer cascade edits are still unsaved");
});

test("delivery editor is accessible and does not overflow a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockDeliveryConfig(page);
  await page.goto("/delivery");

  await expect(page.locator("#cascade-diagram")).toContainText("ntfy");
  await expect(page.locator('#t-cas [data-f="name"]').first()).toHaveAttribute(
    "aria-label", "Cascade tier 1 channel",
  );
  await expect(page.locator('#t-cas [data-f="timeout"]').first()).toHaveAttribute(
    "aria-label", "Cascade tier 1 timeout in seconds",
  );
  await expect(page.locator('#t-pol [data-tier-name]').first()).toHaveAttribute(
    "aria-label", "Policy ops, tier 1 channel",
  );
  await expect(page.locator('#t-rules [data-f="match"]').first()).toHaveAttribute(
    "aria-label", "Rule 1 match conditions",
  );
  await expect(page.locator("#btn-cascade-toggle")).toHaveText(/Enable|Disable/);

  const overflow = await page.evaluate(() => {
    const viewportWidth = document.documentElement.clientWidth;
    const selectors = ["#cascade-diagram", "#t-cas", "#t-pol", "#t-rules"];
    return selectors.filter(selector => {
      const rect = document.querySelector(selector)?.getBoundingClientRect();
      return rect && (rect.left < -1 || rect.right > viewportWidth + 1);
    });
  });
  expect(overflow).toEqual([]);

  for (const selector of ["#t-cas", "#t-pol", "#t-rules"]) {
    const actions = page.locator(`${selector} tbody [data-action]:visible`);
    for (let index = 0; index < await actions.count(); index += 1) {
      const box = await actions.nth(index).boundingBox();
      expect(box, `${selector} action ${index} should be visible`).not.toBeNull();
      expect(box!.x + box!.width, `${selector} action ${index} should fit`).toBeLessThanOrEqual(390);
    }
  }
});
