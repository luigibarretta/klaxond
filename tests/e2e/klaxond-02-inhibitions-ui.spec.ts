import { expect, test } from "@playwright/test";

test("inhibition applies-to checkboxes stay compact and aligned", async ({ page }) => {
  await page.goto("/inhibitions");
  const firstPicker = page.locator("#t-inhib-rules .inhib-source-picker").first();
  await firstPicker.locator("summary").click();
  const firstCheckbox = page.locator('#t-inhib-rules [data-k="applies_to"] input[type="checkbox"]').first();
  await expect(firstCheckbox).toBeVisible();

  const box = await firstCheckbox.boundingBox();
  expect(box?.width).toBeLessThanOrEqual(20);
  await expect(firstCheckbox.locator("xpath=..")).toHaveCSS("align-items", "center");

  await page.setViewportSize({ width: 1920, height: 1080 });
  const regex = page.locator('#t-inhib-rules [data-k="match_regex"]:visible').first();
  await expect(regex).toBeVisible();
  expect((await regex.boundingBox())?.width).toBeGreaterThanOrEqual(180);

  await page.setViewportSize({ width: 390, height: 844 });
  const firstRow = page.locator("#t-inhib-rules .inhib-rule-row").first();
  await expect(firstRow).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect(await firstRow.locator("[data-inhib-preview]").evaluate(element => (
    element.scrollWidth <= element.clientWidth + 1
  ))).toBe(true);

  const savebar = page.locator("#tab-inhibitions .editor-savebar");
  await expect(savebar.locator("#inhib-preset")).toHaveCount(0);
  expect((await savebar.boundingBox())?.height).toBeLessThanOrEqual(84);
  const ttl = firstRow.locator('[data-k="ttl_seconds"]');
  await ttl.evaluate(element => element.scrollIntoView({ block: "center" }));
  const ttlBox = await ttl.boundingBox();
  const savebarBox = await savebar.boundingBox();
  expect(ttlBox && savebarBox && ttlBox.y + ttlBox.height <= savebarBox.y).toBe(true);
});

test("inhibition editor explains rules, filters source scope and validates regex inline", async ({ page }) => {
  await page.goto("/inhibitions");
  const row = page.locator("#t-inhib-rules .inhib-rule-row").first();
  await expect(row.locator("[data-inhib-preview]")).toContainText("When inhibition_source is");

  const picker = row.locator(".inhib-source-picker");
  await picker.locator("summary").click();
  await picker.locator('input[type="search"]').fill("grafana");
  await expect(picker.locator(".inhib-source-option", { hasText: "grafana" })).toBeVisible();
  expect(await picker.locator(".inhib-source-option:not([hidden])").count()).toBe(1);
  await picker.locator('input[type="search"]').fill("no-such-source");
  await expect(picker.locator(".inhib-source-option").first()).toBeHidden();
  await expect(picker.locator(".inhib-source-empty")).toBeVisible();

  await row.locator('[data-k="match_type"]').selectOption("match_label");
  const regex = row.locator('[data-k="match_regex"]');
  await regex.fill("(?=blackbox)");
  await expect(regex).toHaveAttribute("aria-invalid", "true");
  await expect(row.locator("[data-inhib-validation]")).toContainText("Invalid regular expression");
  await expect(regex).toHaveAttribute("aria-errormessage", /inhib-validation-/);
  await regex.fill("(?i)blackbox");
  await expect(regex).not.toHaveAttribute("aria-invalid", "true");
  await expect(row.locator("[data-inhib-validation]")).toHaveText("Valid regular expression");
});

test("inhibition presets add an editable unsaved rule", async ({ page }) => {
  await page.goto("/inhibitions");
  const rows = page.locator("#t-inhib-rules .inhib-rule-row");
  const before = await rows.count();
  await page.selectOption("#inhib-preset", "same_service");
  await page.click("#inhib-preset-add");
  await expect(rows).toHaveCount(before + 1);
  await expect(rows.last().locator('[data-k="source"]')).toHaveValue("service-down");
  await expect(page.locator('[data-tab="inhibitions"] .tab-dirty')).toBeAttached();
  await expect(page.locator('[data-tab="inhibitions"]')).toHaveAttribute("aria-label", /Unsaved changes/);
});
