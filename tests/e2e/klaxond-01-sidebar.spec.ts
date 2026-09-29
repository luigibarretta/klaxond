import { expect, test } from "@playwright/test";
import { openSidebar } from "./klaxond-helpers";

test("mobile shell is modal, stable, keyboard operable, and closes after navigation", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/setup");

  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await expect(page.locator("#sidebar-toggle")).toHaveAttribute("aria-expanded", "false");
  await expect(page.locator('#sidebar-toggle [data-lucide="menu"]')).toBeVisible();
  await expect(page.locator("nav.tabs")).toBeHidden();
  await expect(page.locator(".brand-name")).toBeVisible();
  await expect(page.locator("main")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const contentTop = await page.locator(".app-main").evaluate(element => element.getBoundingClientRect().top);

  await page.click("#sidebar-toggle");
  await expect(page.locator("#sidebar-toggle")).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("#sidebar-toggle")).toBeHidden();
  await expect(page.locator("nav.tabs")).toBeVisible();
  await expect(page.locator("#sidebar-backdrop")).toBeVisible();
  await expect(page.locator("#sidebar")).toHaveCSS("position", "fixed");
  await expect(page.locator("body")).toHaveCSS("overflow", "hidden");
  await expect(page.locator(".app-main")).toHaveAttribute("inert", "");
  expect(await page.locator(".app-main").evaluate(element => element.getBoundingClientRect().top)).toBe(contentTop);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);

  const drawerWidth = await page.locator("#sidebar").evaluate(element =>
    element.getBoundingClientRect().width
  );
  expect(drawerWidth).toBeLessThanOrEqual(272);
  expect(drawerWidth).toBeLessThanOrEqual(390 - 48);

  await page.locator("#sidebar-backdrop").click({ position: { x: 380, y: 400 } });
  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await expect(page.locator("#sidebar-toggle")).toBeVisible();
  await expect(page.locator("#sidebar-toggle")).toBeFocused();

  await page.click("#sidebar-toggle");

  await page.click('[data-group="activity"] .tab-group-toggle');
  await page.click('[data-tab="deliveries"]');
  await expect(page).toHaveURL(/\/deliveries$/);
  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await expect(page.locator("nav.tabs")).toBeHidden();
  await expect(page.locator("#sidebar-backdrop")).toBeHidden();
  await expect(page.locator(".app-main")).not.toHaveAttribute("inert", "");
  await expect(page.locator("#main-content")).toBeFocused();

  await page.click("#sidebar-toggle");
  await page.keyboard.press("Escape");
  await expect(page.locator("body")).toHaveClass(/sidebar-collapsed/);
  await expect(page.locator("#sidebar-toggle")).toBeFocused();
});

test("navigation groups preserve state and expose hidden operational counts", async ({ page }) => {
  await page.goto("/status");
  await openSidebar(page);
  const activityGroup = page.locator('[data-group="activity"]');
  const activityToggle = activityGroup.locator(".tab-group-toggle");

  await expect(activityToggle).toHaveAttribute("aria-expanded", "false");
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => {
    const setBadge = (window as unknown as {
      setTabBadge: (tabId: string, count: number, kind?: string) => void;
    }).setTabBadge;
    for (const tabId of ["deliveries", "emergencies", "logs", "audit"]) setBadge(tabId, 0);
    setBadge("logs", 7, "warn");
  });
  const indicator = activityToggle.locator(".group-indicator");
  await expect(indicator).toHaveText("7");
  await expect(indicator).toHaveClass(/warn/);
  await expect(activityToggle).toHaveAttribute("aria-label", /7 active indicator/);
  const warningContrast = await indicator.evaluate(element => {
    const parse = (value: string) => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const luminance = (rgb: number[]) => {
      const linear = rgb.map(value => {
        const channel = value / 255;
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    };
    const style = getComputedStyle(element);
    const foreground = luminance(parse(style.color));
    const background = luminance(parse(style.backgroundColor));
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  expect(warningContrast).toBeGreaterThanOrEqual(4.5);

  await activityToggle.click();
  await expect(activityToggle).toHaveAttribute("aria-expanded", "true");
  await expect(activityGroup.locator('[data-tab="deliveries"]')).toBeVisible();
  await page.reload();
  await openSidebar(page);
  await expect(activityToggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator('[data-group="configure"] .tab-group-toggle')).toHaveAttribute("aria-expanded", "false");
  await activityToggle.click();
  await expect(activityToggle).toHaveAttribute("aria-expanded", "false");
  await expect(activityGroup.locator('[data-tab="deliveries"]')).toBeHidden();

  await page.goto("/deliveries");
  await openSidebar(page);
  await expect(activityToggle).toHaveAttribute("aria-expanded", "true");
  await expect(activityGroup.locator('[data-tab="deliveries"]')).toBeVisible();
});

test("cancelled dirty navigation keeps the mobile drawer open", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/setup");
  await page.evaluate(() => (window as any)._markTabDirty("setup", true));
  await page.click("#sidebar-toggle");
  await page.click('[data-group="activity"] .tab-group-toggle');
  await page.click('[data-tab="deliveries"]');

  await expect(page.locator(".app-dialog-overlay")).toBeVisible();
  await expect(page.locator("body")).toHaveClass(/mobile-nav-open/);
  await page.keyboard.press("Escape");
  await expect(page.locator(".app-dialog-overlay")).toHaveCount(0);
  await expect(page.locator("body")).toHaveClass(/mobile-nav-open/);
  await expect(page.locator("#tab-setup")).toHaveClass(/active/);
  await expect(page.locator('[data-tab="setup"] .tab-dirty')).toBeAttached();
  await expect(page.locator('[data-tab="deliveries"]')).toBeFocused();

  await page.evaluate(() => (window as any)._markTabDirty("setup", false));
  await page.keyboard.press("Escape");
});

test("keyboard users can skip navigation and see a visible focus indicator", async ({ page }) => {
  await page.goto("/status");
  await page.keyboard.press("Tab");
  await expect(page.locator(".skip-link")).toBeFocused();
  const outline = await page.locator(".skip-link").evaluate(element => getComputedStyle(element).outlineStyle);
  expect(outline).not.toBe("none");
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
});
