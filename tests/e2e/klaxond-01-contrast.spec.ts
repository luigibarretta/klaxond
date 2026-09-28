import { expect, test } from "@playwright/test";

test("delivery semantic text colors meet WCAG AA in both themes", async ({ page }) => {
  await page.goto("/deliveries");
  const ratios = await page.evaluate(() => {
    const rgb = (value) => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const luminance = (value) => {
      const channels = rgb(value).map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    };
    const contrast = (foreground, background) => {
      const lighter = Math.max(luminance(foreground), luminance(background));
      const darker = Math.min(luminance(foreground), luminance(background));
      return (lighter + 0.05) / (darker + 0.05);
    };

    return ["light", "dark"].flatMap((theme) => {
      document.documentElement.dataset.theme = theme;
      const surface = document.createElement("div");
      surface.className = "card";
      surface.innerHTML = '<span class="sev-info">info</span><span class="ch-smtp">smtp</span>';
      document.body.appendChild(surface);
      const background = getComputedStyle(surface).backgroundColor;
      const measurements = ["sev-info", "ch-smtp"].map((className) => ({
        theme,
        className,
        ratio: contrast(
          getComputedStyle(surface.querySelector(`.${className}`)!).color,
          background,
        ),
      }));
      surface.remove();
      return measurements;
    });
  });

  for (const measurement of ratios) {
    expect(
      measurement.ratio,
      `${measurement.theme} .${measurement.className}`,
    ).toBeGreaterThanOrEqual(4.5);
  }
});
