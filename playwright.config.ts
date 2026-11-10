import { defineConfig, devices } from "@playwright/test";

const localBaseURL = "http://127.0.0.1:18181";
const liveBaseURL = process.env.E2E_BASE_URL?.trim();

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 30_000,
  workers: 1,
  expect: { timeout: 5_000 },
  use: {
    baseURL: liveBaseURL || localBaseURL,
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    {
      name: "firefox",
      use: {
        ...devices["Desktop Firefox"],
        // Klaxond sends Cross-Origin-Opener-Policy: same-origin. Navigating from
        // about:blank to such a page swaps Firefox's browsing-context group, and
        // Playwright's Firefox driver then loses the load event about one time in
        // five (page.goto timeouts with every resource loaded). Chromium still
        // exercises COOP; the header itself is covered by the Rust tests.
        launchOptions: { firefoxUserPrefs: { "browser.tabs.remote.useCrossOriginOpenerPolicy": false } }
      }
    },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "mobile-safari", use: { ...devices["iPhone 15"] } }
  ],
  webServer: liveBaseURL ? undefined : {
    command: "bash scripts/e2e-server.sh",
    url: `${localBaseURL}/healthz`,
    reuseExistingServer: false,
    timeout: 60_000
  }
});
