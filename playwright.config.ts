import { defineConfig } from "@playwright/test";

const localBaseURL = "http://127.0.0.1:18181";
const liveBaseURL = process.env.E2E_BASE_URL?.trim();

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 30_000,
  workers: 1,
  expect: { timeout: 5_000 },
  use: {
    baseURL: liveBaseURL || localBaseURL,
    trace: "retain-on-failure"
  },
  webServer: liveBaseURL ? undefined : {
    command: "bash scripts/e2e-server.sh",
    url: `${localBaseURL}/healthz`,
    reuseExistingServer: false,
    timeout: 60_000
  }
});
