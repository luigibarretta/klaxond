import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 30_000,
  workers: 1,
  expect: { timeout: 5_000 },
  use: {
    baseURL: "http://127.0.0.1:18181",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "bash scripts/e2e-server.sh",
    url: "http://127.0.0.1:18181/healthz",
    reuseExistingServer: false,
    timeout: 60_000
  }
});
