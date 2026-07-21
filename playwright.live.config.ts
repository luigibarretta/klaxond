import { defineConfig } from "@playwright/test";

const baseURL = process.env.E2E_BASE_URL;

if (!baseURL?.startsWith("https://")) {
  throw new Error("E2E_BASE_URL must be an HTTPS URL for live Authentik tests");
}

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 90_000,
  workers: 1,
  reporter: "list",
  use: {
    baseURL,
    trace: "off",
    video: "off",
    screenshot: "off"
  }
});
