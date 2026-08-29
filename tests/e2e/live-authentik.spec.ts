import { createHmac } from "node:crypto";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const baseURL = process.env.E2E_BASE_URL ?? "";
const username = process.env.E2E_AUTHENTIK_USERNAME ?? "";
const password = process.env.E2E_AUTHENTIK_PASSWORD ?? "";
const liveConfigured =
  baseURL.startsWith("https://") && username.length > 0 && password.length > 0;

test.use({ trace: "off", video: "off", screenshot: "off" });
test.setTimeout(90_000);

async function clickVisibleButton(page: Page, names: RegExp[]): Promise<boolean> {
  for (const name of names) {
    const button = page.getByRole("button", { name }).first();
    if (await button.isVisible().catch(() => false)) {
      await button.click({ timeout: 3_000 });
      return true;
    }
  }
  return false;
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of value.toUpperCase().replace(/=+$/, "")) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error("Authentik returned an invalid TOTP secret");
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}

function totpFromConfigUrl(configUrl: string): string {
  const configuration = new URL(configUrl);
  if (configuration.protocol !== "otpauth:") {
    throw new Error("Authentik returned an invalid TOTP configuration URL");
  }
  const secret = configuration.searchParams.get("secret");
  const digits = Number(configuration.searchParams.get("digits") ?? "6");
  const period = Number(configuration.searchParams.get("period") ?? "30");
  const algorithm = (configuration.searchParams.get("algorithm") ?? "SHA1").toLowerCase();
  if (!secret || !Number.isInteger(digits) || !Number.isInteger(period)) {
    throw new Error("Authentik returned an incomplete TOTP configuration");
  }
  const counter = BigInt(Math.floor(Date.now() / 1_000 / period));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac(algorithm, decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, "0");
}

async function enrollRequiredTotp(page: Page): Promise<boolean> {
  const setup = page.getByRole("button", { name: /TOTP Device/i }).first();
  if (!(await setup.isVisible().catch(() => false))) return false;
  const challengePromise = page.waitForResponse(
    async (response) => {
      if (!new URL(response.url()).pathname.includes("/api/v3/flows/executor/")) return false;
      const challenge = (await response.json().catch(() => null)) as {
        component?: string;
      } | null;
      return challenge?.component === "ak-stage-authenticator-totp";
    },
    { timeout: 10_000 }
  );
  await setup.click({ timeout: 3_000 });
  const challenge = (await (await challengePromise).json()) as { config_url?: string };
  if (!challenge.config_url) throw new Error("Authentik omitted the TOTP configuration");
  const code = page.locator('input[autocomplete="one-time-code"]').first();
  await code.waitFor({ state: "visible", timeout: 5_000 });
  await code.fill(totpFromConfigUrl(challenge.config_url));
  await page.getByRole("button", { name: /^\s*Continue\s*$/i }).click();
  return true;
}

async function finishAuthorization(page: Page, credentialsAllowed: boolean): Promise<void> {
  const applicationOrigin = new URL(baseURL).origin;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (new URL(page.url()).origin === applicationOrigin) return;
    if (await page.locator("ak-loading-overlay").isVisible().catch(() => false)) {
      await page.waitForTimeout(250);
      continue;
    }
    const identity = page.getByPlaceholder("Email or Username");
    const passwordField = page.getByPlaceholder("Password");
    if (
      !credentialsAllowed &&
      ((await identity.isVisible().catch(() => false)) ||
        (await passwordField.isVisible().catch(() => false)))
    ) {
      throw new Error("Authentik SSO session was not retained after local logout");
    }
    if (await enrollRequiredTotp(page)) {
      await page.waitForTimeout(750);
      continue;
    }
    if (await page.locator('input[autocomplete="one-time-code"]').isVisible().catch(() => false)) {
      throw new Error("Authentik rejected the generated TOTP code");
    }
    const advanced = await clickVisibleButton(page, [
      /^\s*Continue\s*$/i,
      /^\s*Authorize\s*$/i,
      /^\s*Allow\s*$/i,
      /^\s*Yes\s*$/i
    ]);
    await page.waitForTimeout(advanced ? 750 : 250);
  }
  throw new Error(`OIDC authorization did not return to ${applicationOrigin}`);
}

async function loginWithPassword(page: Page): Promise<void> {
  await page.goto("/api/auth/login?start=1&return_to=%2Fstatus", {
    waitUntil: "domcontentloaded"
  });
  const identity = page.getByPlaceholder("Email or Username");
  await identity.waitFor({ state: "visible", timeout: 15_000 });
  await identity.fill(username);
  await page.getByRole("button", { name: /^\s*Log in\s*$/i }).click();
  const passwordField = page.getByPlaceholder("Password");
  await passwordField.waitFor({ state: "visible", timeout: 15_000 });
  await passwordField.fill(password);
  await page.getByRole("button", { name: /^\s*Continue\s*$/i }).click();
  await finishAuthorization(page, true);
}

async function loginFromExistingSso(page: Page): Promise<void> {
  await page.goto("/api/auth/login?start=1&return_to=%2Fstatus", {
    waitUntil: "domcontentloaded"
  });
  await finishAuthorization(page, false);
}

type KlaxondUser = { csrf?: string; mode?: string; sub?: string };

async function currentUser(context: BrowserContext): Promise<KlaxondUser | null> {
  const response = await context.request.get(`${baseURL}/api/auth/me`, { maxRedirects: 0 });
  if (response.status() === 302) return null;
  expect(response.status()).toBe(200);
  return response.json();
}

async function localLogout(page: Page, context: BrowserContext): Promise<void> {
  const user = await currentUser(context);
  expect(user).not.toBeNull();
  const logout = page.locator("[data-auth-logout]:visible").first();
  await logout.waitFor({ state: "visible", timeout: 10_000 });
  await Promise.all([
    page.waitForURL(
      (url) => url.pathname === "/api/auth/login" && url.searchParams.get("logged_out") === "1",
      { waitUntil: "domcontentloaded" }
    ),
    logout.click()
  ]);
}

async function endAuthentikSession(page: Page): Promise<void> {
  const discovery = await page.request.get(
    "https://authentik.luigibarretta.com/application/o/klaxond-it1-prd-mgmt-01/.well-known/openid-configuration"
  );
  expect(discovery.status()).toBe(200);
  const metadata = (await discovery.json()) as { end_session_endpoint?: string };
  expect(metadata.end_session_endpoint).toMatch(/^https:\/\/authentik\.luigibarretta\.com\//);
  await page.goto(metadata.end_session_endpoint as string, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(750);
  await clickVisibleButton(page, [/^\s*Log out\s*$/i, /^\s*Continue\s*$/i, /^\s*Yes\s*$/i]);
}

test.describe("live Authentik OIDC", () => {
  test.skip(!liveConfigured, "live Authentik credentials are not configured");

  test("login, local logout, SSO reuse, and back-channel logout", async ({ page, context }) => {
    if (password.includes("__ansible_vault")) {
      throw new Error("E2E_AUTHENTIK_PASSWORD must contain a decrypted value");
    }
    let authentikSessionStarted = false;
    let authentikSessionEnded = false;
    try {
      await loginWithPassword(page);
      authentikSessionStarted = true;
      expect((await currentUser(context))?.mode).toBe("oidc");

      const setupResponse = await context.request.get(`${baseURL}/api/setup-status`);
      expect(setupResponse.status()).toBe(200);
      const setup = (await setupResponse.json()) as {
        ready?: boolean;
        summary?: { blocking?: number; complete?: number; required?: number };
      };
      expect(setup.ready).toBe(true);
      expect(setup.summary?.blocking).toBe(0);
      expect(setup.summary?.complete).toBe(setup.summary?.required);

      await localLogout(page, context);
      expect(await currentUser(context)).toBeNull();

      await loginFromExistingSso(page);
      expect((await currentUser(context))?.mode).toBe("oidc");

      await endAuthentikSession(page);
      authentikSessionEnded = true;
      await expect.poll(() => currentUser(context), { timeout: 15_000 }).toBeNull();
    } finally {
      if (authentikSessionStarted && !authentikSessionEnded) {
        await endAuthentikSession(page).catch(() => undefined);
      }
    }
  });
});
