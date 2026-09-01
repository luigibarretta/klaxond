import { expect, type APIRequestContext, type Page } from "@playwright/test";
import crypto from "node:crypto";
import fs from "node:fs";

export const LOCAL_ORIGIN = "http://localhost:18181";
export const BASIC_USER = "admin";
export const BASIC_PASSWORD = "test-password";
export const BASIC_AUTH = `Basic ${Buffer.from(`${BASIC_USER}:${BASIC_PASSWORD}`).toString("base64")}`;
export const APP_VERSION = fs.readFileSync("Cargo.toml", "utf8").match(/^version = "([^"]+)"/m)?.[1] || "";
export const AUTHOR_NAME = "Luigi Barretta";
export const AUTHOR_URL = "https://github.com/luigibarretta";

export async function revealVersionEgg(page: Page) {
  for (let i = 0; i < 7; i++) {
    await page.click("#footer-version");
  }
}

export async function enableBasicAuth(request: APIRequestContext) {
  const res = await request.post("/api/auth/config", {
    headers: { Authorization: BASIC_AUTH },
    data: {
      settings: {
        mode: "basic",
        basic: {
          username: BASIC_USER,
          password: BASIC_PASSWORD,
          realm: "klaxond"
        },
        webauthn: {
          enabled: true,
          origin: LOCAL_ORIGIN,
          rp_id: "localhost"
        }
      }
    }
  });
  await expect(res).toBeOK();
}

export async function exportConfigBundle(request: APIRequestContext) {
  const res = await request.get("/api/config/export");
  await expect(res).toBeOK();
  return res.json();
}

export async function restoreConfigBundle(request: APIRequestContext, bundle: unknown, headers: Record<string, string> = {}) {
  const res = await request.post("/api/config/restore", {
    headers: { "Content-Type": "application/json", ...headers },
    data: bundle
  });
  await expect(res).toBeOK();
}

export async function createAdminBearer(request: APIRequestContext, name = "e2e-admin") {
  const res = await request.post("/api/auth/tokens", {
    data: { name, kind: "pat", scopes: ["admin:*"] }
  });
  await expect(res).toBeOK();
  return `Bearer ${(await res.json()).token}`;
}

export async function requestWithAuthFallback(request: APIRequestContext, method: "get" | "post", url: string, options: Record<string, unknown> = {}) {
  const run = (headers: Record<string, string> = {}) => request[method](url, {
    ...options,
    headers: { ...((options.headers as Record<string, string> | undefined) || {}), ...headers }
  });
  let res = await run();
  if ([401, 403, 428].includes(res.status())) {
    if (method === "get") {
      res = await run({ Authorization: BASIC_AUTH });
    } else {
      let me = await request.get("/api/auth/me");
      if (me.status() === 401) {
        me = await request.get("/api/auth/me", { headers: { Authorization: BASIC_AUTH } });
      }
      if (me.ok()) {
        const csrf = (await me.json()).csrf;
        res = await run(csrf ? { "X-Klaxond-CSRF": csrf } : {});
      }
    }
  }
  return res;
}

export async function exportConfigBundleWithAuthFallback(request: APIRequestContext) {
  const res = await requestWithAuthFallback(request, "get", "/api/config/export");
  await expect(res).toBeOK();
  return res.json();
}

function base32Decode(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const raw of secret.replace(/=+$/g, "").toUpperCase()) {
    const val = alphabet.indexOf(raw);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(out);
}

export function totp(secret: string, atSeconds = Math.floor(Date.now() / 1000)) {
  const counter = Math.floor(atSeconds / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);
  return String(bin % 1_000_000).padStart(6, "0");
}

export async function countPagerRows(page: Page, tableId: string) {
  return page.locator(`#${tableId} tbody tr`).evaluateAll(rows =>
    rows.filter(row => (row as HTMLElement).style.display !== "none").length
  );
}

export async function installPagerProbeRows(page: Page, tableId: string, totalRows = 12) {
  await page.evaluate(
    ({ id, total }) => {
      const table = document.getElementById(id) as HTMLTableElement | null;
      if (!table?.tBodies[0]) throw new Error(`missing table ${id}`);
      const cols = Math.max(1, table.tHead?.querySelectorAll("th").length || 1);
      table.tBodies[0].innerHTML = "";
      for (let i = 0; i < total; i++) {
        const row = document.createElement("tr");
        row.className = "pager-probe-row";
        for (let c = 0; c < cols; c++) {
          const cell = document.createElement("td");
          cell.textContent = `${id} row ${i + 1}`;
          row.appendChild(cell);
        }
        table.tBodies[0].appendChild(row);
      }
      (window as unknown as { applyTablePager: (id: string, opts?: unknown) => void }).applyTablePager(id, { reset: true });
    },
    { id: tableId, total: totalRows }
  );
}

export async function assertTablePagerWorks(page: Page, tab: string, tableId: string) {
  const route = tab === "auth" ? "authentication" : tab;
  await page.goto(`/${route}`);
  if (tab === "auth") {
    await expect(page.locator("#auth-current-user")).not.toHaveText("—");
  }

  const pager = page.locator(`[data-table-pager="${tableId}"]`);
  for (let attempt = 0; attempt < 3; attempt++) {
    await installPagerProbeRows(page, tableId);
    await expect(pager).toBeVisible();
    await page.selectOption(`[data-table-pager="${tableId}"] [data-pager-size]`, "10");
    try {
      await expect(pager.locator("[data-pager-range]")).toContainText("1-10 / 12", { timeout: 2_000 });
      break;
    } catch (err) {
      if (attempt === 2) throw err;
      await page.waitForTimeout(300);
    }
  }
  expect(await countPagerRows(page, tableId)).toBe(10);
  await expect(pager.locator("[data-pager-next]")).toBeEnabled();
  await pager.locator("[data-pager-next]").click();
  await expect(pager.locator("[data-pager-range]")).toContainText("11-12 / 12");
  expect(await countPagerRows(page, tableId)).toBe(2);
}
