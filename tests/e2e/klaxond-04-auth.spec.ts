import { expect, test } from "@playwright/test";
import {
  APP_VERSION, AUTHOR_NAME, AUTHOR_URL, BASIC_AUTH, BASIC_PASSWORD, BASIC_USER, LOCAL_ORIGIN,
  addVirtualAuthenticator, assertTablePagerWorks, createAdminBearer, enableBasicAuth,
  exportConfigBundle, exportConfigBundleWithAuthFallback, requestWithAuthFallback,
  restoreConfigBundle, revealVersionEgg, totp,
} from "./klaxond-helpers";

test("backend logs require admin auth when auth is enabled", async ({ request }) => {
  const unsafeBasic = await request.post("/api/auth/config", {
    data: {
      settings: {
        mode: "basic",
        basic: { username: "", password: "test-password" }
      }
    }
  });
  expect(unsafeBasic.status()).toBe(400);
  expect(await unsafeBasic.text()).toContain("username");

  const unsafeOidc = await request.post("/api/auth/config", {
    data: {
      settings: {
        mode: "oidc",
        oidc: {
          issuer: "https://idp.example.test",
          client_id: "klaxond",
          redirect_path: "/custom/callback"
        }
      }
    }
  });
  expect(unsafeOidc.status()).toBe(400);
  expect(await unsafeOidc.text()).toContain("/api/auth/callback");

  const unsafeTrustedProxy = await request.post("/api/auth/config", {
    data: {
      settings: {
        mode: "trusted-proxy",
        trusted_proxy: {
          user_header: "X-Forwarded-User",
          trusted_cidrs: ["127.0.0.1/32"]
        }
      }
    }
  });
  expect(unsafeTrustedProxy.status()).toBe(400);
  expect(await unsafeTrustedProxy.text()).toContain("X-Forwarded-User");

  const scopedToken = await request.post("/api/auth/tokens", {
    data: {
      name: "logs-reader",
      kind: "pat",
      scopes: ["logs:read"]
    }
  });
  await expect(scopedToken).toBeOK();
  const scopedPayload = await scopedToken.json();
  expect(scopedPayload.token).toMatch(/^klx_pat_/);
  expect(JSON.stringify(scopedPayload.record)).not.toContain("token_hash");

  const wrongToken = await request.post("/api/auth/tokens", {
    data: {
      name: "status-only",
      kind: "api-key",
      scopes: ["status:read"]
    }
  });
  await expect(wrongToken).toBeOK();
  const wrongPayload = await wrongToken.json();

  const viewerToken = await request.post("/api/auth/tokens", {
    data: {
      name: "viewer-role",
      kind: "pat",
      scopes: ["viewer:*"]
    }
  });
  await expect(viewerToken).toBeOK();
  const viewerPayload = await viewerToken.json();

  const configReaderToken = await request.post("/api/auth/tokens", {
    data: {
      name: "config-reader",
      kind: "pat",
      scopes: ["config:read"]
    }
  });
  await expect(configReaderToken).toBeOK();
  const configReaderPayload = await configReaderToken.json();

  const authWriterToken = await request.post("/api/auth/tokens", {
    data: {
      name: "auth-writer",
      kind: "pat",
      scopes: ["auth:write"]
    }
  });
  await expect(authWriterToken).toBeOK();
  const authWriterPayload = await authWriterToken.json();

  const update = await request.post("/api/auth/config", {
    data: {
      settings: {
        mode: "basic",
        basic: {
          username: "admin",
          password: "test-password"
        }
      }
    }
  });
  await expect(update).toBeOK();
  const updatedAuth = await update.json();
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("token_hash");
  expect(JSON.stringify(updatedAuth.settings)).not.toContain("credential");

  const denied = await request.get("/api/logs?limit=1");
  expect(denied.status()).toBe(401);
  expect(denied.headers()["www-authenticate"]).toContain("Basic");

  const token = Buffer.from("admin:test-password").toString("base64");
  const allowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Basic ${token}` }
  });
  await expect(allowed).toBeOK();

  const bearerAllowed = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${scopedPayload.token}` }
  });
  await expect(bearerAllowed).toBeOK();

  const bearerDenied = await request.get("/api/logs?limit=1", {
    headers: { Authorization: `Bearer ${wrongPayload.token}` }
  });
  expect(bearerDenied.status()).toBe(403);

  const secretExportDenied = await request.get("/api/config/export", {
    headers: { Authorization: `Bearer ${configReaderPayload.token}` }
  });
  expect(secretExportDenied.status()).toBe(403);

  const authWriterEscalationDenied = await request.post("/api/auth/tokens", {
    headers: { Authorization: `Bearer ${authWriterPayload.token}` },
    data: {
      name: "should-not-escalate",
      kind: "pat",
      scopes: ["admin:*"]
    }
  });
  expect(authWriterEscalationDenied.status()).toBe(403);

  const viewerStatus = await request.get("/api/status", {
    headers: { Authorization: `Bearer ${viewerPayload.token}` }
  });
  await expect(viewerStatus).toBeOK();

  const viewerAudit = await request.get("/api/audit?limit=1", {
    headers: { Authorization: `Bearer ${viewerPayload.token}` }
  });
  await expect(viewerAudit).toBeOK();

  const viewerExportDenied = await request.get("/api/config/export", {
    headers: { Authorization: `Bearer ${viewerPayload.token}` }
  });
  expect(viewerExportDenied.status()).toBe(403);

  const viewerWriteDenied = await request.post("/api/cascade/toggle", {
    headers: { Authorization: `Bearer ${viewerPayload.token}` },
    data: {}
  });
  expect(viewerWriteDenied.status()).toBe(403);
});

test("local login supports TOTP, CSRF protection and sudo reauth", async ({ request }) => {
  const originalBundle = await exportConfigBundleWithAuthFallback(request);
  const cleanupToken = await requestWithAuthFallback(request, "post", "/api/auth/tokens", {
    data: { name: "e2e-cleanup-admin", kind: "pat", scopes: ["admin:*"] }
  });
  await expect(cleanupToken).toBeOK();
  const cleanupBearer = `Bearer ${(await cleanupToken.json()).token}`;

  try {
    const update = await requestWithAuthFallback(request, "post", "/api/auth/config", {
      data: {
        settings: {
          mode: "basic",
          basic: {
            username: BASIC_USER,
            password: BASIC_PASSWORD,
            realm: "klaxond"
          }
        }
      }
    });
    await expect(update).toBeOK();

    const basic = `Basic ${Buffer.from(`${BASIC_USER}:${BASIC_PASSWORD}`).toString("base64")}`;
    const basicMutationDenied = await request.post("/api/cascade/toggle", {
      headers: { Authorization: basic },
      data: {}
    });
    expect(basicMutationDenied.status()).toBe(403);
    expect(await basicMutationDenied.text()).toContain("CSRF");

    const setup = await request.post("/api/auth/totp/setup/start", {
      headers: { Authorization: cleanupBearer },
      data: {}
    });
    await expect(setup).toBeOK();
    const setupBody = await setup.json();
    expect(setupBody.secret).toMatch(/^[A-Z2-7]+$/);
    expect(setupBody.otpauth_uri).toContain("otpauth://totp/");

    const enable = await request.post("/api/auth/totp/setup/confirm", {
      headers: { Authorization: cleanupBearer },
      data: { secret: setupBody.secret, code: totp(setupBody.secret) }
    });
    await expect(enable).toBeOK();

    const noTotp = await request.post("/api/auth/local/login", {
      headers: { "X-Klaxond-Request": "fetch" },
      data: { username: BASIC_USER, password: BASIC_PASSWORD, return_to: "/status" }
    });
    expect(noTotp.status()).toBe(401);
    expect(await noTotp.text()).toContain("TOTP");

    const login = await request.post("/api/auth/local/login", {
      headers: { "X-Klaxond-Request": "fetch" },
      data: {
        username: BASIC_USER,
        password: BASIC_PASSWORD,
        totp: totp(setupBody.secret),
        return_to: "/status"
      }
    });
    await expect(login).toBeOK();
    const loginBody = await login.json();
    expect(loginBody.csrf).toMatch(/^klx_csrf_/);

    const me = await request.get("/api/auth/me");
    await expect(me).toBeOK();
    const csrf = (await me.json()).csrf;
    expect(csrf).toBe(loginBody.csrf);

    const missingCsrf = await request.post("/api/cascade/toggle", { data: {} });
    expect(missingCsrf.status()).toBe(403);
    expect(await missingCsrf.text()).toContain("CSRF");

    const needsSudo = await request.post("/api/cascade/toggle", {
      headers: { "X-Klaxond-CSRF": csrf },
      data: {}
    });
    expect(needsSudo.status()).toBe(428);
    expect(needsSudo.headers()["x-klaxond-reauth"]).toBe("required");

    const badSudo = await request.post("/api/auth/reauth", {
      headers: { "X-Klaxond-CSRF": csrf },
      data: { password: "wrong", totp: totp(setupBody.secret) }
    });
    expect(badSudo.status()).toBe(401);

    const sudo = await request.post("/api/auth/reauth", {
      headers: { "X-Klaxond-CSRF": csrf },
      data: { password: BASIC_PASSWORD, totp: totp(setupBody.secret) }
    });
    await expect(sudo).toBeOK();
    expect((await sudo.json()).sudo_until).toBeGreaterThan(Math.floor(Date.now() / 1000));

    const allowedMutation = await request.post("/api/cascade/toggle", {
      headers: { "X-Klaxond-CSRF": csrf },
      data: {}
    });
    await expect(allowedMutation).toBeOK();
  } finally {
    await restoreConfigBundle(request, originalBundle, { Authorization: cleanupBearer });
  }
});
