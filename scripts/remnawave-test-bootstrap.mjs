#!/usr/bin/env bun
/**
 * Bootstrap the ephemeral Remnawave test panel (docker-compose.remnawave-test.yml)
 * and mint an admin API token for FCP's integration test.
 *
 * Flow: wait for the panel → register the first superadmin (fresh DB) or log in →
 * mint a full-scope API token. Prints two lines to STDOUT (everything else to
 * stderr) so a wrapper can capture them:
 *   REMNAWAVE_TEST_URL=http://localhost:3000
 *   REMNAWAVE_TEST_TOKEN=<token>
 *
 * Usage:  eval "$(bun scripts/remnawave-test-bootstrap.mjs)"   (then run the test)
 */
const BASE = process.env.REMNAWAVE_TEST_URL || 'http://localhost:3000';
// Remnawave requires a 24+ char password with upper + lower + digit.
const USERNAME = process.env.REMNAWAVE_TEST_USER || 'fcpadmin';
const PASSWORD = process.env.REMNAWAVE_TEST_PASS || 'FcpIntegrationTestPw12345678';

const log = (...a) => console.error('[rw-bootstrap]', ...a);

async function api(path, { method = 'GET', token, body } = {}) {
  const res = await fetch(new URL(path, BASE), {
    method,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      // Dashboard (admin-JWT) requests must identify as the browser client, or the
      // panel's JwtDefaultGuard rejects an ADMIN token with "create an API-token in
      // the dashboard". FCP's own API-token (ROLE.API) skips this check entirely.
      'x-remnawave-client-type': 'browser',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { ok: res.ok, status: res.status, json, text };
}

async function waitForPanel() {
  const deadlineMs = Date.now() + 120_000;
  let attempt = 0;
  while (Date.now() < deadlineMs) {
    attempt++;
    try {
      const r = await api('/api/auth/status');
      if (r.ok && r.json?.response) {
        log(`panel ready after ${attempt} attempt(s)`);
        return r.json.response;
      }
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`panel not ready at ${BASE} after 120s`);
}

async function main() {
  log(`target ${BASE}`);
  const status = await waitForPanel();
  log(`auth status: register=${status.isRegisterAllowed} login=${status.isLoginAllowed}`);

  // Fresh (ephemeral) DB ⇒ register the first superadmin; otherwise log in.
  let accessToken;
  if (status.isRegisterAllowed) {
    const r = await api('/api/auth/register', {
      method: 'POST',
      body: { username: USERNAME, password: PASSWORD },
    });
    if (!r.ok) throw new Error(`register failed: ${r.status} ${r.text.slice(0, 300)}`);
    accessToken = r.json.response.accessToken;
    log('registered first superadmin');
  } else {
    const r = await api('/api/auth/login', {
      method: 'POST',
      body: { username: USERNAME, password: PASSWORD },
    });
    if (!r.ok) throw new Error(`login failed: ${r.status} ${r.text.slice(0, 300)}`);
    accessToken = r.json.response.accessToken;
    log('logged in');
  }

  // Mint a long-lived, full-scope API token (this is the Bearer FCP uses).
  // NB: the api-tokens controller is mounted at `/api/tokens` (the 'api-tokens'
  // in the OpenAPI is only an RBAC resource label, not the route — same trap as
  // the HWID controller).
  const t = await api('/api/tokens', {
    method: 'POST',
    token: accessToken,
    body: { name: 'fcp-integration', expiresInDays: 3650, scopes: ['*'] },
  });
  if (!t.ok) throw new Error(`token mint failed: ${t.status} ${t.text.slice(0, 300)}`);
  const token = t.json.response.token;
  if (!token) throw new Error(`token missing in response: ${t.text.slice(0, 300)}`);
  log('minted API token');

  // The two lines the wrapper captures (stdout only).
  console.log(`REMNAWAVE_TEST_URL=${BASE}`);
  console.log(`REMNAWAVE_TEST_TOKEN=${token}`);
}

main().catch((err) => {
  log('ERROR', err.message);
  process.exit(1);
});
