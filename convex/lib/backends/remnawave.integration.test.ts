// @vitest-environment node
/**
 * END-TO-END integration test: drives FCP's Remnawave provider against a REAL,
 * live Remnawave panel (docker-compose.remnawave-test.yml, pinned to the latest
 * release). This is the safety net the mocked unit suite can't be — it would have
 * caught the endpoint-path + response-shape drift we hit twice (the PATCH-with-
 * uuid-in-body update and the /api/hwid/devices/* paths), because here a wrong
 * path or shape fails against the actual API, not a mock of our own assumptions.
 *
 * Gated: skipped unless REMNAWAVE_TEST_URL + REMNAWAVE_TEST_TOKEN are set (the
 * bootstrap script exports them). Excluded from the fast offline suite; run via
 * `bun run test:integration:remnawave`.
 */
import { describe, expect, test } from 'vitest';
import {
  remnawaveDeleteUser,
  remnawaveGetUser,
  remnawaveGetUserUsage,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveSetStatus,
  remnawaveTestConnection,
  remnawaveUpdateUser,
  type RemnawaveConfig,
} from './remnawave';

const BASE_URL = process.env.REMNAWAVE_TEST_URL;
const API_TOKEN = process.env.REMNAWAVE_TEST_TOKEN;
const GIB = 1024 ** 3;

describe.skipIf(!BASE_URL || !API_TOKEN)('remnawave provider — real panel (integration)', () => {
  const cfg: RemnawaveConfig = { baseUrl: BASE_URL!, apiToken: API_TOKEN!, timeoutMs: 15_000 };
  // Unique per run; Remnawave usernames are [a-zA-Z0-9_-], 3-36 chars.
  const username = `fcp_it_${Date.now()}`;

  test('drives the full user lifecycle against the live API', async () => {
    // 0) Reachability + auth (the health probe path + Bearer).
    const conn = await remnawaveTestConnection(cfg);
    expect(conn.ok).toBe(true);

    // 1) Issue — POST /api/users; response maps to our IssuedUser.
    const issued = await remnawaveIssueUser(cfg, {
      username,
      trafficLimitBytes: 10 * GIB,
      trafficLimitStrategy: 'MONTH',
      expireAt: null, // → far-future sentinel; FCP owns lifecycle
      tag: 'member',
    });
    expect(issued.backendUserId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(issued.backendShortId).toBeTruthy();
    expect(issued.subscriptionUrl).toMatch(/^https?:\/\//);
    const uuid = issued.backendUserId;

    // 2) Get — GET /api/users/{uuid}; asserts the Phase-1 enriched fields parse,
    //    and that the HWID list path (GET /api/hwid/devices/{uuid}) returns [].
    const state = await remnawaveGetUser(cfg, uuid);
    expect(state.status).toBe('active');
    expect(state.trafficLimitBytes).toBe(10 * GIB);
    expect(typeof state.usedTrafficBytes).toBe('number');
    expect(state.trafficLimitStrategy).toBe('MONTH');
    expect(
      state.lastTrafficResetAt === undefined || typeof state.lastTrafficResetAt === 'string',
    ).toBe(true);
    expect(state.devices).toEqual([]);

    // 2b) Usage — GET /api/bandwidth-stats/users/{uuid} (aggregate sparkline).
    //     A fresh user has no traffic yet, so total is 0, but the path + shape parse.
    const usage = await remnawaveGetUserUsage(cfg, uuid, 7);
    expect(Array.isArray(usage.points)).toBe(true);
    expect(Array.isArray(usage.labels)).toBe(true);
    expect(usage.total).toBeGreaterThanOrEqual(0);

    // 3) Update — PATCH /api/users with uuid in the BODY (the headline bug we
    //    fixed). Prove it landed by reading the changed limit back.
    await remnawaveUpdateUser(cfg, uuid, { trafficLimitBytes: 20 * GIB });
    expect((await remnawaveGetUser(cfg, uuid)).trafficLimitBytes).toBe(20 * GIB);

    // 4) Status — POST /api/users/{uuid}/actions/{disable,enable}.
    await remnawaveSetStatus(cfg, uuid, false);
    expect((await remnawaveGetUser(cfg, uuid)).status).toBe('disabled');
    await remnawaveSetStatus(cfg, uuid, true);
    expect((await remnawaveGetUser(cfg, uuid)).status).toBe('active');

    // 5) Reset traffic — POST /api/users/{uuid}/actions/reset-traffic.
    await expect(remnawaveResetTraffic(cfg, uuid)).resolves.toBeUndefined();

    // 6) Delete — DELETE /api/users/{uuid}; idempotent (a second delete 404s → ok),
    //    and the user is really gone afterward.
    await expect(remnawaveDeleteUser(cfg, uuid)).resolves.toBeUndefined();
    await expect(remnawaveDeleteUser(cfg, uuid)).resolves.toBeUndefined();
    await expect(remnawaveGetUser(cfg, uuid)).rejects.toThrow();
  });
});
