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
  remnawaveBulkUpdateTrafficLimit,
  remnawaveDeleteUser,
  remnawaveFleetStats,
  remnawaveGetUser,
  remnawaveGetUserUsage,
  remnawaveIssueUser,
  remnawaveMajorVersion,
  remnawaveResetTraffic,
  remnawaveResolveUserIdByShortUuid,
  remnawaveSetStatus,
  remnawaveTestConnection,
  remnawaveUpdateUser,
  type RemnawaveConfig,
} from './remnawave';

/** Poll `read` until it yields `want` (≤ ~5s), then assert — for eventually-consistent panel writes. */
async function eventually<T>(read: () => Promise<T>, want: T): Promise<void> {
  let got: T = await read();
  for (let i = 0; i < 25 && got !== want; i++) {
    await new Promise((r) => setTimeout(r, 200));
    got = await read();
  }
  expect(got).toBe(want);
}

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
    // A 2.x panel hands back the user uuid, a 3.x panel the numeric id — the
    // provider speaks both (docs/backends.md); the rest of this test is
    // shape-agnostic on purpose so it runs against either panel generation.
    expect(issued.backendUserId).toMatch(/^(?:[0-9a-f-]{36}|\d+)$/i);
    expect(issued.backendShortId).toBeTruthy();
    expect(issued.subscriptionUrl).toMatch(/^https?:\/\//);
    const uuid = issued.backendUserId;
    const is3x = /^\d+$/.test(uuid);

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

    // 2c) Fleet stats — GET /api/system/stats + /stats/recap (admin observability).
    const fleet = await remnawaveFleetStats(cfg);
    expect(typeof fleet.onlineNow).toBe('number');
    expect(typeof fleet.nodesTotal).toBe('number');
    expect(fleet.panelVersion).toBeTruthy();
    // The id shape the panel handed out must agree with the version it reports:
    // this is the invariant the 2.x→3.x key migration relies on.
    const major = remnawaveMajorVersion(fleet.panelVersion);
    expect(major).not.toBeNull();
    expect(is3x).toBe(major! >= 3);

    // 2d) Resolve by shortUuid — the migration join; must give back the same id.
    expect(await remnawaveResolveUserIdByShortUuid(cfg, issued.backendShortId)).toBe(uuid);
    expect(await remnawaveResolveUserIdByShortUuid(cfg, 'nosuchshortuuid0')).toBeNull();

    // 2e) Bulk update (the donation re-cap primitive) — `uuids` on 2.x, `userIds` on 3.x.
    //     Eventually consistent on BOTH generations (3.x answers 202 Accepted; a
    //     read right after the write can still show the old value), so poll —
    //     the donation re-cap never reads back synchronously either.
    await remnawaveBulkUpdateTrafficLimit(cfg, [uuid], 15 * GIB);
    await eventually(async () => (await remnawaveGetUser(cfg, uuid)).trafficLimitBytes, 15 * GIB);

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
