/// <reference types="vite/client" />
/**
 * The safety-critical merge helper behind FCP writing the Xray no-client-IP-logging
 * posture into a Remnawave config profile: it must touch ONLY log + policy, be
 * idempotent, and REFUSE a config with no inbounds (a full-replace PATCH of that
 * would wipe the node).
 *
 * Also the run around it: the hourly `logging-privacy` cron
 * (`backendServers.autoHardenLogging`) and the admin's Check / Apply
 * (`backendServers.hardenRemnawaveLogging`) store the newest check as counts in
 * appState, the cron audits only when it changed something, and it leaves a
 * backend alone while a server change holds a profile or node there.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { LOGGING_CHECK_STATE_KEY } from './backendServers';
import { hardenXrayLoggingConfig, PRIVACY_XRAY_LOG } from './lib/backends/remnawave';
import { jsonRes, mockFetch, type FetchStub } from './lib/edges/testing/mockFetch';
import { markBackendSetUp } from './lib/edges/testing/fixtures';
import { panelDigestKey } from './lib/backend/key';
import { changeToken } from './lib/backend/digest';

const modules = import.meta.glob('./**/*.*s');

type PolicyShape = {
  levels: Record<string, Record<string, unknown>>;
  system?: Record<string, unknown>;
};

const baseConfig = () => ({
  log: { loglevel: 'info' },
  inbounds: [
    {
      tag: 'vless-in',
      protocol: 'vless',
      streamSettings: { realitySettings: { privateKey: 'SECRET-KEY', shortIds: ['ab12'] } },
    },
  ],
  outbounds: [{ protocol: 'freedom' }],
  routing: { rules: [{ type: 'field', outboundTag: 'direct' }] },
});

describe('hardenXrayLoggingConfig', () => {
  test('sets the no-logging log + statsUserOnline, preserving everything else', () => {
    const src = baseConfig();
    const { config, changed } = hardenXrayLoggingConfig(src);
    expect(changed).toBe(true);
    expect(config.log).toEqual(PRIVACY_XRAY_LOG);
    expect((config.policy as PolicyShape).levels['0']!.statsUserOnline).toBe(false);
    // inbounds / outbounds / routing / Reality keys preserved verbatim
    expect(config.inbounds).toEqual(src.inbounds);
    expect(config.outbounds).toEqual(src.outbounds);
    expect(config.routing).toEqual(src.routing);
    // input is not mutated
    expect(src.log).toEqual({ loglevel: 'info' });
  });

  test('is idempotent — an already-hardened config reports no change', () => {
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    expect(hardenXrayLoggingConfig(once).changed).toBe(false);
  });

  test('recognizes a hardened config after a jsonb round-trip (key order rewritten)', () => {
    // Remnawave persists the config in a Postgres jsonb column, which reorders
    // object keys canonically (by length, then bytewise). The posture check must
    // be key-order-independent or every re-check reports "logs IPs" forever.
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    const jsonbOrderedLog = Object.fromEntries(
      Object.entries(once.log as Record<string, unknown>).sort(
        ([a], [b]) => a.length - b.length || (a < b ? -1 : 1),
      ),
    );
    expect(Object.keys(jsonbOrderedLog)).not.toEqual(Object.keys(once.log as object));
    const roundTripped = { ...once, log: jsonbOrderedLog };
    expect(hardenXrayLoggingConfig(roundTripped).changed).toBe(false);
  });

  test('an extra harmless log key does not force a rewrite; a wrong value does', () => {
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    const withExtra = { ...once, log: { ...(once.log as object), somethingElse: true } };
    expect(hardenXrayLoggingConfig(withExtra).changed).toBe(false);
    const withAccessLog = { ...once, log: { ...(once.log as object), access: '/var/log/a.log' } };
    expect(hardenXrayLoggingConfig(withAccessLog).changed).toBe(true);
  });

  test('preserves other policy levels + keys while forcing level 0 statsUserOnline off', () => {
    const src = {
      ...baseConfig(),
      policy: {
        levels: { '0': { handshake: 4 }, '1': { connIdle: 300 } },
        system: { statsInboundUplink: true },
      },
    };
    const { config } = hardenXrayLoggingConfig(src);
    const policy = config.policy as PolicyShape;
    expect(policy.levels['0']!.statsUserOnline).toBe(false);
    expect(policy.levels['0']!.handshake).toBe(4); // preserved
    expect(policy.levels['1']).toEqual({ connIdle: 300 }); // preserved
    expect(policy.system).toEqual({ statsInboundUplink: true }); // preserved
  });

  test('REFUSES a config with no inbounds (would wipe the node)', () => {
    expect(() => hardenXrayLoggingConfig({ inbounds: [], outbounds: [] })).toThrow(/inbounds/i);
    expect(() => hardenXrayLoggingConfig({ outbounds: [] })).toThrow(/inbounds/i);
  });

  test('REFUSES a non-object config', () => {
    expect(() => hardenXrayLoggingConfig(null)).toThrow();
    expect(() => hardenXrayLoggingConfig('nope')).toThrow();
    expect(() => hardenXrayLoggingConfig([1, 2])).toThrow();
  });
});

// --- the run: hourly cron + the admin's Check / Apply -------------------------------------------

type T = ReturnType<typeof convexTest>;

afterEach(() => vi.unstubAllGlobals());

const PANEL = 'https://panel.test';

/** A hardened config (what a profile looks like after Apply). */
const hardened = () => hardenXrayLoggingConfig(baseConfig()).config;

/**
 * A fake backend serving the config-profile routes. `profiles` is mutable: a
 * PATCH replaces the stored config, as the backend does. `listStatus` makes the
 * listing fail (an unreadable backend).
 */
function fakeProfiles(
  profiles: Array<{ uuid: string; name: string; config: unknown }>,
  opts: { listStatus?: number } = {},
): FetchStub & { patches: string[] } {
  const patches: string[] = [];
  const stub = mockFetch((call) => {
    if (call.method === 'GET' && call.path === '/api/config-profiles') {
      if (opts.listStatus) return jsonRes({ message: 'nope' }, opts.listStatus);
      return jsonRes({ response: { configProfiles: profiles } });
    }
    const one = /^\/api\/config-profiles\/([^/]+)$/.exec(call.path);
    if (call.method === 'GET' && one) {
      const p = profiles.find((x) => x.uuid === one[1]);
      return p ? jsonRes({ response: p }) : jsonRes({ message: 'not found' }, 404);
    }
    if (call.method === 'PATCH' && call.path === '/api/config-profiles') {
      const body = call.body as { uuid: string; config: unknown };
      const p = profiles.find((x) => x.uuid === body.uuid)!;
      p.config = body.config;
      patches.push(body.uuid);
      return jsonRes({ response: p });
    }
    // The node clocks the ledger reads around a profile write.
    if (call.method === 'GET' && call.path === '/api/nodes')
      return jsonRes({
        response: [{ uuid: 'n-1', name: 'node-one', isDisabled: false, lastStatusChange: 't0' }],
      });
    // Anything else (the post-write observe refresh) is not served here.
    return jsonRes({ message: 'not found' }, 404);
  });
  return Object.assign(stub, { patches });
}

async function seedPanel(t: T, slug = 'rw-a'): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: slug,
      slug,
      config: { type: 'remnawave', baseUrl: PANEL, apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

/** A server change (backend-write ledger op) holding `key` on the backend. */
async function holdClaim(t: T, sid: Id<'backendServers'>, key: string) {
  await t.run(async (ctx) => {
    const now = Date.now();
    const opId = await ctx.db.insert('panelOps', {
      backendServerId: sid,
      kind: 'profile',
      verb: 'patch',
      generation: 1,
      claimKeys: [key],
      label: 'test change',
      intent: '{}',
      postcondition: '{}',
      request: 'pending',
      panelState: 'unobserved',
      asyncEffect: 'none',
      open: true,
      quietLooks: 0,
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.insert('panelClaims', {
      backendServerId: sid,
      key,
      opId,
      generation: 1,
      claimedAt: now,
    });
  });
}

const auditRows = (t: T) =>
  t.run((ctx) =>
    ctx.db
      .query('auditLog')
      .collect()
      .then((rows) => rows.filter((r) => r.action.includes('logging_hardened'))),
  );

describe('logging-privacy run', () => {
  test('nothing has run: the last check is null', async () => {
    const t = convexTest(schema, modules);
    expect(await t.query(internal.backendServers.getLoggingLastCheck, {})).toBeNull();
  });

  test('the cron turns logging off where found, records counts only, audits once', async () => {
    const t = convexTest(schema, modules);
    await seedPanel(t);
    const panel = fakeProfiles([
      { uuid: 'p-log', name: 'Profile logging', config: baseConfig() },
      { uuid: 'p-ok', name: 'Profile quiet', config: hardened() },
    ]);

    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.patches).toEqual(['p-log']);
    expect(rec).toMatchObject({
      source: 'automatic',
      dryRun: false,
      panels: 1,
      panelsUnreadable: 0,
      panelsBusy: 0,
      profiles: 2,
      profilesLogging: 1,
      profilesTurnedOff: 1,
      profilesSkipped: 0,
    });

    const stored = await t.query(internal.backendServers.getLoggingLastCheck, {});
    expect(stored).toEqual(rec);
    // Counts and a time only: no profile name, backend name, address or token.
    const raw = await t.run((ctx) =>
      ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', LOGGING_CHECK_STATE_KEY))
        .unique(),
    );
    for (const leak of ['Profile', 'p-log', 'rw-a', 'panel.test', 'tok', 'SECRET'])
      expect(raw!.value).not.toContain(leak);

    const audit = await auditRows(t);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: 'system', action: 'remnawave.logging_hardened' });
    expect(audit[0]!.payload).toEqual({
      instances: 1,
      profilesChanged: 1,
      profilesTotal: 2,
      panelsUnreadable: 0,
      panelsBusy: 0,
    });

    // The heartbeat was stamped under the cron's name.
    const beat = await t.run((ctx) =>
      ctx.db
        .query('cronHeartbeats')
        .withIndex('by_name', (q) => q.eq('name', 'logging-privacy'))
        .first(),
    );
    expect(beat?.runCount).toBe(1);

    // Steady state: the next run writes nothing and audits nothing.
    const again = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.patches).toEqual(['p-log']);
    expect(again).toMatchObject({ profiles: 2, profilesLogging: 0, profilesTurnedOff: 0 });
    expect(await auditRows(t)).toHaveLength(1);
    expect(again.at).toBeGreaterThanOrEqual(rec.at);
  });

  test("the admin's Check records a manual dry run and writes nothing", async () => {
    const t = convexTest(schema, modules);
    await seedPanel(t);
    const panel = fakeProfiles([{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() }]);

    const report = await t.action(internal.backendServers.hardenRemnawaveLogging, {
      dryRun: true,
    });
    expect(report.instances[0]!.profiles[0]).toMatchObject({ hardened: false, changed: true });
    expect(panel.patches).toEqual([]);
    expect(panel.calls.some((c) => c.method !== 'GET')).toBe(false);

    expect(await t.query(internal.backendServers.getLoggingLastCheck, {})).toMatchObject({
      source: 'manual',
      dryRun: true,
      profiles: 1,
      profilesLogging: 1,
      profilesTurnedOff: 0,
    });
    expect(await auditRows(t)).toHaveLength(0);
  });

  test("the admin's Apply records a manual check; its route audits, not the run", async () => {
    const t = convexTest(schema, modules);
    await seedPanel(t);
    const panel = fakeProfiles([{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() }]);

    await t.action(internal.backendServers.hardenRemnawaveLogging, { dryRun: false });
    expect(panel.patches).toEqual(['p-log']);
    expect(await t.query(internal.backendServers.getLoggingLastCheck, {})).toMatchObject({
      source: 'manual',
      dryRun: false,
      profilesLogging: 1,
      profilesTurnedOff: 1,
    });
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('a backend a server change holds is only read and left for the next run', async () => {
    const t = convexTest(schema, modules);
    const sid = await seedPanel(t);
    const panel = fakeProfiles([{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() }]);

    for (const key of ['profile:p-log', 'node:n-1']) {
      await t.run(async (ctx) => {
        for (const c of await ctx.db.query('panelClaims').collect()) await ctx.db.delete(c._id);
      });
      await holdClaim(t, sid, key);
      expect(
        await t.query(internal.backendServers.serverChangeRunning, { backendServerId: sid }),
      ).toBe(true);
      const rec = await t.action(internal.backendServers.autoHardenLogging, {});
      expect(panel.patches).toEqual([]);
      expect(rec).toMatchObject({ panelsBusy: 1, profilesLogging: 1, profilesTurnedOff: 0 });
    }
    expect(await auditRows(t)).toHaveLength(0);

    // A claim of another kind (a Host) does not hold the profile.
    await t.run(async (ctx) => {
      for (const c of await ctx.db.query('panelClaims').collect()) await ctx.db.delete(c._id);
    });
    await holdClaim(t, sid, 'host:h-1');
    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(rec).toMatchObject({ panelsBusy: 0, profilesTurnedOff: 1 });
    expect(panel.patches).toEqual(['p-log']);
  });

  test('an unreadable backend is counted, not thrown', async () => {
    const t = convexTest(schema, modules);
    await seedPanel(t);
    fakeProfiles([], { listStatus: 500 });

    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(rec).toMatchObject({ panels: 1, panelsUnreadable: 1, profiles: 0 });
    expect(await auditRows(t)).toHaveLength(0);
  });
});

describe('logging-privacy write under the backend-write ledger', () => {
  afterEach(() => vi.unstubAllEnvs());

  /** A backend FCP set up with server changes on: its writes go through the ledger. */
  async function managed(t: T) {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const sid = await seedPanel(t);
    await markBackendSetUp(t, sid);
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('panelProfiles', {
        backendServerId: sid,
        profileUuid: 'p-log',
        name: 'Profile logging',
        shapeHash: 'shape',
        changeToken: 'cached',
        digestKeyId: 'k',
        inbounds: [],
        observedAt: now,
      });
      await ctx.db.insert('panelNodes', {
        backendServerId: sid,
        nodeUuid: 'n-1',
        name: 'node-one',
        online: true,
        isDisabled: false,
        usersOnline: 0,
        configProfileUuid: 'p-log',
        activeInboundUuids: [],
        tags: [],
        observedAt: now,
      });
    });
    expect(
      await t.query(internal.backendServers.loggingThroughLedger, { backendServerId: sid }),
    ).toBe(true);
    return sid;
  }

  const ops = (t: T) => t.run((ctx) => ctx.db.query('panelOps').collect());

  test('the write is a claimed ledger op whose token is recorded before the send', async () => {
    const t = convexTest(schema, modules);
    await managed(t);
    const profiles = [{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() as unknown }];
    const panel = fakeProfiles(profiles);

    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.patches).toEqual(['p-log']);
    expect(rec).toMatchObject({ profilesLogging: 1, profilesTurnedOff: 1, panelsBusy: 0 });

    const [op] = await ops(t);
    expect(op).toMatchObject({ kind: 'profile', verb: 'patch', objectUuid: 'p-log' });
    expect(op!.claimKeys).toEqual(['profile:p-log', 'node:n-1']);
    expect(JSON.parse(op!.intent)).toMatchObject({ logging: true });
    // The token the observer will see is the op's expected one: never a foreign edit.
    const key = (await panelDigestKey()).key;
    expect(JSON.parse(op!.postcondition).expectedToken).toBe(
      await changeToken(profiles[0]!.config, key),
    );
    expect(op!.attemptId).toBeTruthy();
  });

  test('a change that holds the profile or a node leaves it for the next run', async () => {
    const t = convexTest(schema, modules);
    const sid = await managed(t);
    const panel = fakeProfiles([{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() }]);
    await holdClaim(t, sid, 'node:n-1');

    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.patches).toEqual([]);
    expect(rec).toMatchObject({ panelsBusy: 1, profilesLogging: 1, profilesTurnedOff: 0 });
    expect((await ops(t)).filter((o) => JSON.parse(o.intent).logging)).toEqual([]);
  });

  test('a profile that moves between the preview and the send is never written', async () => {
    const t = convexTest(schema, modules);
    await managed(t);
    const profiles = [{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() as unknown }];
    // Another writer lands right after the preview read: a new transport appears.
    let reads = 0;
    const panel = mockFetch((call) => {
      if (call.method === 'GET' && call.path === '/api/config-profiles')
        return jsonRes({ response: { configProfiles: profiles } });
      if (call.method === 'GET' && call.path === '/api/config-profiles/p-log') {
        reads++;
        if (reads === 3) {
          const c = profiles[0]!.config as { inbounds: unknown[] };
          profiles[0]!.config = { ...c, inbounds: [...c.inbounds, { tag: 'new', port: 8443 }] };
        }
        return jsonRes({ response: profiles[0] });
      }
      if (call.method === 'GET' && call.path === '/api/nodes')
        return jsonRes({
          response: [{ uuid: 'n-1', name: 'node-one', isDisabled: false, lastStatusChange: 't0' }],
        });
      return jsonRes({ message: 'not found' }, 404);
    });

    const rec = await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.calls.some((c) => c.method === 'PATCH')).toBe(false);
    expect(rec).toMatchObject({ panelsBusy: 1, profilesTurnedOff: 0 });
    const [op] = await ops(t);
    expect(op).toMatchObject({ request: 'rejected_pre_mutation', open: false });
    expect(op!.errorCode).toBe('servers.profile_changed');
  });
});

describe('logging-privacy write outside the ledger: attribution survives a failed re-read', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('the token is recorded first, and a later observation counts it as FCP’s', async () => {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const t = convexTest(schema, modules);
    const sid = await seedPanel(t);
    const profiles = [{ uuid: 'p-log', name: 'Profile logging', config: baseConfig() as unknown }];
    // The fake serves no observation routes: the re-read after the write fails.
    const panel = fakeProfiles(profiles);
    const { key, keyId } = await panelDigestKey();
    await t.run((ctx) =>
      ctx.db.insert('panelProfiles', {
        backendServerId: sid,
        profileUuid: 'p-log',
        name: 'Profile logging',
        shapeHash: 'shape',
        changeToken: 'before',
        digestKeyId: keyId,
        inbounds: [],
        observedAt: Date.now(),
      }),
    );

    await t.action(internal.backendServers.autoHardenLogging, {});
    expect(panel.patches).toEqual(['p-log']);
    const written = await changeToken(profiles[0]!.config, key);

    const observe = (changeToken: string) =>
      t.mutation(internal.backendObserve.record, {
        backendServerId: sid,
        digestKeyId: keyId,
        nodes: [],
        profiles: [
          {
            profileUuid: 'p-log',
            name: 'Profile logging',
            shapeHash: 'shape',
            changeToken,
            inbounds: [],
          },
        ],
        hosts: [],
        squads: [],
      });
    const foreign = () =>
      t.run(async (ctx) =>
        (await ctx.db.query('panelProfiles').collect()).find((p) => p.profileUuid === 'p-log'),
      );

    // The next ordinary observation sees FCP's own token: not a foreign edit.
    await observe(written);
    expect((await foreign())!.foreignEditAt).toBeUndefined();
    // Somebody else's later edit still is one.
    await observe('somebody-else');
    expect((await foreign())!.foreignEditAt).toBeTypeOf('number');
  });
});
