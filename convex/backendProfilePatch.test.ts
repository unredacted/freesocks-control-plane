/// <reference types="vite/client" />
/**
 * The guarded config-profile edit (`POST {slug}/profiles/{uuid}/preview` then
 * `.../apply`): a read-modify-write of a profile the backend replaces wholesale
 * and offers no conditional update for.
 *
 *  - the preview writes nothing and says who feels the change;
 *  - apply is conditioned on the token the preview saw: a profile someone else
 *    changed in between is refused and NOTHING is sent;
 *  - key material passes through in memory: what was sent still carries the
 *    private key and short ids untouched, and no row, response or audit entry does;
 *  - a name an origin still hands out may not be removed;
 *  - the affected origin is claimed: a rotation or a registration started
 *    meanwhile is refused, and the bridge (the op itself) still does its work;
 *  - the claims hold until the nodes' own clocks move, not when the backend row changes;
 *  - new names are NOT activated on a listener; a new target moves its revision.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import {
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  insertPanelServer,
  markBackendSetUp,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;
const TAG = 'VLESS_RELAY_A';
const SECRETS = ['PRIVATE_KEY_VALUE', 'deadbeef00112233', 'client-uuid-1'];

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

interface Panel {
  config: any;
  node: { lastStatusChange: string | null };
  patches: any[];
}

function installPanel(): Panel {
  const panel: Panel = {
    config: {
      log: { loglevel: 'none' },
      inbounds: [
        {
          tag: TAG,
          port: 443,
          protocol: 'vless',
          settings: { clients: [{ id: 'client-uuid-1' }], decryption: 'none' },
          streamSettings: {
            network: 'tcp',
            security: 'reality',
            realitySettings: {
              target: 'target.example:443',
              serverNames: ['a.example', 'b.example', 'spare.example'],
              privateKey: 'PRIVATE_KEY_VALUE',
              shortIds: ['deadbeef00112233'],
            },
          },
        },
      ],
      outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
    },
    node: { lastStatusChange: 't0' },
    patches: [],
  };
  const json = (o: unknown) =>
    new Response(JSON.stringify({ response: o }), {
      headers: { 'content-type': 'application/json' },
    });
  const profile = () => ({
    uuid: PROFILE,
    name: 'Default',
    config: panel.config,
    inbounds: [{ uuid: INBOUND, tag: TAG }],
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      if (method === 'PATCH' && path === '/api/config-profiles') {
        const body = JSON.parse(init.body as string);
        panel.patches.push(body);
        // The backend clears client lists on write (measured).
        body.config.inbounds[0].settings.clients = [];
        panel.config = body.config;
        return json({});
      }
      if (path === '/api/nodes')
        return json([
          {
            uuid: 'n-1',
            name: 'node-one',
            isConnected: true,
            isDisabled: false,
            lastStatusChange: panel.node.lastStatusChange,
            configProfile: {
              activeConfigProfileUuid: PROFILE,
              activeInbounds: [{ uuid: INBOUND, tag: TAG }],
            },
          },
        ]);
      if (path === '/api/hosts') return json([]);
      if (path === '/api/internal-squads') return json({ internalSquads: [] });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile()] });
      if (path === `/api/config-profiles/${PROFILE}`) return json(profile());
      return json({});
    }),
  );
  return panel;
}

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const panel = installPanel();
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await markBackendSetUp(t, serverId);
  const { relayId, listenerIds } = await registerRelay(t, { listeners: [realityListener()] });
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const preview = async (ops: unknown[]) =>
    (await call('POST', `profiles/${PROFILE}/preview`, { ops })).json();
  // The fixture's node is not enrolled: an edit reaching it needs a treatment
  // (docs/servers.md "Node lifecycle", maintenance); these tests acknowledge.
  const apply = (p: any, unmanaged: 'hold' | 'acknowledge' | undefined = 'acknowledge') =>
    call('POST', `profiles/${PROFILE}/apply`, {
      ops: p.ops,
      baseToken: p.baseToken,
      expectedToken: p.expectedToken,
      inboundUuids: p.inboundUuids,
      ...(unmanaged ? { unmanaged } : {}),
    });
  return {
    t,
    serverId,
    panel,
    call,
    preview,
    apply,
    relayId,
    listenerId: listenerIds.a as Id<'relayListeners'>,
  };
}

const ADD = [
  {
    op: 'setRealityServerNames',
    inboundTag: TAG,
    names: ['a.example', 'b.example', 'spare.example', 'new.example'],
  },
];

describe('preview', () => {
  test('writes nothing, shows the non-secret change and who feels it', async () => {
    const { preview, panel } = await seed();
    const p = await preview(ADD);
    expect(panel.patches).toEqual([]);
    expect(p).toMatchObject({
      profileName: 'Default',
      changed: true,
      touchedTags: [TAG],
      restartsNodes: ['node-one'],
      affectedRelays: [{ relaySlug: 'node-one', listenerKeys: ['a'] }],
    });
    expect(p.changes[0]).toMatchObject({ field: 'serverNames', after: ADD[0].names });
    expect(p.baseToken).not.toBe(p.expectedToken);
    const blob = JSON.stringify(p);
    for (const s of SECRETS) expect(blob).not.toContain(s);
  });

  test('refusals are codes, never backend text', async () => {
    const { call } = await seed();
    const bad = await call('POST', `profiles/${PROFILE}/preview`, {
      ops: [{ op: 'setRealityServerNames', inboundTag: 'NOPE', names: ['x.example'] }],
    });
    expect((await bad.json()).error.code).toBe('servers.unknown_inbound');
    const raw = await call('POST', `profiles/${PROFILE}/preview`, {
      ops: [{ op: 'rawJson', inboundTag: TAG }],
    });
    expect(raw.status).toBe(400);
  });
});

describe('apply', () => {
  test('sends once, keeps key material intact, and holds the claims until the node clock moves', async () => {
    const { t, preview, apply, panel, call } = await seed();
    const p = await preview(ADD);
    const op = await (await apply(p)).json();
    expect(panel.patches).toHaveLength(1);
    const sent = panel.patches[0].config.inbounds[0];
    expect(sent.streamSettings.realitySettings).toMatchObject({
      serverNames: ADD[0].names,
      privateKey: 'PRIVATE_KEY_VALUE',
      shortIds: ['deadbeef00112233'],
      target: 'target.example:443',
    });
    expect(panel.patches[0].config.outbounds).toEqual([{ protocol: 'freedom', tag: 'DIRECT' }]);
    // The backend row shows the change (token matches despite the backend clearing clients)...
    expect(op).toMatchObject({
      kind: 'profile',
      panelState: 'observed',
      asyncEffect: 'pending',
      open: true,
    });
    // ...but the node has not applied it, so the claims hold.
    const keys = (await t.run((ctx) => ctx.db.query('panelClaims').collect())).map((c) => c.key);
    expect(keys.some((k) => k.startsWith('profile:'))).toBe(true);
    expect(keys.some((k) => k.startsWith('node:'))).toBe(true);
    expect(keys.some((k) => k.startsWith('relay:'))).toBe(true);
    panel.node.lastStatusChange = 't1';
    expect(await (await call('POST', `ops/${op.id}/observe`)).json()).toMatchObject({
      state: 'done',
      open: false,
    });
    expect(await t.run((ctx) => ctx.db.query('panelClaims').collect())).toEqual([]);
    // Nothing secret anywhere FCP keeps or says.
    const kept = JSON.stringify(
      await t.run(async (ctx) => ({
        ops: await ctx.db.query('panelOps').collect(),
        profiles: await ctx.db.query('panelProfiles').collect(),
        audit: await ctx.db.query('auditLog').collect(),
      })),
    );
    for (const s of SECRETS) expect(kept).not.toContain(s);
    // The cache already shows the new list.
    const cached = await t.run((ctx) => ctx.db.query('panelProfiles').collect());
    expect(cached[0].inbounds[0].reality?.serverNames).toContain('new.example');
  });

  test('a profile someone else changed since the preview is refused, and nothing is sent', async () => {
    const { preview, apply, panel } = await seed();
    const p = await preview(ADD);
    // A key rotation by another writer: invisible to the shape hash, not to the token.
    panel.config.inbounds[0].streamSettings.realitySettings.shortIds = ['ffffffff00000000'];
    const op = await (await apply(p)).json();
    expect(op).toMatchObject({
      state: 'refused',
      errorCode: 'servers.profile_changed',
      open: false,
    });
    expect(panel.patches).toEqual([]);
  });

  test('new names are NOT handed to members by the edit; an origin keeps what it had', async () => {
    const { t, preview, apply, panel, listenerId, call } = await seed();
    const op = await (await apply(await preview(ADD))).json();
    panel.node.lastStatusChange = 't1';
    await call('POST', `ops/${op.id}/observe`);
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.tlsNames!.map((n) => n.name)).toEqual(['a.example', 'b.example']);
    expect(l.revision).toBe(1);
  });

  test('a name an origin still hands out, or that is still draining, may not be removed', async () => {
    const { t, preview, apply, panel, listenerId } = await seed();
    const without = (names: string[]) => [{ op: 'setRealityServerNames', inboundTag: TAG, names }];
    const res = await apply(await preview(without(['a.example', 'spare.example'])));
    expect((await res.json()).error.code).toBe('servers.name_in_use');
    // Retired but still inside its drain: members may still hold it.
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] });
    expect(
      (await (await apply(await preview(without(['a.example', 'spare.example'])))).json()).error
        .code,
    ).toBe('servers.name_in_use');
    // A name no origin uses is free to go.
    const ok = await (await apply(await preview(without(['a.example', 'b.example'])))).json();
    expect(ok.panelState).toBe('observed');
    expect(panel.patches).toHaveLength(1);
  });

  test('the origin is claimed: a rotation and a registration are refused meanwhile; the bridge still works', async () => {
    const { t, preview, apply, panel, relayId, listenerId, call } = await seed();
    const retarget = [{ op: 'setRealityTarget', inboundTag: TAG, target: 'other.example:8443' }];
    const op = await (await apply(await preview(retarget))).json();
    expect(op.open).toBe(true);
    // The op's own bridge ran under its claim: the listener follows, and is due a retest.
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(l.realityTarget).toEqual({ address: 'other.example', port: 8443 });
    expect(l.revision).toBe(2);
    // Everyone else is refused while the claim is held.
    await expect(
      t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] }),
    ).rejects.toThrow(/panel_op_running/);
    await expect(
      registerRelay(t, { listeners: [realityListener({ originPort: 8443 })] }),
    ).rejects.toThrow(/panel_op_running/);
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    await expect(
      t.run(async (ctx) => {
        const { startRotation } = await import('./edgeRotations');
        return startRotation(
          ctx as never,
          { relayId: relay._id, kind: 'provision', trigger: 'manual' } as never,
        );
      }),
    ).rejects.toThrow();
    panel.node.lastStatusChange = 't1';
    await call('POST', `ops/${op.id}/observe`);
    // Released: the origin's own work is welcome again.
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] });
  });

  test('an origin that is already rotating is left alone', async () => {
    const { t, preview, apply, relayId, panel } = await seed();
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'provisioning',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((ctx) => ctx.db.patch(relayId, { activeRotationId: rotationId }));
    const res = await apply(await preview(ADD));
    expect((await res.json()).error.code).toBe('edge.rotation_running');
    expect(panel.patches).toEqual([]);
  });
});

describe('an edit made somewhere else', () => {
  const flagged = (t: any) =>
    t.run(async (ctx: any) => (await ctx.db.query('panelProfiles').collect())[0].foreignEditAt);

  test("FCP's own edit is never flagged, however late it is first seen", async () => {
    const { t, preview, apply, serverId } = await seed();
    await apply(await preview(ADD));
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    expect(await flagged(t)).toBeFalsy();
  });

  test('a token that moved to something no FCP change expected is flagged until acknowledged', async () => {
    const { t, panel, serverId, call } = await seed();
    // Somebody edits the profile in the backend UI: a short id, which shows in no redacted view.
    panel.config.inbounds[0].streamSettings.realitySettings.shortIds = ['0011223344556677'];
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    expect(await flagged(t)).toBeTypeOf('number');
    const tree = await (await call('GET', 'tree')).json();
    expect(tree.profiles[0].foreignEditAt).toBeTypeOf('string');
    // Reading again does not clear it: only an operator does.
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    expect(await flagged(t)).toBeTypeOf('number');
    expect((await call('POST', `profiles/${PROFILE}/acknowledge`)).status).toBe(200);
    expect(await flagged(t)).toBeFalsy();
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'servers.profile.foreign_edit_seen'))
        .collect(),
    );
    expect(audit.map((r) => r.payload)).toEqual([{ backendSlug: 'panel-a', label: 'Default' }]);
  });

  test('an edit FCP made outside the ledger (the logging harden) re-baselines instead', async () => {
    const { t, panel, serverId } = await seed();
    panel.config.log = { loglevel: 'none', access: 'none' };
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId, ownEdit: true });
    expect(await flagged(t)).toBeFalsy();
  });
});
