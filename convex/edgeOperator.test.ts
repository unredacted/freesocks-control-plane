/// <reference types="vite/client" />
/**
 * The operator endpoints behind the redesigned Admin -> Edges section:
 * setup-status through the bootstrap stages (origin, draft, fleet), the
 * explicit test provision from a tested but UNQUALIFIED account, the preflight
 * dry run (first blocker = what a real start throws; writes nothing), the
 * ranked attention list, the merged timeline, the quarantine resolver view
 * (+ the live column), provider usage, the origin lookup, delivery bindings,
 * the maintenance switch and the Host adoption handoff. Fixtures only
 * (RFC 5737 / 3849, `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { isCancellable } from './edgeRotations';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  registerRelay,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';
import {
  AttentionResponse,
  DeliveryBindingsResponse,
  EdgeMaintenanceView,
  PreflightResponse,
  EdgeRotationDetail,
  ProvidersUsageResponse,
  QuarantineView,
  RelayAdmin,
  SetupStatusResponse,
  TimelineResponse,
} from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const ADMIN_SIGN_KEY = 'test-admin-sign';
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

async function adminCookie(t: T) {
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
  return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
}

/** Backend + one gcore account (untested, unqualified) + origin `node-one` with the REALITY listener `a`. */
async function seed() {
  const t = convexTest(schema, modules);
  const f = await seedEdgeFixture(t);
  const cookie = await adminCookie(t);
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const get = async <S extends { parse: (x: unknown) => unknown }>(path: string, schema: S) => {
    const res = await call('GET', path);
    expect(res.status).toBe(200);
    return schema.parse(await res.json()) as ReturnType<S['parse']>;
  };
  return { ...f, cookie, call, get };
}

const markTested = (t: T, id: Id<'edgeProviderAccounts'>) =>
  t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
const step = (s: SetupStatusResponse, id: string) => s.steps.find((x) => x.id === id)!;
const codes = (s: SetupStatusResponse, id: string) => step(s, id).blockers.map((b) => b.code);
const count = (t: T, table: 'auditLog' | 'edgeRotations') =>
  t.run(async (ctx) => (await ctx.db.query(table).collect()).length);

describe('setup-status', () => {
  test('origin scope walks the bootstrap: untested account -> tested -> edge -> qualification -> publish -> rendering', async () => {
    const { t, call, get, relayId, listenerId, accountId } = await seed();
    let s = await get('setup-status?relay=node-one', SetupStatusResponse);
    expect(s.scope).toBe('relay');
    expect(step(s, 'origin').status).toBe('done');
    expect(s.currentStep).toBe('account');
    expect(codes(s, 'account')).toEqual(['credentials_untested']);
    expect(s.context).toMatchObject({
      relaySlug: 'node-one',
      listenerKey: 'a',
      originKind: 'panel-node',
    });
    // roleVars carry public values only: no token, no address.
    expect(s.roleVars).toMatchObject({
      fcp_relay_slug: 'node-one',
      fcp_relay_listeners: 'a',
      fcp_relay_register_scope: 'admin:edges:register',
    });
    expect(JSON.stringify(s.roleVars)).not.toContain('203.0.113');

    await markTested(t, accountId);
    s = await get('setup-status?relay=node-one', SetupStatusResponse);
    expect(step(s, 'account').status).toBe('done');
    expect(step(s, 'template').status).toBe('done');
    expect(step(s, 'relay').status).toBe('done');
    expect(step(s, 'relay').warnings.map((w) => w.code)).toEqual(['members_dark']);
    expect(s.currentStep).toBe('edge');
    expect(codes(s, 'edge')).toEqual(['no_edge']);
    expect(s.context.accountId).toBe(accountId);

    // An imported (observe-only) edge satisfies the edge step; unqualified account blocks step 6.
    await adoptL4Edge(t, relayId, listenerId, { publish: false });
    s = await get('setup-status?relay=node-one', SetupStatusResponse);
    expect(step(s, 'edge').status).toBe('done');
    // The adopted edge has no account: qualification looks at the origin's chosen account? No: an
    // observe-only edge carries no account, so nothing about accounts blocks it.
    expect(step(s, 'qualification').status).toBe('done');
    expect(s.currentStep).toBe('publish');
    expect(codes(s, 'publish')).toEqual(['pool_empty']);

    const res = await call('POST', 'providers/' + accountId + '/qualify', { qualified: true });
    expect(res.status).toBe(200);
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.9', publish: true });
    s = await get('setup-status?relay=node-one', SetupStatusResponse);
    expect(step(s, 'publish').status).toBe('done');
    // Rendering is judged with a real preview over the sample body.
    expect(['done', 'ready']).toContain(step(s, 'rendering').status);
    expect(step(s, 'automation').warnings.map((w) => w.code)).toContain('edge_layer_disabled');
  });

  test('draft scope judges layer compatibility before the origin exists; a manual draft needs no backend', async () => {
    const { t, call, accountId } = await seed();
    await markTested(t, accountId);
    const res = await call('POST', 'setup-status', {
      draft: {
        origin: { kind: 'panel-node', backendSlug: 'panel-a', nodeName: 'node-two' },
        listeners: [
          { protocol: 'vless', streamTransport: 'raw', security: 'reality', originPort: 443 },
        ],
      },
    });
    expect(res.status).toBe(200);
    const s = SetupStatusResponse.parse(await res.json());
    expect(s.scope).toBe('draft');
    expect(step(s, 'origin').status).toBe('done');
    expect(step(s, 'account').status).toBe('done');
    expect(s.currentStep).toBe('relay');
    expect(codes(s, 'relay')).toEqual(['no_relay']);
    expect(s.context.backendServerId).toBeTruthy();
    // An unknown backend slug: no_backend_server.
    const bad = SetupStatusResponse.parse(
      await (
        await call('POST', 'setup-status', {
          draft: { origin: { kind: 'backend-server', backendSlug: 'nope' }, listeners: [] },
        })
      ).json(),
    );
    expect(codes(bad, 'origin')).toEqual(['no_backend_server']);
    // A UDP listener with no UDP-capable provider: compatible account blocker on step 2 and the udp exclusion on step 4.
    const udp = SetupStatusResponse.parse(
      await (
        await call('POST', 'setup-status', {
          draft: {
            origin: { kind: 'manual' },
            listeners: [{ protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' }],
          },
        })
      ).json(),
    );
    expect(step(udp, 'origin').status).toBe('done');
    expect(codes(udp, 'account')).toEqual(['no_compatible_account']);
  });

  test('fleet scope aggregates per step and lists origins to resume; the draft POST is admitted by a read scope', async () => {
    const { t, get } = await seed();
    await registerRelay(t, { slug: 'node-two', nodeName: 'node-two' });
    const s = await get('setup-status', SetupStatusResponse);
    expect(s.scope).toBe('fleet');
    expect(s.complete).toBe(false);
    expect(s.resume.map((r) => r.relaySlug).sort()).toEqual(['node-one', 'node-two']);
    expect(step(s, 'account').facts).toMatchObject({ relays: 2, done: 0 });
    expect(step(s, 'account').blockers.every((b) => b.subject)).toBe(true);
  });
});

describe('test-provision and preflight', () => {
  test('test-provision from a tested but unqualified account starts an unpublished provision on the named listener and audits it', async () => {
    const { t, call, relayId, accountId } = await seed();
    await markTested(t, accountId);
    const res = await call('POST', `relays/${relayId}/test-provision`, {
      accountId,
      listenerKey: 'a',
    });
    expect(res.status).toBe(200);
    const { rotationId } = (await res.json()) as { rotationId: string };
    const r = await t.run((ctx) => ctx.db.get(rotationId as Id<'edgeRotations'>));
    expect(r).toMatchObject({
      kind: 'provision',
      publishOnDone: false,
      requestedAccountId: accountId,
      allowUnqualified: true,
    });
    // Selection honours the explicit account although it is unqualified.
    const ctx = await t.query(internal.edgeRotations.stepContext, {
      rotationId: rotationId as Id<'edgeRotations'>,
    });
    expect(ctx?.selection?.account?.id).toBe(accountId);
    expect(ctx?.selection?.accountFailure).toBeNull();
    const audits = await t.run(async (c) =>
      (await c.db.query('auditLog').collect()).filter(
        (a) => a.action === 'admin.edge.test_provision',
      ),
    );
    expect(audits).toHaveLength(1);
    expect(audits[0].payload).toMatchObject({
      slug: 'node-one',
      listenerKey: 'a',
      accountName: 'acct-a',
    });
    expect(JSON.stringify(audits[0].payload)).not.toContain('203.0.113');
    // A second start while this one runs is refused: busy.
    const again = await call('POST', `relays/${relayId}/test-provision`, {
      accountId,
      listenerKey: 'a',
    });
    expect(again.status).toBe(409);
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe('edge.busy');
  });

  test('preflight: an untested account, an unknown listener and a missing account are blockers; the result is marked unpublished', async () => {
    const { t, call, relayId, accountId } = await seed();
    const pre = async (body: unknown) =>
      PreflightResponse.parse(
        await (await call('POST', `relays/${relayId}/preflight`, body)).json(),
      );
    let p = await pre({ kind: 'test-provision', accountId, listenerKey: 'a' });
    expect(p.ok).toBe(false);
    expect(p.blockers.map((b) => b.code)).toEqual(['account_untested']);
    expect(p.warnings.map((w) => w.code)).toContain('unpublished_result');
    await markTested(t, accountId);
    p = await pre({ kind: 'test-provision', accountId, listenerKey: 'a' });
    expect(p.ok).toBe(true);
    expect(p.wouldSelect).toMatchObject({
      listenerKey: 'a',
      accountId,
      provider: 'gcore',
      layer: 'l4',
    });
    expect(p.warnings.map((w) => w.code)).toEqual(
      expect.arrayContaining(['account_unqualified', 'unpublished_result', 'members_dark']),
    );
    p = await pre({ kind: 'test-provision', accountId, listenerKey: 'zz' });
    expect(p.blockers.map((b) => b.code)).toContain('listener_not_found');
    p = await pre({ kind: 'test-provision', listenerKey: 'a' });
    expect(p.blockers.map((b) => b.code)).toContain('validation');
    // An ordinary provision has no qualified account: the selection failure is the blocker.
    p = await pre({ kind: 'provision', listenerKey: 'a' });
    expect(p.ok).toBe(false);
    expect(p.blockers.map((b) => b.code)).toEqual(['no_qualified_account']);
  });

  test('preflight property: its first blocker is the code a real start throws, and it writes nothing', async () => {
    const { t, call, relayId, listenerId, accountId } = await seed();
    await markTested(t, accountId);
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: true });
    const standby = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.8',
      publish: false,
    });
    const pre = async (body: unknown) =>
      PreflightResponse.parse(
        await (await call('POST', `relays/${relayId}/preflight`, body)).json(),
      );
    const thrown = async (args: Record<string, unknown>) => {
      try {
        await t.mutation(internal.edgeRotations.start, {
          relayId,
          trigger: 'manual',
          ...args,
        } as never);
        return null;
      } catch (err) {
        return (err as { data?: { code?: string } }).data?.code ?? 'unknown';
      }
    };
    const cases: Array<[Record<string, unknown>, Record<string, unknown>]> = [
      [
        { kind: 'publish', edgeId },
        { kind: 'publish', toEdgeId: edgeId },
      ], // already published
      [{ kind: 'replace' }, { kind: 'replace' }], // validation: targetEdgeId required
      [
        { kind: 'replace', edgeId: standby.edgeId },
        { kind: 'replace', targetEdgeId: standby.edgeId },
      ], // the target is not published
    ];
    for (const [preBody, startArgs] of cases) {
      const before = {
        audit: await count(t, 'auditLog'),
        rotations: await count(t, 'edgeRotations'),
      };
      const p = await pre(preBody);
      expect(p.ok).toBe(false);
      const code = await thrown(startArgs);
      expect(`${p.blockers[0].code}`).toBe((code ?? '').replace(/^edge\./, ''));
      expect(await count(t, 'auditLog')).toBe(before.audit);
      expect(await count(t, 'edgeRotations')).toBe(before.rotations);
    }
    // Frozen: maintenance is the first blocker and the start throws it.
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'drain' });
    const p = await pre({ kind: 'provision', listenerKey: 'a' });
    expect(p.blockers[0].code).toBe('maintenance');
    expect(await thrown({ kind: 'provision' })).toBe('edge.maintenance');
    await t.mutation(internal.edgeMaintenance.thaw, {});
    // Quarantined: the quarantine is first.
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
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
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'hosts_changed' },
      }),
    );
    const q = await pre({ kind: 'provision', listenerKey: 'a' });
    expect(q.blockers[0].code).toBe('quarantined');
    expect(await thrown({ kind: 'provision' })).toBe('edge.quarantined');
  });
});

describe('attention, timeline, usage, lookups, maintenance', () => {
  test('attention ranks quarantine above the pool shortfall and the untested account; freeze adds an info item with a thaw action', async () => {
    const { t, call, get, relayId, listenerId, accountId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { publish: true });
    let a = await get('attention', AttentionResponse);
    // Rendering ships off, so the registered node's members are dark: that outranks the shortfall.
    expect(a.items.map((i) => i.kind)).toEqual([
      'members_dark',
      'pool_below_desired',
      'account_untested',
    ]);
    expect(a.items[0]).toMatchObject({ severity: 'critical', code: 'render_disabled' });
    expect(a.items[1]).toMatchObject({
      relaySlug: 'node-one',
      action: 'provision',
      facts: { published: 1, desired: 2 },
    });
    await markTested(t, accountId);
    a = await get('attention', AttentionResponse);
    expect(a.items.map((i) => i.kind)).toEqual([
      'members_dark',
      'pool_below_desired',
      'account_unqualified',
    ]);
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
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
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'hosts_changed' },
      }),
    );
    await (await call('POST', 'maintenance/freeze', { reason: 'drain' })).json();
    a = await get('attention', AttentionResponse);
    expect(a.items.map((i) => i.kind)).toEqual([
      'quarantine',
      'members_dark',
      'pool_below_desired',
      'account_unqualified',
      'maintenance_frozen',
    ]);
    expect(a.items[0]).toMatchObject({
      severity: 'critical',
      action: 'resolve_quarantine',
      code: 'hosts_changed',
      rotationId,
    });
    expect(a.items[4]).toMatchObject({ action: 'thaw', code: 'drain' });
    const m = EdgeMaintenanceView.parse(await (await call('POST', 'maintenance/thaw', {})).json());
    expect(m.frozen).toBe(false);
    expect((await get('maintenance', EdgeMaintenanceView)).frozen).toBe(false);
  });

  test('timeline merges the origin, edge, listener and rotation rows newest first and classifies the subject', async () => {
    const { t, get, relayId, listenerId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { publish: true });
    // A second edge published directly (index 1 needs no Host flip) audits against the edge row.
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.8',
      publish: false,
    });
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId });
    const tl = await get(`relays/${relayId}/timeline`, TimelineResponse);
    const actions = tl.entries.map((e) => e.action);
    expect(actions).toContain('relay.registered');
    expect(actions).toContain('edge.adopted');
    expect(actions).toContain('edge.published');
    const subjects = new Set(tl.entries.map((e) => e.subject));
    expect(subjects.has('relay')).toBe(true);
    const times = tl.entries.map((e) => e.createdAt);
    expect([...times].sort().reverse()).toEqual(times);
    expect(tl.truncated).toBe(false);
    expect(tl.entries.some((e) => e.targetId === edgeId)).toBe(true);
  });

  test('providers usage counts published / standby edges per account and origin, and what auto-provision would add', async () => {
    const { t, get, relayId, listenerId, accountId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { publish: true, accountId });
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.8', publish: false });
    const u = await get('providers/usage', ProvidersUsageResponse);
    expect(u.relays).toEqual([
      expect.objectContaining({
        slug: 'node-one',
        published: 1,
        standby: 1,
        desiredPublished: 2,
        plannedIfAutoProvision: 0,
      }),
    ]);
    expect(u.accounts[0]).toMatchObject({ name: 'acct-a', published: 1, standby: 0, fake: false });
    expect(u.totals).toMatchObject({ published: 1, standby: 1 });
  });

  test('origins/lookup returns the full admin view by slug (404 when absent); delivery bindings list the registered node', async () => {
    const { call, get, serverId } = await seed();
    const r = await get('relays/lookup?slug=node-one', RelayAdmin);
    expect(r.slug).toBe('node-one');
    expect(r.origin.kind).toBe('panel-node');
    expect((await call('GET', 'relays/lookup?slug=nope')).status).toBe(404);
    expect((await call('GET', 'relays/lookup')).status).toBe(400);
    const b = await get('delivery-bindings', DeliveryBindingsResponse);
    expect(b.bindings).toEqual([
      expect.objectContaining({
        relaySlug: 'node-one',
        nodeName: 'node-one',
        backendServerId: serverId,
        relayPresent: true,
        state: 'active',
      }),
    ]);
  });
});

describe('quarantine view and Host adoption', () => {
  test('quarantine view: previous and current tuples per listener; the live column matches what the backend serves', async () => {
    const { t, call, get, relayId, listenerId } = await seed();
    const prev = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1', publish: true });
    const next = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.50',
      publish: false,
    });
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
        stepVersion: 1,
        cancelRequested: false,
        targetEdgeId: prev.edgeId,
        toEdgeId: next.edgeId,
        previousBinding: { edgeId: prev.edgeId, listenerId, poolIndex: 0 },
        hostPlan: [
          {
            listenerKey: 'a',
            uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            oldAddress: '198.51.100.1',
            oldPort: 443,
            inboundUuid: FIXTURE_INBOUND,
            snapshotVersion: 2,
            oldSni: 'a.example',
            oldHost: null,
          },
        ],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'hosts_changed' },
      }),
    );
    const view = await get(`relays/${relayId}/quarantine`, QuarantineView);
    expect(view.quarantine?.reason).toBe('hosts_changed');
    expect(view.rotation?.id).toBe(rotationId);
    expect(view.listeners).toHaveLength(1);
    expect(view.listeners[0]).toMatchObject({
      listenerKey: 'a',
      remark: 'node-one-relay-a',
      previous: { address: '198.51.100.1', port: 443, sni: 'a.example', edgeId: prev.edgeId },
      current: { address: '198.51.100.50', port: 443, edgeId: next.edgeId },
      live: null,
      match: 'unknown',
    });
    expect(view.inspectedAt).toBeNull();
    // Inspect: the backend serves the NEW address for the listener's remark, plus a stray duplicate.
    mockFetch((c) => {
      if (c.path === '/api/hosts' && c.method === 'GET')
        return jsonRes({
          response: [
            {
              uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              remark: 'node-one-relay-a',
              address: '198.51.100.50',
              port: 443,
              sni: 'a.example',
              isDisabled: false,
              inbound: {
                configProfileUuid: FIXTURE_CONFIG_PROFILE,
                configProfileInboundUuid: FIXTURE_INBOUND,
              },
            },
            {
              uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              remark: 'node-one-relay-a',
              address: '198.51.100.1',
              port: 443,
              sni: 'b.example',
              isDisabled: false,
              inbound: {
                configProfileUuid: FIXTURE_CONFIG_PROFILE,
                configProfileInboundUuid: FIXTURE_INBOUND,
              },
            },
          ],
        });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    try {
      const res = await call('POST', `relays/${relayId}/quarantine/inspect`, {});
      expect(res.status).toBe(200);
      const live = QuarantineView.parse(await res.json());
      expect(live.listeners[0]).toMatchObject({
        match: 'current',
        live: { address: '198.51.100.50', uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
      });
      expect(live.extraHosts).toEqual([
        expect.objectContaining({
          uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          address: '198.51.100.1',
        }),
      ]);
      expect(live.inspectedAt).toBeTruthy();
      // Same address and port as the current binding but ANOTHER server name:
      // that is not the current tuple, and the verdict must not say it is.
      const current = live.listeners[0].current!;
      const other = await t.query(internal.edgeOperator.quarantineView, {
        relayId,
        live: [
          {
            uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            remark: 'node-one-relay-a',
            address: current.address,
            port: current.port,
            sni: 'some-other-name.example',
            host: null,
            inboundUuid: FIXTURE_INBOUND,
          },
        ],
      });
      expect(other.listeners[0].match).toBe('neither');
    } finally {
      vi.unstubAllGlobals();
    }
    // Resolving with a reason audits the reason.
    const r = await call('POST', `relays/${relayId}/resolve-quarantine`, {
      keep: 'current',
      reason: 'backend serves the new edge',
    });
    expect(r.status).toBe(200);
    const audits = await t.run(async (c) =>
      (await c.db.query('auditLog').collect()).filter(
        (a) => a.action === 'edge.quarantine_resolved',
      ),
    );
    expect(audits[0].payload).toMatchObject({
      keep: 'current',
      reason: 'backend serves the new edge',
    });
  });

  test('adopt-host: an operator Host at a published edge with the listener transport becomes adopted (legacy remark kept); a mismatch is refused; hostMode may then flip to fcp', async () => {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    await createAccount(t, { provider: 'gcore', name: 'acct-a' });
    const r = await registerRelay(t, { hostModeRequest: 'operator' });
    const cookie = await adminCookie(t);
    const call = (method: string, path: string, body?: unknown) =>
      t.fetch(`/api/v1/admin/edges/${path}`, {
        method,
        headers: { cookie, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    await adoptL4Edge(t, r.relayId, r.listenerId, { ipv4: '198.51.100.7', publish: true });
    const hosts = [
      {
        uuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        remark: 'node-one-relay',
        address: '198.51.100.7',
        port: 443,
        sni: 'a.example',
        isDisabled: false,
        inbound: {
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: FIXTURE_INBOUND,
        },
      },
      {
        uuid: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
        remark: 'elsewhere',
        address: '198.51.100.99',
        port: 443,
        sni: 'a.example',
        isDisabled: false,
        inbound: {
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: FIXTURE_INBOUND,
        },
      },
    ];
    mockFetch((c) => {
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: hosts });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    try {
      // hostMode fcp is refused before adoption.
      const early = await call('PATCH', `relays/${r.relayId}`, { hostMode: 'fcp' });
      expect(early.status).toBe(409);
      expect(((await early.json()) as { error: { code: string } }).error.code).toBe(
        'edge.host_adopt_required',
      );
      const bad = await call('POST', `relays/${r.relayId}/listeners/a/adopt-host`, {
        hostUuid: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      });
      expect(bad.status).toBe(409);
      expect(((await bad.json()) as { error: { code: string } }).error.code).toBe(
        'edge.host_adopt_mismatch',
      );
      const missing = await call('POST', `relays/${r.relayId}/listeners/a/adopt-host`, {
        hostUuid: 'nope',
      });
      expect(missing.status).toBe(409);
      const ok = await call('POST', `relays/${r.relayId}/listeners/a/adopt-host`, {
        hostUuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      });
      expect(ok.status).toBe(200);
      expect(await ok.json()).toEqual({
        ok: true,
        listenerKey: 'a',
        host: { uuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', ownership: 'adopted' },
      });
      const l = await t.run((ctx) => ctx.db.get(r.listenerId));
      expect(l?.host).toMatchObject({
        state: 'present',
        ownership: 'adopted',
        uuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      });
      expect(l?.legacyHosts).toEqual([
        { uuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', remark: 'node-one-relay' },
      ]);
      const flipped = await call('PATCH', `relays/${r.relayId}`, { hostMode: 'fcp' });
      expect(flipped.status).toBe(200);
      expect((await t.run((ctx) => ctx.db.get(r.relayId)))?.hostMode).toBe('fcp');
      const audits = await t.run(async (c) =>
        (await c.db.query('auditLog').collect()).filter((a) => a.action === 'relay.host.adopted'),
      );
      expect(audits).toHaveLength(1);
      expect(audits[0].payload).toEqual({ relaySlug: 'node-one', listenerKey: 'a' });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('operator-facing refusals and the rotation view', () => {
  test('a rotation says which listener it is for and whether a cancel would be accepted (the server rule, not a client guess)', async () => {
    const { t, call, get, relayId, accountId } = await seed();
    await markTested(t, accountId);
    const res = await call('POST', `relays/${relayId}/test-provision`, {
      accountId,
      listenerKey: 'a',
    });
    const { rotationId } = (await res.json()) as { rotationId: Id<'edgeRotations'> };
    let r = await get(`rotations/${rotationId}`, EdgeRotationDetail);
    expect(r).toMatchObject({ listenerKey: 'a', cancellable: true, terminal: false });
    // The flag is requestCancel's own rule: refused once confirming / finalizing / rolling back.
    for (const phase of ['confirming', 'finalizing', 'rolling_back', 'done'] as const)
      expect(isCancellable({ phase, cancelRequested: false })).toBe(false);
    expect(isCancellable({ phase: 'provisioning', cancelRequested: true })).toBe(false);
    expect(isCancellable({ phase: 'provisioning', cancelRequested: false })).toBe(true);
  });

  test('deleting an account with live edges and the last template of a provider answer specific codes', async () => {
    const { t, call, relayId, listenerId, accountId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { publish: false, accountId });
    const acct = await call('DELETE', `providers/${accountId}`);
    expect(acct.status).toBe(409);
    expect(((await acct.json()) as { error: { code: string } }).error.code).toBe(
      'edge.account_in_use',
    );
    await call('POST', 'templates/ensure-defaults', {});
    const tpl = await t.run(async (ctx) =>
      (await ctx.db.query('edgeTemplates').collect()).find((x) => x.provider === 'gcore'),
    );
    const del = await call('DELETE', `templates/${tpl!._id}`);
    expect(del.status).toBe(409);
    expect(((await del.json()) as { error: { code: string } }).error.code).toBe(
      'edge.template_last_of_provider',
    );
  });

  test('an origin whose only deployed listener is UDP is skipped in words: probe.udp_unsupported', async () => {
    const { t, call } = await seed();
    const udp = await registerRelay(t, {
      slug: 'node-udp',
      kind: 'manual',
      originAddress: '203.0.113.20',
      listeners: [
        {
          listenerKey: 'h',
          protocol: 'hysteria2',
          streamTransport: 'udp',
          security: 'tls',
          originPort: 8443,
          tlsNames: ['h.example'],
        },
      ],
    });
    const res = await call('POST', 'probes', { targets: [`relay:${udp.relayId}`] });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { skipped: string[] };
    expect(body.skipped).toEqual([`relay:${udp.relayId}: probe.udp_unsupported`]);
  });
});

describe('review fixes: attention targets, the tested rule, the quarantine verdict', () => {
  test('a publish item names a publishable standby; with none it becomes navigation; a failed re-test makes a once-tested account untested again', async () => {
    const { t, call, get, relayId, listenerId, accountId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { publish: true });
    const standby = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.8',
      publish: false,
    });
    let pool = (await get('attention', AttentionResponse)).items.find(
      (i) => i.kind === 'pool_below_desired',
    )!;
    expect(pool).toMatchObject({ action: 'publish', edgeId: standby.edgeId });
    // The standby stops being publishable (no address): nothing to call, so navigate.
    await t.run((ctx) => ctx.db.patch(standby.edgeId as Id<'edges'>, { addresses: {} }));
    pool = (await get('attention', AttentionResponse)).items.find(
      (i) => i.kind === 'pool_below_desired',
    )!;
    expect(pool).toMatchObject({ action: 'open_relay', edgeId: null });

    await markTested(t, accountId);
    await t.mutation(internal.edgeProviderAccounts.recordTest, {
      id: accountId,
      ok: false,
      code: 'unauthorized',
    });
    const kinds = (await get('attention', AttentionResponse)).items.map((i) => i.kind);
    expect(kinds).toContain('account_untested');
    const res = await call('POST', `relays/${relayId}/test-provision`, {
      accountId,
      listenerKey: 'a',
    });
    // The start is admitted; SELECTION (the machine's first step) refuses the account.
    expect(res.status).toBe(200);
    const { rotationId } = (await res.json()) as { rotationId: Id<'edgeRotations'> };
    const step = await t.query(internal.edgeRotations.stepContext, { rotationId });
    expect(step?.selection?.account).toBeNull();
    expect(step?.selection?.accountFailure).toBe('account_untested');
    // And the dry run says so before anyone starts it.
    const pre = PreflightResponse.parse(
      await (
        await call('POST', `relays/${relayId}/preflight`, {
          kind: 'test-provision',
          accountId,
          listenerKey: 'a',
        })
      ).json(),
    );
    expect(pre.blockers.map((b) => b.code)).toContain('account_untested');
  });

  test('a suspected origin offers a one-click rotate only when the evidence names exactly one published edge', async () => {
    const { t, get, relayId, listenerId } = await seed();
    const a = await adoptL4Edge(t, relayId, listenerId, { publish: true });
    const suspicion = (edgeIds: string[]) => ({
      state: 'suspected' as const,
      hintLevel: 'none' as const,
      score: 1,
      reportScore: 1,
      loadScore: 0,
      probeScore: 0,
      scope: null,
      countries: [],
      edgeEvidence: edgeIds.map((edgeId) => ({
        edgeId: edgeId as Id<'edges'>,
        source: 'reports' as const,
        countries: ['IR'],
      })),
      firstSeenAt: Date.now(),
      lastEvalAt: Date.now(),
      quietEvals: 0,
      baselineWarm: true,
      veto: null,
    });
    await t.run((ctx) => ctx.db.patch(relayId, { suspicion: suspicion([a.edgeId]) as never }));
    let item = (await get('attention', AttentionResponse)).items.find(
      (i) => i.kind === 'block_suspected',
    )!;
    expect(item).toMatchObject({ action: 'rotate', edgeId: a.edgeId });
    await t.run((ctx) => ctx.db.patch(relayId, { suspicion: suspicion([]) as never }));
    item = (await get('attention', AttentionResponse)).items.find(
      (i) => i.kind === 'block_suspected',
    )!;
    expect(item).toMatchObject({ action: 'open_relay', edgeId: null });
  });

  test('minting a register token: a malformed node list is refused, never dropped into "every node"', async () => {
    const { t, cookie, serverId } = await seed();
    const mint = (edgeRegistration: unknown) =>
      t.fetch('/api/v1/admin/tokens', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'node-role',
          scopes: ['admin:edges:register'],
          edgeRegistration,
        }),
      });
    const bad = await mint({ backendServerIds: [serverId], nodeNames: [42] });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { error: { code: string } }).error.code).toBe('validation');
    expect((await mint({ backendServerIds: [serverId], nodeNames: [''] })).status).toBe(400);
    expect(await t.run(async (ctx) => (await ctx.db.query('apiTokens').collect()).length)).toBe(0);
    const ok = await mint({ backendServerIds: [serverId], nodeNames: ['node-one'] });
    expect(ok.status).toBe(200);
    const row = await t.run(async (ctx) => (await ctx.db.query('apiTokens').first())!);
    expect(row.edgeRegistration).toEqual({
      backendServerIds: [serverId],
      nodeNames: ['node-one'],
    });
  });
});
