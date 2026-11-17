/// <reference types="vite/client" />
/**
 * A node serving its mode's ENCRYPTED TWIN (convex/nodeTwins.ts), against the
 * fake backend with the real setup, ledger, observation, node reconcile and
 * routes; only the session through a front is stubbed. The twin's transport is
 * turned on for the node, its address is written switched off, each published
 * front is checked on the twin's path with the twin's client string, and only
 * then is the twin handed out, through the fronts that passed and no other.
 * Plus what closes it, what is refused, and that taking it away leaves the
 * node exactly as it was.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer, registerRelay, wsListener } from './lib/edges/testing/fixtures';
import { installFakeBackend } from './lib/edges/testing/fakeBackend';
import { signValue } from './lib/cookies';
import { clientEncryption, generateVlessEncryption } from './lib/backend/vlessEncryption';
import { listenerKeyForTag } from './lib/edges/inboundMapping';
import { matcherOf } from './edgeRender';
import { __setFrontChecker } from './frontQualifyOps';
import { __setFrontIngressCheckForTests } from './nodeIntentOps';
import type { QualifyFrontArgs } from './lib/edges/frontCheck';
import { NodeIntentList, ProfilePatchPreview, ServerTree } from '../src/shared/contracts/servers';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

// A removal waits for the ledger to see its delete settle (seconds).
vi.setConfig({ testTimeout: 60_000 });

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});

let current: T | null = null;
afterEach(async () => {
  if (current) {
    const t = current;
    current = null;
    await until(
      () => t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
  }
  __setFrontChecker(null);
  __setFrontIngressCheckForTests(null);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 4000; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

const wsMode = {
  slug: 'freedom-ws',
  name: 'Freedom-WebSocket',
  shape: { transport: 'ws' as const, fronting: 'edge-l7' as const },
  acceptProxyProtocol: false,
  ws: { path: '/ws', port: 8443 },
};
const OWN_TAG = 'FREEDOM_WEBSOCKET';
const TWIN_TAG = 'FREEDOM_WEBSOCKET_E';
// An ordinary node name: with it, an origin's remark runs past 40 characters.
const NODE = 'clunked-example-album';
// A listener key as transport discovery makes one (ten letters, six digits).
const LISTENER_KEY = 'freedomweb2hl30v';
const NODE_UUID = '00000400-0000-4000-8000-000000000000';
const LISTENER_HOST_UUID = '00000401-0000-4000-8000-000000000000';
const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';
const FRONTS = ['front-a.example.org', 'front-b.example.org'];

/**
 * A backend set up with the WebSocket mode and its encrypted twin, one node
 * that already serves the mode behind two published fronts (adopted as it
 * was), and the session through a front stubbed: `verdict(hostname)` says
 * whether a front carries the twin.
 */
async function seed(opts: { twin?: boolean; fronted?: boolean } = {}) {
  const t = convexTest(schema, modules);
  current = t;
  // The node's own origin answers (its reconcile looks at it; nothing here is about it).
  __setFrontIngressCheckForTests(async (a) => ({
    resolves: true,
    answers: { v4: [a.expected.v4 ?? ''], v6: [] },
    tlsValid: true,
    certNames: [a.hostname],
    pathProxied: true,
    foreignHostAnswered: true,
  }));
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend({ applyNodeUpdates: true });
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input: { profileName: 'FreeSocks-Config', modes: [wsMode], originDns: null, adopt: false },
  });
  await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim && r.state === 'ready',
  );
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
  const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const profileUuid = panel.profiles[0].uuid as string;
  const inboundOf = (tag: string) =>
    (panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find((i) => i.tag === tag)!;
  const config = () => panel.profiles[0].config as { inbounds: Record<string, any>[] };

  // The encrypted transport, and the mode's twin (convex/backendTwins.ts).
  if (opts.twin !== false) {
    const op = {
      op: 'addInboundFromTemplate',
      transportTag: TWIN_TAG,
      template: { kind: 'ws', port: 8444, path: '/ws-e', encrypted: true },
    };
    const preview = ProfilePatchPreview.parse(
      await (await call('POST', `profiles/${profileUuid}/preview`, { ops: [op] })).json(),
    );
    const applied = await call('POST', `profiles/${profileUuid}/apply`, {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      transportUuids: preview.transportUuids,
    });
    expect(applied.status).toBe(200);
    await until(
      async () => config().inbounds.find((i) => i.tag === TWIN_TAG),
      (i) => !!i,
    );
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const attached = await call('POST', 'modes/freedom-ws/encrypted-twin', {
      action: 'attach',
      transportTag: TWIN_TAG,
    });
    expect(attached.status).toBe(200);
  }

  // A node that already serves the mode, adopted as it was.
  const own = inboundOf(OWN_TAG);
  panel.nodes.push({
    uuid: NODE_UUID,
    name: NODE,
    address: '192.0.2.60',
    port: 2222,
    countryCode: 'XX',
    isDisabled: false,
    lastStatusChange: 't0',
    configProfile: { activeConfigProfileUuid: profileUuid, activeInbounds: [own] },
  });
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  const { intentId } = await t.mutation(internal.nodeIntents.adoptNode, {
    backendServerId: serverId,
    nodeUuid: NODE_UUID,
    mode: 'freedom-ws',
    originHostname: 'origin-w.example.net',
  });

  // Its fronts: the origin, its listener with the address FCP keeps for it,
  // and two published L7 edges.
  let relayId: Id<'relays'> | null = null;
  let listenerId: Id<'relayListeners'> | null = null;
  const edgeIds: Id<'edges'>[] = [];
  const addFront = async (hostname: string) => {
    const id = await t.run(async (ctx) => {
      const now = Date.now();
      const intent = {
        hostname,
        zoneId: 'a'.repeat(32),
        zoneName: 'example.org',
        originTransport: {
          scheme: 'https' as const,
          certPublic: true,
          certNames: ['origin-w.example.net'],
          acceptsHostHeader: 'any' as const,
        },
        originPort: 443,
        zoneSslMode: 'full',
        templateHash: 'h',
        templateParams: {},
      };
      const edgeId = await ctx.db.insert('edges', {
        relayId: relayId!,
        listenerId: listenerId!,
        provider: 'cloudflare',
        managed: true,
        name: `fcp-${NODE}-${hostname.split('.')[0]}`,
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: 'origin-w.example.net', originPort: 443 }],
        addresses: { hostname },
        layer: 'l7',
        provisionIntent: JSON.stringify(intent),
        publication: 'published',
        poolIndex: edgeIds.length,
        status: 'active',
        statusChangedAt: now,
        health: 'unknown',
        lastHealthAt: now,
        destroyAttempts: 0,
        updatedAt: now,
      });
      const relay = (await ctx.db.get(relayId!))!;
      await ctx.db.patch(relayId!, {
        publishedEdgeIds: [...relay.publishedEdgeIds, edgeId],
        desiredPublished: relay.publishedEdgeIds.length + 1,
      });
      return edgeId;
    });
    edgeIds.push(id);
    return id;
  };
  if (opts.fronted !== false) {
    const r = await registerRelay(t, {
      slug: NODE,
      nodeName: NODE,
      originAddress: 'origin-w.example.net',
      source: 'admin',
      listeners: [
        wsListener({
          listenerKey: LISTENER_KEY,
          tlsNames: ['origin-w.example.net'],
          transportParams: { path: '/ws' },
          panelBinding: {
            inboundTag: OWN_TAG,
            configProfileUuid: profileUuid,
            configProfileInboundUuid: own.uuid,
          },
        }),
      ],
    });
    relayId = r.relayId;
    listenerId = r.listenerId;
    panel.hosts.push({
      uuid: LISTENER_HOST_UUID,
      remark: `${NODE}-relay-${LISTENER_KEY}`,
      address: FRONTS[0],
      port: 443,
      sni: FRONTS[0],
      host: FRONTS[0],
      securityLayer: 'TLS',
      inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: own.uuid },
      isDisabled: false,
    });
    await t.run(async (ctx) => {
      await ctx.db.patch(relayId!, { qualificationUserId: QUALIFY_UUID, hostMode: 'fcp' });
      await ctx.db.patch(listenerId!, {
        host: {
          state: 'present',
          uuid: LISTENER_HOST_UUID,
          ownership: 'fcp',
          intended: {
            remark: `${NODE}-relay-${LISTENER_KEY}`,
            address: FRONTS[0]!,
            port: 443,
            sni: FRONTS[0]!,
            host: FRONTS[0]!,
            inboundUuid: own.uuid,
          },
        },
      });
    });
    for (const hostname of FRONTS) await addFront(hostname);
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  }

  // The session through a front.
  const sessions: QualifyFrontArgs[] = [];
  const carries = new Map<string, boolean>();
  __setFrontChecker(async (args) => {
    sessions.push(args);
    const ok = carries.get(args.hostname) ?? true;
    return ok
      ? { ok: true, steps: [], checkedAt: Date.now() }
      : { ok: false, code: 'front_error', detail: '404', steps: [], checkedAt: Date.now() };
  });

  const intent = () => t.run((ctx) => ctx.db.get(intentId)).then((r) => r!);
  const listener = () => t.run((ctx) => ctx.db.get(listenerId!)).then((r) => r!);
  const relay = () => t.run((ctx) => ctx.db.get(relayId!)).then((r) => r!);
  const twinState = async () => (await intent()).twin?.state ?? null;
  // Nothing scheduled is left to run (a run asks for another when it was
  // kicked meanwhile), and nothing holds the node or its twin.
  const settled = async () => {
    await until(
      () => t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
    return until(
      intent,
      (i) => !i.claim && !(i.twin?.lease && i.twin.lease.expiresAt > Date.now()),
    );
  };
  const nodeActive = () =>
    (panel.nodes.find((n) => n.name === NODE)!.configProfile.activeInbounds as { uuid: string }[])
      .map((i) => i.uuid)
      .sort();
  const twinUuid = () => inboundOf(TWIN_TAG).uuid;
  const twinHosts = () =>
    panel.hosts.filter((h) => h.inbound?.configProfileInboundUuid === twinUuid());
  const servedThrough = async () =>
    ((await listener()).encryptedTwin?.edges ?? []).map((e) => e.edgeId).sort();
  const nodeTwin = (action: 'add' | 'remove') =>
    call('POST', `nodes/intents/${intentId}/encrypted-twin`, { action });
  const runTwin = async () => {
    await t.action(internal.nodeTwins.run, { intentId });
    await settled();
  };
  const view = async () =>
    NodeIntentList.parse(await (await call('GET', 'nodes/intents')).json()).intents.find(
      (i) => i.id === intentId,
    )!.twin;
  return {
    t,
    serverId,
    panel,
    call,
    intentId,
    own: own.uuid,
    twinUuid,
    config,
    edgeIds,
    addFront,
    sessions,
    carries,
    intent,
    listener,
    relay,
    twinState,
    settled,
    nodeActive,
    twinHosts,
    servedThrough,
    nodeTwin,
    runTwin,
    view,
  };
}
type Seeded = Awaited<ReturnType<typeof seed>>;

const codeOf = async (res: Response) => ((await res.json()) as any).error?.code as string;
const serverString = (s: Seeded) =>
  s.config().inbounds.find((i) => i.tag === TWIN_TAG)!.settings.decryption as string;

/** Ask for the twin and wait until the node serves it. */
async function bringToServing(s: Seeded) {
  expect((await s.nodeTwin('add')).status).toBe(200);
  await until(s.twinState, (state) => state === 'serving');
  await s.settled();
}

describe('a node serving the encrypted twin', () => {
  test('is turned on, checked through every front, and only then handed out', async () => {
    const s = await seed();
    expect(s.nodeActive()).toEqual([s.own]);
    const epoch = (await s.relay()).publicationEpoch;

    await bringToServing(s);

    // The node runs both transports; its own is as it was.
    expect(s.nodeActive()).toEqual([s.own, s.twinUuid()].sort());
    // One session per published front: the front's own name, the listener's
    // transport and account, at the twin's path, with the twin's client string.
    expect(s.sessions.map((x) => x.hostname).sort()).toEqual([...FRONTS].sort());
    for (const x of s.sessions) {
      expect(x.params.path).toBe('/ws-e');
      expect(x.proto).toEqual({ protocol: 'vless', streamTransport: 'ws', security: 'tls' });
      expect(x.credential).toEqual({
        kind: 'vless',
        uuid: QUALIFY_UUID,
        encryption: clientEncryption(serverString(s)),
      });
    }
    // Its address: the listener's own target, on the twin's transport, under
    // the twin's remark, on.
    const key = await listenerKeyForTag(TWIN_TAG);
    expect(s.twinHosts()).toHaveLength(1);
    expect(s.twinHosts()[0]).toMatchObject({
      remark: `${NODE}-relay-${key}`,
      address: FRONTS[0],
      port: 443,
      sni: FRONTS[0],
      host: FRONTS[0],
      securityLayer: 'TLS',
      isDisabled: false,
    });
    expect(s.twinHosts()[0]).not.toHaveProperty('path');
    // The renderer knows it, limited to the fronts that passed.
    const l = await s.listener();
    expect(l.encryptedTwin).toMatchObject({
      key,
      panelBinding: { inboundTag: TWIN_TAG, configProfileInboundUuid: s.twinUuid() },
    });
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
    expect(matcherOf(l, 'origin-w.example.net').encrypted).toEqual({
      remarks: [`${NODE}-relay-${key}`],
      edgeIds: l.encryptedTwin!.edges!.map((e) => e.edgeId),
    });
    // What members receive changed.
    expect((await s.relay()).publicationEpoch).toBeGreaterThan(epoch);
    // The node's own path was never touched: still live, same approval.
    const i = await s.intent();
    expect(i.delivery.disposition).toBe('live');
    expect(i.machineRevision).toBe(1);
    expect(i.twin).toMatchObject({ state: 'serving', hostUuid: s.twinHosts()[0]!.uuid });
    expect(i.twin!.code).toBeUndefined();
    expect(await s.view()).toMatchObject({
      state: 'serving',
      code: null,
      route: { path: '/ws-e', port: 8444 },
      routeBy: 'operator',
      fronts: { checked: 2, published: 2 },
    });
    // Nothing FCP keeps or audits holds the key, a front's name or the path.
    const kept = JSON.stringify(
      await s.t.run(async (ctx) => ({
        intents: await ctx.db.query('panelNodeIntents').collect(),
        audit: (await ctx.db.query('auditLog').collect()).filter((a) => a.action.includes('twin')),
      })),
    );
    expect(kept).not.toContain(serverString(s).split('.')[3]);
    expect(kept).not.toContain(FRONTS[0]);
    expect(kept).not.toContain('/ws-e');
    const actions = (await s.t.run((ctx) => ctx.db.query('auditLog').collect())).map(
      (a) => a.action,
    );
    expect(actions).toContain('admin.servers.node_twin.add');
    expect(actions).toContain('servers.node.twin_serving');
  });

  test('a front that does not carry it gets the plain entry alone', async () => {
    const s = await seed();
    s.carries.set(FRONTS[1]!, false);
    await bringToServing(s);
    expect(await s.servedThrough()).toEqual([s.edgeIds[0]]);
    expect(s.twinHosts()[0]!.isDisabled).toBe(false);
    expect((await s.view())!.fronts).toEqual({ checked: 1, published: 2 });

    // It is tried again with the next look, and counted once it passes.
    s.carries.set(FRONTS[1]!, true);
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    await s.runTwin();
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([]);
  });

  test('with no front carrying it, its address stays off and nobody is handed it', async () => {
    const s = await seed();
    for (const f of FRONTS) s.carries.set(f, false);
    expect((await s.nodeTwin('add')).status).toBe(200);
    await until(s.intent, (i) => i.twin?.code === 'servers.node_twin_check_failed');
    await s.settled();
    expect(await s.twinState()).toBe('activating');
    expect(s.twinHosts()).toHaveLength(1);
    expect(s.twinHosts()[0]!.isDisabled).toBe(true);
    expect(await s.servedThrough()).toEqual([]);
    // Named to the renderer all the same, so its entry could never pass through.
    expect((await s.listener()).encryptedTwin).toBeDefined();
    expect(matcherOf(await s.listener(), 'o').encrypted!.edgeIds).toEqual([]);
    expect(await s.view()).toMatchObject({
      state: 'activating',
      code: 'servers.node_twin_check_failed',
      fronts: { checked: 0, published: 2 },
    });

    // The route is added on the node: the next look turns it on.
    for (const f of FRONTS) s.carries.set(f, true);
    await s.runTwin();
    expect(await s.twinState()).toBe('serving');
    expect(s.twinHosts()[0]!.isDisabled).toBe(false);
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
  });

  test('a front published later is not handed the twin until its own check passes', async () => {
    const s = await seed();
    await bringToServing(s);
    const sessions = s.sessions.length;
    const added = await s.addFront('front-c.example.org');
    // Before any look: the renderer still limits the twin to the two it knows.
    expect(matcherOf(await s.listener(), 'o').encrypted!.edgeIds).not.toContain(added);
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    const epoch = (await s.relay()).publicationEpoch;
    await s.runTwin();
    // Only the new front is checked; the others' checks still count.
    expect(s.sessions.slice(sessions).map((x) => x.hostname)).toEqual(['front-c.example.org']);
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
    expect((await s.relay()).publicationEpoch).toBeGreaterThan(epoch);
  });

  test('a check an hour old is made again, and a front that left is dropped', async () => {
    const s = await seed();
    await bringToServing(s);
    const l = await s.listener();
    await s.t.run(async (ctx) => {
      // The first front's check is old; the second front is no longer published.
      await ctx.db.patch(l._id, {
        encryptedTwin: {
          ...l.encryptedTwin!,
          edges: l.encryptedTwin!.edges!.map((e) =>
            e.edgeId === s.edgeIds[0] ? { ...e, checkedAt: Date.now() - 61 * 60_000 } : e,
          ),
        },
      });
      await ctx.db.patch(s.edgeIds[1]!, { publication: 'draining' });
    });
    const sessions = s.sessions.length;
    await s.runTwin();
    expect(s.sessions.slice(sessions).map((x) => x.hostname)).toEqual([FRONTS[0]]);
    expect(await s.servedThrough()).toEqual([s.edgeIds[0]]);
    expect(await s.twinState()).toBe('serving');
  });

  test('a new key closes the twin until every front is checked again with the new client string', async () => {
    const s = await seed();
    await bringToServing(s);
    const before = clientEncryption(serverString(s));
    // The twin's key is replaced on the backend (by hand: FCP has no such change).
    s.config().inbounds.find((i) => i.tag === TWIN_TAG)!.settings.decryption =
      generateVlessEncryption().decryption;
    for (const f of FRONTS) s.carries.set(f, false);
    await s.runTwin();
    // Closed: no front counted, the address off.
    expect(await s.twinState()).toBe('activating');
    expect(await s.servedThrough()).toEqual([]);
    expect(s.twinHosts()[0]!.isDisabled).toBe(true);
    const actions = (await s.t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
      (a) => a.action === 'servers.node.twin_closed',
    );
    expect(actions.map((a) => (a.payload as { code?: string }).code)).toEqual([
      'servers.node_twin_drifted',
    ]);

    // Checked again with the new client string, it serves again.
    for (const f of FRONTS) s.carries.set(f, true);
    const sessions = s.sessions.length;
    await s.runTwin();
    expect(await s.twinState()).toBe('serving');
    const after = clientEncryption(serverString(s));
    expect(after).not.toBe(before);
    for (const x of s.sessions.slice(sessions))
      expect(x.credential).toMatchObject({ encryption: after });
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
  });

  test('its address follows the listener’s own when a front is replaced, without closing', async () => {
    const s = await seed();
    await bringToServing(s);
    // The listener's own address now names the other front.
    const host = s.panel.hosts.find((h) => h.uuid === LISTENER_HOST_UUID)!;
    Object.assign(host, { address: FRONTS[1], sni: FRONTS[1], host: FRONTS[1] });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    const sessions = s.sessions.length;
    await s.runTwin();
    expect(s.twinHosts()[0]).toMatchObject({
      address: FRONTS[1],
      sni: FRONTS[1],
      host: FRONTS[1],
      isDisabled: false,
    });
    expect(await s.twinState()).toBe('serving');
    // No front was checked again for it: both are templates the renderer rewrites.
    expect(s.sessions).toHaveLength(sessions);
  });

  test('nothing of it is written while the node’s fronts are being changed', async () => {
    const s = await seed();
    await bringToServing(s);
    const relay = await s.relay();
    // A front being replaced: a rotation holds the origin.
    const rotationId = await s.t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId: relay._id,
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
    await s.t.run((ctx) => ctx.db.patch(relay._id, { activeRotationId: rotationId }));
    const added = await s.addFront('front-c.example.org');
    const sessions = s.sessions.length;
    await s.runTwin();
    expect(s.sessions).toHaveLength(sessions);
    expect(await s.servedThrough()).not.toContain(added);
    expect(s.twinHosts()[0]!.isDisabled).toBe(false);
    expect((await s.intent()).twin).toMatchObject({
      state: 'serving',
      code: 'servers.node_twin_front_busy',
    });
    // Done: the next look checks the new front and clears the note.
    await s.t.run((ctx) => ctx.db.patch(relay._id, { activeRotationId: undefined }));
    await s.runTwin();
    expect(await s.servedThrough()).toContain(added);
    expect((await s.intent()).twin!.code).toBeUndefined();
  });

  test('a node leaving its fronts has the twin’s address switched off first', async () => {
    const s = await seed();
    await bringToServing(s);
    const relay = await s.relay();
    await s.t.run((ctx) => ctx.db.patch(relay._id, { deleting: true }));
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    await s.runTwin();
    expect(s.twinHosts()[0]!.isDisabled).toBe(true);
    expect(await s.servedThrough()).toEqual([]);
    expect((await s.intent()).twin).toMatchObject({
      state: 'activating',
      code: 'servers.node_twin_no_front',
    });
  });

  test('a failing front is said once, not on every look', async () => {
    const s = await seed();
    for (const f of FRONTS) s.carries.set(f, false);
    expect((await s.nodeTwin('add')).status).toBe(200);
    await until(s.intent, (i) => i.twin?.code === 'servers.node_twin_check_failed');
    await s.settled();
    await s.runTwin();
    await s.runTwin();
    const said = async (action: string) =>
      (await s.t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
        (a) => a.action === action,
      ).length;
    expect(await said('servers.node.twin_check_failed')).toBe(1);
    // Serving, then one front stops carrying it: said when it is lost, once.
    for (const f of FRONTS) s.carries.set(f, true);
    await s.runTwin();
    expect(await s.twinState()).toBe('serving');
    s.carries.set(FRONTS[1]!, false);
    const l = await s.listener();
    await s.t.run((ctx) =>
      ctx.db.patch(l._id, {
        encryptedTwin: {
          ...l.encryptedTwin!,
          edges: l.encryptedTwin!.edges!.map((e) => ({
            ...e,
            checkedAt: Date.now() - 61 * 60_000,
          })),
        },
      }),
    );
    await s.runTwin();
    await s.runTwin();
    expect(await s.servedThrough()).toEqual([s.edgeIds[0]]);
    expect(await said('servers.node.twin_front_failed')).toBe(1);
  });

  test('taking it away leaves the node exactly as it was', async () => {
    const s = await seed();
    await bringToServing(s);
    const epoch = (await s.relay()).publicationEpoch;
    expect((await s.nodeTwin('remove')).status).toBe(200);
    await until(s.intent, (i) => !i.twin);
    await s.settled();
    await until(
      async () => s.nodeActive(),
      (a) => a.length === 1,
    );
    expect(s.nodeActive()).toEqual([s.own]);
    expect(s.twinHosts()).toEqual([]);
    expect((await s.listener()).encryptedTwin).toBeUndefined();
    expect((await s.relay()).publicationEpoch).toBeGreaterThan(epoch);
    expect(await s.view()).toBeNull();
    // The listener's own address and the node are as before.
    expect(s.panel.hosts.find((h) => h.uuid === LISTENER_HOST_UUID)).toMatchObject({
      address: FRONTS[0],
      isDisabled: false,
    });
    expect((await s.intent()).delivery.disposition).toBe('live');
    // Only then can the mode's twin be taken off the backend.
    expect(
      (await s.call('POST', 'modes/freedom-ws/encrypted-twin', { action: 'detach' })).status,
    ).toBe(200);
  });

  test('taken away and asked for again, it serves again', async () => {
    const s = await seed();
    await bringToServing(s);
    const first = s.twinHosts()[0]!.uuid;
    expect((await s.nodeTwin('remove')).status).toBe(200);
    await until(s.intent, (i) => !i.twin);
    await s.settled();
    // The ledger's own sweep settles the delete, which marks the address's
    // name as removed on purpose.
    await s.t.action(internal.backendWrites.reconcile, {});
    await s.settled();
    const marks = await s.t.run(async (ctx) =>
      (await ctx.db.query('panelOwnership').collect()).filter(
        (r) => r.kind === 'host' && r.state === 'tombstoned',
      ),
    );
    expect(marks).toHaveLength(1);
    // Asked for again, it is recreated on purpose.
    await bringToServing(s);
    expect(s.twinHosts()).toHaveLength(1);
    expect(s.twinHosts()[0]!.uuid).not.toBe(first);
    expect(s.twinHosts()[0]!.isDisabled).toBe(false);
    expect(await s.servedThrough()).toEqual([...s.edgeIds].sort());
  });

  test('a material change of the listener closes it until every front is checked again', async () => {
    const s = await seed();
    await bringToServing(s);
    const l = await s.listener();
    // The listener was updated in place (its transport, its names): its
    // revision moved, and so did what its fronts' own proofs are bound to.
    await s.t.run((ctx) => ctx.db.patch(l._id, { revision: l.revision + 1 }));
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    const sessions = s.sessions.length;
    await s.runTwin();
    // Every front again, none on the strength of a check made before.
    expect(
      s.sessions
        .slice(sessions)
        .map((x) => x.hostname)
        .sort(),
    ).toEqual([...FRONTS].sort());
    expect(await s.twinState()).toBe('serving');
    const closed = (await s.t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
      (a) => a.action === 'servers.node.twin_closed',
    );
    expect(closed.map((a) => (a.payload as { code?: string }).code)).toEqual([
      'servers.node_twin_drifted',
    ]);
  });

  test('members served the backend’s body as it comes never get the twin', async () => {
    const s = await seed();
    await bringToServing(s);
    // The node's delivery through its fronts is released: bodies go out raw.
    const binding = await s.t.run((ctx) => ctx.db.query('edgeDeliveryBindings').first());
    expect(binding).toMatchObject({ state: 'active', relaySlug: NODE });
    await s.t.run((ctx) => ctx.db.patch(binding!._id, { state: 'released' }));
    expect(await s.t.query(internal.nodeTwins.due, { now: Date.now() })).toEqual([s.intentId]);
    await s.runTwin();
    // Off before any raw body could carry it.
    expect(s.twinHosts()[0]!.isDisabled).toBe(true);
    expect(await s.servedThrough()).toEqual([]);
    expect((await s.intent()).twin).toMatchObject({
      state: 'activating',
      code: 'servers.node_twin_not_rendered',
    });
    // And it is not switched on for such a node in the first place.
    const fresh = await seed();
    const b = await fresh.t.run((ctx) => ctx.db.query('edgeDeliveryBindings').first());
    await fresh.t.run((ctx) => ctx.db.patch(b!._id, { state: 'released' }));
    const res = await fresh.nodeTwin('add');
    expect(res.status).toBe(409);
    expect(await codeOf(res)).toBe('servers.node_twin_not_rendered');
    // A deferred binding is the same thing.
    const deferred = await seed();
    const relay = await deferred.relay();
    await deferred.t.run((ctx) => ctx.db.patch(relay._id, { bindingDeferred: true }));
    expect(await codeOf(await deferred.nodeTwin('add'))).toBe('servers.node_twin_not_rendered');
  });

  test('a twin address whose uuid was never recorded leaves with a retiring node', async () => {
    const s = await seed();
    await bringToServing(s);
    const host = s.twinHosts()[0]!;
    // The create landed, the run stopped before it recorded the address.
    const i = await s.intent();
    await s.t.run((ctx) => ctx.db.patch(i._id, { twin: { ...i.twin!, hostUuid: undefined } }));
    const retirementId = await s.t.run((ctx) =>
      ctx.db.insert('panelRetirements', {
        backendServerId: s.serverId,
        intentId: s.intentId,
        requestedBy: 'admin',
        stage: 'draining',
        events: [],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    const c = await s.t.query(internal.nodeRetirement.context, { retirementId });
    expect(c!.addresses.map((h) => h.hostUuid)).toContain(host.uuid);
    // The listener's own address is not the node's to remove this way.
    expect(c!.addresses.map((h) => h.hostUuid)).not.toContain(LISTENER_HOST_UUID);
  });

  test('the mode’s twin cannot be taken off the backend while a node serves it', async () => {
    const s = await seed();
    await bringToServing(s);
    const res = await s.call('POST', 'modes/freedom-ws/encrypted-twin', { action: 'detach' });
    expect(res.status).toBe(409);
    expect(await codeOf(res)).toBe('servers.twin_in_use');
  });
});

describe('the node page', () => {
  test('shows the twin’s transport as encrypted, and its address as one FCP keeps', async () => {
    const s = await seed();
    await bringToServing(s);
    const tree = ServerTree.parse(await (await s.call('GET', 'tree')).json());
    const node = tree.nodes.find((n) => n.name === NODE)!;
    const own = node.transports.find((t) => t.tag === OWN_TAG)!;
    const twin = node.transports.find((t) => t.tag === TWIN_TAG)!;
    expect(own).toMatchObject({ encrypted: false, twin: false });
    expect(twin).toMatchObject({ encrypted: true, twin: true });
    // One address each, both templates FCP writes: neither is a member's as it stands.
    expect(own.addresses.map((a) => a.fcpOwned)).toEqual([true]);
    expect(twin.addresses.map((a) => a.fcpOwned)).toEqual([true]);
    // Nothing of the layer's key or client string is in the view.
    const text = JSON.stringify(tree);
    expect(text).not.toContain('mlkem768x25519plus');
  });

  test('an address someone else put on the twin’s transport is not taken for FCP’s', async () => {
    const s = await seed();
    await bringToServing(s);
    s.panel.hosts.push({
      uuid: '00000499-0000-4000-8000-000000000000',
      remark: 'someone-made-this',
      address: 'elsewhere.example.org',
      port: 443,
      inbound: {
        configProfileUuid: s.panel.profiles[0].uuid,
        configProfileInboundUuid: s.twinUuid(),
      },
      isDisabled: false,
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const tree = ServerTree.parse(await (await s.call('GET', 'tree')).json());
    const twin = tree.nodes
      .find((n) => n.name === NODE)!
      .transports.find((t) => t.tag === TWIN_TAG)!;
    expect(
      twin.addresses.map((a) => [a.remark, a.fcpOwned]).sort((a, b) => (a[0]! < b[0]! ? -1 : 1)),
    ).toEqual(
      [
        [twin.addresses.find((a) => a.fcpOwned)!.remark, true],
        ['someone-made-this', false],
      ].sort((a, b) => (a[0]! < b[0]! ? -1 : 1)),
    );
  });
});

describe('the node page, after an edit on the backend', () => {
  test('the recorded twin address stays FCP’s when someone moves it to another transport', async () => {
    const s = await seed();
    await bringToServing(s);
    const host = s.twinHosts()[0]!;
    // A panel edit binds the twin's address to the node's own transport.
    host.inbound = {
      configProfileUuid: s.panel.profiles[0].uuid,
      configProfileInboundUuid: s.own,
    };
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const tree = ServerTree.parse(await (await s.call('GET', 'tree')).json());
    const own = tree.nodes.find((n) => n.name === NODE)!.transports.find((t) => t.tag === OWN_TAG)!;
    const moved = own.addresses.find((a) => a.addressUuid === host.uuid)!;
    // Still not an address to change or delete by hand.
    expect(moved.fcpOwned).toBe(true);
  });
});

describe('the node behind its fronts', () => {
  test('only a twin may come or go on it, and nothing else with it', async () => {
    const s = await seed();
    const update = (fields: Record<string, unknown>) =>
      s.t.mutation(internal.backendWrites.requestNodeUpdate, {
        backendServerId: s.serverId,
        nodeUuid: NODE_UUID,
        ...fields,
      } as never);
    const both = [s.own, s.twinUuid()];
    // Asked like any change of its transports: refused, as before.
    await expect(update({ activeInboundUuids: both })).rejects.toThrow(
      /servers\.node_relay_origin/,
    );
    // The twin's toggle carries nothing else: not another port, not the node's own transport.
    await expect(
      update({ activeInboundUuids: both, port: 2223, twinToggle: true }),
    ).rejects.toThrow(/servers\.node_relay_origin/);
    await expect(update({ activeInboundUuids: [s.twinUuid()], twinToggle: true })).rejects.toThrow(
      /servers\.node_relay_origin/,
    );
    // The twin alone is let through.
    const { opId } = await update({ activeInboundUuids: both, twinToggle: true });
    expect(opId).toBeTruthy();
  });

  test('the node role is handed the twin’s route beside the node’s own, and only while it is wanted', async () => {
    const s = await seed();
    // A node the role runs (enrolled, with an origin name of its own).
    const { intentId } = await s.t.mutation(internal.nodeIntents.enroll, {
      backendServerId: s.serverId,
      name: 'node-r',
      mode: 'freedom-ws',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.70', port: 2222 },
        publicIps: { v4: '203.0.113.70' },
        capabilities: { caddy: true, ipv6: false },
      },
    });
    await s.t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: 'origin-r.example.net' },
    });
    const routes = async () =>
      (await s.t.action(internal.nodeIntents.bootstrap, { intentId })).ingress!.routes;
    const revision = (await s.t.run((ctx) => ctx.db.get(intentId)))!.machineRevision;
    expect(await routes()).toEqual([{ path: '/ws', port: 8443 }]);
    const setTwin = (state: 'activating' | 'serving' | 'removing') =>
      s.t.run((ctx) =>
        ctx.db.patch(intentId, { twin: { state, since: Date.now(), updatedAt: Date.now() } }),
      );
    for (const state of ['activating', 'serving'] as const) {
      await setTwin(state);
      expect(await routes()).toEqual([
        { path: '/ws', port: 8443 },
        { path: '/ws-e', port: 8444 },
      ]);
    }
    await setTwin('removing');
    expect(await routes()).toEqual([{ path: '/ws', port: 8443 }]);
    // No machine setting moved for it: the node's own revision and approval stand.
    expect((await s.t.run((ctx) => ctx.db.get(intentId)))!.machineRevision).toBe(revision);
  });
});

describe('what is refused', () => {
  test('a mode without a twin on this backend', async () => {
    const s = await seed({ twin: false });
    const res = await s.nodeTwin('add');
    expect(res.status).toBe(409);
    expect(await codeOf(res)).toBe('servers.twin_absent');
    expect((await s.intent()).twin).toBeUndefined();
  });

  test('a node FCP runs no front for', async () => {
    const s = await seed({ fronted: false });
    const res = await s.nodeTwin('add');
    expect(res.status).toBe(409);
    expect(await codeOf(res)).toBe('servers.node_twin_no_front');
    expect(s.nodeActive()).toEqual([s.own]);
  });

  test('asked twice, and taken away when there is none', async () => {
    const s = await seed();
    await bringToServing(s);
    const again = await s.nodeTwin('add');
    expect(again.status).toBe(409);
    expect(await codeOf(again)).toBe('servers.node_twin_present');
    const none = await seed();
    const gone = await none.nodeTwin('remove');
    expect(gone.status).toBe(409);
    expect(await codeOf(gone)).toBe('servers.node_twin_absent');
  });
});
