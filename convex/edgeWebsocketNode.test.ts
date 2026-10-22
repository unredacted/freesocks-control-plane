/**
 * A WebSocket node takes no load balancer (docs/edges.md § "Layers",
 * lib/edges/websocketNode.ts): which node is one, and every server path that
 * would offer, accept, choose or publish an L4 edge for its transport. The
 * same paths keep offering load balancers to a node that is not one. Fixtures
 * only (RFC 5737, `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  adoptL4Edge,
  createAccount,
  realityListener,
  seedEdgeFixture,
  wsListener,
  type EdgeFixture,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow } from './lib/edges/testing/reads';
import { websocketNodeOf } from './lib/edges/websocketNode';
import { selectionContext } from './edgeRotations';
import { checkPublishable } from './relays';
import { resolveEdgeConfig } from './lib/edgeConfig';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const NODE = 'node-one';
const MODES = {
  'freedom-ws': { name: 'Freedom-WebSocket', shape: { transport: 'ws', fronting: 'edge-l7' } },
  'freedom-reality': {
    name: 'Freedom-Reality',
    shape: { transport: 'reality', fronting: 'edge-l4' },
  },
} as const;
type Mode = keyof typeof MODES;

/**
 * The fixture's node enrolled in `mode`: the backend's setup row with the mode,
 * and the node's intent (only a WebSocket node has an ingress). `inSetup:
 * false` leaves the mode out of the setup row (the intent alone says it).
 */
async function enroll(
  t: T,
  serverId: Id<'backendServers'>,
  mode: Mode,
  opts: { inSetup?: boolean } = {},
) {
  const now = Date.now();
  const ws = mode === 'freedom-ws';
  await t.run(async (ctx) => {
    await ctx.db.insert('panelSetups', {
      backendServerId: serverId,
      desired: '{}',
      desiredHash: 'fixture',
      generation: 1,
      state: 'ready',
      profileName: 'FreeSocks-Config',
      modes:
        opts.inSetup === false
          ? []
          : [
              {
                slug: mode,
                name: MODES[mode].name,
                shape: MODES[mode].shape,
                acceptProxyProtocol: false,
                tag: MODES[mode].name.toUpperCase().replace(/-/g, '_'),
                placement: 'bound',
                family: mode === 'freedom-ws' ? 'none' : 'bound',
              },
            ],
      templates: [],
      originDns: null,
      adopted: false,
      gateVersion: 0,
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.insert('panelNodeIntents', {
      backendServerId: serverId,
      name: NODE,
      label: NODE,
      mode,
      contractVersion: 2,
      generation: 1,
      desiredHash: 'fixture',
      state: 'ready',
      observed: {
        management: { address: '192.0.2.20', port: 2222 },
        publicIps: { v4: '203.0.113.10' },
        capabilities: { caddy: ws, ipv6: false },
        at: now,
      },
      settings: {
        ingress: ws
          ? {
              externalPort: 443,
              hostHeader: 'any',
              internal: [{ inboundTag: 'VLESS_WS', listen: '127.0.0.1', port: 8443, path: '/ws' }],
            }
          : undefined,
        originHostnameSource: ws ? 'explicit' : 'none',
        ...(ws ? { explicitHostname: 'ws.example' } : {}),
        publishV6: false,
        nodePort: 2222,
      },
      machineRevision: 1,
      activation: { stage: 'machine_ready', evidence: [] },
      delivery: {
        disposition: 'staged',
        acceptingAssignments: false,
        exposure: {
          everLive: false,
          hosts: [],
          mirrors: 0,
          testCredentials: 0,
          dns: 0,
        },
      },
      origin: { dns: 'none' },
      registeredAt: now,
      updatedAt: now,
    });
  });
}

/**
 * A node with the WebSocket listener, a tested and trusted load balancer
 * account (the fixture's) and, with `cdn`, a tested and trusted CDN account
 * whose zone was checked.
 */
async function world(opts: { mode?: Mode | null; cdn?: boolean; reality?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, {
    qualified: true,
    provider: 'upcloud',
    listeners: [opts.reality ? realityListener() : wsListener()],
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
  const l4Location = (await defaultLocationRow(t, fx.accountId))!._id;
  let cdn: Id<'edgeProviderAccounts'> | null = null;
  let cdnLocation: Id<'edgeLocations'> | null = null;
  if (opts.cdn) {
    await t.mutation(internal.edgeAdmin.patchConfig, {
      patch: { l7: { dnsProvidersFront: true } },
    });
    cdn = await createAccount(t, { provider: 'cloudflare', name: 'acct-cdn', qualified: true });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: cdn, ok: true });
    cdnLocation = (await defaultLocationRow(t, cdn))!._id;
    await t.mutation(internal.edgeLocations.recordCheck, {
      id: cdnLocation,
      ok: true,
      observed: { zoneSslMode: 'full', websockets: 'on' },
    });
  }
  if (opts.mode !== null) await enroll(t, fx.serverId, opts.mode ?? 'freedom-ws');
  return { t, fx, l4: fx.accountId, l4Location, cdn, cdnLocation };
}

const websocketOf = (t: T, fx: EdgeFixture) =>
  t.run(async (ctx) => websocketNodeOf(ctx.db, (await ctx.db.get(fx.relayId))!.origin));

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    return String((err as { data?: { code?: string } }).data?.code ?? err);
  }
  return 'no refusal';
}

describe('which node is a WebSocket node', () => {
  test("an enrolled node whose mode is fronted by CDNs only; the intent's ingress says it when the mode has no entry", async () => {
    const plain = await world({ mode: null });
    // Not an enrolled node at all (an operator's own WebSocket transport).
    expect(await websocketOf(plain.t, plain.fx)).toBe(false);

    const ws = await world();
    expect(await websocketOf(ws.t, ws.fx)).toBe(true);

    const reality = await world({ mode: 'freedom-reality', reality: true });
    expect(await websocketOf(reality.t, reality.fx)).toBe(false);

    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { listeners: [wsListener()] });
    await enroll(t, fx.serverId, 'freedom-ws', { inSetup: false });
    expect(await websocketOf(t, fx)).toBe(true);
  });
});

describe('a load balancer for a WebSocket node', () => {
  test('a pick of a load balancer is refused where it is checked (`checkPicks`), a CDN pick is not', async () => {
    const { t, l4Location, cdnLocation } = await world({ cdn: true });
    const check = (websocketNode: boolean) =>
      t.query(internal.edgeSetupPlan.checkPicks, {
        picks: [
          { locationId: l4Location, options: {} },
          { locationId: cdnLocation!, options: {} },
        ],
        websocketNode,
      });
    const refused = await check(true);
    expect(refused[0]).toMatchObject({ ok: false, code: 'edge.l4_not_for_websocket' });
    expect(refused[0]!.ok === false && refused[0]!.issues[0]).toContain('Use a CDN');
    expect(refused[1]!.ok).toBe(true);
    // Any other node keeps its load balancers.
    expect((await check(false))[0]!.ok).toBe(true);
  });

  test('a rotation naming a load balancer is refused at its start; selection never chooses one', async () => {
    const { t, fx, l4, l4Location } = await world();
    for (const named of [{ requestedLocationId: l4Location }, { requestedAccountId: l4 }])
      expect(
        await refusal(
          t.mutation(internal.edgeRotations.start, {
            relayId: fx.relayId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: false,
            listenerId: fx.listenerId,
            ...named,
          }),
        ),
      ).toBe('edge.l4_not_for_websocket');
    const select = (rotation: Parameters<typeof selectionContext>[1]) =>
      t.run(async (ctx) =>
        selectionContext(
          ctx,
          rotation,
          (await ctx.db.get(fx.relayId))!,
          null,
          await resolveEdgeConfig(ctx.db),
        ),
      );
    const named = await select({
      kind: 'provision',
      trigger: 'manual',
      listenerId: fx.listenerId,
      requestedLocationId: l4Location,
    });
    expect(named.accountFailure).toBe('l4_not_for_websocket');
    // Automatic: the only account is a load balancer, so there is nothing to pick.
    const automatic = await select({
      kind: 'provision',
      trigger: 'reconcile',
      listenerId: fx.listenerId,
    });
    expect(automatic.account).toBeNull();
    expect(automatic.accountFailure).toBe('no_account_for_layer');
  });

  test('a CDN is what automatic selection picks for it; the same listener elsewhere may take the load balancer', async () => {
    const ws = await world({ cdn: true });
    const select = (w: Awaited<ReturnType<typeof world>>) =>
      w.t.run(async (ctx) =>
        selectionContext(
          ctx,
          { kind: 'provision', trigger: 'manual', listenerId: w.fx.listenerId },
          (await ctx.db.get(w.fx.relayId))!,
          null,
          await resolveEdgeConfig(ctx.db),
        ),
      );
    // (The load balancer would be preferred, could it be had.)
    await ws.t.run((c) => c.db.patch(ws.l4, { priority: -100 }));
    expect((await select(ws)).account?.id).toBe(ws.cdn);
    // Elsewhere the load balancer may be named, and is taken.
    const plain = await world({ mode: null, cdn: true });
    const named = await plain.t.run(async (ctx) =>
      selectionContext(
        ctx,
        {
          kind: 'provision',
          trigger: 'manual',
          listenerId: plain.fx.listenerId,
          requestedLocationId: plain.l4Location,
        },
        (await ctx.db.get(plain.fx.relayId))!,
        null,
        await resolveEdgeConfig(ctx.db),
      ),
    );
    expect(named.accountFailure).toBeNull();
    expect(named.account?.id).toBe(plain.l4);
  });

  test('a load-balancer spare it already has is left as it is: never a standby, never published', async () => {
    const { t, fx, l4 } = await world();
    const spare = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.31',
      accountId: l4,
    });
    const edge = (await t.run((c) => c.db.get(spare.edgeId as Id<'edges'>)))!;
    expect(edge.status).toBe('active');
    const check = await t.run((ctx) => checkPublishable(ctx, edge, false));
    expect(check).toMatchObject({ ok: false, code: 'l4_not_for_websocket' });
    // A run that would publish takes no standby of it.
    const sel = await t.run(async (ctx) =>
      selectionContext(
        ctx,
        { kind: 'provision', trigger: 'manual', listenerId: fx.listenerId, publishOnDone: true },
        (await ctx.db.get(fx.relayId))!,
        null,
        await resolveEdgeConfig(ctx.db),
      ),
    );
    expect(sel.standbyId).toBeNull();
    // A manual publish of it is refused at the start.
    expect(
      await refusal(
        t.mutation(internal.edgeRotations.start, {
          relayId: fx.relayId,
          kind: 'publish',
          trigger: 'manual',
          toEdgeId: edge._id,
        }),
      ),
    ).toBe('edge.l4_not_for_websocket');
    // It is still there, untouched.
    expect((await t.run((c) => c.db.get(edge._id)))!).toMatchObject({
      status: 'active',
      publication: 'unpublished',
    });
  });

  test('the same spare on a node that is not a WebSocket node is not refused for its layer', async () => {
    const { t, fx, l4 } = await world({ mode: null });
    const spare = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.32',
      accountId: l4,
    });
    const edge = (await t.run((c) => c.db.get(spare.edgeId as Id<'edges'>)))!;
    const check = await t.run((ctx) => checkPublishable(ctx, edge, false));
    expect(check.ok ? null : check.code).not.toBe('l4_not_for_websocket');
  });

  test("the node's providers: no load balancer is offered or added; a CDN is", async () => {
    const { t, fx, l4Location, cdnLocation } = await world({ cdn: true });
    const view = (await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId }))!;
    expect(view.websocketNode).toBe(true);
    expect(view.available.map((a) => a.locationId)).toEqual([cdnLocation]);
    expect(
      await refusal(
        t.mutation(internal.edgeProviderSets.change, { relayId: fx.relayId, add: [l4Location] }),
      ),
    ).toBe('edge.l4_not_for_websocket');
    // Elsewhere the load balancer is offered, and added.
    const plain = await world({ mode: null, cdn: true });
    const other = (await plain.t.query(internal.edgeProviderSets.view, {
      relayId: plain.fx.relayId,
    }))!;
    expect(other.websocketNode).toBe(false);
    expect(other.available.map((a) => a.locationId).sort()).toEqual(
      [plain.l4Location, plain.cdnLocation].sort(),
    );
    await plain.t.mutation(internal.edgeProviderSets.change, {
      relayId: plain.fx.relayId,
      add: [plain.l4Location],
    });
    expect(
      (await plain.t.run((c) => c.db.get(plain.fx.relayId)))!.providerSet?.map((p) => p.locationId),
    ).toEqual([plain.l4Location]);
  });
  test('a load balancer the set already holds carries nothing for it (none is planned there)', async () => {
    const { t, fx, l4Location, cdnLocation } = await world({ cdn: true });
    await t.run((c) =>
      c.db.patch(fx.relayId, {
        providerSet: [
          { locationId: l4Location, addedAt: 1 },
          { locationId: cdnLocation!, addedAt: 2 },
        ],
      }),
    );
    const view = (await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId }))!;
    expect(view.uncarried).toEqual([]);
    // The one transport's carriers are the CDN alone: one group.
    expect(view.reduced.map((r) => r.listenerKey)).toEqual(['w']);
  });
});

describe('no backup elsewhere', () => {
  const attentionCode = async (t: T) =>
    (await t.query(internal.edgeOperator.attention, {})).items.find(
      (i) => i.kind === 'reduced_resilience',
    )?.code;

  test('a WebSocket node on one CDN needs a second CDN', async () => {
    const { t, fx, cdnLocation } = await world({ cdn: true });
    await t.run((c) =>
      c.db.patch(fx.relayId, { providerSet: [{ locationId: cdnLocation!, addedAt: 1 }] }),
    );
    expect(await attentionCode(t)).toBe('second_cdn_needed');
  });

  test("a REALITY node on one provider's load balancers keeps its wording", async () => {
    const { t, fx, l4Location } = await world({ mode: 'freedom-reality', reality: true });
    await t.run((c) =>
      c.db.patch(fx.relayId, { providerSet: [{ locationId: l4Location, addedAt: 1 }] }),
    );
    expect(await attentionCode(t)).toBe('one_group');
  });
});
