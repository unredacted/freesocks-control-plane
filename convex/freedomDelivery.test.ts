/// <reference types="vite/client" />
/**
 * Freedom modes only through edges (`edge.freedom.edgesOnly`, docs/edges.md):
 * while it is on, a freedom-family key is never handed a node no binding
 * covers (the route, the raw view, a mirror's render and the raw backend URL
 * all withhold it, and a body cached before the switch moved never answers
 * it), the pinner lands such a key on a covered node when the body has one, a
 * freedom mode is never saved or set up direct, the seed stores it on for a
 * deployment without members and off for one with members, and the preview
 * counts what turning it on would close. Fixtures use RFC 5737 addresses and
 * `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import {
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  insertPanelServer,
  realityListener,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';
import { FREEDOM_EDGES_ONLY_KEY, withheldReason } from './lib/edges/freedomDelivery';
import { pickNode, pinSubscriptionToNode } from './lib/nodePinning';
import { signValue } from './lib/cookies';
import { scopeFor } from './httpEdges';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'freedom-sign');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const NODE = FIXTURE_NODE;
const OTHER = 'node-two';
const EDGE_A = '198.51.100.1';
const OTHER_ADDR = '198.51.100.50';
const UUID = '11111111-2222-4333-8444-555555555555';
const SQUAD = '33333333-3333-4333-8333-333333333333';
const SQUAD_B = '44444444-4444-4444-8444-444444444444';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';
/** The covered node's template Host (`<node>-relay-<listenerKey>`), and an uncovered node's own address. */
const COVERED_LINE = `vless://${UUID}@${EDGE_A}:443?${REALITY_QS}#${NODE}-relay-a`;
const OTHER_LINE = `vless://${UUID}@${OTHER_ADDR}:443?${REALITY_QS}#${encodeURIComponent(`${OTHER} | target.example`)}`;

function stubPanel(body: string) {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () => new Response(body, { status: 200, headers: { 'content-type': 'text/plain' } }),
    ),
  );
}

const setSwitch = (t: T, on: boolean) =>
  t.run((ctx) => upsertSettingRow(ctx, FREEDOM_EDGES_ONLY_KEY, JSON.stringify(on)));

/**
 * One backend whose node `node-one` an origin covers with a published L4 edge,
 * a freedom mode (`freedom-reality`) whose pool is one group, and keys in it.
 */
async function seed(
  opts: {
    keys?: Array<{ token: string; short: string; pinned?: string; placement?: string | null }>;
    mode?: string;
    /** The freedom modes' pools (default: `freedom-reality` holds one group). */
    pools?: Record<string, string[]>;
  } = {},
) {
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, {
    listeners: [realityListener({ tlsNames: ['a.example'] })],
  });
  await t.mutation(internal.seed.seedConnectionModes, {});
  const keys = opts.keys ?? [{ token: 'tok_one', short: 'short-1', pinned: OTHER }];
  const subIds = await t.run(async (ctx) => {
    for (const [modeSlug, squadUuids] of Object.entries(
      opts.pools ?? { 'freedom-reality': [SQUAD] },
    ))
      await ctx.db.insert('modePlacements', {
        modeSlug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids }),
        updatedAt: Date.now(),
      });
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const ids: Id<'subscriptions'>[] = [];
    for (const k of keys) {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        ...(opts.mode ? { connectionModeId: opts.mode } : {}),
        updatedAt: Date.now(),
      });
      const placement = k.placement === undefined ? SQUAD : k.placement;
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: `uuid-${k.short}`,
        backendShortId: k.short,
        backendServerId: fx.serverId,
        subscriptionUrl: `https://panel.example/sub/${k.short}`,
        subscriptionMirrors: [],
        subToken: k.token,
        state: 'active',
        ...(placement ? { backendPlacement: placement } : {}),
        ...(k.pinned ? { pinnedNode: k.pinned } : {}),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      ids.push(subId);
    }
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return ids;
  });
  await t.mutation(internal.relays.adoptEdge, {
    relayId: fx.relayId,
    listenerId: fx.listenerId,
    ipv4: EDGE_A,
    publish: true,
    verified: true,
  });
  return { t, serverId: fx.serverId, relayId: fx.relayId, subIds };
}

const sub = (t: T, token = 'tok_one') =>
  t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': 'v2rayNG/1.9.0' } });

async function memberCookie(t: T, subId: Id<'subscriptions'>) {
  const userId = (await t.run((ctx) => ctx.db.get(subId)))!.userId;
  const sid = `sid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'member', userId, ttlMs: 3_600_000 });
  return `fs_session=${await signValue(sid, 'freedom-sign')}`;
}

describe('the delivery rule', () => {
  test('off: a freedom key on a node no edge covers is handed that node, as before', async () => {
    stubPanel(OTHER_LINE);
    const { t } = await seed();
    const res = await sub(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(OTHER_ADDR);
  });

  test('on: the same key is answered node_unprotected, never the node', async () => {
    stubPanel(OTHER_LINE);
    const { t, subIds } = await seed();
    await setSwitch(t, true);
    const res = await sub(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('node_unprotected');
    expect(await res.text()).not.toContain(OTHER_ADDR);
    // The raw-config view applies the same decision.
    const raw = await t.fetch('/api/v1/subscription/content', {
      headers: { cookie: await memberCookie(t, subIds[0]!) },
    });
    expect(raw.status).toBe(503);
    const text = await raw.text();
    expect(text).not.toContain(OTHER_ADDR);
    expect(JSON.parse(text).error.details).toEqual({ reason: 'node_unprotected' });
    // A mirror renders through the same decision (its body becomes the stub).
    expect(
      await t.query(internal.edgeRender.decideForSubscription, {
        subscriptionId: subIds[0]!,
        family: 'other',
        nodeName: OTHER,
      }),
    ).toEqual({ kind: 'unavailable', reason: 'node_unprotected', relaySlug: null });
    // Counted like every refusal: the operator sees dark members.
    const refusals = await t.run((ctx) => ctx.db.query('appState').collect());
    expect(JSON.stringify(refusals)).toContain('node_unprotected');
  });

  test('on: a privacy key on the same node is still handed it', async () => {
    stubPanel(OTHER_LINE);
    const { t } = await seed({
      mode: 'privacy-reality',
      keys: [{ token: 'tok_one', short: 'short-1', pinned: OTHER, placement: null }],
    });
    await setSwitch(t, true);
    const res = await sub(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(OTHER_ADDR);
  });

  test("on: a key in a privacy group is handed its node, whatever its member's stored mode", async () => {
    stubPanel(OTHER_LINE);
    // The group decides what the body carries; a stored or default mode does not hold a key.
    const { t, subIds } = await seed({
      mode: 'freedom-ws',
      keys: [{ token: 'tok_one', short: 'short-1', pinned: OTHER, placement: null }],
    });
    await setSwitch(t, true);
    const res = await sub(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(OTHER_ADDR);
    expect(
      await t.query(internal.freedomDelivery.rawUrlWithheld, { subscriptionId: subIds[0]! }),
    ).toBe(false);
  });

  test('on: a freedom key on the covered node gets the edge, never the origin', async () => {
    stubPanel(COVERED_LINE);
    const { t } = await seed({ keys: [{ token: 'tok_one', short: 'short-1', pinned: NODE }] });
    await setSwitch(t, true);
    const res = await sub(t);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain(`@${EDGE_A}:443?`);
    expect(body).not.toContain(FIXTURE_ORIGIN);
  });

  test('a body cached before the switch moved never answers the key after it', async () => {
    stubPanel(OTHER_LINE);
    const { t, serverId } = await seed();
    expect((await sub(t)).status).toBe(200);
    const before = await t.query(internal.edgeRender.epochFor, {
      backendServerId: serverId,
      nodeName: OTHER,
    });
    expect(before).toBeNull();
    await setSwitch(t, true);
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: OTHER }),
    ).toBe('f');
    // The fresh cache entry is keyed under the old token: the request decides again.
    const res = await sub(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('node_unprotected');
  });

  test('an unmanaged node a maintenance hold closes re-keys its cache too', async () => {
    stubPanel(OTHER_LINE);
    const { t, serverId } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('panelMaintenanceHolds', {
        backendServerId: serverId,
        transitionId: 'hold-1',
        reason: 'maintenance',
        heldNodeNames: [OTHER],
        closedIntentIds: [],
        released: false,
        since: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    const token = await t.query(internal.edgeRender.epochFor, {
      backendServerId: serverId,
      nodeName: OTHER,
    });
    expect(token).toMatch(/^g/);
  });

  test('on: the pinner lands a freedom key on the covered node when the body has one', async () => {
    stubPanel(`${OTHER_LINE}\n${COVERED_LINE}`);
    const keys = Array.from({ length: 6 }, (_, i) => ({ token: `tok_${i}`, short: `short-${i}` }));
    const { t, serverId } = await seed({ keys });
    await setSwitch(t, true);
    const rules = await t.query(internal.freedomDelivery.pinRules, {
      backendServerId: serverId,
      backendShortId: 'short-0',
    });
    expect(rules.servable).toEqual([NODE]);
    for (const k of keys) {
      const res = await sub(t, k.token);
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain(`@${EDGE_A}:443?`);
      expect(body).not.toContain(OTHER_ADDR);
    }
  });

  test("an operator's look at one node keeps the plain pick (the rehearsal before a binding)", async () => {
    stubPanel(`${OTHER_LINE}\n${COVERED_LINE}`);
    // A key whose plain pick is the uncovered node.
    const short = Array.from({ length: 50 }, (_, i) => `short-${i}`).find(
      (k) => pickNode(k, [OTHER, NODE]) === OTHER,
    )!;
    const { t, serverId } = await seed({ keys: [{ token: 'tok_one', short }] });
    await setSwitch(t, true);
    const fetch = (nodeCheck: boolean) =>
      t.action(internal.backends.fetchSubscriptionContent, {
        backend: 'remnawave',
        backendServerId: serverId,
        backendShortId: short,
        subscriptionUrl: `https://panel.example/sub/${short}`,
        ...(nodeCheck ? { nodeCheck } : {}),
      });
    expect((await fetch(false)).pinnedNode).toBe(NODE);
    expect((await fetch(true)).pinnedNode).toBe(OTHER);
  });

  test('on: the raw backend URL of a freedom key is never shown', async () => {
    stubPanel(OTHER_LINE);
    const { t, subIds } = await seed();
    expect(
      await t.query(internal.freedomDelivery.rawUrlWithheld, { subscriptionId: subIds[0]! }),
    ).toBe(false);
    await setSwitch(t, true);
    expect(
      await t.query(internal.freedomDelivery.rawUrlWithheld, { subscriptionId: subIds[0]! }),
    ).toBe(true);
  });
});

describe('the pick and the verdict (pure)', () => {
  test('a servable node is preferred over the previous pin, an excluded node within the servable is avoided', () => {
    const nodes = ['a', 'b', 'c'];
    expect(pickNode('k', nodes, undefined, (n) => n === 'b')).toBe('b');
    // The only servable node is the previous pin: still picked (never an uncovered one).
    expect(pickNode('k', nodes, ['b'], (n) => n === 'b')).toBe('b');
    // No servable node in the body: the pick falls back to every node.
    expect(nodes).toContain(pickNode('k', nodes, undefined, () => false));
    const body = `${OTHER_LINE}\n${COVERED_LINE}`;
    expect(pinSubscriptionToNode(body, 'any-key', undefined, (n) => n === NODE).node).toBe(NODE);
    expect(pinSubscriptionToNode(body, 'any-key', undefined, (n) => n === OTHER).node).toBe(OTHER);
  });

  test('why a node is held back', () => {
    const none = { bound: false, layers: new Set<'l4' | 'l7'>() };
    const l4 = { bound: true, layers: new Set<'l4' | 'l7'>(['l4']) };
    const empty = { bound: true, layers: new Set<'l4' | 'l7'>() };
    expect(withheldReason({ protection: none, enrolled: false, fronting: null })).toBe(
      'withheld_unmanaged',
    );
    expect(withheldReason({ protection: none, enrolled: true, fronting: 'edge-l4' })).toBe(
      'withheld_unprotected',
    );
    expect(withheldReason({ protection: none, enrolled: true, fronting: 'direct' })).toBe(
      'withheld_direct_mode',
    );
    expect(withheldReason({ protection: empty, enrolled: true, fronting: 'edge-l4' })).toBe(
      'withheld_no_edge',
    );
    // An edge of another layer does not cover the mode.
    expect(withheldReason({ protection: l4, enrolled: true, fronting: 'edge-l7' })).toBe(
      'withheld_no_edge',
    );
    expect(withheldReason({ protection: l4, enrolled: true, fronting: 'edge-l4' })).toBeNull();
    // A mode whose layer is unknown is covered by any live edge.
    expect(withheldReason({ protection: l4, enrolled: false, fronting: null })).toBeNull();
  });
});

/** A ready setup row carrying one mode with the given fronting (enough for the refusals). */
async function insertSetup(
  t: T,
  serverId: Id<'backendServers'>,
  slug: string,
  fronting: 'direct' | 'edge-l4',
) {
  await t.run((ctx) =>
    ctx.db.insert('panelSetups', {
      backendServerId: serverId,
      desired: '{}',
      desiredHash: 'h',
      generation: 1,
      state: 'ready',
      profileName: 'FreeSocks-Config',
      modes: [
        {
          slug,
          name: 'Mode',
          shape: { transport: 'reality', fronting },
          acceptProxyProtocol: false,
          tag: 'MODE',
          placement: 'bound',
          family: 'none',
        },
      ],
      templates: [],
      adopted: false,
      readyAt: Date.now(),
      gateVersion: 0,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }),
  );
}

describe('saving a freedom mode set up direct', () => {
  async function modes() {
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    await t.mutation(internal.seed.seedConnectionModes, {});
    await insertSetup(t, serverId, 'freedom-reality', 'direct');
    return { t, serverId };
  }

  test('on: turning on, moving into the family or creating one is refused with the reason', async () => {
    const { t } = await modes();
    await setSwitch(t, true);
    await expect(
      t.mutation(internal.connectionModes.updateMode, { slug: 'freedom-reality', enabled: true }),
    ).rejects.toThrow(/only served through edges.*set up direct/);
    // Moving a privacy mode set up direct into the freedom family.
    await insertSetup(
      t,
      (await insertPanelServer(t, { slug: 'other-panel' })) as never,
      'privacy-reality',
      'direct',
    );
    await expect(
      t.mutation(internal.connectionModes.updateMode, {
        slug: 'privacy-reality',
        family: 'freedom',
      }),
    ).rejects.toThrow(/only served through edges/);
    // Turning the freedom family back on while a direct freedom mode is on.
    await t.mutation(internal.connectionModes.updateFamily, { slug: 'freedom', enabled: false });
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'freedom-reality',
      enabled: false,
    });
    await t.run(async (ctx) => {
      const m = await ctx.db
        .query('connectionModes')
        .withIndex('by_slug', (q) => q.eq('slug', 'freedom-reality'))
        .unique();
      await ctx.db.patch(m!._id, { enabled: true });
    });
    await expect(
      t.mutation(internal.connectionModes.updateFamily, { slug: 'freedom', enabled: true }),
    ).rejects.toThrow(/only served through edges/);
    // Copy edits and turning it off stay allowed.
    await t.mutation(internal.connectionModes.updateMode, { slug: 'freedom-reality', label: 'X' });
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'freedom-reality',
      enabled: false,
    });
  });

  test('off: the same saves go through', async () => {
    const { t } = await modes();
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'freedom-reality',
      enabled: true,
    });
    const row = await t.run((ctx) =>
      ctx.db
        .query('connectionModes')
        .withIndex('by_slug', (q) => q.eq('slug', 'freedom-reality'))
        .unique(),
    );
    expect(row!.enabled).toBe(true);
  });

  test('on: a backend setup that adds a freedom mode direct is refused before any write', async () => {
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    await t.mutation(internal.seed.seedConnectionModes, {});
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam',
      label: 'fam',
      targetAddress: 'decoy.example',
      targetPort: 443,
    });
    const calls = vi.fn(async () => new Response('', { status: 500 }));
    vi.stubGlobal('fetch', calls);
    await setSwitch(t, true);
    const input = {
      profileName: 'FreeSocks-Config',
      modes: [
        {
          slug: 'freedom-reality',
          name: 'Freedom-Direct',
          shape: { transport: 'reality' as const, fronting: 'direct' as const },
          familySlug: 'fam',
          acceptProxyProtocol: false,
        },
      ],
      originDns: null,
      adopt: false,
    };
    await expect(
      t.mutation(internal.backendSetup.start, { backendServerId: serverId, input }),
    ).rejects.toThrow(/servers\.freedom_mode_direct:freedom-reality/);
    expect(calls).not.toHaveBeenCalled();
    // A privacy mode set up direct is what direct is for.
    await t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: { ...input, modes: [{ ...input.modes[0]!, slug: 'privacy-reality' }] },
    });
  });
});

describe('the seed', () => {
  const stored = (t: T) =>
    t.run(async (ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', FREEDOM_EDGES_ONLY_KEY))
        .unique(),
    );

  test('a deployment with no members gets it on', async () => {
    const t = convexTest(schema, modules);
    expect(await t.mutation(internal.seed.seedFreedomEdgesOnly, {})).toEqual({
      inserted: true,
      on: true,
    });
    expect((await stored(t))!.value).toBe('true');
  });

  test('a deployment that already has members gets it off', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
    });
    expect(await t.mutation(internal.seed.seedFreedomEdgesOnly, {})).toEqual({
      inserted: true,
      on: false,
    });
    expect((await stored(t))!.value).toBe('false');
  });

  test('a stored value is never touched again, whichever way it was set', async () => {
    const t = convexTest(schema, modules);
    await setSwitch(t, false);
    expect(await t.mutation(internal.seed.seedFreedomEdgesOnly, {})).toEqual({
      inserted: false,
      on: false,
    });
    const out = await t.action(internal.seed.seedCutover, {});
    expect(out.freedomEdgesOnly).toBe(false);
    expect((await stored(t))!.value).toBe('false');
  });

  test('no generic settings write reaches it', async () => {
    const t = convexTest(schema, modules);
    // The Edges settings patch writes only the `edge.*` knobs it knows.
    await t.mutation(internal.edgeAdmin.patchConfig, {
      patch: { 'freedom.edgesOnly': true, 'edge.freedom.edgesOnly': true },
    });
    expect(await stored(t)).toBeNull();
  });
});

describe('the preview and the switch', () => {
  /** Two keys in the freedom mode: one on the covered node, one on a node no edge covers. */
  const twoKeys = [
    { token: 'tok_cov', short: 'short-cov', pinned: NODE },
    { token: 'tok_one', short: 'short-1', pinned: OTHER },
  ];

  test('counts the nodes and members it would close, per mode', async () => {
    const { t } = await seed({ keys: twoKeys });
    const p = await t.action(internal.freedomDelivery.preview, {});
    expect(p.on).toBe(false);
    const m = p.modes.find((x) => x.mode === 'freedom-reality')!;
    expect(m.nodes).toEqual({ total: 2, servable: 1, withheld: 1 });
    expect(m.withheldNodes).toEqual([
      { node: OTHER, nodeUuid: null, enrolled: false, reason: 'withheld_unmanaged' },
    ]);
    // The key on the uncovered node moves to the covered one: nobody is cut off.
    expect(m.members).toEqual({ total: 2, onWithheld: 1, cutOff: 0, moved: 1 });
    expect(p.totals).toEqual({ withheldNodes: 1, affectedMembers: 1, cutOffMembers: 0 });
    expect(JSON.stringify(p)).not.toContain(SQUAD);
  });

  test('a mode with no covered node: every member of it is cut off', async () => {
    const { t } = await seed({
      keys: [
        { token: 'tok_one', short: 'short-1', pinned: OTHER },
        { token: 'tok_two', short: 'short-2' },
      ],
    });
    const p = await t.action(internal.freedomDelivery.preview, {});
    const m = p.modes.find((x) => x.mode === 'freedom-reality')!;
    expect(m.nodes).toEqual({ total: 1, servable: 0, withheld: 1 });
    expect(m.members).toEqual({ total: 2, onWithheld: 1, cutOff: 2, moved: 0 });
    expect(p.totals.cutOffMembers).toBe(2);
  });

  test('a group is judged on its own: a covered node of another group of the mode does not save it', async () => {
    const { t } = await seed({
      pools: { 'freedom-reality': [SQUAD, SQUAD_B] },
      keys: [
        ...twoKeys,
        { token: 'tok_b1', short: 'short-b1', pinned: 'node-three', placement: SQUAD_B },
        { token: 'tok_b2', short: 'short-b2', placement: SQUAD_B },
      ],
    });
    const p = await t.action(internal.freedomDelivery.preview, {});
    const m = p.modes.find((x) => x.mode === 'freedom-reality')!;
    expect(m.nodes).toEqual({ total: 3, servable: 1, withheld: 2 });
    // Group A's key on the uncovered node moves; group B has no covered node: both its keys get nothing.
    expect(m.members).toEqual({ total: 4, onWithheld: 2, cutOff: 2, moved: 1 });
    expect(p.totals).toEqual({ withheldNodes: 2, affectedMembers: 3, cutOffMembers: 2 });
  });

  test('a freedom group with keys and no known node is cut off, and turning it on needs the confirm', async () => {
    const { t } = await seed({
      keys: [
        { token: 'tok_one', short: 'short-1' },
        { token: 'tok_two', short: 'short-2' },
      ],
    });
    const p = await t.action(internal.freedomDelivery.preview, {});
    const m = p.modes.find((x) => x.mode === 'freedom-reality')!;
    expect(m.nodes).toEqual({ total: 0, servable: 0, withheld: 0 });
    expect(m.members).toEqual({ total: 2, onWithheld: 0, cutOff: 2, moved: 0 });
    await expect(t.mutation(internal.freedomDelivery.setEdgesOnly, { on: true })).rejects.toThrow(
      /would no longer be handed/,
    );
  });

  test('a key pinned under a name its node had before a rename counts as on that node', async () => {
    const { t, serverId } = await seed({
      keys: [
        { token: 'tok_cov', short: 'short-cov', pinned: NODE },
        { token: 'tok_old', short: 'short-old', pinned: 'node-old' },
      ],
    });
    await t.run(async (ctx) => {
      const renameId = await ctx.db.insert('panelNodeRenames', {
        backendServerId: serverId,
        nodeUuid: 'uuid-two',
        from: 'node-old',
        to: OTHER,
        relayIds: [],
        state: 'done',
        step: 'done',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('panelNodeAliases', {
        backendServerId: serverId,
        formerName: 'node-old',
        name: OTHER,
        nodeUuid: 'uuid-two',
        renameId,
        at: Date.now(),
      });
    });
    const p = await t.action(internal.freedomDelivery.preview, {});
    const m = p.modes.find((x) => x.mode === 'freedom-reality')!;
    expect(m.withheldNodes.map((n) => n.node)).toEqual([OTHER]);
    expect(m.members).toEqual({ total: 2, onWithheld: 1, cutOff: 0, moved: 1 });
    await expect(t.mutation(internal.freedomDelivery.setEdgesOnly, { on: true })).rejects.toThrow(
      /would no longer be handed/,
    );
  });

  test('a group two freedom modes share counts each key once in the totals', async () => {
    const { t } = await seed({
      pools: { 'freedom-reality': [SQUAD], 'freedom-xhttp': [SQUAD] },
      keys: twoKeys,
    });
    const p = await t.action(internal.freedomDelivery.preview, {});
    expect(p.modes.map((m) => [m.mode, m.members.moved])).toEqual([
      ['freedom-reality', 1],
      ['freedom-xhttp', 1],
    ]);
    expect(p.totals).toEqual({ withheldNodes: 1, affectedMembers: 1, cutOffMembers: 0 });
  });

  test('turning it on with members affected needs the confirm, and is audited', async () => {
    const { t } = await seed({ keys: twoKeys });
    await expect(t.mutation(internal.freedomDelivery.setEdgesOnly, { on: true })).rejects.toThrow(
      /edge\.freedom_confirm_required|would no longer be handed/,
    );
    expect((await t.query(internal.freedomDelivery.view, {})).on).toBe(false);
    const state = await t.mutation(internal.freedomDelivery.setEdgesOnly, {
      on: true,
      confirm: true,
    });
    expect(state.on).toBe(true);
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'edge.freedom.edges_only'))
        .collect(),
    );
    expect(audit.map((a) => a.payload)).toEqual([
      { on: true, confirmed: true, withheldNodes: 1, affected: true },
    ]);
    // Every mirror is rendered again in one full pass, not the sweep's window.
    const jobs = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(jobs.map((j) => j.name)).toContain('storage:drainMirrors');
    // Off needs no confirm.
    expect((await t.mutation(internal.freedomDelivery.setEdgesOnly, { on: false })).on).toBe(false);
  });

  test('the routes: reading it and its preview takes the settings read scope, the switch its write scope', () => {
    expect(scopeFor(['freedom'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['freedom', 'preview'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['freedom'], 'POST')).toBe('admin:settings:write');
  });

  test('turning it on with nobody affected needs no confirm', async () => {
    const { t } = await seed({ keys: [{ token: 'tok_cov', short: 'short-cov', pinned: NODE }] });
    expect((await t.mutation(internal.freedomDelivery.setEdgesOnly, { on: true })).on).toBe(true);
  });

  test('on: every held-back node is an attention item with its reason, never an address', async () => {
    const { t } = await seed({ keys: twoKeys });
    await setSwitch(t, true);
    const { items } = await t.query(internal.edgeOperator.attention, {});
    const withheld = items.filter((i) => i.kind === 'freedom_node_withheld');
    expect(withheld).toHaveLength(1);
    expect(withheld[0]).toMatchObject({
      code: 'withheld_unmanaged',
      action: 'protect_node',
      facts: { node: OTHER, mode: 'freedom-reality', enrolled: false },
    });
    expect(JSON.stringify(withheld)).not.toContain(OTHER_ADDR);
    await setSwitch(t, false);
    const off = await t.query(internal.edgeOperator.attention, {});
    expect(off.items.some((i) => i.kind === 'freedom_node_withheld')).toBe(false);
  });
});
