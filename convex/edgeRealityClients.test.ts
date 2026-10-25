/// <reference types="vite/client" />
/**
 * Which clients a node's REALITY transports let in (convex/edgeRealityClients.ts):
 * read from the panel (the transport's `minClientVer` / `maxClientVer`, the
 * node's Xray version), judged, and kept on a protected origin for attention
 * `reality_refuses_clients` and the setup-status warning. The beta case: a
 * hand-built transport with no `minClientVer` on Xray 26.7.28 refuses every
 * sing-box and Mihomo client while a test made with an Xray client passes.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { fakePanel } from './lib/edges/testing/fakePanel';
import {
  adoptL4Edge,
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  FIXTURE_NODE,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const NODE_UUID = '33333333-3333-4333-8333-333333333333';
const EDGE = '198.51.100.7';
/** A 32-byte REALITY private key (base64url), as the panel stores it. */
const REALITY_PRIVATE_KEY = Buffer.alloc(32, 7).toString('base64url');

/** The node's profile as the panel serves it; `bounds` go into the transport's realitySettings. */
function profile(bounds: Record<string, unknown> = {}) {
  return {
    uuid: FIXTURE_CONFIG_PROFILE,
    name: 'node-one',
    config: {
      inbounds: [
        {
          tag: 'VLESS_RELAY_A',
          port: 443,
          protocol: 'vless',
          settings: { clients: [] },
          streamSettings: {
            network: 'tcp',
            security: 'reality',
            realitySettings: {
              target: 'target.example:443',
              serverNames: ['target.example'],
              privateKey: REALITY_PRIVATE_KEY,
              shortIds: ['abcd'],
              ...bounds,
            },
          },
        },
      ],
    },
    inbounds: [{ uuid: FIXTURE_INBOUND, tag: 'VLESS_RELAY_A' }],
  };
}

/** A 3.x node row: its Xray version under `versions` (null while it has not answered). */
const nodeRow = (xray: string | null) => ({
  uuid: NODE_UUID,
  name: FIXTURE_NODE,
  isConnected: true,
  versions: xray ? { xray, node: '3.4.2' } : null,
});

/**
 * A protected origin (`node-one`, REALITY listener `a` on VLESS_RELAY_A, a
 * published edge: bound) on a panel whose answers the test changes as it goes.
 */
async function world(opts: { xray?: string | null; bounds?: Record<string, unknown> } = {}) {
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  const served = {
    nodes: [nodeRow(opts.xray === undefined ? '26.7.28' : opts.xray)] as unknown[],
    profiles: { [FIXTURE_CONFIG_PROFILE]: profile(opts.bounds) } as Record<string, unknown>,
  };
  const panel = fakePanel(served);
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t);
  await adoptL4Edge(t, fx.relayId, fx.listenerId, { ipv4: EDGE, publish: true });
  const relay = async () => (await t.run((ctx) => ctx.db.get(fx.relayId)))!;
  const attention = async () =>
    (await t.query(internal.edgeOperator.attention, {})).items.filter(
      (i) => i.kind === 'reality_refuses_clients',
    );
  const relayWarnings = async () =>
    (await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'node-one' })).steps
      .find((s) => s.id === 'relay')!
      .warnings.filter((w) => w.code === 'reality_refuses_clients');
  return { t, fx, panel, served, relay, attention, relayWarnings };
}

const check = (w: Awaited<ReturnType<typeof world>>, tag = 'VLESS_RELAY_A') =>
  w.t.action(internal.edgeRealityClients.check, {
    backendServerId: w.fx.serverId,
    nodeUuid: NODE_UUID,
    nodeName: FIXTURE_NODE,
    transports: [{ key: 'a', profileUuid: FIXTURE_CONFIG_PROFILE, tag }],
  });

describe('checking a REALITY transport on the panel', () => {
  test('no minClientVer on Xray 26.7.28: sing-box and Mihomo are refused', async () => {
    const w = await world();
    expect(await check(w)).toEqual([
      {
        key: 'a',
        tag: 'VLESS_RELAY_A',
        refusal: {
          refuses: ['singbox', 'mihomo'],
          reasons: [{ cause: 'core_default', families: ['singbox', 'mihomo'] }],
          xrayVersion: '26.7.28',
          minClientVer: null,
          maxClientVer: null,
        },
      },
    ]);
  });

  test('"minClientVer": "1.8.1" lets them in; an Xray before the default needs none', async () => {
    expect(
      (await check(await world({ bounds: { minClientVer: '1.8.1' } })))[0]!.refusal,
    ).toBeNull();
    expect((await check(await world({ xray: '26.6.27' })))[0]!.refusal).toBeNull();
  });

  test('from Xray 26.9.8 on, sing-box is refused whatever the transport sets', async () => {
    expect(
      (await check(await world({ bounds: { minClientVer: '1.8.1' }, xray: '26.10.21' })))[0]!
        .refusal,
    ).toMatchObject({
      refuses: ['singbox'],
      reasons: [{ cause: 'core_key_share', families: ['singbox'] }],
    });
  });

  test('a minClientVer above 1.8.1 refuses sing-box; a node that has not answered is unknown', async () => {
    expect(
      (await check(await world({ bounds: { minClientVer: '1.8.2' }, xray: '26.6.27' })))[0]!
        .refusal,
    ).toMatchObject({ refuses: ['singbox'], reasons: [{ cause: 'min_above' }] });
    expect((await check(await world({ xray: null })))[0]!.refusal).toMatchObject({
      reasons: [{ cause: 'core_unknown', families: ['singbox', 'mihomo'] }],
      xrayVersion: null,
    });
  });

  test('a transport the panel does not describe is left out; nothing secret is returned', async () => {
    const w = await world();
    expect(await check(w, 'VLESS_GONE')).toEqual([]);
    expect(JSON.stringify(await check(w))).not.toContain(REALITY_PRIVATE_KEY);
    // A panel that does not answer: nothing, never a throw.
    w.served.profiles = {};
    expect(await check(w)).toEqual([]);
  });
});

describe('a protected origin whose REALITY transport refuses clients', () => {
  test('the reconcile records it, attention and setup-status warn with each reason, and a fix clears both at the next look', async () => {
    const w = await world();
    expect(await w.attention()).toEqual([]);
    // The edge reconcile's Host pass runs the look after the direct-Host check.
    await w.t.action(internal.hostOps.reconcileHosts, {});
    expect((await w.relay()).realityClients?.refusals).toEqual([
      {
        listenerKey: 'a',
        tag: 'VLESS_RELAY_A',
        refuses: ['singbox', 'mihomo'],
        reasons: [{ cause: 'core_default', families: ['singbox', 'mihomo'] }],
        xrayVersion: '26.7.28',
        minClientVer: null,
        maxClientVer: null,
      },
    ]);
    const [item] = await w.attention();
    expect(item).toMatchObject({
      kind: 'reality_refuses_clients',
      severity: 'warning',
      relaySlug: 'node-one',
      // The row is worded from the verdict it carries (families, reasons, fixes).
      code: null,
      facts: {
        count: 1,
        refuses: ['singbox', 'mihomo'],
        transports: [
          {
            tag: 'VLESS_RELAY_A',
            refusal: {
              refuses: ['singbox', 'mihomo'],
              reasons: [{ cause: 'core_default', families: ['singbox', 'mihomo'] }],
              xrayVersion: '26.7.28',
              minClientVer: null,
              maxClientVer: null,
            },
          },
        ],
      },
      action: 'open_relay',
    });
    expect(await w.relayWarnings()).toEqual([
      { code: 'reality_refuses_clients', subject: 'a', detail: 'reality_core_default' },
    ]);
    // A look that sees the same writes nothing.
    const at = (await w.relay()).realityClients!.at;
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients!.at).toBe(at);

    // A second restriction is its own warning, with its own reason.
    w.served.profiles = { [FIXTURE_CONFIG_PROFILE]: profile({ maxClientVer: '1.8.1' }) };
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect(await w.relayWarnings()).toEqual([
      { code: 'reality_refuses_clients', subject: 'a', detail: 'reality_core_default' },
      { code: 'reality_refuses_clients', subject: 'a', detail: 'reality_max_below' },
    ]);

    // The operator adds the fix in the backend: the next look clears it.
    w.served.profiles = { [FIXTURE_CONFIG_PROFILE]: profile({ minClientVer: '1.8.1' }) };
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients).toBeUndefined();
    expect(await w.attention()).toEqual([]);
    expect(await w.relayWarnings()).toEqual([]);
  });

  test('a look the panel could not answer keeps what was known; a node moved off the default release clears it', async () => {
    const w = await world();
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients?.refusals).toHaveLength(1);
    const known = w.served.profiles;
    w.served.profiles = {};
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients?.refusals).toHaveLength(1);
    w.served.profiles = known;
    w.served.nodes = [nodeRow('26.6.27')];
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients).toBeUndefined();
    // Past 26.9.8 the default is gone, but sing-box is refused for another reason.
    w.served.nodes = [nodeRow('26.10.21')];
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    expect((await w.relay()).realityClients?.refusals[0]?.reasons).toEqual([
      { cause: 'core_key_share', families: ['singbox'] },
    ]);
  });

  test('an origin that is not bound yet is not looked at', async () => {
    const w = await world();
    await w.t.run(async (ctx) => {
      for (const b of await ctx.db.query('edgeDeliveryBindings').collect())
        await ctx.db.delete(b._id);
    });
    expect(await w.t.action(internal.edgeRealityClients.reobserve, {})).toEqual({
      relays: 0,
      refusing: 0,
    });
    expect((await w.relay()).realityClients).toBeUndefined();
  });

  test('the rollback clear leaves no field an older schema refuses', async () => {
    const w = await world();
    await w.t.action(internal.edgeRealityClients.reobserve, {});
    await w.t.run((ctx) =>
      ctx.db.insert('panelNodes', {
        backendServerId: w.fx.serverId,
        nodeUuid: NODE_UUID,
        name: FIXTURE_NODE,
        online: true,
        isDisabled: false,
        usersOnline: 0,
        activeInboundUuids: [FIXTURE_INBOUND],
        tags: [],
        xrayVersion: '26.7.28',
        observedAt: Date.now(),
      }),
    );
    expect(await w.t.mutation(internal.edgeRealityClients.clearForRollback, {})).toMatchObject({
      relays: 1,
      nodes: 1,
    });
    expect((await w.relay()).realityClients).toBeUndefined();
    const nodes = await w.t.run((ctx) => ctx.db.query('panelNodes').collect());
    expect(nodes[0]!.xrayVersion).toBeUndefined();
  });
});
