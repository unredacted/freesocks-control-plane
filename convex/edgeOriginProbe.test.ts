/// <reference types="vite/client" />
/**
 * `GET relays/inbound-candidates`: the node's inbounds mapped to candidates
 * with `originTransport` filled where the origin probe succeeded (and the
 * layers recomputed), unknown nodes refused, nothing registered.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { fakePanel } from './lib/edges/testing/fakePanel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { __setOriginProbeDepsForTests } from './edgeOriginProbeOps';
import { InboundCandidatesResponse } from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  __setOriginProbeDepsForTests(null);
});

const PROFILE = '0f1e2d3c-4b5a-4968-8776-655443322110';
const WS_UUID = '11111111-2222-4333-8444-555555555555';
const REALITY_UUID = '22222222-2222-4222-8222-222222222222';
const NODE_UUID = 'node-1';
const ORIGIN = '203.0.113.10';

function panelWithInbounds() {
  return fakePanel({
    nodes: [
      {
        uuid: NODE_UUID,
        name: 'node-one',
        configProfile: {
          activeConfigProfileUuid: PROFILE,
          activeInbounds: [
            { uuid: WS_UUID, tag: 'VLESS_WS' },
            { uuid: REALITY_UUID, tag: 'VLESS_REALITY' },
          ],
        },
      },
    ],
    profiles: {
      [PROFILE]: {
        uuid: PROFILE,
        name: 'p',
        config: {
          inbounds: [
            {
              tag: 'VLESS_WS',
              port: 443,
              protocol: 'vless',
              settings: { clients: [{ id: 'SECRET' }] },
              streamSettings: {
                network: 'ws',
                security: 'tls',
                wsSettings: { path: '/ws' },
                tlsSettings: { serverName: 'ws.example' },
              },
            },
            {
              tag: 'VLESS_REALITY',
              port: 8443,
              protocol: 'vless',
              settings: { clients: [{ id: 'SECRET' }] },
              streamSettings: {
                network: 'tcp',
                security: 'reality',
                realitySettings: {
                  dest: 'target.example:443',
                  serverNames: ['a.example'],
                  privateKey: 'PRIV',
                  shortIds: ['abcd'],
                },
              },
            },
          ],
        },
        inbounds: [
          { uuid: WS_UUID, tag: 'VLESS_WS' },
          { uuid: REALITY_UUID, tag: 'VLESS_REALITY' },
        ],
      },
    },
  });
}

async function seed() {
  const panel = panelWithInbounds();
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  await t.run((ctx) =>
    ctx.db.insert('backendNodeInventory', {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      name: 'node-one',
      usersOnline: 0,
      online: true,
      lastStatsAt: Date.now(),
      address: ORIGIN,
      port: 443,
    }),
  );
  return { t, panel, serverId };
}

describe('inbound candidates with the origin probe', () => {
  test('HTTP-transport candidates get their originTransport from the probe and become L7-frontable; the rest stay L4-only', async () => {
    const { t, serverId } = await seed();
    const probed: unknown[] = [];
    __setOriginProbeDepsForTests({
      lookup: async () => [],
      tcpConnect: async () => ({ ok: true }),
      tlsInspect: async (o) => {
        probed.push(o);
        return { ok: true, authorized: true, names: ['ws.example'] };
      },
      httpsStatus: async () => ({ status: 200 }),
    });
    const r = await t.action(internal.edgeOriginProbe.inboundCandidates, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
    });
    expect(InboundCandidatesResponse.parse(JSON.parse(JSON.stringify(r)))).toBeTruthy();
    expect(r.node).toEqual({ nodeUuid: NODE_UUID, name: 'node-one', address: ORIGIN });
    expect(r.originAddress).toBe(ORIGIN);
    expect(r.relaySlug).toBeNull();
    expect(r.unsupported).toEqual([]);
    const ws = r.candidates.find((c) => c.sourceTag === 'VLESS_WS')!;
    const reality = r.candidates.find((c) => c.sourceTag === 'VLESS_REALITY')!;
    expect(ws.originTransport).toEqual({
      scheme: 'https',
      certPublic: true,
      certNames: ['ws.example'],
      acceptsHostHeader: 'any',
    });
    expect(ws.listenerSpec.originTransport).toEqual(ws.originTransport);
    expect(ws.probe).toEqual({ ok: true, reason: null });
    expect(ws.layers.layers.sort()).toEqual(['l4', 'l7']);
    expect(reality.originTransport).toBeNull();
    expect(reality.probe).toBeNull();
    expect(reality.layers.layers).toEqual(['l4']);
    // Only the HTTP-transport inbound was dialled, at the node's address and the inbound's port.
    expect(probed).toEqual([
      { host: ORIGIN, port: 443, servername: 'ws.example', timeoutMs: 6000 },
    ]);
    // Nothing was registered or persisted.
    expect(await t.run((ctx) => ctx.db.query('relays').collect())).toEqual([]);
    expect(await t.run((ctx) => ctx.db.query('relayListeners').collect())).toEqual([]);
    // No secret from the profile leaks into the response.
    const blob = JSON.stringify(r);
    for (const s of ['SECRET', 'PRIV', 'abcd']) expect(blob).not.toContain(s);
  });

  test('a failed probe keeps the candidate L4-only with the reason; an unknown node is refused', async () => {
    const { t, serverId } = await seed();
    __setOriginProbeDepsForTests({
      lookup: async () => [],
      tcpConnect: async () => ({ ok: true }),
      tlsInspect: async () => ({ ok: false, authorized: false, names: [], error: 'timeout' }),
      httpsStatus: async () => ({ status: null }),
    });
    const r = await t.action(internal.edgeOriginProbe.inboundCandidates, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
    });
    const ws = r.candidates.find((c) => c.sourceTag === 'VLESS_WS')!;
    expect(ws.originTransport).toBeNull();
    expect(ws.probe).toEqual({ ok: false, reason: 'timeout' });
    expect(ws.layers.layers).toEqual(['l4']);
    await expect(
      t.action(internal.edgeOriginProbe.inboundCandidates, {
        backendServerId: serverId,
        nodeUuid: 'no-such-node',
      }),
    ).rejects.toThrow(/node_unknown/);
  });
});
