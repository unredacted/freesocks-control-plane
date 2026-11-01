// @vitest-environment node
/// <reference types="vite/client" />
/**
 * A node that answers only for its own name (a terminator with one site
 * block, no catch-all): the origin probe reads `acceptsHostHeader: names`, a
 * CDN front that sends its own name would be refused, and a front FCP builds
 * at a provider whose template can send the origin's name is built to, with
 * that choice frozen in the edge's intent (lib/edges/layers.ts
 * `withOriginHost`). Fixtures are RFC 5737 literals and `*.example` names.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { __setEdgeProviderForTests } from './lib/edges/providers/registry';
import { FastlyTemplate } from './lib/edges/providers/templates';
import type { EdgeProvider, EdgeSpec } from './lib/edges/providers/types';
import { parseIntent } from './lib/edges/intent';
import {
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  registerRelay,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

const ORIGIN = 'node-one.origin.example';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const ZONE = 'fronts.example.org';
const ZONE_ID = 'a'.repeat(32);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setEdgeProviderForTests('fastly', null);
});

/** A Fastly adapter with the REAL template schema that records the template each call got. */
function fakeFastly() {
  const seen: Array<{ call: string; overrideHost: unknown }> = [];
  const provider = {
    id: 'fastly',
    templateSchema: FastlyTemplate,
    templateFields: [],
    defaultTemplate: {},
    testCredentials: async () => ({ ok: true }),
    planProvision: (_cfg: unknown, spec: EdgeSpec, tpl: Record<string, unknown>) => {
      seen.push({ call: 'plan', overrideHost: tpl.overrideHost });
      return [
        { id: 'svc', kind: 'create_service', resourceName: spec.name, discoverability: 'by_name' },
      ];
    },
    runStep: async () => ({ status: 'pending' }),
    discover: async () => ({ status: 'unresolved' }),
    describe: async () => ({ state: 'pending', addresses: {}, health: 'unknown' }),
    inspect: async () => ({ summary: { addresses: {}, members: [], listeners: [] }, raw: {} }),
    inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
    planDestroy: () => [],
    runDestroy: async () => ({ status: 'confirmed_gone' }),
  } as unknown as EdgeProvider;
  __setEdgeProviderForTests('fastly', provider);
  return { seen };
}

async function seed(acceptsHostHeader: 'any' | 'names') {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  mockFetch(() => jsonRes({ response: [] }));
  await t.run(async (ctx) => {
    for (const [key, value] of [
      ['edge.enabled', 'true'],
      ['edge.l7.autoSelect', 'false'],
    ] as const)
      await ctx.db.insert('appSettings', { key, value, updatedAt: Date.now() });
  });
  // The DNS account the front writes its records through (DNS only).
  const { id: dnsAccountId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudflare',
    name: 'acct-dns',
    settings: { zoneId: ZONE_ID, zoneName: ZONE },
    credentials: { apiToken: 'cf' },
  });
  const { id: fastly } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'fastly',
    name: 'acct-fastly',
    settings: {
      dnsAccountId,
      zoneId: ZONE_ID,
      zoneName: ZONE,
      certificateAuthority: 'certainly',
    } as never,
    credentials: { apiToken: 'fs' },
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fastly, ok: true });
  await t.mutation(internal.edgeProviderAccounts.setQualified, { id: fastly, qualified: true });
  // A Cloudflare account that fronts traffic itself: its front sends its own name.
  const { id: cloudflare } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudflare',
    name: 'acct-cf',
    settings: { zoneId: 'b'.repeat(32), zoneName: 'cf.example.org' },
    credentials: { apiToken: 'cf2' },
    frontsTraffic: true,
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, {
    id: cloudflare,
    ok: true,
    observed: { zoneSslMode: 'full', websockets: 'on' },
  });
  await t.mutation(internal.edgeProviderAccounts.setQualified, { id: cloudflare, qualified: true });
  await t.run(async (ctx) => {
    for (const zone of await ctx.db
      .query('edgeLocations')
      .withIndex('by_account', (q) => q.eq('accountId', cloudflare))
      .collect())
      await ctx.db.patch(zone._id, {
        observed: JSON.stringify({ zoneSslMode: 'full' }),
        observedAt: Date.now(),
      });
  });
  const { relayId, listenerId } = await registerRelay(t, {
    originAddress: ORIGIN,
    listeners: [
      wsListener({
        listenerKey: 'w',
        tlsNames: [ORIGIN],
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: [ORIGIN],
          acceptsHostHeader,
        },
        transportParams: { path: '/ws' },
        panelBinding: {
          inboundTag: 'VLESS_WS',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: INBOUND,
        },
      }),
    ],
  });
  return { t, fastly, cloudflare, relayId, listenerId };
}

async function planOnce(
  t: Awaited<ReturnType<typeof seed>>['t'],
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
  accountId: Id<'edgeProviderAccounts'>,
) {
  const { rotationId } = await t.mutation(internal.edgeRotations.start, {
    relayId,
    kind: 'provision',
    trigger: 'manual',
    listenerId,
    requestedAccountId: accountId,
    publishOnDone: false,
  });
  // One step: select, plan and freeze the intent.
  await t.action(internal.edgeRotations.step, { rotationId });
  return (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
}

describe('a node that answers only for its own name', () => {
  test("a Fastly front is built to send the node's name, and its intent freezes that", async () => {
    const adapter = fakeFastly();
    const { t, fastly, relayId, listenerId } = await seed('names');
    const r = await planOnce(t, relayId, listenerId, fastly);
    expect(r.events?.map((e) => e.code)).not.toContain('failed');
    expect(r.toEdgeId).toBeTruthy();
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    const intent = parseIntent(edge.provisionIntent)!;
    // The template (and the pick) said "the front name"; the node would refuse it.
    expect(intent.templateParams.overrideHost).toBe('origin');
    expect(intent.originTransport.acceptsHostHeader).toBe('names');
    expect(adapter.seen.length).toBeGreaterThan(0);
    expect(adapter.seen.every((x) => x.call === 'plan' && x.overrideHost === 'origin')).toBe(true);
    // The template row itself is untouched: only this front sends the node's name.
    const tpl = await t.run(async (ctx) =>
      (await ctx.db.query('edgeTemplates').collect()).filter((x) => x.provider === 'fastly'),
    );
    for (const row of tpl)
      expect((row.params as { overrideHost?: string }).overrideHost).not.toBe('origin');
  });

  test('a node that takes any Host keeps the template: the front sends its own name', async () => {
    const adapter = fakeFastly();
    const { t, fastly, relayId, listenerId } = await seed('any');
    const r = await planOnce(t, relayId, listenerId, fastly);
    expect(r.events?.map((e) => e.code)).not.toContain('failed');
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(parseIntent(edge.provisionIntent)!.templateParams.overrideHost).toBe('hostname');
    expect(adapter.seen.length).toBeGreaterThan(0);
    expect(adapter.seen.every((x) => x.call === 'plan' && x.overrideHost === 'hostname')).toBe(
      true,
    );
  });

  test('a CDN whose front sends its own name is not a candidate for it, even when named', async () => {
    fakeFastly();
    const { t, cloudflare, relayId, listenerId } = await seed('names');
    const r = await planOnce(t, relayId, listenerId, cloudflare);
    expect(r.phase).toBe('failed');
    expect(r.toEdgeId).toBeUndefined();
    expect(JSON.stringify(r.events ?? [])).toContain('account_incompatible');
  });
});
