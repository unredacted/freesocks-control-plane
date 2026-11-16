// @vitest-environment node
/// <reference types="vite/client" />
/**
 * An EdgeOne front through the real machinery: the rotation machine plans,
 * builds, qualifies and publishes it, and the reconcile cron destroys it, with
 * the REAL EdgeOne adapter and SDK wrapper driven against a fake Tencent
 * account (lib/edges/testing/fakeEdgeOne.ts). Both ways a zone gets its
 * records: EdgeOne's own DNS (no DNS account on the location), and a DNS
 * account for a zone connected by CNAME, resolved for the adapter only where
 * the location (and then the edge's frozen intent) names one.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  jsonRes,
  mockFetch,
  routeFetch,
  type Captured,
  type PartialHandler,
} from './lib/edges/testing/mockFetch';
import { __setFrontChecker } from './frontQualifyOps';
import { __setEdgeOneApiFactory, edgeOneSdkApi } from './lib/edges/providers/edgeone/sdk';
import { __setEdgeOneCaaLookup, __setEdgeOneDnsClientFactory } from './lib/edges/providers/edgeone';
import { fakeEdgeOne, type FakeEdgeOne } from './lib/edges/testing/fakeEdgeOne';
import { fakeDnsZone } from './lib/edges/testing/fakeCloudFront';
import {
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  registerRelay,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

const ORIGIN = 'node-one.origin.example';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';
const ZONE = 'fronts.example.org';
const EO_ZONE_ID = 'zone-2abcdef01234';
const DNS_ZONE_ID = 'a'.repeat(32);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setEdgeOneApiFactory(null);
  __setEdgeOneDnsClientFactory(null);
  __setEdgeOneCaaLookup(null);
  __setFrontChecker(null);
});

/** A backend panel holding the node's one Host (`before`: a fake that answers its own host first). */
function fakePanel(before?: PartialHandler) {
  const hosts = [
    {
      uuid: HOST_UUID,
      remark: 'node-one-relay-w',
      address: '198.51.100.1',
      port: 443,
      sni: 'a.example',
      host: '',
      inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: INBOUND },
    },
  ];
  const panel = (c: Captured): Response => {
    if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: hosts });
    if (c.path === '/api/hosts' && c.method === 'PATCH') {
      const b = c.body as {
        uuid: string;
        address: string;
        port: number;
        sni?: string;
        host?: string;
      };
      const h = hosts.find((x) => x.uuid === b.uuid);
      if (h) Object.assign(h, b);
      return jsonRes({ response: h ?? null });
    }
    return jsonRes({ message: 'not found' }, 404);
  };
  mockFetch(before ? routeFetch(before, panel) : panel);
  return hosts;
}

async function seed(viaDnsAccount: boolean) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    for (const [key, value] of [
      ['edge.enabled', 'true'],
      ['edge.l7.autoSelect', 'false'],
    ] as const)
      await ctx.db.insert('appSettings', { key, value, updatedAt: Date.now() });
  });
  let dnsAccountId: string | undefined;
  if (viaDnsAccount) {
    const dns = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-dns',
      settings: { zoneId: DNS_ZONE_ID, zoneName: ZONE },
      credentials: { apiToken: 'SECRET_CF_TOKEN_0123' },
    });
    dnsAccountId = dns.id as string;
  }
  const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'edgeone',
    name: 'acct-edgeone',
    settings: {
      secretId: 'AKIDfcptestkey01',
      zoneId: EO_ZONE_ID,
      zoneName: ZONE,
      ...(dnsAccountId ? { dnsAccountId, dnsZoneId: DNS_ZONE_ID } : {}),
    } as never,
    credentials: { secretKey: 'SECRET-tencent-0123456789abcdef' } as never,
  });
  await t.mutation(internal.edgeProviderAccounts.setQualified, { id: accountId, qualified: true });
  const { relayId, listenerId } = await registerRelay(t, {
    originAddress: ORIGIN,
    listeners: [
      wsListener({
        listenerKey: 'w',
        tlsNames: ['a.example'],
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: [ORIGIN],
          acceptsHostHeader: 'any',
        },
        transportParams: { path: '/ws' },
        panelBinding: {
          inboundTag: 'VLESS_RELAY_W',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: INBOUND,
        },
      }),
    ],
  });
  await t.run((ctx) => ctx.db.patch(relayId, { qualificationUserId: QUALIFY_UUID }));
  return { t, accountId, dnsAccountId, relayId, listenerId };
}

function tencent(type: 'full' | 'partial'): FakeEdgeOne {
  const fake = fakeEdgeOne({
    zones: [
      {
        ZoneId: EO_ZONE_ID,
        ZoneName: ZONE,
        Type: type,
        Status: 'active',
        ActiveStatus: 'active',
        Area: 'overseas',
      },
    ],
  });
  __setEdgeOneApiFactory((cfg, diagnostic) => edgeOneSdkApi(cfg, diagnostic, fake.client));
  __setEdgeOneCaaLookup(async () => []);
  return fake;
}

async function drain(t: ReturnType<typeof convexTest>, rotationId: Id<'edgeRotations'>) {
  for (let i = 0; i < 400; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const r = await t.query(internal.edgeRotations.get, { id: rotationId });
    if (r && ['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase)) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
      return;
    }
  }
  throw new Error('drain: the rotation did not settle');
}

async function provisionAndDestroy(
  t: ReturnType<typeof convexTest>,
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
) {
  const { rotationId } = await t.mutation(internal.edgeRotations.start, {
    relayId,
    kind: 'provision',
    trigger: 'manual',
    listenerId,
    publishOnDone: true,
  });
  await drain(t, rotationId);
  const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
  expect(r.phase).toBe('done');
  expect(r.outcome).toBe('published');
  const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
  expect(edge).toMatchObject({ layer: 'l7', provider: 'edgeone', publication: 'published' });
  expect(edge.readiness).toMatchObject({ dns: 'ready', certificate: 'ready', front: 'ready' });
  return {
    edge,
    destroy: async () => {
      await t.run((ctx) => ctx.db.patch(edge._id, { publication: 'unpublished' }));
      await t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId: edge._id });
      for (let passes = 0; passes < 20; passes++) {
        await t.action(internal.edgeReconcile.run, {});
        const now = (await t.query(internal.edges.get, { id: edge._id }))!;
        if (now.status === 'destroyed') break;
      }
      return (await t.query(internal.edges.get, { id: edge._id }))!;
    },
  };
}

describe('edgeRotations + edgeReconcile: an EdgeOne front', () => {
  test("in a zone EdgeOne hosts: no DNS account, EdgeOne's own record switched on, all of it gone after", async () => {
    vi.useFakeTimers();
    const fake = tencent('full');
    const hosts = fakePanel();
    __setFrontChecker(async (args) => {
      expect(args.proto).toEqual({ protocol: 'vless', streamTransport: 'ws', security: 'tls' });
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    const { t, relayId, listenerId } = await seed(false);
    const { edge, destroy } = await provisionAndDestroy(t, relayId, listenerId);
    const hostname = edge.addresses.hostname!;
    expect(hosts[0]).toMatchObject({ address: hostname, sni: hostname, host: hostname });
    const intent = JSON.parse(edge.provisionIntent!);
    expect(intent).toMatchObject({ hostname, zoneId: EO_ZONE_ID, zoneName: ZONE });
    expect(intent).not.toHaveProperty('dnsAccountId');
    expect(fake.state.domains).toEqual([
      expect.objectContaining({ DomainName: hostname, DomainStatus: 'online' }),
    ]);
    expect(fake.state.records).toEqual([
      expect.objectContaining({ Name: hostname, Status: 'enable' }),
    ]);

    const gone = await destroy();
    expect(gone.status).toBe('destroyed');
    expect(fake.state.domains).toEqual([]);
    expect(fake.state.records).toEqual([]);
  });

  test('in a zone connected by CNAME: the CNAME goes through the DNS account the intent froze', async () => {
    vi.useFakeTimers();
    const fake = tencent('partial');
    const zone = fakeDnsZone({
      apiToken: 'SECRET_CF_TOKEN_0123',
      zoneId: DNS_ZONE_ID,
      zoneName: ZONE,
      accountId: 'dns',
    });
    __setEdgeOneDnsClientFactory((cfg) => {
      // The adapter got the DNS account's zone, never EdgeOne's zone id.
      expect(cfg.zoneId).toBe(DNS_ZONE_ID);
      return zone;
    });
    // The public resolver sends a name to EdgeOne once the zone holds its CNAME.
    fake.state.resolves = (name) => zone.rows.some((r) => r.name === name);
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, dnsAccountId, relayId, listenerId } = await seed(true);
    const { edge, destroy } = await provisionAndDestroy(t, relayId, listenerId);
    const hostname = edge.addresses.hostname!;
    expect(JSON.parse(edge.provisionIntent!)).toMatchObject({
      zoneId: EO_ZONE_ID,
      dnsAccountId,
      dnsZoneId: DNS_ZONE_ID,
    });
    expect(zone.rows).toEqual([
      expect.objectContaining({ name: hostname, content: fake.state.domains[0]!.Cname }),
    ]);
    // EdgeOne's own DNS was never used for such a zone.
    expect(fake.state.calls).not.toContain('DescribeDnsRecords');

    const gone = await destroy();
    expect(gone.status).toBe('destroyed');
    expect(zone.rows).toEqual([]);
    expect(fake.state.domains).toEqual([]);
  });
});
