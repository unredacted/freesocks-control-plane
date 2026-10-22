// @vitest-environment node
/// <reference types="vite/client" />
/**
 * A CloudFront front through the real machinery: the rotation machine plans,
 * builds, qualifies and publishes it, and the reconcile cron destroys it, with
 * the REAL CloudFront adapter driven against a fake AWS account
 * (lib/edges/testing/fakeCloudFront.ts) and its records written into an
 * in-memory zone. What the rotation and reconcile do for any L7 front (frozen
 * intent, the shared certificate's lock and ownership record, the
 * qualification gate, the destroy walk) is what Fastly's fronts get too; this
 * proves CloudFront's steps fit it, including the minutes-long deployment wait
 * and the disable, wait, delete teardown.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { __setFrontChecker } from './frontQualifyOps';
import { __setCloudFrontApiFactory } from './lib/edges/providers/cloudfront/sdk';
import {
  __setCloudFrontCaaLookup,
  __setCloudFrontDnsClientFactory,
} from './lib/edges/providers/cloudfront';
import {
  FakeCloudFrontAccount,
  fakeDnsZone,
  type FakeDnsZone,
} from './lib/edges/testing/fakeCloudFront';
import {
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  registerRelay,
  wsListener,
} from './lib/edges/testing/fixtures';
import { stepLockKey } from './edgeRotations';

const modules = import.meta.glob('./**/*.*s');

const ORIGIN = 'node-one.origin.example';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';
const ZONE = 'fronts.example.org';
const ZONE_ID = 'a'.repeat(32);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setCloudFrontApiFactory(null);
  __setCloudFrontDnsClientFactory(null);
  __setCloudFrontCaaLookup(null);
  __setFrontChecker(null);
});

/** A backend panel holding the node's one Host. */
function fakePanel() {
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
  mockFetch((c) => {
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
  });
  return hosts;
}

async function seed() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
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
    credentials: { apiToken: 'SECRET_CF_TOKEN_0123' },
  });
  const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudfront',
    name: 'acct-cloudfront',
    settings: {
      accessKeyId: 'AKIAEXAMPLEEXAMPLE00',
      dnsAccountId,
      zoneId: ZONE_ID,
      zoneName: ZONE,
    } as never,
    credentials: { secretAccessKey: 'SECRET-aws-0123456789abcdef' } as never,
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

/** The fake AWS account and DNS zone behind the adapter's seams. */
function fakeAws(): { aws: FakeCloudFrontAccount; zone: FakeDnsZone } {
  const aws = new FakeCloudFrontAccount();
  const zone = fakeDnsZone({
    apiToken: 'SECRET_CF_TOKEN_0123',
    zoneId: ZONE_ID,
    zoneName: ZONE,
    accountId: 'dns',
  });
  aws.dns = zone;
  // Each change stays InProgress for three reads: the deployment is a real wait.
  aws.deployAfterReads = 3;
  __setCloudFrontApiFactory((_cfg, diagnostic) => aws.api(diagnostic));
  __setCloudFrontDnsClientFactory(() => zone);
  __setCloudFrontCaaLookup(async () => []);
  return { aws, zone };
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

describe('edgeRotations + edgeReconcile: a CloudFront front', () => {
  test('provision → qualify → publish, then the reconcile walk disables, waits for and deletes it', async () => {
    vi.useFakeTimers();
    const { aws, zone } = fakeAws();
    const hosts = fakePanel();
    __setFrontChecker(async (args) => {
      expect(args.proto).toEqual({ protocol: 'vless', streamTransport: 'ws', security: 'tls' });
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    const { t, accountId, dnsAccountId, relayId, listenerId } = await seed();
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
    expect(edge).toMatchObject({ layer: 'l7', provider: 'cloudfront', publication: 'published' });
    const hostname = edge.addresses.hostname!;
    expect(hostname).toMatch(new RegExp(`^[a-z0-9]+\\.${ZONE.replace(/\./g, '\\.')}$`));
    expect(edge.readiness).toMatchObject({ dns: 'ready', certificate: 'ready', front: 'ready' });
    expect(hosts[0]).toMatchObject({ address: hostname, sni: hostname, host: hostname });
    // The intent froze the zone, the DNS account and the shared certificate.
    expect(JSON.parse(edge.provisionIntent!)).toMatchObject({
      hostname,
      zoneId: ZONE_ID,
      zoneName: ZONE,
      dnsAccountId,
      certificateScope: 'wildcard',
    });
    // At the provider: one wildcard (issued through its record), one policy, one
    // deployed distribution, the traffic name pointing at it.
    expect(aws.certificates).toEqual([
      expect.objectContaining({ domainName: `*.${ZONE}`, status: 'ISSUED' }),
    ]);
    expect(aws.policies.map((p) => p.config.Name)).toEqual(['fcp-ws-1']);
    const d = aws.distributions[0]!;
    expect(d).toMatchObject({ status: 'Deployed' });
    expect(d.config.Aliases?.Items).toEqual([hostname]);
    expect(zone.rows.find((x) => x.name === hostname)).toMatchObject({ content: d.domainName });
    // The deployment was a real wait (polled), not a single look.
    expect(aws.calls.filter((c) => c === 'getDistribution').length).toBeGreaterThanOrEqual(3);
    // The certificate this edge requested is remembered as the account's (its removal needs it).
    const account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account.orderedSharedResources).toContain(
      `tls_subscription:${aws.certificates[0]!.arn}`,
    );
    // No external lock is left held.
    const locks = await t.run((ctx) => ctx.db.query('externalLocks').collect());
    expect(locks.filter((l) => l.expiresAt > Date.now() && l.holderEdgeId)).toEqual([]);

    // Teardown through the reconcile cron.
    await t.run((ctx) => ctx.db.patch(edge._id, { publication: 'unpublished' }));
    await t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId: edge._id });
    aws.calls.length = 0;
    let passes = 0;
    for (; passes < 20; passes++) {
      await t.action(internal.edgeReconcile.run, {});
      const now = (await t.query(internal.edges.get, { id: edge._id }))!;
      if (now.status === 'destroyed') break;
    }
    const gone = (await t.query(internal.edges.get, { id: edge._id }))!;
    expect(gone.status).toBe('destroyed');
    expect(passes).toBeGreaterThan(0);
    expect(aws.distributions).toEqual([]);
    expect(
      aws.calls.filter((c) => c === 'updateDistribution' || c === 'deleteDistribution'),
    ).toEqual(['updateDistribution', 'deleteDistribution']);
    // What other fronts share stays: the certificate, its record, the policy.
    expect(aws.certificates).toHaveLength(1);
    expect(aws.policies).toHaveLength(1);
    expect(zone.rows.some((x) => x.name === hostname)).toBe(false);
    expect(zone.rows.some((x) => x.name.startsWith('_'))).toBe(true);
    expect(aws.calls).not.toContain('deleteCertificate');
  });
});

describe('edgeRotations: the locks a CloudFront front takes', () => {
  test('its certificate steps hold the zone certificate lock, its distribution step the policy lock', () => {
    const intent = {
      hostname: `x.${ZONE}`,
      zoneId: 'z1',
      certificateScope: 'wildcard',
      originTransport: {},
    };
    const edge = {
      provisionIntent: JSON.stringify(intent),
      accountId: 'a1',
      provider: 'cloudfront',
    } as never;
    expect(stepLockKey(edge, 'create_tls_subscription')).toBe('fastly-certificate:a1:z1');
    expect(stepLockKey(edge, 'create_dns_acme')).toBe('fastly-certificate:a1:z1');
    expect(stepLockKey(edge, 'create_service')).toBe('cloudfront-policy:a1');
    expect(stepLockKey(edge, 'await_tls')).toBeNull();
    expect(stepLockKey(edge, 'create_dns_record')).toBeNull();
    // Another provider's service step takes no policy lock.
    expect(
      stepLockKey(
        { provisionIntent: JSON.stringify(intent), accountId: 'a1', provider: 'fastly' } as never,
        'create_service',
      ),
    ).toBeNull();
  });
});
