/// <reference types="vite/client" />
/**
 * The isolate half of the front qualification: what the session is given, and
 * what is written back.
 *
 * The rules that matter are (a) a result is only a qualification for the exact
 * configuration it ran against, so a slot/profile/intent write that lands while
 * the session is in flight must not be recorded as a pass, and (b) a relay with
 * no usable qualification credential fails loudly rather than being skipped.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { qualificationVerdict } from './lib/edges/intent';

const modules = import.meta.glob('./**/*.*s');

const UUID = '01234567-89ab-cdef-0123-456789abcdef';
const HOSTNAME = 'a1b2c3d4.edge.example';

const intent = {
  hostname: HOSTNAME,
  zoneId: 'zone-1',
  zoneName: 'edge.example',
  originTransport: {
    scheme: 'https' as const,
    certPublic: true,
    certNames: ['node.example'],
    acceptsHostHeader: 'any' as const,
  },
  originPort: 443,
  templateHash: 'h',
  templateParams: {},
};

async function seed(
  t: ReturnType<typeof convexTest>,
  opts: { qualificationUserId?: string; withIntent?: boolean } = {},
) {
  return await t.run(async (ctx) => {
    const now = Date.now();
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel',
      slug: 'panel',
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: now,
    });
    const relayId = await ctx.db.insert('relays', {
      slug: 'relay-a',
      backendServerId: serverId,
      nodeHostname: 'node-a',
      originAddress: 'node.example',
      modeSlugs: [],
      enabled: true,
      autoRotate: false,
      hostManaged: true,
      providerAffinity: 'rotate',
      desiredPublished: 1,
      standbyPerRelay: 0,
      cooldownMs: 1,
      maxRotationsPerDay: 3,
      drainMs: 1,
      publicationEpoch: 0,
      publishedEdgeIds: [],
      standbyEdgeIds: [],
      rotationsToday: 0,
      ...(opts.qualificationUserId ? { qualificationUserId: opts.qualificationUserId } : {}),
      updatedAt: now,
    });
    const profileId = await ctx.db.insert('protocolProfiles', {
      slug: 'pf-ws',
      name: 'ws profile',
      protocol: 'ws' as const,
      serverNames: [{ sni: 'node.example', status: 'active' as const }],
      enabled: true,
      revision: 3,
      updatedAt: now,
    });
    const slotId = await ctx.db.insert('relaySlots', {
      relayId,
      slotKey: 'a1',
      profileId,
      inboundTag: 'T',
      configProfileUuid: 'cp',
      configProfileInboundUuid: 'in',
      originPort: 443,
      templateHostRemark: 'node-a-relay-a1',
      deployed: true,
      retired: false,
      originTransport: intent.originTransport,
      transportParams: { path: '/relay-ws', upgradeToken: 'websocket' },
      revision: 5,
      updatedAt: now,
    });
    const edgeId = await ctx.db.insert('edges', {
      relayId,
      slotId,
      provider: 'cloudflare',
      managed: true,
      name: 'fcp-relay-a1-000000',
      steps: [],
      resources: [],
      listeners: [],
      addresses: { hostname: HOSTNAME },
      layer: 'l7',
      ...(opts.withIntent === false ? {} : { provisionIntent: JSON.stringify(intent) }),
      publication: 'unpublished',
      status: 'active',
      statusChangedAt: now,
      health: 'unknown',
      destroyAttempts: 0,
      updatedAt: now,
    });
    return { edgeId, slotId, profileId, relayId };
  });
}

const passing = (checkedAt: number) => ({
  ok: true,
  steps: [
    { step: 'tls', ok: true, ms: 12 },
    { step: 'transport', ok: true, ms: 8 },
    { step: 'vless', ok: true, ms: 40 },
    { step: 'close', ok: true, ms: 3 },
  ],
  checkedAt,
});

describe('frontQualify.context', () => {
  test('hands the session the hostname, transport parameters and credential', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, slotId, profileId } = await seed(t, { qualificationUserId: UUID });
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c).not.toBeNull();
    expect(c!.hostname).toBe(HOSTNAME);
    expect(c!.protocol).toBe('ws');
    expect(c!.carried).toBe(true);
    expect(c!.params).toEqual({
      path: '/relay-ws',
      host: null,
      serviceName: null,
      upgradeToken: 'websocket',
    });
    expect(c!.credential).toEqual({ uuid: UUID });
    expect(c!.stepTimeoutMs).toBe(10_000);
    expect(c!.ttlMinutes).toBe(60);
    expect(c!.binding).toMatchObject({
      hostname: HOSTNAME,
      slotId,
      slotRevision: 5,
      profileId,
      profileRevision: 3,
      protocol: 'ws',
    });
  });

  test('an id that is not a usable VLESS uuid is no credential', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: '7:42' });
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.credential).toBeNull();
    expect(c!.credentialConfigured).toBe(true);
  });

  test('an edge without a frozen intent cannot be qualified', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: UUID, withIntent: false });
    expect(await t.query(internal.frontQualify.context, { edgeId })).toBeNull();
  });
});

describe('frontQualify.record', () => {
  test('a pass is stored with its binding, an expiry and readiness.front', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    const checkedAt = Date.now();
    const out = await t.mutation(internal.frontQualify.record, {
      edgeId,
      result: passing(checkedAt),
      binding: c.binding,
    });
    expect(out).toEqual({ ok: true, code: null });
    const edge = await t.run((ctx) => ctx.db.get(edgeId));
    expect(edge!.frontQualification!.ok).toBe(true);
    expect(edge!.frontQualification!.expiresAt).toBe(checkedAt + 60 * 60_000);
    expect(edge!.readiness!.front).toBe('ready');
    expect(edge!.readiness!.dns).toBe('unknown');
    // Still a qualification for what would be published right now.
    expect(qualificationVerdict(edge!.frontQualification!, c.binding, checkedAt + 1)).toBe('ok');
  });

  test('a failure is stored with its code and readiness.front goes to failed', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    await t.mutation(internal.frontQualify.record, {
      edgeId,
      result: { ok: false, code: 'front_error', detail: '403', steps: [], checkedAt: Date.now() },
      binding: c.binding,
    });
    const edge = await t.run((ctx) => ctx.db.get(edgeId));
    expect(edge!.frontQualification).toMatchObject({ ok: false, code: 'front_error' });
    expect(edge!.readiness!.front).toBe('failed');
  });

  test('a slot write during the session is not a qualification', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, slotId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    // The node role redeploys the inbound on a different path mid-session.
    await t.run((ctx) =>
      ctx.db.patch(slotId, {
        transportParams: { path: '/moved', upgradeToken: 'websocket' },
        revision: 6,
      }),
    );
    const out = await t.mutation(internal.frontQualify.record, {
      edgeId,
      result: passing(Date.now()),
      binding: c.binding,
    });
    expect(out).toEqual({ ok: false, code: 'config_changed' });
    const edge = await t.run((ctx) => ctx.db.get(edgeId));
    expect(edge!.frontQualification!.ok).toBe(false);
    // The stored binding describes the CURRENT configuration, not the proved one.
    expect(edge!.frontQualification!.binding.slotRevision).toBe(6);
    expect(edge!.readiness!.front).toBe('failed');
  });

  test('recording against a vanished edge is a no-op, not a crash', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    await t.run((ctx) => ctx.db.delete(edgeId));
    expect(
      await t.mutation(internal.frontQualify.record, {
        edgeId,
        result: passing(Date.now()),
        binding: c.binding,
      }),
    ).toEqual({ ok: false, code: 'not_qualifiable' });
  });
});

describe('frontQualifyOps.run', () => {
  test('a relay with no qualification account records the refusal', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t);
    const out = await t.action(internal.frontQualifyOps.run, { edgeId });
    expect(out).toEqual({ ok: false, code: 'no_qualification_credential' });
    const edge = await t.run((ctx) => ctx.db.get(edgeId));
    expect(edge!.frontQualification).toMatchObject({
      ok: false,
      code: 'no_qualification_credential',
    });
    expect(edge!.readiness!.front).toBe('failed');
  });

  test('an L4 profile is refused before any socket is opened', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, profileId } = await seed(t, { qualificationUserId: UUID });
    await t.run((ctx) => ctx.db.patch(profileId as Id<'protocolProfiles'>, { protocol: 'tls' }));
    const out = await t.action(internal.frontQualifyOps.run, { edgeId });
    expect(out).toEqual({ ok: false, code: 'unsupported_protocol' });
  });

  test('a missing edge never reaches the network', async () => {
    const t = convexTest(schema, modules);
    const { edgeId } = await seed(t, { qualificationUserId: UUID });
    await t.run((ctx) => ctx.db.delete(edgeId));
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: false,
      code: 'not_qualifiable',
    });
  });
});
