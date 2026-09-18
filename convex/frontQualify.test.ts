/// <reference types="vite/client" />
/**
 * The isolate half of the front qualification: what the session is given, and
 * what is written back.
 *
 * The rules that matter are (a) a result is only a qualification for the exact
 * configuration it ran against, so a listener/intent write that lands while
 * the session is in flight must not be recorded as a pass, and (b) a relay with
 * no usable qualification credential fails loudly rather than being skipped.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { qualificationVerdict } from './lib/edges/intent';
import { seedEdgeFixture, wsListener } from './lib/edges/testing/fixtures';

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
  // A VLESS-over-WebSocket listener (the only kind with an authenticated
  // proof), registered the way the node role does it, so its revision is 1.
  const fx = await seedEdgeFixture(t, {
    listeners: [
      wsListener({
        tlsNames: ['node.example'],
        transportParams: { path: '/relay-ws', upgradeToken: 'websocket' },
        originTransport: intent.originTransport,
      }),
    ],
  });
  if (opts.qualificationUserId)
    await t.run((ctx) =>
      ctx.db.patch(fx.relayId, { qualificationUserId: opts.qualificationUserId }),
    );
  // An observe-only import of the front: a hostname edge on the ws listener.
  const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
    relayId: fx.relayId,
    listenerId: fx.listenerId,
    hostname: HOSTNAME,
  });
  if (opts.withIntent !== false)
    await t.run((ctx) => ctx.db.patch(edgeId, { provisionIntent: JSON.stringify(intent) }));
  return { edgeId: edgeId as Id<'edges'>, listenerId: fx.listenerId, relayId: fx.relayId };
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
  test('hands the session the hostname, what the listener speaks, its transport parameters and the credential', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c).not.toBeNull();
    expect(c!.hostname).toBe(HOSTNAME);
    expect(c!.proto).toEqual({ protocol: 'vless', streamTransport: 'ws', security: 'tls' });
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
    const listener = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(c!.binding).toMatchObject({
      hostname: HOSTNAME,
      listenerId,
      listenerRevision: listener.revision,
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
    });
    expect(c!.binding.transportParamsHash).toMatch(/^[0-9a-f]{16}$/);
    expect(c!.binding.intentHash).toMatch(/^[0-9a-f]{16}$/);
  });

  test('a listener without an authenticated proof is reported as not carried', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    await t.run((ctx) => ctx.db.patch(listenerId, { protocol: 'trojan' }));
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.carried).toBe(false);
    expect(c!.proto.protocol).toBe('trojan');
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
    expect(edge!.frontQualification!.binding).toEqual(c.binding);
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

  test('a listener write during the session is not a qualification (revision race)', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    // The node role redeploys the inbound on a different path mid-session.
    const before = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        transportParams: { path: '/moved', upgradeToken: 'websocket' },
        revision: before.revision + 1,
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
    expect(edge!.frontQualification!.binding.listenerRevision).toBe(before.revision + 1);
    expect(edge!.frontQualification!.binding.listenerId).toBe(listenerId);
    expect(edge!.readiness!.front).toBe('failed');
  });

  test('a revision bump alone (same parameters) also races: the proof is bound to the revision', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    const c = (await t.query(internal.frontQualify.context, { edgeId }))!;
    const before = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    await t.run((ctx) => ctx.db.patch(listenerId, { revision: before.revision + 1 }));
    expect(
      await t.mutation(internal.frontQualify.record, {
        edgeId,
        result: passing(Date.now()),
        binding: c.binding,
      }),
    ).toEqual({ ok: false, code: 'config_changed' });
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

  test('a listener with no authenticated proof is refused before any socket is opened', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    // Raw TCP is not HTTP-carried (vless/raw/tls).
    await t.run((ctx) => ctx.db.patch(listenerId, { streamTransport: 'raw' }));
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: false,
      code: 'unsupported_protocol',
    });
    // Trojan over ws is HTTP-carried but has no VLESS proof.
    await t.run((ctx) => ctx.db.patch(listenerId, { streamTransport: 'ws', protocol: 'trojan' }));
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: false,
      code: 'unsupported_protocol',
    });
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
