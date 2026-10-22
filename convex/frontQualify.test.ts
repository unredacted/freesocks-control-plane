/// <reference types="vite/client" />
/**
 * The isolate half of the front qualification: what the session is given, and
 * what is written back.
 *
 * The rules that matter are (a) a result is only a qualification for the exact
 * configuration it ran against, so a listener/intent write that lands while
 * the session is in flight must not be recorded as a pass, and (b) an origin with
 * no usable qualification credential fails loudly rather than being skipped.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { qualificationVerdict } from './lib/edges/intent';
import { seedEdgeFixture, wsListener } from './lib/edges/testing/fixtures';
import { fakePanel, type FakePanelUser } from './lib/edges/testing/fakePanel';
import { __setFrontChecker } from './frontQualifyOps';
import type { FrontCheckResult } from './lib/edges/frontCheck';
import { QUALIFICATION_TRAFFIC_LIMIT_BYTES } from './relayQualification';

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
  test('an XHTTP listener hands the session its stored mode (a stream-only transport must be refused, not probed)', async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId } = await seed(t, { qualificationUserId: UUID });
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        streamTransport: 'xhttp',
        transportParams: { path: '/xh', mode: 'stream-one' },
      }),
    );
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.params).toMatchObject({ path: '/xh', mode: 'stream-one' });
  });

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
    expect(c!.credential).toEqual({ kind: 'vless', uuid: UUID });
    expect(c!.provider).toBeNull(); // an imported fixture edge names no provider
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
    await t.run((ctx) => ctx.db.patch(listenerId, { streamTransport: 'raw' }));
    const c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.carried).toBe(false);
    expect(c!.proto.streamTransport).toBe('raw');
  });

  test("Trojan over WebSocket is proved with the same account's Trojan password", async () => {
    const t = convexTest(schema, modules);
    const { edgeId, listenerId, relayId } = await seed(t, { qualificationUserId: UUID });
    await t.run((ctx) => ctx.db.patch(listenerId, { protocol: 'trojan' }));
    // No password stored (a credential minted before Trojan proofs): no credential, not a guess.
    let c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.carried).toBe(true);
    expect(c!.credential).toBeNull();
    await t.run((ctx) => ctx.db.patch(relayId, { qualificationTrojanPassword: 'tp' }));
    c = await t.query(internal.frontQualify.context, { edgeId });
    expect(c!.credential).toEqual({ kind: 'trojan', password: 'tp' });
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
    // The node role redeploys the transport on a different path mid-session.
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

/** The origin's qualification account as it lives on the fake backend (its 2.x uuid stored on the origin). */
async function qualificationAccount(
  t: ReturnType<typeof convexTest>,
  panel: ReturnType<typeof fakePanel>,
  relayId: Id<'relays'>,
): Promise<FakePanelUser> {
  const user: FakePanelUser = {
    uuid: '00000000-0000-4000-8000-0000000000a1',
    shortUuid: 'short-q',
    username: 'fcp-qualify-node-one-abcd1234',
    vlessUuid: '00000000-0000-4000-8000-0000000000b1',
    trojanPassword: 'trojan-pw',
    subscriptionUrl: 'https://panel.example/api/sub/short-q',
    status: 'ACTIVE',
    usedTrafficBytes: 0,
    trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
  };
  panel.users.set(user.username, user);
  await t.run((ctx) => ctx.db.patch(relayId, { qualificationBackendUserId: user.uuid }));
  return user;
}

afterEach(() => {
  __setFrontChecker(null);
  vi.unstubAllGlobals();
});

describe('frontQualifyOps.run', () => {
  test('an origin with no qualification account records the refusal', async () => {
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
    // Shadowsocks is not HTTP-carried either.
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        protocol: 'shadowsocks',
        streamTransport: 'raw',
        security: 'none',
      }),
    );
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: false,
      code: 'unsupported_protocol',
    });
  });

  test('a used-up qualification account is reset and re-enabled before the session opens', async () => {
    const panel = fakePanel();
    const t = convexTest(schema, modules);
    const { edgeId, relayId } = await seed(t, { qualificationUserId: UUID });
    const user = await qualificationAccount(t, panel, relayId);
    // A test profile left connected in a client: the backend limited the account.
    user.status = 'LIMITED';
    user.usedTrafficBytes = 706906753;
    let statusAtSession: string | null = null;
    __setFrontChecker(async () => {
      statusAtSession = user.status;
      return passing(Date.now()) as FrontCheckResult;
    });
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: true,
      code: null,
    });
    expect(statusAtSession).toBe('ACTIVE');
    expect(user.usedTrafficBytes).toBe(0);
  });

  test('an account the backend will not reset is named, and no session is sent on it', async () => {
    const panel = fakePanel();
    const t = convexTest(schema, modules);
    const { edgeId, relayId } = await seed(t, { qualificationUserId: UUID });
    const user = await qualificationAccount(t, panel, relayId);
    user.status = 'LIMITED';
    user.usedTrafficBytes = 706906753;
    panel.failResetWith = 500;
    const checker = vi.fn(async () => passing(Date.now()) as FrontCheckResult);
    __setFrontChecker(checker);
    expect(await t.action(internal.frontQualifyOps.run, { edgeId })).toEqual({
      ok: false,
      code: 'test_account_used_up',
    });
    expect(checker).not.toHaveBeenCalled();
    const edge = await t.run((ctx) => ctx.db.get(edgeId));
    expect(edge!.frontQualification).toMatchObject({ ok: false, code: 'test_account_used_up' });
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
