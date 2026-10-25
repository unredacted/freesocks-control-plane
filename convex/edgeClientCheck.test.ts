/// <reference types="vite/client" />
/**
 * FCP's own client check (docs/edges.md § "FCP's own client check"), the Convex
 * half: the real test link of an address (fake panel), turned into each engine's
 * outbound, sent signed to a fake client-check service that answers per engine
 * and destination; the verdict against a control address; what is recorded
 * (codes only) and raised (attention), and every "could not check" path.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { fakePanel, type FakePanelHost } from './lib/edges/testing/fakePanel';
import {
  adoptL4Edge,
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  FIXTURE_ORIGIN,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';
import { DEFAULT_CLIENT_CHECK_URL } from './lib/edges/clientCheck/client';
import {
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
} from './lib/edges/clientCheck/protocol';
import { ReplayGuard, verifyRequest } from './lib/edges/clientCheck/signing';
import type { ClientCheckEngine, ClientCheckSessionCode } from '../src/shared/contracts/edgeCodes';
import { mapEdgeAdmin } from './edges';
import { verificationListenerOf } from './lib/edges/verificationContext';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const SECRET = 'client-check-test-secret';
const ORIGIN = FIXTURE_ORIGIN;
const SPARE = '198.51.100.7';
const IN_USE = '198.51.100.8';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';

const directHost = (): FakePanelHost => ({
  uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-000000000001',
  remark: 'node-one-reality',
  address: ORIGIN,
  port: 443,
  sni: 'a.example',
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: FIXTURE_INBOUND },
});

type Answer = { code: ClientCheckSessionCode; egressIp?: string | null } | { status: number };
/** What the fake service answers, per engine and the address the outbound dials. */
type Script = (engine: ClientCheckEngine, address: string) => Answer;

/**
 * The fake client-check service in front of the fake panel: checks FCP's
 * signature like the real one, then answers by `script`. Returns the calls it saw.
 */
function fakeService(script: Script) {
  const calls: Array<{ engine: ClientCheckEngine; address: string }> = [];
  const guard = new ReplayGuard();
  const panelFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!url.startsWith(DEFAULT_CLIENT_CHECK_URL)) return panelFetch(input, init);
    const path = new URL(url).pathname;
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body = typeof init.body === 'string' ? init.body : '';
    const verified = await verifyRequest(
      SECRET,
      {
        method: init.method ?? 'GET',
        path,
        time: headers[CLIENT_CHECK_TIME_HEADER] ?? null,
        signature: headers[CLIENT_CHECK_SIGNATURE_HEADER] ?? null,
        body,
      },
      Date.now(),
      guard,
    );
    if (verified !== 'ok') return new Response('{}', { status: 401 });
    if (path === '/v1/health')
      return Response.json({
        ok: true,
        engines: [
          { engine: 'sing-box', version: '1.14.3' },
          { engine: 'xray', version: '26.10.21' },
        ],
        egressHost: 'echo.example',
      });
    const req = JSON.parse(body) as { engine: ClientCheckEngine; outbound: Record<string, any> };
    const address: string =
      req.engine === 'sing-box'
        ? req.outbound.server
        : (req.outbound.settings.vnext ?? req.outbound.settings.servers)[0].address;
    calls.push({ engine: req.engine, address });
    const a = script(req.engine, address);
    if ('status' in a) return new Response('{}', { status: a.status });
    return Response.json({
      ok: a.code === 'ok',
      engine: req.engine,
      engineVersion: req.engine === 'sing-box' ? '1.14.3' : '26.10.21',
      egressIp: a.code === 'ok' ? (a.egressIp ?? ORIGIN) : null,
      ms: 5,
      code: a.code,
    });
  });
  return calls;
}

async function seed() {
  fakePanel({
    hosts: [directHost()],
    body: (u) =>
      u
        ? [
            `vless://${u.vlessUuid}@${ORIGIN}:443?${REALITY_QS}#node-one-reality`,
            `vless://${u.vlessUuid}@203.0.113.20:443?${REALITY_QS}#node-two-reality`,
          ].join('\n')
        : null,
  });
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t);
  await t.run((ctx) =>
    ctx.db.insert('modePlacements', {
      modeSlug: 'freedom-ws',
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: ['sq-node-one'] }),
      updatedAt: Date.now(),
    }),
  );
  const spare = (await adoptL4Edge(t, fx.relayId, fx.listenerId, {
    ipv4: SPARE,
    verified: false,
  })) as { edgeId: Id<'edges'> };
  return { t, fx, spare: spare.edgeId };
}

/** A second address of the same transport, in use and confirmed: the control. */
async function addInUse(
  t: Awaited<ReturnType<typeof seed>>['t'],
  fx: { relayId: Id<'relays'>; listenerId: Id<'relayListeners'> },
) {
  const r = (await adoptL4Edge(t, fx.relayId, fx.listenerId, {
    ipv4: IN_USE,
    publish: true,
  })) as { edgeId: Id<'edges'> };
  return r.edgeId;
}

describe("FCP's client check", () => {
  test('not set up: nothing is checked or recorded', async () => {
    const { t, spare } = await seed();
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toEqual({
      checked: false,
      code: 'not_configured',
    });
    expect((await t.run((ctx) => ctx.db.get(spare)))!.clientCheck).toBeUndefined();
    expect(await t.query(internal.edgeClientCheck.status, {})).toEqual({
      configured: false,
      health: null,
    });
  });

  test('both engines through the address, out of the node: passed, no control needed, codes recorded', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, spare } = await seed();
    const calls = fakeService(() => ({ code: 'ok' }));
    const r = await t.action(internal.edgeClientCheck.check, { edgeId: spare });
    expect(r).toMatchObject({ checked: true, verdict: 'passed', ok: true, control: false });
    expect(calls).toEqual([
      { engine: 'sing-box', address: SPARE },
      { engine: 'xray', address: SPARE },
    ]);
    const edge = (await t.run((ctx) => ctx.db.get(spare)))!;
    expect(edge.clientCheck).toMatchObject({ verdict: 'passed', ok: true, by: 'admin' });
    // Codes and versions only: no address, no egress IP anywhere in the record.
    expect(JSON.stringify(edge.clientCheck)).not.toContain(SPARE);
    expect(JSON.stringify(edge.clientCheck)).not.toContain(ORIGIN);
    const view = await t.run(async (ctx) =>
      mapEdgeAdmin(
        edge,
        await verificationListenerOf(ctx.db, (await ctx.db.get(edge.listenerId))!),
      ),
    );
    expect(view.clientCheck).toMatchObject({ verdict: 'passed', current: true });
    // Advice only: a passing check is not a tick, the spare is still untested.
    expect(edge.verification).toBeUndefined();
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.client_check'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({
      verdict: 'passed',
      engines: 'sing-box:ok xray:ok',
    });
  });

  test('sing-box refused here AND through the address in use: as good as the others', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, fx, spare } = await seed();
    await addInUse(t, fx);
    const calls = fakeService((engine) =>
      engine === 'sing-box' ? { code: 'reality_refused' } : { code: 'ok' },
    );
    const r = await t.action(internal.edgeClientCheck.check, { edgeId: spare });
    expect(r).toMatchObject({ checked: true, verdict: 'passed_with_refusals', control: true });
    expect(calls.map((c) => c.address)).toEqual([SPARE, SPARE, IN_USE, IN_USE]);
  });

  test('refused here while the address in use admits it: the address failed', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, fx, spare } = await seed();
    await addInUse(t, fx);
    fakeService((engine, address) =>
      engine === 'sing-box' && address === SPARE ? { code: 'timeout' } : { code: 'ok' },
    );
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      checked: true,
      verdict: 'address_failed',
      ok: false,
    });
  });

  test('a session that comes out somewhere else: egress_mismatch', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, spare } = await seed();
    fakeService(() => ({ code: 'ok', egressIp: '203.0.113.99' }));
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      verdict: 'egress_mismatch',
      ok: false,
    });
  });

  test('an address in use whose check found a client refused raises client_refused', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, fx } = await seed();
    const inUse = await addInUse(t, fx);
    fakeService((engine) => (engine === 'sing-box' ? { code: 'reality_refused' } : { code: 'ok' }));
    await t.action(internal.edgeClientCheck.check, { edgeId: inUse });
    const attention = await t.query(internal.edgeOperator.attention, {});
    const item = attention.items.find((i) => i.kind === 'client_refused');
    expect(item).toMatchObject({
      severity: 'warning',
      facts: { count: 1, engines: [{ engine: 'sing-box', code: 'reality_refused' }] },
    });
    // A check from before the transport changed says nothing about it any more.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(fx.listenerId))!;
      await ctx.db.patch(l._id, { revision: l.revision + 1 });
    });
    const after = await t.query(internal.edgeOperator.attention, {});
    expect(after.items.some((i) => i.kind === 'client_refused')).toBe(false);
  });

  test('egress through another address the node is known by passes', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, fx, spare } = await seed();
    await t.run((ctx) => ctx.db.patch(fx.relayId, { nodeAddresses: ['2001:db8::7'] }));
    fakeService(() => ({ code: 'ok', egressIp: '2001:db8:0::7' }));
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      verdict: 'passed',
    });
  });

  test('rollback: every verdict and every check key, a page at a time', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, fx, spare } = await seed();
    fakeService(() => ({ code: 'ok' }));
    await t.action(internal.edgeClientCheck.check, { edgeId: spare });
    await t.run(async (ctx) => {
      for (let i = 0; i < 205; i++)
        await ctx.db.insert('edgeTestCredentials', {
          relayId: fx.relayId,
          backendServerId: fx.serverId,
          backend: 'remnawave',
          purpose: 'client_check',
          username: `fcp-test-check-${i}`,
          removal: 'done',
          attempts: 0,
          expiresAt: Date.now(),
          updatedAt: Date.now(),
        });
    });
    vi.useFakeTimers();
    await t.mutation(internal.edgeClientCheck.clearForRollback, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    vi.useRealTimers();
    expect((await t.run((ctx) => ctx.db.get(spare)))!.clientCheck).toBeUndefined();
    const left = await t.run((ctx) => ctx.db.query('edgeTestCredentials').collect());
    expect(left.filter((r) => r.purpose === 'client_check')).toEqual([]);
  });

  test('the service refusing or busy is "could not check", never a verdict', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t, spare } = await seed();
    fakeService(() => ({ status: 401 }));
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toEqual({
      checked: false,
      code: 'unauthorized',
    });
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', 'another-secret');
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toEqual({
      checked: false,
      code: 'unauthorized',
    });
    expect((await t.run((ctx) => ctx.db.get(spare)))!.clientCheck).toBeUndefined();
  });

  test('health: answering, then not answering raises client_check_unavailable', async () => {
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
    const { t } = await seed();
    fakeService(() => ({ code: 'ok' }));
    expect(await t.action(internal.edgeClientCheck.refreshHealth, {})).toMatchObject({
      ok: true,
      engines: [
        { engine: 'sing-box', version: '1.14.3' },
        { engine: 'xray', version: '26.10.21' },
      ],
    });
    let attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.some((i) => i.kind === 'client_check_unavailable')).toBe(false);
    vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', 'another-secret');
    expect(await t.action(internal.edgeClientCheck.refreshHealth, {})).toMatchObject({
      ok: false,
      code: 'unauthorized',
    });
    attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'client_check_unavailable')).toMatchObject({
      severity: 'warning',
      code: 'unauthorized',
    });
  });
});
