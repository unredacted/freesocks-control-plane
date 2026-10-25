/// <reference types="vite/client" />
/**
 * Replacing a blocked address without a spare (docs/edges.md § "Replacing a
 * blocked address without a spare"): with FCP's own client check on and
 * answering, a replace with no tested spare provisions a new load balancer in a
 * location the owner ticked an address in, proves it in `verifying` against the
 * address in use, and publishes it; a failed check publishes nothing and holds
 * the next try; "could not check" leaves an untested spare that the next
 * replace takes instead of buying again; a replacement blocked again soon holds
 * automatic replacement of its transport; who receives the replacement is one
 * decision (`inherit`).
 *
 * The provider and the backend's Host table are faked (UpCloud + a panel), the
 * client-check service is a fetch stub that checks FCP's signature, and the
 * check's test link comes from a seam (no panel serves credential bodies here).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  realityListener,
  registerRelay,
  verifyL4Edge,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow } from './lib/edges/testing/reads';
import { upsertSettingRow } from './appSettings';
import { __setClientCheckLinks } from './edgeClientCheck';
import { CLIENT_CHECK_FAIL_COOLDOWN_MS, reblockedSoon } from './edgeRotations';
import { checkPublishable } from './relays';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { DEFAULT_CLIENT_CHECK_URL } from './lib/edges/clientCheck/client';
import {
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
} from './lib/edges/clientCheck/protocol';
import { ReplayGuard, verifyRequest } from './lib/edges/clientCheck/signing';
import { REPLACEMENT_POLICY, replacementPlacement } from './lib/edges/replacementHolders';
import type { ClientCheckEngine, ClientCheckSessionCode } from '../src/shared/contracts/edgeCodes';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  __setClientCheckLinks(null);
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

const SECRET = 'replace-test-secret';
const ORIGIN = '203.0.113.10';
const OLD_EDGE = '198.51.100.1';
const NEW_EDGE = '198.51.100.50';
const SECOND_NEW = '198.51.100.51';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const UUID = '00000000-0000-4000-8000-000000000001';
const PBK = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0';

type Answer = { code: ClientCheckSessionCode; egressIp?: string } | { status: number };

/**
 * UpCloud + a panel Host table (as edgeRotations.test.ts) and, in front, the
 * client-check service answering `script(engine, address)` for each signed call.
 */
function world(script: (engine: ClientCheckEngine, address: string) => Answer) {
  const panelHosts = [
    {
      uuid: HOST_UUID,
      remark: 'node-one-relay-u',
      address: OLD_EDGE,
      port: 443,
      sni: 'a.example',
      inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: INBOUND },
    },
  ];
  const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
  const mint = [NEW_EDGE, SECOND_NEW];
  let minted = 0;
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') {
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
      if (c.path === '/api/hosts' && c.method === 'PATCH') {
        const body = c.body as { uuid: string; address: string; port: number; sni?: string };
        const h = panelHosts.find((x) => x.uuid === body.uuid);
        if (h) {
          h.address = body.address;
          h.port = body.port;
          if (body.sni !== undefined) h.sni = body.sni;
        }
        return jsonRes({ response: h ?? null });
      }
      return jsonRes({ message: 'not found' }, 404);
    }
    if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
      const uuid = `lb-${lbs.size + 1}`;
      lbs.set(uuid, {
        uuid,
        name: (c.body as { name: string }).name,
        operational_state: 'running',
      });
      return jsonRes(lbs.get(uuid));
    }
    if (c.path === '/1.3/ip_address' && c.method === 'POST')
      return jsonRes({ ip_address: { address: mint[minted++] ?? NEW_EDGE, floating: 'yes' } });
    if (/^\/1\.3\/load-balancer\/[^/]+\/ip-addresses$/.test(c.path) && c.method === 'POST')
      return jsonRes({});
    const get = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (get && c.method === 'GET') {
      const lb = lbs.get(get[1]!);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    throw new Error(`unexpected ${c.method} ${c.url}`);
  });
  const checks: Array<{ engine: ClientCheckEngine; address: string }> = [];
  const guard = new ReplayGuard();
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!url.startsWith(DEFAULT_CLIENT_CHECK_URL)) return inner(input, init);
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body = typeof init.body === 'string' ? init.body : '';
    const ok = await verifyRequest(
      SECRET,
      {
        method: init.method ?? 'GET',
        path: new URL(url).pathname,
        time: headers[CLIENT_CHECK_TIME_HEADER] ?? null,
        signature: headers[CLIENT_CHECK_SIGNATURE_HEADER] ?? null,
        body,
      },
      Date.now(),
      guard,
    );
    if (ok !== 'ok') return new Response('{}', { status: 401 });
    const req = JSON.parse(body) as { engine: ClientCheckEngine; outbound: Record<string, any> };
    const address: string =
      req.engine === 'sing-box'
        ? req.outbound.server
        : (req.outbound.settings.vnext ?? req.outbound.settings.servers)[0].address;
    checks.push({ engine: req.engine, address });
    const a = script(req.engine, address);
    if ('status' in a) return new Response('{}', { status: a.status });
    return Response.json({
      ok: a.code === 'ok',
      engine: req.engine,
      engineVersion: null,
      egressIp: a.code === 'ok' ? (a.egressIp ?? ORIGIN) : null,
      ms: 5,
      code: a.code,
    });
  });
  return { stub, lbs, panelHosts, checks };
}

/** The check's test link: the address's own binding, as `edgeTestLinks.build` would show it. */
function linkSeam() {
  __setClientCheckLinks(async (ctx, edgeId) => {
    const b = await ctx.runQuery(internal.edgeVerification.binding, { edgeId });
    if (!b) return { ok: false, detail: 'edge.no_address' };
    const q = `security=reality&type=tcp&sni=a.example&fp=chrome&pbk=${PBK}&sid=ab&flow=xtls-rprx-vision`;
    return {
      ok: true,
      link: `vless://${UUID}@${b.endpoint}?${q}#FCP%20test`,
      binding: {
        endpoint: b.endpoint,
        listenerKey: b.listenerKey,
        listenerRevision: b.listenerRevision,
        configHash: b.configHash,
      },
      credentialId: null,
    };
  });
}

/**
 * backend + a trusted UpCloud account + origin node-one (REALITY listener `u`)
 * with a hand-made edge published at index 0, the client check on and
 * answering, and (unless `ticked: false`) the account's location ticked: an
 * endpoint the owner confirmed there is its trust evidence.
 */
async function seed(opts: { ticked?: boolean; enabled?: boolean } = {}) {
  vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: 'upcloud',
    name: 'acct-u',
    qualified: true,
  });
  const { relayId, listenerIds } = await registerRelay(t, {
    listeners: [
      realityListener({
        listenerKey: 'u',
        tlsNames: ['a.example'],
        panelBinding: {
          inboundTag: 'VLESS_RELAY_U',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: INBOUND,
        },
      }),
    ],
  });
  const listenerId = listenerIds.u!;
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: OLD_EDGE, publish: true });
  const oldEdgeId = edgeId as Id<'edges'>;
  const location = (await defaultLocationRow(t, accountId))!;
  if (opts.ticked !== false)
    await t.run((ctx) =>
      ctx.db.patch(location._id, {
        qualification: {
          by: 'admin',
          at: Date.now(),
          evidence: {
            edgeId: oldEdgeId,
            endpoint: `${OLD_EDGE}:443`,
            accountTestedAt: Date.now(),
            templateHash: 'tpl',
            listenerId,
            listenerRevision: 1,
          },
        },
      }),
    );
  await t.run((ctx) =>
    upsertSettingRow(ctx, 'edge.clientCheck.enabled', JSON.stringify(opts.enabled !== false)),
  );
  await t.mutation(internal.edgeClientCheck.recordHealth, {
    ok: true,
    code: null,
    engines: [
      { engine: 'sing-box', version: '1.14.3' },
      { engine: 'xray', version: '26.10.21' },
    ],
    egressHost: 'echo.example',
  });
  linkSeam();
  return { t, accountId, relayId, listenerId, oldEdgeId, locationId: location._id };
}

async function drain(t: ReturnType<typeof convexTest>, rotationId: Id<'edgeRotations'>) {
  for (let i = 0; i < 600; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const r = await t.query(internal.edgeRotations.get, { id: rotationId });
    if (r && ['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase)) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
      return r;
    }
  }
  throw new Error('drain: the rotation did not settle');
}

const replace = (
  t: ReturnType<typeof convexTest>,
  relayId: Id<'relays'>,
  targetEdgeId: Id<'edges'>,
  trigger: 'manual' | 'detector' = 'manual',
) =>
  t.mutation(internal.edgeRotations.start, {
    relayId,
    kind: 'replace',
    trigger,
    burn: true,
    targetEdgeId,
  });

describe('replacing a blocked address without a spare', () => {
  test('no spare: a new address in the ticked location, checked by FCP, published; the old one drains', async () => {
    vi.useFakeTimers();
    const w = world(() => ({ code: 'ok' }));
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    const { rotationId } = await replace(t, relayId, oldEdgeId);
    const r = await drain(t, rotationId);
    expect(r).toMatchObject({ phase: 'done', outcome: 'published' });
    expect(r.events.map((e) => e.code)).toEqual(
      expect.arrayContaining(['selected_provision', 'client_check', 'verified', 'published']),
    );
    expect(w.lbs.size).toBe(1);
    const fresh = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(fresh).toMatchObject({ publication: 'published', poolIndex: 0, listenerId });
    expect(fresh.addresses.v4).toBe(NEW_EDGE);
    // FCP's own check confirmed it, bound like a tick, with the engines that proved it.
    expect(fresh.verification).toMatchObject({
      rung: 'verified',
      by: 'system',
      method: 'client_check',
      endpoint: `${NEW_EDGE}:443`,
    });
    expect(fresh.verification!.engines!.map((e) => e.engine)).toEqual(['sing-box', 'xray']);
    expect(fresh.clientCheck).toMatchObject({ verdict: 'passed', by: 'system' });
    expect(fresh.replacementOf).toMatchObject({ edgeId: oldEdgeId, trigger: 'manual' });
    const old = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(old).toMatchObject({ publication: 'draining', status: 'draining' });
    expect(w.checks.every((c) => c.address === NEW_EDGE)).toBe(true);
    // The backend Host moved to the new address.
    expect(w.panelHosts[0]!.address).toBe(NEW_EDGE);
  });

  test('a new address that fails the check: nothing published, the edge failed, the next try waits an hour', async () => {
    vi.useFakeTimers();
    // sing-box gets through the address in use, never through the new one.
    const w = world((engine, address) =>
      engine === 'sing-box' && address === NEW_EDGE ? { code: 'timeout' } : { code: 'ok' },
    );
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await replace(t, relayId, oldEdgeId);
    const startedAt = Date.now();
    const r = await drain(t, rotationId);
    expect(r).toMatchObject({ phase: 'failed', outcome: 'client_check_failed' });
    // Three tries, each against the control (the address in use).
    expect(w.checks.filter((c) => c.address === NEW_EDGE && c.engine === 'sing-box')).toHaveLength(
      3,
    );
    expect(w.checks.some((c) => c.address === OLD_EDGE)).toBe(true);
    const fresh = (await t.query(internal.edges.get, { id: r.createdEdgeId! }))!;
    expect(fresh.status).toBe('failed');
    expect(fresh.verification).toBeUndefined();
    expect(fresh.clientCheck).toMatchObject({ verdict: 'address_failed', control: true });
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    expect(origin.cooldownUntil).toBeGreaterThanOrEqual(
      startedAt + CLIENT_CHECK_FAIL_COOLDOWN_MS - 1,
    );
    // The cooldown refuses the next automatic and manual start alike (force passes).
    await expect(replace(t, relayId, oldEdgeId)).rejects.toThrow(/cooldown|cooling/i);
  });

  test('could not check: the new address stays an untested spare, and the next replace takes it instead of buying', async () => {
    vi.useFakeTimers();
    let down = true;
    const w = world(() => (down ? { status: 500 } : { code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await replace(t, relayId, oldEdgeId);
    const r = await drain(t, rotationId);
    expect(r.phase).toBe('done');
    expect(r.events.map((e) => e.code)).toContain('unverified_standby');
    const spare = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(spare).toMatchObject({ publication: 'unpublished', status: 'active' });
    expect(spare.verification).toBeUndefined();
    expect(w.lbs.size).toBe(1);
    // The service is back: a second replace checks that spare, buys nothing.
    down = false;
    await t.mutation(internal.edgeClientCheck.recordHealth, {
      ok: true,
      code: null,
      engines: [],
      egressHost: null,
    });
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: undefined }));
    const second = await drain(t, (await replace(t, relayId, oldEdgeId)).rotationId);
    expect(second).toMatchObject({ phase: 'done', outcome: 'published', toEdgeId: spare._id });
    expect(second.viaStandby).toBe(true);
    expect(w.lbs.size).toBe(1);
    const now = (await t.query(internal.edges.get, { id: spare._id }))!;
    expect(now.verification).toMatchObject({ method: 'client_check' });
  });

  test('a spare whose check found the address at fault is not taken again; the next replace buys a new one', async () => {
    vi.useFakeTimers();
    // The first address minted (the spare) never carries a session; the rest do.
    const w = world((_engine, address) =>
      address === NEW_EDGE ? { code: 'timeout' } : { code: 'ok' },
    );
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    const spare = (
      await drain(
        t,
        (
          await t.mutation(internal.edgeRotations.start, {
            relayId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: false,
            listenerId,
          })
        ).rotationId,
      )
    ).toEdgeId!;
    const first = await drain(t, (await replace(t, relayId, oldEdgeId)).rotationId);
    expect(first).toMatchObject({ phase: 'failed', outcome: 'client_check_failed' });
    expect(first.viaStandby).toBe(true);
    const failed = (await t.query(internal.edges.get, { id: spare }))!;
    expect(failed).toMatchObject({ status: 'active', publication: 'unpublished' });
    expect(failed.clientCheck).toMatchObject({ verdict: 'address_failed' });
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: undefined, rotationsToday: 0 }));
    vi.advanceTimersByTime(1000);
    const second = await drain(t, (await replace(t, relayId, oldEdgeId)).rotationId);
    expect(second).toMatchObject({ phase: 'done', outcome: 'published' });
    expect(second.viaStandby).toBeFalsy();
    expect(second.toEdgeId).not.toBe(spare);
    expect(w.lbs.size).toBe(2);
  });

  test('a confirmation FCP wrote opens the publication gate only on its terms: the switch on, the location ticked', async () => {
    vi.useFakeTimers();
    world(() => ({ code: 'ok' }));
    const { t, relayId, listenerId, locationId } = await seed();
    const spare = (
      await drain(
        t,
        (
          await t.mutation(internal.edgeRotations.start, {
            relayId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: false,
            listenerId,
          })
        ).rotationId,
      )
    ).toEdgeId!;
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      confirmed: true,
    });
    const gate = () =>
      t.run(async (ctx) => checkPublishable(ctx, (await ctx.db.get(spare))!, false));
    expect(await gate()).toEqual({ ok: true });
    // The switch off: the record stays, but stands in for nobody's tick.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.clientCheck.enabled', 'false'));
    expect(await gate()).toEqual({ ok: false, code: 'unverified_endpoint' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.clientCheck.enabled', 'true'));
    expect(await gate()).toEqual({ ok: true });
    // The location no longer ticked (its evidence gone, however that happened).
    await t.run((ctx) =>
      ctx.db.patch(locationId, { qualification: { by: 'admin', at: Date.now() } }),
    );
    expect(await gate()).toEqual({ ok: false, code: 'unverified_endpoint' });
  });

  test('one address in use while replacements count on the check: single_address', async () => {
    world(() => ({ code: 'ok' }));
    const { t } = await seed();
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'single_address')).toMatchObject({
      severity: 'warning',
      facts: { inUse: 1 },
    });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.clientCheck.enabled', 'false'));
    const off = await t.query(internal.edgeOperator.attention, {});
    expect(off.items.some((i) => i.kind === 'single_address')).toBe(false);
  });

  test('no ticked location: refused before anything is bought', async () => {
    world(() => ({ code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed({ ticked: false });
    await expect(replace(t, relayId, oldEdgeId)).rejects.toThrow(/no_ticked_location/);
  });

  test('the switch off: today’s rule (a tested spare or nothing)', async () => {
    world(() => ({ code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed({ enabled: false });
    await expect(replace(t, relayId, oldEdgeId)).rejects.toThrow(/no_verified_spare/);
  });

  test('turning automation on keeps a spare unless the check answers its health check', async () => {
    world(() => ({ code: 'ok' }));
    const { t } = await seed({ enabled: false });
    const cfg = () => t.run((ctx) => resolveEdgeConfig(ctx.db));
    await t.mutation(internal.edgeAdmin.setAutomation, { on: true });
    expect(await cfg()).toMatchObject({ standbyPerListener: 0, clientCheck: { enabled: true } });
    await t.mutation(internal.edgeAdmin.setAutomation, { on: false });
    await t.mutation(internal.edgeClientCheck.recordHealth, {
      ok: false,
      code: 'unavailable',
      engines: [],
      egressHost: null,
    });
    await t.mutation(internal.edgeAdmin.setAutomation, { on: true });
    expect(await cfg()).toMatchObject({ standbyPerListener: 1, clientCheck: { enabled: true } });
  });

  test('the service not answering its health check: no waiver', async () => {
    world(() => ({ code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed();
    await t.mutation(internal.edgeClientCheck.recordHealth, {
      ok: false,
      code: 'unavailable',
      engines: [],
      egressHost: null,
    });
    await expect(replace(t, relayId, oldEdgeId)).rejects.toThrow(/no_verified_spare/);
  });

  test('a replacement blocked again soon: the detector holds its transport; the operator resumes it', async () => {
    vi.useFakeTimers();
    world(() => ({ code: 'ok' }));
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
      // The address in use was put in use by a replace a moment ago.
      await ctx.db.patch(oldEdgeId, {
        publishedAt: Date.now(),
        replacementOf: { edgeId: oldEdgeId, at: Date.now(), trigger: 'detector' },
      });
    });
    await expect(replace(t, relayId, oldEdgeId, 'detector')).rejects.toThrow(
      /replacement_reblocked/,
    );
    await t.mutation(internal.edgeRotations.holdAutoReplace, {
      relayId,
      edgeId: oldEdgeId,
      code: 'replacement_reblocked',
    });
    // Held now, even once the window has passed.
    await t.run((ctx) => ctx.db.patch(oldEdgeId, { publishedAt: Date.now() - 48 * 3_600_000 }));
    await expect(replace(t, relayId, oldEdgeId, 'detector')).rejects.toThrow(/auto_replace_held/);
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'auto_replace_held')).toMatchObject({
      severity: 'critical',
      code: 'replacement_reblocked',
      listenerKey: 'u',
    });
    // An operator's own replace is never held.
    const manual = await replace(t, relayId, oldEdgeId);
    expect(manual.rotationId).toBeTruthy();
    await t.run((ctx) => ctx.db.patch(relayId, { activeRotationId: undefined }));
    const resumed = await t.mutation(internal.edgeRotations.resumeAutoReplace, {
      relayId,
      listenerId,
    });
    expect(resumed).toEqual({ ok: true, lifted: 1 });
    expect((await t.query(internal.relays.get, { id: relayId }))!.autoReplaceHolds).toBeUndefined();
  });

  test('the detector holds a rapid re-block whatever blocker its start named', async () => {
    world(() => ({ code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed();
    // What the detector asks after ANY refused start (a fleet brake, the daily cap...).
    const ask = () =>
      t.mutation(internal.edgeRotations.holdAutoReplace, {
        relayId,
        edgeId: oldEdgeId,
        code: 'replacement_reblocked',
        ifReblocked: true,
      });
    // Not a replacement: nothing to hold.
    expect(await ask()).toEqual({ held: false });
    await t.run((ctx) =>
      ctx.db.patch(oldEdgeId, {
        publishedAt: Date.now(),
        replacementOf: { edgeId: oldEdgeId, at: Date.now(), trigger: 'detector' },
      }),
    );
    expect(await ask()).toEqual({ held: true });
    expect((await t.query(internal.relays.get, { id: relayId }))!.autoReplaceHolds).toEqual([
      expect.objectContaining({ code: 'replacement_reblocked', edgeId: oldEdgeId }),
    ]);
  });
});

describe('the pieces', () => {
  test('who receives a replacement: inherit keeps the target’s pool index', () => {
    expect(REPLACEMENT_POLICY).toBe('inherit');
    expect(replacementPlacement({ policy: 'inherit', target: { poolIndex: 3 } })).toEqual({
      poolIndex: 3,
    });
  });

  test('rollback: the new fields go, an address FCP confirmed keeps serving as a named connection', async () => {
    vi.useFakeTimers();
    world(() => ({ code: 'ok' }));
    const { t, relayId, oldEdgeId } = await seed();
    const r = await drain(t, (await replace(t, relayId, oldEdgeId)).rotationId);
    const id = r.toEdgeId!;
    await t.mutation(internal.edgeRotations.holdAutoReplace, {
      relayId,
      edgeId: id,
      code: 'replacement_reblocked',
    });
    await t.mutation(internal.edgeClientCheck.clearForRollback, {});
    await vi.runAllTimersAsync();
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    const e = (await t.query(internal.edges.get, { id }))!;
    expect(e.clientCheck).toBeUndefined();
    expect(e.replacementOf).toBeUndefined();
    expect(e.verification).toMatchObject({ method: 'named_connection', by: 'system' });
    expect(e.verification!.engines).toBeUndefined();
    const rot = (await t.query(internal.edgeRotations.get, { id: r._id }))!;
    expect(rot.clientCheckGate).toBeUndefined();
    expect((await t.query(internal.relays.get, { id: relayId }))!.autoReplaceHolds).toBeUndefined();
  });

  test('reblockedSoon: only a replacement, only inside the window, 0 = never', async () => {
    const cfg = { replacement: { reblockHours: 24 } };
    const now = 1_800_000_000_000;
    const rep = {
      replacementOf: { edgeId: 'e' as Id<'edges'>, at: now - 1000, trigger: 'detector' },
    };
    expect(reblockedSoon({ ...rep, publishedAt: now - 3_600_000 }, cfg, now)).toBe(true);
    expect(reblockedSoon({ ...rep, publishedAt: now - 25 * 3_600_000 }, cfg, now)).toBe(false);
    expect(reblockedSoon({ publishedAt: now }, cfg, now)).toBe(false);
    expect(reblockedSoon(rep, { replacement: { reblockHours: 0 } }, now)).toBe(false);
  });

  test('a passing check by hand confirms a spare only in a ticked location with the switch on; an untrust clears it', async () => {
    vi.useFakeTimers();
    world(() => ({ code: 'ok' }));
    const { t, relayId, listenerId, locationId } = await seed();
    // A spare in that location (provisioned, untested).
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
      listenerId,
    });
    const r = await drain(t, rotationId);
    const spare = r.toEdgeId!;
    expect((await t.query(internal.edges.get, { id: spare }))!.verification).toBeUndefined();
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.clientCheck.enabled', 'false'));
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      verdict: 'passed',
      confirmed: false,
    });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.clientCheck.enabled', 'true'));
    // A signature is accepted once: the frozen test clock must move between two checks.
    vi.advanceTimersByTime(1000);
    expect(await t.action(internal.edgeClientCheck.check, { edgeId: spare })).toMatchObject({
      verdict: 'passed',
      confirmed: true,
    });
    expect((await t.query(internal.edges.get, { id: spare }))!.verification).toMatchObject({
      method: 'client_check',
      by: 'system',
    });
    // The owner untrusts the location: the spare needs a test again.
    await t.mutation(internal.edgeLocations.setQualified, { id: locationId, qualified: false });
    expect((await t.query(internal.edges.get, { id: spare }))!.verification).toBeUndefined();
  });

  test('a tick in a location trusted by the override becomes its evidence; the reconcile fills older ones', async () => {
    vi.useFakeTimers();
    world(() => ({ code: 'ok' }));
    const { t, relayId, listenerId, accountId, locationId } = await seed({ ticked: false });
    await t.run((ctx) => ctx.db.patch(accountId, { lastTestOkAt: Date.now() }));
    const loc = async () => (await t.run((ctx) => ctx.db.get(locationId)))!;
    expect((await loc()).qualification?.evidence).toBeUndefined();
    const r = await drain(
      t,
      (
        await t.mutation(internal.edgeRotations.start, {
          relayId,
          kind: 'provision',
          trigger: 'manual',
          publishOnDone: false,
          listenerId,
        })
      ).rotationId,
    );
    await verifyL4Edge(t, r.toEdgeId!);
    expect((await loc()).qualification?.evidence?.edgeId).toBe(r.toEdgeId);
    // Cleared, then filled again by the reconcile from the same ticked address.
    await t.run((ctx) =>
      ctx.db.patch(locationId, { qualification: { by: 'admin', at: Date.now() } }),
    );
    expect(await t.mutation(internal.edgeVerification.fillTickedEvidence, {})).toEqual({
      filled: 1,
    });
    expect((await loc()).qualification?.evidence?.edgeId).toBe(r.toEdgeId);
  });
});
