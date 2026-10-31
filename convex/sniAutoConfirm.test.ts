/// <reference types="vite/client" />
/**
 * FCP's own test of a send (docs/edges.md "FCP's own test of a send"):
 *
 *  - switch off (the default): a send waits for a person exactly as before,
 *    nothing is scheduled, issued or tested;
 *  - on: a minute after the backend holds the send, FCP's client check tests
 *    the witness through the node's confirmed address, with every engine the
 *    service holds (Mihomo too), against the same address with a name members
 *    get now; a pass hands the names to that node's members as the system;
 *  - a test that does not pass hands out nothing, says why, and is tried
 *    again a bounded number of times;
 *  - a change to the live rows while the test runs voids it;
 *  - an operator's tick and FCP's test never both confirm.
 *
 * The client-check service is a fake behind the same signature checks; the
 * links come through the check's test seam. RFC 5737 addresses and `*.example`
 * names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  FIXTURE_ORIGIN as ORIGIN,
  adoptL4Edge,
  insertPanelServer,
  markBackendSetUp,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { __setClientCheckLinks } from './edgeClientCheck';
import { DEFAULT_CLIENT_CHECK_URL } from './lib/edges/clientCheck/client';
import {
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
} from './lib/edges/clientCheck/protocol';
import { ReplayGuard, verifyRequest } from './lib/edges/clientCheck/signing';
import { AUTO_MAX_FAILURES, AUTO_RETRY_MS } from './lib/edges/sni/autoTest';
import type { ClientCheckEngine, ClientCheckSessionCode } from '../src/shared/contracts/edgeCodes';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;
const TAG = 'VLESS_RELAY_A';
const SECRET = 'auto-confirm-test-secret';
const UUID = '00000000-0000-4000-8000-0000000000aa';
const PBK = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0';
/** The name the listener hands out before the send: the control presents it. */
const CURRENT = 'a.example';

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('EDGE_CLIENT_CHECK_SECRET', SECRET);
  // Scheduled functions wait until a test runs them: each step is driven here.
  vi.useFakeTimers();
});
afterEach(() => {
  __setClientCheckLinks(null);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** The fake panel of sniRollouts.test.ts: one profile, one REALITY transport, one node. */
function installPanel() {
  const panel = { names: ['a.example', 'b.example'], patches: 0 };
  const json = (o: unknown) =>
    new Response(JSON.stringify({ response: o }), {
      headers: { 'content-type': 'application/json' },
    });
  const profile = () => ({
    uuid: PROFILE,
    name: 'Default',
    config: {
      inbounds: [
        {
          tag: TAG,
          port: 443,
          protocol: 'vless',
          settings: { clients: [], decryption: 'none' },
          streamSettings: {
            network: 'tcp',
            security: 'reality',
            realitySettings: {
              target: 'target.example:443',
              serverNames: panel.names,
              privateKey: 'PRIVATE_KEY_VALUE',
              shortIds: ['deadbeef00112233'],
            },
          },
        },
      ],
    },
    inbounds: [{ uuid: INBOUND, tag: TAG }],
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      if ((init.method ?? 'GET').toUpperCase() === 'PATCH') {
        const body = JSON.parse(init.body as string);
        panel.names = body.config.inbounds[0].streamSettings.realitySettings.serverNames;
        panel.patches++;
        return json({});
      }
      if (path === '/api/nodes')
        return json([
          {
            uuid: 'n-1',
            name: 'node-one',
            isConnected: true,
            isDisabled: false,
            lastStatusChange: 't0',
            configProfile: {
              activeConfigProfileUuid: PROFILE,
              activeInbounds: [{ uuid: INBOUND, tag: TAG }],
            },
          },
        ]);
      if (path === '/api/hosts') return json([]);
      if (path === '/api/internal-squads') return json({ internalSquads: [] });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile()] });
      if (path === `/api/config-profiles/${PROFILE}`) return json(profile());
      return json({});
    }),
  );
  return panel;
}

type Answer = { code: ClientCheckSessionCode; egressIp?: string } | { status: number };
/** What the fake service answers, per engine and the server name the outbound presents. */
type Script = (engine: ClientCheckEngine, sni: string) => Answer;

/**
 * The fake client-check service in front of the fake panel: checks FCP's
 * signature like the real one, reports three engines, then answers by `script`.
 */
function installService(script: { current: Script }) {
  const calls: Array<{ engine: ClientCheckEngine; sni: string }> = [];
  const guard = new ReplayGuard();
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!url.startsWith(DEFAULT_CLIENT_CHECK_URL)) return inner(input as string, init);
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body = typeof init.body === 'string' ? init.body : '';
    const path = new URL(url).pathname;
    const ok = await verifyRequest(
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
    if (ok !== 'ok') return new Response('{}', { status: 401 });
    if (path === '/v1/health')
      return Response.json({
        ok: true,
        engines: [
          { engine: 'sing-box', version: '1.14.4' },
          { engine: 'xray', version: '26.10.29' },
          { engine: 'mihomo', version: '1.19.33' },
        ],
        egressHost: 'echo.example',
      });
    const req = JSON.parse(body) as { engine: ClientCheckEngine; outbound: Record<string, any> };
    const o = req.outbound;
    const sni: string =
      req.engine === 'sing-box'
        ? o.tls.server_name
        : req.engine === 'mihomo'
          ? o.servername
          : o.streamSettings.realitySettings.serverName;
    calls.push({ engine: req.engine, sni });
    const a = script.current(req.engine, sni);
    if ('status' in a) return new Response('{}', { status: a.status });
    return Response.json({
      ok: a.code === 'ok',
      engine: req.engine,
      engineVersion: 'x',
      egressIp: a.code === 'ok' ? (a.egressIp ?? ORIGIN) : null,
      ms: 5,
      code: a.code,
    });
  });
  // The receipt's test link through the address: the name asked for, else the one members get.
  __setClientCheckLinks(async (ctx, edgeId, opts) => {
    const b = await ctx.runQuery(internal.edgeVerification.binding, { edgeId });
    if (!b) return { ok: false, detail: 'edge.no_address' };
    const sni = opts?.candidateSni ?? CURRENT;
    const q = `security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${PBK}&sid=ab&flow=xtls-rprx-vision`;
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
  return calls;
}

/** The node takes the names when `taken`: before that a new name is refused by every engine. */
function nodeScript(state: { taken: boolean }): Script {
  return (_engine, sni) =>
    sni === CURRENT || state.taken ? { code: 'ok' } : { code: 'reality_refused' };
}

async function seed(opts: { auto: boolean; script?: Script } = { auto: true }) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  installPanel();
  const script = { current: opts.script ?? (() => ({ code: 'ok' as const })) };
  const calls = installService(script);
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await markBackendSetUp(t, serverId);
  await t.mutation(internal.sniFamilies.patchConfig, {
    patch: { enabled: true, autoConfirm: opts.auto },
  });
  const { relayId, listenerIds } = await registerRelay(t, { listeners: [realityListener()] });
  const listenerId = listenerIds.a as Id<'relayListeners'>;
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: true });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam',
    label: 'Fam',
    targetAddress: 'target.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: 'fam',
    lines: ['fresh-1.example', 'fresh-2.example'],
  });
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
    });
  const { id } = await t.mutation(internal.sniFamilies.bind, {
    slug: 'fam',
    backendSlug: 'panel-a',
    inboundTag: TAG,
  });
  // The service answered its health check (the edge-reconcile pass asks every 5 minutes).
  await t.action(internal.edgeClientCheck.refreshHealth, {});
  return {
    t,
    script,
    calls,
    relayId,
    listenerId,
    edgeId: edgeId as Id<'edges'>,
    bindingId: id as Id<'sniInboundBindings'>,
  };
}

const activeNames = async (t: T, listenerId: Id<'relayListeners'>) =>
  ((await t.run((ctx) => ctx.db.get(listenerId)))!.tlsNames ?? [])
    .filter((n) => n.status === 'active')
    .map((n) => n.name);

const receipts = (t: T) => t.run((ctx) => ctx.db.query('sniAcceptanceReceipts').collect());
const audits = async (t: T, action: string) =>
  (await t.run((ctx) => ctx.db.query('auditLog').collect())).filter((a) => a.action === action);
const scheduled = (t: T) =>
  t.run(async (ctx) =>
    (await ctx.db.system.query('_scheduled_functions').collect())
      .filter((j) => j.state.kind === 'pending')
      .map((j) => j.name),
  );

/** One sweep, then the run it started (the scheduler is frozen; each step is driven). */
async function sweepAndRun(t: T) {
  const swept = await t.mutation(internal.sniAutoConfirm.sweep, {});
  const issued = (await receipts(t)).filter(
    (r) => r.evidenceKind === 'client_check' && r.state === 'issued',
  );
  for (const r of issued) await t.action(internal.sniAutoConfirm.run, { receiptId: r._id });
  return { swept, issued };
}

describe('switch off', () => {
  test('a send waits for a person exactly as before: nothing scheduled, issued or tested', async () => {
    const { t, calls, bindingId, listenerId } = await seed({ auto: false });
    const out = await t.action(internal.sniRollouts.start, { bindingId });
    expect(out.phase).toBe('panel_confirmed');
    expect(await scheduled(t)).not.toContain('sniAutoConfirm:sweep');
    expect(await t.mutation(internal.sniAutoConfirm.sweep, {})).toEqual({
      started: 0,
      why: 'off',
    });
    expect(await receipts(t)).toEqual([]);
    expect(calls.filter((c) => c.engine)).toEqual([]);
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    const view = await t.query(internal.sniTransports.status, { backendSlug: 'panel-a' });
    expect(view.switches.autoTest).toBe('off');
    expect(view.transports[0]!.nodes[0]!.autoTest).toBeNull();
  });
});

describe('a pass', () => {
  test('the send schedules the test; a pass hands the generation to the node, as the system', async () => {
    const { t, calls, bindingId, listenerId, relayId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    expect(await scheduled(t)).toContain('sniAutoConfirm:sweep');
    const epoch0 = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const { swept } = await sweepAndRun(t);
    expect(swept).toEqual({ started: 1, why: null });
    // The witness, by every engine the service holds; no control was needed.
    expect(calls).toEqual([
      { engine: 'sing-box', sni: 'fresh-1.example' },
      { engine: 'xray', sni: 'fresh-1.example' },
      { engine: 'mihomo', sni: 'fresh-1.example' },
    ]);
    expect(await activeNames(t, listenerId)).toEqual([
      'a.example',
      'b.example',
      'fresh-1.example',
      'fresh-2.example',
    ]);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 1);
    const [rc] = await receipts(t);
    expect(rc).toMatchObject({
      rolloutId,
      evidenceKind: 'client_check',
      state: 'confirmed',
      isWitness: true,
      sni: 'fresh-1.example',
      check: { verdict: 'passed', code: null, control: false },
    });
    expect(rc!.actorAdminId).toBeUndefined();
    // Audited as FCP's client check, never as an admin's tick.
    const accepted = await audits(t, 'edge.sni.names.accepted');
    expect(accepted).toHaveLength(1);
    expect(accepted[0]).toMatchObject({ actorType: 'system' });
    expect(accepted[0]!.payload).toMatchObject({
      by: 'client_check',
      count: 2,
      witness: true,
      engines: 'sing-box:ok xray:ok mihomo:ok',
    });
    // Nothing waits any more: the next sweep starts nothing.
    expect((await t.mutation(internal.sniAutoConfirm.sweep, {})).started).toBe(0);
    const node = (await t.query(internal.sniTransports.status, { backendSlug: 'panel-a' }))
      .transports[0]!.nodes[0]!;
    expect(node).toMatchObject({ waitingTest: 0, autoTest: { state: 'passed' } });
  });

  test('sing-box refused by the node whatever the name: not the name, the send passes', async () => {
    // An Xray that wants an ML-KEM key share refuses sing-box through every name.
    const { t, calls, bindingId, listenerId } = await seed({
      auto: true,
      script: (engine) => (engine === 'sing-box' ? { code: 'reality_refused' } : { code: 'ok' }),
    });
    await t.action(internal.sniRollouts.start, { bindingId });
    await sweepAndRun(t);
    // The control: the same address with the name members get now.
    expect(calls.filter((c) => c.sni === CURRENT).map((c) => c.engine)).toEqual([
      'sing-box',
      'xray',
      'mihomo',
    ]);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'confirmed',
      check: { verdict: 'passed_with_refusals', control: true },
    });
    expect(await activeNames(t, listenerId)).toContain('fresh-2.example');
  });
});

describe('names that prove only themselves', () => {
  test('no witness: one name per test, the next one after each pass', async () => {
    const { t, bindingId, listenerId } = await seed();
    // Both names were listed by this transport before: neither is a witness.
    await t.run(async (ctx) => {
      const b = (await ctx.db.get(bindingId))!;
      for (const name of ['fresh-1.example', 'fresh-2.example'])
        await ctx.db.insert('sniInboundNameHistory', {
          backendServerId: b.backendServerId,
          inboundUuid: b.inboundUuid,
          name,
          firstSeenGeneration: 0,
        });
    });
    await t.action(internal.sniRollouts.start, { bindingId });
    await sweepAndRun(t);
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example', 'fresh-1.example']);
    // The pass asked for the next sweep of this send; it tests the next name.
    expect(await scheduled(t)).toContain('sniAutoConfirm:sweep');
    await sweepAndRun(t);
    expect(await activeNames(t, listenerId)).toEqual([
      'a.example',
      'b.example',
      'fresh-1.example',
      'fresh-2.example',
    ]);
    expect((await receipts(t)).map((r) => [r.sni, r.isWitness, r.state])).toEqual([
      ['fresh-1.example', false, 'confirmed'],
      ['fresh-2.example', false, 'confirmed'],
    ]);
  });
});

describe('a test that does not pass', () => {
  test('the node has not taken the names: nothing handed out, the page says why, tried again later', async () => {
    const node = { taken: false };
    const { t, bindingId, listenerId } = await seed({ auto: true, script: nodeScript(node) });
    await t.action(internal.sniRollouts.start, { bindingId });
    await sweepAndRun(t);
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'failed',
      check: { verdict: 'address_failed', control: true },
    });
    expect(await audits(t, 'edge.sni.names.accepted')).toEqual([]);
    const tested = await audits(t, 'edge.sni.names.tested');
    expect(tested.map((a) => [a.actorType, a.payload])).toEqual([
      [
        'system',
        expect.objectContaining({
          outcome: 'failed',
          verdict: 'address_failed',
          engines: 'sing-box:reality_refused xray:reality_refused mihomo:reality_refused',
        }),
      ],
    ]);
    const view = await t.query(internal.sniTransports.status, { backendSlug: 'panel-a' });
    expect(view.switches.autoTest).toBe('ready');
    expect(view.transports[0]!.nodes[0]).toMatchObject({
      waitingTest: 2,
      autoTest: { state: 'failed', verdict: 'address_failed', failures: 1, sni: 'fresh-1.example' },
    });
    // Too soon to try again; after the retry interval it is, and the node has the names by then.
    expect((await t.mutation(internal.sniAutoConfirm.sweep, {})).started).toBe(0);
    vi.setSystemTime(Date.now() + AUTO_RETRY_MS);
    node.taken = true;
    await sweepAndRun(t);
    expect(await activeNames(t, listenerId)).toContain('fresh-1.example');
    expect((await receipts(t)).map((r) => r.state).sort()).toEqual(['confirmed', 'failed']);
  });

  test('a name that keeps failing is tried a bounded number of times, then left to a person', async () => {
    const { t, bindingId } = await seed({ auto: true, script: nodeScript({ taken: false }) });
    await t.action(internal.sniRollouts.start, { bindingId });
    for (let i = 0; i < AUTO_MAX_FAILURES + 2; i++) {
      await sweepAndRun(t);
      vi.setSystemTime(Date.now() + AUTO_RETRY_MS);
    }
    expect((await receipts(t)).filter((r) => r.state === 'failed')).toHaveLength(AUTO_MAX_FAILURES);
    const node = (await t.query(internal.sniTransports.status, { backendSlug: 'panel-a' }))
      .transports[0]!.nodes[0]!;
    expect(node.autoTest).toMatchObject({ state: 'stopped', failures: AUTO_MAX_FAILURES });
    // A person's test still works.
    expect(node.testable).toHaveLength(1);
  });

  test('the service not answering: could not check, nothing handed out', async () => {
    const { t, bindingId, listenerId, script } = await seed();
    script.current = () => ({ status: 503 });
    await t.action(internal.sniRollouts.start, { bindingId });
    await sweepAndRun(t);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'failed',
      check: { verdict: null, code: 'not_configured' },
    });
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    const node = (await t.query(internal.sniTransports.status, { backendSlug: 'panel-a' }))
      .transports[0]!.nodes[0]!;
    expect(node.autoTest).toMatchObject({ state: 'could_not_check', code: 'not_configured' });
  });
});

describe('guards', () => {
  test('the live rows change while the test runs: voided, nothing handed out', async () => {
    const { t, bindingId, listenerId } = await seed();
    await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniAutoConfirm.sweep, {});
    const [issued] = await receipts(t);
    // The listener changed materially after the receipt was made: the endpoint needs a retest.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, { revision: l.revision + 1 });
    });
    await t.action(internal.sniAutoConfirm.run, { receiptId: issued!._id });
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'superseded',
      check: { verdict: 'passed', code: 'edge.sni.binding_changed' },
    });
    expect(await audits(t, 'edge.sni.names.accepted')).toEqual([]);
  });

  test('the profile moves on the backend while the test runs: voided by the same guard as a tick', async () => {
    const { t, bindingId, listenerId } = await seed();
    await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniAutoConfirm.sweep, {});
    const [issued] = await receipts(t);
    const profile = (await t.run((ctx) => ctx.db.query('panelProfiles').collect()))[0]!;
    await t.run((ctx) => ctx.db.patch(profile._id, { changeToken: 'someone-else-wrote' }));
    await t.action(internal.sniAutoConfirm.run, { receiptId: issued!._id });
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'superseded',
      check: { code: 'edge.sni.profile_moved' },
    });
  });

  test('switched off while the test runs: the pass is recorded, nothing handed out', async () => {
    const { t, bindingId, listenerId } = await seed();
    await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniAutoConfirm.sweep, {});
    const [issued] = await receipts(t);
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { autoConfirm: false } });
    await t.action(internal.sniAutoConfirm.run, { receiptId: issued!._id });
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    expect((await receipts(t))[0]).toMatchObject({
      state: 'superseded',
      check: { verdict: 'passed', code: 'switched_off' },
    });
  });

  test("an operator's receipt-confirm route never confirms FCP's receipt", async () => {
    const { t, bindingId } = await seed();
    await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniAutoConfirm.sweep, {});
    const [issued] = await receipts(t);
    await expect(
      t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: issued!._id }),
    ).rejects.toThrow(/FCP's own test/);
  });

  test('a node with no confirmed address is left to a person', async () => {
    const { t, bindingId, edgeId } = await seed();
    await t.run((ctx) => ctx.db.patch(edgeId, { verification: undefined }));
    await t.action(internal.sniRollouts.start, { bindingId });
    expect((await t.mutation(internal.sniAutoConfirm.sweep, {})).started).toBe(0);
    expect(await receipts(t)).toEqual([]);
  });
});

describe('an operator and FCP on the same send', () => {
  /** An operator's receipt through the same address (the link builder has its own suite). */
  async function operatorReceipt(t: T, rolloutId: Id<'sniRollouts'>, edgeId: Id<'edges'>) {
    const c = await t.query(internal.sniRollouts.receiptContext, { rolloutId, edgeId });
    return t.mutation(internal.sniRollouts.recordReceipt, {
      rolloutId,
      generation: c.generation,
      relayId: c.relayId,
      listenerId: c.listenerId,
      edgeId,
      sni: c.sni,
      isWitness: c.isWitness,
      expectedToken: c.expectedToken,
      endpoint: c.binding.endpoint,
      listenerRevision: c.binding.listenerRevision,
      configHash: c.binding.configHash,
    });
  }

  test("the operator's tick lands while FCP tests: FCP's pass confirms nothing again", async () => {
    const { t, bindingId, edgeId, relayId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniAutoConfirm.sweep, {});
    const auto = (await receipts(t))[0]!;
    const theirs = await operatorReceipt(t, rolloutId!, edgeId);
    const ticked = await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: theirs });
    expect(ticked).toMatchObject({ ok: true, activated: 2 });
    const epoch = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    await t.action(internal.sniAutoConfirm.run, { receiptId: auto._id });
    expect(await t.run((ctx) => ctx.db.get(auto._id))).toMatchObject({
      state: 'superseded',
      check: { verdict: 'passed', code: 'already_proven' },
    });
    // One confirmation, one epoch bump, one accepted entry: the operator's.
    const accepted = await audits(t, 'edge.sni.names.accepted');
    expect(accepted.map((a) => a.actorType)).toEqual(['admin']);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch);
  });

  test("FCP's pass lands first: the operator's later tick is recorded and moves nothing", async () => {
    const { t, bindingId, edgeId, relayId, listenerId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const theirs = await operatorReceipt(t, rolloutId!, edgeId);
    await sweepAndRun(t);
    const revision = (await t.run((ctx) => ctx.db.get(listenerId)))!.namesRevision;
    const epoch = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const ticked = await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: theirs });
    expect(ticked).toEqual({ ok: true, activated: 0, witness: true });
    expect((await t.run((ctx) => ctx.db.get(theirs)))!.state).toBe('confirmed');
    expect((await t.run((ctx) => ctx.db.get(listenerId)))!.namesRevision).toBe(revision);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch);
    expect((await audits(t, 'edge.sni.names.accepted')).map((a) => a.actorType)).toEqual([
      'system',
    ]);
  });
});

describe('rollback', () => {
  test("FCP's receipts are removed; an operator's stay", async () => {
    const { t, bindingId, edgeId } = await seed({
      auto: true,
      script: nodeScript({ taken: false }),
    });
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    await sweepAndRun(t);
    const c = await t.query(internal.sniRollouts.receiptContext, { rolloutId: rolloutId!, edgeId });
    await t.mutation(internal.sniRollouts.recordReceipt, {
      rolloutId: rolloutId!,
      generation: c.generation,
      relayId: c.relayId,
      listenerId: c.listenerId,
      edgeId,
      sni: c.sni,
      isWitness: c.isWitness,
      expectedToken: c.expectedToken,
      endpoint: c.binding.endpoint,
      listenerRevision: c.binding.listenerRevision,
      configHash: c.binding.configHash,
    });
    expect(await t.mutation(internal.sniAutoConfirm.clearForRollback, {})).toEqual({
      cleared: 1,
      done: true,
    });
    expect((await receipts(t)).map((r) => r.evidenceKind)).toEqual(['operator_test_link']);
  });
});
