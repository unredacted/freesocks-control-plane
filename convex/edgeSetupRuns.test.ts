/// <reference types="vite/client" />
/**
 * Guided setup runs (edgeSetupRuns.ts + edgeSetupPlan.ts): the stage machine
 * end to end against the real rotation machine (a fake UpCloud + a fake backend
 * behind one fetch stub), with the other subsystems (Host hides, restore,
 * test links, rehearsal, the qualification credential) injected through the
 * stage-ops seam. Acceptance cases 1, 2, 3, 6, 9, 10, 11, 12, 20, 21 and 26 of
 * the plan. Fixtures only (RFC 5737 / 3849, `*.example`).
 */
import { ConvexError } from 'convex/values';
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { __setStageOpsForTests, approvedDarkCohorts, type StageOps } from './edgeSetupRuns';
import { __setPlanOpsForTests } from './edgeSetupPlan';
import type { PanelInbound } from './lib/backends/types';
import { MAX_OBSERVATION_AGE_MS, slugForNode, vectorsEqual } from './lib/edges/setupRuns';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setStageOpsForTests(null);
  __setPlanOpsForTests(null);
});

const ORIGIN = '203.0.113.10';
const NODE_UUID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const SS_INBOUND = '44444444-4444-4444-8444-444444444444';
const VMESS_INBOUND = '55555555-5555-4555-8555-555555555555';
const HOST_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const HOST_S = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
const HOST_V = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3';

interface PanelHost {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string;
  host?: string;
  isDisabled?: boolean;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
}

const inboundA: PanelInbound = {
  tag: 'VLESS_RELAY_A',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: FIXTURE_INBOUND,
  protocol: 'vless',
  port: 443,
  network: 'tcp',
  security: 'reality',
  reality: { target: 'target.example:443', serverNames: ['a.example'] },
  active: true,
};
const inboundS: PanelInbound = {
  tag: 'SS_IN',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: SS_INBOUND,
  protocol: 'shadowsocks',
  port: 8388,
  network: 'tcp',
  security: 'none',
  active: true,
};
const inboundV: PanelInbound = {
  tag: 'VMESS_IN',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: VMESS_INBOUND,
  protocol: 'vmess',
  port: 8443,
  network: 'tcp',
  security: 'tls',
  active: true,
};
const directHostA = (): PanelHost => ({
  uuid: HOST_A,
  remark: 'direct-a',
  address: ORIGIN,
  port: 443,
  sni: 'a.example',
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: FIXTURE_INBOUND },
});
const directHostS = (): PanelHost => ({
  uuid: HOST_S,
  remark: 'direct-s',
  address: ORIGIN,
  port: 8388,
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: SS_INBOUND },
});
const directHostV = (): PanelHost => ({
  uuid: HOST_V,
  remark: 'direct-v',
  address: ORIGIN,
  port: 8443,
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: VMESS_INBOUND },
});

/**
 * A fake UpCloud (every create mints a fresh RFC 5737 address) + a fake backend
 * whose Hosts are observable (the publish rotation creates the FCP Host).
 */
function fakeWorld(opts: { hosts?: PanelHost[]; failCreateAt?: number } = {}) {
  const panelHosts: PanelHost[] = opts.hosts ?? [directHostA()];
  const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
  let creates = 0;
  let lbCreates = 0;
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') {
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
      if (c.path === '/api/hosts' && c.method === 'PATCH') {
        const body = c.body as {
          uuid: string;
          address?: string;
          port?: number;
          sni?: string;
          host?: string;
          isDisabled?: boolean;
        };
        const h = panelHosts.find((x) => x.uuid === body.uuid);
        if (h) {
          if (body.address !== undefined) h.address = body.address;
          if (body.port !== undefined) h.port = body.port;
          if (body.sni !== undefined) h.sni = body.sni;
          if (body.host !== undefined) h.host = body.host;
          if (body.isDisabled !== undefined) h.isDisabled = body.isDisabled;
        }
        return jsonRes({ response: h ?? null });
      }
      if (c.path === '/api/hosts' && c.method === 'POST') {
        creates++;
        const body = c.body as PanelHost;
        const uuid = `cccccccc-cccc-4ccc-8ccc-${String(creates).padStart(12, '0')}`;
        panelHosts.push({ ...body, uuid });
        return jsonRes({ response: { uuid } });
      }
      return jsonRes({ message: 'not found' }, 404);
    }
    if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
      lbCreates++;
      // Fail exactly the Nth load-balancer create (a transient provider error).
      if (opts.failCreateAt !== undefined && lbCreates === opts.failCreateAt)
        return jsonRes({ error: { error_code: 'INTERNAL' } }, 500);
      const uuid = `lb-${lbs.size + 1}`;
      lbs.set(uuid, {
        uuid,
        name: (c.body as { name: string }).name,
        operational_state: 'running',
      });
      return jsonRes(lbs.get(uuid));
    }
    if (c.path === '/1.3/ip_address' && c.method === 'POST')
      return jsonRes({ ip_address: { address: `198.51.100.${10 + lbs.size}`, floating: 'yes' } });
    if (/^\/1\.3\/load-balancer\/[^/]+\/ip-addresses$/.test(c.path) && c.method === 'POST')
      return jsonRes({});
    const get = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (get && c.method === 'GET') {
      const lb = lbs.get(get[1]);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    if (get && c.method === 'DELETE') {
      lbs.delete(get[1]);
      return jsonRes({});
    }
    throw new Error(`unexpected ${c.method} ${c.url}`);
  });
  return { stub, panelHosts, lbs, creates: () => creates, lbCreates: () => lbCreates };
}

/** Backend + a TESTED but unqualified UpCloud account + the node in the inventory. */
async function seed(
  opts: { inbounds?: PanelInbound[]; hosts?: PanelHost[]; failCreateAt?: number } = {},
) {
  vi.useFakeTimers();
  const world = fakeWorld({ hosts: opts.hosts, failCreateAt: opts.failCreateAt });
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const accountId = await createAccount(t, { provider: 'upcloud', name: 'acct-u' });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
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
  __setPlanOpsForTests({
    listNodeInbounds: async () => opts.inbounds ?? [inboundA],
    listHosts: async () =>
      world.panelHosts.map((h) => ({ ...h, isDisabled: h.isDisabled ?? false })),
  });
  const calls = {
    hide: [] as Array<{ approvedUuids: string[] }>,
    restore: [] as string[],
    probes: [] as string[],
  };
  let hideResult: Partial<Awaited<ReturnType<StageOps['hideHosts']>>> = {};
  let hideStatus: Partial<Awaited<ReturnType<StageOps['hideStatus']>>> = {};
  let listingVersion = 1;
  let rehearsalHold = false;
  const ops: Partial<StageOps> = {
    ensureCredential: async () => ({ ok: true, reused: false }),
    requestVerificationProbes: async (_ctx, edgeId) => {
      calls.probes.push(edgeId as string);
      await landPartialEvidence(t, edgeId);
    },
    runFrontProof: async () => ({ ok: false, code: 'unsupported_protocol' }),
    buildTestLink: async (ctx, edgeId) => {
      const b = await ctx.runQuery(internal.edgeVerification.binding, { edgeId });
      if (!b) throw new Error('no binding');
      return {
        link: `vless://test@${b.endpoint}?security=reality#test`,
        format: 'links',
        binding: {
          edgeId: edgeId as string,
          endpoint: b.endpoint,
          listenerRevision: b.listenerRevision,
          configHash: b.configHash,
          listenerKey: b.listenerKey,
          issuedAt: new Date().toISOString(),
        },
        credentialId: null,
      };
    },
    hideHosts: async (_ctx, a) => {
      calls.hide.push({ approvedUuids: a.approvedUuids });
      return {
        state: 'confirmed',
        hidden: 1,
        pending: 0,
        failed: 0,
        reviewChanged: [],
        ...hideResult,
      };
    },
    hideStatus: async () => ({
      outstanding: 0,
      confirmed: 1,
      unresolved: 0,
      failed: 0,
      rows: [],
      ...hideStatus,
    }),
    rehearse: async (ctx, a) => ({
      ok: !rehearsalHold,
      failures: rehearsalHold ? [{ cohortKey: 'hold', format: 'links', reason: 'hold' }] : [],
      familiesDisabled: [],
      proofsExpired: [],
      vector: await ctx.runQuery(internal.edgeSetupRuns.localVector, { relayId: a.relayId }),
      hostsObservation: {
        listingHash: `h${listingVersion}`,
        observedAt: Date.now(),
        version: listingVersion,
      },
      listingChanged: false,
      attempts: 1,
      cohorts: 1,
      source: 'members' as const,
      formats: ['links' as const],
    }),
    vectorNow: (ctx, relayId) => ctx.runQuery(internal.edgeSetupRuns.localVector, { relayId }),
    restoreStart: async (_ctx, a) => {
      calls.restore.push(a.purpose);
    },
  };
  __setStageOpsForTests(ops);
  return {
    t,
    world,
    serverId,
    accountId,
    calls,
    setHideResult: (r: typeof hideResult) => {
      hideResult = r;
    },
    setHideStatus: (s: typeof hideStatus) => {
      hideStatus = s;
    },
    bumpListing: () => {
      listingVersion++;
    },
    setRehearsalHold: (on: boolean) => {
      rehearsalHold = on;
    },
  };
}

/** The probe round "lands": two outside vantages reachable + a passing internal tls-sni / tcp shape run. */
async function landPartialEvidence(t: T, edgeId: Id<'edges'>) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const listener = (await ctx.db.get(edge.listenerId))!;
    const now = Date.now();
    for (const country of ['DE', 'FR']) {
      await ctx.db.insert('probeReachability', {
        targetKind: 'edge',
        targetRef: edgeId as string,
        country,
        source: 'globalping',
        ipVersion: 4,
        addressKind: 'ip',
        probeProtocol: 'tcp',
        port: listener.originPort,
        okCount: 1,
        failCount: 0,
        lastOkAt: now,
        verdict: 'reachable',
        updatedAt: now,
      });
    }
    await ctx.db.insert('probeRuns', {
      targetKind: 'edge',
      targetRef: edgeId as string,
      source: 'internal',
      target: `${edge.addresses.v4}:${listener.originPort}`,
      port: listener.originPort,
      ipVersion: 4,
      addressKind: 'ip',
      probeProtocol: listener.security === 'none' ? 'tcp' : 'tls-sni',
      requestedFamily: 4,
      status: 'finished',
      trigger: 'qualification',
      requestedAt: now,
      finishedAt: now,
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: true }],
    });
  });
}

async function planFor(t: T, serverId: Id<'backendServers'>) {
  return t.action(internal.edgeSetupPlan.plan, { backendServerId: serverId, nodeUuid: NODE_UUID });
}

async function startRun(
  t: T,
  serverId: Id<'backendServers'>,
  accountId: Id<'edgeProviderAccounts'>,
  opts: { approvedHideUuids?: string[]; keepDirect?: boolean } = {},
) {
  const plan = await planFor(t, serverId);
  const res = await t.action(internal.edgeSetupPlan.create, {
    backendServerId: serverId,
    nodeUuid: NODE_UUID,
    accountId,
    planHash: plan.planHash,
    approvedHideUuids: opts.approvedHideUuids ?? [],
    ...(opts.keepDirect ? { keepDirect: true } : {}),
  });
  return { runId: res.runId as Id<'edgeSetupRuns'>, plan };
}

const run = (t: T, id: Id<'edgeSetupRuns'>) =>
  t.query(internal.edgeSetupRuns.get, { id }).then((r) => r!);

/** Drive every scheduled function (run steps, rotation steps) until `until` holds or nothing moves. */
async function pump(
  t: T,
  runId: Id<'edgeSetupRuns'>,
  until: (r: Awaited<ReturnType<typeof run>>) => boolean,
) {
  for (let i = 0; i < 600; i++) {
    const r = await run(t, runId);
    if (until(r)) return r;
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
  }
  const r = await run(t, runId);
  throw new Error(
    `pump: stuck at ${r.stage}/${r.state} ${r.need?.code ?? ''} ${r.need?.detail ?? ''}`,
  );
}

/** Fine-grained driving: one millisecond per iteration, so a transient stage / expect is observable. */
async function pumpFine(
  t: T,
  runId: Id<'edgeSetupRuns'>,
  until: (r: Awaited<ReturnType<typeof run>>) => boolean,
) {
  for (let i = 0; i < 5000; i++) {
    const r = await run(t, runId);
    if (until(r)) return r;
    await vi.advanceTimersByTimeAsync(1);
    await t.finishInProgressScheduledFunctions();
  }
  const r = await run(t, runId);
  throw new Error(`pumpFine: stuck at ${r.stage}/${r.state} ${r.need?.code ?? ''}`);
}

const settled = (r: { state: string }) =>
  r.state === 'needs_you' || ['done', 'done_unbound', 'failed', 'cancelled'].includes(r.state);

/** Tick every pending test link exactly as the card would. */
async function tickAll(t: T, runId: Id<'edgeSetupRuns'>) {
  const r = await run(t, runId);
  return t.mutation(internal.edgeSetupRuns.resume, {
    runId,
    confirmations: (r.testLinks ?? []).map((l) => ({
      edgeId: l.edgeId,
      endpoint: l.binding.endpoint,
      listenerRevision: l.binding.listenerRevision,
      configHash: l.binding.configHash,
    })),
  });
}

async function bindingFor(t: T, serverId: Id<'backendServers'>) {
  return t.query(internal.relays.deliveryBinding, {
    backendServerId: serverId,
    nodeName: 'node-one',
  });
}

async function relayOf(t: T, runId: Id<'edgeSetupRuns'>) {
  const r = await run(t, runId);
  return (await t.run((ctx) => ctx.db.get(r.relayId!)))!;
}

async function audits(t: T, action: string) {
  return t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter((a) => a.action === action),
  );
}

describe('edgeSetupPlan', () => {
  test('a backend call that throws names the step instead of an anonymous failure; a coded refusal passes through', async () => {
    const { t, serverId } = await seed();
    __setPlanOpsForTests({
      listNodeInbounds: async () => {
        throw new TypeError('secret-bearing text 203.0.113.9');
      },
    });
    const err = await planFor(t, serverId).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ConvexError);
    const data = (err as ConvexError<{ code: string; message: string }>).data;
    expect(data.code).toBe('edge.plan_step_failed');
    expect(data.message).toContain("reading the node's transports");
    expect(data.message).toContain('TypeError');
    expect(data.message).not.toContain('203.0.113.9');
    __setPlanOpsForTests({
      listNodeInbounds: async () => [inboundA],
      listHosts: async () => {
        throw new ConvexError({ code: 'backend.panel_read_failed', message: 'x' });
      },
    });
    await expect(planFor(t, serverId)).rejects.toMatchObject({
      data: { code: 'backend.panel_read_failed' },
    });
  });

  test('the plan lists frontable transports, classifies the direct Hosts, judges accounts, and hashes what the run must echo', async () => {
    const { t, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS, inboundV],
      hosts: [directHostA(), directHostS(), directHostV()],
    });
    const plan = await planFor(t, serverId);
    expect(plan.nodeName).toBe('node-one');
    expect(plan.relaySlug).toBe(slugForNode('node-one'));
    expect(plan.requiredListeners).toHaveLength(2);
    const vmess = plan.inbounds.find((i) => i.sourceTag === 'VMESS_IN')!;
    expect(vmess.frontable).toBe(false);
    expect(vmess.reason).toBe('protocol');
    // The REALITY and SS transports are covered in every format; the vmess Host is uncovered.
    expect(plan.directHosts.map((h) => [h.uuid, h.covered])).toEqual(
      expect.arrayContaining([
        [HOST_A, true],
        [HOST_S, true],
        [HOST_V, false],
      ]),
    );
    expect(plan.accounts).toEqual([
      expect.objectContaining({ id: accountId, layer: 'l4', compatible: true, reasons: [] }),
    ]);
    expect(plan.renderGlobal.willEnable).toBe(true);
    expect(plan.emptyNode).toBe(true);
    expect(plan.planHash).toMatch(/^[0-9a-f]{64}$/);
    // The hash covers the direct-Host identities: another Host = another hash.
    __setPlanOpsForTests({
      listNodeInbounds: async () => [inboundA, inboundS, inboundV],
      listHosts: async () =>
        [directHostA(), directHostS()].map((h) => ({ ...h, isDisabled: false })),
    });
    const again = await planFor(t, serverId);
    expect(again.planHash).not.toBe(plan.planHash);
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId,
        planHash: plan.planHash,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/plan_stale/);
    // An untested account is offered with its reason, never compatible.
    const untested = await createAccount(t, { provider: 'upcloud', name: 'acct-x' });
    const p3 = await planFor(t, serverId);
    expect(p3.accounts.find((a) => a.id === untested)).toMatchObject({
      compatible: false,
      reasons: ['account_untested'],
    });
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId: untested,
        planHash: p3.planHash,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/account_incompatible/);
    // Consent must name a Host the plan showed as uncovered.
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId,
        planHash: p3.planHash,
        approvedHideUuids: [HOST_A],
      }),
    ).rejects.toThrow(/validation/);
  });
});

describe('edgeSetupRuns: the happy path (cases 1, 26)', () => {
  test('one listener: standby first, partial from outside, try_it before anything is published, publish, hide, rehearse, go live', async () => {
    const { t, world, serverId, accountId, calls } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    // Stage 4b: the run stops at the try_it card with ONE test link; nothing published, no binding.
    let r = await pump(t, runId, settled);
    expect(r.stage).toBe('try_it');
    expect(r.state).toBe('needs_you');
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(1);
    expect(r.listeners[0].verify).toBe('partial');
    expect(calls.probes).toHaveLength(1);
    const relay = await relayOf(t, runId);
    expect(relay.setupOwned).toBe(true);
    expect(relay.bindingDeferred).toBe(true);
    expect(relay.autoRotate).toBe(true);
    expect(relay.publishedEdgeIds.filter(Boolean)).toHaveLength(0);
    expect(await bindingFor(t, serverId)).toBeNull();
    // The standby is unpublished and NOT verified: the gate would refuse it.
    const edge = (await t.run((ctx) => ctx.db.get(r.listeners[0].edgeId!)))!;
    expect(edge.publication).toBe('unpublished');
    expect(edge.verification).toBeUndefined();
    expect(world.creates()).toBe(0);
    // Without the tick, nothing moves (a retry re-enters the card).
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.generation).toBe(2);
    // "One of them does not work": the untested candidate is cancelled and a
    // fresh one provisioned; the run comes back to the card with a NEW edge.
    const firstEdgeId = r.listeners[0]!.edgeId;
    await t.mutation(internal.edgeSetupRuns.retry, { runId, tryAnotherAddress: true });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]!.edgeId).not.toBe(firstEdgeId);
    expect(world.lbCreates()).toBe(2);
    expect((await t.run((ctx) => ctx.db.get(firstEdgeId!)))!.status).toBe('cancelled');
    // The tick: the confirmation is forwarded to edgeVerification.confirm (account trust follows).
    const res = await tickAll(t, runId);
    expect(res.accountTrusted).toBe(true);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
    expect(r.stage).toBe('done');
    expect(r.listeners[0]).toMatchObject({ verify: 'verified', published: true });
    // Publish created the FCP Host; the hide op ran once with no uncovered consent.
    expect(world.creates()).toBe(1);
    expect(calls.hide).toEqual([{ approvedUuids: [] }]);
    // Go-live: binding claimed, ownership cleared, rendering on and audited.
    const after = await relayOf(t, runId);
    expect(after.setupOwned).toBeUndefined();
    expect(after.bindingDeferred).toBeUndefined();
    expect(after.publishedEdgeIds.filter(Boolean)).toHaveLength(1);
    expect((await bindingFor(t, serverId))?.state).toBe('active');
    const cfg = await t.run((ctx) =>
      import('./lib/edgeConfig').then((m) => m.resolveEdgeConfig(ctx.db)),
    );
    expect(cfg.render.enabled).toBe(true);
    expect(await audits(t, 'edge.render.enabled_by_setup')).toHaveLength(1);
    expect(await audits(t, 'edge.setup_run.go_live')).toHaveLength(1);
    const finished = await audits(t, 'edge.setup_run.finished');
    expect(finished.at(-1)?.payload).toMatchObject({ outcome: 'live' });
    // The rotation rows carry the run + generation they were started under.
    const rots = await t.run((ctx) => ctx.db.query('edgeRotations').collect());
    // Two provisions: the first candidate was replaced from the card ("one of them does not work").
    expect(rots.map((x) => x.kind).sort()).toEqual(['provision', 'provision', 'publish']);
    expect(rots.every((x) => x.setupRun?.runId === runId)).toBe(true);
    // After go-live there is no cancel.
    await expect(t.action(internal.edgeSetupRuns.cancel, { runId })).rejects.toThrow(
      /setup_run_finished/,
    );
  });
});

describe('edgeSetupRuns: two listeners (cases 2, 20)', () => {
  test('two L4 listeners need two ticks; one tick keeps the card; both covered before any hide; each publishes its own edge', async () => {
    const { t, world, serverId, accountId, calls } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(2);
    expect(new Set(r.listeners.map((l) => l.edgeId)).size).toBe(2);
    // One tick (the Shadowsocks endpoint): still the card, with one link left.
    const first = r.testLinks!.find((l) => l.listenerKey.startsWith('ssin'))!;
    await t.mutation(internal.edgeSetupRuns.resume, {
      runId,
      confirmations: [
        {
          edgeId: first.edgeId,
          endpoint: first.binding.endpoint,
          listenerRevision: first.binding.listenerRevision,
          configHash: first.binding.configHash,
        },
      ],
    });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(1);
    expect(r.testLinks![0].edgeId).not.toBe(first.edgeId);
    expect(world.creates()).toBe(0);
    // A stale tick (the REALITY listener changed while the operator was testing:
    // a new server name bumps its revision) is refused; the card is rebuilt.
    const stale = r.testLinks![0];
    await t.mutation(internal.relayListeners.upsert, {
      relayId: r.relayId!,
      spec: {
        listenerKey: stale.listenerKey,
        protocol: 'vless',
        streamTransport: 'raw',
        security: 'reality',
        originPort: 443,
        tlsNames: ['a.example', 'b.example'],
        realityTarget: { address: 'target.example', port: 443 },
        panelBinding: {
          inboundTag: 'VLESS_RELAY_A',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: FIXTURE_INBOUND,
        },
      },
    });
    await expect(
      t.mutation(internal.edgeSetupRuns.resume, {
        runId,
        confirmations: [
          {
            edgeId: stale.edgeId,
            endpoint: stale.binding.endpoint,
            listenerRevision: stale.binding.listenerRevision,
            configHash: stale.binding.configHash,
          },
        ],
      }),
    ).rejects.toThrow(/verification_stale/);
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.testLinks![0].binding.listenerRevision).toBeGreaterThan(
      stale.binding.listenerRevision,
    );
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
    expect(r.listeners.every((l) => l.published)).toBe(true);
    // Both Hosts created before the single hide; each listener's template edge is its own.
    expect(world.creates()).toBe(2);
    expect(calls.hide).toHaveLength(1);
    const listeners = await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', r.relayId!))
        .collect(),
    );
    for (const l of listeners) {
      const entry = r.listeners.find((x) => x.listenerKey === l.listenerKey)!;
      expect(l.templateEdgeId).toBe(entry.edgeId);
    }
  });
});

describe('edgeSetupRuns: unsupported transport with active users (case 3)', () => {
  test('without consent the run finishes unbound; with consent the approved uuid is hidden; a Host added after review interrupts', async () => {
    const { t, serverId, accountId, calls, setHideResult } = await seed({
      inbounds: [inboundA, inboundV],
      hosts: [directHostA(), directHostV()],
    });
    // Keep those members on the direct address: publish, then done_unbound.
    const { runId } = await startRun(t, serverId, accountId, { keepDirect: true });
    let r = await pump(t, runId, settled);
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done_unbound');
    expect(calls.hide).toHaveLength(0);
    expect(await bindingFor(t, serverId)).toBeNull();
    const relay = await relayOf(t, runId);
    expect(relay.setupOwned).toBe(true);
    expect(relay.bindingDeferred).toBe(true);
    expect(relay.publishedEdgeIds.filter(Boolean)).toHaveLength(1);
    // The attention list offers go-live for it (the A1 rule), and nothing auto-binds.
    const att = await t.query(internal.edgeOperator.attention, {});
    expect(att.items.some((i) => i.kind === 'go_live_pending' && i.relaySlug === relay.slug)).toBe(
      true,
    );
    // A second run on the same origin reuses the owned origin at its recorded stage, with consent by uuid.
    const { runId: run2 } = await startRun(t, serverId, accountId, { approvedHideUuids: [HOST_V] });
    const r2start = await run(t, run2);
    expect(r2start.relayId).toBe(relay._id);
    // The consent re-check at stage 6: hides report a Host the consent did not name.
    setHideResult({
      reviewChanged: [{ uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9', remark: 'direct-new' }],
    });
    let r2 = await pump(t, run2, settled);
    expect(r2.need?.code).toBe('review_changed');
    expect(r2.reviewDelta).toEqual([
      { uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9', remark: 'direct-new' },
    ]);
    expect(calls.hide.at(-1)).toEqual({ approvedUuids: [HOST_V] });
    // The new consent replaces the old EXACTLY (revision bump) and stage 6 runs
    // again: the operator re-submits every Host they still approve.
    setHideResult({});
    await t.mutation(internal.edgeSetupRuns.resume, {
      runId: run2,
      approvedHideUuids: [HOST_V, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9'],
    });
    r2 = await pump(t, run2, settled);
    expect(r2.state).toBe('done');
    expect(r2.planRevision).toBe(2);
    expect(calls.hide.at(-1)?.approvedUuids.sort()).toEqual(
      [HOST_V, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9'].sort(),
    );
    expect((await bindingFor(t, serverId))?.state).toBe('active');
  });
});

describe('edgeSetupRuns: fencing (case 6)', () => {
  test('rotation start + expect land atomically; duplicate and stale terminal callbacks are no-ops; retry bumps the generation', async () => {
    const { t, serverId, accountId } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    // Drive until the provision rotation is expected.
    let r = await pumpFine(t, runId, (x) => !!x.expect);
    const relay = await relayOf(t, runId);
    expect(relay.activeRotationId).toBe(r.expect!.rotationId);
    expect(r.state).toBe('waiting');
    expect(r.expect!.generation).toBe(1);
    const rot = (await t.run((ctx) => ctx.db.get(r.expect!.rotationId)))!;
    expect(rot.setupRun).toEqual({ runId, generation: 1 });
    // A hook for a rotation the run does not expect: no-op.
    const fake = await t.mutation(internal.edgeSetupRuns.onRotationTerminal, {
      runId,
      rotationId: rot._id,
      generation: 99,
    });
    expect(fake).toMatchObject({ acted: false, reason: 'not_expected' });
    // A hook before the rotation is terminal: no-op.
    const early = await t.mutation(internal.edgeSetupRuns.onRotationTerminal, {
      runId,
      rotationId: rot._id,
      generation: 1,
    });
    expect(early).toMatchObject({ acted: false, reason: 'not_terminal' });
    // Let it finish: the real hook acts once, a duplicate does nothing.
    r = await pumpFine(t, runId, (x) => !x.expect);
    const dup = await t.mutation(internal.edgeSetupRuns.onRotationTerminal, {
      runId,
      rotationId: rot._id,
      generation: 1,
    });
    expect(dup.acted).toBe(false);
    const finished = (await t.run((ctx) => ctx.db.get(rot._id)))!;
    expect(finished.phase).toBe('done');
    expect(r.listeners[0].edgeId).toBe(finished.toEdgeId);
    // Reach the card, retry (generation 2): the old rotation's callback is ignored.
    r = await pump(t, runId, settled);
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    const stale = await t.mutation(internal.edgeSetupRuns.onRotationTerminal, {
      runId,
      rotationId: rot._id,
      generation: 1,
    });
    expect(stale.acted).toBe(false);
    r = await run(t, runId);
    expect(r.generation).toBe(2);
    // The reconcile pass re-fires a missed hook and re-kicks a stale step without acting twice.
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
  });
});

describe('edgeSetupRuns: provider failure (case 9)', () => {
  test('a failed provision stops the run at provision; the origin stays owned and unbound; retry reuses the other listener’s standby', async () => {
    const { t, world, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
      failCreateAt: 2,
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.state).toBe('failed');
    expect(r.stage).toBe('provision');
    expect(r.need?.code).toBe('provider_failed');
    const relay = await relayOf(t, runId);
    expect(relay.setupOwned).toBe(true);
    expect(relay.setupStage).toBe('provision');
    expect(await bindingFor(t, serverId)).toBeNull();
    // One standby exists; the failed one is marked for the reconcile destroy.
    const edges = await t.run((ctx) =>
      ctx.db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id))
        .collect(),
    );
    expect(edges.map((e) => e.status).sort()).toEqual(['active', 'failed']);
    expect(world.lbCreates()).toBe(2);
    // Reconcile leaves an owned origin alone (no upkeep starts), whatever the run's state.
    await t.mutation(internal.edgeAdmin.setAutomation, { on: true });
    const report = await t.action(internal.edgeReconcile.run, {});
    expect(report.started).toBe(0);
    expect(report.published).toBe(0);
    // Retry: the first listener's standby is reused, only the second is provisioned.
    const before = world.lbCreates();
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(world.lbCreates()).toBe(before + 1);
    expect(new Set(r.listeners.map((l) => l.edgeId)).size).toBe(2);
    const failedAudit = await audits(t, 'edge.setup_run.finished');
    expect(failedAudit[0]?.payload).toMatchObject({ outcome: 'failed', stage: 'provision' });
  });
});

describe('edgeSetupRuns: coverage (case 10)', () => {
  test('a pool with no room for the second listener interrupts with coverage_incomplete', async () => {
    const { t, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    // Shrink the pool under the run: one slot for two listeners.
    await t.run((ctx) => ctx.db.patch(r.relayId!, { desiredPublished: 1 }));
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect(r.stage).toBe('publish');
    expect(r.need?.code).toBe('coverage_incomplete');
    expect(r.listeners.filter((l) => l.published)).toHaveLength(1);
    expect(await bindingFor(t, serverId)).toBeNull();
    // Room again: retry re-enters publish, the second edge lands, the run goes live.
    await t.run((ctx) => ctx.db.patch(r.relayId!, { desiredPublished: 2 }));
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
  });
});

describe('edgeSetupRuns: require-edges and no shortcut (case 11)', () => {
  test('refuses on each unmet condition, returns pending untested L4 endpoints instead of binding, then binds through stages 7-8', async () => {
    const { t, serverId, accountId } = await seed();
    // A deferred origin set up by hand: registered as a guided origin, an edge published by the operator.
    const { id: relayId } = await t.mutation(internal.relays.create, {
      slug: 'node-one',
      origin: {
        kind: 'panel-node',
        backendServerId: serverId,
        nodeName: 'node-one',
        nodeUuid: NODE_UUID,
      },
      originAddress: ORIGIN,
      listeners: [
        {
          listenerKey: 'a',
          protocol: 'vless',
          streamTransport: 'raw',
          security: 'reality',
          originPort: 443,
          tlsNames: ['a.example'],
          realityTarget: { address: 'target.example', port: 443 },
          panelBinding: {
            inboundTag: 'VLESS_RELAY_A',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: FIXTURE_INBOUND,
          },
        },
      ],
      deferBinding: true,
      setupOwned: true,
    });
    const listenerId = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .first(),
    ))!._id;
    // Uncovered: nothing published yet.
    await expect(
      t.mutation(internal.edgeSetupRuns.requireEdges, { relayId, accountId }),
    ).rejects.toThrow(/coverage_incomplete/);
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: true, accountId });
    // Publishing on a deferred origin never bound it (no shortcut).
    expect(await bindingFor(t, serverId)).toBeNull();
    // A listener change makes the confirmation stale: require-edges answers the pending endpoint, binds nothing.
    await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: {
        listenerKey: 'a',
        protocol: 'vless',
        streamTransport: 'raw',
        security: 'reality',
        originPort: 443,
        tlsNames: ['a.example', 'b.example'],
        realityTarget: { address: 'target.example', port: 443 },
        panelBinding: {
          inboundTag: 'VLESS_RELAY_A',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: FIXTURE_INBOUND,
        },
      },
    });
    const res = await t.mutation(internal.edgeSetupRuns.requireEdges, { relayId, accountId });
    expect(res.state).toBe('needs_you');
    expect(res.stage).toBe('try_it');
    expect(res.pending).toHaveLength(1);
    expect(res.pending[0]).toMatchObject({ edgeId, listenerKey: 'a' });
    expect(await bindingFor(t, serverId)).toBeNull();
    // A second activation while the run owns the node is refused.
    await expect(
      t.mutation(internal.edgeSetupRuns.requireEdges, { relayId, accountId }),
    ).rejects.toThrow(/setup_run_active/);
    // The tick, then stages 7-8 verbatim.
    await tickAll(t, res.runId);
    const r = await pump(t, res.runId, settled);
    expect(r.state).toBe('done');
    expect((await bindingFor(t, serverId))?.state).toBe('active');
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(relay.setupOwned).toBeUndefined();
    // Not deferred any more: refused.
    await expect(
      t.mutation(internal.edgeSetupRuns.requireEdges, { relayId, accountId }),
    ).rejects.toThrow(/not_deferred/);
  });

  test('the detector veto and the reconcile skip hold for an owned origin after a failed run (a registered origin binds at once)', async () => {
    const { t } = await seed();
    const { relayId } = await registerRelay(t, { slug: 'node-two', nodeName: 'node-two' });
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(relay.bindingDeferred).toBeUndefined();
    expect(relay.setupOwned).toBeUndefined();
    await expect(t.mutation(internal.edgeSetupRuns.requireEdges, { relayId })).rejects.toThrow(
      /not_deferred/,
    );
  });
});

describe('edgeSetupRuns: rehearsal and the observation boundary (cases 12, 21)', () => {
  test(
    'a disabled family interrupts; a stale observation, a drifted vector and an unsettled hide each send the run back',
    { timeout: 30_000 },
    async () => {
      const { t, serverId, accountId, setHideStatus, setRehearsalHold } = await seed();
      await t.mutation(internal.edgeAdmin.patchConfig, {
        patch: { render: { clients: { mihomo: { enabled: false } } } },
      });
      const { runId } = await startRun(t, serverId, accountId);
      let r = await pump(t, runId, settled);
      await tickAll(t, runId);
      r = await pump(t, runId, settled);
      expect(r.stage).toBe('rehearse');
      expect(r.need?.code).toBe('family_disabled');
      expect(r.need?.detail).toBe('mihomo');
      await t.mutation(internal.edgeAdmin.patchConfig, {
        patch: { render: { clients: { mihomo: { enabled: true } } } },
      });
      // Hold the run at stage 7 (the rehearsal reports no serve) so the go-live
      // checks can be exercised by hand against a rehearsal record built from
      // the live rows: the scheduled step is fenced out by the arm's version bump.
      setRehearsalHold(true);
      await t.mutation(internal.edgeSetupRuns.retry, { runId });
      r = await pump(t, runId, settled);
      expect(r.stage).toBe('rehearse');
      expect(r.need?.code).toBe('rehearsal_failed');
      const arm = async (observedAt: number) => {
        const cur = await run(t, runId);
        const vector = await t.query(internal.edgeSetupRuns.localVector, { relayId: cur.relayId! });
        await t.run((ctx) =>
          ctx.db.patch(runId, {
            stage: 'go_live',
            state: 'running',
            need: undefined,
            stepVersion: cur.stepVersion + 1,
            rehearsal: {
              at: observedAt,
              attempts: 1,
              vector,
              hostsObservation: { at: observedAt, version: 1, hash: 'h' },
              darkCohortKeys: [],
            },
          }),
        );
        return run(t, runId);
      };
      // 1. An unsettled hide row: back to stage 6.
      setHideStatus({ outstanding: 1 });
      r = await arm(Date.now());
      let res = await t.mutation(internal.edgeSetupRuns.goLive, {
        runId,
        stepVersion: r.stepVersion,
      });
      expect(res).toMatchObject({ ok: false, code: 'hides_unsettled' });
      expect((await run(t, runId)).stage).toBe('hide_direct_hosts');
      setHideStatus({});
      // 2. A Host observation older than 60 s at stage 8: back to 7 (the rehearsal repeats).
      r = await arm(Date.now() - MAX_OBSERVATION_AGE_MS - 1_000);
      res = await t.mutation(internal.edgeSetupRuns.goLive, { runId, stepVersion: r.stepVersion });
      expect(res).toMatchObject({ ok: false, code: 'observation_stale' });
      expect((await run(t, runId)).stage).toBe('rehearse');
      // 3. Vector drift between 7 and 8 (a listener revision bump): back to 7.
      r = await arm(Date.now());
      const before = r.rehearsal!.vector;
      await t.mutation(internal.relayListeners.upsert, {
        relayId: r.relayId!,
        spec: {
          listenerKey: r.listeners[0].listenerKey,
          protocol: 'vless',
          streamTransport: 'raw',
          security: 'reality',
          originPort: 443,
          tlsNames: ['a.example', 'c.example'],
          realityTarget: { address: 'target.example', port: 443 },
          panelBinding: {
            inboundTag: 'VLESS_RELAY_A',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: FIXTURE_INBOUND,
          },
        },
      });
      const nowVector = await t.query(internal.edgeSetupRuns.localVector, { relayId: r.relayId! });
      expect(vectorsEqual(before, nowVector)).toBe(false);
      res = await t.mutation(internal.edgeSetupRuns.goLive, { runId, stepVersion: r.stepVersion });
      expect(res).toMatchObject({ ok: false, code: 'vector_drift' });
      expect((await run(t, runId)).stage).toBe('rehearse');
      // The revision bump also made the L4 confirmation stale: the run asks for the tick again, then goes live.
      setRehearsalHold(false);
      r = await pump(t, runId, settled);
      expect(r.need?.code).toBe('try_it');
      await tickAll(t, runId);
      r = await pump(t, runId, settled);
      expect(r.state).toBe('done');
      expect((await bindingFor(t, serverId))?.state).toBe('active');
    },
  );
});

describe('edgeSetupRuns: cancel', () => {
  test('before publish the origin is deleted restore-direct; between publish and go-live the restore workflow runs and the origin stays owned', async () => {
    const { t, serverId, accountId, calls } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    const relayId = r.relayId!;
    const c1 = await t.action(internal.edgeSetupRuns.cancel, { runId });
    expect(c1.disposition).toBe('deleted');
    expect((await run(t, runId)).state).toBe('cancelled');
    expect((await t.run((ctx) => ctx.db.get(relayId)))?.deleting).toBe(true);
    expect(await bindingFor(t, serverId)).toBeNull();
    // Finish the delete so the origin is free again, then a run that cancels after publication.
    await t.run(async (ctx) => {
      for (const e of await ctx.db.query('edges').collect())
        await ctx.db.patch(e._id, { status: 'destroyed', publication: 'unpublished' });
    });
    await t.mutation(internal.relays.finalizeDelete, { id: relayId });
    // Reuse a fresh fake world state: the old direct Host is still there.
    const { runId: run2 } = await startRun(t, serverId, accountId);
    r = await pump(t, run2, settled);
    await t.run((ctx) => ctx.db.patch(r.relayId!, { desiredPublished: 1 }));
    await tickAll(t, run2);
    // Stop at stage 7 by making the family rule refuse, then cancel there.
    await t.mutation(internal.edgeAdmin.patchConfig, {
      patch: { render: { clients: { mihomo: { enabled: false } } } },
    });
    r = await pump(t, run2, settled);
    expect(r.stage).toBe('rehearse');
    const c2 = await t.action(internal.edgeSetupRuns.cancel, { runId: run2 });
    expect(c2.disposition).toBe('restore');
    expect(calls.restore).toEqual(['cancel_setup']);
    const relay = (await t.run((ctx) => ctx.db.get(r.relayId!)))!;
    expect(relay.setupOwned).toBe(true);
    expect(relay.bindingDeferred).toBe(true);
    expect(relay.deleting).toBeUndefined();
    expect(relay.publishedEdgeIds.filter(Boolean)).toHaveLength(1);
    expect(await audits(t, 'edge.setup_run.cancelled')).toHaveLength(2);
  });
});

describe('edgeSetupRuns: maintenance', () => {
  test('a freeze blocks stage 1 and 3 but a run past try_it finishes its publish under setup.complete', async () => {
    const { t, serverId, accountId } = await seed();
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.stage).toBe('prepare');
    expect(r.need?.code).toBe('maintenance');
    await t.mutation(internal.edgeMaintenance.thaw, {});
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    // Frozen again while the operator was testing: the publish (stage 5) is
    // completion of admitted work and passes; a plain start would not.
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'drain' });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId: r.relayId!,
        kind: 'provision',
        trigger: 'manual',
      }),
    ).rejects.toThrow(/maintenance/);
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
  });
});

describe('approvedDarkCohorts (case 3, the rehearsal side)', () => {
  const run = (approved: string[], dark: string[] = []) => ({
    approvedHideUuids: approved,
    rehearsal: dark.length
      ? {
          at: 0,
          attempts: 1,
          vector: {
            listenerRevisions: {},
            renderConfigHash: '',
            publicationEpoch: 0,
            qualificationEvidenceIds: [],
          },
          hostsObservation: { at: 0, version: 0, hash: '' },
          darkCohortKeys: dark,
        }
      : undefined,
  });
  const f = (cohortKey: string, reason: string) => ({
    cohortKey,
    format: 'links' as const,
    reason,
  });

  test('a consented cohort whose every body is empty is dark; nothing is dark without consent', () => {
    const failures = [f('squad-b', 'empty_body'), f('squad-b', 'no_match')];
    expect(approvedDarkCohorts({ failures, formats: ['links'] }, run(['host-1']))).toEqual([
      'squad-b',
    ]);
    expect(approvedDarkCohorts({ failures, formats: ['links'] }, run([]))).toEqual([]);
  });

  test('a genuine failure anywhere keeps the run at rehearsal_failed', () => {
    const failures = [f('squad-b', 'empty_body'), f('squad-a', 'leak_detected')];
    expect(approvedDarkCohorts({ failures, formats: ['links'] }, run(['host-1']))).toEqual([]);
    expect(
      approvedDarkCohorts(
        { failures: [f('credential', 'empty_body')], formats: ['links'] },
        run(['h']),
      ),
    ).toEqual([]);
  });

  test('a cohort is dark only when EVERY rehearsed format failed dark', () => {
    // links empty, but sing-box still renders: a real failure, not a dark cohort.
    const failures = [{ cohortKey: 'squad-b', format: 'links' as const, reason: 'empty_body' }];
    expect(
      approvedDarkCohorts({ failures, formats: ['links', 'singbox'] }, run(['host-1'])),
    ).toEqual([]);
    const both = [
      ...failures,
      { cohortKey: 'squad-b', format: 'singbox' as const, reason: 'no_match' },
    ];
    expect(
      approvedDarkCohorts({ failures: both, formats: ['links', 'singbox'] }, run(['host-1'])),
    ).toEqual(['squad-b']);
  });

  test('a cohort already recorded dark is not reported twice', () => {
    const failures = [f('squad-b', 'empty_body')];
    expect(
      approvedDarkCohorts({ failures, formats: ['links'] }, run(['host-1'], ['squad-b'])),
    ).toEqual([]);
  });
});
