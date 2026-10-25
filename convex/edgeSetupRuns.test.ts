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
import { fakeEdgeWorld, type BackendAddress } from './lib/edges/testing/fakeEdgeWorld';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  registerRelay,
  setFrontsTraffic,
} from './lib/edges/testing/fixtures';
import {
  __setStageOpsForTests,
  approvedDarkCohorts,
  mapRunAdmin,
  type StageOps,
} from './edgeSetupRuns';
import type { RealityClientRefusal } from '../src/shared/contracts/realityClients';
import { __setPlanOpsForTests } from './edgeSetupPlan';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import type { BackendTransport } from './lib/backends/types';
import { MAX_OBSERVATION_AGE_MS, slugForNode, vectorsEqual } from './lib/edges/setupRuns';
import { signValue } from './lib/cookies';
import {
  SetupPlanResponse,
  SetupRunAdmin,
  type SetupRunCreateRequest,
  type SetupRunRetryRequest,
} from '../src/shared/contracts/edges';
import { defaultLocationRow, deliveryBindingOf } from './lib/edges/testing/reads';
import { effectiveTemplateOfLocation } from './edgeLocations';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
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

const inboundA: BackendTransport = {
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
const inboundS: BackendTransport = {
  tag: 'SS_IN',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: SS_INBOUND,
  protocol: 'shadowsocks',
  port: 8388,
  network: 'tcp',
  security: 'none',
  active: true,
};
const inboundV: BackendTransport = {
  tag: 'VMESS_IN',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: VMESS_INBOUND,
  protocol: 'vmess',
  port: 8443,
  network: 'tcp',
  security: 'tls',
  active: true,
};
const directHostA = (): BackendAddress => ({
  uuid: HOST_A,
  remark: 'direct-a',
  address: ORIGIN,
  port: 443,
  sni: 'a.example',
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: FIXTURE_INBOUND },
});
const directHostS = (): BackendAddress => ({
  uuid: HOST_S,
  remark: 'direct-s',
  address: ORIGIN,
  port: 8388,
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: SS_INBOUND },
});
const directHostV = (): BackendAddress => ({
  uuid: HOST_V,
  remark: 'direct-v',
  address: ORIGIN,
  port: 8443,
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: VMESS_INBOUND },
});

function fakeWorld(opts: { hosts?: BackendAddress[]; failCreateAt?: number } = {}) {
  return fakeEdgeWorld({ hosts: opts.hosts ?? [directHostA()], failCreateAt: opts.failCreateAt });
}

/** Backend + a TESTED but unqualified UpCloud account + the node in the inventory. */
async function seed(
  opts: {
    inbounds?: BackendTransport[];
    hosts?: BackendAddress[];
    failCreateAt?: number;
    /** Lands a per-country round with the verification probes (the nth request, from 1). */
    countryRound?: (t: T, edgeId: Id<'edges'>, nth: number) => Promise<void>;
    /** What the nth verification round finds (default: the address is partial). */
    evidence?: (nth: number) => Evidence;
    /** What saving an address again answers (default: its provider has nothing to save). */
    reapply?: StageOps['reapplyEdge'];
    /** Thrown by the test-link builder instead of a link while it returns one. */
    testLinkError?: () => Error | null;
    /** Runs inside the restore start, before it is recorded (a race lands here). */
    onRestoreStart?: () => Promise<void>;
    /** What the run's test card reads of the REALITY transports (default: nothing known). */
    realityClients?: StageOps['realityClients'];
  } = {},
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
    reapplied: [] as string[],
  };
  let hideResult: Partial<Awaited<ReturnType<StageOps['hideHosts']>>> = {};
  let hideStatus: Partial<Awaited<ReturnType<StageOps['hideStatus']>>> = {};
  let listingVersion = 1;
  let rehearsalHold = false;
  const ops: Partial<StageOps> = {
    ensureCredential: async () => ({ ok: true, reused: false }),
    requestVerificationProbes: async (_ctx, edgeId) => {
      calls.probes.push(edgeId as string);
      const evidence = opts.evidence?.(calls.probes.length) ?? 'partial';
      if (evidence === 'partial') await landPartialEvidence(t, edgeId);
      else if (evidence === 'unreachable') await landUnreachableEvidence(t, edgeId);
      else if (evidence === 'blocked_cn') await landBlockedInEvidence(t, edgeId);
      else await landUntestedEvidence(t, edgeId, evidence);
      if (opts.countryRound) await opts.countryRound(t, edgeId, calls.probes.length);
    },
    reapplyEdge: async (ctx, edgeId) => {
      calls.reapplied.push(edgeId as string);
      return opts.reapply
        ? opts.reapply(ctx, edgeId)
        : { status: 'skipped' as const, code: 'not_offered' as const };
    },
    runFrontProof: async () => ({ ok: false, code: 'unsupported_protocol' }),
    buildTestLink: async (ctx, edgeId) => {
      const refused = opts.testLinkError?.();
      if (refused) throw refused;
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
      await opts.onRestoreStart?.();
      calls.restore.push(a.purpose);
    },
    realityClients: opts.realityClients ?? (async () => []),
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

type Evidence = 'partial' | 'unreachable' | 'blocked_cn' | 'beta_mix' | 'nothing_tested';

/**
 * A round whose sources mostly could not test (what beta saw on a working
 * dual-stack address): FCP's own shape check reached it over IPv4; its IPv6
 * run failed `no_route` (the host has no IPv6); check-host's IPv4 job timed
 * out (and it takes no IPv6 literal, so it had no IPv6 run); Globalping
 * refused both requests. `nothing_tested`: every source failed, IPv4 too.
 */
async function landUntestedEvidence(
  t: T,
  edgeId: Id<'edges'>,
  mix: Exclude<Evidence, 'partial' | 'unreachable' | 'blocked_cn'>,
) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const listener = (await ctx.db.get(edge.listenerId))!;
    const v6 = '2001:db8::5';
    if (mix === 'beta_mix' && !edge.addresses.v6)
      await ctx.db.patch(edgeId, { addresses: { ...edge.addresses, v6 } });
    const now = Date.now();
    const port = listener.originPort;
    const land = (
      source: 'internal' | 'checkhost' | 'globalping',
      family: 4 | 6,
      status: 'finished' | 'failed' | 'timeout',
      error?: string,
    ) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: edgeId as string,
        source,
        target: family === 6 ? `[${v6}]:${port}` : `${edge.addresses.v4}:${port}`,
        port,
        ipVersion: family,
        addressKind: 'ip',
        probeProtocol:
          source !== 'internal' ? 'tcp' : listener.security === 'none' ? 'tcp' : 'tls-sni',
        requestedFamily: family,
        status,
        trigger: 'qualification',
        requestedAt: now,
        finishedAt: now,
        results:
          status === 'finished' ? [{ country: 'XX', vantageClass: 'datacenter', ok: true }] : [],
        ...(error ? { error } : {}),
      });
    if (mix === 'beta_mix') {
      await land('internal', 4, 'finished');
      await land('internal', 6, 'failed', 'no_route');
      await land('globalping', 6, 'failed', 'request_refused');
    } else await land('internal', 4, 'failed', 'error');
    await land('checkhost', 4, 'timeout', 'timeout');
    await land('globalping', 4, 'failed', 'request_refused');
  });
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

/**
 * The probe round "lands" on a dead address (a load balancer resetting every
 * connection): both outside vantages unreachable, the internal shape run fails.
 */
/**
 * Born blocked in CN: every vantage there fails (sources agree), RU reaches
 * it, and FCP's own shape check passes.
 */
async function landBlockedInEvidence(t: T, edgeId: Id<'edges'>) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const listener = (await ctx.db.get(edge.listenerId))!;
    const now = Date.now();
    for (const [country, ok] of [
      ['CN', false],
      ['RU', true],
    ] as const)
      await ctx.db.insert('probeReachability', {
        targetKind: 'edge',
        targetRef: edgeId as string,
        country,
        source: 'globalping',
        ipVersion: 4,
        addressKind: 'ip',
        probeProtocol: 'tcp',
        port: listener.originPort,
        okCount: ok ? 3 : 0,
        failCount: ok ? 0 : 3,
        ...(ok ? { lastOkAt: now, lastReachableAt: now } : { lastFailAt: now }),
        failNetworks: ok ? [] : ['AS64501', 'AS64502', 'AS64503'],
        verdict: ok ? 'reachable' : 'unreachable',
        updatedAt: now,
      });
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

async function landUnreachableEvidence(t: T, edgeId: Id<'edges'>) {
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
        okCount: 0,
        failCount: 1,
        lastFailAt: now,
        verdict: 'unreachable',
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
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: false }],
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
  return deliveryBindingOf(t, {
    backendServerId: serverId,
    nodeName: 'node-one',
  });
}

async function relayOf(t: T, runId: Id<'edgeSetupRuns'>) {
  const r = await run(t, runId);
  return (await t.run((ctx) => ctx.db.get(r.relayId!)))!;
}

/** A JSON POST to the edges admin routes as a signed-in admin (cookie, unsealed). */
async function adminPost(t: T) {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
  return async (path: string, body: unknown) => {
    const res = await t.fetch(`/api/v1/admin/edges/${path}`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  };
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

  test('a DNS account is not offered as a front until Settings lets DNS accounts front', async () => {
    const { t, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
    });
    const dns = await createAccount(t, { provider: 'cloudflare', name: 'acct-dns' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, {
      id: dns,
      ok: true,
      observed: { zoneSslMode: 'full', websockets: 'on' },
    });
    const off = await planFor(t, serverId);
    expect(off.accounts.map((a) => a.id)).toEqual([accountId]);
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId: dns,
        planHash: off.planHash,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/account_incompatible/);
    await setFrontsTraffic(t, dns, true);
    const on = await planFor(t, serverId);
    expect(on.accounts.map((a) => a.id).sort()).toEqual([accountId, dns].sort());
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

  test('a node with more transports than a run takes: the plan lists them all, the run protects the ones the operator names', async () => {
    // Nine Shadowsocks transports: one more than a run protects.
    const many: BackendTransport[] = Array.from({ length: 9 }, (_, i) => ({
      ...inboundS,
      tag: `SS_${i + 1}`,
      configProfileInboundUuid: `44444444-4444-4444-8444-44444444440${i + 1}`,
      port: 8001 + i,
    }));
    // Members of the two the operator names dial the node directly (what their
    // test links are built from).
    const { t, serverId, accountId } = await seed({
      inbounds: many,
      hosts: [4, 8].map((n) => ({
        ...directHostS(),
        uuid: `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaab0${n}`,
        remark: `direct-ss-${n}`,
        port: 8000 + n,
        inbound: {
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: `44444444-4444-4444-8444-44444444440${n}`,
        },
      })),
    });
    const all = await planFor(t, serverId);
    expect(all.tooManyInbounds).toBe(true);
    expect(all.inbounds.filter((i) => i.frontable)).toHaveLength(9);
    const create = (planHash: string, listenerKeys?: string[]) =>
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId,
        planHash,
        approvedHideUuids: [],
        ...(listenerKeys ? { listenerKeys } : {}),
      });
    await expect(create(all.planHash)).rejects.toThrow(/too_many_inbounds/);
    // The operator names two: the plan is for exactly those, under its own hash.
    const keys = all.inbounds.filter((i) => i.frontable).map((i) => i.listenerKey);
    const two = [keys[3]!, keys[7]!];
    const post = await adminPost(t);
    const planned = await post('setup-runs/plan', {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      listenerKeys: two,
    });
    expect(planned.status).toBe(200);
    const chosen = SetupPlanResponse.parse(planned.json);
    expect(chosen.tooManyInbounds).toBe(false);
    expect(chosen.requiredListeners).toEqual(two);
    expect(chosen.planHash).not.toBe(all.planHash);
    // The create re-plans with the same choice; another choice is a stale hash.
    await expect(create(chosen.planHash, [keys[0]!, keys[1]!])).rejects.toThrow(/plan_stale/);
    const created = await post('setup-runs', {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      accountId,
      planHash: chosen.planHash,
      approvedHideUuids: [],
      listenerKeys: two,
    } satisfies SetupRunCreateRequest);
    expect(created.status).toBe(200);
    const runId = created.json.runId as string;
    const r = await run(t, runId as Id<'edgeSetupRuns'>);
    expect(r.listeners.map((l) => l.listenerKey)).toEqual(two);
    // A choice is 1..8 distinct frontable transports.
    const plan = (listenerKeys: string[]) =>
      t.action(internal.edgeSetupPlan.plan, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        listenerKeys,
      });
    await expect(plan([])).rejects.toThrow(/validation/);
    await expect(plan(keys)).rejects.toThrow(/validation/);
    await expect(plan([keys[0]!, keys[0]!])).rejects.toThrow(/validation/);
    await expect(plan([keys[0]!, 'not-a-transport'])).rejects.toThrow(/validation/);
  });
});

/**
 * A per-country round lands with the verification probes: three IR vantages
 * (working or failing), two control countries that work, and FCP's own
 * `tls-sni` check, all one round.
 */
const countryRound =
  (ir: (nth: number) => 'ok' | 'fail') => async (t: T, edgeId: Id<'edges'>, nth: number) => {
    await t.run(async (ctx) => {
      const edge = (await ctx.db.get(edgeId))!;
      const listener = (await ctx.db.get(edge.listenerId))!;
      const now = Date.now();
      const base = {
        targetKind: 'edge' as const,
        targetRef: edgeId as string,
        target: `${edge.addresses.v4}:${listener.originPort}`,
        port: listener.originPort,
        ipVersion: 4 as const,
        addressKind: 'ip' as const,
        requestedFamily: 4 as const,
        status: 'finished' as const,
        trigger: 'qualification' as const,
        requestedAt: now,
        finishedAt: now,
        roundId: `edge:${edgeId}:${nth}`,
      };
      const ok = ir(nth) === 'ok';
      await ctx.db.insert('probeRuns', {
        ...base,
        source: 'globalping',
        probeProtocol: 'tcp',
        controls: ['DE', 'US'],
        results: [
          ...[1, 2, 3].map((k) => ({
            country: 'IR',
            asn: `AS${k}`,
            vantageClass: 'eyeball' as const,
            ok,
          })),
          ...['DE', 'US'].map((country) => ({
            country,
            asn: `AS9${country}`,
            vantageClass: 'eyeball' as const,
            ok: true,
            control: true,
          })),
        ],
      });
      await ctx.db.insert('probeRuns', {
        ...base,
        source: 'internal',
        probeProtocol: 'tls-sni',
        results: [{ country: 'XX', vantageClass: 'datacenter' as const, ok: true }],
      });
    });
  };

async function checkFromIran(t: T) {
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.country.enabled', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify([{ code: 'IR', checkEdges: true, checkNamesInside: false }]),
    );
  });
}

describe('edgeSetupRuns: per-country checks before use', () => {
  test('a first round that finds the new address blocked in IR asks; trying another address goes on', async () => {
    const { t, serverId, accountId, world } = await seed({
      countryRound: countryRound((nth) => (nth === 1 ? 'fail' : 'ok')),
    });
    await checkFromIran(t);
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.state).toBe('needs_you');
    expect(r.need).toMatchObject({
      code: 'blocked_in',
      detail: `${r.listeners[0]!.listenerKey}:IR`,
    });
    expect(r.listeners[0]!.verify).toBe('unreachable');
    const first = r.listeners[0]!.edgeId;
    await t.mutation(internal.edgeSetupRuns.retry, { runId, tryAnotherAddress: true });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]!.edgeId).not.toBe(first);
    expect(r.listeners[0]!.verify).toBe('partial');
    expect(world.lbCreates()).toBe(2);
    expect((await t.run((ctx) => ctx.db.get(first!)))!.status).toBe('cancelled');
  });

  test('an address the probes already find partial still gets its own round first, and stops at blocked_in', async () => {
    const { t, serverId, accountId, calls } = await seed({
      countryRound: countryRound(() => 'fail'),
    });
    await checkFromIran(t);
    const { runId } = await startRun(t, serverId, accountId);
    // Evidence lands before stage 4 looks (a reused spare, background probes):
    // the rung alone would already be `partial`.
    const early = await pumpFine(t, runId, (x) => x.listeners[0]?.edgeId !== undefined);
    await landPartialEvidence(t, early.listeners[0]!.edgeId!);
    const r = await pump(t, runId, settled);
    expect(calls.probes).toHaveLength(1);
    expect(r.need).toMatchObject({
      code: 'blocked_in',
      detail: `${r.listeners[0]!.listenerKey}:IR`,
    });
  });

  test('"Use it anyway" keeps the blocked address and goes on', async () => {
    const { t, serverId, accountId } = await seed({ countryRound: countryRound(() => 'fail') });
    await checkFromIran(t);
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('blocked_in');
    const first = r.listeners[0]!.edgeId;
    await t.mutation(internal.edgeSetupRuns.retry, { runId, acceptPartial: true });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]).toMatchObject({ edgeId: first, verify: 'partial' });
  });

  test('with the checks off the same blocked round changes nothing', async () => {
    const { t, serverId, accountId } = await seed({ countryRound: countryRound(() => 'fail') });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
  });
});

describe('edgeSetupRuns: an address the outside check finds unreachable', () => {
  const sent: StageOps['reapplyEdge'] = async () => ({ status: 'sent', settled: true });

  test('it is saved again at its provider once, checked afresh, and the run goes on when it now passes', async () => {
    const { t, world, serverId, accountId, calls } = await seed({
      evidence: (nth) => (nth === 1 ? 'unreachable' : 'partial'),
      reapply: sent,
    });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    const edgeId = r.listeners[0]!.edgeId!;
    // Once, for this address, then a second round that counted only its own evidence.
    expect(calls.reapplied).toEqual([edgeId]);
    expect(calls.probes).toEqual([edgeId, edgeId]);
    expect(r.listeners[0]).toMatchObject({ verify: 'partial', reappliedEdgeId: edgeId });
    expect(r.events.find((e) => e.code === 'reapplied')).toMatchObject({
      level: 'info',
      detail: r.listeners[0]!.listenerKey,
    });
    // The same address: nothing new was bought.
    expect(world.lbCreates()).toBe(1);
  });

  test('still unreachable after it: the card asks, and Check again checks the same address afresh', async () => {
    const { t, world, serverId, accountId, calls } = await seed({
      evidence: (nth) => (nth <= 2 ? 'unreachable' : 'partial'),
      reapply: sent,
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.need).toMatchObject({ code: 'address_unreachable' });
    const edgeId = r.listeners[0]!.edgeId!;
    expect(r.listeners[0]!.verify).toBe('unreachable');
    expect(calls.probes).toHaveLength(2);
    // A run of the earlier check still in flight: the fresh check waits for it,
    // so a verdict it brings in late is never counted as fresh.
    const inflight = await t.run((ctx) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: edgeId as string,
        source: 'globalping',
        target: '198.51.100.9:443',
        status: 'running',
        trigger: 'qualification',
        requestedAt: Date.now(),
        results: [],
      }),
    );
    await t.mutation(internal.edgeSetupRuns.retry, { runId, checkAgain: true });
    r = await pumpFine(t, runId, (x) => x.state === 'waiting');
    for (let i = 0; i < 5; i++) {
      await vi.runOnlyPendingTimersAsync();
      await t.finishInProgressScheduledFunctions();
    }
    expect(calls.probes).toHaveLength(2);
    await t.run((ctx) => ctx.db.patch(inflight, { status: 'finished', finishedAt: Date.now() }));
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]).toMatchObject({ edgeId, verify: 'partial' });
    expect(calls.probes).toHaveLength(3);
    // The address is saved again once only, and no other one was bought.
    expect(calls.reapplied).toEqual([edgeId]);
    expect(world.lbCreates()).toBe(1);
  });

  test('a provider with nothing to save again asks at once; Check again that fails asks again', async () => {
    const { t, serverId, accountId, calls } = await seed({ evidence: () => 'unreachable' });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('address_unreachable');
    expect(calls.reapplied).toHaveLength(1);
    expect(calls.probes).toHaveLength(1);
    expect(r.events.some((e) => e.code === 'reapplied')).toBe(false);
    await t.mutation(internal.edgeSetupRuns.retry, { runId, checkAgain: true });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('address_unreachable');
    expect(calls.probes).toHaveLength(2);
    expect(calls.reapplied).toHaveLength(1);
  });

  test('busy, or the call failed: still one fresh check; Check again answers only the check cards', async () => {
    const { t, serverId, accountId, calls } = await seed({
      evidence: (nth) => (nth === 1 ? 'unreachable' : 'partial'),
      reapply: async () => {
        throw new ConvexError({ code: 'ScalewayError', message: 'unknown outcome' });
      },
    });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.events.find((e) => e.code === 'reapplied')?.detail).toBe(
      `${r.listeners[0]!.listenerKey}: ScalewayError`,
    );
    expect(calls.probes).toHaveLength(2);
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, { runId, checkAgain: true }),
    ).rejects.toThrow(/Check again/);
  });
});

describe('edgeSetupRuns: an address born blocked in a listed country', () => {
  test('the outside check reads every listed country: blocked_in, with no re-apply; another address goes on', async () => {
    const { t, world, serverId, accountId, calls } = await seed({
      evidence: (nth) => (nth === 1 ? 'blocked_cn' : 'partial'),
      reapply: async () => ({ status: 'sent', settled: true }),
    });
    // The per-country checks are off: the outside check alone must catch it.
    await t.run((ctx) =>
      upsertSettingRow(
        ctx,
        CENSORED_COUNTRIES_KEY,
        JSON.stringify(
          ['CN', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
        ),
      ),
    );
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.state).toBe('needs_you');
    expect(r.need).toMatchObject({
      code: 'blocked_in',
      detail: `${r.listeners[0]!.listenerKey}:CN`,
    });
    expect(r.listeners[0]!.verify).toBe('unreachable');
    // Saving the same configuration again never unblocks an address in a country.
    expect(calls.reapplied).toEqual([]);
    const first = r.listeners[0]!.edgeId;
    expect((await t.run((ctx) => ctx.db.get(first!)))!.publication).not.toBe('published');
    await t.mutation(internal.edgeSetupRuns.retry, { runId, tryAnotherAddress: true });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]!.edgeId).not.toBe(first);
    expect(world.lbCreates()).toBe(2);
  });

  test('refused from a country off the list stays unreachable (the re-apply comes first)', async () => {
    const { t, serverId, accountId, calls } = await seed({ evidence: () => 'blocked_cn' });
    await t.run((ctx) =>
      upsertSettingRow(
        ctx,
        CENSORED_COUNTRIES_KEY,
        JSON.stringify([{ code: 'RU', checkEdges: true, checkNamesInside: false }]),
      ),
    );
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('address_unreachable');
    expect(calls.reapplied).toHaveLength(1);
  });
});

describe('edgeSetupRuns: what the outside check could not test', () => {
  test('the beta mix: reached on IPv4, IPv6 untested by every source; no re-apply, IPv6 shows as not checked', async () => {
    const { t, world, serverId, accountId, calls } = await seed({ evidence: () => 'beta_mix' });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]).toMatchObject({ verify: 'partial', notChecked: [6] });
    expect(calls.probes).toHaveLength(1);
    // Nothing was refused at the address: its provider is left alone.
    expect(calls.reapplied).toEqual([]);
    expect(r.events.some((e) => e.code === 'reapplied')).toBe(false);
    expect(world.lbCreates()).toBe(1);
    // The run card says it in plain words.
    const view = await t.query(internal.edgeSetupRuns.getForAdmin, { id: runId });
    expect(view?.listeners[0]).toMatchObject({ notChecked: [6] });
  });

  test('nothing could test the address at all: no re-apply, the test card decides', async () => {
    const { t, serverId, accountId, calls } = await seed({ evidence: () => 'nothing_tested' });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners[0]).toMatchObject({ verify: 'partial', notChecked: [4] });
    expect(calls.reapplied).toEqual([]);
  });

  test('Check again clears what the earlier check could not test', async () => {
    const { t, serverId, accountId } = await seed({
      evidence: (nth) => (nth === 1 ? 'unreachable' : 'partial'),
    });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    // The provider has nothing to save again: the card asks at once.
    expect(r.need?.code).toBe('address_unreachable');
    await t.run((ctx) =>
      ctx.db.patch(runId, {
        listeners: r.listeners.map((l) => ({ ...l, notChecked: [6 as const] })),
      }),
    );
    await t.mutation(internal.edgeSetupRuns.retry, { runId, checkAgain: true });
    const after = await pump(t, runId, settled);
    expect(after.need?.code).toBe('try_it');
    expect(after.listeners[0]!.notChecked).toBeUndefined();
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

describe('edgeSetupRuns: the provider options a node gets at a pick', () => {
  test("a pick's options build its edges, freeze on them and go live with the node's set", async () => {
    const { t, world, serverId, accountId } = await seed();
    const loc = (await defaultLocationRow(t, accountId))!;
    const picks = [loc._id as string];
    // A value the provider refuses is a problem of that pick in the plan.
    const bad = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks,
      pickOptions: { [loc._id]: { maxSessions: 0 } },
    });
    expect(bad.set?.problems).toEqual([
      expect.objectContaining({ locationId: loc._id, reason: 'edge.option_invalid' }),
    ]);
    const pickOptions = { [loc._id]: { maxSessions: 5000 } };
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks,
      pickOptions,
    });
    expect(plan.set?.picks[0]?.options).toEqual({ maxSessions: 5000 });
    // The run is refused with other options than the plan was shown with.
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        picks: [loc._id],
        planHash: plan.planHash,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/plan_stale/);
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id],
      pickOptions,
      planHash: plan.planHash,
      approvedHideUuids: [],
    });
    const runId = res.runId as Id<'edgeSetupRuns'>;
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.picks?.[0]?.options).toBe(JSON.stringify({ maxSessions: 5000 }));
    // The provider was asked for it, and the edge froze it beside the location's own hash.
    const body = world.lbBodies()[0] as {
      backends: Array<{ members: Array<{ max_sessions: number }> }>;
    };
    expect(body.backends[0]!.members[0]!.max_sessions).toBe(5000);
    const edge = (await t.run((ctx) => ctx.db.get(r.listeners[0]!.edgeId!)))!;
    expect(JSON.parse(edge.choices!)).toEqual({ maxSessions: 5000 });
    const located = await t.run(async (ctx) =>
      effectiveTemplateOfLocation(
        ctx,
        (await ctx.db.get(accountId))!,
        (await ctx.db.get(loc._id))!,
      ),
    );
    expect(edge.baseTemplateHash).toBe(located.hash);
    expect(edge.templateHash).not.toBe(located.hash);
    // Its tick trusts the location: the choices are the node's, the template the place's.
    const ticked = await tickAll(t, runId);
    expect(ticked.accountTrusted).toBe(true);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
    // Go-live records the options on the node's set, where later automatic work reads them.
    const relay = await relayOf(t, runId);
    expect(relay.providerSet).toEqual([
      expect.objectContaining({
        locationId: loc._id,
        options: JSON.stringify({ maxSessions: 5000 }),
      }),
    ]);
  });

  test('options with the single-location selector are refused, never dropped', async () => {
    const { t, serverId, accountId } = await seed();
    const loc = (await defaultLocationRow(t, accountId))!;
    const plan = await planFor(t, serverId);
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId,
        planHash: plan.planHash,
        approvedHideUuids: [],
        pickOptions: { [loc._id]: { maxSessions: 5000 } },
      }),
    ).rejects.toThrow(/single location/);
  });

  test('a run never reuses a standby built for other choices than its pick asks for', async () => {
    const { t, world, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
      failCreateAt: 2,
    });
    const loc = (await defaultLocationRow(t, accountId))!;
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id],
    });
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id],
      planHash: plan.planHash,
      approvedHideUuids: [],
    });
    const runId = res.runId as Id<'edgeSetupRuns'>;
    let r = await pump(t, runId, settled);
    expect(r.state).toBe('failed');
    // The standby left behind was built with the location's defaults. A run
    // that did not build it (a later one, as here: no target holds it) and
    // whose pick asks for something else must not take it.
    const standby = r.listeners.find((l) => l.edgeId)?.edgeId;
    expect(standby).toBeDefined();
    await t.run(async (ctx) => {
      const row = (await ctx.db.get(runId))!;
      await ctx.db.patch(runId, {
        picks: row.picks!.map((p) => ({ ...p, options: JSON.stringify({ maxSessions: 5000 }) })),
        listeners: row.listeners.map(({ edgeId: _held, ...l }) => l),
      });
    });
    const before = world.lbCreates();
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    // Both listeners get an edge built with the pick's options; the standby is not taken.
    expect(world.lbCreates()).toBe(before + 2);
    expect(r.listeners.map((l) => l.edgeId)).not.toContain(standby);
    for (const l of r.listeners) {
      const edge = (await t.run((ctx) => ctx.db.get(l.edgeId!)))!;
      expect(JSON.parse(edge.choices!)).toEqual({ maxSessions: 5000 });
    }
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

describe('edgeSetupRuns: one line does not work', () => {
  test("Doesn't work on one line replaces only that address; the other line and its tick stand", async () => {
    const { t, serverId, accountId } = await seed({
      inbounds: [inboundA, inboundS],
      hosts: [directHostA(), directHostS()],
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    const [first, second] = r.testLinks!;
    // A tick saved on its own keeps the card for the other line.
    await t.mutation(internal.edgeSetupRuns.resume, {
      runId,
      confirmations: [
        {
          edgeId: first!.edgeId,
          endpoint: first!.binding.endpoint,
          listenerRevision: first!.binding.listenerRevision,
          configHash: first!.binding.configHash,
        },
      ],
    });
    r = await pump(t, runId, settled);
    expect(r.testLinks!.map((l) => l.edgeId)).toEqual([second!.edgeId]);
    // The ticked line cannot be called broken; an edgeId belongs to try_it's
    // "Doesn't work" only, and to a line of this run.
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, {
        runId,
        tryAnotherAddress: true,
        edgeId: first!.edgeId as Id<'edges'>,
      }),
    ).rejects.toThrow(/already confirmed/);
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, { runId, edgeId: second!.edgeId as Id<'edges'> }),
    ).rejects.toThrow(/validation/);
    // "Doesn't work" on the other line (over HTTP, as the card sends it): only
    // its candidate is cancelled and replaced.
    const post = await adminPost(t);
    const res = await post(`setup-runs/${runId}/retry`, {
      tryAnotherAddress: true,
      edgeId: second!.edgeId,
    } satisfies SetupRunRetryRequest);
    expect(res.status).toBe(200);
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(1);
    expect(r.testLinks![0]!.listenerKey).toBe(second!.listenerKey);
    expect(r.testLinks![0]!.edgeId).not.toBe(second!.edgeId);
    const entry = (key: string) => r.listeners.find((l) => l.listenerKey === key)!;
    expect(entry(first!.listenerKey).edgeId).toBe(first!.edgeId);
    const [kept, dropped] = await t.run(async (ctx) => [
      await ctx.db.get(first!.edgeId as Id<'edges'>),
      await ctx.db.get(second!.edgeId as Id<'edges'>),
    ]);
    expect(kept?.verification?.rung).toBe('verified');
    expect(dropped?.status).toBe('cancelled');
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect(r.state).toBe('done');
  });
});

describe('edgeSetupRuns: a used-up test account', () => {
  test('a test account the backend will not reset is the card, not a dead link or a failed run; Try again brings the links back', async () => {
    // What edgeTestLinks.build throws when relayQualification.keepUsable could
    // not reset the origin's test account (edgeTestLinks.test.ts covers the reset).
    let usedUp = true;
    const { t, serverId, accountId } = await seed({
      testLinkError: () =>
        usedUp
          ? new ConvexError({
              code: 'edge.test_account_used_up',
              message: 'The test account is used up and could not be reset',
            })
          : null,
    });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.stage).toBe('try_it');
    expect(r.state).toBe('needs_you');
    expect(r.need).toMatchObject({ code: 'test_account_used_up' });
    expect(r.testLinks ?? []).toEqual([]);
    // The candidate is kept: nothing was wrong with the address.
    const edgeId = r.listeners[0]!.edgeId!;
    expect((await t.run((ctx) => ctx.db.get(edgeId)))!.status).not.toBe('cancelled');
    expect((await audits(t, 'edge.setup_run.needs_operator')).at(-1)?.payload).toMatchObject({
      code: 'test_account_used_up',
    });

    // The account is usable again (reset, or old test profiles removed): Try again.
    usedUp = false;
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(1);
    expect(r.listeners[0]!.edgeId).toBe(edgeId);
  });
});

describe("edgeSetupRuns: the panel's mode groups not read yet", () => {
  test('the test card waits for the check account instead of failing, and goes on once the groups are read', async () => {
    // What edgeTestLinks.build throws while relayQualification.ensure cannot
    // tell which group holds the transports (relayQualification.test.ts).
    let unknown = true;
    const { t, serverId, accountId } = await seed({
      testLinkError: () =>
        unknown
          ? new ConvexError({ code: 'edge.mode_groups_unknown', message: 'not read yet' })
          : null,
    });
    const { runId } = await startRun(t, serverId, accountId);
    // A waiting step asks again on its own timer: driven a second at a time.
    const step = async (until: (r: Awaited<ReturnType<typeof run>>) => boolean) => {
      for (let i = 0; i < 2000; i++) {
        const r = await run(t, runId);
        if (until(r)) return r;
        await vi.advanceTimersByTimeAsync(1000);
        await t.finishInProgressScheduledFunctions();
      }
      throw new Error('stuck');
    };
    const waiting = await step(
      (x) => x.stage === 'try_it' && x.events.at(-1)?.code === 'mode_groups_unknown',
    );
    expect(waiting.state).toBe('waiting');
    expect(waiting.need ?? null).toBeNull();
    const edgeId = waiting.listeners[0]!.edgeId!;
    unknown = false;
    const r = await step(settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks).toHaveLength(1);
    expect(r.listeners[0]!.edgeId).toBe(edgeId);
  });
});

describe('edgeSetupRuns: no mode group holds every protected transport', () => {
  test('the test card asks for a connection mode instead of failing the run', async () => {
    const { t, serverId, accountId } = await seed({
      testLinkError: () =>
        new ConvexError({ code: 'edge.no_group_holds_transports', message: 'split' }),
    });
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    expect([r.stage, r.state]).toEqual(['try_it', 'needs_you']);
    expect(r.need).toMatchObject({ code: 'choose_mode', detail: 'no_group_holds_transports' });
    // The address is kept: nothing was wrong with it.
    const edgeId = r.listeners[0]!.edgeId!;
    expect((await t.run((ctx) => ctx.db.get(edgeId)))!.status).not.toBe('cancelled');
  });
});

describe("edgeSetupRuns: Doesn't work when no new address can be made", () => {
  /** The run at its test card, with the one address it built. */
  async function atTheCard(opts: Parameters<typeof seed>[0] = {}) {
    const w = await seed(opts);
    const { runId } = await startRun(w.t, w.serverId, w.accountId);
    const r = await pump(w.t, runId, settled);
    return { ...w, runId, r };
  }
  const edgeRow = (t: T, id: string) => t.run((ctx) => ctx.db.get(id as Id<'edges'>));
  /** The account's daily budget is what it already used today. */
  const budgetUsedUp = (t: T, accountId: Id<'edgeProviderAccounts'>) =>
    t.run(async (ctx) => {
      const a = (await ctx.db.get(accountId))!;
      expect(a.allocationsToday).toBeGreaterThan(0);
      await ctx.db.patch(accountId, { dailyAllocationBudget: a.allocationsToday });
    });

  test('a used-up daily budget refuses it and keeps the address; with budget again it replaces', async () => {
    const { t, world, accountId, runId, r } = await atTheCard();
    expect(r.need?.code).toBe('try_it');
    const edgeId = r.testLinks![0]!.edgeId;
    await budgetUsedUp(t, accountId);
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, {
        runId,
        tryAnotherAddress: true,
        edgeId: edgeId as Id<'edges'>,
      }),
    ).rejects.toThrow(/replacement_cannot_start.*Account budget exhausted/);
    // Nothing moved: the same card, the same address, still live.
    const after = await run(t, runId);
    expect(after).toMatchObject({ state: 'needs_you', generation: r.generation });
    expect(after.need?.code).toBe('try_it');
    expect(after.testLinks!.map((l) => l.edgeId)).toEqual([edgeId]);
    expect(after.listeners[0]!.edgeId).toBe(edgeId);
    expect((await edgeRow(t, edgeId))!.status).toBe('active');
    expect(world.lbCreates()).toBe(1);
    // With budget again, "Doesn't work" replaces it.
    await t.run((ctx) => ctx.db.patch(accountId, { dailyAllocationBudget: 0 }));
    await t.mutation(internal.edgeSetupRuns.retry, {
      runId,
      tryAnotherAddress: true,
      edgeId: edgeId as Id<'edges'>,
    });
    const next = await pump(t, runId, settled);
    expect(next.need?.code).toBe('try_it');
    expect(next.testLinks![0]!.edgeId).not.toBe(edgeId);
    expect((await edgeRow(t, edgeId))!.status).toBe('cancelled');
    expect(world.lbCreates()).toBe(2);
  });

  test('a freeze refuses it at the card in its own words, removing nothing', async () => {
    const { t, runId, r } = await atTheCard();
    const edgeId = r.testLinks![0]!.edgeId;
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, {
        runId,
        tryAnotherAddress: true,
        edgeId: edgeId as Id<'edges'>,
      }),
    ).rejects.toThrow(/replacement_cannot_start.*maintenance/);
    expect((await edgeRow(t, edgeId))!.status).toBe('active');
    expect((await run(t, runId)).need?.code).toBe('try_it');
  });

  test('an account at its live cap refuses it too: a cancelled address counts until it is destroyed', async () => {
    const { t, world, accountId, runId, r } = await atTheCard();
    const edgeId = r.testLinks![0]!.edgeId;
    await t.run((ctx) => ctx.db.patch(accountId, { maxLiveEdges: 1 }));
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, {
        runId,
        tryAnotherAddress: true,
        edgeId: edgeId as Id<'edges'>,
      }),
    ).rejects.toThrow(/replacement_cannot_start.*Account capacity reached/);
    expect((await edgeRow(t, edgeId))!.status).toBe('active');
    expect(world.lbCreates()).toBe(1);
  });

  test('"Try another address" on an unreachable address is kept the same way', async () => {
    const { t, accountId, runId, r } = await atTheCard({ evidence: () => 'unreachable' });
    expect(r.need?.code).toBe('address_unreachable');
    const edgeId = r.listeners[0]!.edgeId!;
    await budgetUsedUp(t, accountId);
    await expect(
      t.mutation(internal.edgeSetupRuns.retry, { runId, tryAnotherAddress: true }),
    ).rejects.toThrow(/replacement_cannot_start/);
    const after = await run(t, runId);
    expect(after.need?.code).toBe('address_unreachable');
    expect(after.listeners[0]).toMatchObject({ edgeId, verify: 'unreachable' });
    expect((await edgeRow(t, edgeId))!.status).toBe('active');
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
    // Protecting the leftover again resumes at publish, not at the rehearsal it
    // was cancelled in: the new run's listeners hold no edge until publish
    // (through provision) takes the origin's own back.
    await t.mutation(internal.edgeAdmin.patchConfig, {
      patch: { render: { clients: { mihomo: { enabled: true } } } },
    });
    const { runId: run3 } = await startRun(t, serverId, accountId);
    const r3start = await run(t, run3);
    expect(r3start.relayId).toBe(relay._id);
    expect(r3start.stage).toBe('publish');
    const r3 = await pump(t, run3, settled);
    // It takes the origin's own edges back and goes live (no card without links).
    expect([r3.stage, r3.state]).toEqual(['done', 'done']);
    expect(r3.listeners.every((l) => !!l.edgeId)).toBe(true);
  });
});

describe('edgeSetupRuns: an older failed run once a newer one took the node', () => {
  test('Try again on it is refused, and no cancel deletes or restores the live origin', async () => {
    const { t, serverId, accountId, calls } = await seed({ failCreateAt: 1 });
    const { runId: old } = await startRun(t, serverId, accountId);
    const failed = await pump(t, old, settled);
    expect(failed.state).toBe('failed');
    // A new run picks the half set up origin up and goes live on it.
    const { runId: next } = await startRun(t, serverId, accountId);
    await pump(t, next, settled);
    await tickAll(t, next);
    const live = await pump(t, next, settled);
    expect(live.state).toBe('done');
    expect(live.relayId).toBe(failed.relayId);
    expect((await bindingFor(t, serverId))?.state).toBe('active');
    // "Try again" on the old run's sheet.
    await expect(t.mutation(internal.edgeSetupRuns.retry, { runId: old })).rejects.toThrow(
      /setup_run_superseded/,
    );
    expect((await run(t, old)).state).toBe('failed');
    // Even a run that found its way back onto the live origin cannot cancel it away.
    await t.run((ctx) => ctx.db.patch(old, { state: 'running', stage: 'try_it' }));
    const c = await t.action(internal.edgeSetupRuns.cancel, { runId: old });
    expect(c.disposition).toBe('none');
    const relay = (await t.run((ctx) => ctx.db.get(live.relayId!)))!;
    expect(relay.deleting).toBeUndefined();
    expect(relay.restore).toBeUndefined();
    expect(calls.restore).toEqual([]);
    expect((await bindingFor(t, serverId))?.state).toBe('active');
  });
});

describe('edgeSetupRuns: a cancel racing the go-live', () => {
  /** A run held at stage 7 (the rehearsal reports no serve), then released: its next step goes live. */
  async function dueToGoLive() {
    const race: { go?: () => Promise<void> } = {};
    const seeded = await seed({ onRestoreStart: async () => race.go?.() });
    const { t, serverId, accountId, setRehearsalHold } = seeded;
    const { runId } = await startRun(t, serverId, accountId);
    await pump(t, runId, settled);
    setRehearsalHold(true);
    await tickAll(t, runId);
    const held = await pump(t, runId, settled);
    expect(held.need?.code).toBe('rehearsal_failed');
    setRehearsalHold(false);
    // Try again: the rehearsal step is scheduled (not run yet); it passes and goes live at once.
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    return { ...seeded, runId, race };
  }

  /** Run whatever is scheduled, a few rounds (a step and what it schedules at once). */
  async function runScheduled(t: T) {
    for (let i = 0; i < 5; i++) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
    }
  }

  test('a go-live due while the cancel decides never lands: the run ends cancelled and nothing binds', async () => {
    const { t, serverId, calls, runId, race } = await dueToGoLive();
    // Whatever the run has scheduled runs between the cancel's decision and its restore.
    race.go = () => runScheduled(t);
    const c = await t.action(internal.edgeSetupRuns.cancel, { runId });
    expect(c.disposition).toBe('restore');
    expect(calls.restore).toEqual(['cancel_setup']);
    expect((await run(t, runId)).state).toBe('cancelled');
    expect(await bindingFor(t, serverId)).toBeNull();
    expect((await relayOf(t, runId)).setupOwned).toBe(true);
  });

  test('a cancel whose restore cannot start yet can be pressed again: the run is not ended before its cleanup', async () => {
    const { t, calls, runId, race } = await dueToGoLive();
    let refuse = true;
    race.go = async () => {
      if (!refuse) return;
      refuse = false;
      throw new ConvexError({ code: 'edge.panel_op_running', message: 'busy' });
    };
    await expect(t.action(internal.edgeSetupRuns.cancel, { runId })).rejects.toThrow(
      /panel_op_running/,
    );
    expect((await run(t, runId)).state).not.toBe('cancelled');
    expect(calls.restore).toEqual([]);
    // The second press goes through and ends the run.
    const c = await t.action(internal.edgeSetupRuns.cancel, { runId });
    expect(c.disposition).toBe('restore');
    expect(calls.restore).toEqual(['cancel_setup']);
    expect((await run(t, runId)).state).toBe('cancelled');
  });

  test('go-live waits while a restore runs on the origin, and a cancelled setup restores only an origin it owns', async () => {
    const { t, serverId, runId } = await dueToGoLive();
    const r = await run(t, runId);
    // A restore workflow takes the origin (another cancel, a delete) before the go-live step.
    const now = Date.now();
    await t.run((ctx) =>
      ctx.db.patch(r.relayId!, {
        restore: {
          purpose: 'delete_relay',
          phase: 'freeze',
          attempt: 0,
          startedAt: now,
          updatedAt: now,
        },
      }),
    );
    const after = await pump(t, runId, settled);
    expect(after.state).toBe('needs_you');
    expect(after.stage).toBe('go_live');
    expect(await bindingFor(t, serverId)).toBeNull();
    // An origin no setup owns any more is never restored as a cancelled setup.
    await t.run((ctx) => ctx.db.patch(r.relayId!, { restore: undefined, setupOwned: undefined }));
    await expect(
      t.mutation(internal.edgeRestore.start, { relayId: r.relayId!, purpose: 'cancel_setup' }),
    ).rejects.toThrow(/edge\.origin_live/);
  });
});

describe('edgeSetupRuns: a failed run is found again', () => {
  test("the origin status names the failed run and an attention item opens it; a retry restarts the sheet's clock and clears both", async () => {
    const { t, serverId, accountId } = await seed({ failCreateAt: 1 });
    const { runId } = await startRun(t, serverId, accountId);
    let r = await pump(t, runId, settled);
    expect(r.state).toBe('failed');
    const attention = () => t.query(internal.edgeOperator.attention, {});
    let att = await attention();
    const item = att.items.find((i) => i.kind === 'setup_run_failed');
    expect(item).toMatchObject({
      severity: 'warning',
      action: 'open_run',
      relayId: r.relayId as string,
      facts: { runId: runId as string },
    });
    let status = att.origins.find((o) => o.relayId === (r.relayId as string))!.status;
    expect(status).toMatchObject({
      kind: 'needs-you',
      code: 'setup_run_failed',
      runId: null,
      failedRunId: runId as string,
    });
    // The sheet counts the first attempt from the start, a retried one from its retry.
    let admin = (await t.query(internal.edgeSetupRuns.getForAdmin, { id: runId }))!;
    expect(admin.attemptStartedAt).toBe(admin.startedAt);
    vi.advanceTimersByTime(60_000);
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    admin = (await t.query(internal.edgeSetupRuns.getForAdmin, { id: runId }))!;
    expect(Date.parse(admin.attemptStartedAt) - Date.parse(admin.startedAt)).toBeGreaterThanOrEqual(
      60_000,
    );
    // Running again: the live run is what the status names.
    att = await attention();
    expect(att.items.some((i) => i.kind === 'setup_run_failed')).toBe(false);
    status = att.origins.find((o) => o.relayId === (r.relayId as string))!.status;
    expect(status.failedRunId).toBeNull();
    expect(status.runId).toBe(runId as string);
    r = await run(t, runId);
    expect(r.state).toBe('running');
  });
});

describe('edgeSetupRuns: maintenance', () => {
  test('a freeze refuses a new run, blocks stage 1 and 3, but a run past try_it finishes its publish under setup.complete', async () => {
    const { t, serverId, accountId } = await seed();
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    // A new run is new work: refused in the mutation that would persist it.
    await expect(startRun(t, serverId, accountId)).rejects.toThrow(/maintenance/);
    await t.mutation(internal.edgeMaintenance.thaw, {});
    const { runId } = await startRun(t, serverId, accountId);
    // Frozen before its first step: the run waits at stage 1 for the operator.
    await t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    let r = await pump(t, runId, settled);
    expect(r.stage).toBe('prepare');
    expect(r.need?.code).toBe('maintenance');
    // A retry that would provision is new work too: refused while frozen.
    await expect(t.mutation(internal.edgeSetupRuns.retry, { runId })).rejects.toThrow(
      /maintenance/,
    );
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

describe('edgeSetupRuns: a provider set of two locations', () => {
  test('two picks: one address per pick, two ticks, both published, the set recorded; a hook never overwrites the other target', async () => {
    const { t, serverId, accountId } = await seed();
    const first = (await defaultLocationRow(t, accountId))!._id;
    const second = (
      await t.mutation(internal.edgeLocations.create, {
        accountId,
        placement: { zone: 'nl-ams1' },
        label: 'Zone two',
      })
    ).id as Id<'edgeLocations'>;
    // The plan shown for the set says what it makes: one provider, two
    // locations, so the transport needs an address in each.
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [first, second],
    });
    expect(plan.set?.targets.map((x) => x.locationId).sort()).toEqual([first, second].sort());
    expect(plan.set?.reduced).toEqual([]);
    const created = (await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [first, second],
      planHash: plan.planHash,
      approvedHideUuids: [],
    })) as { runId: string };
    const runId = created.runId as Id<'edgeSetupRuns'>;
    let r = await pump(t, runId, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.listeners.map((l) => l.locationId).sort()).toEqual([first, second].sort());
    // Each target holds its own address, in its own location.
    const edges = await t.run(async (ctx) =>
      Promise.all(r.listeners.map((l) => ctx.db.get(l.edgeId!))),
    );
    expect(new Set(edges.map((e) => e!._id)).size).toBe(2);
    for (const [i, l] of r.listeners.entries()) expect(edges[i]!.locationId).toBe(l.locationId);
    expect(r.testLinks).toHaveLength(2);
    await tickAll(t, runId);
    r = await pump(t, runId, settled);
    expect([r.stage, r.state]).toEqual(['done', 'done']);
    expect(r.listeners.every((l) => l.published)).toBe(true);
    const relay = await relayOf(t, runId);
    expect(relay.publishedEdgeIds.filter(Boolean)).toHaveLength(2);
    expect(relay.providerSet?.map((p) => p.locationId)).toEqual([first, second]);
    // Wrong picks are refused at the plan: a location picked twice.
    await expect(
      t.action(internal.edgeSetupPlan.plan, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        picks: [first, first],
      }),
    ).rejects.toThrow(/picked twice/);
  });
});

describe('edgeSetupRuns: replacing a pick of a set', () => {
  test('the cover is worked out again: the kept pick keeps its line and address, the new pick gets a fresh one, the old candidate is cancelled', async () => {
    const { t, serverId, accountId } = await seed();
    const first = (await defaultLocationRow(t, accountId))!._id;
    const mk = async (zone: string) =>
      (await t.mutation(internal.edgeLocations.create, { accountId, placement: { zone } }))
        .id as Id<'edgeLocations'>;
    const second = await mk('nl-ams1');
    const third = await mk('fi-hel1');
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [first, second],
    });
    const created = (await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [first, second],
      planHash: plan.planHash,
      approvedHideUuids: [],
    })) as { runId: string };
    const runId = created.runId as Id<'edgeSetupRuns'>;
    const card = await pump(t, runId, settled);
    expect(card.need?.code).toBe('try_it');
    const kept = card.listeners.find((l) => l.locationId === first)!;
    const dropped = card.listeners.find((l) => l.locationId === second)!;
    await t.mutation(internal.edgeSetupRuns.retry, {
      runId,
      replacePick: { from: second, to: third },
    });
    const after = await run(t, runId);
    expect(after.picks!.map((p) => p.locationId)).toEqual([first, third]);
    expect(after.listeners.map((l) => l.locationId).sort()).toEqual([first, third].sort());
    // The kept line keeps its address; the replaced pick's candidate is cancelled.
    expect(after.listeners.find((l) => l.locationId === first)!.edgeId).toBe(kept.edgeId);
    expect(after.listeners.find((l) => l.locationId === third)!.edgeId).toBeUndefined();
    expect((await t.run((c) => c.db.get(dropped.edgeId!)))!.status).toBe('cancelled');
    expect(after.stage).toBe('provision');
  });
});

describe('edgeSetupRuns: a certificate wait the run is waiting on', () => {
  test('the run hears what its rotation waits on, only while it waits on THAT rotation', async () => {
    const { t, serverId, accountId } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pumpFine(t, runId, (x) => !!x.expect);
    const rotationId = r.expect!.rotationId;
    const advance = async (waitCode?: string) => {
      const rot = (await t.run((ctx) => ctx.db.get(rotationId)))!;
      return t.mutation(internal.edgeRotations.advance, {
        rotationId,
        stepVersion: rot.stepVersion,
        event: { type: 'progress', delayMs: 60_000, ...(waitCode ? { waitCode } : {}) },
      });
    };
    await advance('tls_caa_conflict');
    let now = await run(t, runId);
    expect(now.events.at(-1)).toMatchObject({ level: 'warn', code: 'tls_caa_conflict' });
    // The rotation's own log has it too.
    const rot = (await t.run((ctx) => ctx.db.get(rotationId)))!;
    expect(rot.events.at(-1)).toMatchObject({ level: 'warn', code: 'tls_caa_conflict' });
    // A run no longer waiting on this rotation hears nothing.
    await t.run((ctx) => ctx.db.patch(runId, { expect: undefined }));
    const before = (await run(t, runId)).events.length;
    await advance('tls_challenge_missing');
    now = await run(t, runId);
    expect(now.events).toHaveLength(before);
  });
});

describe('edgeSetupRuns: a zone whose fronts could get no certificate', () => {
  test('the plan names it on the zone, and a run stops at its first stage instead of provisioning', async () => {
    const { t, serverId, accountId } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    // The zone's next check ends on the CAA preflight.
    await t.run(async (ctx) => {
      for (const l of await ctx.db
        .query('edgeLocations')
        .withIndex('by_account', (q) => q.eq('accountId', accountId))
        .collect())
        await ctx.db.patch(l._id, { checkError: 'caa_forbids_ca' });
    });
    const plan = await planFor(t, serverId);
    const offered = plan.accounts.find((a) => a.id === accountId)!;
    // Named on the zone, which stays pickable: a node may choose another
    // certificate there under its Options (its pick check judges it).
    expect(offered).toMatchObject({ compatible: true });
    expect((offered.locations ?? []).every((l) => l.certificateRefusal === 'caa_forbids_ca')).toBe(
      true,
    );
    // A pick on the account's own certificate is refused by the plan.
    const loc = (await defaultLocationRow(t, accountId))!;
    const picked = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id as string],
    });
    expect(picked.set?.problems).toEqual([
      expect.objectContaining({ locationId: loc._id, reason: 'edge.caa_forbids_ca' }),
    ]);
    const r = await pump(t, runId, settled);
    expect(r.need).toMatchObject({ code: 'account_incompatible', detail: 'caa_forbids_ca' });
    const relay = r.relayId ? await t.run((ctx) => ctx.db.get(r.relayId!)) : null;
    expect(relay?.activeRotationId ?? null).toBeNull();
  });
});

describe("edgeSetupRuns: a node FCP does not manage, fronted by the operator's own load balancer", () => {
  // The panel lists the node by its private management address; members dial
  // a load balancer the operator built, through a Host remarked `<node>-relay`
  // at the load balancer's public address. No Host dials the node itself.
  const MANAGEMENT = '10.0.0.5';
  const LB = '198.51.100.20';
  const HOST_LB = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9';
  const frontHost = (over: Partial<BackendAddress> = {}): BackendAddress => ({
    uuid: HOST_LB,
    remark: 'node-one-relay',
    address: LB,
    port: 443,
    sni: 'a.example',
    inbound: {
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: FIXTURE_INBOUND,
    },
    ...over,
  });
  async function seedFronted(
    opts: Parameters<typeof seed>[0] & {
      panelAddress?: string;
      synthesisReady?: boolean;
      /** What the plan reads of each REALITY transport (null = it admits every client). */
      realityRefusal?: RealityClientRefusal | null;
    } = {},
  ) {
    const s = await seed({ hosts: [frontHost()], ...opts });
    await s.t.run(async (ctx) => {
      const row = (await ctx.db.query('backendNodeInventory').collect())[0]!;
      await ctx.db.patch(row._id, { address: opts.panelAddress ?? MANAGEMENT });
    });
    // What the panel says of the REALITY transport (its key and names), read
    // by the plan as the test link will.
    const ready: Array<{ tag: string }> = [];
    const clientsAsked: unknown[] = [];
    __setPlanOpsForTests({
      listNodeInbounds: async () => opts.inbounds ?? [inboundA],
      listHosts: async () =>
        s.world.panelHosts.map((h) => ({ ...h, isDisabled: h.isDisabled ?? false })),
      synthesisReady: async (_ctx, a) => {
        ready.push({ tag: a.tag });
        return opts.synthesisReady ?? true;
      },
      realityClients: async (_ctx, a) => {
        clientsAsked.push(a);
        return opts.realityRefusal === undefined
          ? []
          : a.transports.map((x) => ({ key: x.key, tag: x.tag, refusal: opts.realityRefusal! }));
      },
    });
    return { ...s, ready, clientsAsked };
  }
  const planWith = (t: T, serverId: Id<'backendServers'>, extra: Record<string, unknown> = {}) =>
    t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      ...extra,
    });
  const codeOf = (p: Promise<unknown>) =>
    p.then(
      () => null,
      (e: unknown) => (e as ConvexError<{ code: string }>).data?.code ?? String(e),
    );

  test('the panel address is private: no load balancer is offered and the run is refused; the public address the operator gives is checked, shown and used', async () => {
    const { t, serverId, accountId, world } = await seedFronted();
    const plan = await planWith(t, serverId);
    expect(plan).toMatchObject({
      originAddress: MANAGEMENT,
      originSource: 'panel',
      originPrivate: true,
    });
    const acct = plan.accounts.find((a) => a.id === (accountId as string))!;
    expect(acct.compatible).toBe(false);
    expect(acct.reasons).toContain('origin_private');
    // The operator's front is known, and is no direct Host of the node.
    expect(plan.frontHosts).toEqual([{ uuid: HOST_LB, remark: 'node-one-relay' }]);
    expect(plan.directHosts).toEqual([]);
    expect(
      await codeOf(
        t.action(internal.edgeSetupPlan.create, {
          backendServerId: serverId,
          nodeUuid: NODE_UUID,
          accountId,
          planHash: plan.planHash,
          approvedHideUuids: [],
        }),
      ),
    ).toBe('edge.origin_not_public');
    // What the operator gives is checked: a private IP, a name (a load balancer
    // forwards to an IP, never a name), something that is neither.
    expect(await codeOf(planWith(t, serverId, { originAddress: '10.0.0.9' }))).toBe(
      'edge.origin_not_public',
    );
    expect(await codeOf(planWith(t, serverId, { originAddress: '[fd00::5]' }))).toBe(
      'edge.origin_not_public',
    );
    expect(await codeOf(planWith(t, serverId, { originAddress: 'node.example.net' }))).toBe(
      'edge.origin_not_ip',
    );
    expect(await codeOf(planWith(t, serverId, { originAddress: 'not an address' }))).toBe(
      'edge.origin_not_ip',
    );
    // An IPv6 address is kept the one way an IP is written (no brackets: a
    // provider takes it as a bare IP).
    const v6 = await planWith(t, serverId, { originAddress: '[2001:DB8:0:0::10]' });
    expect(v6).toMatchObject({ originAddress: '2001:db8::10', originSource: 'given' });
    // The public address: shown, a load balancer offered, the run forwards there.
    const given = await planWith(t, serverId, { originAddress: ORIGIN });
    expect(given).toMatchObject({
      originAddress: ORIGIN,
      originSource: 'given',
      originPrivate: false,
      managementAddress: MANAGEMENT,
    });
    expect(given.accounts.find((a) => a.id === (accountId as string))!.compatible).toBe(true);
    expect(given.planHash).not.toBe(plan.planHash);
    // The fronts the review names are part of what was shown: one renamed
    // since is a stale plan.
    world.panelHosts[0]!.remark = 'node-one-relay-old';
    expect(
      await codeOf(
        t.action(internal.edgeSetupPlan.create, {
          backendServerId: serverId,
          nodeUuid: NODE_UUID,
          accountId,
          planHash: given.planHash,
          approvedHideUuids: [],
          originAddress: ORIGIN,
        }),
      ),
    ).toBe('edge.plan_stale');
    world.panelHosts[0]!.remark = 'node-one-relay';
    // A create naming another address than the plan showed is stale.
    expect(
      await codeOf(
        t.action(internal.edgeSetupPlan.create, {
          backendServerId: serverId,
          nodeUuid: NODE_UUID,
          accountId,
          planHash: given.planHash,
          approvedHideUuids: [],
          originAddress: '203.0.113.99',
        }),
      ),
    ).toBe('edge.plan_stale');
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      accountId,
      planHash: given.planHash,
      approvedHideUuids: [],
      originAddress: ORIGIN,
    });
    const runId = res.runId as Id<'edgeSetupRuns'>;
    const r = await pump(t, runId, (x) => !!x.relayId);
    const created = await relayOf(t, r._id);
    expect(created.originAddress).toBe(ORIGIN);
    // The node is known by its management address too: a Host there is its own.
    expect(created.nodeAddresses).toEqual([MANAGEMENT]);
    // A step cut short after the origin was made (the run never noted it) finds
    // the origin again and records the address all the same.
    await t.run(async (ctx) => {
      await ctx.db.patch(created._id, { nodeAddresses: undefined });
      const row = (await ctx.db.get(runId))!;
      await ctx.db.patch(runId, {
        stage: 'prepare',
        state: 'running',
        relayId: undefined,
        stepVersion: row.stepVersion + 1,
      });
    });
    await t.action(internal.edgeSetupRuns.step, {
      runId,
      stepVersion: (await run(t, runId)).stepVersion,
    });
    expect((await run(t, runId)).relayId).toBe(created._id);
    expect((await relayOf(t, runId)).nodeAddresses).toEqual([MANAGEMENT]);
    // The origin is now fixed: another address is refused for it.
    expect(await codeOf(planWith(t, serverId, { originAddress: '203.0.113.99' }))).toBe(
      'edge.origin_address_locked',
    );
  });

  test('the panel lists the node by a name: no load balancer is offered (it forwards to an IP), and the public IP is asked for', async () => {
    const { t, serverId, accountId } = await seedFronted({ panelAddress: 'node-one.example.net' });
    const plan = await planWith(t, serverId);
    expect(plan).toMatchObject({
      originAddress: 'node-one.example.net',
      originSource: 'panel',
      originName: true,
      originPrivate: false,
    });
    const acct = plan.accounts.find((a) => a.id === (accountId as string))!;
    expect(acct.reasons).toContain('origin_name');
    const loc = (await defaultLocationRow(t, accountId))!;
    const picked = await planWith(t, serverId, { picks: [loc._id] });
    expect(
      await codeOf(
        t.action(internal.edgeSetupPlan.create, {
          backendServerId: serverId,
          nodeUuid: NODE_UUID,
          picks: [loc._id],
          planHash: picked.planHash,
          approvedHideUuids: [],
        }),
      ),
    ).toBe('edge.origin_not_ip');
  });

  test('a load balancer is never created, named or reused for an origin it cannot forward to, whoever asks', async () => {
    const { t, accountId, world } = await seedFronted();
    const { relayId } = await registerRelay(t, { originAddress: MANAGEMENT });
    const listenerId = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .first(),
    ))!._id;
    // Named: refused before anything starts.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'provision',
        trigger: 'manual',
        listenerId,
        requestedAccountId: accountId,
      }),
    ).rejects.toThrow(/origin_not_public/);
    // A load balancer spare it already has (made before this check) is never
    // picked to publish, nor named.
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.30',
      verified: true,
    });
    await t.run((ctx) => ctx.db.patch(edgeId as Id<'edges'>, { health: 'online' }));
    // Chosen by FCP: neither that spare nor a load balancer account is a
    // candidate, nothing is bought and nothing published.
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: true,
    });
    for (let i = 0; i < 20; i++) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
    }
    const rot = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(rot.phase).toBe('failed');
    expect(world.lbCreates()).toBe(0);
    expect((await t.run((ctx) => ctx.db.get(edgeId as Id<'edges'>)))?.publication).toBe(
      'unpublished',
    );
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'publish',
        trigger: 'manual',
        toEdgeId: edgeId as Id<'edges'>,
      }),
    ).rejects.toThrow(/origin_not_public/);
    // The same holds for a name: a load balancer forwards to an IP.
    await t.run((ctx) => ctx.db.patch(relayId, { originAddress: 'node-one.example.net' }));
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'provision',
        trigger: 'manual',
        listenerId,
        requestedAccountId: accountId,
      }),
    ).rejects.toThrow(/origin_not_ip/);
  });

  test('a transport no test link can be made for (no Host at the node, an entry FCP cannot build) is refused before any address is bought', async () => {
    const { t, serverId, accountId, world } = await seedFronted({
      inbounds: [inboundS],
      hosts: [frontHost({ port: 8388, inbound: directHostS().inbound })],
    });
    const loc = (await defaultLocationRow(t, accountId))!;
    const plan = await planWith(t, serverId, { originAddress: ORIGIN, picks: [loc._id] });
    expect(plan.inbounds.find((i) => i.sourceTag === 'SS_IN')?.noTestLink).toBe(true);
    expect(plan.set?.problems).toContainEqual({
      locationId: loc._id,
      reason: 'test_link_unavailable',
    });
    expect(
      await codeOf(
        t.action(internal.edgeSetupPlan.create, {
          backendServerId: serverId,
          nodeUuid: NODE_UUID,
          picks: [loc._id],
          planHash: plan.planHash,
          approvedHideUuids: [],
          originAddress: ORIGIN,
        }),
      ),
    ).toBe('edge.test_link_unavailable');
    expect(world.lbCreates()).toBe(0);
    // A REALITY transport needs no Host there: its entry is built from the
    // node, read from the panel at plan time as the test link will read it.
    const { t: t2, serverId: s2, accountId: a2, ready } = await seedFronted();
    const loc2 = (await defaultLocationRow(t2, a2))!;
    const reality = await planWith(t2, s2, { originAddress: ORIGIN, picks: [loc2._id] });
    expect(reality.inbounds.find((i) => i.sourceTag === 'VLESS_RELAY_A')?.noTestLink).toBe(
      undefined,
    );
    expect(reality.set?.problems).toEqual([]);
    expect(ready).toEqual([{ tag: 'VLESS_RELAY_A' }]);
    // A panel that no longer describes it (or gives it no key) has none to build.
    const { t: t3, serverId: s3, accountId: a3 } = await seedFronted({ synthesisReady: false });
    const loc3 = (await defaultLocationRow(t3, a3))!;
    const stale = await planWith(t3, s3, { originAddress: ORIGIN, picks: [loc3._id] });
    expect(stale.inbounds.find((i) => i.sourceTag === 'VLESS_RELAY_A')?.noTestLink).toBe(true);
    expect(stale.set?.problems).toContainEqual({
      locationId: loc3._id,
      reason: 'test_link_unavailable',
    });
  });

  test('a REALITY transport that refuses sing-box and Mihomo clients is named on the plan, protected all the same, and its test card line says so', async () => {
    // The beta case: hand-built, no minClientVer, Xray 26.7.28.
    const refusal: RealityClientRefusal = {
      refuses: ['singbox', 'mihomo'],
      reasons: [{ cause: 'core_default', families: ['singbox', 'mihomo'] }],
      xrayVersion: '26.7.28',
      minClientVer: null,
      maxClientVer: null,
    };
    const { t, serverId, accountId, clientsAsked } = await seedFronted({
      realityRefusal: refusal,
      realityClients: async (_ctx, a) =>
        a.listenerKeys.map((key) => ({ key, tag: 'VLESS_RELAY_A', refusal })),
    });
    const loc = (await defaultLocationRow(t, accountId))!;
    const plan = await planWith(t, serverId, { originAddress: ORIGIN, picks: [loc._id] });
    const inbound = plan.inbounds.find((i) => i.sourceTag === 'VLESS_RELAY_A')!;
    expect(inbound.refusesClients).toEqual(refusal);
    // The plan asked the panel about the transport it protects, on its node.
    expect(clientsAsked).toEqual([
      {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        nodeName: 'node-one',
        transports: [
          {
            key: inbound.listenerKey,
            profileUuid: FIXTURE_CONFIG_PROFILE,
            tag: 'VLESS_RELAY_A',
          },
        ],
      },
    ]);
    // A warning: the set has no problem and the run is created.
    expect(plan.set?.problems).toEqual([]);
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id],
      planHash: plan.planHash,
      approvedHideUuids: [],
      originAddress: ORIGIN,
    });
    const r = await pump(t, res.runId as Id<'edgeSetupRuns'>, settled);
    expect(r.need?.code).toBe('try_it');
    expect(r.testLinks?.map((l) => l.realityClients)).toEqual([refusal]);
    // The card reads it from the run's admin view.
    const view = SetupRunAdmin.parse(JSON.parse(JSON.stringify(mapRunAdmin(r))));
    expect(view.testLinks[0]!.realityClients).toEqual(refusal);
  });

  test('a REALITY transport that admits every client: no warning on the plan, and its test line still says it is REALITY', async () => {
    const { t, serverId, accountId } = await seedFronted({
      realityRefusal: null,
      realityClients: async (_ctx, a) =>
        a.listenerKeys.map((key) => ({ key, tag: 'VLESS_RELAY_A', refusal: null })),
    });
    const loc = (await defaultLocationRow(t, accountId))!;
    const plan = await planWith(t, serverId, { originAddress: ORIGIN, picks: [loc._id] });
    expect(plan.inbounds.find((i) => i.sourceTag === 'VLESS_RELAY_A')?.refusesClients).toBe(
      undefined,
    );
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      picks: [loc._id],
      planHash: plan.planHash,
      approvedHideUuids: [],
      originAddress: ORIGIN,
    });
    const r = await pump(t, res.runId as Id<'edgeSetupRuns'>, settled);
    expect(r.testLinks?.map((l) => l.realityClients)).toEqual([null]);
  });
});

describe('edgeSetupRuns: protecting a node whose earlier protection is still being removed', () => {
  test('the plan says so and the create is refused in its own words; a run that meets it waits instead of failing as taken', async () => {
    const { t, serverId, accountId } = await seed();
    const { runId } = await startRun(t, serverId, accountId);
    const r = await pump(t, runId, settled);
    const relayId = r.relayId!;
    await t.action(internal.edgeSetupRuns.cancel, { runId });
    expect((await t.run((ctx) => ctx.db.get(relayId)))?.deleting).toBe(true);
    const plan = await planFor(t, serverId);
    expect(plan.originDeleting).toBe(true);
    expect(plan.existingRelay).toBeNull();
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        accountId,
        planHash: plan.planHash,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/origin_deleting/);
    // A run created just before the delete began meets it at prepare: it waits.
    await t.run(async (ctx) => {
      for (const e of await ctx.db.query('edges').collect())
        await ctx.db.patch(e._id, { status: 'destroyed', publication: 'unpublished' });
    });
    await t.mutation(internal.relays.finalizeDelete, { id: relayId });
    const { runId: run2 } = await startRun(t, serverId, accountId);
    const { relayId: again } = await registerRelay(t, { slug: 'node-one-old' });
    await t.run((ctx) => ctx.db.patch(again, { deleting: true }));
    await vi.advanceTimersByTimeAsync(1);
    await t.finishInProgressScheduledFunctions();
    const waiting = await run(t, run2);
    expect([waiting.stage, waiting.state]).toEqual(['prepare', 'waiting']);
    expect(waiting.events.at(-1)?.code).toBe('origin_deleting');
    expect(waiting.need ?? null).toBeNull();
    // Once it is gone the run carries on with an origin of its own.
    await t.run((ctx) => ctx.db.delete(again));
    const r2 = await pump(t, run2, (x) => !!x.relayId);
    expect(r2.relayId).not.toBe(again);
  });
});
