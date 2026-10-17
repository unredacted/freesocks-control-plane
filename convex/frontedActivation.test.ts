// @vitest-environment node
/// <reference types="vite/client" />
/**
 * A FRONTED node from enrollment to members (docs/servers.md "Node
 * lifecycle", docs/edges.md "Guided setup runs"), against the fake backend
 * and fake providers, with the real activation, setup run, rotation,
 * rehearsal, render and mirror code:
 *
 *  - the setup run parks at publish (`node_not_approved`) with nothing
 *    published, the approval over HTTP wakes exactly that run, and the commit
 *    opens the gate: a pinned member goes from `node_gated` to a rendered body
 *    carrying the edge, never the origin;
 *  - a live node's replacement stays a candidate (never in a member body, a
 *    cache or a mirror) through publication, a failed promotion and a
 *    re-approval, and its rehearsal renders the candidates;
 *  - "Protect again" over HTTP (a `reprotect` run): fresh candidates, members
 *    keep the committed delivery throughout, a cancel drops only the
 *    candidates and a failure hands the live origin back;
 *  - ownership vs attempt fencing: wakes and end hooks of an older attempt or
 *    an older run are no-ops;
 *  - the mirror barrier, and the refusals.
 *
 * The node environment is needed for the node-runtime modules (ingress check,
 * front qualification, mirrors). Fixtures are RFC 5737 / `*.example` only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { walkRelayCohorts } from './edgeCohorts';
import { selectionContext } from './edgeRotations';
import { resolveEdgeConfig } from './lib/edgeConfig';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_PANEL_SLUG,
  createAccount,
  insertPanelServer,
  verifyL4Edge,
} from './lib/edges/testing/fixtures';
import { createFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { createFakeUpcloud } from './lib/edges/testing/fakeEdgeWorld';
import { z } from 'zod';
import { __setEdgeProviderForTests } from './lib/edges/providers/registry';
import type { EdgeProvider, EdgeSpec, Ledger, LedgerResource } from './lib/edges/providers/types';
import { jsonRes, mockFetch, routeFetch, type PartialHandler } from './lib/edges/testing/mockFetch';
import { __setStageOpsForTests, type StageOps } from './edgeSetupRuns';
import { __setPlanOpsForTests } from './edgeSetupPlan';
import { __setFrontIngressCheckForTests } from './nodeIntentOps';
import { __setFrontChecker } from './frontQualifyOps';
import { MIRROR_UNAVAILABLE_STUB, __setS3SendForTests, type S3Op } from './storage';
import { REPAIR_GRACE_MS } from './mirrorUploads';
import { onSetupRunEnded } from './edgeSetupRuns';
import { publicationAdmission } from './nodeActivation';
import { signValue } from './lib/cookies';
import { ActivationReview } from '../src/shared/contracts/servers';
import {
  SetupRunAdmin,
  SetupRunCancelResponse,
  SetupRunCreatedResponse,
} from '../src/shared/contracts/edges';
import {
  deliveryBindingOf,
  gateOfNode,
  insertPlanned,
  openMirrorUploads,
} from './lib/edges/testing/reads';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setStageOpsForTests(null);
  __setPlanOpsForTests(null);
  __setFrontIngressCheckForTests(null);
  __setFrontChecker(null);
  __setS3SendForTests(null);
});

const NODE = 'node-r';
const NODE_W = 'node-w';
/** The node's public address: what edges dial, never what a member is given. */
const ORIGIN_V4 = '203.0.113.20';
const ORIGIN_W_V4 = '203.0.113.30';
const ORIGIN_W_NAME = 'origin-w.example';
const SINGBOX_UA = 'SFA/1.10.0 (sing-box 1.10.0)';
const LINKS_UA = 'v2rayNG/1.8.29';

const setupInput = {
  profileName: 'FreeSocks-Config',
  modes: [
    {
      slug: 'freedom-reality',
      name: 'Freedom-Reality',
      shape: { transport: 'reality' as const, fronting: 'edge-l4' as const },
      familySlug: 'fam-fronted',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-ws',
      name: 'Freedom-WebSocket',
      shape: { transport: 'ws' as const, fronting: 'edge-l7' as const },
      acceptProxyProtocol: false,
      ws: { path: '/ws', port: 8443 },
    },
  ],
  originDns: null,
  adopt: false,
};

/**
 * A fake L7 adapter in place of the Cloudflare one: one DNS record, then a
 * hostname, recording what the machine asked for (the vendor's wire format is
 * pinned by its contract tests, not here).
 */
function installFakeL7(): {
  seen: Array<{ call: string; hostname?: string; originPort?: number }>;
  uninstall: () => void;
} {
  const seen: Array<{ call: string; hostname?: string; originPort?: number }> = [];
  // The hostname each DNS record was minted for (resource id -> hostname).
  const minted = new Map<string, string>();
  const provider = {
    id: 'cloudflare',
    templateSchema: z.object({}).passthrough(),
    templateFields: [],
    defaultTemplate: {},
    testCredentials: async () => ({ ok: true }),
    planProvision: (_cfg: unknown, spec: EdgeSpec) => {
      seen.push({ call: 'plan', hostname: spec.hostname });
      return [
        {
          id: 'dns',
          kind: 'create_dns_record',
          resourceName: spec.name,
          discoverability: 'by_name',
        },
      ];
    },
    runStep: async (_cfg: unknown, _step: unknown, spec: EdgeSpec) => {
      seen.push({
        call: 'runStep',
        hostname: spec.hostname,
        originPort: spec.listeners[0]?.members[0]?.port,
      });
      const resourceId = `rec-${minted.size + 1}`;
      if (spec.hostname) minted.set(resourceId, spec.hostname);
      return {
        status: 'done',
        resources: [{ kind: 'dns_record', resourceId, ownership: 'created' }],
        addresses: { hostname: spec.hostname },
      };
    },
    discover: async () => ({ status: 'unresolved' }),
    describe: async (_cfg: unknown, ledger: Ledger) => {
      const live = ledger.resources.find(
        (r: LedgerResource) => r.deleteState !== 'confirmed_gone' && minted.has(r.resourceId),
      );
      const hostname = live ? minted.get(live.resourceId) : undefined;
      return {
        state: hostname ? 'active' : 'pending',
        addresses: hostname ? { hostname } : {},
        health: 'unknown',
        readiness: { dns: 'ready', certificate: 'ready' },
      };
    },
    inspect: async () => ({ summary: { addresses: {}, members: [], listeners: [] }, raw: {} }),
    inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
    planDestroy: (_cfg: unknown, ledger: Ledger) =>
      ledger.resources.filter((r: LedgerResource) => r.deleteState !== 'confirmed_gone'),
    runDestroy: async () => ({ status: 'confirmed_gone' }),
  } as unknown as EdgeProvider;
  __setEdgeProviderForTests('cloudflare', provider);
  return { seen, uninstall: () => __setEdgeProviderForTests('cloudflare', null) };
}

// --- driving the scheduler -----------------------------------------------------------------------

/** Run every scheduled function (steps, rotations, reconciles, wakes) until `until` holds. */
async function drive<R>(t: T, read: () => Promise<R>, until: (r: R) => boolean, what: string) {
  for (let i = 0; i < 800; i++) {
    const r = await read();
    if (until(r)) return r;
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
  }
  const last = (await read()) as {
    stage?: string;
    state?: string;
    need?: unknown;
    events?: unknown[];
  };
  throw new Error(
    `drive: ${what} did not settle: ${JSON.stringify({
      stage: last?.stage,
      state: last?.state,
      need: last?.need,
      events: last?.events?.slice(-6),
    })}`,
  );
}

const intentOf = (t: T, id: Id<'panelNodeIntents'>) => t.run((c) => c.db.get(id)).then((r) => r!);
const setupRun = (t: T, id: Id<'edgeSetupRuns'>) =>
  t.query(internal.edgeSetupRuns.get, { id }).then((r) => r!);
const activationRun = (t: T, id: Id<'panelActivationRuns'>) =>
  t.run((c) => c.db.get(id)).then((r) => r!);
const parked = (r: { state: string; need?: { code: string } }) =>
  r.state === 'needs_you' || ['done', 'done_unbound', 'failed', 'cancelled'].includes(r.state);
/** Settled after an approval: finished, or waiting for something OTHER than the approval. */
const movedOn = (r: { state: string; need?: { code: string } }) =>
  ['done', 'done_unbound', 'failed', 'cancelled'].includes(r.state) ||
  (r.state === 'needs_you' && r.need?.code !== 'node_not_approved');

// --- the world -------------------------------------------------------------------------------------

interface World {
  t: T;
  serverId: Id<'backendServers'>;
  backend: FakeBackend;
  calls: {
    rehearsedEdges: string[][];
    s3: Array<{ op: S3Op; provider: string }>;
    /** Every restore workflow a setup run started (by purpose). */
    restores: string[];
  };
  hooks: {
    /** Runs once before the next rehearsal reads anything (a move while the run is at 7). */
    beforeRehearsal: (() => Promise<void>) | null;
    /** Runs once after the next rehearsal returned (a policy move between 7 and 8). */
    afterRehearsal: (() => Promise<void>) | null;
    /** While set, every rehearsal fails (the run waits at `rehearsal_failed`). */
    holdRehearsal: boolean;
    /** Runs once during the next S3 put (a policy move while an upload is in flight). */
    duringPut: (() => Promise<void>) | null;
    /** While set, the provider refuses every load-balancer create (a provider error). */
    failProviderCreate: boolean;
  };
}

/** Families on (a REALITY mode binds one), one family with a qualified name. */
async function seedFamily(t: T) {
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-fronted',
    label: 'fam-fronted',
    targetAddress: 'decoy-b.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: 'fam-fronted',
    lines: ['decoy-b.example'],
  });
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
}

/** The fake backend + UpCloud (after any handler that answers first) as the one global fetch. */
function installFetch(backend: FakeBackend, first: PartialHandler[] = []) {
  const upcloud = createFakeUpcloud();
  mockFetch(routeFetch(...first, backend.handle, upcloud.handle));
  return upcloud;
}

async function world(): Promise<World> {
  vi.useFakeTimers();
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const backend = createFakeBackend();
  const hooks: World['hooks'] = {
    beforeRehearsal: null,
    afterRehearsal: null,
    holdRehearsal: false,
    duringPut: null,
    failProviderCreate: false,
  };
  installFetch(backend, [
    (c) =>
      hooks.failProviderCreate &&
      new URL(c.url).hostname === 'api.upcloud.com' &&
      c.path === '/1.3/load-balancer' &&
      c.method === 'POST'
        ? jsonRes({ error: { error_code: 'INTERNAL' } }, 500)
        : null,
  ]);
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await seedFamily(t);
  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input: setupInput,
  });
  await drive(
    t,
    () => t.run((c) => c.db.get(started.setupId)),
    (s) => !!s && !s.claim && (s.state === 'ready' || s.state === 'failed'),
    'backend setup',
  );
  expect((await t.run((c) => c.db.get(started.setupId)))!.state).toBe('ready');
  const calls: World['calls'] = { rehearsedEdges: [], s3: [], restores: [] };
  return { t, serverId, backend, calls, hooks };
}

/** Enroll a node of `mode`, report it applied, and wait for `machine_ready`. */
async function enrollReady(
  w: World,
  opts: { name: string; mode: 'freedom-reality' | 'freedom-ws'; v4: string; hostname?: string },
) {
  const { t, serverId } = w;
  const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
    backendServerId: serverId,
    name: opts.name,
    mode: opts.mode,
    contractVersion: 2,
    observed: {
      management: { address: '192.0.2.20', port: 2222 },
      publicIps: { v4: opts.v4 },
      capabilities: { caddy: opts.mode === 'freedom-ws', ipv6: false },
    },
  });
  await drive(
    t,
    () => intentOf(t, intentId),
    (i) => !i.claim,
    'enrollment',
  );
  let revision = 1;
  if (opts.hostname) {
    // A WebSocket node's origin name (no managed zone here): an FCP-owned setting.
    const r = await t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: opts.hostname },
    });
    revision = r.machineRevision;
    await drive(
      t,
      () => intentOf(t, intentId),
      (i) => !i.claim,
      'the settings reconcile',
    );
  }
  await t.mutation(internal.nodeIntents.applied, {
    intentId,
    appliedRevision: revision,
    nodeStarted: true,
  });
  const intent = await drive(
    t,
    () => intentOf(t, intentId),
    (i) => !i.claim && i.activation.stage === 'machine_ready',
    'machine_ready',
  );
  expect(intent.delivery.disposition).toBe('staged');
  return intentId;
}

/** The probe round "lands" for an L4 standby: two outside vantages + a passing internal shape run. */
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
 * The seams this file uses, and only these: outside probe evidence, the WS
 * origin probe, the external-hop ingress check and the L7 proof's session (no
 * sockets here). Everything else (the qualification credential, the test link
 * the card shows, Host hides, the rehearsal over the backend's real bodies,
 * the rotations, go-live) is the production code.
 */
function installSeams(w: World) {
  const { t } = w;
  const ops: Partial<StageOps> = {
    requestVerificationProbes: async (_ctx, edgeId) => {
      await landPartialEvidence(t, edgeId);
    },
    rehearse: async (ctx, a) => {
      const before = w.hooks.beforeRehearsal;
      w.hooks.beforeRehearsal = null;
      if (before) await before();
      // The production rehearsal, with a record of which edges it rendered.
      const c = await ctx.runQuery(internal.edgeRehearsal.context, {
        relayId: a.relayId,
        darkCohortKeys: a.darkCohortKeys,
        ...(a.activationRunId ? { activationRunId: a.activationRunId } : {}),
        cohorts: await walkRelayCohorts(ctx, a.relayId),
      });
      w.calls.rehearsedEdges.push((c?.published ?? []).map((p) => p.edgeId as string).sort());
      const res = await ctx.runAction(internal.edgeRehearsal.run, a);
      const after = w.hooks.afterRehearsal;
      w.hooks.afterRehearsal = null;
      if (after) await after();
      if (w.hooks.holdRehearsal)
        return {
          ...res,
          ok: false,
          failures: [{ cohortKey: 'hold', format: 'links' as const, reason: 'hold' }],
        };
      return res;
    },
    restoreStart: async (_ctx, a) => {
      w.calls.restores.push(a.purpose);
    },
  };
  __setStageOpsForTests(ops);
  __setPlanOpsForTests({
    probeOrigins: async (_ctx, a) =>
      a.targets.map((tg) => ({
        listenerKey: tg.listenerKey,
        originTransport: {
          scheme: 'https' as const,
          certPublic: true,
          certNames: [tg.originAddress],
          // The probe's strict reading (a decoy answering 404 at `/`): the
          // node's own verified ingress decides for an enrolled node.
          acceptsHostHeader: 'names' as const,
        },
      })),
  });
  __setFrontIngressCheckForTests(async (a) => ({
    resolves: true,
    answers: { v4: [a.expected.v4 ?? ''], v6: [] },
    tlsValid: true,
    certNames: [a.hostname],
    pathProxied: true,
    foreignHostAnswered: true,
  }));
  __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
  __setS3SendForTests(async (provider, op) => {
    w.calls.s3.push({ op, provider: provider.name });
    const during = w.hooks.duringPut;
    w.hooks.duringPut = null;
    if (op.kind === 'put' && during) await during();
  });
}

/** An admin HTTP caller with a full-privilege cookie (Servers and Edges routes). */
async function adminCookie(t: T): Promise<string> {
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: `op-${Math.random().toString(36).slice(2, 6)}`,
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  return `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
}

async function servers(t: T, cookie: string, method: string, path: string, body?: unknown) {
  return t.fetch(`/api/v1/admin/servers/${FIXTURE_PANEL_SLUG}/${path}`, {
    method,
    headers: { cookie, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Approve a node over HTTP exactly as the card does: read the review, approve its hash. */
async function approveOverHttp(t: T, cookie: string, intentId: Id<'panelNodeIntents'>) {
  const res = await servers(t, cookie, 'GET', `nodes/intents/${intentId}/review`);
  expect(res.status).toBe(200);
  const review = ActivationReview.parse(await res.json());
  expect(review.blockers).toEqual([]);
  const ok = await servers(t, cookie, 'POST', `nodes/intents/${intentId}/approve`, {
    reviewHash: review.reviewHash,
  });
  expect(ok.status).toBe(200);
  return {
    review,
    runId: (await ok.json()).runId as Id<'panelActivationRuns'>,
  };
}

/** Tick every pending test link exactly as the card would. */
async function tickAll(t: T, runId: Id<'edgeSetupRuns'>) {
  const r = await setupRun(t, runId);
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

/** Protect a ready node: plan, create, drive through try_it, park at publish. */
async function protectToPark(
  w: World,
  opts: { nodeName: string; accountId: Id<'edgeProviderAccounts'> },
): Promise<Id<'edgeSetupRuns'>> {
  const { t, serverId } = w;
  const node = (
    await t.run((c) =>
      c.db
        .query('backendNodeInventory')
        .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
        .collect(),
    )
  ).find((n) => n.name === opts.nodeName);
  // The inventory learned the node at enrollment (no manual refresh).
  expect(node).toBeTruthy();
  const plan = await t.action(internal.edgeSetupPlan.plan, {
    backendServerId: serverId,
    nodeUuid: node!.nodeUuid,
  });
  const res = await t.action(internal.edgeSetupPlan.create, {
    backendServerId: serverId,
    nodeUuid: node!.nodeUuid,
    accountId: opts.accountId,
    planHash: plan.planHash,
    approvedHideUuids: [],
  });
  const runId = res.runId as Id<'edgeSetupRuns'>;
  let r = await drive(t, () => setupRun(t, runId), parked, 'setup run');
  if (r.need?.code === 'try_it') {
    // The card's links are real: built from the node's own transport (no Host
    // exists before publication), pointing at the candidate edge, never the origin.
    for (const l of r.testLinks ?? []) {
      expect(l.method).toBe('test_link');
      expect(l.link).toMatch(/^vless:\/\/[0-9a-f-]+@198\.51\.100\.\d+:\d+\?.*security=reality/);
      // The flow the backend gives a REALITY account over raw TCP (Xray refuses any other).
      expect(l.link).toContain('flow=xtls-rprx-vision');
      expect(l.link).not.toContain('203.0.113.');
    }
    await tickAll(t, runId);
    r = await drive(t, () => setupRun(t, runId), parked, 'setup run after the ticks');
  }
  expect([r.stage, r.state, r.need?.code]).toEqual(['publish', 'needs_you', 'node_not_approved']);
  return runId;
}

/** A member whose key is pinned to `node` (one cohort), fetched over the real /sub route. */
async function seedMember(w: World, node: string, token = 'tok_member') {
  const { t, serverId, backend } = w;
  backend.users.push({
    uuid: '77777777-7777-4777-8777-777777777777',
    shortUuid: 'short-member',
    vlessUuid: 'aaaaaaaa-1111-4222-8333-444444444444',
    username: 'member',
    status: 'ACTIVE',
    subscriptionUrl: 'https://panel.example/api/sub/short-member',
  });
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      supportId: 'SUP-1',
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: '77777777-7777-4777-8777-777777777777',
      backendShortId: 'short-member',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/api/sub/short-member',
      subscriptionMirrors: [],
      subToken: token,
      state: 'active',
      pinnedNode: node,
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return subId;
  });
}

const fetchSub = (t: T, ua = LINKS_UA, token = 'tok_member') =>
  t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });

/** A tested UpCloud account (L4) and a tested Cloudflare account (L7, the fake adapter). */
async function accounts(t: T) {
  const l4 = await createAccount(t, { provider: 'upcloud', name: 'acct-l4' });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: l4, ok: true });
  const l7 = await createAccount(t, { provider: 'cloudflare', name: 'acct-l7' });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: l7, ok: true });
  await t.run((ctx) =>
    ctx.db.patch(l7, {
      observedSettings: JSON.stringify({ zoneSslMode: 'full' }),
      observedAt: Date.now(),
    }),
  );
  return { l4, l7 };
}

async function relayOfRun(t: T, runId: Id<'edgeSetupRuns'>) {
  const r = await setupRun(t, runId);
  return (await t.run((c) => c.db.get(r.relayId!)))!;
}

const gateOf = (t: T, serverId: Id<'backendServers'>, nodeName = NODE) =>
  gateOfNode(t, { backendServerId: serverId, nodeName });

// --- the golden path ------------------------------------------------------------------------------

/** A live freedom-reality node with one member, through the whole golden path. */
async function liveL4(w: World) {
  const { t } = w;
  installSeams(w);
  const accts = await accounts(t);
  const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
  const subId = await seedMember(w, NODE);
  const cookie = await adminCookie(t);
  const runId = await protectToPark(w, { nodeName: NODE, accountId: accts.l4 });
  const { runId: actId } = await approveOverHttp(t, cookie, intentId);
  const done = await drive(t, () => setupRun(t, runId), movedOn, 'setup run after approval');
  expect([done.stage, done.state]).toEqual(['done', 'done']);
  const act = await activationRun(t, actId);
  const e1 = act.resources.edgeIds[0] as Id<'edges'>;
  const relayId = done.relayId!;
  return { ...accts, intentId, subId, cookie, runId, actId, e1, relayId };
}

const edgeAddress = (t: T, id: Id<'edges'>) =>
  t.run((c) => c.db.get(id)).then((e) => e!.addresses.v4 ?? e!.addresses.hostname!);

describe('a fronted node goes from enrollment to members', () => {
  test('freedom-reality (L4): parked at publish with nothing published, approved over HTTP, live with the edge', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    await seedMember(w, NODE);
    const cookie = await adminCookie(t);

    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    // Parked, not failed: no publish rotation exists and nothing is published.
    const relay = await relayOfRun(t, runId);
    expect(relay.publishedEdgeIds.filter(Boolean)).toEqual([]);
    const rotations = await t.run((c) =>
      c.db
        .query('edgeRotations')
        .collect()
        .then((rs) => rs.filter((x) => x.relayId === relay._id && x.kind === 'publish')),
    );
    expect(rotations).toEqual([]);
    const held = await setupRun(t, runId);
    expect(held.events.some((e) => e.code === 'publish_held')).toBe(true);
    // The origin's credential is minted in the node's OWN mode, so its body
    // can ever carry this node's transport.
    const binding = await t.query(internal.relayQualification.ensureContext, {
      relayId: relay._id,
    });
    expect(binding?.modeSlug).toBe('freedom-reality');
    expect(held.need?.detail).toBe('machine_ready');
    // The progress view names the enrolled node the approval card calls.
    const view = SetupRunAdmin.parse(
      await t.query(internal.edgeSetupRuns.getForAdmin, { id: runId }),
    );
    expect(view.enrolled).toEqual({
      slug: FIXTURE_PANEL_SLUG,
      intentId: intentId as string,
      stage: 'machine_ready',
    });
    // Members are held off a node that is not live.
    expect((await gateOf(t, serverId)).state).toBe('blocked');
    expect((await fetchSub(t)).status).toBe(503);

    // The approval card: the review shows the standby, and approving wakes the run.
    const { review, runId: actId } = await approveOverHttp(t, cookie, intentId);
    expect(review.shape.listeners).toHaveLength(1);
    expect(review.display.standbys[0]).toMatchObject({ layer: 'l4', accountName: 'acct-l4' });
    const linked = await setupRun(t, runId);
    expect(linked.activationRunId).toBe(actId);
    expect((await activationRun(t, actId)).setupRunId).toBe(runId);

    const done = await drive(t, () => setupRun(t, runId), movedOn, 'setup run after approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    const act = await activationRun(t, actId);
    expect(act.state).toBe('committed');
    const intent = await intentOf(t, intentId);
    expect(intent.delivery.disposition).toBe('live');
    expect(intent.activation.stage).toBe('live');
    expect(intent.approved?.committed.edgeIds.length).toBe(1);
    expect((await gateOf(t, serverId)).state).toBe('open');
    expect(await deliveryBindingOf(t, { backendServerId: serverId, nodeName: NODE })).toBeTruthy();
    // The rehearsal rendered exactly the activation's candidates.
    expect(w.calls.rehearsedEdges.at(-1)).toEqual(act.resources.edgeIds.map(String).sort());

    // The member now gets the rendered body: the edge's PUBLIC address, never the origin.
    const address = await edgeAddress(t, act.resources.edgeIds[0] as Id<'edges'>);
    for (const ua of [LINKS_UA, SINGBOX_UA]) {
      const res = await fetchSub(t, ua);
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain(address);
      expect(body).not.toContain(ORIGIN_V4);
    }
  });

  test('freedom-ws (L7): the loopback WebSocket is frontable at L7 by its origin name, and parks at publish without a tick', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const l7Fake = installFakeL7();
    try {
      const { l7 } = await accounts(t);
      const intentId = await enrollReady(w, {
        name: NODE_W,
        mode: 'freedom-ws',
        v4: ORIGIN_W_V4,
        hostname: ORIGIN_W_NAME,
      });
      await seedMember(w, NODE_W);
      // The plan reads the node from its intent: the origin NAME (never the
      // management address) and the ingress that makes the loopback WS frontable.
      const node = (
        await t.run((c) =>
          c.db
            .query('backendNodeInventory')
            .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
            .collect(),
        )
      ).find((n) => n.name === NODE_W)!;
      const plan = await t.action(internal.edgeSetupPlan.plan, {
        backendServerId: serverId,
        nodeUuid: node.nodeUuid,
      });
      expect(plan.originAddress).toBe(ORIGIN_W_NAME);
      expect(plan.enrolled).toBe(true);
      const ws = plan.inbounds.filter((i) => i.frontable);
      expect(ws).toHaveLength(1);
      expect(ws[0]!.layers).toContain('l7');
      expect(plan.accounts.find((a) => a.id === (l7 as string))?.compatible).toBe(true);

      const runId = await protectToPark(w, { nodeName: NODE_W, accountId: l7 });
      const parkedRun = await setupRun(t, runId);
      // An L7 front is proven by its own session, never ticked by hand.
      expect(parkedRun.testLinks ?? []).toEqual([]);
      expect(parkedRun.listeners.every((l) => l.layer === 'l7' && l.verify === 'verified')).toBe(
        true,
      );
      expect(l7Fake.seen.some((x) => x.call === 'runStep')).toBe(true);

      const cookie = await adminCookie(t);
      const { runId: actId } = await approveOverHttp(t, cookie, intentId);
      const done = await drive(t, () => setupRun(t, runId), movedOn, 'L7 run after approval');
      expect([done.stage, done.state]).toEqual(['done', 'done']);
      expect((await activationRun(t, actId)).state).toBe('committed');
      expect((await gateOf(t, serverId, NODE_W)).state).toBe('open');
      const front = await edgeAddress(
        t,
        (await activationRun(t, actId)).resources.edgeIds[0] as Id<'edges'>,
      );
      // The listener's Host says TLS over the loopback transport's plaintext:
      // without it the backend renders `security=none` and nothing resolves.
      const host = w.backend.hosts.find((h) => String(h.remark).startsWith(`${NODE_W}-`));
      expect(host?.securityLayer).toBe('TLS');
      const res = await fetchSub(t, SINGBOX_UA);
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain(front);
      expect(body).not.toContain(ORIGIN_W_V4);
    } finally {
      l7Fake.uninstall();
    }
  });
});

// --- a live node's replacement --------------------------------------------------------------------

describe("a live node's replacement stays a candidate until its commit", () => {
  test('through publication, a failed promotion and a re-approval: never in a member body, a cache or a mirror; its rehearsal renders the candidates', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    // A mirror the member already holds.
    await t.run(async (ctx) => {
      await ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.example',
        bucket: 'b',
        publicUrl: 'https://cdn.example',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.patch(live.subId, {
        subscriptionMirrors: [
          {
            provider: 'p1',
            publicUrl: 'https://cdn.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
        ],
      });
    });
    const accountB = await createAccount(t, { provider: 'upcloud', name: 'acct-l4-b' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountB, ok: true });

    // A protect run on the live node's origin with ANOTHER account: a shape
    // the committed approval never named. (The origin is handed to the run
    // here; reaching it from the UI is not this test's subject.)
    await t.run((c) => c.db.patch(live.relayId, { setupOwned: true, setupStage: 'provision' }));
    const runId = await protectToPark(w, { nodeName: NODE, accountId: accountB });
    const parked1 = await setupRun(t, runId);
    const e2 = parked1.listeners[0]!.edgeId!;
    expect(e2).not.toBe(live.e1);
    const e2Address = await edgeAddress(t, e2);

    // A live listener whose Host pointer is not a committed edge cannot take a
    // candidate with the gate open: the review asks for maintenance first.
    const listenerId = (await t.run((c) => c.db.get(live.e1)))!.listenerId;
    await t.run((c) => c.db.patch(listenerId, { templateEdgeId: undefined }));
    const isolation = await t.query(internal.nodeActivation.review, { intentId: live.intentId });
    expect(isolation.blockers).toContain('servers.maintenance_required');
    await t.run((c) => c.db.patch(listenerId, { templateEdgeId: live.e1 }));

    // Approve; the candidate is published; the promotion fails (a revision
    // moved between the rehearsal and go-live): the activation is blocked.
    w.hooks.afterRehearsal = () =>
      t.run((c) => c.db.patch(live.intentId, { deliveryRevision: 'moved' })).then(() => {});
    const { runId: act2 } = await approveOverHttp(t, live.cookie, live.intentId);
    expect((await activationRun(t, act2)).resources.edgeIds).toEqual([e2]);
    const blocked = await drive(
      t,
      () => setupRun(t, runId),
      (r) => movedOn(r) || (r.stage === 'go_live' && r.state === 'needs_you'),
      'run to the failed promotion',
    );
    expect(blocked.state).toBe('needs_you');
    expect(blocked.need).toEqual({ code: 'node_not_approved', detail: 'servers.revision_moved' });
    expect((await activationRun(t, act2)).state).toBe('blocked');
    const relay = (await t.run((c) => c.db.get(live.relayId)))!;
    expect(relay.publishedEdgeIds).toContain(e2);
    // The rehearsal rendered the CANDIDATE, not the committed edge members hold.
    expect(w.calls.rehearsedEdges.at(-1)).toEqual([e2 as string]);
    // Members still get the committed edge, and nothing else: body, cache, mirror.
    const intent = await intentOf(t, live.intentId);
    expect(intent.delivery.disposition).toBe('live');
    for (const ua of [LINKS_UA, SINGBOX_UA]) {
      const body = await (await fetchSub(t, ua)).text();
      expect(body).toContain(e1Address);
      expect(body).not.toContain(e2Address);
    }
    const cache = (await t.run((c) => c.db.get(live.subId)))!.subCache ?? '';
    expect(cache).toContain(e1Address);
    expect(cache).not.toContain(e2Address);
    await t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: live.subId,
      force: true,
    });
    const put = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(put.body).toContain(e1Address);
    expect(put.body).not.toContain(e2Address);

    // A re-approval is a new candidate: the run returns to the rehearsal (a
    // fresh one), then commits. Only now do members get the replacement.
    const rehearsalsBefore = w.calls.rehearsedEdges.length;
    const { runId: act3 } = await approveOverHttp(t, live.cookie, live.intentId);
    expect((await activationRun(t, act2)).state).toBe('superseded');
    const done = await drive(t, () => setupRun(t, runId), movedOn, 'run after the re-approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    expect(done.events.some((e) => e.code === 'approved' && e.detail === 'back at rehearse')).toBe(
      true,
    );
    expect(w.calls.rehearsedEdges.length).toBeGreaterThan(rehearsalsBefore);
    expect(w.calls.rehearsedEdges.at(-1)).toEqual([e2 as string]);
    expect((await activationRun(t, act3)).state).toBe('committed');
    const member = await t.query(internal.edgeRender.decideForSubscription, {
      subscriptionId: live.subId,
      family: 'other',
    });
    expect(member.kind).toBe('render');
    if (member.kind === 'render')
      expect(member.context.published.map((p) => p.edgeId)).toContain(e2);
    expect((await gateOf(t, serverId)).candidates.edgeIds).toEqual([]);
    // What members are served stays committed: the edge it replaced beside the
    // new one (still published), so the next review is not mistaken for a new Host.
    const after = await intentOf(t, live.intentId);
    expect([...after.approved!.committed.edgeIds].sort()).toEqual(
      [live.e1 as string, e2 as string].sort(),
    );
    const next = await t.query(internal.nodeActivation.review, { intentId: live.intentId });
    expect(next.blockers).not.toContain('servers.maintenance_required');
  });

  test('a re-protect within the approved shape reaches done without a new approval', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    // The same account and template: the replacement address reuses the approval.
    await t.run((c) => c.db.patch(live.relayId, { setupOwned: true, setupStage: 'provision' }));
    const node = (await t.run((c) => c.db.query('backendNodeInventory').collect())).find(
      (n) => n.name === NODE,
    )!;
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: w.serverId,
      nodeUuid: node.nodeUuid,
    });
    const res = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: w.serverId,
      nodeUuid: node.nodeUuid,
      accountId: live.l4,
      planHash: plan.planHash,
      approvedHideUuids: [],
    });
    const runId = res.runId as Id<'edgeSetupRuns'>;
    let r = await drive(t, () => setupRun(t, runId), parked, 're-protect');
    if (r.need?.code === 'try_it') {
      await tickAll(t, runId);
      r = await drive(t, () => setupRun(t, runId), parked, 're-protect after the ticks');
    }
    expect([r.stage, r.state]).toEqual(['done', 'done']);
    expect(r.activationRunId).toBeUndefined();
    const runs = await t.run((c) => c.db.query('panelActivationRuns').collect());
    expect(runs.filter((x) => x.state === 'committed')).toHaveLength(1);
  });
});

// --- re-protect: its own run kind -------------------------------------------------------------------

/** POST an Edges admin route exactly as the node page does (admin cookie, JSON body). */
async function edgesPost(t: T, cookie: string, path: string, body: unknown = {}) {
  return t.fetch(`/api/v1/admin/edges/${path}`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** "Protect again" on the node page: the run it started. */
async function reprotectOverHttp(t: T, cookie: string, relayId: Id<'relays'>) {
  const res = await edgesPost(t, cookie, `relays/${relayId}/reprotect`);
  expect(res.status).toBe(200);
  const created = SetupRunCreatedResponse.parse(await res.json());
  expect(created.stage).toBe('prepare');
  return created.runId as Id<'edgeSetupRuns'>;
}

/** The refusal code of an Edges admin response. */
const errorCode = async (res: Response) =>
  ((await res.json()) as { error: { code: string } }).error.code;

/** What a pinned member's links body holds now: the committed address, never the origin. */
async function memberBody(t: T, committed: string, absent: string[] = []) {
  const res = await fetchSub(t);
  expect(res.status).toBe(200);
  const body = await res.text();
  expect(body).toContain(committed);
  expect(body).not.toContain(ORIGIN_V4);
  for (const a of absent) expect(body).not.toContain(a);
  return body;
}

const relayRow = (t: T, id: Id<'relays'>) => t.run((c) => c.db.get(id)).then((r) => r!);
const bindingOf = (t: T, serverId: Id<'backendServers'>) =>
  deliveryBindingOf(t, { backendServerId: serverId, nodeName: NODE });

/** A re-protect run driven to its first card, with the fresh candidate it provisioned. */
async function reprotectToTryIt(w: World, live: Awaited<ReturnType<typeof liveL4>>) {
  const { t } = w;
  const runId = await reprotectOverHttp(t, live.cookie, live.relayId);
  const r = await drive(t, () => setupRun(t, runId), parked, 're-protect to the card');
  expect([r.stage, r.state, r.need?.code]).toEqual(['try_it', 'needs_you', 'try_it']);
  const e2 = r.listeners[0]!.edgeId!;
  return { runId, run: r, e2, e2Address: await edgeAddress(t, e2) };
}

describe('re-protect a live node (its own run kind)', () => {
  test('within the approved shape, over HTTP: a fresh candidate with a real test link, members keep the committed edge at every step, done without a new approval', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    await memberBody(t, e1Address);

    const desiredBefore = (await relayRow(t, live.relayId)).desiredPublished;
    const { runId, run, e2, e2Address } = await reprotectToTryIt(w, live);
    const view = SetupRunAdmin.parse(
      await t.query(internal.edgeSetupRuns.getForAdmin, { id: runId }),
    );
    expect(view.kind).toBe('reprotect');
    expect(view.relayId).toBe(live.relayId);
    // A NEW address, never the committed one (no reuse of what members hold).
    expect(e2).not.toBe(live.e1);
    expect(e2Address).not.toBe(e1Address);
    // A real test link for it (a fresh address, so no named-connection retest).
    expect(run.testLinks).toHaveLength(1);
    const link = run.testLinks![0]!;
    expect(link.method).toBe('test_link');
    expect(link.edgeId).toBe(e2);
    expect(link.link).toMatch(/^vless:\/\/[0-9a-f-]+@198\.51\.100\.\d+:\d+\?.*security=reality/);
    expect(link.link).toContain(e2Address);
    expect(link.link).not.toContain(ORIGIN_V4);
    // The origin is owned while the run lasts; members keep exactly what they had.
    expect((await relayRow(t, live.relayId)).setupOwned).toBe(true);
    expect((await gateOf(t, serverId)).state).toBe('open');
    await memberBody(t, e1Address, [e2Address]);

    // After the publish (the committed approval admits a replacement address
    // in its shape), checked as the rehearsal starts.
    let atRehearsal: { body: string; published: Array<Id<'edges'> | null> } | null = null;
    w.hooks.beforeRehearsal = async () => {
      atRehearsal = {
        body: await (await fetchSub(t)).text(),
        published: (await relayRow(t, live.relayId)).publishedEdgeIds,
      };
    };
    await tickAll(t, runId);
    const done = await drive(t, () => setupRun(t, runId), movedOn, 're-protect after the ticks');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    expect(done.activationRunId).toBeUndefined();
    const seen = atRehearsal as { body: string; published: Array<Id<'edges'> | null> } | null;
    expect(seen?.published).toContain(e2);
    expect(seen?.body).toContain(e1Address);
    expect(seen?.body).not.toContain(ORIGIN_V4);

    // Done: the new address took the old one's place (it drains, as after a
    // Replace), the pool is its old size again, the node is handed back.
    const relay = await relayRow(t, live.relayId);
    expect(relay.publishedEdgeIds.filter(Boolean)).toEqual([e2]);
    expect((await t.run((c) => c.db.get(live.e1)))!.publication).toBe('draining');
    expect(relay.desiredPublished).toBe(desiredBefore);
    expect(relay.setupOwned).toBeUndefined();
    expect(relay.setupStage).toBeUndefined();
    expect(await bindingOf(t, serverId)).toBeTruthy();
    expect((await gateOf(t, serverId)).state).toBe('open');
    await memberBody(t, e2Address, [e1Address]);
    // No new approval was needed: the one committed activation is the original.
    const acts = await t.run((c) => c.db.query('panelActivationRuns').collect());
    expect(acts.map((a) => a.state)).toEqual(['committed']);
    const started = await t.run((c) =>
      c.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.setup_run.started'))
        .collect(),
    );
    expect(started.at(-1)?.payload).toMatchObject({ kind: 'reprotect', stage: 'prepare' });
  });

  test('outside the approved shape: parks for the approval, the candidate stays isolated until go-live promotes it', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    // The node's delivery moved since its commit: the committed approval no
    // longer admits a new address, so the candidate needs a review.
    await t.run((c) => c.db.patch(live.intentId, { deliveryRevision: 'moved' }));

    const { runId, e2, e2Address } = await reprotectToTryIt(w, live);
    await tickAll(t, runId);
    const held = await drive(t, () => setupRun(t, runId), parked, 're-protect to the approval');
    expect([held.stage, held.state, held.need?.code]).toEqual([
      'publish',
      'needs_you',
      'node_not_approved',
    ]);
    expect((await relayRow(t, live.relayId)).publishedEdgeIds).not.toContain(e2);
    await memberBody(t, e1Address, [e2Address]);

    // Approved over HTTP: the candidate publishes, isolated from members.
    let atRehearsal: { body: string; published: Array<Id<'edges'> | null> } | null = null;
    w.hooks.beforeRehearsal = async () => {
      atRehearsal = {
        body: await (await fetchSub(t)).text(),
        published: (await relayRow(t, live.relayId)).publishedEdgeIds,
      };
    };
    const { review, runId: actId } = await approveOverHttp(t, live.cookie, live.intentId);
    expect(review.display.standbys[0]).toMatchObject({ layer: 'l4', accountName: 'acct-l4' });
    expect((await activationRun(t, actId)).resources.edgeIds).toEqual([e2]);
    const done = await drive(t, () => setupRun(t, runId), movedOn, 're-protect after approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    const seen = atRehearsal as { body: string; published: Array<Id<'edges'> | null> } | null;
    expect(seen?.published).toContain(e2);
    expect(seen?.body).toContain(e1Address);
    expect(seen?.body).not.toContain(e2Address);
    expect(seen?.body).not.toContain(ORIGIN_V4);
    expect(w.calls.rehearsedEdges.at(-1)).toEqual([e2 as string]);

    // Promoted at go-live: members get the replacement, which took the old
    // address's place (the old one drains, as after a Replace).
    expect((await activationRun(t, actId)).state).toBe('committed');
    expect((await gateOf(t, serverId)).candidates.edgeIds).toEqual([]);
    await memberBody(t, e2Address, [e1Address]);
    expect((await t.run((c) => c.db.get(live.e1)))!.publication).toBe('draining');
    expect((await relayRow(t, live.relayId)).setupOwned).toBeUndefined();
  });

  test('cancel at the card drops only the candidate: binding, committed edge, gate and members untouched, nothing deleted or restored', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    const bindingBefore = await bindingOf(t, serverId);
    const { runId, e2, e2Address } = await reprotectToTryIt(w, live);
    // While the run owns the origin, the pool takes no write by hand: the
    // committed address and the run's slot stay where they are.
    for (const path of [`${live.e1}/unpublish`, `relays/${live.relayId}/rebalance`]) {
      const refused = await edgesPost(t, live.cookie, path);
      expect(refused.status).toBe(409);
      expect(await errorCode(refused)).toBe('edge.setup_owned');
    }
    expect((await relayRow(t, live.relayId)).publishedEdgeIds).toContain(live.e1);

    const res = await edgesPost(t, live.cookie, `setup-runs/${runId}/cancel`);
    expect(res.status).toBe(200);
    expect(SetupRunCancelResponse.parse(await res.json())).toEqual({
      ok: true,
      disposition: 'candidates',
    });
    expect((await setupRun(t, runId)).state).toBe('cancelled');
    // The candidate is cancelled for the reconcile destroy; the committed edge stays.
    expect((await t.run((c) => c.db.get(e2)))!.status).toBe('cancelled');
    const e1 = (await t.run((c) => c.db.get(live.e1)))!;
    expect([e1.publication, e1.status]).toEqual(['published', 'active']);
    const relay = await relayRow(t, live.relayId);
    expect(relay.publishedEdgeIds).toContain(live.e1);
    expect(relay.deleting).toBeFalsy();
    expect(relay.restore).toBeUndefined();
    expect(relay.setupOwned).toBeUndefined();
    expect(w.calls.restores).toEqual([]);
    const binding = await bindingOf(t, serverId);
    expect(binding?.state).toBe('active');
    expect(binding?.policyVersion).toBe(bindingBefore?.policyVersion);
    expect((await gateOf(t, serverId)).state).toBe('open');
    expect((await intentOf(t, live.intentId)).delivery.disposition).toBe('live');
    await memberBody(t, e1Address, [e2Address]);
    const cancelled = await t.run((c) =>
      c.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.setup_run.cancelled'))
        .collect(),
    );
    expect(cancelled.at(-1)?.payload).toMatchObject({ disposition: 'candidates' });
    // The node is handed back: it can be protected again at once.
    expect((await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`)).status).toBe(200);
  });

  test('cancel after the approval drains the published candidate and blocks the activation; the committed delivery stays', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    await t.run((c) => c.db.patch(live.intentId, { deliveryRevision: 'moved' }));
    const { runId, e2, e2Address } = await reprotectToTryIt(w, live);
    await tickAll(t, runId);
    await drive(t, () => setupRun(t, runId), parked, 're-protect to the approval');
    // The run publishes the approved candidate and then waits at its rehearsal.
    w.hooks.holdRehearsal = true;
    const { runId: actId } = await approveOverHttp(t, live.cookie, live.intentId);
    const held = await drive(t, () => setupRun(t, runId), movedOn, 'run to the held rehearsal');
    expect([held.stage, held.need?.code]).toEqual(['rehearse', 'rehearsal_failed']);
    expect((await relayRow(t, live.relayId)).publishedEdgeIds).toContain(e2);
    expect((await gateOf(t, serverId)).candidates.edgeIds).toEqual([e2 as string]);
    await memberBody(t, e1Address, [e2Address]);

    const res = await edgesPost(t, live.cookie, `setup-runs/${runId}/cancel`);
    expect(res.status).toBe(200);
    expect(SetupRunCancelResponse.parse(await res.json()).disposition).toBe('candidates');
    // The candidate left the pool to drain; the committed edge is untouched.
    const cand = (await t.run((c) => c.db.get(e2)))!;
    expect([cand.publication, cand.status]).toEqual(['draining', 'draining']);
    const relay = await relayRow(t, live.relayId);
    expect(relay.publishedEdgeIds).not.toContain(e2);
    expect(relay.publishedEdgeIds).toContain(live.e1);
    expect(relay.setupOwned).toBeUndefined();
    expect(relay.restore).toBeUndefined();
    expect(w.calls.restores).toEqual([]);
    // The activation it was bound to is blocked; the live node keeps serving.
    const act = await activationRun(t, actId);
    expect([act.state, act.code]).toEqual(['blocked', 'servers.setup_run_cancelled']);
    expect((await intentOf(t, live.intentId)).delivery.disposition).toBe('live');
    expect((await gateOf(t, serverId)).state).toBe('open');
    expect((await bindingOf(t, serverId))?.state).toBe('active');
    await memberBody(t, e1Address, [e2Address]);
  });

  test('a failure leaves the live node live and hands the origin back; retry claims it again', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    w.hooks.failProviderCreate = true;
    const runId = await reprotectOverHttp(t, live.cookie, live.relayId);
    const failed = await drive(t, () => setupRun(t, runId), parked, 're-protect to the failure');
    expect([failed.stage, failed.state, failed.need?.code]).toEqual([
      'provision',
      'failed',
      'provider_failed',
    ]);
    const relay = await relayRow(t, live.relayId);
    expect(relay.setupOwned).toBeUndefined();
    expect(relay.setupStage).toBeUndefined();
    expect(relay.publishedEdgeIds).toContain(live.e1);
    expect((await bindingOf(t, serverId))?.state).toBe('active');
    expect((await gateOf(t, serverId)).state).toBe('open');
    await memberBody(t, e1Address);

    // Switched off since the failure: the retry does not claim it again.
    await t.run((c) => c.db.patch(live.relayId, { enabled: false }));
    const off = await edgesPost(t, live.cookie, `setup-runs/${runId}/retry`);
    expect(off.status).toBe(409);
    expect(await errorCode(off)).toBe('edge.relay_disabled');
    expect((await relayRow(t, live.relayId)).setupOwned).toBeUndefined();
    await t.run((c) => c.db.patch(live.relayId, { enabled: true }));

    // The provider recovers: retry claims the origin again and carries on.
    w.hooks.failProviderCreate = false;
    const retried = await edgesPost(t, live.cookie, `setup-runs/${runId}/retry`);
    expect(retried.status).toBe(200);
    const owned = await relayRow(t, live.relayId);
    expect([owned.setupOwned, owned.setupStage]).toEqual([true, 'provision']);
    const again = await drive(t, () => setupRun(t, runId), parked, 're-protect after the retry');
    expect([again.stage, again.need?.code]).toEqual(['try_it', 'try_it']);
    expect(again.listeners[0]!.edgeId).not.toBe(live.e1);
    await memberBody(t, e1Address);
  });

  test('refusals: a second run, an unmanaged node and a deleting origin, as HTTP codes', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    const runId = await reprotectOverHttp(t, live.cookie, live.relayId);
    const second = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(second.status).toBe(409);
    expect(await errorCode(second)).toBe('edge.setup_run_active');
    expect((await edgesPost(t, live.cookie, `setup-runs/${runId}/cancel`)).status).toBe(200);
    // A failed run's retry claims the origin again only while nothing else owns it.
    await t.run((c) => c.db.patch(live.relayId, { setupOwned: true }));
    await t.run((c) => c.db.patch(runId, { state: 'failed' }));
    await expect(t.mutation(internal.edgeSetupRuns.retry, { runId })).rejects.toThrow(
      /setup_run_active/,
    );
    await t.run((c) => c.db.patch(live.relayId, { setupOwned: undefined }));
    // Not while the node is being renamed (its rotations would be refused mid-run).
    const renameId = await t.run((c) =>
      c.db.insert('panelNodeRenames', {
        backendServerId: w.serverId,
        nodeUuid: '00000000-0000-4000-8000-000000000001',
        from: NODE,
        to: 'node-renamed',
        relayIds: [live.relayId],
        state: 'running',
        step: 'backend',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((c) => c.db.patch(live.relayId, { renaming: { renameId, since: Date.now() } }));
    const renaming = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(renaming.status).toBe(409);
    expect(await errorCode(renaming)).toBe('edge.panel_op_running');
    await t.run((c) => c.db.patch(live.relayId, { renaming: undefined }));
    // A node the role never enrolled is not protected again from here.
    await t.run((c) => c.db.delete(live.intentId));
    const unmanaged = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(unmanaged.status).toBe(409);
    expect(await errorCode(unmanaged)).toBe('edge.reprotect_not_enrolled');
    // An origin being deleted is gone.
    await t.run((c) => c.db.patch(live.relayId, { deleting: true }));
    const gone = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(gone.status).toBe(404);
    expect(await errorCode(gone)).toBe('not_found');
  });

  test('cancel drops every new address of the run, also one a committed admission already published', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1Address = await edgeAddress(t, live.e1);
    const desiredBefore = (await relayRow(t, live.relayId)).desiredPublished;
    const { runId, e2, e2Address } = await reprotectToTryIt(w, live);
    // Within the approved shape the new address is published under the
    // committed admission (no candidate), then the run waits at its rehearsal.
    w.hooks.holdRehearsal = true;
    await tickAll(t, runId);
    const held = await drive(t, () => setupRun(t, runId), parked, 'run to the held rehearsal');
    expect([held.stage, held.need?.code]).toEqual(['rehearse', 'rehearsal_failed']);
    expect((await relayRow(t, live.relayId)).publishedEdgeIds).toContain(e2);
    expect((await gateOf(t, serverId)).candidates.edgeIds).toEqual([]);

    const res = await edgesPost(t, live.cookie, `setup-runs/${runId}/cancel`);
    expect(res.status).toBe(200);
    expect(SetupRunCancelResponse.parse(await res.json()).disposition).toBe('candidates');
    // The run's own address leaves the pool to drain; the committed one stays.
    const dropped = (await t.run((c) => c.db.get(e2)))!;
    expect([dropped.publication, dropped.status]).toEqual(['draining', 'draining']);
    const relay = await relayRow(t, live.relayId);
    expect(relay.publishedEdgeIds.filter(Boolean)).toEqual([live.e1]);
    expect(relay.desiredPublished).toBe(desiredBefore);
    expect(relay.setupOwned).toBeUndefined();
    expect((await bindingOf(t, serverId))?.state).toBe('active');
    await memberBody(t, e1Address, [e2Address]);
  });

  test('a full pool gets room for the new address, and Protect again twice in a row goes live both times', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    // Nothing free in the pool: each new address must be given room.
    await t.run((c) => c.db.patch(live.relayId, { desiredPublished: 1 }));
    let current = live.e1;
    for (const round of [1, 2]) {
      const { runId, e2, e2Address } = await reprotectToTryIt(w, live);
      expect((await relayRow(t, live.relayId)).desiredPublished).toBe(2);
      await tickAll(t, runId);
      const done = await drive(t, () => setupRun(t, runId), movedOn, `re-protect ${round}`);
      expect([done.stage, done.state]).toEqual(['done', 'done']);
      // The new address took the old one's place; the room is given back,
      // with no hole left below it (a hole would admit a second publication).
      const relay = await relayRow(t, live.relayId);
      expect(relay.publishedEdgeIds).toEqual([e2]);
      expect((await t.run((c) => c.db.get(e2)))!.poolIndex).toBe(0);
      expect(relay.desiredPublished).toBe(1);
      expect((await t.run((c) => c.db.get(current)))!.publication).toBe('draining');
      expect((await bindingOf(t, serverId))?.state).toBe('active');
      await memberBody(t, e2Address);
      current = e2;
    }
  });

  test('refused with no room left, and for an origin served through more than one account', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    // Already at the most addresses one origin may use.
    const full = Array.from({ length: 8 }, () => live.e1);
    await t.run((c) => c.db.patch(live.relayId, { publishedEdgeIds: full, desiredPublished: 8 }));
    const noRoom = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(noRoom.status).toBe(409);
    expect(await errorCode(noRoom)).toBe('edge.reprotect_no_room');
    expect((await relayRow(t, live.relayId)).setupOwned).toBeFalsy();
    await t.run((c) =>
      c.db.patch(live.relayId, { publishedEdgeIds: [live.e1], desiredPublished: 2 }),
    );
    // A second transport served through another account.
    await t.run(async (c) => {
      const e1 = (await c.db.get(live.e1))!;
      const l1 = (await c.db.get(e1.listenerId))!;
      const { _id: _l, _creationTime: _lc, ...listener } = l1;
      const l2 = await c.db.insert('relayListeners', { ...listener, listenerKey: 'second' });
      const { _id: _e, _creationTime: _ec, ...edge } = e1;
      const e2 = await c.db.insert('edges', { ...edge, listenerId: l2, accountId: live.l7 });
      await c.db.patch(l2, { templateEdgeId: e2 });
      await c.db.patch(live.relayId, { publishedEdgeIds: [live.e1, e2], desiredPublished: 3 });
    });
    const mixed = await edgesPost(t, live.cookie, `relays/${live.relayId}/reprotect`);
    expect(mixed.status).toBe(409);
    expect(await errorCode(mixed)).toBe('edge.reprotect_mixed_accounts');
  });

  test('a node not live behind its origin yet is refused: protect it first', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    const relay = await relayOfRun(t, runId);
    expect(relay.bindingDeferred).toBe(true);
    const res = await edgesPost(t, cookie, `relays/${relay._id}/reprotect`);
    expect(res.status).toBe(409);
    expect(await errorCode(res)).toBe('edge.reprotect_not_bound');
    // The first protection is untouched by the refusal.
    expect((await setupRun(t, runId)).state).toBe('needs_you');
  });
});

// --- fencing ----------------------------------------------------------------------------------------

describe('ownership links and attempt fencing', () => {
  test('approve, wake, retry, cancel: the cancel blocks exactly the bound activation; stale wakes and end hooks do nothing', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    w.hooks.holdRehearsal = true;
    const approvedAt = (await setupRun(t, runId)).generation;
    const { runId: actId } = await approveOverHttp(t, cookie, intentId);
    const held = await drive(t, () => setupRun(t, runId), movedOn, 'run to the held rehearsal');
    expect(held.need?.code).toBe('rehearsal_failed');
    expect(held.activationRunId).toBe(actId);
    // A wake of the approval-time attempt is a no-op now.
    expect(
      await t.mutation(internal.edgeSetupRuns.wakeForApproval, {
        setupRunId: runId,
        activationRunId: actId,
        generation: approvedAt,
      }),
    ).toEqual({ acted: false, reason: 'generation' });
    // Retry: a new attempt, the same ownership.
    const before = await setupRun(t, runId);
    await t.mutation(internal.edgeSetupRuns.retry, { runId });
    const again = await drive(t, () => setupRun(t, runId), movedOn, 'run after the retry');
    expect(again.generation).toBe(before.generation + 1);
    expect(again.activationRunId).toBe(actId);
    // An end hook for the replaced attempt does nothing.
    await t.run((ctx) => onSetupRunEnded(ctx, before, before.generation));
    expect((await activationRun(t, actId)).state).toBe('running');
    // An end hook from ANOTHER (older) setup run never touches this activation.
    const older = await t.run(async (ctx) => {
      const id = await ctx.db.insert('edgeSetupRuns', {
        ...(({ _id, _creationTime, ...rest }) => rest)(before),
        state: 'failed',
        generation: 1,
      });
      return (await ctx.db.get(id))!;
    });
    await t.run((ctx) => onSetupRunEnded(ctx, older, 1));
    expect((await activationRun(t, actId)).state).toBe('running');

    // Cancel after the approval: the activation it was bound to is blocked,
    // and the node parks for a fresh approval with nothing served.
    await t.action(internal.edgeSetupRuns.cancel, { runId });
    const act = await activationRun(t, actId);
    expect(act.state).toBe('blocked');
    expect(act.code).toBe('servers.setup_run_cancelled');
    const intent = await intentOf(t, intentId);
    expect(intent.activation.stage).toBe('awaiting_approval');
    expect(intent.activation.currentRunId).toBeUndefined();
    expect(intent.delivery.disposition).toBe('staged');
    expect((await gateOf(t, serverId)).state).toBe('blocked');
  });

  test('a candidate that stops fitting its approval before it publishes blocks the activation: a fresh approval is possible and wakes the run', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    const parkedAt = (await setupRun(t, runId)).generation;
    const { runId: actId } = await approveOverHttp(t, cookie, intentId);
    // Before the wake publishes, the standby is moved to another account under it.
    const other = await createAccount(t, { provider: 'upcloud', name: 'acct-l4-other' });
    const edgeId = (await setupRun(t, runId)).listeners[0]!.edgeId!;
    await t.run((c) => c.db.patch(edgeId, { accountId: other }));
    const held = await drive(
      t,
      () => setupRun(t, runId),
      (r) =>
        (r.generation > parkedAt && r.state === 'needs_you') ||
        ['done', 'failed', 'cancelled'].includes(r.state),
      'run to the refused publication',
    );
    expect([held.stage, held.need?.code]).toEqual(['publish', 'node_not_approved']);
    expect((await activationRun(t, actId)).state).toBe('blocked');
    expect((await activationRun(t, actId)).code).toBe('servers.review_stale');
    expect((await intentOf(t, intentId)).activation.stage).toBe('awaiting_approval');
    // The review describes the new shape and can be approved; that approval wakes the run.
    const { runId: act2 } = await approveOverHttp(t, cookie, intentId);
    const done = await drive(t, () => setupRun(t, runId), movedOn, 'run after the re-approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    expect((await activationRun(t, act2)).state).toBe('committed');
  });

  test('an activation superseded while the run rehearses waits for the next approval, which wakes it', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    // A maintenance pass on the node while the run is at its rehearsal.
    w.hooks.beforeRehearsal = async () => {
      await t.mutation(internal.nodeIntents.startMaintenance, { intentId });
      await t.mutation(internal.nodeIntents.finishMaintenance, { intentId });
    };
    const { runId: act1 } = await approveOverHttp(t, cookie, intentId);
    const waiting = await drive(
      t,
      () => setupRun(t, runId),
      (r) => movedOn(r) || (r.stage === 'rehearse' && r.state === 'needs_you'),
      'run to the superseded rehearsal',
    );
    expect([waiting.stage, waiting.state, waiting.need?.code]).toEqual([
      'rehearse',
      'needs_you',
      'node_not_approved',
    ]);
    expect((await activationRun(t, act1)).state).toBe('superseded');
    await drive(
      t,
      () => intentOf(t, intentId),
      (i) => !i.claim,
      'the reconcile after maintenance',
    );
    const { runId: act2 } = await approveOverHttp(t, cookie, intentId);
    const done = await drive(t, () => setupRun(t, runId), movedOn, 'run after the next approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    expect((await activationRun(t, act2)).state).toBe('committed');
  });

  test('a go-live waiting for a fresh approval can be cancelled; nothing was bound', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    // The candidate goes stale between the rehearsal and go-live.
    w.hooks.afterRehearsal = () =>
      t.run((c) => c.db.patch(intentId, { deliveryRevision: 'moved' })).then(() => {});
    const { runId: actId } = await approveOverHttp(t, cookie, intentId);
    const waiting = await drive(
      t,
      () => setupRun(t, runId),
      (r) => r.stage === 'go_live' && r.state === 'needs_you',
      'run to the stale candidate',
    );
    expect(waiting.need?.code).toBe('node_not_approved');
    expect((await activationRun(t, actId)).state).toBe('blocked');
    const res = await t.action(internal.edgeSetupRuns.cancel, { runId });
    expect(res.disposition).toBe('restore');
    expect((await setupRun(t, runId)).state).toBe('cancelled');
    expect(await deliveryBindingOf(t, { backendServerId: serverId, nodeName: NODE })).toBeNull();
    expect((await gateOf(t, serverId)).state).toBe('blocked');
  });

  test('approve during try_it is refused; an approval that lands before the publish check never parks', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const node = (await t.run((c) => c.db.query('backendNodeInventory').collect())).find(
      (n) => n.name === NODE,
    )!;
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: w.serverId,
      nodeUuid: node.nodeUuid,
    });
    const { runId: created } = await t.action(internal.edgeSetupPlan.create, {
      backendServerId: w.serverId,
      nodeUuid: node.nodeUuid,
      accountId: l4,
      planHash: plan.planHash,
      approvedHideUuids: [],
    });
    const runId = created as Id<'edgeSetupRuns'>;
    const tryIt = await drive(t, () => setupRun(t, runId), parked, 'run to try_it');
    expect(tryIt.need?.code).toBe('try_it');
    const review = await t.query(internal.nodeActivation.review, { intentId });
    expect(review.blockers).toContain('servers.standbys_unverified');
    await expect(
      t.mutation(internal.nodeActivation.approve, { intentId, reviewHash: review.reviewHash }),
    ).rejects.toThrow(/standbys_unverified/);
    // The ticks land and the approval follows at once, before the publish step runs.
    await tickAll(t, runId);
    const ready = await t.query(internal.nodeActivation.review, { intentId });
    expect(ready.blockers).toEqual([]);
    const { runId: actId } = await t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: ready.reviewHash,
    });
    // What the approval named is the shape: an edge of another account is a new review.
    const standby = (await t.run((c) => c.db.get(tryIt.listeners[0]!.edgeId!)))!;
    const listener = (await t.run((c) => c.db.get(standby.listenerId)))!;
    expect(
      await t.run((ctx) =>
        publicationAdmission(ctx, w.serverId, NODE, {
          listenerKey: listener.listenerKey,
          accountId: 'another-account',
          templateHash: standby.templateHash ?? null,
        }),
      ),
    ).toEqual({ kind: 'refused', code: 'servers.review_stale' });
    const done = await drive(t, () => setupRun(t, runId), movedOn, 'run after an early approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
    expect(done.events.some((e) => e.code === 'publish_held')).toBe(false);
    expect((await activationRun(t, actId)).state).toBe('committed');
  });
});

// --- refusals ---------------------------------------------------------------------------------------

describe('enrollment', () => {
  test('a settings change while the enrollment reconcile runs hands the claim over to the new generation', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: NODE_W,
      mode: 'freedom-ws',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.20', port: 2222 },
        publicIps: { v4: ORIGIN_W_V4 },
        capabilities: { caddy: true, ipv6: false },
      },
    });
    // The operator's origin name lands while the enrollment's reconcile holds the claim.
    expect((await intentOf(t, intentId)).claim).toBeTruthy();
    const { machineRevision } = await t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: ORIGIN_W_NAME },
    });
    const settled = await drive(
      t,
      () => intentOf(t, intentId),
      (i) => !i.claim,
      'the claim',
    );
    expect(settled.machineRevision).toBe(machineRevision);
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: machineRevision,
      nodeStarted: true,
    });
    const ready = await drive(
      t,
      () => intentOf(t, intentId),
      (i) => !i.claim && i.activation.stage === 'machine_ready',
      'machine_ready',
    );
    expect(ready.activation.evidence.some((e) => e.kind === 'ingress_verified')).toBe(true);
  });
});

describe('refusals', () => {
  test('keepDirect is refused for an enrolled fronted node at create and at resume', async () => {
    const w = await world();
    const { t, serverId } = w;
    installSeams(w);
    const { l4 } = await accounts(t);
    await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const node = (await t.run((c) => c.db.query('backendNodeInventory').collect())).find(
      (n) => n.name === NODE,
    )!;
    const plan = await t.action(internal.edgeSetupPlan.plan, {
      backendServerId: serverId,
      nodeUuid: node.nodeUuid,
    });
    await expect(
      t.action(internal.edgeSetupPlan.create, {
        backendServerId: serverId,
        nodeUuid: node.nodeUuid,
        accountId: l4,
        planHash: plan.planHash,
        approvedHideUuids: [],
        keepDirect: true,
      }),
    ).rejects.toThrow(/keep_direct_enrolled/);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: l4 });
    // The one resume path that could finish unbound (a changed Host review).
    await t.run((c) => c.db.patch(runId, { need: { code: 'review_changed' } }));
    await expect(
      t.mutation(internal.edgeSetupRuns.resume, { runId, keepDirect: true }),
    ).rejects.toThrow(/keep_direct_enrolled/);
    expect((await setupRun(t, runId)).state).toBe('needs_you');
  });

  test('a publication outside the approved shape is refused: another account for a candidate or a committed node', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    const e1 = (await t.run((c) => c.db.get(live.e1)))!;
    const listener = (await t.run((c) => c.db.get(e1.listenerId)))!;
    const admission = (accountId: string | null, templateHash = e1.templateHash ?? null) =>
      t.run((ctx) =>
        publicationAdmission(ctx, serverId, NODE, {
          listenerKey: listener.listenerKey,
          accountId,
          templateHash,
        }),
      );
    // A replacement address in the committed shape reuses the approval.
    expect((await admission(String(live.l4))).kind).toBe('committed');
    // Another account or template needs a review.
    expect(await admission(String(live.l7))).toEqual({
      kind: 'refused',
      code: 'servers.node_not_approved',
    });
    expect(await admission(String(live.l4), 'another-template')).toEqual({
      kind: 'refused',
      code: 'servers.node_not_approved',
    });
    // Revisions moved since the commit: no publication rides the old approval.
    await t.run((c) => c.db.patch(live.intentId, { deliveryRevision: 'moved' }));
    expect((await admission(String(live.l4))).kind).toBe('refused');
  });
});

describe("an L4 endpoint tick binds to the enrolled node's REALITY key", () => {
  /** The node's REALITY key (or a short id, or a clock bound) moves: its auth digest changes. */
  const rekey = (t: T, intentId: Id<'panelNodeIntents'>) =>
    t.run((c) => c.db.patch(intentId, { authRevision: 'auth-moved' }));

  test('a key move before approval: approval refuses until each address is tried again, then succeeds', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const accts = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    await seedMember(w, NODE);
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: accts.l4 });
    const l4 = (await setupRun(t, runId)).listeners
      .filter((l) => l.layer === 'l4')
      .map((l) => l.edgeId as Id<'edges'>);
    expect(l4.length).toBeGreaterThan(0);
    // Ticked and approvable before the key moves.
    expect((await t.query(internal.nodeActivation.review, { intentId })).blockers).toEqual([]);

    await rekey(t, intentId);
    const review = await t.query(internal.nodeActivation.review, { intentId });
    // The review card says why; the refusal keeps its code.
    expect(review.blockers).toContain('servers.standbys_unverified:key_changed');
    await expect(
      t.mutation(internal.nodeActivation.approve, { intentId, reviewHash: review.reviewHash }),
    ).rejects.toThrow(/servers\.standbys_unverified/);
    const stale = (await t.query(internal.edgeOperator.attention, {})).items.filter(
      (i) => i.kind === 'retest_needed',
    );
    expect(stale.map((i) => i.code)).toEqual(l4.map(() => 'reality_key_changed'));
    // The binding a client echoes keeps its shape: the digest is folded in, never shown.
    const binding = (await t.query(internal.edgeVerification.binding, { edgeId: l4[0]! }))!;
    expect(JSON.stringify(binding)).not.toContain('auth-moved');

    // Try it again with the new key: the tick binds to it, and the approval follows.
    for (const e of l4) await verifyL4Edge(t, e);
    const rec = (await t.run((c) => c.db.get(l4[0]!)))!.verification!;
    expect(rec.authRevision).toBe('auth-moved');
    await approveOverHttp(t, cookie, intentId);
    const done = await drive(t, () => setupRun(t, runId), movedOn, 'setup run after approval');
    expect([done.stage, done.state]).toEqual(['done', 'done']);
  });

  test('an L7 front (proven by its own session) is not held by a key move', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const l7Fake = installFakeL7();
    try {
      const { l7 } = await accounts(t);
      const intentId = await enrollReady(w, {
        name: NODE_W,
        mode: 'freedom-ws',
        v4: ORIGIN_W_V4,
        hostname: ORIGIN_W_NAME,
      });
      await seedMember(w, NODE_W);
      await protectToPark(w, { nodeName: NODE_W, accountId: l7 });
      await rekey(t, intentId);
      const review = await t.query(internal.nodeActivation.review, { intentId });
      expect(review.blockers.filter((b) => b.startsWith('servers.standbys'))).toEqual([]);
    } finally {
      l7Fake.uninstall();
    }
  });

  test('a key move on a LIVE node is drift: it closes exactly as before, and its addresses need the tick again', async () => {
    const w = await world();
    const { t, serverId } = w;
    const live = await liveL4(w);
    expect((await fetchSub(t)).status).toBe(200);
    const intent = (await t.run((c) => c.db.get(live.intentId)))!;
    await t.run((c) =>
      c.db.patch(live.intentId, { claim: { attemptId: 'a-1', expiresAt: Date.now() + 60_000 } }),
    );
    const r = await t.mutation(internal.nodeIntents.observeRevisions, {
      intentId: live.intentId,
      generation: intent.generation,
      attemptId: 'a-1',
      configRevision: intent.configRevision!,
      authRevision: 'auth-moved',
      hostMoved: false,
      ownChange: true,
    });
    expect(r).toEqual({ ok: true, drift: true });
    const after = (await t.run((c) => c.db.get(live.intentId)))!;
    expect(after.delivery.disposition).toBe('unavailable');
    expect(after.maintenance?.reason).toBe('drift');
    expect((await gateOf(t, serverId)).state).toBe('blocked');
    // Members were held off by the drift, as before: the gate, not the tick, answers.
    const res = await fetchSub(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('node_gated');
    // The served address's tick no longer counts under the new key.
    const view = await t.query(internal.edgeVerification.binding, { edgeId: live.e1 });
    expect(view?.verification.current).toBe(false);
  });
});

describe('the operator hears about a node that waits on them', () => {
  test('ready to protect, then waiting for approval, then nothing once live', async () => {
    const w = await world();
    const { t } = w;
    installSeams(w);
    const accts = await accounts(t);
    const intentId = await enrollReady(w, { name: NODE, mode: 'freedom-reality', v4: ORIGIN_V4 });
    const nodeItems = async () =>
      (await t.query(internal.edgeOperator.attention, {})).items.filter((i) =>
        i.kind.startsWith('node_'),
      );
    const ready = await nodeItems();
    expect(ready).toEqual([
      expect.objectContaining({
        id: `node_ready_to_protect:${intentId}`,
        kind: 'node_ready_to_protect',
        action: 'protect_node',
        facts: expect.objectContaining({ serverSlug: FIXTURE_PANEL_SLUG, node: NODE }),
      }),
    ]);
    await seedMember(w, NODE);
    const cookie = await adminCookie(t);
    const runId = await protectToPark(w, { nodeName: NODE, accountId: accts.l4 });
    expect(await nodeItems()).toEqual([
      expect.objectContaining({
        kind: 'node_awaiting_approval',
        code: 'node_not_approved',
        action: 'open_node',
        facts: expect.objectContaining({ runId }),
      }),
    ]);
    await approveOverHttp(t, cookie, intentId);
    await drive(t, () => setupRun(t, runId), movedOn, 'setup run after approval');
    expect(await nodeItems()).toEqual([]);
  });
});

describe('automatic work on a live node stays in its approved shape', () => {
  test('a replace or a pool fill picks only an account (or a spare) the node was approved for, else it is refused', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    // A second L4 account, trusted and preferred: outside the committed shape.
    const other = await createAccount(t, { provider: 'upcloud', name: 'acct-l4-b' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: other, ok: true });
    for (const id of [live.l4, other])
      await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    // (A lower priority number is picked first.)
    await t.run((c) => c.db.patch(other, { priority: -100 }));
    const e1 = (await t.run((c) => c.db.get(live.e1)))!;
    const select = (kind: 'replace' | 'provision') =>
      t.run(async (ctx) => {
        const origin = (await ctx.db.get(live.relayId))!;
        return selectionContext(
          ctx,
          kind === 'replace'
            ? { kind, trigger: 'manual', listenerId: e1.listenerId }
            : { kind, trigger: 'reconcile', listenerId: e1.listenerId, publishOnDone: true },
          origin,
          kind === 'replace' ? e1 : null,
          await resolveEdgeConfig(ctx.db),
        );
      });
    // The preferred account is passed over: only the approved one fits.
    expect((await select('replace')).account?.id).toBe(live.l4);
    expect((await select('provision')).account?.id).toBe(live.l4);
    // A standby provision (not published by the run) is not held to the shape.
    const standby = await t.run(async (ctx) =>
      selectionContext(
        ctx,
        { kind: 'provision', trigger: 'reconcile', listenerId: e1.listenerId },
        (await ctx.db.get(live.relayId))!,
        null,
        await resolveEdgeConfig(ctx.db),
      ),
    );
    expect(standby.account?.id).toBe(other);
    // The approved account gone: nothing fits, and a new review is the way forward.
    await t.run((c) => c.db.patch(live.l4, { enabled: false }));
    expect(await select('replace')).toMatchObject({
      account: null,
      accountFailure: 'outside_approved_shape',
    });
    // An automatic pool fill is refused at the start (no failed rotation every tick).
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId: live.relayId,
        kind: 'provision',
        trigger: 'reconcile',
        publishOnDone: true,
        listenerId: e1.listenerId,
      }),
    ).rejects.toThrow(/approved for/);
    const rotations = await t.run((c) =>
      c.db
        .query('edgeRotations')
        .withIndex('by_relay', (q) => q.eq('relayId', live.relayId))
        .collect(),
    );
    expect(rotations.every((r) => r.trigger !== 'reconcile')).toBe(true);
    // Where the result is published the approval is checked again: an edge
    // outside the shape (here an import from the other account) stays a
    // standby and the pool is untouched.
    const spare = await t.mutation(internal.relays.adoptEdge, {
      relayId: live.relayId,
      listenerId: e1.listenerId,
      ipv4: '198.51.100.88',
      verified: true,
      accountId: other,
    });
    const before = (await t.run((c) => c.db.get(live.relayId)))!;
    const rotationId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId: live.relayId,
        kind: 'provision',
        trigger: 'reconcile',
        publishOnDone: true,
        burn: false,
        force: false,
        toEdgeId: spare.edgeId as Id<'edges'>,
        listenerId: e1.listenerId,
        phase: 'publishing',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((c) => c.db.patch(live.relayId, { activeRotationId: rotationId }));
    const res = await t.mutation(internal.edgeRotations.applyPublish, {
      rotationId,
      stepVersion: 1,
    });
    expect(res).toMatchObject({ ok: true, poolIndex: null });
    const after = (await t.run((c) => c.db.get(live.relayId)))!;
    expect(after.publishedEdgeIds).toEqual(before.publishedEdgeIds);
    expect(after.standbyEdgeIds).toContain(spare.edgeId);
    const rot = (await t.run((c) => c.db.get(rotationId)))!;
    expect(rot.events.map((e) => e.code)).toContain('outside_approved_shape');
    await t.run((c) => c.db.patch(live.relayId, { activeRotationId: undefined }));

    // A REPLACE whose new edge lands outside the shape keeps its target served:
    // nothing was swapped, so the finalize drains nothing and records no rotation.
    const replaceId = await t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId: live.relayId,
        kind: 'replace',
        trigger: 'detector',
        burn: true,
        force: false,
        targetEdgeId: live.e1,
        toEdgeId: spare.edgeId as Id<'edges'>,
        listenerId: e1.listenerId,
        phase: 'publishing',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await t.run((c) => c.db.patch(live.relayId, { activeRotationId: replaceId }));
    expect(
      await t.mutation(internal.edgeRotations.applyPublish, {
        rotationId: replaceId,
        stepVersion: 1,
      }),
    ).toMatchObject({ ok: true, poolIndex: null });
    expect(
      await t.mutation(internal.edgeRotations.finalize, { rotationId: replaceId, stepVersion: 2 }),
    ).toEqual({ ok: true });
    const target = (await t.run((c) => c.db.get(live.e1)))!;
    expect([target.publication, target.status, target.burnedAt]).toEqual([
      'published',
      'active',
      undefined,
    ]);
    expect((await t.run((c) => c.db.get(live.relayId)))!.publishedEdgeIds).toEqual(
      before.publishedEdgeIds,
    );
    const rotated = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.rotated'))
        .collect(),
    );
    expect(
      rotated.some((a) => (a.payload as { rotationId?: string }).rotationId === replaceId),
    ).toBe(false);

    // Pool upkeep's direct standby publish holds the spare to the shape too:
    // with a free slot, the out-of-shape spare stays a spare...
    await t.run((c) => c.db.patch(live.relayId, { desiredPublished: 2 }));
    expect(
      await t.mutation(internal.edgeReconcileMutations.publishStandby, {
        relayId: live.relayId,
        candidates: [spare.edgeId as Id<'edges'>],
      }),
    ).toEqual({ published: false, rotationId: null, awaitingVerification: false });
    expect((await t.run((c) => c.db.get(spare.edgeId as Id<'edges'>)))!.publication).toBe(
      'unpublished',
    );
    // ...and the same spare in the approved shape is published.
    await t.run((c) =>
      c.db.patch(spare.edgeId as Id<'edges'>, {
        accountId: live.l4,
        templateHash: e1.templateHash,
      }),
    );
    await t.run((c) => c.db.patch(live.l4, { enabled: true }));
    // (The account change moved the endpoint's configuration: confirm it again.)
    await verifyL4Edge(t, spare.edgeId as Id<'edges'>);
    expect(
      await t.mutation(internal.edgeReconcileMutations.publishStandby, {
        relayId: live.relayId,
        candidates: [spare.edgeId as Id<'edges'>],
      }),
    ).toMatchObject({ published: true });
  });
});

// --- the mirror barrier -----------------------------------------------------------------------------

describe('the mirror barrier', () => {
  async function withMirrorProvider(t: T) {
    await t.run((ctx) =>
      ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.example',
        bucket: 'b',
        publicUrl: 'https://cdn.example',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('a refresh whose upload a policy move overtook stays open, and the next pass re-renders it under the policy that holds', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    await t.run((ctx) =>
      ctx.db.patch(live.subId, {
        subscriptionMirrors: [
          {
            provider: 'p1',
            publicUrl: 'https://cdn.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
        ],
      }),
    );
    // The node closes for maintenance WHILE the rendered body is uploading.
    w.hooks.duringPut = () =>
      t.mutation(internal.nodeIntents.startMaintenance, { intentId: live.intentId }).then(() => {});
    await t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: live.subId,
      force: true,
    });
    const stale = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(stale.body).toContain(await edgeAddress(t, live.e1));
    const open = await openMirrorUploads(t, { subscriptionId: live.subId });
    expect(open).toHaveLength(1);
    expect(open[0]!.kind).toBe('refresh');

    // Within the in-flight grace the repair leaves it alone; after it, the
    // object is re-rendered under the CURRENT policy: the node is gated, so
    // the mirror stops serving the edge (the unavailable stub).
    await t.action(internal.storage.repairMirrorUploads, {});
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toHaveLength(1);
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    const repaired = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(repaired.body).toBe(MIRROR_UNAVAILABLE_STUB);
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toEqual([]);
  });

  test("a first mirror's upload overtaken by a policy move is repaired the same way", async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    const userId = (await t.run((c) => c.db.get(live.subId)))!.userId;
    w.hooks.duringPut = () =>
      t.mutation(internal.nodeIntents.startMaintenance, { intentId: live.intentId }).then(() => {});
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('ok');
    const open = await openMirrorUploads(t, { subscriptionId: live.subId });
    expect(open.map((o) => o.kind)).toEqual(['initial']);
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    const repaired = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(repaired.body).toBe(MIRROR_UNAVAILABLE_STUB);
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toEqual([]);
  });

  test('a provider that keeps failing keeps ONE open record for its copy (the repair retries it), and it settles once that copy is rewritten', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('mirrorProviders', {
        name: 'p2',
        endpoint: 'https://s3-2.example',
        bucket: 'b2',
        publicUrl: 'https://cdn-2.example',
        region: 'auto',
        accessKeyId: 'ak2',
        secretAccessKey: 'sk2',
        isActive: true,
        priority: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.patch(live.subId, {
        subscriptionMirrors: [
          {
            provider: 'p1',
            publicUrl: 'https://cdn.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
          {
            provider: 'p2',
            publicUrl: 'https://cdn-2.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
        ],
      });
    });
    __setS3SendForTests(async (provider) => {
      if (provider.name === 'p2') throw new Error('provider down');
    });
    for (let i = 0; i < 3; i++)
      await t.action(internal.storage.refreshMirrorsForSubscription, {
        subscriptionId: live.subId,
        force: true,
      });
    // The copy that was not rewritten may still serve an older policy's body.
    const left = await openMirrorUploads(t, { subscriptionId: live.subId });
    expect(left.map((o) => o.providers)).toEqual([['p2']]);
    // The provider recovers: the repair rewrites its copy and the record settles.
    __setS3SendForTests(async () => {});
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toEqual([]);
    // A policy that keeps moving under the uploads leaves ONE open record, not one per pass.
    __setS3SendForTests(async () => {
      await t.run((c) =>
        c.db.patch(live.intentId, { updatedAt: Date.now() }).then(() =>
          c.db
            .query('panelSetups')
            .withIndex('by_server', (q) => q.eq('backendServerId', w.serverId))
            .unique()
            .then((s) => c.db.patch(s!._id, { gateVersion: s!.gateVersion + 1 })),
        ),
      );
    });
    for (let i = 0; i < 3; i++) {
      vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
      await t.action(internal.storage.refreshMirrorsForSubscription, {
        subscriptionId: live.subId,
        force: true,
      });
      await t.action(internal.storage.repairMirrorUploads, {});
    }
    expect((await openMirrorUploads(t, { subscriptionId: live.subId })).length).toBeLessThanOrEqual(
      1,
    );
  });

  test('a re-issue that carries the mirror takes its open record along: the repair rewrites the object, never withdraws it', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    await t.run((ctx) =>
      ctx.db.patch(live.subId, {
        subscriptionMirrors: [
          {
            provider: 'p1',
            publicUrl: 'https://cdn.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
        ],
      }),
    );
    w.hooks.duringPut = () =>
      t.mutation(internal.nodeIntents.startMaintenance, { intentId: live.intentId }).then(() => {});
    await t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: live.subId,
      force: true,
    });
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toHaveLength(1);
    // The member's key is re-issued: the mirror moves to the new row.
    const old = (await t.run((c) => c.db.get(live.subId)))!;
    const newSub = await t.mutation(internal.subscriptions.insertSubscription, {
      userId: old.userId,
      backend: 'remnawave',
      backendUserId: old.backendUserId,
      backendShortId: old.backendShortId,
      backendServerId: old.backendServerId,
      subscriptionUrl: old.subscriptionUrl,
      subscriptionMirrors: [],
      carrySubTokenFromId: live.subId,
    });
    expect(await openMirrorUploads(t, { subscriptionId: newSub })).toHaveLength(1);
    const deletesBefore = w.calls.s3.filter((x) => x.op.kind === 'delete').length;
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    expect(w.calls.s3.filter((x) => x.op.kind === 'delete').length).toBe(deletesBefore);
    const rewritten = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(rewritten.body).toBe(MIRROR_UNAVAILABLE_STUB);
    expect(await openMirrorUploads(t, { subscriptionId: newSub })).toEqual([]);
  });

  test('a residue copy whose delete fails stays open until the delete goes through', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    // An upload of a copy nothing references any more (a lost first mirror).
    const { id } = await t.mutation(internal.mirrorUploads.open, {
      subscriptionId: live.subId,
      objectPath: 'mirrors/orphan',
      providers: ['p1'],
      tokenBefore: null,
      kind: 'initial',
    });
    __setS3SendForTests(async (_p, op) => {
      if (op.kind === 'delete') throw new Error('provider down');
    });
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    const still = await openMirrorUploads(t, { subscriptionId: live.subId });
    expect(still.map((o) => o._id)).toEqual([id]);
    __setS3SendForTests(async (provider, op) => {
      w.calls.s3.push({ op, provider: provider.name });
    });
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    expect(w.calls.s3.at(-1)).toEqual({
      op: { kind: 'delete', key: 'mirrors/orphan' },
      provider: 'p1',
    });
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toEqual([]);
  });

  test('closing a live node for maintenance rewrites its mirrors under the closed gate', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    await t.run((ctx) =>
      ctx.db.patch(live.subId, {
        subscriptionMirrors: [
          {
            provider: 'p1',
            publicUrl: 'https://cdn.example/mirrors/m1',
            objectPath: 'mirrors/m1',
            status: 'ok',
          },
        ],
      }),
    );
    const before = w.calls.s3.length;
    await t.mutation(internal.nodeIntents.startMaintenance, { intentId: live.intentId });
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const puts = w.calls.s3.slice(before).filter((x) => x.op.kind === 'put');
    expect(puts.length).toBeGreaterThan(0);
    expect((puts.at(-1)!.op as { body: string }).body).toBe(MIRROR_UNAVAILABLE_STUB);
  });

  test('an upload under a stable policy settles at once', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    await withMirrorProvider(t);
    const userId = (await t.run((c) => c.db.get(live.subId)))!.userId;
    expect(
      (await t.action(internal.storage.provisionMirror, { userId, countryCode: null })).status,
    ).toBe('ok');
    expect(await openMirrorUploads(t, { subscriptionId: live.subId })).toEqual([]);
  });
});

describe('retention of the workflow rows (convex/retention.ts)', () => {
  const OLD = 100 * 86_400_000;
  const strip = <D extends { _id: unknown; _creationTime: number }>(d: D) => {
    const { _id, _creationTime, ...rest } = d;
    return rest;
  };

  test('terminal rows past the window go; every row something still reads stays', async () => {
    const w = await world();
    const { t } = w;
    const live = await liveL4(w);
    const old = Date.now() - OLD;
    const intent = await intentOf(t, live.intentId);
    const act = await activationRun(t, live.actId);
    const run = await setupRun(t, live.runId);

    // Setup runs: the node's newest run stays whatever its age; an older finished one goes.
    const newestRun = await t.run(async (c) => {
      await c.db.patch(live.runId, { updatedAt: old });
      return c.db.insert('edgeSetupRuns', { ...strip(run), state: 'failed', updatedAt: old });
    });

    // Activation runs.
    const planned = await insertPlanned(t, {
      relayId: live.relayId,
      listenerId: (await t.run((c) => c.db.get(live.e1)))!.listenerId,
      accountId: live.l4,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: ORIGIN_V4, originPort: 443 }],
      steps: [],
    });
    const acts = await t.run(async (c) => {
      const base = { ...strip(act), updatedAt: old };
      const other = (hash: string) => ({ ...base.candidate, reviewHash: hash });
      return {
        // Committed under an older approval: nothing reads it.
        staleCommit: await c.db.insert('panelActivationRuns', {
          ...base,
          candidate: other('older-review'),
        }),
        // Committed under the node's current approval: admission reads its review.
        approvalCommit: await c.db.insert('panelActivationRuns', { ...base }),
        // Superseded with a candidate edge still alive: it stays isolated only while the row exists.
        liveCandidate: await c.db.insert('panelActivationRuns', {
          ...base,
          state: 'superseded',
          resources: { hostUuids: [], edgeIds: [planned.id] },
        }),
        // Superseded with only committed resources: nothing left to isolate.
        spent: await c.db.insert('panelActivationRuns', { ...base, state: 'failed' }),
      };
    });

    // Ledger ops: a claimed one stays, an open one stays, the other settled ones go.
    const ops = await t.run(async (c) => {
      const all = await c.db
        .query('panelOps')
        .withIndex('by_server', (q) => q.eq('backendServerId', w.serverId))
        .collect();
      const closed = all.filter((o) => !o.open);
      expect(closed.length).toBeGreaterThan(1);
      for (const o of closed) await c.db.patch(o._id, { updatedAt: old });
      await c.db.insert('panelClaims', {
        backendServerId: w.serverId,
        key: 'test:claimed',
        opId: closed[0]!._id,
        generation: 1,
        claimedAt: old,
      });
      const open = await c.db.insert('panelOps', { ...strip(closed[1]!), open: true });
      return { claimed: closed[0]!._id, gone: closed.slice(1).map((o) => o._id), open };
    });

    // Host hides: the newest row of a Host stays; an older one of the same Host goes;
    // every row of a deleted origin goes.
    const hides = await t.run(async (c) => {
      const row = {
        relayId: live.relayId,
        backendServerId: w.serverId,
        hostUuid: 'host-1',
        observed: {
          remark: 'r',
          address: ORIGIN_V4,
          port: 443,
          sni: null,
          host: null,
          inboundUuid: null,
          isDisabled: false,
        },
        intent: 'disable' as const,
        state: 'released' as const,
        attempt: 1,
        updatedAt: old,
      };
      const older = await c.db.insert('edgeHostHides', row);
      const newest = await c.db.insert('edgeHostHides', row);
      const relay = (await c.db.get(live.relayId))!;
      const goneRelay = await c.db.insert('relays', { ...strip(relay), slug: 'gone-relay' });
      await c.db.delete(goneRelay);
      const orphan = await c.db.insert('edgeHostHides', { ...row, relayId: goneRelay });
      return { older, newest, orphan };
    });

    // Port changes: a finished one goes with its requirements; one whose op is open stays.
    const ports = await t.run(async (c) => {
      const base = {
        backendServerId: w.serverId,
        profileUuid: 'p',
        profileName: 'p',
        inboundTag: 'tag',
        inboundUuid: 'u',
        toPort: 8443,
        ops: '[]',
        baseToken: 'b',
        expectedToken: 'e',
        inboundUuids: {},
        createdAt: old,
        updatedAt: old,
      };
      const cancelled = await c.db.insert('panelPortChanges', { ...base, state: 'cancelled' });
      const requirement = await c.db.insert('panelPortRequirements', {
        backendServerId: w.serverId,
        changeId: cancelled,
        nodeName: NODE,
        port: 8443,
        confirmedBy: 'role',
        state: 'cancelled',
        createdAt: old,
        updatedAt: old,
      });
      const applying = await c.db.insert('panelPortChanges', {
        ...base,
        state: 'applying',
        opId: ops.open,
      });
      return { cancelled, requirement, applying };
    });

    await t.mutation(internal.retention.sweepEdgeSetupRuns, {});
    await t.mutation(internal.retention.sweepActivationRuns, {});
    await t.mutation(internal.retention.sweepHostHides, {});
    await t.mutation(internal.retention.sweepPortChanges, {});
    await t.mutation(internal.retention.sweepPanelOps, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);

    const exists = (id: string) =>
      t.run(async (c) => (await c.db.get(id as Id<'edgeSetupRuns'>)) !== null);
    expect(await exists(live.runId)).toBe(false);
    expect(await exists(newestRun)).toBe(true);

    expect(intent.approved?.reviewHash).toBe(act.candidate.reviewHash);
    expect(await exists(acts.staleCommit)).toBe(false);
    expect(await exists(acts.approvalCommit)).toBe(true);
    expect(await exists(acts.liveCandidate)).toBe(true);
    expect(await exists(acts.spent)).toBe(false);
    // The node's current run is never swept.
    if (intent.activation.currentRunId)
      expect(await exists(intent.activation.currentRunId)).toBe(true);
    // The live candidate goes once its edge is destroyed.
    await t.run((c) => c.db.patch(planned.id, { status: 'destroyed' }));
    await t.mutation(internal.retention.sweepActivationRuns, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await exists(acts.liveCandidate)).toBe(false);

    expect(await exists(hides.older)).toBe(false);
    expect(await exists(hides.newest)).toBe(true);
    expect(await exists(hides.orphan)).toBe(false);

    expect(await exists(ports.cancelled)).toBe(false);
    expect(await exists(ports.requirement)).toBe(false);
    expect(await exists(ports.applying)).toBe(true);

    expect(await exists(ops.claimed)).toBe(true);
    expect(await exists(ops.open)).toBe(true);
    for (const id of ops.gone) expect(await exists(id)).toBe(false);

    // Members keep the committed delivery throughout.
    expect((await gateOfNode(t, { backendServerId: w.serverId, nodeName: NODE })).state).toBe(
      'open',
    );
  });
});
