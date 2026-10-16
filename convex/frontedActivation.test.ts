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
import type { Id } from './_generated/dataModel';
import { FIXTURE_PANEL_SLUG, createAccount, insertPanelServer } from './lib/edges/testing/fixtures';
import { createFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { createFakeUpcloud } from './lib/edges/testing/fakeEdgeWorld';
import { z } from 'zod';
import { __setEdgeProviderForTests } from './lib/edges/providers/registry';
import type { EdgeProvider, EdgeSpec, Ledger, LedgerResource } from './lib/edges/providers/types';
import { mockFetch, routeFetch, type PartialHandler } from './lib/edges/testing/mockFetch';
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
import { SetupRunAdmin } from '../src/shared/contracts/edges';

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
const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';
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
  calls: { rehearsedEdges: string[][]; s3: Array<{ op: S3Op; provider: string }> };
  hooks: {
    /** Runs once after the next rehearsal returned (a policy move between 7 and 8). */
    afterRehearsal: (() => Promise<void>) | null;
    /** While set, every rehearsal fails (the run waits at `rehearsal_failed`). */
    holdRehearsal: boolean;
    /** Runs once during the next S3 put (a policy move while an upload is in flight). */
    duringPut: (() => Promise<void>) | null;
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

/** The fake backend + UpCloud (+ any extra fake) as the one global fetch. */
function installFetch(backend: FakeBackend, extra: PartialHandler[] = []) {
  const upcloud = createFakeUpcloud();
  mockFetch(routeFetch(backend.handle, upcloud.handle, ...extra));
  return upcloud;
}

async function world(): Promise<World> {
  vi.useFakeTimers();
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const backend = createFakeBackend();
  installFetch(backend);
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
  const calls: World['calls'] = { rehearsedEdges: [], s3: [] };
  const hooks: World['hooks'] = { afterRehearsal: null, holdRehearsal: false, duringPut: null };
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
 * The seams this file uses, and only these: outside probe evidence, the test
 * link the card shows, the L7 qualification credential and the WS origin
 * probe. Everything else (Host hides, the rehearsal over the backend's real
 * bodies, the rotations, go-live) is the production code.
 */
function installSeams(w: World) {
  const { t } = w;
  const ops: Partial<StageOps> = {
    ensureCredential: async (_ctx, a) => {
      await t.run((c) => c.db.patch(a.relayId, { qualificationUserId: QUALIFY_UUID }));
      return { ok: true, reused: false };
    },
    requestVerificationProbes: async (_ctx, edgeId) => {
      await landPartialEvidence(t, edgeId);
    },
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
    rehearse: async (ctx, a) => {
      // The production rehearsal, with a record of which edges it rendered.
      const c = await ctx.runQuery(internal.edgeRehearsal.context, {
        relayId: a.relayId,
        darkCohortKeys: a.darkCohortKeys,
        ...(a.activationRunId ? { activationRunId: a.activationRunId } : {}),
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
    restoreStart: async () => {},
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
          acceptsHostHeader: 'any' as const,
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
  t.query(internal.nodeIntents.nodeGate, { backendServerId: serverId, nodeName });

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
    expect(
      await t.query(internal.relays.deliveryBinding, { backendServerId: serverId, nodeName: NODE }),
    ).toBeTruthy();
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
    expect(
      await t.query(internal.relays.deliveryBinding, { backendServerId: serverId, nodeName: NODE }),
    ).toBeNull();
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
    const open = await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId });
    expect(open).toHaveLength(1);
    expect(open[0]!.kind).toBe('refresh');

    // Within the in-flight grace the repair leaves it alone; after it, the
    // object is re-rendered under the CURRENT policy: the node is gated, so
    // the mirror stops serving the edge (the unavailable stub).
    await t.action(internal.storage.repairMirrorUploads, {});
    expect(
      await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId }),
    ).toHaveLength(1);
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    const repaired = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(repaired.body).toBe(MIRROR_UNAVAILABLE_STUB);
    expect(await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId })).toEqual(
      [],
    );
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
    const open = await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId });
    expect(open.map((o) => o.kind)).toEqual(['initial']);
    vi.advanceTimersByTime(REPAIR_GRACE_MS + 1_000);
    await t.action(internal.storage.repairMirrorUploads, {});
    const repaired = w.calls.s3.filter((x) => x.op.kind === 'put').at(-1)!.op as { body: string };
    expect(repaired.body).toBe(MIRROR_UNAVAILABLE_STUB);
    expect(await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId })).toEqual(
      [],
    );
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
    expect(await t.query(internal.mirrorUploads.openFor, { subscriptionId: live.subId })).toEqual(
      [],
    );
  });
});
