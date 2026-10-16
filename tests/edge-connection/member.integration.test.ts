/// <reference types="vite/client" />
/**
 * THE RELEASE GATE: a member connects through an edge, with real software end
 * to end (docs/client-compatibility.md "Edge connection").
 *
 * FCP runs in convex-test against the real panel of the stack and its two real
 * relay nodes. Each node is taken through the real lifecycle: enrollment, the
 * role's applied report, `machine_ready` (for the WebSocket node: FCP's own
 * ingress check resolving the origin hostname and dialling the node), the
 * guided setup run (prepare, credential, provision, verify, try_it, publish),
 * parked at publish until the node is approved over HTTP, then hides,
 * rehearsal over the panel's real bodies and go-live. A member of the node's
 * mode is issued on the panel, fetches the REAL `/api/v1/sub/<token>` with a
 * sing-box User-Agent, and a real sing-box connects with that body and fetches
 * a page only the nodes can reach. The traffic is asserted through the intended
 * edge (the forwarder's counter, the front's access log) and around nothing
 * else: the member's network reaches no node, and the body names none.
 *
 * Seams, and only these: the outside probe round that verifies an L4 standby
 * (the evidence lands as it would from outside vantages), and two stand-ins
 * inside the otherwise REAL L7 front proof (the front is dialled at its address
 * rather than through public DNS, and its neutral 204 target is the stack's
 * page). The provider APIs are fakes that wire the stack's real edges.
 * Everything else, the try_it test link included (imported into sing-box and
 * connected through the candidate edge before the tick), is the production
 * code against the real panel.
 *
 * Run by scripts/edge-connection-integration.sh inside the runner container.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';
import schema from '../../convex/schema';
import { internal } from '../../convex/_generated/api';
import type { Doc, Id } from '../../convex/_generated/dataModel';
import { __setStageOpsForTests } from '../../convex/edgeSetupRuns';
import { __setFrontChecker } from '../../convex/frontQualifyOps';
import { qualifyFront } from '../../convex/lib/edges/frontCheck';
import { createAccount } from '../../convex/lib/edges/testing/fixtures';
import { signValue } from '../../convex/lib/cookies';
import { outgoingAddresses } from '../../convex/lib/edges/render';
import type { Cohort, CohortCursor, CohortPage } from '../../convex/lib/edges/cohorts';
import { detectBodyFormat } from '../../convex/lib/edges/clientFamilies';
import { ActivationReview } from '../../src/shared/contracts/servers';
import { clients } from '../compat/manifest';
import {
  ADDR,
  ENABLED,
  NODE_ADDRESSES,
  accessLog,
  clientReachesDirectly,
  env,
  fetchThroughClientEventually,
  forwarderConnections,
  forwarderStats,
  sandboxSingbox,
  singboxForLink,
  sleep,
  startClient,
  stopClient,
  until,
} from './stack';
import { installProviderFakes } from './providers';

const modules = import.meta.glob('../../convex/**/*.*s');
type T = TestConvex<typeof schema>;

const SLUG = 'ec-panel';
const FAMILY = 'ec-decoy';
const SINGBOX_UA = clients.find((c) => c.format === 'singbox')!.userAgents[0]!;
const LINKS_UA = clients.find((c) => c.format === 'links')!.userAgents[0]!;
const NODES = {
  reality: { name: 'ec-reality', mode: 'freedom-reality', addr: ADDR.realityNode },
  ws: { name: 'ec-ws', mode: 'freedom-ws', addr: ADDR.wsNode },
} as const;

// --- driving the real scheduler ------------------------------------------------------------------

/** Poll until `done` holds (the scheduled functions run on real timers). Never prints a row. */
async function settle<R>(
  read: () => Promise<R>,
  done: (r: R) => boolean,
  what: string,
  show: (r: R) => string,
  ms = 240_000,
): Promise<R> {
  const end = Date.now() + ms;
  for (;;) {
    const r = await read();
    if (done(r)) return r;
    if (Date.now() > end) throw new Error(`${what} did not settle: ${show(r)}`);
    await sleep(500);
  }
}

type Run = NonNullable<Awaited<ReturnType<typeof setupRun>>>;
const setupRun = (t: T, id: Id<'edgeSetupRuns'>) => t.query(internal.edgeSetupRuns.get, { id });
const showRun = (r: Run | null) =>
  r ? `${r.stage}/${r.state} ${r.need?.code ?? ''} ${r.need?.detail ?? ''}`.trim() : 'missing';
const showIntent = (i: Doc<'panelNodeIntents'> | null) =>
  i ? `${i.state} ${i.code ?? ''} stage=${i.activation.stage}` : 'missing';
/** The backend write ledger in code words (kind, verb, outcome): what a stuck node was waiting on. */
const opsSummary = () =>
  t.run(async (ctx) =>
    (await ctx.db.query('panelOps').collect())
      .map((o) => `${o.kind}.${o.verb}:${o.request}${o.errorCode ? `(${o.errorCode})` : ''}`)
      .join(' '),
  );
const terminal = (r: Run | null) =>
  !!r && ['done', 'done_unbound', 'failed', 'cancelled'].includes(r.state);
const parked = (r: Run | null) => !!r && (r.state === 'needs_you' || terminal(r));

// --- the world -----------------------------------------------------------------------------------

let t: T;
let serverId: Id<'backendServers'>;
let cookie: string;
let accounts: { l4: Id<'edgeProviderAccounts'>; l7: Id<'edgeProviderAccounts'> };
let fakes: ReturnType<typeof installProviderFakes>;

/** The probe round "lands" for an L4 standby: two outside vantages + a passing internal shape run. */
async function landPartialEvidence(edgeId: Id<'edges'>) {
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

async function adminCookie(): Promise<string> {
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'ec-operator',
      displayName: 'Operator',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  return `fs_admin_session=${await signValue(sid, 'ec-admin-sign')}`;
}

const servers = (method: string, path: string, body?: unknown) =>
  t.fetch(`/api/v1/admin/servers/${SLUG}/${path}`, {
    method,
    headers: { cookie, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

beforeAll(async () => {
  if (!ENABLED) return;
  vi.stubEnv('SESSION_SIGNING_KEY', 'ec-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'ec-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'ec-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'ec-pepper');
  fakes = installProviderFakes({
    allowHosts: [new URL(env.panelUrl).hostname],
    l7Zone: env.l7Zone,
  });
  __setStageOpsForTests({
    requestVerificationProbes: async (_ctx, edgeId) => landPartialEvidence(edgeId),
  });
  // The REAL front proof (TLS, the WebSocket upgrade, VLESS for the
  // qualification credential, through the front and the node), with two
  // stand-ins for the public internet: the front is dialled at its address
  // instead of through public DNS, and the neutral 204 is the stack's page.
  __setFrontChecker((args) =>
    qualifyFront(
      { ...args, target: { host: env.originPage, port: 80, path: '/generate_204' } },
      { dial: { host: ADDR.front.edge, port: 443 } },
    ),
  );

  t = convexTest(schema, modules);
  serverId = await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'Edge connection',
      slug: SLUG,
      config: { type: 'remnawave', baseUrl: env.panelUrl, apiToken: env.panelToken },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  await t.mutation(internal.seed.seedConnectionModes, {});
  // Members are issued into freedom-reality, which ships disabled.
  await t.mutation(internal.connectionModes.updateMode, {
    slug: 'freedom-reality',
    enabled: true,
  });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  // Polls every 5 s instead of 20 (the floor), and L7 accounts may be picked by
  // the run (automatic L7 selection is an operator switch, off by default).
  await t.mutation(internal.edgeAdmin.patchConfig, {
    patch: { pollSeconds: 5, l7: { autoSelect: true } },
  });

  // The REALITY family: the stack's target serves every name it lists.
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  await t.mutation(internal.sniFamilies.create, {
    slug: FAMILY,
    label: FAMILY,
    targetAddress: env.realityTarget,
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: FAMILY,
    lines: [`www.${env.realityTarget}`],
  });
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });

  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input: {
      profileName: 'FreeSocks-Config',
      modes: [
        {
          slug: 'freedom-reality',
          name: 'Freedom-Reality',
          shape: { transport: 'reality', fronting: 'edge-l4' },
          familySlug: FAMILY,
          acceptProxyProtocol: false,
        },
        {
          slug: 'freedom-ws',
          name: 'Freedom-WebSocket',
          shape: { transport: 'ws', fronting: 'edge-l7' },
          acceptProxyProtocol: false,
          ws: { path: env.wsPath, port: env.wsPort },
        },
      ],
      originDns: null,
      adopt: false,
    },
  });
  const setup = await settle(
    () => t.run((c) => c.db.get(started.setupId)),
    (s) => !!s && !s.claim && s.state !== 'pending',
    'backend setup',
    (s) => `${s?.state} ${s?.code ?? ''}`,
  );
  expect(setup!.state, `backend setup: ${setup!.code ?? ''}`).toBe('ready');

  const l4 = await createAccount(t, { provider: 'upcloud', name: 'ec-l4' });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: l4, ok: true });
  const l7 = await createAccount(t, {
    provider: 'cloudflare',
    name: 'ec-l7',
    settings: { zoneId: 'ec'.padEnd(32, '0'), zoneName: env.l7Zone },
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, {
    id: l7,
    ok: true,
    observed: { zoneSslMode: 'full', websockets: 'on' },
  });
  accounts = { l4, l7 };
  cookie = await adminCookie();
}, 600_000);

afterAll(() => {
  if (!ENABLED) return;
  stopClient();
  __setStageOpsForTests(null);
  __setFrontChecker(null);
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

// --- one node, end to end ------------------------------------------------------------------------

/** Enroll a node as its role does, report the machine applied, wait for `machine_ready`. */
async function enrollReady(node: (typeof NODES)[keyof typeof NODES]) {
  const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
    backendServerId: serverId,
    name: node.name,
    mode: node.mode,
    contractVersion: 2,
    observed: {
      management: { address: node.addr.control, port: 2222 },
      publicIps: { v4: node.addr.edge },
      capabilities: { caddy: node.mode === 'freedom-ws', ipv6: false },
    },
  });
  const enrolled = () =>
    settle(
      () => t.run((c) => c.db.get(intentId)),
      (i) => !!i && !i.claim,
      'enrollment',
      showIntent,
    ).catch(async (e) => {
      throw new Error(`${(e as Error).message} ops: ${await opsSummary()}`);
    });
  await enrolled();
  let revision = 1;
  if (node.mode === 'freedom-ws') {
    // No managed origin DNS on this backend: the operator names the origin,
    // after the role's enrollment has been reconciled (as in production, where
    // the operator acts minutes later, never inside the first run).
    const r = await t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: env.originHostname },
    });
    revision = r.machineRevision;
    await enrolled();
  }
  await t.mutation(internal.nodeIntents.applied, {
    intentId,
    appliedRevision: revision,
    nodeStarted: true,
  });
  const intent = await settle(
    () => t.run((c) => c.db.get(intentId)),
    (i) => !!i && !i.claim && (i.activation.stage === 'machine_ready' || i.state === 'blocked'),
    'machine_ready',
    showIntent,
  );
  expect(intent!.activation.stage, `${showIntent(intent)} ops: ${await opsSummary()}`).toBe(
    'machine_ready',
  );
  return intentId;
}

/** A member of `mode`, issued on the panel through the member issuance path. */
async function issueMember(mode: string): Promise<string> {
  const userId = await t.run(async (ctx) => {
    const tier =
      (await ctx.db.query('tiers').first()) ??
      (await ctx.db.get(
        await ctx.db.insert('tiers', {
          slug: 'free',
          name: 'Free',
          backend: 'remnawave',
          monthlyTrafficGb: 50,
          deviceLimit: 0,
          hwidLimit: 0,
          hwidEnabled: false,
          trafficStrategy: 'MONTH',
          isDefaultFree: true,
          isActive: true,
          priority: 0,
          expirationDaysAfterMembershipLapse: 0,
          updatedAt: Date.now(),
        }),
      ));
    return ctx.db.insert('users', {
      tierId: tier!._id,
      status: 'active',
      connectionModeId: mode,
      updatedAt: Date.now(),
    });
  });
  await t.action(internal.account.regenerate, { userId });
  return t.run(async (ctx) => {
    const user = await ctx.db.get(userId);
    const sub = await ctx.db.get(user!.currentSubscriptionId!);
    return sub!.subToken!;
  });
}

const fetchSub = (token: string, ua = SINGBOX_UA) =>
  t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });

/** No node address or origin name anywhere in a body, whatever its format. */
function expectNoOrigin(body: string) {
  for (const a of [...NODE_ADDRESSES, env.originHostname])
    expect(body.includes(a), `the body names the origin ${a}`).toBe(false);
}

/** Plan, create and drive the guided setup run to its approval park, ticking try_it. */
async function protectToPark(
  intentId: Id<'panelNodeIntents'>,
  accountId: Id<'edgeProviderAccounts'>,
) {
  const intent = (await t.run((c) => c.db.get(intentId)))!;
  const plan = await t.action(internal.edgeSetupPlan.plan, {
    backendServerId: serverId,
    nodeUuid: intent.nodeUuid!,
  });
  const offered = plan.accounts.find((a: { id: string }) => a.id === accountId);
  // What the plan saw of the node's transports: tags, verdicts, layers, the probe's answer.
  const seen = JSON.stringify(
    plan.inbounds.map((i) => ({
      tag: i.sourceTag,
      frontable: i.frontable,
      reason: i.reason,
      detail: i.detail,
      layers: i.layers,
      originTransport: (i.listenerSpec as { originTransport?: unknown } | null)?.originTransport,
    })),
  );
  expect(
    offered?.compatible,
    `account not offered: ${JSON.stringify(offered?.reasons)} transports: ${seen}`,
  ).toBe(true);
  const { runId } = await t.action(internal.edgeSetupPlan.create, {
    backendServerId: serverId,
    nodeUuid: intent.nodeUuid!,
    accountId,
    planHash: plan.planHash,
    approvedHideUuids: [],
  });
  const id = runId as Id<'edgeSetupRuns'>;
  let r = await settle(() => setupRun(t, id), parked, 'setup run', showRun);
  const ticked = r!.need?.code === 'try_it';
  if (ticked) {
    // The card's tick: the operator tries each new L4 address from a real
    // client with the isolated test link, and ticks it only when it works.
    for (const l of r!.testLinks ?? []) {
      const before = await forwarderConnections(443);
      await startClient(singboxForLink(l.link));
      try {
        const page = await fetchThroughClientEventually(1080, 45_000);
        expect(page?.token, 'the test link does not connect').toBe(env.originToken);
      } finally {
        stopClient();
      }
      expect(await forwarderConnections(443)).toBeGreaterThan(before);
    }
    await t.mutation(internal.edgeSetupRuns.resume, {
      runId: id,
      confirmations: (r!.testLinks ?? []).map((l) => ({
        edgeId: l.edgeId,
        endpoint: l.binding.endpoint,
        listenerRevision: l.binding.listenerRevision,
        configHash: l.binding.configHash,
      })),
    });
    r = await settle(
      () => setupRun(t, id),
      (x) => parked(x) && x!.need?.code !== 'try_it',
      'setup run after the tick',
      showRun,
    );
  }
  if (r!.need?.code !== 'node_not_approved')
    console.error(`[edge-connection] ${await diagnose(r!)}`);
  expect([r!.stage, r!.state, r!.need?.code], showRun(r)).toEqual([
    'publish',
    'needs_you',
    'node_not_approved',
  ]);
  return { runId: id, ticked };
}

/**
 * What a run that stopped short was looking at, in fixture values and code
 * words only (no credential, no body): its last events, the activation, and
 * the edges the rehearsal would render with their eligibility.
 */
async function diagnose(r: Run): Promise<string> {
  const events = (r.events ?? [])
    .slice(-12)
    .map((e: { code: string; detail?: string }) => `${e.code}${e.detail ? `(${e.detail})` : ''}`);
  const act = r.activationRunId
    ? await t.run((c) => c.db.get(r.activationRunId as Id<'panelActivationRuns'>))
    : null;
  const edges = await t.run(async (c) =>
    (await c.db.query('edges').collect())
      .filter((e) => e.relayId === r.relayId)
      .map((e) => ({
        id: String(e._id).slice(-6),
        status: e.status,
        publication: e.publication,
        layer: e.layer,
        v4: e.addresses.v4,
        hostname: e.addresses.hostname,
        verified: !!e.verification,
      })),
  );
  // The context takes the origin's cohorts, walked a page per query (edgeCohorts.ts).
  const cohorts: Cohort[] = [];
  if (r.relayId) {
    const origin = await t.query(internal.edgeCohorts.originOfRelay, { relayId: r.relayId });
    let cursor: CohortCursor | null = null;
    while (origin) {
      const page: CohortPage = await t.query(internal.edgeCohorts.page, { ...origin, cursor });
      cohorts.push(...page.cohorts);
      if (!page.next) break;
      cursor = page.next;
    }
  }
  const ctx = r.relayId
    ? await t.query(internal.edgeRehearsal.context, {
        relayId: r.relayId,
        darkCohortKeys: [],
        ...(r.activationRunId
          ? { activationRunId: r.activationRunId as Id<'panelActivationRuns'> }
          : {}),
        cohorts,
      })
    : null;
  const rendered = (ctx?.published ?? []).map((p) =>
    Object.fromEntries(
      Object.entries(p as unknown as Record<string, unknown>).filter(
        ([k]) => !/cred|uuid|key|secret|token/i.test(k),
      ),
    ),
  );
  return JSON.stringify({
    events,
    activation: act
      ? { state: act.state, stage: act.stage, edges: act.resources.edgeIds.length }
      : null,
    edges,
    rendered,
    cohorts: ctx ? Object.keys(ctx.subs ?? {}) : null,
  }).slice(0, 4000);
}

/** The approval card over HTTP: read the review, approve its hash; the run wakes and finishes. */
async function approveAndGoLive(intentId: Id<'panelNodeIntents'>, runId: Id<'edgeSetupRuns'>) {
  const res = await servers('GET', `nodes/intents/${intentId}/review`);
  expect(res.status).toBe(200);
  const review = ActivationReview.parse(await res.json());
  expect(review.blockers).toEqual([]);
  const ok = await servers('POST', `nodes/intents/${intentId}/approve`, {
    reviewHash: review.reviewHash,
  });
  expect(ok.status).toBe(200);
  const done = await settle(
    () => setupRun(t, runId),
    (r) => terminal(r) || (r!.state === 'needs_you' && r!.need?.code !== 'node_not_approved'),
    'setup run after approval',
    showRun,
  );
  if (done!.state !== 'done') console.error(`[edge-connection] ${await diagnose(done!)}`);
  expect([done!.stage, done!.state], showRun(done)).toEqual(['done', 'done']);
  const intent = (await t.run((c) => c.db.get(intentId)))!;
  expect(intent.activation.stage).toBe('live');
  expect(intent.delivery.disposition).toBe('live');
  return done!;
}

/** The served sing-box body, checked: it parses, every endpoint is `expected`, no origin anywhere. */
async function servedBody(token: string, expected: { address: string; port: number }) {
  const res = await fetchSub(token);
  expect(res.status, `subscription: ${res.headers.get('x-fcp-delivery') ?? ''}`).toBe(200);
  const body = await res.text();
  expect(detectBodyFormat(body)).toBe('singbox-json');
  const endpoints = outgoingAddresses(body, 'singbox-json');
  expect(endpoints.length).toBeGreaterThan(0);
  for (const e of endpoints) expect(e).toEqual(expected);
  expectNoOrigin(body);
  return body;
}

/** Connect with the served body; the page must come back through the edge. */
async function connectWith(body: string) {
  const { config, port } = sandboxSingbox(body);
  expect(JSON.parse(config).outbounds).toEqual(JSON.parse(body).outbounds);
  await startClient(config, port);
  try {
    const page = await fetchThroughClientEventually(port, 45_000);
    expect(page?.token, 'no page through the edge').toBe(env.originToken);
    return page!;
  } finally {
    // Closing the tunnels makes the front log the session.
    stopClient();
  }
}

// --- the gate ------------------------------------------------------------------------------------

describe.skipIf(!ENABLED)(
  'a member connects through an edge (real panel, nodes and client)',
  () => {
    test('the member network reaches no node directly', () => {
      for (const address of NODE_ADDRESSES)
        for (const port of [443, 2222, env.wsPort])
          expect(clientReachesDirectly(address, port), `${address}:${port}`).toBe(false);
      expect(clientReachesDirectly(ADDR.originPage, 80)).toBe(false);
    });

    describe('L4: REALITY behind a TCP forwarder (freedom-reality)', () => {
      let intentId: Id<'panelNodeIntents'>;
      let runId: Id<'edgeSetupRuns'>;
      let token: string;

      test('enrolls and the machine is ready', async () => {
        intentId = await enrollReady(NODES.reality);
      });

      test('a member is issued, and nothing reaches it while the node is not live', async () => {
        token = await issueMember(NODES.reality.mode);
        // A link-list client: the route caches per User-Agent for 30 s, and the
        // sing-box fetch after go-live must be the member's first in its format.
        const res = await fetchSub(token, LINKS_UA);
        expectNoOrigin(await res.text());
      });

      test('Autopilot provisions, asks for the tick, and parks at publish until approved', async () => {
        const parkedAt = await protectToPark(intentId, accounts.l4);
        runId = parkedAt.runId;
        expect(parkedAt.ticked).toBe(true);
        // The provider was asked to forward to the node's public address on its port.
        const create = fakes.calls.upcloud.find(
          (c) => c.method === 'POST' && c.path === '/1.3/load-balancer',
        );
        expect((create?.body as any)?.backends?.[0]?.members?.[0]).toMatchObject({
          ip: ADDR.realityNode.edge,
          port: 443,
        });
        expect((await forwarderStats())['443']?.target).toBe(`${ADDR.realityNode.edge}:443`);
      });

      test('approved over HTTP: hides, rehearsal over the real bodies, go-live', async () => {
        await approveAndGoLive(intentId, runId);
      });

      test('the member gets the edge, never the origin, and connects through it', async () => {
        const body = await servedBody(token, { address: ADDR.forwarder.client, port: 443 });
        const before = await forwarderConnections(443);
        const page = await connectWith(body);
        expect(page.peer).toBe(ADDR.realityNode.origin);
        expect(await forwarderConnections(443)).toBeGreaterThan(before);
      });
    });

    describe('L7: WebSocket behind its ingress, fronted by a CDN (freedom-ws)', () => {
      let intentId: Id<'panelNodeIntents'>;
      let runId: Id<'edgeSetupRuns'>;
      let token: string;
      let hostname = '';

      test("enrolls, and FCP's own ingress check passes against the node", async () => {
        intentId = await enrollReady(NODES.ws);
        const intent = (await t.run((c) => c.db.get(intentId)))!;
        expect(intent.activation.evidence.map((e) => e.kind)).toEqual(
          expect.arrayContaining(['dns_resolves', 'ingress_verified', 'machine_ready']),
        );
      });

      test('a member is issued, and nothing reaches it while the node is not live', async () => {
        token = await issueMember(NODES.ws.mode);
        const res = await fetchSub(token, LINKS_UA);
        expectNoOrigin(await res.text());
      });

      test('Autopilot fronts it and parks at publish until approved', async () => {
        const parkedAt = await protectToPark(intentId, accounts.l7);
        runId = parkedAt.runId;
        // L7 has no try_it card: its proof is the verification.
        expect(parkedAt.ticked).toBe(false);
        const record = [...fakes.records.values()].at(-1);
        expect(record).toMatchObject({ type: 'CNAME', content: env.originHostname, proxied: true });
        hostname = record!.name;
        expect(hostname.endsWith(`.${env.l7Zone}`)).toBe(true);
      });

      test('approved over HTTP: hides, rehearsal over the real bodies, go-live', async () => {
        await approveAndGoLive(intentId, runId);
      });

      test('the member gets the front, never the origin, and connects through it', async () => {
        const body = await servedBody(token, { address: hostname, port: 443 });
        const outbound = JSON.parse(body).outbounds.find(
          (o: { type: string; server?: string }) => o.type === 'vless' && o.server === hostname,
        );
        expect(outbound?.tls).toMatchObject({ enabled: true, server_name: hostname });
        expect(outbound?.transport).toMatchObject({
          type: 'ws',
          path: env.wsPath,
          headers: { Host: hostname },
        });
        const page = await connectWith(body);
        expect(page.peer).toBe(ADDR.wsNode.origin);
        // The member's own session (from the client network; the front proof's
        // sessions come from the control plane).
        const session = await until(
          async () =>
            accessLog('front').find(
              (e) =>
                e.host === hostname &&
                e.uri === env.wsPath &&
                e.status === 101 &&
                e.remoteIp === ADDR.client,
            ),
          20_000,
          500,
        );
        expect(session, "the front never carried the member's session").toBeTruthy();
        // The node's ingress saw the FRONT, never the member.
        expect(
          accessLog('ingress').some(
            (e) => e.host === hostname && e.remoteIp === ADDR.front.edge && e.status === 101,
          ),
        ).toBe(true);
        expect(accessLog('ingress').some((e) => e.remoteIp.startsWith('203.0.113.'))).toBe(false);
      });
    });

    test('FCP reached nothing but the panel and the fake providers', () => {
      expect(fakes.refused).toEqual([]);
    });
  },
);
