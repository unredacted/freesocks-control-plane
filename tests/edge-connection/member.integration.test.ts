/// <reference types="vite/client" />
/**
 * THE RELEASE GATE: a member connects through an edge, with real software end
 * to end, for every cell of the supported matrix (docs/edges.md "Supported
 * matrix", tests/compat/manifest.ts `edgeMatrix`; docs/client-compatibility.md
 * "Edge connection").
 *
 * FCP runs in convex-test against the real panel of the stack and its real
 * relay nodes:
 *  - ENROLLED nodes (REALITY and XHTTP under REALITY at L4, WebSocket behind
 *    its ingress at L7) are taken through the node lifecycle: enrollment, the
 *    role's applied report, `machine_ready` (for the WebSocket node: FCP's own
 *    ingress check resolving the origin hostname and dialling the node), the
 *    guided setup run (prepare, credential, provision, verify, try_it,
 *    publish), parked at publish until the node is approved over HTTP, then
 *    hides, rehearsal over the panel's real bodies and go-live;
 *  - OPERATOR nodes (an Xray profile the operator wrote, managed by the panel
 *    at the node's public address, served direct to its members first) are
 *    discovered and fronted by the same guided setup run: every transport of
 *    the L4 node behind its own load balancer, every HTTP transport of the L7
 *    node behind its own CDN hostname.
 * Then, per tested cell and per engine the cell claims (sing-box, Mihomo), a
 * member of the node's mode whose key lands on that cell's edge fetches the
 * REAL `/api/v1/sub/<token>` with that engine's User-Agent, and the pinned
 * engine connects with that body and fetches a page only the nodes can reach.
 * The traffic is asserted through the intended edge (the forwarder's counter
 * for that edge's address, the front's access log for that hostname) and
 * around nothing else: the member's network reaches no node, and no body names
 * one.
 *
 * Seams, and only these: the outside probe round that verifies an L4 standby
 * (the evidence lands as it would from outside vantages), and two stand-ins
 * inside the otherwise REAL L7 front proof (the front is dialled at its address
 * rather than through public DNS, and its neutral 204 target is the stack's
 * page). The provider APIs are fakes that wire the stack's real edges.
 * Everything else, the try_it test links included (imported into the engine
 * that speaks them and connected through the candidate edge before the tick),
 * is the production code against the real panel.
 *
 * Run by scripts/edge-connection-integration.sh inside the runner container.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';
import schema from '../../convex/schema';
import { internal } from '../../convex/_generated/api';
import type { Doc, Id } from '../../convex/_generated/dataModel';
import { __setStageOpsForTests } from '../../convex/edgeSetupRuns';
import { __setFrontChecker } from '../../convex/frontQualifyOps';
import { __setEdgePlumbingForTests } from '../../convex/lib/edgeConfig';
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
  sleep,
  startClient,
  stopClient,
  until,
} from './stack';
import { OUTLINE_MANAGER_HOST, installProviderFakes } from './providers';
import {
  OPERATOR_INBOUNDS,
  OPERATOR_NODES,
  operatorProfile,
  testedCells,
  type EnrolledNode,
  type OperatorNode,
  type TestedCell,
} from './cells';
import {
  configForEndpoint,
  parseShareLink,
  sandboxServed,
  servedEntries,
  type Engine,
} from './clients';

const modules = import.meta.glob('../../convex/**/*.*s');
type T = TestConvex<typeof schema>;

const SLUG = 'ec-panel';
/** The Outline server's Shadowsocks port (docker-compose.edge-connection-test.yml `ec-outline`). */
const OUTLINE_PORT = 8388;
const FAMILY = 'ec-decoy';
const UA: Record<Engine, string> = {
  singbox: clients.find((c) => c.format === 'singbox')!.userAgents[0]!,
  mihomo: clients.find((c) => c.format === 'mihomo')!.userAgents[0]!,
};
const LINKS_UA = clients.find((c) => c.format === 'links')!.userAgents[0]!;
const BODY_FORMAT: Record<Engine, 'singbox-json' | 'clash-yaml'> = {
  singbox: 'singbox-json',
  mihomo: 'clash-yaml',
};
const NODES: Record<
  EnrolledNode,
  {
    name: string;
    mode: string;
    addr: { control: string; edge: string; origin: string };
    layer: 'l4' | 'l7';
  }
> = {
  reality: { name: 'ec-reality', mode: 'freedom-reality', addr: ADDR.realityNode, layer: 'l4' },
  xhttpReality: {
    name: 'ec-xreality',
    mode: 'freedom-xhttp',
    addr: ADDR.xhttpRealityNode,
    layer: 'l4',
  },
  ws: { name: 'ec-ws', mode: 'freedom-ws', addr: ADDR.wsNode, layer: 'l7' },
};
/** Every tested cell of the manifest, with its case (throws for a claim with no case). */
const CELLS = ENABLED ? testedCells() : [];

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
/**
 * The panel's own view of its nodes, credential-free (name, address, whether
 * it is connected and why not): what to read when a node write came back
 * ambiguous (`servers.op_uncertain`) and the ledger parked the node.
 */
const panelNodesSummary = async () => {
  try {
    const nodes: Array<Record<string, unknown>> = await panel('GET', 'nodes');
    return JSON.stringify(
      nodes.map((n) => ({
        name: n.name,
        address: n.address,
        connected: n.isConnected,
        connecting: n.isConnecting,
        disabled: n.isDisabled,
        lastStatus:
          typeof n.lastStatusMessage === 'string' ? n.lastStatusMessage.slice(0, 120) : null,
      })),
    );
  } catch (e) {
    return `unreadable (${(e as Error).message})`;
  }
};
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

/** The panel's own API, as the operator uses it to set up an operator node. */
async function panel(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(new URL(`/api/${path}`, env.panelUrl), {
    method,
    headers: { authorization: `Bearer ${env.panelToken}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`panel ${method} ${path.split('/')[0]}: HTTP ${res.status}`);
  const text = await res.text();
  return text ? JSON.parse(text).response : null;
}

beforeAll(async () => {
  if (!ENABLED) return;
  vi.stubEnv('SESSION_SIGNING_KEY', 'ec-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'ec-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'ec-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'ec-pepper');
  fakes = installProviderFakes({
    allowHosts: [new URL(env.panelUrl).hostname],
    l7Zone: env.l7Zone,
    outline: { address: ADDR.outline.edge, port: OUTLINE_PORT, password: env.outlinePassword },
  });
  __setStageOpsForTests({
    requestVerificationProbes: async (_ctx, edgeId) => landPartialEvidence(edgeId),
  });
  // The REAL front proof (TLS, the transport's handshake, the VLESS or Trojan
  // request for the qualification credential, through the front and the
  // node), with two stand-ins for the public internet: the front is dialled at
  // its address instead of through public DNS, and the neutral 204 is the
  // stack's page.
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
  await t.run(async (ctx) => {
    // Every cell's member is found by re-keying it until its edge is in the
    // body: far more fetches per token than a client makes, so the per-token
    // limit would answer 429 long before the matrix is through.
    await ctx.db.insert('appSettings', {
      key: 'ratelimit.subscription.fetch.token',
      value: JSON.stringify({ max: 100_000, windowMs: 60_000, enabled: true }),
      updatedAt: Date.now(),
    });
  });
  await t.mutation(internal.seed.seedConnectionModes, {});
  // Members are issued into freedom-reality and freedom-xhttp, which ship disabled.
  for (const slug of ['freedom-reality', 'freedom-xhttp'])
    await t.mutation(internal.connectionModes.updateMode, { slug, enabled: true });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  // Polls every 5 s instead of 20 (a constant, shortened through the test
  // seam), and L7 accounts may be picked by the run (automatic L7 selection is
  // an operator switch, off by default).
  __setEdgePlumbingForTests({ pollMs: 5_000 });
  // The L7 front here is a Cloudflare account, a DNS provider: it fronts only with the switch on.
  await t.mutation(internal.edgeAdmin.patchConfig, {
    patch: { l7: { autoSelect: true, dnsProvidersFront: true } },
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
          slug: 'freedom-xhttp',
          name: 'Freedom-XHTTP',
          shape: { transport: 'xhttp-reality', fronting: 'edge-l4' },
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

  // Room, and today's allocations, for every L4 edge of the run: the enrolled
  // nodes', the operator node's eight and the Outline server's.
  const l4 = await createAccount(t, {
    provider: 'upcloud',
    name: 'ec-l4',
    maxLiveEdges: 20,
    dailyAllocationBudget: 30,
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: l4, ok: true });
  const l7 = await createAccount(t, {
    provider: 'cloudflare',
    name: 'ec-l7',
    maxLiveEdges: 20,
    dailyAllocationBudget: 30,
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

// --- nodes ---------------------------------------------------------------------------------------

/** Enroll a node as its role does, report the machine applied, wait for `machine_ready`. */
async function enrollReady(node: (typeof NODES)[EnrolledNode]) {
  const ws = node.mode === 'freedom-ws';
  const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
    backendServerId: serverId,
    name: node.name,
    mode: node.mode,
    contractVersion: 2,
    observed: {
      management: { address: node.addr.control, port: 2222 },
      publicIps: { v4: node.addr.edge },
      capabilities: { caddy: ws, ipv6: false },
    },
  });
  const enrolled = () =>
    settle(
      () => t.run((c) => c.db.get(intentId)),
      (i) => !!i && !i.claim,
      'enrollment',
      showIntent,
    ).catch(async (e) => {
      throw new Error(
        `${(e as Error).message} ops: ${await opsSummary()} panel nodes: ${await panelNodesSummary()}`,
      );
    });
  await enrolled();
  let revision = 1;
  if (ws) {
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
  if (intent!.activation.stage !== 'machine_ready')
    console.error(
      `[edge-connection] ${showIntent(intent)} ops: ${await opsSummary()} panel nodes: ${await panelNodesSummary()}`,
    );
  expect(intent!.activation.stage, showIntent(intent)).toBe('machine_ready');
  return intentId;
}

/**
 * An operator node as the operator has it before FCP fronts anything: the
 * operator's profile on the panel, the node managed at its public address,
 * one direct Host per transport (its members connect to the node itself), and
 * a connection mode placed on a mode group holding exactly its transports.
 * The backend's node inventory is refreshed so the plan can see the node.
 */
async function setUpOperatorNode(node: OperatorNode): Promise<{ nodeUuid: string }> {
  const n = OPERATOR_NODES[node];
  const profile = await panel('POST', 'config-profiles', {
    name: `EC operator ${node}`,
    config: operatorProfile(node, env.tlsName),
  });
  const inbounds: Array<{ uuid: string; tag: string }> = profile.inbounds;
  const group = await panel('POST', 'internal-squads', {
    name: `EC-${node}`,
    inbounds: inbounds.map((i) => i.uuid),
  });
  for (const ib of inbounds) {
    const spec = OPERATOR_INBOUNDS.find((i) => i.tag === ib.tag)!;
    await panel('POST', 'hosts', {
      inbound: { configProfileUuid: profile.uuid, configProfileInboundUuid: ib.uuid },
      remark: `${n.name}-direct-${spec.port}`,
      address: n.edge,
      port: spec.port,
      ...(spec.security === 'tls' ? { sni: env.tlsName } : {}),
    });
  }
  const created = await panel('POST', 'nodes', {
    name: n.name,
    address: n.edge,
    port: 2222,
    configProfile: {
      activeConfigProfileUuid: profile.uuid,
      activeInbounds: inbounds.map((i) => i.uuid),
    },
  });
  const up = await until(
    async () => (await panel('GET', `nodes/${created.uuid}`)).isConnected === true,
    180_000,
    2000,
  );
  expect(up, `${n.name} never connected to the panel`).toBe(true);
  await t.mutation(internal.connectionModes.createMode, {
    slug: n.mode,
    label: `EC ${node}`,
    family: 'freedom',
    deliveryStyle: 'url',
    backends: ['remnawave'],
    enabled: true,
  });
  await t.mutation(internal.connectionModes.setModePlacements, {
    backend: 'remnawave',
    patch: { modes: { [n.mode]: { groupUuids: [group.uuid] } } },
  });
  await t.action(internal.backendNodes.refreshNodeInventory, { backendServerId: serverId });
  return { nodeUuid: created.uuid };
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

const fetchSub = (token: string, ua: string) =>
  t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });

/** No node address or origin name anywhere in a body, whatever its format. */
function expectNoOrigin(body: string) {
  for (const a of [...NODE_ADDRESSES, env.originHostname])
    expect(body.includes(a), `the body names the origin ${a}`).toBe(false);
}

// --- the guided setup run ------------------------------------------------------------------------

/**
 * The card's tick: the operator imports each isolated test link into a real
 * client (the engine that speaks it) and ticks it only when it connects
 * through the candidate edge, counted at that edge's address.
 */
async function tryEveryLink(links: NonNullable<Run['testLinks']>) {
  for (const l of links) {
    const endpoint = parseShareLink(l.link);
    const { engine, config } = configForEndpoint(endpoint, 1080);
    const before = await forwarderConnections(443, endpoint.server);
    await startClient(config, 1080, engine);
    try {
      const page = await fetchThroughClientEventually(1080, 45_000);
      expect(page?.token, `the test link through ${endpoint.server} does not connect`).toBe(
        env.originToken,
      );
    } finally {
      stopClient();
    }
    expect(await forwarderConnections(443, endpoint.server)).toBeGreaterThan(before);
  }
}

/**
 * Plan, create and drive the guided setup run until it parks for the
 * operator's approval (an enrolled node) or finishes (an operator node, which
 * FCP does not manage and so publishes without one), ticking try_it on the way.
 */
async function protect(
  nodeUuid: string,
  accountId: Id<'edgeProviderAccounts'>,
  expect_: { listeners: number; approval: boolean },
) {
  // One edge per transport, provisioned one after the other: an eight-transport
  // node takes minutes of the provider loop.
  const ms = 240_000 + expect_.listeners * 60_000;
  const plan = await t.action(internal.edgeSetupPlan.plan, { backendServerId: serverId, nodeUuid });
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
  expect(plan.requiredListeners.length, seen).toBe(expect_.listeners);
  // Protect everything: the direct Hosts of transports a format cannot render
  // (XHTTP has no sing-box form) are not covered by the plan on their own.
  const approvedHideUuids = plan.directHosts
    .filter((h: { covered: boolean }) => !h.covered)
    .map((h: { uuid: string }) => h.uuid);
  const { runId } = await t.action(internal.edgeSetupPlan.create, {
    backendServerId: serverId,
    nodeUuid,
    accountId,
    planHash: plan.planHash,
    approvedHideUuids,
  });
  const id = runId as Id<'edgeSetupRuns'>;
  let r = await settle(() => setupRun(t, id), parked, 'setup run', showRun, ms);
  const ticked = r!.need?.code === 'try_it';
  if (ticked) {
    await tryEveryLink(r!.testLinks ?? []);
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
      ms,
    );
  }
  const want = expect_.approval
    ? ['publish', 'needs_you', 'node_not_approved']
    : ['done', 'done', undefined];
  if (r!.need?.code !== want[2] || r!.state !== want[1])
    console.error(`[edge-connection] ${await diagnose(r!)}`);
  expect([r!.stage, r!.state, r!.need?.code], showRun(r)).toEqual(want);
  return { runId: id, ticked, run: r! };
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
        front: e.frontQualification?.code ?? (e.frontQualification ? 'ok' : null),
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
        ([k]) => !/cred|uuid|key|secret|token|password/i.test(k),
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

// --- the member ----------------------------------------------------------------------------------

interface CellEdge {
  edgeId: Id<'edges'>;
  layer: 'l4' | 'l7';
  /** What a member dials: the load balancer's address, or the CDN hostname. */
  address: string;
}

/** The published edge of every listener of a node's origin, by the transport's tag. */
async function edgesByTag(nodeName: string): Promise<Map<string, CellEdge>> {
  const rows = await t.run(async (ctx) => {
    const relay = (await ctx.db.query('relays').collect()).find(
      (r) => r.origin.kind === 'panel-node' && r.origin.nodeName === nodeName,
    );
    expect(relay, `no origin for ${nodeName}`).toBeTruthy();
    const out: Array<[string, CellEdge]> = [];
    for (const e of await ctx.db.query('edges').collect()) {
      if (e.relayId !== relay!._id || e.publication !== 'published') continue;
      const listener = await ctx.db.get(e.listenerId);
      const tag = listener?.panelBinding?.inboundTag;
      const layer = (e.layer ?? 'l4') as 'l4' | 'l7';
      const address = layer === 'l7' ? e.addresses.hostname : e.addresses.v4;
      if (tag && address) out.push([tag, { edgeId: e._id, layer, address }]);
    }
    return out;
  });
  return new Map(rows);
}

/** Every live edge of an origin with what a member dials (any publication state). */
async function edgesOfRelay(relayId: Id<'relays'>): Promise<CellEdge[]> {
  return t.run(async (ctx) =>
    (await ctx.db.query('edges').collect())
      .filter((e) => e.relayId === relayId && e.status === 'active')
      .map((e) => {
        const layer = (e.layer ?? 'l4') as 'l4' | 'l7';
        return {
          edgeId: e._id,
          layer,
          address: (layer === 'l7' ? e.addresses.hostname : e.addresses.v4) ?? '',
        };
      }),
  );
}

/** Every edge address of a node's origin (all that a body of that node may name). */
const edgeAddresses = (edges: Map<string, CellEdge>) => [...edges.values()].map((e) => e.address);

/**
 * The member's served body in `engine`'s format, re-keyed until it carries
 * `edge` (a member gets a primary and a backup edge of the origin's pool, so
 * a key that lands on this edge is the member whose cell it is). Checked: it
 * parses, every endpoint is one of the origin's edges on 443, no origin
 * anywhere.
 */
async function bodyCarrying(
  token: string,
  engine: Engine,
  edge: CellEdge,
  allowed: readonly string[],
): Promise<{ body: string; entry: string }> {
  for (let attempt = 0; attempt < 48; attempt++) {
    if (attempt > 0)
      await t.run(async (ctx) => {
        const sub = (await ctx.db.query('subscriptions').collect()).find(
          (s) => s.subToken === token,
        )!;
        await ctx.db.patch(sub._id, {
          renderKey: randomBytes(32).toString('hex'),
          subCache: undefined,
        });
      });
    const res = await fetchSub(token, UA[engine]);
    expect(res.status, `subscription: ${res.headers.get('x-fcp-delivery') ?? ''}`).toBe(200);
    const body = await res.text();
    expect(detectBodyFormat(body)).toBe(BODY_FORMAT[engine]);
    const endpoints = outgoingAddresses(body, BODY_FORMAT[engine]);
    expect(endpoints.length).toBeGreaterThan(0);
    for (const e of endpoints) {
      expect(allowed, `an endpoint that is not this origin's edge: ${e.address}`).toContain(
        e.address,
      );
      expect(e.port).toBe(443);
    }
    expectNoOrigin(body);
    const entry = servedEntries(engine, body).find((x) => x.server === edge.address);
    if (entry) return { body, entry: entry.name };
  }
  throw new Error(`no key of the member landed on the edge at ${edge.address}`);
}

/**
 * Connect with the served body through ONE of its entries; the page must come
 * back from `peer` (the node), and the traffic must have crossed `edge`.
 */
async function connectThrough(
  engine: Engine,
  served: { body: string; entry: string },
  edge: CellEdge,
  peer: string,
) {
  const { config, port } = sandboxServed(engine, served.body, served.entry);
  // The sandbox changed the plumbing only: the rendered proxies are FCP's.
  expect(
    servedEntries(engine, config).map((e) => e.raw),
    'the sandbox changed a rendered proxy',
  ).toEqual(servedEntries(engine, served.body).map((e) => e.raw));
  const before = edge.layer === 'l4' ? await forwarderConnections(443, edge.address) : 0;
  const sinceLog = accessLog('front').length;
  await startClient(config, port, engine);
  try {
    const page = await fetchThroughClientEventually(port, 45_000);
    expect(page?.token, 'no page through the edge').toBe(env.originToken);
    expect(page!.peer).toBe(peer);
  } finally {
    // Closing the tunnels makes the front log the session.
    stopClient();
  }
  if (edge.layer === 'l4')
    expect(await forwarderConnections(443, edge.address)).toBeGreaterThan(before);
  else {
    // The member's own session (from the client network; the front proof's
    // sessions come from the control plane).
    const session = await until(
      async () =>
        accessLog('front')
          .slice(sinceLog)
          .find((e) => e.host === edge.address && e.remoteIp === ADDR.client && e.status < 300),
      20_000,
      500,
    );
    expect(session, "the front never carried the member's session").toBeTruthy();
  }
}

/** The tested cells a node proves. */
const cellsOf = (pred: (c: TestedCell) => boolean) => CELLS.filter(pred);

// --- the gate ------------------------------------------------------------------------------------

describe.skipIf(!ENABLED)(
  'a member connects through an edge, for every cell of the supported matrix',
  () => {
    test('the member network reaches no node directly', () => {
      for (const address of NODE_ADDRESSES)
        for (const port of [443, 2222, env.wsPort])
          expect(clientReachesDirectly(address, port), `${address}:${port}`).toBe(false);
      expect(clientReachesDirectly(ADDR.originPage, 80)).toBe(false);
    });

    for (const key of ['reality', 'xhttpReality', 'ws'] as const) {
      const node = NODES[key];
      const cells = cellsOf((c) => c.case.kind === 'enrolled' && c.case.node === key);
      describe(`enrolled ${node.mode} (${cells.map((c) => c.key).join(', ')})`, () => {
        let intentId: Id<'panelNodeIntents'>;
        let runId: Id<'edgeSetupRuns'>;
        let token: string;

        test('enrolls and the machine is ready', async () => {
          intentId = await enrollReady(node);
          if (key === 'ws') {
            const intent = (await t.run((c) => c.db.get(intentId)))!;
            expect(intent.activation.evidence.map((e) => e.kind)).toEqual(
              expect.arrayContaining(['dns_resolves', 'ingress_verified', 'machine_ready']),
            );
          }
        });

        test('a member is issued, and nothing reaches it while the node is not live', async () => {
          token = await issueMember(node.mode);
          // A link-list client: the route caches per User-Agent for 30 s, and
          // every engine's fetch after go-live must be the member's first in its format.
          const res = await fetchSub(token, LINKS_UA);
          expectNoOrigin(await res.text());
        });

        test('Autopilot fronts it and parks at publish until approved', async () => {
          const intent = (await t.run((c) => c.db.get(intentId)))!;
          const parkedAt = await protect(
            intent.nodeUuid!,
            node.layer === 'l4' ? accounts.l4 : accounts.l7,
            { listeners: 1, approval: true },
          );
          runId = parkedAt.runId;
          // L4 asks for the tick through the test link; L7's proof is the verification.
          expect(parkedAt.ticked).toBe(node.layer === 'l4');
          if (node.layer === 'l4') {
            // The provider was asked to forward to the node's public address on its port.
            const create = fakes.calls.upcloud.findLast(
              (c) => c.method === 'POST' && c.path === '/1.3/load-balancer',
            );
            expect((create?.body as any)?.backends?.[0]?.members?.[0]).toMatchObject({
              ip: node.addr.edge,
              port: 443,
            });
          } else {
            const record = [...fakes.records.values()].at(-1);
            expect(record).toMatchObject({
              type: 'CNAME',
              content: env.originHostname,
              proxied: true,
            });
            expect(record!.name.endsWith(`.${env.l7Zone}`)).toBe(true);
          }
        });

        test('approved over HTTP: hides, rehearsal over the real bodies, go-live', async () => {
          await approveAndGoLive(intentId, runId);
        });

        for (const cell of cells)
          for (const engine of cell.engines as Engine[])
            test(`${cell.key} with ${engine}: the member gets the edge, never the origin, and connects through it`, async () => {
              const edges = await edgesByTag(node.name);
              expect(edges.size).toBe(1);
              const edge = [...edges.values()][0]!;
              const served = await bodyCarrying(token, engine, edge, edgeAddresses(edges));
              if (key === 'ws' && engine === 'singbox') {
                const outbound = JSON.parse(served.body).outbounds.find(
                  (o: { tag: string }) => o.tag === served.entry,
                );
                expect(outbound?.tls).toMatchObject({ enabled: true, server_name: edge.address });
                expect(outbound?.transport).toMatchObject({
                  type: 'ws',
                  path: env.wsPath,
                  headers: { Host: edge.address },
                });
              }
              await connectThrough(engine, served, edge, node.addr.origin);
              if (key === 'ws')
                // The node's ingress saw the FRONT, never the member.
                expect(accessLog('ingress').some((e) => e.remoteIp.startsWith('203.0.113.'))).toBe(
                  false,
                );
            });

        // A provider set of two locations (docs/edges.md "Provider sets"): the
        // live node gets an address in a second location through an `add` run
        // (tested, reviewed, committed), and a member's main address and backup
        // land in different locations, each one connecting.
        if (key === 'reality')
          test('a second location: an add run, then main and backup in different locations, both connecting', async () => {
            const relayId = await t.run(
              async (c) =>
                (await c.db.query('relays').collect()).find(
                  (r) => r.origin.kind === 'panel-node' && r.origin.nodeName === node.name,
                )!._id,
            );
            const second = (
              await t.mutation(internal.edgeLocations.create, {
                accountId: accounts.l4,
                placement: { zone: 'nl-ams1' },
                label: 'Zone two',
              })
            ).id as Id<'edgeLocations'>;
            const change = await t.mutation(internal.edgeProviderSets.change, {
              relayId,
              add: [second],
            });
            const addRun = change.runId as Id<'edgeSetupRuns'>;
            let r = await settle(() => setupRun(t, addRun), parked, 'add run', showRun, 300_000);
            expect(r!.need?.code, showRun(r)).toBe('try_it');
            await tryEveryLink(r!.testLinks ?? []);
            await t.mutation(internal.edgeSetupRuns.resume, {
              runId: addRun,
              confirmations: (r!.testLinks ?? []).map((l) => ({
                edgeId: l.edgeId,
                endpoint: l.binding.endpoint,
                listenerRevision: l.binding.listenerRevision,
                configHash: l.binding.configHash,
              })),
            });
            r = await settle(
              () => setupRun(t, addRun),
              (x) => parked(x) && x!.need?.code !== 'try_it',
              'add run after the tick',
              showRun,
              300_000,
            );
            // A new location is a new shape: the node's review, then go-live.
            expect(r!.need?.code, showRun(r)).toBe('node_not_approved');
            await approveAndGoLive(intentId, addRun);
            const both = await t.run(async (c) =>
              (await c.db.query('edges').collect()).filter(
                (e) =>
                  e.relayId === relayId && e.publication === 'published' && e.status === 'active',
              ),
            );
            expect(new Set(both.map((e) => e.locationId)).size).toBe(2);
            const cellEdges: CellEdge[] = both.map((e) => ({
              edgeId: e._id,
              layer: 'l4',
              address: e.addresses.v4!,
            }));
            const engine = (cells[0]!.engines as Engine[])[0]!;
            // The member's body: a main address and a backup, in different locations.
            const res = await fetchSub(token, UA[engine]);
            expect(res.status).toBe(200);
            const sub = await t.run(async (c) =>
              (await c.db.query('subscriptions').collect()).find((x) => x.subToken === token),
            );
            const main = both.find((e) => e._id === sub?.lastRender?.primaryEdgeId);
            const backup = both.find((e) => e._id === sub?.lastRender?.backupEdgeId);
            expect(main && backup, 'a main address and a backup').toBeTruthy();
            expect(main!.locationId).not.toBe(backup!.locationId);
            // The engine connects through each of them.
            for (const edge of cellEdges) {
              const served = await bodyCarrying(
                token,
                engine,
                edge,
                cellEdges.map((x) => x.address),
              );
              await connectThrough(engine, served, edge, node.addr.origin);
            }
          });
      });
    }

    for (const node of ['l4m', 'l7m'] as const) {
      const n = OPERATOR_NODES[node];
      const cells = cellsOf((c) => c.case.kind === 'operator' && c.case.inbound.node === node);
      const tags = OPERATOR_INBOUNDS.filter((i) => i.node === node).map((i) => i.tag);
      describe(`operator node ${n.name} at ${node === 'l4m' ? 'L4' : 'L7'} (${cells.length} cells)`, () => {
        let nodeUuid: string;
        let token: string;
        let edges: Map<string, CellEdge>;

        test('the operator serves it direct, then FCP discovers and fronts every transport', async () => {
          ({ nodeUuid } = await setUpOperatorNode(node));
          // The qualification and test-link credential of a node FCP does not
          // manage is minted on the default mode's group: make it this node's
          // (the operator's choice of mode for the node).
          await t.mutation(internal.connectionModes.updateMode, {
            slug: n.mode,
            makeDefault: true,
          });
          const done = await protect(nodeUuid, node === 'l4m' ? accounts.l4 : accounts.l7, {
            listeners: tags.length,
            approval: false,
          });
          expect(done.ticked).toBe(node === 'l4m');
          edges = await edgesByTag(n.name);
          expect([...edges.keys()].sort()).toEqual([...tags].sort());
          for (const e of edges.values()) expect(e.layer).toBe(node === 'l4m' ? 'l4' : 'l7');
          if (node === 'l4m')
            // Each load balancer forwards to exactly its transport's port on the node.
            for (const [tag, e] of edges) {
              const port = OPERATOR_INBOUNDS.find((i) => i.tag === tag)!.port;
              expect((await forwarderStats())[`${e.address}:443`]?.target).toBe(
                `${n.edge}:${port}`,
              );
            }
          else
            // Every proxied record points at the node; a port other than the
            // zone's 443 rides an Origin Rule.
            for (const e of edges.values())
              expect([...fakes.records.values()].find((r) => r.name === e.address)).toMatchObject({
                type: 'A',
                content: n.edge,
                proxied: true,
              });
        });

        test('a member of its mode is issued', async () => {
          token = await issueMember(n.mode);
        });

        for (const cell of cells)
          for (const engine of cell.engines as Engine[])
            test(`${cell.key} with ${engine}: the member gets the edge, never the origin, and connects through it`, async () => {
              const tag = (cell.case as { kind: 'operator'; inbound: { tag: string } }).inbound.tag;
              const edge = edges.get(tag)!;
              const served = await bodyCarrying(token, engine, edge, edgeAddresses(edges));
              await connectThrough(engine, served, edge, n.origin);
            });
      });
    }

    const outlineCells = cellsOf((c) => c.case.kind === 'outline');
    describe(`an Outline server at L4 (${outlineCells.map((c) => c.key).join(', ')}, Outline key)`, () => {
      let outlineServerId: Id<'backendServers'>;
      let relayId: Id<'relays'>;
      let token: string;
      let edge: CellEdge;

      test('a member of the Outline server is issued its key', async () => {
        expect(outlineCells.length).toBeGreaterThan(0);
        outlineServerId = await t.run((ctx) =>
          ctx.db.insert('backendServers', {
            backend: 'outline',
            name: 'Edge connection Outline',
            slug: 'ec-outline',
            // The Manager API's secret path is part of the URL, as an operator pastes it.
            config: {
              type: 'outline',
              apiUrl: `https://${OUTLINE_MANAGER_HOST}/ec-secret/`,
              websocketEnabled: false,
            },
            isActive: true,
            priority: 0,
            keyCount: 0,
            updatedAt: Date.now(),
          }),
        );
        const userId = await t.run(async (ctx) => {
          const tierId = await ctx.db.insert('tiers', {
            slug: 'ec-outline',
            name: 'Outline',
            backend: 'outline',
            monthlyTrafficGb: 50,
            deviceLimit: 0,
            hwidLimit: 0,
            hwidEnabled: false,
            trafficStrategy: 'MONTH',
            isDefaultFree: false,
            isActive: true,
            priority: 1,
            expirationDaysAfterMembershipLapse: 0,
            updatedAt: Date.now(),
          });
          return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
        });
        await t.action(internal.account.regenerate, { userId });
        token = await t.run(async (ctx) => {
          const user = await ctx.db.get(userId);
          const sub = await ctx.db.get(user!.currentSubscriptionId!);
          expect(sub!.backendServerId).toBe(outlineServerId);
          return sub!.subToken!;
        });
      });

      test('the operator protects it by hand: an origin, an L4 edge, Try it, publish', async () => {
        // An Outline server is one origin with one Shadowsocks listener (Outline
        // has no node inventory for the guided setup; Admin -> Edges by hand).
        relayId = (
          await t.mutation(internal.relays.create, {
            slug: 'ec-outline',
            origin: { kind: 'backend-server', backendServerId: outlineServerId },
            originAddress: ADDR.outline.edge,
            listeners: [
              {
                listenerKey: 'ss',
                protocol: 'shadowsocks',
                streamTransport: 'raw',
                security: 'none',
                originPort: OUTLINE_PORT,
              },
            ] as never,
          })
        ).id;
        const listenerId = await t.run(
          async (ctx) =>
            (await ctx.db
              .query('relayListeners')
              .withIndex('by_relay', (q) => q.eq('relayId', relayId))
              .first())!._id,
        );
        const rotation = async (args: Record<string, unknown>) => {
          const { rotationId } = await t.mutation(internal.edgeRotations.start, {
            relayId,
            trigger: 'manual',
            ...args,
          } as never);
          const done = await settle(
            () => t.query(internal.edgeRotations.get, { id: rotationId }),
            (r) => !!r && ['done', 'failed', 'rolled_back', 'cancelled'].includes(r.phase),
            `${String(args.kind)} rotation`,
            (r) => `${r?.phase} ${(r as { failureCode?: string } | null)?.failureCode ?? ''}`,
          );
          expect(
            done!.phase,
            JSON.stringify((done as { events?: unknown }).events ?? []).slice(-800),
          ).toBe('done');
        };
        await rotation({ kind: 'provision', listenerId, requestedAccountId: accounts.l4 });
        const edges = await edgesOfRelay(relayId);
        expect(edges).toHaveLength(1);
        edge = edges[0]!;
        // The provider was asked to forward to the Outline server's port.
        expect((await forwarderStats())[`${edge.address}:443`]?.target).toBe(
          `${ADDR.outline.edge}:${OUTLINE_PORT}`,
        );
        // Try it: the isolated test link comes from a temporary Outline key.
        const link = await t.action(internal.edgeTestLinks.build, { edgeId: edge.edgeId });
        await tryEveryLink([{ link: link.link, binding: link.binding } as never]);
        await t.mutation(internal.edgeVerification.confirm, {
          edgeId: edge.edgeId,
          endpoint: link.binding.endpoint,
          listenerRevision: link.binding.listenerRevision,
          configHash: link.binding.configHash,
          method: 'test_link',
        });
        await rotation({ kind: 'publish', toEdgeId: edge.edgeId });
      });

      for (const cell of outlineCells)
        test(`${cell.key} with an Outline key: the member gets the edge, never the origin, and connects through it`, async () => {
          // What an Outline client fetches behind its ssconf:// key.
          const res = await fetchSub(token, 'Outline/1.0');
          expect(res.status, `subscription: ${res.headers.get('x-fcp-delivery') ?? ''}`).toBe(200);
          const body = (await res.text()).trim();
          expectNoOrigin(body);
          expect(body.split('\n')).toHaveLength(1);
          const key = parseShareLink(body);
          expect(key).toMatchObject({
            protocol: 'shadowsocks',
            server: edge.address,
            port: 443,
            method: 'chacha20-ietf-poly1305',
          });
          const { config } = configForEndpoint(key, 1080, 'singbox');
          const before = await forwarderConnections(443, edge.address);
          await startClient(config, 1080, 'singbox');
          try {
            const page = await fetchThroughClientEventually(1080, 45_000);
            expect(page?.token, 'no page through the edge').toBe(env.originToken);
            expect(page!.peer).toBe(ADDR.outline.origin);
          } finally {
            stopClient();
          }
          expect(await forwarderConnections(443, edge.address)).toBeGreaterThan(before);
        });
    });

    test('FCP reached nothing but the panel and the fake providers', () => {
      expect(fakes.refused).toEqual([]);
    });
  },
);
