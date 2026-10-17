/// <reference types="vite/client" />
/**
 * Renaming a node (docs/servers.md "Renaming a node"): the backend row, every
 * FCP row keyed by the name, the Host remarks FCP wrote and members' pins.
 *
 *  - every reference moves; no Host is created or deleted (same uuids, same
 *    state), so nothing a member holds stops working;
 *  - the old name keeps resolving: the origin, the delivery binding, the gate
 *    and the node role's view answer under it;
 *  - what would leave something behind is refused before anything is sent;
 *  - an uncertain backend answer parks the rename; `backend-reconcile` settles
 *    the write by looking and resumes it; a refused write changes nothing.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { installFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { jsonRes, routeFetch, type Captured } from './lib/edges/testing/mockFetch';
import { signValue } from './lib/cookies';
import { NodeRenameView } from '../src/shared/contracts/servers';
import { renamedRemark } from './lib/backend/nodeRename';
import { currentNodeName } from './lib/backend/nodeAliases';
import { matcherOf } from './edgeRender';
import { assertNoRelayPanelClaim } from './lib/edges/relayGuards';
import { deliveryBindingOf, gateOfNode, relayForNode } from './lib/edges/testing/reads';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;
const TAG = 'PRIVACY_REALITY';

let current: T | null = null;
beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
/** Every scheduled function of this test has run (a reconcile, a resume). */
const drained = (t: T) =>
  until(
    () => t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
    (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
  );
afterEach(async () => {
  // Work still running must finish against THIS test's fake backend.
  if (current) {
    const t = current;
    current = null;
    await drained(t);
  }
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 600; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

const setupInput = {
  profileName: 'FreeSocks-Config',
  modes: [
    {
      slug: 'privacy-reality',
      name: 'Privacy-Reality',
      shape: { transport: 'reality' as const, fronting: 'direct' as const },
      familySlug: 'fam-direct',
      acceptProxyProtocol: false,
    },
  ],
  originDns: null,
  adopt: false,
};

/**
 * An enrolled direct node `node-a` with its address, an origin in front of it
 * whose listener Host FCP owns, members pinned to it, and a node-role token
 * bounded to it.
 */
async function seed() {
  const t = convexTest(schema, modules);
  current = t;
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend();
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-direct',
    label: 'fam-direct',
    targetAddress: 'decoy-a.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: 'fam-direct',
    lines: ['decoy-a.example'],
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
    input: setupInput,
  });
  await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim,
  );
  const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
    backendServerId: serverId,
    name: 'node-a',
    mode: 'privacy-reality',
    contractVersion: 2,
    observed: {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    },
  });
  const idle = () =>
    until(
      () => t.run((ctx) => ctx.db.get(intentId)),
      (r) => !!r && !r.claim,
    );
  await idle();

  const profileUuid = panel.profiles[0].uuid as string;
  const transportUuid = (panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
    (i) => i.tag === TAG,
  )!.uuid;
  const nodeUuid = panel.nodes.find((n) => n.name === 'node-a')!.uuid as string;

  // The origin in front of it, whose listener's Host FCP wrote.
  const { relayId, listenerId } = await registerRelay(t, {
    slug: 'node-a',
    nodeName: 'node-a',
    originAddress: '203.0.113.10',
    listeners: [
      realityListener({
        panelBinding: {
          inboundTag: TAG,
          configProfileUuid: profileUuid,
          configProfileInboundUuid: transportUuid,
        },
      }),
    ],
  });
  const relayHostUuid = '00000900-0000-4000-8000-000000000000';
  panel.hosts.push({
    uuid: relayHostUuid,
    remark: 'node-a-relay-a',
    address: '198.51.100.5',
    port: 443,
    sni: 'a.example',
    isDisabled: false,
    inbound: { configProfileUuid: profileUuid, configProfileInboundUuid: transportUuid },
  });
  await t.run(async (ctx) => {
    await ctx.db.patch(relayId, { hostMode: 'fcp' });
    await ctx.db.patch(listenerId, {
      matchRule: { kind: 'remark', remark: 'node-a-relay-a' },
      host: {
        state: 'present',
        uuid: relayHostUuid,
        ownership: 'fcp',
        intended: {
          remark: 'node-a-relay-a',
          address: '198.51.100.5',
          port: 443,
          sni: 'a.example',
          host: null,
          inboundUuid: transportUuid,
        },
      },
    });
    const binding = await ctx.db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) =>
        q.eq('backendServerId', serverId).eq('nodeName', 'node-a'),
      )
      .unique();
    if (!binding)
      await ctx.db.insert('edgeDeliveryBindings', {
        backendServerId: serverId,
        nodeName: 'node-a',
        policy: 'edge-required',
        policyVersion: 1,
        relaySlug: 'node-a',
        state: 'active',
        updatedAt: Date.now(),
      });
  });
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });

  // Members pinned to it, one kept off it, and the node role's token.
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const subIds = await t.run(async (ctx) => {
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
    const ids = [];
    for (const [i, pin] of [
      ['node-a', undefined],
      ['node-a', undefined],
      [undefined, 'node-a'],
      ['elsewhere', undefined],
    ].entries()) {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        supportId: `S${i}`,
        updatedAt: Date.now(),
      });
      ids.push(
        await ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: `u${i}`,
          backendShortId: `s${i}`,
          backendServerId: serverId,
          subscriptionUrl: `https://panel.example/sub/s${i}`,
          subscriptionMirrors: [],
          state: 'active',
          ...(pin[0] ? { pinnedNode: pin[0] } : {}),
          ...(pin[1] ? { excludeNode: pin[1] } : {}),
          updatedAt: Date.now(),
        }),
      );
    }
    await ctx.db.insert('apiTokens', {
      name: 'role',
      tokenHash: 'h',
      tokenPrefix: 'p',
      createdByAdminId: adminUserId,
      scopes: ['admin:edges:register'],
      subjectType: 'service',
      edgeRegistration: { backendServerIds: [serverId], nodeNames: ['node-a'] },
      updatedAt: Date.now(),
    });
    return ids;
  });

  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return {
    t,
    serverId,
    panel,
    intentId,
    relayId,
    listenerId,
    relayHostUuid,
    nodeUuid,
    subIds,
    call,
    idle,
  };
}

type Seeded = Awaited<ReturnType<typeof seed>>;

const rename = async (s: Seeded, name: string, nodeUuid = s.nodeUuid) =>
  s.call('POST', `nodes/${nodeUuid}/rename`, { name });
const renameRow = (s: Seeded, id: string) =>
  s.t.run((ctx) => ctx.db.get(id as Id<'panelNodeRenames'>));
const settledRename = (s: Seeded, id: string) =>
  until(
    () => renameRow(s, id),
    (r) => !!r && (r.state !== 'running' || (!r.claim && r.code === 'servers.op_running')),
  );
const hostWrites = (panel: FakeBackend) =>
  panel.writes.filter((w) => /\/api\/hosts/.test(w.call)).map((w) => w.call.split(' ')[0]);
const errCode = async (res: Response) =>
  ((await res.json()) as { error: { code: string } }).error.code;

describe('a rename moves every reference', () => {
  test('backend row, FCP rows, Host remarks and pins; the old name still resolves', async () => {
    const s = await seed();
    const directHost = s.panel.hosts.find((h) => h.remark === 'node-a | decoy-a.example')!;
    expect(directHost).toBeTruthy();
    const writesBefore = s.panel.writes.length;
    const res = await rename(s, 'node-b');
    expect(res.status).toBe(200);
    const view = NodeRenameView.parse(await res.json());
    expect(view).toMatchObject({ from: 'node-a', to: 'node-b', state: 'running' });
    const done = await settledRename(s, view.id);
    expect(done).toMatchObject({ state: 'done', step: 'done' });

    // The backend: the row and both Hosts FCP wrote, re-remarked in place.
    expect(s.panel.nodes.find((n) => n.uuid === s.nodeUuid)!.name).toBe('node-b');
    const byUuid = (u: string) => s.panel.hosts.find((h) => h.uuid === u)!;
    expect(byUuid(directHost.uuid).remark).toBe('node-b | decoy-a.example');
    expect(byUuid(s.relayHostUuid).remark).toBe('node-b-relay-a');
    // Nothing a member holds was taken away: no Host created or deleted, none toggled.
    const during = { ...s.panel, writes: s.panel.writes.slice(writesBefore) };
    expect(hostWrites(during).filter((m) => m !== 'PATCH')).toEqual([]);
    expect(hostWrites(during)).toHaveLength(2);
    expect(byUuid(directHost.uuid).isDisabled).toBe(directHost.isDisabled);
    expect(byUuid(s.relayHostUuid).isDisabled).toBe(false);

    // FCP's rows.
    const rows = await s.t.run(async (ctx) => ({
      intent: await ctx.db.get(s.intentId),
      relay: await ctx.db.get(s.relayId),
      listener: await ctx.db.get(s.listenerId),
      binding: await ctx.db
        .query('edgeDeliveryBindings')
        .withIndex('by_server', (q) => q.eq('backendServerId', s.serverId))
        .collect(),
      subs: await Promise.all(s.subIds.map((id) => ctx.db.get(id))),
      tokens: await ctx.db.query('apiTokens').collect(),
      aliases: await ctx.db.query('panelNodeAliases').collect(),
      inventory: await ctx.db.query('backendNodeInventory').collect(),
    }));
    expect(rows.intent).toMatchObject({ name: 'node-b', formerNames: ['node-a'] });
    expect(rows.relay).toMatchObject({ nodeName: 'node-b', origin: { nodeName: 'node-b' } });
    expect(rows.relay!.renaming).toBeUndefined();
    expect(rows.listener!.matchRule).toEqual({ kind: 'remark', remark: 'node-b-relay-a' });
    expect(rows.listener!.formerRemarks).toEqual(['node-a-relay-a']);
    expect(rows.listener!.host?.intended?.remark).toBe('node-b-relay-a');
    expect(rows.binding).toHaveLength(1);
    expect(rows.binding[0]).toMatchObject({ nodeName: 'node-b' });
    expect(rows.binding[0]!.policyVersion).toBeGreaterThan(1);
    expect(rows.subs.map((x) => [x!.pinnedNode ?? null, x!.excludeNode ?? null])).toEqual([
      ['node-b', null],
      ['node-b', null],
      [null, 'node-b'],
      ['elsewhere', null],
    ]);
    expect(rows.tokens[0]!.edgeRegistration!.nodeNames).toEqual(['node-a', 'node-b']);
    expect(rows.aliases.map((a) => [a.formerName, a.name])).toEqual([['node-a', 'node-b']]);
    for (const inv of rows.inventory.filter((i) => i.nodeUuid === s.nodeUuid))
      expect(inv.name).toBe('node-b');

    // The old name still answers: origin, binding, gate, and the role's view.
    const viaOld = await relayForNode(s.t, {
      backendServerId: s.serverId,
      nodeName: 'node-a',
    });
    expect(viaOld?._id).toBe(s.relayId);
    const binding = await deliveryBindingOf(s.t, {
      backendServerId: s.serverId,
      nodeName: 'node-a',
    });
    expect(binding?.relaySlug).toBe('node-a');
    const [gateOld, gateNew] = await Promise.all(
      ['node-a', 'node-b'].map((nodeName) =>
        gateOfNode(s.t, { backendServerId: s.serverId, nodeName }),
      ),
    );
    expect(gateOld).toEqual(gateNew);
    const role = await s.call('GET', 'nodes/by-name/node-a');
    expect(role.status).toBe(200);
    expect(((await role.json()) as { name: string }).name).toBe('node-b');

    // The renderer matches the old remark too (a body fetched before, a cached one).
    const listener = rows.listener!;
    expect(matcherOf(listener, '203.0.113.10').legacyRemarks).toContain('node-a-relay-a');

    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining(['servers.node.rename_started', 'servers.node.renamed']),
    );
    // The node is reconciled under its new name: its address is its own, not "extra".
    await s.idle();
    expect(byUuid(directHost.uuid)).toBeTruthy();
  });

  test('renamed twice: the first name still resolves, and stays reserved', async () => {
    const s = await seed();
    const first = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    await settledRename(s, first.id);
    // The node is reconciled under its new name first; a rename waits for that.
    await drained(s.t);
    const second = NodeRenameView.parse(await (await rename(s, 'node-c')).json());
    expect((await settledRename(s, second.id))?.state).toBe('done');
    const viaFirst = await relayForNode(s.t, {
      backendServerId: s.serverId,
      nodeName: 'node-a',
    });
    expect(viaFirst?.nodeName).toBe('node-c');
    const intent = await s.t.run((ctx) => ctx.db.get(s.intentId));
    expect(intent).toMatchObject({ name: 'node-c', formerNames: ['node-a', 'node-b'] });
    // Every former name points straight at the current one (flattened).
    const aliases = await s.t.run((ctx) => ctx.db.query('panelNodeAliases').collect());
    expect(aliases.map((a) => [a.formerName, a.name]).sort()).toEqual([
      ['node-a', 'node-c'],
      ['node-b', 'node-c'],
    ]);
    // A former name is never handed to another node (a pin or the role may still use it).
    expect(await errCode(await rename(s, 'node-a'))).toBe('servers.node_name_taken');
  });
});

describe('what is refused before anything is sent', () => {
  test('taken names, a plain edit, a second rename, origin-unsafe names, operator Hosts', async () => {
    const s = await seed();
    s.panel.nodes.push({
      uuid: '00000901-0000-4000-8000-000000000000',
      name: 'other',
      address: '192.0.2.30',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: s.panel.profiles[0].uuid, activeInbounds: [] },
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    expect(await errCode(await rename(s, 'other'))).toBe('servers.node_name_taken');
    expect(await errCode(await rename(s, 'node-a'))).toBe('validation');
    expect(await errCode(await rename(s, 'x'))).toBe('validation');
    // The origin keeps the name as a DNS label.
    expect(await errCode(await rename(s, 'Node-B'))).toBe('servers.node_name_origin');
    expect(await errCode(await rename(s, 'node.b'))).toBe('servers.node_name_origin');
    // A plain edit never renames.
    expect(await errCode(await s.call('PATCH', `nodes/${s.nodeUuid}`, { name: 'node-b' }))).toBe(
      'servers.node_rename_separate',
    );
    // Hosts the operator writes are theirs.
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { hostMode: 'operator' }));
    expect(await errCode(await rename(s, 'node-b'))).toBe('servers.node_rename_foreign_hosts');
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { hostMode: 'fcp' }));
    // Nothing was sent for any of it.
    expect(s.panel.writes.filter((w) => w.call === 'PATCH /api/nodes')).toEqual([]);
    expect(await s.t.run((ctx) => ctx.db.query('panelNodeRenames').collect())).toEqual([]);
    // One at a time; meanwhile the origin is fenced against every edge write.
    // (The backend's answer is lost and the row never shows the name: it waits.)
    s.panel.stub.route(
      routeFetch(
        (c: Captured) =>
          c.method === 'PATCH' && c.path === '/api/nodes'
            ? jsonRes({ message: 'bad gateway' }, 502)
            : null,
        s.panel.handle,
      ),
    );
    const waiting = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    expect((await settledRename(s, waiting.id))!.state).toBe('running');
    expect(await errCode(await rename(s, 'node-c'))).toBe('servers.node_rename_running');
    const relay = await s.t.run((ctx) => ctx.db.get(s.relayId));
    await expect(s.t.run((ctx) => assertNoRelayPanelClaim(ctx.db, relay!))).rejects.toThrow(
      /edge.panel_op_running/,
    );
  });

  test('a backend that refuses the write changes nothing, and the fence goes', async () => {
    const s = await seed();
    s.panel.stub.route(
      routeFetch(
        (c: Captured) =>
          c.method === 'PATCH' && c.path === '/api/nodes' ? jsonRes({ message: 'no' }, 401) : null,
        s.panel.handle,
      ),
    );
    const view = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    const done = await settledRename(s, view.id);
    expect(done).toMatchObject({ state: 'failed', code: 'servers.panel_refused' });
    const rows = await s.t.run(async (ctx) => ({
      intent: await ctx.db.get(s.intentId),
      relay: await ctx.db.get(s.relayId),
      aliases: await ctx.db.query('panelNodeAliases').collect(),
    }));
    expect(rows.intent!.name).toBe('node-a');
    expect(rows.relay!.nodeName).toBe('node-a');
    expect(rows.relay!.renaming).toBeUndefined();
    expect(rows.aliases).toEqual([]);
    expect(s.panel.hosts.some((h) => h.remark.startsWith('node-b'))).toBe(false);
  });
});

describe('an interrupted rename resumes', () => {
  test('an uncertain backend answer parks it; the reconcile settles by looking and finishes', async () => {
    const s = await seed();
    // The gateway answers 502 while the backend did the work (a lost answer).
    let lost = 0;
    s.panel.stub.route(
      routeFetch((c: Captured) => {
        if (c.method === 'PATCH' && c.path === '/api/nodes' && lost === 0) {
          lost++;
          s.panel.handle(c);
          return jsonRes({ message: 'bad gateway' }, 502);
        }
        // And one Host remark write the same way, mid-way through the Hosts.
        if (c.method === 'PATCH' && c.path === '/api/hosts' && lost === 1) {
          lost++;
          s.panel.handle(c);
          return jsonRes({ message: 'bad gateway' }, 502);
        }
        return null;
      }, s.panel.handle),
    );
    const view = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    // Each uncertain write is settled by a look (the run's own, or the cron's),
    // never sent twice, and the rename carries on to the end.
    for (let i = 0; i < 6; i++) {
      const r = await settledRename(s, view.id);
      if (r!.state !== 'running') break;
      await s.t.action(internal.backendWrites.reconcile, {});
    }
    const done = await settledRename(s, view.id);
    expect(done!.state).toBe('done');
    expect(lost).toBe(2);
    expect(s.panel.writes.filter((w) => w.call === 'PATCH /api/nodes')).toHaveLength(1);
    expect(s.panel.hosts.filter((h) => h.remark.startsWith('node-a'))).toEqual([]);
    expect(s.panel.hosts.filter((h) => h.remark.startsWith('node-b'))).toHaveLength(2);
    const intent = await s.t.run((ctx) => ctx.db.get(s.intentId));
    expect(intent!.name).toBe('node-b');
  });
});

describe('remark forms', () => {
  test("FCP's forms for the old name, and nothing else", () => {
    expect(renamedRemark('node-a | decoy.example', 'decoy.example', 'node-a', 'node-b')).toBe(
      'node-b | decoy.example',
    );
    // A longer name falls back to the tagged form, exactly as a fresh address would.
    const long = 'a-much-longer-node-name-xx';
    expect(
      renamedRemark('node-a | www.decoy-site.example', 'www.decoy-site.example', 'node-a', long),
    ).toMatch(new RegExp(`^${long} \\| [0-9a-z]{7}$`));
    expect(renamedRemark('node-a-relay-k1', null, 'node-a', 'node-b')).toBe('node-b-relay-k1');
    expect(renamedRemark('node-a-relay', null, 'node-a', 'node-b')).toBe('node-b-relay');
    // Not FCP's: another node whose name merely starts the same, an operator remark.
    expect(renamedRemark('node-a-west | x.example', 'x.example', 'node-a', 'node-b')).toBeNull();
    expect(renamedRemark('node-a-west-relay-k', null, 'node-a', 'node-b')).toBeNull();
    expect(renamedRemark('node-a-ws', null, 'node-a', 'node-b')).toBeNull();
  });
});

describe('review follow-ups', () => {
  /** A rename whose backend write has an unknown outcome: it holds, running, at `backend`. */
  async function parkedRename(s: Seeded, to: string) {
    s.panel.stub.route(
      routeFetch(
        (c: Captured) =>
          c.method === 'PATCH' && c.path === '/api/nodes'
            ? jsonRes({ message: 'bad gateway' }, 502)
            : null,
        s.panel.handle,
      ),
    );
    const view = NodeRenameView.parse(await (await rename(s, to)).json());
    expect((await settledRename(s, view.id))!.state).toBe('running');
    return view;
  }

  test('a Host remark the backend refuses is not sent again until an operator retries', async () => {
    const s = await seed();
    let refuse = true;
    s.panel.stub.route(
      routeFetch((c: Captured) => {
        const body = c.body as { uuid?: string } | undefined;
        if (
          refuse &&
          c.method === 'PATCH' &&
          c.path === '/api/hosts' &&
          body?.uuid === s.relayHostUuid
        )
          return jsonRes({ message: 'forbidden' }, 403);
        return null;
      }, s.panel.handle),
    );
    const view = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    const held = await until(
      () => renameRow(s, view.id),
      (r) => !!r && !r.claim && r.code === 'servers.rename_host_refused',
    );
    expect(held).toMatchObject({ state: 'running', step: 'hosts' });
    expect(held!.refusedHosts).toEqual([
      { hostUuid: s.relayHostUuid, remark: 'node-a-relay-a', code: 'servers.panel_refused' },
    ]);
    const relayHostPatches = () =>
      s.panel.writes.filter(
        (w) =>
          w.call === 'PATCH /api/hosts' && (w.body as { uuid?: string }).uuid === s.relayHostUuid,
      ).length;
    // The refused write went out once; the clock does not send it again.
    expect(relayHostPatches()).toBe(0);
    await s.t.action(internal.backendWrites.reconcile, {});
    await drained(s.t);
    expect((await renameRow(s, view.id))!.code).toBe('servers.rename_host_refused');
    // Fixed on the backend side: an operator retries, and the rename finishes.
    refuse = false;
    const res = await s.call('POST', `renames/${view.id}/retry`);
    expect(res.status).toBe(200);
    const done = await settledRename(s, view.id);
    expect(done!.state).toBe('done');
    expect(s.panel.hosts.find((h) => h.uuid === s.relayHostUuid)!.remark).toBe('node-b-relay-a');
  });

  test('a name another running rename is about to give is taken', async () => {
    const s = await seed();
    s.panel.nodes.push({
      uuid: '00000902-0000-4000-8000-000000000000',
      name: 'other',
      address: '192.0.2.31',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: s.panel.profiles[0].uuid, activeInbounds: [] },
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    await parkedRename(s, 'node-b');
    const res = await rename(s, 'node-b', '00000902-0000-4000-8000-000000000000');
    expect(await errCode(res)).toBe('servers.node_name_taken');
  });

  test('a chain of renames resolves to its end, however long', async () => {
    const s = await seed();
    const renameId = (await s.t.run((ctx) =>
      ctx.db.insert('panelNodeRenames', {
        backendServerId: s.serverId,
        nodeUuid: s.nodeUuid,
        from: 'n0',
        to: 'n12',
        relayIds: [],
        state: 'done',
        step: 'done',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    )) as Id<'panelNodeRenames'>;
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 12; i++)
        await ctx.db.insert('panelNodeAliases', {
          backendServerId: s.serverId,
          formerName: `n${i}`,
          name: `n${i + 1}`,
          nodeUuid: s.nodeUuid,
          renameId,
          at: Date.now(),
        });
    });
    expect(await s.t.run((ctx) => currentNodeName(ctx.db, s.serverId, 'n0'))).toBe('n12');
    expect(await s.t.run((ctx) => currentNodeName(ctx.db, s.serverId, 'n12'))).toBeNull();
  });

  test('while a rename runs, no origin or setup run is keyed to the node, and it is not retired', async () => {
    const s = await seed();
    await parkedRename(s, 'node-b');
    // A new origin keyed to the name it is getting (its old one is bound already).
    for (const nodeName of ['node-b'])
      await expect(
        s.t.mutation(internal.relays.create, {
          slug: `x-${nodeName}`,
          origin: { kind: 'panel-node', backendServerId: s.serverId, nodeName },
          originAddress: '203.0.113.40',
          listeners: [],
        } as never),
      ).rejects.toThrow(/edge.panel_op_running/);
    // A guided setup run for it.
    const accountId = await createAccount(s.t);
    await expect(
      s.t.mutation(internal.edgeSetupRuns.insert, {
        plan: JSON.stringify({
          backendServerId: s.serverId,
          nodeUuid: s.nodeUuid,
          nodeName: 'node-a',
          accounts: [],
        }),
        planHash: 'h',
        accountId,
        approvedHideUuids: [],
      }),
    ).rejects.toThrow(/edge.panel_op_running/);
    // Its retirement, by the role or by an admin.
    await expect(
      s.t.mutation(internal.nodeIntents.requestRetirement, {
        intentId: s.intentId,
        requestedBy: 'role',
      }),
    ).rejects.toThrow(/servers.node_rename_running/);
    await expect(
      s.t.mutation(internal.nodeRetirement.decide, {
        intentId: s.intentId,
        disposition: 'keep-dark',
      }),
    ).rejects.toThrow(/servers.node_rename_running/);
  });

  test('a token spanning several backends does not gain the new name; one bounded to this backend does', async () => {
    const s = await seed();
    const otherServer = await insertPanelServer(s.t, { slug: 'panel-b' });
    const ids = await s.t.run(async (ctx) => {
      const admin = (await ctx.db.query('adminUsers').first())!;
      const wide = await ctx.db.insert('apiTokens', {
        name: 'wide',
        tokenHash: 'h2',
        tokenPrefix: 'p2',
        createdByAdminId: admin._id,
        scopes: ['admin:edges:register'],
        subjectType: 'service',
        edgeRegistration: { backendServerIds: [otherServer, s.serverId], nodeNames: ['node-a'] },
        updatedAt: Date.now(),
      });
      const elsewhere = await ctx.db.insert('apiTokens', {
        name: 'elsewhere',
        tokenHash: 'h3',
        tokenPrefix: 'p3',
        createdByAdminId: admin._id,
        scopes: ['admin:edges:register'],
        subjectType: 'service',
        edgeRegistration: { backendServerIds: [otherServer], nodeNames: ['node-a'] },
        updatedAt: Date.now(),
      });
      return { wide, elsewhere };
    });
    const view = NodeRenameView.parse(await (await rename(s, 'node-b')).json());
    expect((await settledRename(s, view.id))!.state).toBe('done');
    const tokens = await s.t.run((ctx) => ctx.db.query('apiTokens').collect());
    const names = (id: Id<'apiTokens'>) =>
      tokens.find((t) => t._id === id)!.edgeRegistration!.nodeNames;
    // The seed's token is bounded to this backend alone: it gains the name.
    expect(tokens.find((t) => t.name === 'role')!.edgeRegistration!.nodeNames).toEqual([
      'node-a',
      'node-b',
    ]);
    // A token for other backends too would reach their `node-b` as well: unchanged.
    expect(names(ids.wide)).toEqual(['node-a']);
    expect(names(ids.elsewhere)).toEqual(['node-a']);
    // The role keeps acting for the node under the name it was given.
    expect((await s.call('GET', 'nodes/by-name/node-a')).status).toBe(200);
  });
});
