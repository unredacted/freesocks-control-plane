/// <reference types="vite/client" />
/**
 * Activating a direct node on the fake panel: the test link is built from the
 * node's own credential and the inbound's live parameters and carries a
 * binding; a confirmation with a moved endpoint is refused; approval creates
 * one run; the Host is enabled as a candidate and the gate stays closed; a
 * forced rehearsal failure disables it again and releases nothing; a passing
 * rehearsal commits and the gate opens. Fixtures use RFC 5737 addresses and
 * `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { generateRealityKey } from './lib/panel/realityKeys';

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
});

const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;
const USER_UUID = 'aaaaaaaa-1111-4222-8333-444444444444';

interface Panel {
  profiles: any[];
  squads: any[];
  hosts: any[];
  nodes: any[];
  users: any[];
  writes: { call: string; body: any }[];
  seq: number;
  /** What the panel serves as the credential's subscription body per UA family. */
  bodyFor: (ua: string) => string;
}

function installPanel(): Panel {
  const panel: Panel = {
    profiles: [],
    squads: [],
    hosts: [],
    nodes: [],
    users: [],
    writes: [],
    seq: 10,
    bodyFor: () => '',
  };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const enabledHosts = () => panel.hosts.filter((h) => !h.isDisabled);
  // The panel's own body: one vless link per enabled Host on the reality inbound.
  panel.bodyFor = (ua: string) => {
    const pk = panel.profiles[0]?.publicKeyByTag?.VLESS_REALITY ?? 'pk';
    const entries = enabledHosts().map((h) => ({
      remark: h.remark,
      address: h.address,
      port: h.port,
      sni: h.sni,
      pk,
    }));
    if (/sing-box/i.test(ua))
      return JSON.stringify({
        outbounds: entries.map((e) => ({
          type: 'vless',
          tag: e.remark,
          server: e.address,
          server_port: e.port,
          tls: { enabled: true, reality: { enabled: true, public_key: e.pk } },
        })),
      });
    if (/clash|mihomo/i.test(ua))
      return `proxies:\n${entries
        .map(
          (e) =>
            `  - name: ${e.remark}\n    type: vless\n    server: ${e.address}\n    port: ${e.port}\n    reality-opts:\n      public-key: ${e.pk}\n`,
        )
        .join('')}`;
    return entries
      .map(
        (e) =>
          `vless://${USER_UUID}@${e.address}:${e.port}?encryption=none&security=reality&type=tcp&sni=${e.sni}&fp=chrome&pbk=${e.pk}&sid=#${e.remark}`,
      )
      .join('\n');
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      const path = url.pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body as string) : {};
      const headers = new Headers(init.headers as HeadersInit | undefined);
      if (method === 'GET') {
        if (path === '/api/nodes')
          return json(panel.nodes.map((n) => ({ ...n, isConnected: true })));
        if (path === '/api/hosts') return json(panel.hosts);
        if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
        if (path === '/api/config-profiles') return json({ configProfiles: panel.profiles });
        if (path === '/api/keygen') return json({ pubKey: 'panel-node-secret-placeholder' });
        if (path === '/api/subscription-templates') return json([]);
        const p = panel.profiles.find((x) => path === `/api/config-profiles/${x.uuid}`);
        if (p) return json(p);
        const u = panel.users.find((x) => path === `/api/users/${x.uuid}`);
        if (u) return json(u);
        if (path.startsWith('/api/hwid/devices/')) return json({ devices: [] });
        if (path.startsWith('/api/sub/'))
          return new Response(panel.bodyFor(headers.get('user-agent') ?? ''), {
            status: 200,
            headers: { 'content-type': 'text/plain' },
          });
        return json({});
      }
      panel.writes.push({ call: `${method} ${path}`, body });
      if (path === '/api/config-profiles' && method === 'POST') {
        const uuid = UUID(++panel.seq);
        const inbounds = (body.config.inbounds as { tag: string }[]).map((i) => ({
          uuid: UUID(++panel.seq),
          tag: i.tag,
        }));
        const publicKeyByTag: Record<string, string> = {};
        for (const i of body.config.inbounds as any[])
          if (i.streamSettings?.realitySettings?.privateKey)
            publicKeyByTag[i.tag] = i.streamSettings.realitySettings.privateKey;
        panel.profiles.push({
          uuid,
          name: body.name,
          config: body.config,
          inbounds,
          publicKeyByTag,
        });
        return json({ uuid }, 201);
      }
      if (path === '/api/internal-squads' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          inbounds: (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid })),
        };
        panel.squads.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/hosts' && method === 'POST') {
        const made = { uuid: UUID(++panel.seq), ...body, isDisabled: body.isDisabled === true };
        panel.hosts.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/hosts' && method === 'PATCH') {
        const h = panel.hosts.find((x) => x.uuid === body.uuid)!;
        Object.assign(h, body);
        return json(h);
      }
      if (path === '/api/nodes' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          address: body.address,
          port: body.port ?? 2222,
          countryCode: body.countryCode ?? 'XX',
          isDisabled: false,
          lastStatusChange: 't0',
          configProfile: {
            activeConfigProfileUuid: body.configProfile.activeConfigProfileUuid,
            activeInbounds: (body.configProfile.activeInbounds as string[]).map((uuid) => ({
              uuid,
              tag: uuid,
            })),
          },
        };
        panel.nodes.push(made);
        return json(made, 201);
      }
      if (path === '/api/users' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          shortUuid: `short-${panel.seq}`,
          vlessUuid: USER_UUID,
          username: body.username,
          status: 'ACTIVE',
          subscriptionUrl: `https://panel.example/api/sub/short-${panel.seq}`,
          trafficLimitBytes: 0,
          usedTrafficBytes: 0,
          hwidDeviceLimit: null,
          expireAt: body.expireAt ?? new Date(Date.now() + 86_400_000).toISOString(),
          activeInternalSquads: [],
        };
        panel.users.push(made);
        return json(made, 201);
      }
      return json({});
    }),
  );
  return panel;
}

const setupInput = {
  profileName: 'FreeSocks-Config',
  cdn: { path: '/ws', port: 8443 },
  reality: { target: { address: 'decoy-a.example', port: 443 }, serverNames: ['decoy-a.example'] },
  relay: {
    target: { address: 'decoy-b.example', port: 443 },
    serverNames: ['decoy-b.example'],
    acceptProxyProtocol: false,
  },
  squads: { fronted: 'FreeSocks-Fronted', reality: 'FreeSocks-Reality', relay: 'FreeSocks-Relay' },
  originDns: null,
};

async function settled<R extends { claim?: unknown }>(get: () => Promise<R | null>): Promise<R> {
  for (let i = 0; i < 500; i++) {
    await new Promise((r) => setTimeout(r, 5));
    const row = await get();
    if (row && !row.claim) return row;
  }
  throw new Error('workflow did not settle');
}

async function runUntil<R extends { state: string }>(
  get: () => Promise<R | null>,
  done: (s: string) => boolean,
): Promise<R> {
  for (let i = 0; i < 500; i++) {
    await new Promise((r) => setTimeout(r, 5));
    const row = await get();
    if (row && done(row.state)) return row;
  }
  throw new Error('run did not settle');
}

async function seedLiveDirect() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  const started = await t.mutation(internal.panelSetup.start, {
    backendServerId: serverId,
    input: setupInput,
  });
  await settled(() => t.run((ctx) => ctx.db.get(started.setupId)));
  // The fake keeps the private key under `publicKeyByTag`; what the profile
  // observation derives is the real public key, so align the fake's bodies.
  const priv = panel.profiles[0].config.inbounds[1].streamSettings.realitySettings.privateKey;
  const { realityPublicKey } = await import('./lib/panel/digest');
  panel.profiles[0].publicKeyByTag.VLESS_REALITY = realityPublicKey(priv);
  const { intentId } = await t.mutation(internal.panelIntents.enroll, {
    backendServerId: serverId,
    name: 'node-a',
    purpose: 'direct',
    contractVersion: 2,
    observed: {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    },
  });
  await settled(() => t.run((ctx) => ctx.db.get(intentId)));
  await t.mutation(internal.panelIntents.applied, {
    intentId,
    appliedRevision: 1,
    nodeStarted: true,
  });
  const intent = await settled(() => t.run((ctx) => ctx.db.get(intentId)));
  expect(intent.activation.stage).toBe('machine_ready');
  return { t, serverId, panel, intentId };
}

const gateOf = (t: T, serverId: Id<'backendServers'>) =>
  t.query(internal.panelIntents.nodeGate, { backendServerId: serverId, nodeName: 'node-a' });

describe('activating a direct node', () => {
  test('test link, bound confirmation, approval, candidate Host, rehearsal, commit', async () => {
    const { t, serverId, panel, intentId } = await seedLiveDirect();
    expect(generateRealityKey().privateKey).toBeTruthy();

    // The isolated link: the credential's uuid, the endpoint, the live parameters.
    const built = await t.action(internal.panelActivation.buildDirectTestLink, { intentId });
    expect(built.link).toMatch(
      /^vless:\/\/aaaaaaaa-1111-4222-8333-444444444444@203\.0\.113\.10:443\?/,
    );
    expect(built.link).toContain('security=reality');
    expect(built.binding).toMatchObject({
      endpoint: '203.0.113.10:443',
      machineRevision: 1,
      params: { sni: 'decoy-a.example', fingerprint: 'chrome' },
    });
    const creds = await t.run((ctx) => ctx.db.query('edgeTestCredentials').collect());
    expect(creds).toHaveLength(1);
    expect(creds[0]!.nodeIntentId).toBe(intentId);
    // No secret of the link (the short id, the credential uuid) in what FCP keeps.
    const kept = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelNodeIntents').collect(),
        await ctx.db.query('auditLog').collect(),
      ]),
    );
    expect(kept).not.toContain(USER_UUID);

    // A confirmation whose endpoint moved is refused; the right one advances the ladder.
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await expect(
      t.mutation(internal.panelActivation.confirmDirect, {
        intentId,
        binding: { ...binding, endpoint: '203.0.113.11:443' },
      }),
    ).rejects.toThrow(/confirmation_stale/);
    const confirmed = await t.mutation(internal.panelActivation.confirmDirect, {
      intentId,
      binding,
    });
    expect(confirmed.stage).toBe('candidates_verified');

    // Review and approve: one run, the Host still disabled, the gate closed.
    const review = await t.query(internal.panelActivation.review, { intentId });
    expect(review.blockers).toEqual([]);
    expect(review.shape.hostTuple).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'decoy-a.example',
    });
    await expect(
      t.mutation(internal.panelActivation.approve, { intentId, reviewHash: 'stale' }),
    ).rejects.toThrow(/review_stale/);
    const { runId } = await t.mutation(internal.panelActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    const run = await runUntil(
      () => t.run((ctx) => ctx.db.get(runId)),
      (s) => s !== 'running',
    );
    expect(run.state).toBe('committed');
    expect(panel.hosts[0]!.isDisabled).toBe(false);
    const intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.activation.stage).toBe('live');
    expect(intent.delivery.disposition).toBe('live');
    expect(intent.approved).toMatchObject({
      reviewHash: review.reviewHash,
      committed: { hostUuids: [panel.hosts[0]!.uuid], edgeIds: [] },
    });
    expect(intent.delivery.exposure).toMatchObject({
      everLive: true,
      hosts: [panel.hosts[0]!.uuid],
    });
    expect((await gateOf(t, serverId)).state).toBe('open');
    // Nothing kept holds the node secret or the credential uuid.
    const after = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelActivationRuns').collect(),
        await ctx.db.query('panelNodeIntents').collect(),
      ]),
    );
    expect(after).not.toContain('panel-node-secret-placeholder');
  });

  test('a failed rehearsal releases nothing: the Host goes back to disabled and the gate stays closed', async () => {
    const { t, serverId, panel, intentId } = await seedLiveDirect();
    const built = await t.action(internal.panelActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await t.mutation(internal.panelActivation.confirmDirect, { intentId, binding });
    // The panel's bodies will not carry the node (the fake serves another key).
    panel.profiles[0].publicKeyByTag.VLESS_REALITY = 'not-the-key';
    const review = await t.query(internal.panelActivation.review, { intentId });
    const { runId } = await t.mutation(internal.panelActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    const run = await runUntil(
      () => t.run((ctx) => ctx.db.get(runId)),
      (s) => s !== 'running',
    );
    expect(run.state).toBe('blocked');
    expect(run.code).toBe('servers.rehearsal_failed');
    expect(run.rehearsal?.ok).toBe(false);
    expect(panel.hosts[0]!.isDisabled).toBe(true);
    // The node is parked where it can be approved again; nothing is served.
    const intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.activation.stage).toBe('awaiting_approval');
    expect(intent.activation.currentRunId).toBeUndefined();
    expect(intent.delivery.disposition).toBe('staged');
    expect(intent.approved).toBeUndefined();
    expect((await gateOf(t, serverId)).state).toBe('blocked');

    // With the cause fixed, a fresh approval starts a fresh run and commits.
    const { realityPublicKey } = await import('./lib/panel/digest');
    panel.profiles[0].publicKeyByTag.VLESS_REALITY = realityPublicKey(
      panel.profiles[0].config.inbounds[1].streamSettings.realitySettings.privateKey,
    );
    const again = await t.query(internal.panelActivation.review, { intentId });
    expect(again.blockers).toEqual([]);
    const { runId: runId2 } = await t.mutation(internal.panelActivation.approve, {
      intentId,
      reviewHash: again.reviewHash,
    });
    expect(runId2).not.toBe(runId);
    const run2 = await runUntil(
      () => t.run((ctx) => ctx.db.get(runId2)),
      (s) => s !== 'running',
    );
    expect(run2.state).toBe('committed');
    expect((await t.run((ctx) => ctx.db.get(runId)))!.state).toBe('superseded');
    expect((await gateOf(t, serverId)).state).toBe('open');
  });

  test('a moved endpoint under a live node is observed drift: the gate closes, the Host follows, the tick is gone', async () => {
    const { t, serverId, panel, intentId } = await seedLiveDirect();
    const built = await t.action(internal.panelActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await t.mutation(internal.panelActivation.confirmDirect, { intentId, binding });
    const review = await t.query(internal.panelActivation.review, { intentId });
    const { runId } = await t.mutation(internal.panelActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    await runUntil(
      () => t.run((ctx) => ctx.db.get(runId)),
      (s) => s !== 'running',
    );
    expect((await gateOf(t, serverId)).state).toBe('open');

    // The role reports a new public address: the committed Host's tuple is dead.
    await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      purpose: 'direct',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4: '203.0.113.11' },
        capabilities: { caddy: false, ipv6: false },
      },
    });
    const intent = await settled(() => t.run((ctx) => ctx.db.get(intentId)));
    expect(intent.delivery.disposition).toBe('unavailable');
    expect(intent.maintenance?.reason).toBe('drift');
    expect(intent.activation.currentRunId).toBeUndefined();
    expect(intent.activation.evidence.some((e) => e.kind === 'direct_confirmed')).toBe(false);
    expect(intent.activation.stage).not.toBe('live');
    expect((await gateOf(t, serverId)).state).toBe('blocked');
    // The existing Host now carries the new endpoint; the approved snapshot is untouched.
    expect(panel.hosts).toHaveLength(1);
    expect(panel.hosts[0]!.address).toBe('203.0.113.11');
    expect(intent.approved?.reviewHash).toBe(review.reviewHash);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'servers.node.drift')).toBe(true);
  });

  test('a moved observation supersedes the run and a stale commit is refused', async () => {
    const { t, panel, intentId } = await seedLiveDirect();
    const built = await t.action(internal.panelActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await t.mutation(internal.panelActivation.confirmDirect, { intentId, binding });
    const review = await t.query(internal.panelActivation.review, { intentId });
    // An in-place machine change before the run commits: the review is stale, the run superseded.
    await t.mutation(internal.panelIntents.patchSettings, {
      intentId,
      patch: { nodePort: 2223 },
    });
    await expect(
      t.mutation(internal.panelActivation.approve, { intentId, reviewHash: review.reviewHash }),
    ).rejects.toThrow(/machine_not_ready|review_stale|direct_unconfirmed/);
    const intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.machineRevision).toBe(2);
    expect(intent.activation.stage).toBe('bootstrap_available');
    expect(panel.hosts[0]!.isDisabled).toBe(true);
  });
});
