/// <reference types="vite/client" />
/**
 * A node serving an extra mode (docs/servers.md "A node serving an extra
 * mode"): Hysteria 2 on UDP 443 beside the node's own direct REALITY on TCP
 * 443, against the fake backend that renders Hysteria as Remnawave 3.4.8 does
 * (a pin turned into "skip verification" in Mihomo and sing-box):
 *
 *  - staged until the node's firewall lets 443/udp in: a TCP report never
 *    confirms it, a UDP report does;
 *  - then the transport is on for the node, its address is made with the pin
 *    and the rewrites that make every format verify by pin, and it serves only
 *    once the rehearsal saw it pinned in every body;
 *  - a new certificate closes ONLY this mode, then it is rehearsed again under
 *    the new pin, while the REALITY address never goes off;
 *  - a rehearsal that fails turns the address off again;
 *  - removal takes the address away, then the transport;
 *  - an adopted node (no role) is confirmed by an admin;
 *  - what may not be served beside a node's mode is refused up front.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import YAML from 'yaml';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { installFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { signValue } from './lib/cookies';
import { generateHysteriaCertificate } from './lib/backend/hysteriaCert';
import { NodeIntentView } from '../src/shared/contracts/servers';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

vi.setConfig({ testTimeout: 60_000 });

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
let current: T | null = null;
afterEach(async () => {
  if (current) {
    const t = current;
    current = null;
    await until(
      () => t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
  }
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 4000; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

const HY = 'PRIVACY_HYSTERIA';

async function seed(opts: { hysteriaName?: string } = {}) {
  const t = convexTest(schema, modules);
  current = t;
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend({ applyNodeUpdates: true });
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.run(async (ctx) => {
    await ctx.db.insert('connectionModes', {
      slug: 'privacy-hysteria',
      familySlug: 'privacy',
      deliveryStyle: 'rawConfig',
      enabled: false,
      isFamilyDefault: false,
      backends: ['remnawave'],
      order: 5,
      updatedAt: Date.now(),
    });
  });
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
    input: {
      profileName: 'FreeSocks-Config',
      modes: [
        {
          slug: 'privacy-reality',
          name: 'Privacy-Reality',
          shape: { transport: 'reality', fronting: 'direct' },
          familySlug: 'fam-direct',
          acceptProxyProtocol: false,
        },
        {
          slug: 'privacy-hysteria',
          name: 'Privacy-Hysteria',
          shape: { transport: 'hysteria', fronting: 'direct' },
          acceptProxyProtocol: false,
          hysteria: { serverName: opts.hysteriaName ?? 'quic.example', salamander: false },
        },
      ],
      originDns: null,
      adopt: false,
    },
  });
  const setup = await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim,
  );
  expect(setup!.state).toBe('ready');
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
  await t.mutation(internal.nodeIntents.applied, {
    intentId,
    appliedRevision: 1,
    nodeStarted: true,
  });
  await idle();

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
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const hyUuid = (panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
    (i) => i.tag === HY,
  )!.uuid;
  return { t, serverId, panel, intentId, call, idle, hyUuid };
}
type Seeded = Awaited<ReturnType<typeof seed>>;

const intentOf = (s: Seeded) => s.t.run((ctx) => ctx.db.get(s.intentId));
const extraOf = async (s: Seeded) => (await intentOf(s))!.extraModes?.[0];
const roleView = async (s: Seeded) =>
  (await s.call('GET', 'nodes/by-name/node-a')).json() as Promise<{
    firewall: { ports: { port: number; protocol: string; reason: string }[] };
  }>;
const hyHosts = (s: Seeded) =>
  s.panel.hosts.filter((h) => h.inbound?.configProfileInboundUuid === s.hyUuid);
const nodeActive = (s: Seeded) =>
  s.panel.nodes
    .find((n) => n.name === 'node-a')!
    .configProfile.activeInbounds.map((i: { uuid: string }) => i.uuid) as string[];
const storedPins = async (s: Seeded) =>
  (await s.t.run((ctx) => ctx.db.query('panelProfiles').collect()))[0]!.inbounds.find(
    (i) => i.tag === HY,
  )!.hysteriaAuth!;
const extraMode = (s: Seeded, action: string) =>
  s.call('POST', `nodes/intents/${s.intentId}/extra-mode`, { mode: 'privacy-hysteria', action });
const report = (s: Seeded, ports: { port: number; protocol?: string }[]) =>
  s.call('POST', 'nodes/by-name/node-a/applied', {
    appliedRevision: 1,
    nodeStarted: true,
    firewall: { ports },
  });

async function bringToServing(s: Seeded) {
  expect((await extraMode(s, 'add')).status).toBe(200);
  expect(
    (
      await report(s, [
        { port: 443, protocol: 'tcp' },
        { port: 443, protocol: 'udp' },
      ])
    ).status,
  ).toBe(200);
  return until(
    () => extraOf(s),
    (x) => x?.state === 'serving' || x?.code === 'servers.rehearsal_failed',
  );
}

describe('a node serving Hysteria beside its own REALITY', () => {
  test('staged until its firewall lets 443/udp in; a TCP report never confirms it', async () => {
    const s = await seed();
    expect((await extraMode(s, 'add')).status).toBe(200);
    expect(await extraOf(s)).toMatchObject({
      state: 'waiting_firewall',
      firewall: { port: 443, protocol: 'udp', confirmedBy: 'role' },
    });
    expect((await roleView(s)).firewall.ports).toEqual([
      { port: 443, protocol: 'tcp', reason: 'serving' },
      { port: 443, protocol: 'udp', reason: 'pending' },
    ]);
    // Nothing on the backend moved yet.
    expect(nodeActive(s)).not.toContain(s.hyUuid);
    expect(hyHosts(s)).toHaveLength(0);
    // A role that opened TCP only (or predates protocols) confirms nothing.
    expect((await report(s, [{ port: 443 }])).status).toBe(200);
    expect((await extraOf(s))!.state).toBe('waiting_firewall');
    // The node view says what waits.
    const view = NodeIntentView.array().parse(
      ((await (await s.call('GET', 'nodes/intents')).json()) as { intents: unknown[] }).intents,
    );
    expect(view[0]!.extraModes).toEqual([
      expect.objectContaining({
        slug: 'privacy-hysteria',
        state: 'waiting_firewall',
        firewall: { port: 443, protocol: 'udp', confirmedBy: 'role', confirmed: false },
      }),
    ]);
  });

  test('then the transport goes on and its address serves, pinned in every format', async () => {
    const s = await seed();
    const e = await bringToServing(s);
    expect(e).toMatchObject({ state: 'serving', evidence: { checked: 'rehearsal' } });
    expect(e!.code).toBeUndefined();
    expect(nodeActive(s)).toContain(s.hyUuid);
    const pins = await storedPins(s);
    const [host] = hyHosts(s);
    expect(host).toMatchObject({
      remark: 'node-a | quic.example',
      address: '203.0.113.10',
      port: 443,
      sni: 'quic.example',
      alpn: 'h3',
      securityLayer: 'TLS',
      pinnedPeerCertSha256: pins.pinHex,
      isDisabled: false,
    });
    // What members' apps get: verified by pin, in every format, never "insecure".
    const link = s.panel
      .bodyFor('v2rayNG/1.8.29')
      .split('\n')
      .find((l) => l.startsWith('hysteria2://'))!;
    const q = new URL(link.replace('hysteria2://', 'https://')).searchParams;
    expect(q.get('pinSHA256')).toBe(pins.pinHex);
    expect(q.get('insecure')).toBeNull();
    expect(q.get('fm')).toBeNull();
    const sb = JSON.parse(s.panel.bodyFor('SFI/1.11.0 sing-box/1.11.0')).outbounds.find(
      (o: { type: string }) => o.type === 'hysteria2',
    );
    expect(sb.tls.certificate_public_key_sha256).toEqual([pins.spkiB64]);
    expect(sb.tls.insecure).toBeUndefined();
    const clash = (
      YAML.parse(s.panel.bodyFor('clash-verge/2.0.0 mihomo/1.19.0')) as {
        proxies: Record<string, unknown>[];
      }
    ).proxies.find((p) => p.type === 'hysteria2')!;
    expect(clash.fingerprint).toBe(pins.pinHex);
    expect(clash['skip-cert-verify']).toBeUndefined();
    // The node's own REALITY address is untouched, and the extra one is not in its list.
    const intent = await intentOf(s);
    expect(intent!.addressUuids ?? []).not.toContain(host.uuid);
    // The mode's own check credential sits in the Hysteria group, never the node's own.
    const creds = await s.t.run((ctx) => ctx.db.query('edgeTestCredentials').collect());
    expect(creds.filter((c) => c.modeSlug === 'privacy-hysteria')).toHaveLength(1);
  });

  test('a new certificate closes only this mode, then it serves again under the new pin', async () => {
    const s = await seed();
    await bringToServing(s);
    const before = await storedPins(s);
    const reality = s.panel.hosts.filter((h) => h.inbound?.configProfileInboundUuid !== s.hyUuid);
    expect(reality.length).toBeGreaterThan(0);
    // An operator replaces the certificate on the profile.
    const fresh = generateHysteriaCertificate('quic.example');
    const ib = (s.panel.profiles[0].config.inbounds as any[]).find((i) => i.tag === HY);
    ib.streamSettings.tlsSettings.certificates = [
      { certificate: fresh.certificate, key: fresh.key },
    ];
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    expect((await storedPins(s)).pinHex).toBe(fresh.pinHex);
    await s.t.action(internal.nodeExtraModes.run, { intentId: s.intentId });
    const e = await until(
      () => extraOf(s),
      (x) => x?.state === 'serving',
    );
    expect(e!.evidence!.revision).toContain(fresh.pinHex);
    expect(hyHosts(s)[0]!.pinnedPeerCertSha256).toBe(fresh.pinHex);
    expect(hyHosts(s)[0]!.pinnedPeerCertSha256).not.toBe(before.pinHex);
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.map((a) => a.action)).toContain('servers.node.extra_mode_closed');
    // REALITY was never switched off: no write ever disabled one of its addresses.
    const realityUuids = new Set(reality.map((h) => h.uuid));
    expect(
      s.panel.writes.filter(
        (w) =>
          w.call === 'PATCH /api/hosts' &&
          realityUuids.has((w.body as { uuid?: string }).uuid ?? '') &&
          (w.body as { isDisabled?: boolean }).isDisabled === true,
      ),
    ).toEqual([]);
  });

  test('a rehearsal that does not see the pin turns the address off again', async () => {
    const s = await seed();
    const real = s.panel.bodyFor;
    // A backend that drops the pin in links (as one without the rewrites would).
    s.panel.bodyFor = (ua) => real(ua).replace(/pinSHA256=[0-9a-f]+&?/, '');
    expect((await extraMode(s, 'add')).status).toBe(200);
    await report(s, [{ port: 443, protocol: 'udp' }]);
    const e = await until(
      () => extraOf(s),
      (x) => x?.code === 'servers.rehearsal_failed',
    );
    expect(e!.state).toBe('activating');
    expect(hyHosts(s)[0]!.isDisabled).toBe(true);
  });

  test('removal takes the address away, then the transport', async () => {
    const s = await seed();
    await bringToServing(s);
    expect((await extraMode(s, 'remove')).status).toBe(200);
    await until(
      () => intentOf(s),
      (i) => !i?.extraModes?.length,
    );
    await until(
      async () => nodeActive(s),
      (a) => !a.includes(s.hyUuid),
    );
    expect(hyHosts(s)).toHaveLength(0);
  });
});

describe('what is refused up front', () => {
  test('a Hysteria name that is one of the REALITY names', async () => {
    const s = await seed({ hysteriaName: 'decoy-a.example' });
    const res = await extraMode(s, 'add');
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe('servers.extra_mode_name_collision');
  });

  test('the node’s own mode, a mode twice, a REALITY mode', async () => {
    const s = await seed();
    const own = await s.call('POST', `nodes/intents/${s.intentId}/extra-mode`, {
      mode: 'privacy-reality',
      action: 'add',
    });
    expect((await own.json()).error.code).toBe('servers.extra_mode_present');
    expect((await extraMode(s, 'add')).status).toBe(200);
    expect((await (await extraMode(s, 'add')).json()).error.code).toBe(
      'servers.extra_mode_present',
    );
  });

  test('a node no role runs is confirmed by an admin, never by a report', async () => {
    const s = await seed();
    await s.t.run((ctx) =>
      ctx.db.patch(s.intentId as Id<'panelNodeIntents'>, {
        adopted: { at: Date.now(), externallyFronted: false },
      }),
    );
    expect((await extraMode(s, 'add')).status).toBe(200);
    expect((await extraOf(s))!.firewall.confirmedBy).toBe('operator');
    const ok = await extraMode(s, 'firewall-confirmed');
    expect(ok.status).toBe(200);
    expect((await extraOf(s))!.state).not.toBe('waiting_firewall');
  });
});
