/// <reference types="vite/client" />
/**
 * The isolated test link (docs/edges.md § "Publication"; acceptance 26, the
 * test-link part): from a REALISTIC credential body that carries only the
 * node's direct Host under a different remark and NO FCP Host, the test-only
 * matcher resolves the intended transport's entry and the real renderer emits
 * exactly one connection, the candidate's; pool, epoch, Hosts, snapshots and
 * persisted match rules are unchanged; an ambiguous body is refused
 * (`edge.test_link_no_match`); the binding is the one the confirmation accepts.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { fakeOutline, fakePanel, type FakePanelHost } from './lib/edges/testing/fakePanel';
import {
  adoptL4Edge,
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  FIXTURE_ORIGIN,
  insertPanelServer,
  registerRelay,
  seedEdgeFixture,
  shadowsocksListener,
} from './lib/edges/testing/fixtures';
import { realityEntryLine, selectTestEntry, TEST_LINK_USER_AGENT } from './edgeTestLinks';
import { parseProxyUri } from './lib/edges/render/uri';
import { expireTestCredential } from './lib/edges/testing/reads';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const ORIGIN = FIXTURE_ORIGIN;
const SPARE = '198.51.100.7';
const OTHER_NODE = '203.0.113.20';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';
const H = (n: number) => `aaaaaaaa-aaaa-4aaa-8aaa-${n.toString().padStart(12, '0')}`;
const INBOUND_B = '55555555-5555-4555-8555-555555555555';

const directHost = (over: Partial<FakePanelHost> = {}): FakePanelHost => ({
  uuid: H(1),
  remark: 'node-one-reality',
  address: ORIGIN,
  port: 443,
  sni: 'a.example',
  inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: FIXTURE_INBOUND },
  ...over,
});

/** The body the backend serves the credential: this node's direct entry (a role-style remark) + another node's. */
function realisticBody(uuid: string, lines: string[] = []): string {
  return [
    `vless://${uuid}@${ORIGIN}:443?${REALITY_QS}#node-one-reality`,
    `vless://${uuid}@${OTHER_NODE}:443?${REALITY_QS}#node-two-reality`,
    ...lines,
  ].join('\n');
}

/** What the backend serves an account it has limited: a placeholder, no real entry. */
const LIMITED_BODY =
  'vless://00000000-0000-4000-8000-000000000000@0.0.0.0:1?encryption=none&type=tcp#Subscription%20limited';

/** A 32-byte REALITY private key (base64url), as the panel stores it. */
const REALITY_PRIVATE_KEY = Buffer.alloc(32, 7).toString('base64url');

/**
 * The node's config profile as the panel serves it: its REALITY transport with
 * the live parameters a test entry is built from (`tag`: the transport it holds).
 */
function realityProfile(tag = 'VLESS_RELAY_A') {
  return {
    [FIXTURE_CONFIG_PROFILE]: {
      uuid: FIXTURE_CONFIG_PROFILE,
      name: 'node-one',
      config: {
        inbounds: [
          {
            tag,
            port: 443,
            protocol: 'vless',
            settings: { clients: [] },
            streamSettings: {
              network: 'tcp',
              security: 'reality',
              realitySettings: {
                dest: 'target.example:443',
                serverNames: ['target.example'],
                privateKey: REALITY_PRIVATE_KEY,
                shortIds: ['abcd'],
              },
            },
          },
        ],
      },
      inbounds: [{ uuid: FIXTURE_INBOUND, tag }],
    },
  };
}

async function seed(
  opts: {
    hosts?: FakePanelHost[];
    extraLines?: string[];
    profiles?: Record<string, unknown>;
    lines?: (uuid: string) => string[];
  } = {},
) {
  const panel = fakePanel({
    profiles: opts.profiles,
    hosts: opts.hosts ?? [directHost()],
    body: (u) =>
      u
        ? u.status === 'ACTIVE'
          ? opts.lines
            ? opts.lines(u.vlessUuid).join('\n')
            : realisticBody(u.vlessUuid, opts.extraLines)
          : LIMITED_BODY
        : null,
  });
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t);
  // A bound pool so the credential mints on the node's placement.
  await t.run((ctx) =>
    ctx.db.insert('modePlacements', {
      modeSlug: 'freedom-ws',
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: ['sq-node-one'] }),
      updatedAt: Date.now(),
    }),
  );
  // The candidate: an active, UNPUBLISHED, untested L4 spare.
  const { edgeId } = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
    ipv4: SPARE,
    verified: false,
  });
  const snapshot = async () => {
    const relay = (await t.run((ctx) => ctx.db.get(fx.relayId)))!;
    const listener = (await t.run((ctx) => ctx.db.get(fx.listenerId)))!;
    const edge = (await t.run((ctx) => ctx.db.get(edgeId as Id<'edges'>)))!;
    return {
      publishedEdgeIds: relay.publishedEdgeIds,
      epoch: relay.publicationEpoch,
      matchRule: listener.matchRule,
      revision: listener.revision,
      host: listener.host ?? null,
      publication: edge.publication,
      verification: edge.verification ?? null,
      subs: await t.run((ctx) => ctx.db.query('subscriptions').collect()),
    };
  };
  return { t, fx, panel, edgeId: edgeId as Id<'edges'>, snapshot };
}

describe('the isolated test link', () => {
  test('a realistic body (direct Host under a different remark, no FCP Host): exactly one connection, the candidate; nothing persisted; the binding is accepted by the confirmation', async () => {
    const { t, fx, panel, edgeId, snapshot } = await seed();
    const before = await snapshot();
    const r = await t.action(internal.edgeTestLinks.build, { edgeId });
    expect(r.format).toBe('links');
    const lines = r.link.split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const u = parseProxyUri(lines[0])!;
    expect(u.host).toBe(SPARE);
    expect(u.port).toBe(443);
    expect(['a.example', 'b.example']).toContain(u.params.get('sni'));
    expect(u.params.get('pbk')).toBe('PUBKEY'); // credentials + routing untouched
    expect(r.link).not.toContain(ORIGIN);
    expect(r.link).not.toContain(OTHER_NODE);
    expect(decodeURIComponent(u.fragment!)).toBe('FCP test node-one a');
    expect(r.credentialId).toBeNull(); // the origin's qualification user, no temporary row
    // The binding equals what the verification route derives, and the tick accepts it.
    const b = (await t.query(internal.edgeVerification.binding, { edgeId }))!;
    expect(r.binding).toMatchObject({
      edgeId: edgeId as string,
      endpoint: b.endpoint,
      listenerKey: b.listenerKey,
      listenerRevision: b.listenerRevision,
      configHash: b.configHash,
    });
    expect(r.binding.endpoint).toBe(`${SPARE}:443`);
    const confirmed = await t.mutation(internal.edgeVerification.confirm, {
      edgeId,
      endpoint: r.binding.endpoint,
      listenerRevision: r.binding.listenerRevision,
      configHash: r.binding.configHash,
      method: 'test_link',
    });
    expect(confirmed.ok).toBe(true);
    // Nothing else moved: pool, epoch, match rule, listener revision, Host state, publication.
    const after = await snapshot();
    expect(after.publishedEdgeIds).toEqual(before.publishedEdgeIds);
    expect(after.epoch).toBe(before.epoch);
    expect(after.matchRule).toEqual(before.matchRule);
    expect(after.revision).toBe(before.revision);
    expect(after.host).toEqual(before.host);
    expect(after.publication).toBe('unpublished');
    expect(after.subs).toEqual([]);
    expect(after.verification?.method).toBe('test_link'); // the tick, not the link, wrote this
    // The backend saw reads only: no Host write, no second user.
    const writes = panel.calls.filter(
      (c) => c.method !== 'GET' && !(c.method === 'POST' && c.path === '/api/users'),
    );
    expect(writes).toEqual([]);
    expect(panel.created).toHaveLength(1);
    expect(panel.calls.find((c) => c.path.startsWith('/api/sub/'))?.headers['user-agent']).toBe(
      TEST_LINK_USER_AGENT,
    );
    // A second link reuses the credential (no new user) and renders the same endpoint.
    const r2 = await t.action(internal.edgeTestLinks.build, { edgeId });
    expect(panel.created).toHaveLength(1);
    expect(parseProxyUri(r2.link)!.host).toBe(SPARE);
    void fx;
  });

  test('a candidate server name: the link presents exactly that name, and nothing else changes', async () => {
    const { t, edgeId } = await seed();
    const plain = await t.action(internal.edgeTestLinks.build, { edgeId });
    const candidate = await t.action(internal.edgeTestLinks.build, {
      edgeId,
      candidateSni: 'never-handed-out.example',
    });
    const sni = (link: string) =>
      new URLSearchParams(link.slice(link.indexOf('?') + 1).split('#')[0]).get('sni');
    expect(sni(candidate.link)).toBe('never-handed-out.example');
    expect(sni(plain.link)).not.toBe('never-handed-out.example');
    // Same endpoint, same credential material, same binding: only the name differs.
    const strip = (link: string) => link.replace(/sni=[^&#]*/, 'sni=X');
    expect(strip(candidate.link)).toBe(strip(plain.link));
    expect(candidate.binding).toMatchObject({
      endpoint: plain.binding.endpoint,
      listenerRevision: plain.binding.listenerRevision,
      configHash: plain.binding.configHash,
    });
    // The name reached no listener: a test link hands nothing to members.
    const listeners = await t.run((ctx) => ctx.db.query('relayListeners').collect());
    expect(JSON.stringify(listeners)).not.toContain('never-handed-out.example');
  });

  test('a used-up test account is reset (and re-enabled) before the body is fetched; one the backend will not reset is named, never a dead link', async () => {
    const { t, panel, edgeId } = await seed();
    await t.action(internal.edgeTestLinks.build, { edgeId }); // mints the account
    const user = [...panel.users.values()][0]!;
    // A test profile left connected in a client: the backend limited the account.
    user.status = 'LIMITED';
    user.usedTrafficBytes = 706906753;
    panel.calls.length = 0;
    const r = await t.action(internal.edgeTestLinks.build, { edgeId });
    expect(r.link.split('\n').filter(Boolean)).toHaveLength(1);
    expect(r.link).not.toContain('0.0.0.0');
    const order = panel.calls.map((c) => `${c.method} ${c.path}`);
    const reset = order.indexOf(`POST /api/users/${user.uuid}/actions/reset-traffic`);
    const enable = order.indexOf(`POST /api/users/${user.uuid}/actions/enable`);
    const body = order.findIndex((x) => x.startsWith('GET /api/sub/'));
    expect(reset).toBeGreaterThanOrEqual(0);
    expect(enable).toBeGreaterThan(reset);
    expect(body).toBeGreaterThan(enable);

    // Used up again, and the backend refuses the reset: the reason, not a link.
    user.status = 'LIMITED';
    user.usedTrafficBytes = 706906753;
    panel.failResetWith = 500;
    await expect(t.action(internal.edgeTestLinks.build, { edgeId })).rejects.toThrow(
      /edge\.test_account_used_up.*used up and could not be reset/,
    );
  });

  test('an ambiguous body (two direct Hosts on the transport at the origin) is refused; a body with no entry for the transport too', async () => {
    const { t, edgeId } = await seed({
      hosts: [directHost(), directHost({ uuid: H(2), remark: 'node-one-reality-copy' })],
      extraLines: [`vless://x@${ORIGIN}:443?${REALITY_QS}#node-one-reality-copy`],
    });
    await expect(t.action(internal.edgeTestLinks.build, { edgeId })).rejects.toThrow(
      /test_link_no_match/,
    );
  });

  test("a node FCP does not manage, fronted by the operator's own load balancer: no Host dials the node, so the entry is built from the transport's live REALITY parameters", async () => {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    // Members dial the operator's load balancer (its Host `<node>-relay` at its
    // own address); nothing in the body is at the node's address.
    const LB = '198.51.100.20';
    const { t, edgeId } = await seed({
      hosts: [directHost({ remark: 'node-one-relay', address: LB })],
      lines: (uuid) => [`vless://${uuid}@${LB}:443?${REALITY_QS}#node-one-relay`],
      profiles: realityProfile(),
    });
    const r = await t.action(internal.edgeTestLinks.build, { edgeId });
    const lines = r.link.split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const u = parseProxyUri(lines[0])!;
    expect(u.host).toBe(SPARE);
    expect(u.params.get('security')).toBe('reality');
    expect(u.params.get('pbk')).toBeTruthy();
    expect(u.params.get('sid')).toBe('abcd');
    expect(r.link).not.toContain(LB);
    expect(r.link).not.toContain(ORIGIN);
  });

  test('the plan asks the panel first: a transport it describes with a key can be built, one it no longer holds cannot', async () => {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const ready = await seed({ profiles: realityProfile() });
    const ask = (t: typeof ready.t, tag: string) =>
      t.action(internal.edgeTestLinks.synthesisReady, {
        backendServerId: ready.fx.serverId,
        profileUuid: FIXTURE_CONFIG_PROFILE,
        tag,
      });
    expect(await ask(ready.t, 'VLESS_RELAY_A')).toBe(true);
    expect(await ask(ready.t, 'VLESS_GONE')).toBe(false);
    // A profile whose REALITY key is missing gives no entry either.
    const profile = realityProfile();
    const inbound = (
      profile[FIXTURE_CONFIG_PROFILE].config.inbounds[0] as {
        streamSettings: { realitySettings: Record<string, unknown> };
      }
    ).streamSettings.realitySettings;
    delete inbound.privateKey;
    const keyless = await seed({ profiles: profile });
    expect(await ask(keyless.t, 'VLESS_RELAY_A')).toBe(false);
  });

  test('no entry for the transport: the Host is on ANOTHER transport, or the body has none at the origin', async () => {
    // Nor can the panel describe the transport (its profile holds another one),
    // so no entry can be built from it either.
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const profiles = realityProfile('VLESS_OTHER');
    const other = await seed({
      profiles,
      hosts: [
        directHost({
          inbound: {
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: INBOUND_B,
          },
        }),
      ],
    });
    await expect(
      other.t.action(internal.edgeTestLinks.build, { edgeId: other.edgeId }),
    ).rejects.toThrow(/test_link_no_match/);
    // A disabled direct Host (hidden) with no FCP Host yet: nothing names the transport's entry.
    const hidden = await seed({ hosts: [directHost({ isDisabled: true })], profiles });
    await expect(
      hidden.t.action(internal.edgeTestLinks.build, { edgeId: hidden.edgeId }),
    ).rejects.toThrow(/test_link_no_match/);
  });

  test("after the direct Host is hidden the listener's own FCP Host names the entry (a spare retest)", async () => {
    // The direct Host is disabled (hidden) and the body carries the FCP Host
    // entry at the published edge: the own remark resolves the transport.
    const { t, edgeId } = await seed({
      hosts: [
        directHost({ isDisabled: true }),
        directHost({ uuid: H(3), remark: 'node-one-relay-a', address: '198.51.100.1' }),
      ],
      extraLines: [`vless://x@198.51.100.1:443?${REALITY_QS}#node-one-relay-a`],
    });
    const r = await t.action(internal.edgeTestLinks.build, { edgeId });
    const u = parseProxyUri(r.link)!;
    expect(u.host).toBe(SPARE);
    expect(r.link.split('\n').filter(Boolean)).toHaveLength(1);
    expect(r.link).not.toContain('198.51.100.1');
  });

  test('the test-only matcher (pure): direct by Host identity first, else the own remark; ambiguity refused', () => {
    const c = {
      originAddress: ORIGIN,
      originPort: 443,
      inboundUuid: FIXTURE_INBOUND,
      ownRemarks: ['node-one-relay-a'],
      proto: { protocol: 'vless', streamTransport: 'raw', security: 'reality' } as const,
      deliveryStyle: 'subscription' as const,
    };
    const direct = `vless://u@${ORIGIN}:443?${REALITY_QS}#node-one-reality`;
    const own = `vless://u@198.51.100.1:443?${REALITY_QS}#node-one-relay-a`;
    const foreign = `vless://u@${OTHER_NODE}:443?${REALITY_QS}#node-two-reality`;
    const hosts = [directHost()].map((h) => ({ ...h, isDisabled: false, sni: null, host: null }));
    expect(selectTestEntry([direct, foreign].join('\n'), c, hosts)).toEqual({ line: direct });
    // Both present: the direct entry wins (one Host names it).
    expect(selectTestEntry([direct, own].join('\n'), c, hosts)).toEqual({ line: direct });
    // Direct hidden (not in the enabled Host list): the own remark.
    expect(selectTestEntry([direct, own].join('\n'), c, [])).toEqual({ line: own });
    // A line at the origin whose remark no Host on the transport carries is not the entry.
    expect(selectTestEntry(foreign, c, hosts)).toEqual({ code: 'no_match' });
    // Protocol facts must agree: a ws line is not this REALITY listener's entry.
    const ws = `vless://u@${ORIGIN}:443?security=tls&type=ws&path=%2Fws#node-one-reality`;
    expect(selectTestEntry(ws, c, hosts)).toEqual({ code: 'no_match' });
    // Two Hosts on the transport at the origin, both lines present: ambiguous.
    const copy = `vless://u@${ORIGIN}:443?${REALITY_QS}#node-one-reality-copy`;
    expect(
      selectTestEntry([direct, copy].join('\n'), c, [
        ...hosts,
        { ...hosts[0], uuid: H(2), remark: 'node-one-reality-copy' },
      ]),
    ).toEqual({ code: 'ambiguous_match' });
    // Base64-wrapped bodies decode.
    expect(selectTestEntry(btoa(direct), c, hosts)).toEqual({ line: direct });
    // Single-key delivery (Outline): the one entry at the origin.
    const ss = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@203.0.113.77:8388/?outline=1#k`;
    expect(
      selectTestEntry(
        ss,
        {
          ...c,
          originAddress: '203.0.113.77',
          originPort: 8388,
          inboundUuid: null,
          ownRemarks: [],
          proto: { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' },
          deliveryStyle: 'single-key',
        },
        null,
      ),
    ).toEqual({ line: ss });
  });

  test('Outline: the link comes from a temporary key (single-key render) and the row is left for the sweep', async () => {
    const outline = fakeOutline({ origin: '203.0.113.77', port: 8388 });
    const t = convexTest(schema, modules);
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'outline-one',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: '203.0.113.77',
      listeners: [shadowsocksListener()],
    });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      port: 8388,
      verified: false,
    });
    const r = await t.action(internal.edgeTestLinks.build, { edgeId: edgeId as Id<'edges'> });
    const u = parseProxyUri(r.link)!;
    expect(u.scheme).toBe('ss');
    expect(u.host).toBe(SPARE);
    expect(u.port).toBe(8388);
    expect(r.link.split('\n').filter(Boolean)).toHaveLength(1);
    expect(r.credentialId).not.toBeNull();
    expect(outline.created).toHaveLength(1);
    const row = (await t.run((ctx) => ctx.db.query('edgeTestCredentials').collect()))[0];
    expect(row).toMatchObject({ purpose: 'test_link', removal: 'pending' });
    // Verified through the link: `method: test_link`; releasing the credential lets the sweep remove it.
    await t.mutation(internal.edgeVerification.confirm, {
      edgeId: edgeId as Id<'edges'>,
      endpoint: r.binding.endpoint,
      listenerRevision: r.binding.listenerRevision,
      configHash: r.binding.configHash,
      method: 'test_link',
    });
    await expireTestCredential(t, { id: row._id });
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 1 });
    expect(outline.deleted).toHaveLength(1);
  });

  test('an L7 edge has no test link (its proof verifies it)', async () => {
    const { t, fx } = await seed();
    const edgeId = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId: fx.relayId,
        listenerId: fx.listenerId,
        managed: false,
        name: 'front',
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
        addresses: { hostname: 'front.example' },
        layer: 'l7',
        provider: 'cloudflare',
        status: 'active',
        publication: 'unpublished',
        health: 'unknown',
        destroyAttempts: 0,
        statusChangedAt: Date.now(),
        updatedAt: Date.now(),
      } as never),
    );
    await expect(t.action(internal.edgeTestLinks.build, { edgeId })).rejects.toThrow(
      /l7_proof_required/,
    );
  });
});

describe('realityEntryLine', () => {
  const params = { serverNames: ['a.example'], publicKey: 'PUBKEY', shortId: 'abcd' };
  test('an IPv6 origin is bracketed, so the link parses; Vision is the flow', () => {
    const v6 = realityEntryLine(
      '11111111-2222-4333-8444-555555555555',
      '2001:db8::20',
      443,
      params,
      'r',
    );
    expect(v6).toMatch(/^vless:\/\/[0-9a-f-]+@\[2001:db8::20\]:443\?/);
    expect(parseProxyUri(v6)?.host).toBe('2001:db8::20');
    expect(v6).toContain('flow=xtls-rprx-vision');
    const v4 = realityEntryLine(
      '11111111-2222-4333-8444-555555555555',
      '203.0.113.20',
      443,
      params,
      'r',
    );
    expect(v4).toMatch(/@203\.0\.113\.20:443\?/);
  });

  test('XHTTP under REALITY carries its path and mode and no flow', () => {
    const link = realityEntryLine(
      '11111111-2222-4333-8444-555555555555',
      '203.0.113.20',
      443,
      params,
      'r',
      { kind: 'xhttp', path: '/', mode: 'auto' },
    );
    const q = new URL(link).searchParams;
    expect(Object.fromEntries(q)).toMatchObject({
      type: 'xhttp',
      path: '/',
      mode: 'auto',
      security: 'reality',
      sni: 'a.example',
      pbk: 'PUBKEY',
      sid: 'abcd',
    });
    expect(q.has('flow')).toBe(false);
  });
});
