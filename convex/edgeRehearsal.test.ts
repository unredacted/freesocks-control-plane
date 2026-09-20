/// <reference types="vite/client" />
/**
 * The delivery rehearsal (docs/edges.md § "Rendering"; acceptance 12, 16, 21,
 * 22): cohorts from authoritative membership (two placements with different
 * transport sets, both rehearsed, every page walked), an approved dark cohort
 * excluded, an empty node rehearsed from the rehearsal credential, a disabled
 * family rule listed, an expired L7 proof listed, the before/after Host
 * listing repeated (bounded), and an Outline server with members rehearsed
 * from its real single-key subscriptions (an empty one: `use_manual_setup`).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { clientRuleKey, defaultClientRule } from './lib/edgeConfig';
import { cohortsForRelay } from './lib/edges/cohorts';
import { fakeOutline, fakePanel, type FakePanelUser } from './lib/edges/testing/fakePanel';
import {
  adoptL4Edge,
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  insertPanelServer,
  realityListener,
  registerRelay,
  seedEdgeFixture,
  shadowsocksListener,
} from './lib/edges/testing/fixtures';
import {
  __setHostObserverForTests,
  REHEARSAL_MAX_ATTEMPTS,
  REHEARSAL_USER_AGENTS,
  sameVector,
} from './edgeRehearsal';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  __setHostObserverForTests(null);
});

const NODE = FIXTURE_NODE;
const ORIGIN = FIXTURE_ORIGIN;
const EDGE_A = '198.51.100.1';
const EDGE_B = '198.51.100.2';
const UUID = '11111111-2222-4333-8444-555555555555';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';
const INBOUND_B = '66666666-6666-4666-8666-666666666666';
const REMARK_A = `${NODE}-relay-a`;
const REMARK_B = `${NODE}-relay-b`;

/** What the backend serves per format for a body carrying ONE listener's FCP Host entry. */
function bodyFor(
  format: 'links' | 'singbox' | 'clash',
  remark: string,
  edge: string,
  port: number,
) {
  if (format === 'links') return `vless://${UUID}@${edge}:${port}?${REALITY_QS}#${remark}`;
  if (format === 'singbox')
    return JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: [remark, 'direct'], default: remark },
        {
          type: 'vless',
          tag: remark,
          server: edge,
          server_port: port,
          uuid: UUID,
          tls: {
            enabled: true,
            server_name: 'target.example',
            reality: { enabled: true, public_key: 'P' },
          },
        },
        { type: 'direct', tag: 'direct' },
      ],
    });
  return `mixed-port: 7890
mode: global
proxies:
  - name: ${remark}
    type: vless
    server: ${edge}
    port: ${port}
    uuid: ${UUID}
    udp: true
    tls: true
    servername: target.example
    network: tcp
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY
      short-id: abcd1234
proxy-groups:
  - name: select
    type: select
    proxies:
      - ${remark}
rules:
  - MATCH,select
`;
}

function formatOfUa(ua: string): 'links' | 'singbox' | 'clash' {
  if (ua === REHEARSAL_USER_AGENTS.singbox) return 'singbox';
  if (ua === REHEARSAL_USER_AGENTS.clash) return 'clash';
  return 'links';
}

/** Body rule: the member's placement decides which listener's entry the body carries. */
type BodyRule = (user: FakePanelUser | null, shortId: string, ua: string) => string | null;

async function seed(opts: { body?: BodyRule; bindPool?: boolean } = {}) {
  const shortToPlacement = new Map<string, string>();
  // A backend user (the rehearsal credential) is on the node's placement `sq-a`;
  // a member short id the test seeded maps through `shortToPlacement`.
  const defaultBody: BodyRule = (user, shortId, ua) => {
    const format = formatOfUa(ua);
    const placement = user ? 'sq-a' : (shortToPlacement.get(shortId) ?? 'sq-a');
    return placement === 'sq-b'
      ? bodyFor(format, REMARK_B, EDGE_B, 8443)
      : bodyFor(format, REMARK_A, EDGE_A, 443);
  };
  const panel = fakePanel({
    body: (u, ua, shortId) => (opts.body ?? defaultBody)(u, shortId, ua),
  });
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, {
    listeners: [
      realityListener(),
      realityListener({
        listenerKey: 'b',
        originPort: 8443,
        panelBinding: {
          inboundTag: 'VLESS_RELAY_B',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: INBOUND_B,
        },
      }),
    ],
  });
  if (opts.bindPool !== false)
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-a'] }),
        updatedAt: Date.now(),
      }),
    );
  // Both listeners covered by a published, confirmed edge (the state after stage 5).
  await adoptL4Edge(t, fx.relayId, fx.listenerIds.a, { ipv4: EDGE_A, publish: true });
  await adoptL4Edge(t, fx.relayId, fx.listenerIds.b, { ipv4: EDGE_B, port: 8443, publish: true });
  let n = 0;
  const addMember = async (placement: 'sq-a' | 'sq-b', pinned = NODE) => {
    n++;
    const short = `member${n}`;
    shortToPlacement.set(short, placement);
    return t.run(async (ctx) => {
      const tierId =
        (await ctx.db.query('tiers').first())?._id ??
        (await ctx.db.insert('tiers', {
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
        }));
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        supportId: `SUP-${n}`,
        updatedAt: Date.now(),
      });
      return ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: `uuid-${n}`,
        backendShortId: short,
        backendServerId: fx.serverId,
        subscriptionUrl: `https://panel.example/api/sub/${short}`,
        subscriptionMirrors: [],
        subToken: `tok_${n}`,
        state: 'active',
        pinnedNode: pinned,
        backendPlacement: placement,
        updatedAt: Date.now(),
      });
    });
  };
  const run = (dark: string[] = []) =>
    t.action(internal.edgeRehearsal.run, { relayId: fx.relayId, darkCohortKeys: dark });
  return { t, fx, panel, addMember, run };
}

describe('the delivery rehearsal', () => {
  test('two placements with different transport sets are both rehearsed from membership, in every supported format; the vector is what vectorNow reports', async () => {
    const { t, fx, addMember, run } = await seed();
    await addMember('sq-a');
    await addMember('sq-b');
    const r = await run();
    expect(r.failures).toEqual([]);
    expect(r).toMatchObject({
      ok: true,
      familiesDisabled: [],
      proofsExpired: [],
      listingChanged: false,
      attempts: 1,
      cohorts: 2,
      source: 'members',
    });
    expect(r.vector.listenerRevisions).toEqual({ a: expect.any(Number), b: expect.any(Number) });
    expect(r.vector.qualificationEvidenceIds).toHaveLength(2);
    expect(r.hostsObservation.listingHash).toBeTruthy();
    expect(r.hostsObservation.version).toBe(r.hostsObservation.observedAt);
    const now = (await t.query(internal.edgeRehearsal.vectorNow, { relayId: fx.relayId }))!;
    expect(sameVector(r.vector, now)).toBe(true);
    // A listener revision bump changes the vector (the go-live compare catches it).
    await t.mutation(internal.relayListeners.setEnabled, { id: fx.listenerIds.b, enabled: false });
    const later = (await t.query(internal.edgeRehearsal.vectorNow, { relayId: fx.relayId }))!;
    expect(sameVector(r.vector, later)).toBe(false);
  });

  test('an approved dark cohort is excluded from the serve requirement; a cohort whose body cannot render is a failure per format', async () => {
    const { addMember, run } = await seed({
      body: (u, short, ua) => {
        // sq-b members receive a body with NO origin entry at all (their transport is unsupported).
        const fmt = formatOfUa(ua);
        return short.startsWith('member2')
          ? `vless://${UUID}@${ORIGIN}:9999?${REALITY_QS}#${NODE}-other`
          : bodyFor(fmt, REMARK_A, EDGE_A, 443);
      },
    });
    await addMember('sq-a');
    await addMember('sq-b');
    const failing = await run();
    expect(failing.ok).toBe(false);
    expect(failing.failures.map((f) => `${f.cohortKey}:${f.format}`).sort()).toEqual([
      'sq-b:clash',
      'sq-b:links',
      'sq-b:singbox',
    ]);
    expect(
      failing.failures.every((f) => f.reason === 'empty_pool' || f.reason === 'leak_detected'),
    ).toBe(true);
    const dark = await run(['sq-b']);
    expect(dark).toMatchObject({ ok: true, failures: [], cohorts: 1 });
  });

  test('pagination covers every page: the second placement sits after 450 subscriptions of the first', async () => {
    const { t, fx, addMember } = await seed();
    for (let i = 0; i < 450; i++) await addMember('sq-a');
    await addMember('sq-b');
    // A subscription pinned elsewhere is not a cohort of this node.
    await addMember('sq-b', 'node-two');
    const viaRelay = await t.run(async (ctx) =>
      cohortsForRelay(ctx, (await ctx.db.get(fx.relayId))!),
    );
    expect(viaRelay.map((c) => c.key)).toEqual(['sq-a', 'sq-b']);
    expect(viaRelay.every((c) => c.nodeName === NODE)).toBe(true);
  });

  test('an empty node is rehearsed from the rehearsal credential (minted on the placement); no placement -> choose_mode', async () => {
    const { t, fx, panel, run } = await seed();
    const r = await run();
    expect(r).toMatchObject({ ok: true, failures: [], cohorts: 0, source: 'credential' });
    expect(panel.created).toHaveLength(1);
    expect((await t.run((ctx) => ctx.db.get(fx.relayId)))!.qualificationMint).toMatchObject({
      state: 'stored',
      placement: 'sq-a',
    });
    // The credential body was fetched per format with the catalogued user agents.
    const uas = panel.calls
      .filter((c) => c.path.startsWith('/api/sub/'))
      .map((c) => c.headers['user-agent']);
    expect(new Set(uas)).toEqual(new Set(Object.values(REHEARSAL_USER_AGENTS)));
    // A second run reuses the credential.
    await run();
    expect(panel.created).toHaveLength(1);

    const bare = await seed({ bindPool: false });
    const r2 = await bare.run();
    expect(r2.ok).toBe(false);
    expect(r2.failures.map((f) => f.reason)).toEqual(['choose_mode', 'choose_mode', 'choose_mode']);
    expect(bare.panel.created).toEqual([]);
  });

  test('a disabled family rule and an expired L7 proof are listed (the run is not ok)', async () => {
    const { t, fx, addMember, run } = await seed();
    await addMember('sq-a');
    await t.run((ctx) =>
      upsertSettingRow(
        ctx,
        clientRuleKey('mihomo'),
        JSON.stringify({ ...defaultClientRule('mihomo'), enabled: false }),
      ),
    );
    let r = await run();
    expect(r.ok).toBe(false);
    expect(r.familiesDisabled).toEqual(['mihomo']);
    expect(r.failures).toEqual([]); // the dry run itself still renders
    await t.run((ctx) =>
      upsertSettingRow(ctx, clientRuleKey('mihomo'), JSON.stringify(defaultClientRule('mihomo'))),
    );
    // A published L7 front whose proof lapsed.
    const l7 = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId: fx.relayId,
        listenerId: fx.listenerIds.a,
        managed: false,
        name: 'front',
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
        addresses: { hostname: 'front.example' },
        layer: 'l7',
        provider: 'cloudflare',
        status: 'active',
        publication: 'published',
        poolIndex: 5,
        health: 'unknown',
        destroyAttempts: 0,
        frontQualification: {
          ok: true,
          checkedAt: Date.now() - 10,
          expiresAt: Date.now() - 1,
          binding: {
            hostname: 'front.example',
            listenerId: fx.listenerIds.a,
            listenerRevision: 1,
            protocol: 'vless',
            streamTransport: 'raw',
            security: 'reality',
            transportParamsHash: 'h',
            intentHash: 'i',
          },
        },
        statusChangedAt: Date.now(),
        updatedAt: Date.now(),
      } as never),
    );
    r = await run();
    expect(r.ok).toBe(false);
    expect(r.proofsExpired).toEqual([l7]);
    expect(r.familiesDisabled).toEqual([]);
  });

  test('the observation boundary: a Host change during the rehearsal repeats it (bounded), the final listing is the observation', async () => {
    const { addMember, run } = await seed();
    await addMember('sq-a');
    let calls = 0;
    __setHostObserverForTests(async () => {
      calls++;
      // 1st attempt: before=h1, after=h2 (changed); 2nd: before=h3, after=h3.
      const hash = calls <= 2 ? `h${calls}` : 'h3';
      return {
        listingHash: hash,
        observedAt: 1_000 + calls,
        direct: { covered: [], uncovered: [] },
      };
    });
    const r = await run();
    expect(r).toMatchObject({ ok: true, attempts: 2, listingChanged: false });
    expect(r.hostsObservation).toEqual({ listingHash: 'h3', observedAt: 1_004, version: 1_004 });
    // Never agreeing: the attempt budget ends with `listingChanged`.
    calls = 0;
    __setHostObserverForTests(async () => {
      calls++;
      return {
        listingHash: `x${calls}`,
        observedAt: calls,
        direct: { covered: [], uncovered: [] },
      };
    });
    const r2 = await run();
    expect(r2).toMatchObject({ ok: false, attempts: REHEARSAL_MAX_ATTEMPTS, listingChanged: true });
    expect(r2.failures).toEqual([]);
  });
});

describe('the delivery rehearsal on Outline', () => {
  const OUTLINE_ORIGIN = '203.0.113.77';
  async function seedOutline() {
    const outline = fakeOutline({ origin: OUTLINE_ORIGIN, port: 8388 });
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'outline-one',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: OUTLINE_ORIGIN,
      listeners: [shadowsocksListener()],
    });
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.9', port: 8388, publish: true });
    return { t, outline, serverId, relayId };
  }

  test('an Outline server with members is rehearsed from its real single-key subscriptions', async () => {
    const { t, outline, serverId, relayId } = await seedOutline();
    // A real member key on the server (the fake serves it by id).
    outline.keys.set('7', {
      id: '7',
      name: 'member',
      accessUrl: `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@${OUTLINE_ORIGIN}:8388/?outline=1#member`,
    });
    await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'outline',
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
        supportId: 'SUP-O',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'outline',
        backendUserId: `${serverId}:7`,
        backendShortId: '7',
        backendServerId: serverId,
        subscriptionUrl: 'ss://placeholder',
        subscriptionMirrors: [],
        subToken: 'tok_o',
        state: 'active',
        updatedAt: Date.now(),
      });
    });
    const r = await t.action(internal.edgeRehearsal.run, { relayId, darkCohortKeys: [] });
    expect(r).toMatchObject({ ok: true, failures: [], cohorts: 1, source: 'members' });
    expect(outline.created).toEqual([]); // no temporary key for a rehearsal
  });

  test('an empty Outline server: use_manual_setup from the credential path, nothing created', async () => {
    const { t, outline, relayId } = await seedOutline();
    const r = await t.action(internal.edgeRehearsal.run, { relayId, darkCohortKeys: [] });
    expect(r.ok).toBe(false);
    expect(r.source).toBe('credential');
    expect(r.failures).toEqual([
      { cohortKey: 'credential', format: 'links', reason: 'use_manual_setup' },
    ]);
    expect(outline.created).toEqual([]);
  });
});
