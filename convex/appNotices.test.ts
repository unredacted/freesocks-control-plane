/// <reference types="vite/client" />
/**
 * The app notice at the subscription route (convex/appNotices.ts,
 * lib/appNotice.ts): an app that cannot speak the member's mode gets a config
 * whose only entries say so, at a place no origin covers (direct) and at a
 * covered one (edge-rendered) alike; a body with an entry, or an empty one a
 * current app was given, is never replaced. The notice is never cached, is
 * counted beside the refusals, and leaves a throttled record the account view
 * shows for 7 days. Example names and RFC 5737 addresses only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import YAML from 'yaml';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { readRefusals } from './deliveryRefusals';
import { CLASH_YAML } from './lib/backend/subscriptionTemplates/CLASH';
import { SINGBOX_JSON } from './lib/backend/subscriptionTemplates/SINGBOX';
import { APP_NOTICE_RESTAMP_MS, APP_NOTICE_WINDOW_MS } from './lib/appNotice';
import { FIXTURE_NODE, realityListener, seedEdgeFixture } from './lib/edges/testing/fixtures';
import { AccountResponse } from '../src/shared/contracts/account';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const UUID = '11111111-2222-4333-8444-555555555555';
const EDGE_A = '198.51.100.1';
/** The legacy CLASH template as the panel serves it to an app with no VLESS: no proxy at all. */
const LEGACY_EMPTY = CLASH_YAML.replace(/ # LEAVE THIS LINE!/g, '');
const SINGBOX_EMPTY = JSON.stringify(SINGBOX_JSON);
const LEGACY_UA = 'ClashforWindows/0.20.39';
const MIHOMO_UA = 'mihomo/1.19.33';

let panelBody = LEGACY_EMPTY;
function stubPanel(contentType = 'text/yaml') {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(panelBody, {
          status: 200,
          headers: {
            'content-type': contentType,
            'subscription-userinfo': 'upload=0; download=10; total=100; expire=0',
          },
        }),
    ),
  );
}

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  panelBody = LEGACY_EMPTY;
  stubPanel();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

async function insertMember(
  t: T,
  serverId: Id<'backendServers'>,
  sub: Record<string, unknown> = {},
): Promise<{ userId: Id<'users'>; subId: Id<'subscriptions'> }> {
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
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      state: 'active',
      updatedAt: Date.now(),
      ...sub,
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { userId, subId };
  });
}

/** A key on a backend no origin covers: the panel body is handed out as it came (direct). */
async function seedDirect(sub: Record<string, unknown> = {}) {
  const t = convexTest(schema, modules);
  const serverId = await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-1',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  return { t, ...(await insertMember(t, serverId, sub)) };
}

/** A key pinned to a node an origin covers with one published edge (edge-rendered delivery). */
async function seedEdge(listener = realityListener({ tlsNames: ['a.example'] })) {
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, { listeners: [listener] });
  const ids = await insertMember(t, fx.serverId, { pinnedNode: FIXTURE_NODE });
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
  await t.mutation(internal.relays.adoptEdge, {
    relayId: fx.relayId,
    listenerId: fx.listenerId,
    ipv4: EDGE_A,
    publish: true,
    verified: true,
  });
  return { t, ...ids };
}

const get = (t: T, ua: string) => t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': ua } });
const rowOf = (t: T, subId: Id<'subscriptions'>) =>
  t.run(async (ctx) => (await ctx.db.get(subId))!);
const refusals = (t: T) => t.run((ctx) => readRefusals(ctx.db, Date.now()));

/** Run what the route scheduled (the counter, the record) to the end. */
async function drain(t: T) {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  await t.finishAllScheduledFunctions(vi.runAllTimers);
  vi.useRealTimers();
}

type ClashDoc = {
  proxies: Array<{ name: string; type: string; server: string; port: number }>;
  'proxy-groups': Array<{ name: string; proxies: string[] }>;
  rules: string[];
};

describe('a place no origin covers (direct delivery)', () => {
  test('a legacy Clash core gets the notice, never cached, counted, and recorded for the account page', async () => {
    const { t, subId } = await seedDirect();
    const res = await get(t, LEGACY_UA);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    expect(res.headers.get('profile-title')).toMatch(/^base64:/);
    expect(res.headers.get('subscription-userinfo')).toContain('total=100');
    const doc = YAML.parse(await res.text()) as ClashDoc;
    expect(doc.proxies.map((p) => p.name)).toEqual([
      '⚠ App too old for FreeSocks',
      'Install FlClash or Mihomo Party',
      'Help: your FreeSocks account page',
    ]);
    expect(doc.proxies.every((p) => p.type === 'socks5' && p.server === '127.0.0.1')).toBe(true);
    expect(doc.rules).toEqual(['MATCH,FreeSocks Select']);
    await drain(t);
    const row = await rowOf(t, subId);
    // Not cached, not stamped as a delivery: it carries no connection.
    expect(row.subCache).toBeUndefined();
    expect(row.lastDeliveredAt).toBeUndefined();
    expect(row.appNotice).toEqual({ family: 'clash', at: expect.any(Number) });
    expect((await refusals(t)).byReason).toEqual({ app_notice: 1 });
  });

  test('a current Clash app given the same empty body gets it as before; no notice, no record', async () => {
    const { t, subId } = await seedDirect();
    const res = await get(t, MIHOMO_UA);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).not.toContain('socks5');
    expect(body).toContain('fake-ip-range: 198.18.0.1/16');
    await drain(t);
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
    expect((await refusals(t)).total).toBe(0);
  });

  test('a body holding an entry is never replaced, whatever app asks', async () => {
    panelBody = `mode: rule
proxies:
  - name: entry-a
    type: ss
    server: 203.0.113.9
    port: 8388
    cipher: aes-128-gcm
    password: pw
proxy-groups:
  - name: select
    type: select
    proxies:
      - entry-a
rules:
  - MATCH,select
`;
    const { t, subId } = await seedDirect();
    const body = await (await get(t, LEGACY_UA)).text();
    expect(body).toContain('203.0.113.9');
    expect(body).not.toContain('socks5');
    await drain(t);
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
  });

  test('the record is written at most every few hours, and again once older', async () => {
    const { t, subId } = await seedDirect();
    await get(t, LEGACY_UA);
    await drain(t);
    const first = (await rowOf(t, subId)).appNotice!.at;
    await get(t, LEGACY_UA);
    await drain(t);
    expect((await rowOf(t, subId)).appNotice!.at).toBe(first);
    // Nothing was even scheduled for it the second time.
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.filter((s) => s.name.includes('appNotices'))).toHaveLength(1);
    const old = Date.now() - APP_NOTICE_RESTAMP_MS - 1;
    await t.run((ctx) => ctx.db.patch(subId, { appNotice: { family: 'clash', at: old } }));
    await get(t, LEGACY_UA);
    await drain(t);
    expect((await rowOf(t, subId)).appNotice!.at).toBeGreaterThan(old);
  });
});

describe('a place an origin covers (edge-rendered delivery)', () => {
  test('a legacy Clash core gets the notice in place of the no_entries refusal', async () => {
    const { t, subId } = await seedEdge();
    const res = await get(t, LEGACY_UA);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-fcp-delivery')).toBeNull();
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    const body = await res.text();
    expect(body).not.toContain(EDGE_A);
    expect((YAML.parse(body) as ClashDoc).proxies[0]!.name).toBe('⚠ App too old for FreeSocks');
    await drain(t);
    expect((await rowOf(t, subId)).appNotice?.family).toBe('clash');
    expect((await refusals(t)).byReason).toEqual({ app_notice: 1 });
  });

  test('a current app given an empty body keeps the 503 (and its last configuration)', async () => {
    const { t, subId } = await seedEdge();
    const res = await get(t, MIHOMO_UA);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('no_entries');
    await drain(t);
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
    expect((await refusals(t)).byReason).toEqual({ no_entries: 1 });
  });

  test('sing-box at an XHTTP-only place: told its app cannot use the mode', async () => {
    panelBody = SINGBOX_EMPTY;
    stubPanel('application/json');
    const { t, subId } = await seedEdge(
      realityListener({ listenerKey: 'x', streamTransport: 'xhttp', tlsNames: ['a.example'] }),
    );
    const res = await get(t, 'SFA/1.12.0');
    expect(res.status).toBe(200);
    const doc = JSON.parse(await res.text()) as {
      outbounds: Array<{ type: string; tag: string }>;
      route: { final: string };
    };
    expect(doc.outbounds.map((o) => o.tag)).toEqual([
      'FreeSocks Select',
      "⚠ App can't use this connection mode",
      'Install Hiddify or Anywhere',
      'Or switch mode on your FreeSocks account page',
    ]);
    expect(doc.route.final).toBe('FreeSocks Select');
    await drain(t);
    expect((await rowOf(t, subId)).appNotice?.family).toBe('singbox');
  });

  test('a body with the listener entry is rendered as always, never a notice', async () => {
    panelBody = `vless://${UUID}@${EDGE_A}:443?encryption=none&security=reality&sni=a.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp#${FIXTURE_NODE}-relay-a`;
    stubPanel('text/plain');
    const { t, subId } = await seedEdge();
    const res = await get(t, 'clash');
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(`@${EDGE_A}:443?`);
    await drain(t);
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
  });
});

describe('the record', () => {
  test('never lands on a key that moved in place since, nor on one that is not live', async () => {
    const { t, subId } = await seedDirect({ deliveryRev: 2 });
    await t.mutation(internal.appNotices.record, {
      subscriptionId: subId,
      family: 'clash',
      deliveryRev: 1,
    });
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
    await t.run((ctx) => ctx.db.patch(subId, { state: 'disabled' }));
    await t.mutation(internal.appNotices.record, {
      subscriptionId: subId,
      family: 'clash',
      deliveryRev: 2,
    });
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
  });

  test('the rollback step clears every record, page by page', async () => {
    const { t, subId } = await seedDirect({ appNotice: { family: 'clash', at: Date.now() } });
    const out = await t.mutation(internal.appNotices.clearForRollback, {});
    expect(out).toEqual({ cleared: 1, done: true });
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
  });

  test('a mode switch in place clears it; a server switch keeps it', async () => {
    const { t, subId } = await seedDirect({ appNotice: { family: 'singbox', at: Date.now() } });
    await t.mutation(internal.subscriptions.placementApplied, {
      subscriptionId: subId,
      rotatePin: true,
    });
    expect((await rowOf(t, subId)).appNotice?.family).toBe('singbox');
    await t.mutation(internal.subscriptions.placementApplied, { subscriptionId: subId });
    expect((await rowOf(t, subId)).appNotice).toBeUndefined();
  });
});

describe('the account view hint', () => {
  beforeEach(() => {
    // The live getUser is mocked, as elsewhere for the account view.
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
  });

  test('shown for 7 days after the last notice, through the account contract', async () => {
    const at = Date.now() - 60_000;
    const { t, userId, subId } = await seedDirect({ appNotice: { family: 'clash', at } });
    const view = await t.action(internal.account.getAccountView, { userId });
    expect(view?.subscription?.appNotice).toEqual({
      family: 'clash',
      at: new Date(at).toISOString(),
    });
    const parsed = AccountResponse.parse(view);
    expect(parsed.subscription?.appNotice).toEqual({
      family: 'clash',
      at: new Date(at).toISOString(),
    });
    await t.run((ctx) =>
      ctx.db.patch(subId, {
        appNotice: { family: 'clash', at: Date.now() - APP_NOTICE_WINDOW_MS - 1 },
      }),
    );
    const later = await t.action(internal.account.getAccountView, { userId });
    expect(later?.subscription?.appNotice).toBeNull();
    // An older server sends no field: the contract reads none.
    const { appNotice: _gone, ...older } = later!.subscription!;
    expect(
      AccountResponse.parse({ ...later, subscription: older }).subscription?.appNotice,
    ).toBeNull();
  });
});
