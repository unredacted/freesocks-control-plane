/// <reference types="vite/client" />
/**
 * The account view (account.getAccountView, GET /api/v1/account) as a whole:
 * golden answers for the shapes a member can be in, so a change to HOW the
 * view is read (one query transaction instead of a chain of them) is proven
 * not to change WHAT it answers. Volatile values (ids, creation times, the
 * mock backend's rolling expiry, a freshly minted support ID) are normalized;
 * everything else is compared exactly, and every route answer must still parse
 * with the wire contract.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AccountResponse } from '../src/shared/contracts/account';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { signValue } from './lib/cookies';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { refuseNetwork } from './lib/edges/testing/mockFetch';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

const SIGN_KEY = 'test-sign';
const FREEDOM_SQUAD = '11111111-2222-3333-4444-000000000001';
const MEMBER_IP = '192.0.2.50';
const EXIT_IP = '198.51.100.7';
const EXPIRES = Date.UTC(2031, 0, 2, 3, 4, 5);
const DONOR_SINCE = Date.UTC(2026, 4, 6, 7, 8, 9);

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('TRUSTED_PROXY', 'true');
  vi.stubEnv('CF_FRONTED', 'true');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** Ids, creation times, the notice time, the mock backend's rolling expiry and a minted support ID vary per run. */
function normalize(view: unknown): unknown {
  const v = structuredClone(view) as {
    user?: { id?: string; createdAt?: string; supportId?: string | null };
    subscription?: { expiresAt?: string | null; appNotice?: { at: string } | null } | null;
  } | null;
  if (!v) return v;
  if (v.user) {
    v.user.id = '<user>';
    v.user.createdAt = '<created>';
    if (typeof v.user.supportId === 'string' && v.user.supportId !== 'SUP-FIXED')
      v.user.supportId = /^[A-Z0-9-]+$/.test(v.user.supportId) ? '<minted>' : v.user.supportId;
  }
  if (v.subscription && typeof v.subscription.expiresAt === 'string')
    v.subscription.expiresAt = '<live>';
  if (v.subscription?.appNotice) v.subscription.appNotice.at = '<at>';
  return v;
}

interface WorldOpts {
  sub?: boolean;
  supportId?: boolean;
  rich?: boolean;
  detect?: boolean;
  /** Materialize the catalog with a bound censorship pick (freedom-reality), so the suggestion varies. */
  censorPick?: boolean;
}

async function world(o: WorldOpts = {}) {
  // Convex's per-execution limits enforced: the view is one query transaction now.
  const t = convexTest({ schema, modules, transactionLimits: true });
  const ids = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
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
      connectionModeId: 'freedom-ws',
      ...(o.supportId === false ? {} : { supportId: 'SUP-FIXED' }),
      ...(o.rich
        ? {
            membershipExpiresAt: EXPIRES,
            firstDonatedAt: DONOR_SINCE,
            donatedCentsTotal: 1250,
            donationCount: 3,
            preferredLocation: 'AMS',
          }
        : {}),
      updatedAt: Date.now(),
    });
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-1',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      location: 'AMS',
      locationLabel: 'Amsterdam',
      updatedAt: Date.now(),
    });
    await ctx.db.insert('modePlacements', {
      modeSlug: 'freedom-ws',
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: [FREEDOM_SQUAD] }),
      updatedAt: Date.now(),
    });
    if (o.censorPick) {
      await ctx.db.insert('connectionModeFamilies', {
        slug: 'freedom',
        iconId: 'zap',
        enabled: true,
        order: 0,
        updatedAt: Date.now(),
      });
      for (const [slug, order] of [
        ['freedom-ws', 0],
        ['freedom-reality', 1],
      ] as const)
        await ctx.db.insert('connectionModes', {
          slug,
          familySlug: 'freedom',
          deliveryStyle: order === 0 ? 'url' : 'rawConfig',
          enabled: true,
          isFamilyDefault: order === 0,
          isCensorshipRecommended: order === 1,
          backends: ['remnawave'],
          order,
          updatedAt: Date.now(),
        });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['11111111-2222-3333-4444-555555555555'] }),
        updatedAt: Date.now(),
      });
    }
    let subId: Id<'subscriptions'> | null = null;
    if (o.sub !== false) {
      subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'uuid-1',
        backendShortId: 'short-1',
        backendServerId: serverId,
        backendPlacement: FREEDOM_SQUAD,
        subscriptionUrl: 'https://panel.example/sub/short-1',
        subscriptionMirrors: o.rich
          ? [
              {
                provider: 'good',
                publicUrl: 'https://m.example/a',
                status: 'ok',
                formats: ['links'],
              },
              { provider: 'bad', publicUrl: 'https://m.example/b', status: 'failed' },
              { provider: 'legacy', publicUrl: 'https://m.example/c' },
            ]
          : [],
        subToken: 'tok_abc',
        ...(o.rich ? { appNotice: { family: 'clash' as const, at: Date.now() - 60_000 } } : {}),
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    }
    if (o.rich) {
      await ctx.db.insert('billingOrders', {
        processor: 'stripe',
        opaqueRef: 'ord_gift_1',
        userId,
        durationDays: 30,
        amountCents: 500,
        currency: 'usd',
        status: 'paid',
        kind: 'gift',
        quantity: 1,
        giftReveal: ['CODE-1'],
        giftRevealPending: true,
        updatedAt: Date.now(),
      });
    }
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU', 'TR'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
    await upsertSettingRow(ctx, 'delivery.country.detect', JSON.stringify(o.detect ?? false));
    await upsertSettingRow(
      ctx,
      'delivery.country.ownExitRanges',
      JSON.stringify(['198.51.100.0/24']),
    );
    return { userId, subId, serverId };
  });
  await t.mutation(internal.ownExits.refresh, {});
  return { t, ...ids };
}

async function memberCookie(t: T, userId: Id<'users'>) {
  const sid = `sid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'member', userId, ttlMs: 3_600_000 });
  return `fs_session=${await signValue(sid, SIGN_KEY)}`;
}

async function getRoute(t: T, userId: Id<'users'>, headers: Record<string, string> = {}) {
  const res = await t.fetch('/api/v1/account', {
    headers: { cookie: await memberCookie(t, userId), 'cf-connecting-ip': MEMBER_IP, ...headers },
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as unknown;
  expect(AccountResponse.safeParse(body).success).toBe(true);
  return body;
}

describe('getAccountView golden answers', () => {
  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
  });

  test('a member without a key', async () => {
    const { t, userId } = await world({ sub: false });
    expect(normalize(await t.action(internal.account.getAccountView, { userId })))
      .toMatchInlineSnapshot(`
        {
          "pendingGiftOrderRef": null,
          "preferredLocation": null,
          "subscription": null,
          "user": {
            "connectionModeId": "freedom-ws",
            "createdAt": "<created>",
            "currentMode": {
              "available": true,
              "deliveryStyle": "url",
              "description": null,
              "family": {
                "id": "freedom",
                "label": null,
              },
              "id": "freedom-ws",
              "label": null,
            },
            "donatedCentsTotal": 0,
            "donatedGbTotal": 0,
            "donationCount": 0,
            "donorSince": null,
            "id": "<user>",
            "membership": null,
            "status": "active",
            "supportId": "SUP-FIXED",
            "tier": {
              "backend": "remnawave",
              "deviceLimit": 1,
              "deviceLimited": false,
              "monthlyTrafficGb": 50,
              "name": "Free",
              "slug": "free",
            },
          },
        }
      `);
  });

  test('a member with every optional part, without the credential grant', async () => {
    const { t, userId } = await world({ rich: true });
    expect(normalize(await t.action(internal.account.getAccountView, { userId })))
      .toMatchInlineSnapshot(`
        {
          "pendingGiftOrderRef": "ord_gift_1",
          "preferredLocation": "AMS",
          "subscription": {
            "appNotice": {
              "at": "<at>",
              "family": "clash",
            },
            "backend": "remnawave",
            "canSwitchServer": false,
            "devices": [],
            "edgeRequired": false,
            "expiresAt": "<live>",
            "location": {
              "code": "AMS",
              "label": "Amsterdam",
            },
            "mirrors": [],
            "shortUuid": "",
            "status": "active",
            "subToken": null,
            "trafficLimitBytes": 53687091200,
            "trafficUsedBytes": 1073741824,
            "udpUnavailable": false,
            "url": "",
          },
          "user": {
            "connectionModeId": "freedom-ws",
            "createdAt": "<created>",
            "currentMode": {
              "available": true,
              "deliveryStyle": "url",
              "description": null,
              "family": {
                "id": "freedom",
                "label": null,
              },
              "id": "freedom-ws",
              "label": null,
            },
            "donatedCentsTotal": 1250,
            "donatedGbTotal": 12.5,
            "donationCount": 3,
            "donorSince": "2026-05-06T07:08:09.000Z",
            "id": "<user>",
            "membership": {
              "expiresAt": "2031-01-02T03:04:05.000Z",
              "isCurrent": true,
            },
            "status": "active",
            "supportId": "SUP-FIXED",
            "tier": {
              "backend": "remnawave",
              "deviceLimit": 1,
              "deviceLimited": false,
              "monthlyTrafficGb": 50,
              "name": "Free",
              "slug": "free",
            },
          },
        }
      `);
  });

  test('a member with every optional part, with the credential grant', async () => {
    const { t, userId } = await world({ rich: true });
    expect(
      normalize(
        await t.action(internal.account.getAccountView, {
          userId,
          includeSubscriptionCredentials: true,
        }),
      ),
    ).toMatchInlineSnapshot(`
      {
        "pendingGiftOrderRef": "ord_gift_1",
        "preferredLocation": "AMS",
        "subscription": {
          "appNotice": {
            "at": "<at>",
            "family": "clash",
          },
          "backend": "remnawave",
          "canSwitchServer": false,
          "devices": [],
          "edgeRequired": false,
          "expiresAt": "<live>",
          "location": {
            "code": "AMS",
            "label": "Amsterdam",
          },
          "mirrors": [
            {
              "formats": [
                "links",
              ],
              "provider": "good",
              "publicUrl": "https://m.example/a",
            },
            {
              "formats": [
                "links",
              ],
              "provider": "legacy",
              "publicUrl": "https://m.example/c",
            },
          ],
          "shortUuid": "short-1",
          "status": "active",
          "subToken": "tok_abc",
          "trafficLimitBytes": 53687091200,
          "trafficUsedBytes": 1073741824,
          "udpUnavailable": false,
          "url": "https://panel.example/sub/short-1",
        },
        "user": {
          "connectionModeId": "freedom-ws",
          "createdAt": "<created>",
          "currentMode": {
            "available": true,
            "deliveryStyle": "url",
            "description": null,
            "family": {
              "id": "freedom",
              "label": null,
            },
            "id": "freedom-ws",
            "label": null,
          },
          "donatedCentsTotal": 1250,
          "donatedGbTotal": 12.5,
          "donationCount": 3,
          "donorSince": "2026-05-06T07:08:09.000Z",
          "id": "<user>",
          "membership": {
            "expiresAt": "2031-01-02T03:04:05.000Z",
            "isCurrent": true,
          },
          "status": "active",
          "supportId": "SUP-FIXED",
          "tier": {
            "backend": "remnawave",
            "deviceLimit": 1,
            "deviceLimited": false,
            "monthlyTrafficGb": 50,
            "name": "Free",
            "slug": "free",
          },
        },
      }
    `);
  });

  test('an edge-required binding withholds the raw URL even with the grant', async () => {
    const { t, userId, serverId } = await world();
    await t.run((ctx) =>
      ctx.db.insert('edgeDeliveryBindings', {
        backendServerId: serverId,
        policy: 'edge-required',
        policyVersion: 1,
        relaySlug: 'node-a',
        state: 'active',
        updatedAt: Date.now(),
      }),
    );
    const view = await t.action(internal.account.getAccountView, {
      userId,
      includeSubscriptionCredentials: true,
    });
    expect(view?.subscription).toMatchObject({ url: '', shortUuid: '', edgeRequired: true });
  });

  test('a pre-W3 account gets its support ID minted (and kept) by the view', async () => {
    const { t, userId } = await world({ supportId: false });
    const view = await t.action(internal.account.getAccountView, { userId });
    expect(view?.user.supportId).toMatch(/^[A-Z0-9-]+$/);
    const stored = await t.run(async (ctx) => (await ctx.db.get(userId))?.supportId);
    expect(stored).toBe(view?.user.supportId);
    expect((await t.action(internal.account.getAccountView, { userId }))?.user.supportId).toBe(
      stored,
    );
  });

  test('an unknown user is null', async () => {
    const { t, userId } = await world({ sub: false });
    await t.run((ctx) => ctx.db.delete(userId));
    expect(await t.action(internal.account.getAccountView, { userId })).toBeNull();
  });
});

describe('getAccountView with the backend unreachable', () => {
  test('serves local data with the tier cap and the unknown status', async () => {
    refuseNetwork();
    const { t, userId } = await world({ rich: true });
    expect(normalize(await t.action(internal.account.getAccountView, { userId })))
      .toMatchInlineSnapshot(`
        {
          "pendingGiftOrderRef": "ord_gift_1",
          "preferredLocation": "AMS",
          "subscription": {
            "appNotice": {
              "at": "<at>",
              "family": "clash",
            },
            "backend": "remnawave",
            "canSwitchServer": false,
            "devices": [],
            "edgeRequired": false,
            "expiresAt": null,
            "location": {
              "code": "AMS",
              "label": "Amsterdam",
            },
            "mirrors": [],
            "shortUuid": "",
            "status": "unknown",
            "subToken": null,
            "trafficLimitBytes": 53687091200,
            "trafficUsedBytes": 0,
            "udpUnavailable": false,
            "url": "",
          },
          "user": {
            "connectionModeId": "freedom-ws",
            "createdAt": "<created>",
            "currentMode": {
              "available": true,
              "deliveryStyle": "url",
              "description": null,
              "family": {
                "id": "freedom",
                "label": null,
              },
              "id": "freedom-ws",
              "label": null,
            },
            "donatedCentsTotal": 1250,
            "donatedGbTotal": 12.5,
            "donationCount": 3,
            "donorSince": "2026-05-06T07:08:09.000Z",
            "id": "<user>",
            "membership": {
              "expiresAt": "2031-01-02T03:04:05.000Z",
              "isCurrent": true,
            },
            "status": "active",
            "supportId": "SUP-FIXED",
            "tier": {
              "backend": "remnawave",
              "deviceLimit": 1,
              "deviceLimited": false,
              "monthlyTrafficGb": 50,
              "name": "Free",
              "slug": "free",
            },
          },
        }
      `);
  });
});

describe('GET /api/v1/account golden answers', () => {
  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
  });

  test('detection off, a listed country: the stored-nothing suggestion uses this request', async () => {
    const { t, userId } = await world({ rich: true, censorPick: true });
    expect(normalize(await getRoute(t, userId, { 'cf-ipcountry': 'IR' }))).toMatchInlineSnapshot(`
        {
          "geoCountry": "IR",
          "geoCountryCensored": true,
          "pendingGiftOrderRef": "ord_gift_1",
          "preferredLocation": "AMS",
          "subscription": {
            "appNotice": {
              "at": "<at>",
              "family": "clash",
            },
            "backend": "remnawave",
            "canSwitchServer": false,
            "devices": [],
            "edgeRequired": false,
            "expiresAt": "<live>",
            "location": {
              "code": "AMS",
              "label": "Amsterdam",
            },
            "mirrors": [
              {
                "formats": [
                  "links",
                ],
                "provider": "good",
                "publicUrl": "https://m.example/a",
              },
              {
                "formats": [
                  "links",
                ],
                "provider": "legacy",
                "publicUrl": "https://m.example/c",
              },
            ],
            "shortUuid": "short-1",
            "status": "active",
            "subToken": "tok_abc",
            "trafficLimitBytes": 53687091200,
            "trafficUsedBytes": 1073741824,
            "udpUnavailable": false,
            "url": "https://panel.example/sub/short-1",
          },
          "suggestedModeId": "freedom-reality",
          "user": {
            "connectionModeId": "freedom-ws",
            "createdAt": "<created>",
            "currentMode": {
              "available": true,
              "deliveryStyle": "url",
              "description": null,
              "family": {
                "id": "freedom",
                "label": null,
              },
              "id": "freedom-ws",
              "label": null,
            },
            "donatedCentsTotal": 1250,
            "donatedGbTotal": 12.5,
            "donationCount": 3,
            "donorSince": "2026-05-06T07:08:09.000Z",
            "id": "<user>",
            "membership": {
              "expiresAt": "2031-01-02T03:04:05.000Z",
              "isCurrent": true,
            },
            "status": "active",
            "supportId": "SUP-FIXED",
            "tier": {
              "backend": "remnawave",
              "deviceLimit": 1,
              "deviceLimited": false,
              "monthlyTrafficGb": 50,
              "name": "Free",
              "slug": "free",
            },
          },
        }
      `);
  });

  test('detection off, no country', async () => {
    const { t, userId } = await world({ sub: false, censorPick: true });
    expect(normalize(await getRoute(t, userId))).toMatchInlineSnapshot(`
      {
        "geoCountry": null,
        "geoCountryCensored": false,
        "pendingGiftOrderRef": null,
        "preferredLocation": null,
        "subscription": null,
        "suggestedModeId": "freedom-ws",
        "user": {
          "connectionModeId": "freedom-ws",
          "createdAt": "<created>",
          "currentMode": {
            "available": true,
            "deliveryStyle": "url",
            "description": null,
            "family": {
              "id": "freedom",
              "label": null,
            },
            "id": "freedom-ws",
            "label": null,
          },
          "donatedCentsTotal": 0,
          "donatedGbTotal": 0,
          "donationCount": 0,
          "donorSince": null,
          "id": "<user>",
          "membership": null,
          "status": "active",
          "supportId": "SUP-FIXED",
          "tier": {
            "backend": "remnawave",
            "deviceLimit": 1,
            "deviceLimited": false,
            "monthlyTrafficGb": 50,
            "name": "Free",
            "slug": "free",
          },
        },
      }
    `);
  });

  test('detection on, a country: the guess is stored and drives the suggestion', async () => {
    const { t, userId, subId } = await world({ detect: true, censorPick: true });
    const body = (await getRoute(t, userId, { 'cf-ipcountry': 'TR' })) as Record<string, unknown>;
    expect({
      geoCountry: body.geoCountry,
      suggestedModeId: body.suggestedModeId,
      geoCountryCensored: body.geoCountryCensored,
    }).toMatchInlineSnapshot(`
      {
        "geoCountry": "TR",
        "geoCountryCensored": true,
        "suggestedModeId": "freedom-reality",
      }
    `);
    expect(await t.run(async (ctx) => (await ctx.db.get(subId!))?.regionSeenCountry)).toBe('TR');
    // A later request from elsewhere keeps the stored guess for the suggestion.
    const later = (await getRoute(t, userId, { 'cf-ipcountry': 'DE' })) as Record<string, unknown>;
    expect({
      geoCountry: later.geoCountry,
      suggestedModeId: later.suggestedModeId,
      geoCountryCensored: later.geoCountryCensored,
    }).toMatchInlineSnapshot(`
      {
        "geoCountry": "DE",
        "geoCountryCensored": false,
        "suggestedModeId": "freedom-reality",
      }
    `);
  });

  test("detection on, no country, from one of FCP's own exits", async () => {
    const { t, userId } = await world({ detect: true, censorPick: true });
    const body = (await getRoute(t, userId, { 'cf-connecting-ip': EXIT_IP })) as Record<
      string,
      unknown
    >;
    expect({
      geoCountry: body.geoCountry,
      suggestedModeId: body.suggestedModeId,
      geoCountryCensored: body.geoCountryCensored,
    }).toMatchInlineSnapshot(`
      {
        "geoCountry": null,
        "geoCountryCensored": false,
        "suggestedModeId": "freedom-ws",
      }
    `);
  });

  test('detection on, a choice of "somewhere else" stands over the request country', async () => {
    const { t, userId } = await world({ detect: true, censorPick: true });
    await t.mutation(internal.memberCountry.setChoice, { userId, region: 'ZZ' });
    const body = (await getRoute(t, userId, { 'cf-ipcountry': 'IR' })) as Record<string, unknown>;
    expect({
      geoCountry: body.geoCountry,
      suggestedModeId: body.suggestedModeId,
      geoCountryCensored: body.geoCountryCensored,
    }).toMatchInlineSnapshot(`
      {
        "geoCountry": "IR",
        "geoCountryCensored": true,
        "suggestedModeId": "freedom-ws",
      }
    `);
  });
});
