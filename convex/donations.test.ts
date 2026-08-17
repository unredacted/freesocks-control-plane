import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { gbToBytes } from './lib/backends/types';
import {
  effectiveBonusGb,
  readDonationState,
  recordDonation,
  subtractDonation,
} from './lib/donationBonus';

const modules = import.meta.glob('./**/*.*s');

type BulkBody = { uuids: string[]; fields: { trafficLimitBytes: number } };

/** A bulk/update-capturing fetch stub (everything else → 200 {}). */
function captureBulk(bucket: BulkBody[]) {
  return vi.fn(async (input: string | URL, init?: RequestInit) => {
    if (String(input).includes('/api/users/bulk/update')) {
      bucket.push(JSON.parse(init!.body as string) as BulkBody);
    }
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
}

async function setup() {
  // Real-HTTP path (mock off) so the bulk update actually hits the stubbed fetch.
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
  const t = convexTest(schema, modules);
  const { freeTierId, instanceId } = await t.run(async (ctx) => {
    const freeTierId = await ctx.db.insert('tiers', {
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
    const instanceId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'n1',
      slug: 'n1',
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    const put = (k: string, v: unknown) =>
      ctx.db.insert('appSettings', { key: k, value: JSON.stringify(v), updatedAt: Date.now() });
    await put('billing.donation.enabled', true);
    await put('billing.donation.bonusGbPerUsd', 1);
    await put('billing.donation.monthlyBonusCapGb', 100);
    return { freeTierId, instanceId };
  });
  return { t, freeTierId, instanceId };
}

async function seedFreeKey(
  t: ReturnType<typeof convexTest>,
  tierId: Id<'tiers'>,
  instanceId: Id<'backendServers'>,
  backendUserId: string,
): Promise<void> {
  await t.run(async (ctx) => {
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      freeKeyExpiresAt: Date.now() + 86_400_000,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId,
      backendShortId: `${backendUserId}-s`,
      backendServerId: instanceId,
      subscriptionUrl: `https://panel.test/sub/${backendUserId}`,
      subscriptionMirrors: [],
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
  });
}

const thisMonth = () => new Date().toISOString().slice(0, 7); // YYYY-MM

describe('donations.applyFreeBonus', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('re-caps free keys to base+bonus and records the applied bonus', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    // $30 donated this month → +30 GB (rate 1 GB/$).
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 0 }),
        updatedAt: Date.now(),
      }),
    );
    const bulk: BulkBody[] = [];
    vi.stubGlobal('fetch', captureBulk(bulk));

    await t.action(internal.donations.applyFreeBonus, {});

    expect(bulk.length).toBe(1);
    expect(bulk[0]!.uuids).toEqual(['u-1']);
    expect(bulk[0]!.fields.trafficLimitBytes).toBe(gbToBytes(50 + 30));
    await t.run(async (ctx) => {
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).appliedBonusGb).toBe(30);
      // The cron stamps its heartbeat so the admin dashboard can alarm on a
      // stale/pending job (previously the only unstamped cron).
      const hb = await ctx.db
        .query('cronHeartbeats')
        .withIndex('by_name', (q) => q.eq('name', 'donation-bonus-reconcile'))
        .unique();
      expect(hb?.lastRunAt).toBeGreaterThan(0);
    });
  });

  test('re-caps OUTLINE free keys too (per-user data-limit update)', async () => {
    const { t } = await setup();
    // An outline free tier + instance + one key.
    await t.run(async (ctx) => {
      const outlineTierId = await ctx.db.insert('tiers', {
        slug: 'free-outline',
        name: 'Free Outline',
        backend: 'outline',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 0,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      });
      const outlineInstanceId = await ctx.db.insert('backendServers', {
        backend: 'outline',
        name: 'ol',
        slug: 'ol',
        config: {
          type: 'outline',
          apiUrl: 'https://outline.test/secret/',
          websocketEnabled: false,
        },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId: outlineTierId,
        status: 'active',
        freeKeyExpiresAt: Date.now() + 86_400_000,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'outline',
        backendUserId: 'ol-key-1',
        backendShortId: 'ol-key-1',
        backendServerId: outlineInstanceId,
        subscriptionUrl: 'ss://x',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    });
    // $30 donated → +30 GB on top of the 50 GB base.
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 0 }),
        updatedAt: Date.now(),
      }),
    );
    const limitCalls: unknown[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        if (String(input).includes('/data-limit')) {
          limitCalls.push(JSON.parse(init!.body as string));
        }
        return new Response('{}', { status: 200 });
      }),
    );

    await t.action(internal.donations.applyFreeBonus, {});

    expect(limitCalls).toEqual([{ limit: { bytes: gbToBytes(50 + 30) } }]);
  });

  test('no-op when the effective bonus already equals the applied bonus', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 30 }),
        updatedAt: Date.now(),
      }),
    );
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await t.action(internal.donations.applyFreeBonus, {});
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('resets free keys to base once a pre-window pool has expired', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    // A row written before the rolling window: no `buckets`, so its money is read
    // as expiring when ITS month ended (never retroactively extended). Long past
    // → the fleet must be pushed back to base.
    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: '2000-01', donatedCents: 3000, appliedBonusGb: 30 }),
        updatedAt: Date.now(),
      });
      // Last month's frozen impact-ledger entry — the roll must NOT rewrite it.
      await ctx.db.insert('appState', {
        key: 'donation:history',
        value: JSON.stringify([{ monthKey: '2000-01', donatedCents: 3000, bonusGb: 30 }]),
        updatedAt: Date.now(),
      });
    });
    const bulk: BulkBody[] = [];
    vi.stubGlobal('fetch', captureBulk(bulk));

    await t.action(internal.donations.applyFreeBonus, {});

    expect(bulk[0]!.fields.trafficLimitBytes).toBe(gbToBytes(50)); // base, no bonus
    await t.run(async (ctx) => {
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).appliedBonusGb).toBe(0);
      // The finished month's ledger entry keeps its recorded impact (the roll
      // previously stamped bonusGb: 0 onto it, wiping the month's history); the
      // new month gets its own zeroed entry.
      const hist = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:history'))
        .unique();
      const entries = JSON.parse(hist!.value) as {
        monthKey: string;
        donatedCents: number;
        bonusGb: number;
      }[];
      const old = entries.find((e) => e.monthKey === '2000-01');
      expect(old?.bonusGb).toBe(30);
      expect(old?.donatedCents).toBe(3000);
      const fresh = entries.find((e) => e.monthKey === thisMonth());
      expect(fresh?.bonusGb).toBe(0);
      expect(fresh?.donatedCents).toBe(0);
    });
  });

  test('a donation keeps funding the fleet across a calendar-month roll', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    // $30 given LAST month, inside a 30-day window that is still open. The old
    // month-bucket model zeroed this at 00:00 UTC on the 1st.
    const lastMonth = new Date();
    lastMonth.setUTCMonth(lastMonth.getUTCMonth() - 1);
    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({
          monthKey: lastMonth.toISOString().slice(0, 7),
          donatedCents: 3000,
          appliedBonusGb: 0,
          buckets: [
            {
              d: lastMonth.toISOString().slice(0, 10),
              c: 3000,
              x: Date.now() + 5 * 86_400_000,
            },
          ],
        }),
        updatedAt: Date.now(),
      });
    });
    const bulk: BulkBody[] = [];
    vi.stubGlobal('fetch', captureBulk(bulk));

    await t.action(internal.donations.applyFreeBonus, {});

    expect(bulk[0]!.fields.trafficLimitBytes).toBe(gbToBytes(80)); // 50 base + 30 bonus
  });

  test('a failing chunk does not abort the run, sets NO marker, and audits donation.bonus_partial', async () => {
    const { t, freeTierId, instanceId } = await setup();
    // A second instance whose panel is down; one key on each.
    const deadInstanceId = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'dead',
        slug: 'dead',
        config: { type: 'remnawave', baseUrl: 'https://dead.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    await seedFreeKey(t, freeTierId, instanceId, 'u-live');
    await seedFreeKey(t, freeTierId, deadInstanceId, 'u-dead');
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 0 }),
        updatedAt: Date.now(),
      }),
    );
    const bulk: BulkBody[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes('dead.test')) return new Response('down', { status: 500 });
        if (url.includes('/api/users/bulk/update')) {
          bulk.push(JSON.parse(init!.body as string) as BulkBody);
        }
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }),
    );

    await t.action(internal.donations.applyFreeBonus, {});

    // The healthy instance's chunk still ran (no whole-run abort)…
    expect(bulk.length).toBe(1);
    expect(bulk[0]!.uuids).toEqual(['u-live']);
    await t.run(async (ctx) => {
      // …but the applied marker was NOT set (next hourly run re-pushes)…
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).appliedBonusGb).toBe(0);
      // …and the failure is surfaced (the start-of-run heartbeat alone would
      // have made the job look healthy).
      const audits = await ctx.db.query('auditLog').collect();
      const partial = audits.find((a) => a.action === 'donation.bonus_partial');
      expect(partial).toBeDefined();
      expect((partial!.payload as { failedChunks: number }).failedChunks).toBeGreaterThan(0);
    });
  });
});

describe('donations.donationTotals', () => {
  test('reads the maintained user-row aggregates (retention-proof), GB computed at the current rate', async () => {
    const { t, freeTierId } = await setup();
    const { userId, otherId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        donatedCentsTotal: 800,
        donationCount: 2,
        updatedAt: Date.now(),
      });
      const otherId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        donatedCentsTotal: 900,
        donationCount: 1,
        updatedAt: Date.now(),
      });
      return { userId, otherId };
    });
    expect(await t.query(internal.donations.donationTotals, { userId })).toEqual({
      donatedCentsTotal: 800,
      donationCount: 2,
      donatedGbTotal: 8, // 800 cents at the 1 GB/$ configured rate (computed server-side)
    });
    expect(await t.query(internal.donations.donationTotals, { userId: otherId })).toEqual({
      donatedCentsTotal: 900,
      donationCount: 1,
      donatedGbTotal: 9,
    });
  });

  test('zeros for a user with no aggregates', async () => {
    const { t, freeTierId } = await setup();
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: Date.now() }),
    );
    expect(await t.query(internal.donations.donationTotals, { userId })).toEqual({
      donatedCentsTotal: 0,
      donationCount: 0,
      donatedGbTotal: 0,
    });
  });
});

describe('publicConfig donation impact projection', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('ships GB-only history (no dollar amounts) + the banded free-user count', async () => {
    const { t } = await setup();
    await t.run(async (ctx) => {
      const put = (key: string, value: unknown) =>
        ctx.db.insert('appState', {
          key,
          value: JSON.stringify(value),
          updatedAt: Date.now(),
        });
      // Two closed months in the ledger + a live current-month accumulator.
      await put('donation:history', [
        { monthKey: '2026-05', donatedCents: 2000, bonusGb: 20 },
        { monthKey: '2026-06', donatedCents: 4000, bonusGb: 40 },
      ]);
      await put('donation:freeBonus', {
        monthKey: thisMonth(),
        donatedCents: 1500,
        appliedBonusGb: 15,
      });
      await put('stats:userCounts', {
        active: 7,
        grace: 0,
        disabled: 0,
        deleted: 0,
        inactive: 0,
        backendDrift: 0,
        freeActive: 5,
      });
    });
    const cfg = await t.query(api.publicConfig.get, {});
    // Banded: the exact count (5) rounds DOWN to the nearest 10 — never an
    // exact live fleet-size signal in the public bootstrap config.
    expect(cfg.billing.donation.freeUsersHelped).toBe(0);
    // Current month synthesized from the live accumulator ($15 × 1 GB/USD).
    expect(cfg.billing.donation.history).toEqual([
      { month: '2026-05', bonusGb: 20 },
      { month: '2026-06', bonusGb: 40 },
      { month: thisMonth(), bonusGb: 15 },
    ]);
    // GB only — the ledger's donatedCents never reaches the public projection.
    expect(JSON.stringify(cfg.billing.donation.history)).not.toContain('donatedCents');
    // The raw GB-per-dollar RATE never ships either — and neither does the
    // per-amount bonus map (bonusGb = cents × rate disclosed it, and with
    // currentBonusGb public the month's donation revenue was derivable).
    // Amounts only. (Review B-F3.)
    expect('bonusGbPerUsd' in cfg.billing.donation).toBe(false);
    expect('suggested' in cfg.billing.donation).toBe(false);
    expect(cfg.billing.donation.suggestedAmountsCents).toEqual([300, 500, 1000, 2500]);
  });

  test('empty history on a deployment with no impact yet', async () => {
    const { t } = await setup();
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.billing.donation.history).toEqual([]);
    expect(cfg.billing.donation.freeUsersHelped).toBe(0);
  });
});

describe('donation pool windows (lib/donationBonus)', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const DAY = 86_400_000;
  const readState = (t: ReturnType<typeof convexTest>) =>
    t.run(async (ctx) => readDonationState(ctx.db));

  test('a donation is stamped with the configured window and expires after it', async () => {
    const { t } = await setup();
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'billing.donation.bonusWindowDays',
        value: JSON.stringify(7),
        updatedAt: Date.now(),
      });
    });
    const now = Date.now();
    await t.run(async (ctx) => recordDonation(ctx, 1000, now));

    const state = await readState(t);
    expect(state.buckets).toHaveLength(1);
    expect(state.buckets![0]!.c).toBe(1000);
    expect(state.buckets![0]!.x).toBe(now + 7 * DAY);
    const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
    expect(effectiveBonusGb(state, cfg, now + 6 * DAY)).toBe(10);
    expect(effectiveBonusGb(state, cfg, now + 8 * DAY)).toBe(0);
  });

  test('changing the window does NOT extend donations already recorded', async () => {
    const { t } = await setup();
    // Fixed mid-month anchor: both gifts land in the same month, so the prune
    // can't remove one and make the assertion depend on the calendar.
    const may10 = Date.UTC(2026, 4, 10);
    await t.run(async (ctx) => recordDonation(ctx, 1000, may10)); // default 30d
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'billing.donation.bonusWindowDays',
        value: JSON.stringify(365),
        updatedAt: Date.now(),
      });
    });
    await t.run(async (ctx) => recordDonation(ctx, 500, may10 + 2 * DAY));

    const state = await readState(t);
    const first = state.buckets!.find((b) => b.c === 1000);
    expect(first?.x).toBe(may10 + 30 * DAY); // still its original window
    const second = state.buckets!.find((b) => b.c === 500);
    expect(second?.x).toBe(may10 + 2 * DAY + 365 * DAY);
  });

  test('same-day donations merge into one bucket', async () => {
    const { t } = await setup();
    const now = Date.now();
    await t.run(async (ctx) => recordDonation(ctx, 1000, now));
    await t.run(async (ctx) => recordDonation(ctx, 250, now + 60_000));

    const state = await readState(t);
    expect(state.buckets).toHaveLength(1);
    expect(state.buckets![0]!.c).toBe(1250);
    expect(state.buckets![0]!.x).toBe(now + 60_000 + 30 * DAY); // the later expiry wins
  });

  test('a refund drains the live pool, newest bucket first', async () => {
    const { t } = await setup();
    const now = Date.now();
    await t.run(async (ctx) => recordDonation(ctx, 1000, now - 2 * DAY));
    await t.run(async (ctx) => recordDonation(ctx, 500, now));
    await t.run(async (ctx) => subtractDonation(ctx, 500, now));

    const state = await readState(t);
    expect(state.buckets!.reduce((s, b) => s + b.c, 0)).toBe(1000);
    // The older bucket is the survivor: draining newest-first keeps funding live
    // for as long as possible.
    expect(state.buckets!.map((b) => b.c)).toEqual([1000]);
  });

  test('a refund drains the bucket that actually funded it, not the newest one', async () => {
    const { t } = await setup();
    const may10 = Date.UTC(2026, 4, 10);
    const may20 = Date.UTC(2026, 4, 20);
    await t.run(async (ctx) => recordDonation(ctx, 1000, may10)); // the one refunded
    await t.run(async (ctx) => recordDonation(ctx, 500, may20)); // unrelated, later
    await t.run(async (ctx) => subtractDonation(ctx, 1000, may20 + DAY, may10));

    const state = await readState(t);
    // The later gift survives intact; the refunded day is gone.
    expect(state.buckets!.map((b) => ({ d: b.d, c: b.c }))).toEqual([{ d: '2026-05-20', c: 500 }]);
  });

  test('a refund of an EXPIRED donation leaves the live pool alone', async () => {
    const { t } = await setup();
    const jan = Date.UTC(2026, 0, 10);
    const now = Date.UTC(2026, 4, 20);
    await t.run(async (ctx) => recordDonation(ctx, 1000, jan)); // long expired
    await t.run(async (ctx) => recordDonation(ctx, 500, now)); // live
    await t.run(async (ctx) => subtractDonation(ctx, 1000, now, jan));

    const state = await readState(t);
    const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
    // The live $5 is untouched — the refund had nothing live to take back.
    expect(effectiveBonusGb(state, cfg, now)).toBe(5);
  });

  test("a previous month's refund does not shrink THIS month's ledger", async () => {
    const { t } = await setup();
    const apr = Date.UTC(2026, 3, 10);
    const may = Date.UTC(2026, 4, 20);
    await t.run(async (ctx) => recordDonation(ctx, 1000, apr));
    await t.run(async (ctx) => recordDonation(ctx, 500, may));
    await t.run(async (ctx) => subtractDonation(ctx, 1000, may, apr));

    const state = await readState(t);
    // May raised $5 and still reports $5; April's refund is not May's business.
    expect(state.monthKey).toBe('2026-05');
    expect(state.donatedCents).toBe(500);
  });

  test('a legacy `days` row converts to buckets that expire when ITS month ended', async () => {
    const { t } = await setup();
    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({
          monthKey: '2026-07',
          donatedCents: 3000,
          appliedBonusGb: 30,
          // Cumulative snapshots, the pre-window shape.
          days: { '2026-07-03': 1000, '2026-07-09': 3000 },
        }),
        updatedAt: Date.now(),
      });
    });
    const state = await readState(t);
    // Deltas, not the cumulative totals.
    expect(state.buckets).toEqual([
      { d: '2026-07-03', c: 1000, x: Date.UTC(2026, 7, 1) },
      { d: '2026-07-09', c: 2000, x: Date.UTC(2026, 7, 1) },
    ]);
    expect(state.days).toBeUndefined();
    const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
    // Live during July, gone in August — the rule those gifts were made under.
    expect(effectiveBonusGb(state, cfg, Date.UTC(2026, 6, 20))).toBe(30);
    expect(effectiveBonusGb(state, cfg, Date.UTC(2026, 7, 2))).toBe(0);
  });

  test('expired buckets outside the current month are pruned on write', async () => {
    const { t } = await setup();
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({
          monthKey: '2020-01',
          donatedCents: 5000,
          appliedBonusGb: 0,
          buckets: [{ d: '2020-01-05', c: 5000, x: Date.UTC(2020, 1, 1) }],
        }),
        updatedAt: now,
      });
    });
    await t.run(async (ctx) => recordDonation(ctx, 100, now));

    const state = await readState(t);
    expect(state.buckets).toHaveLength(1);
    expect(state.buckets![0]!.c).toBe(100);
  });
});
