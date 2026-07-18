/**
 * Donation free-bandwidth bonus — the runtime side of lib/donationBonus.ts.
 * `applyFreeBonus` re-caps the whole free fleet to base+bonus whenever the shared
 * monthly bonus moves (a donation lands, or the calendar month rolls over → back
 * to base), idempotently. Scheduled from the checkout grant (billing.applyEvent)
 * and backstopped by the hourly `donation-bonus-reconcile` cron. Every function is
 * internal — the accumulator is not world-readable (publicConfig ships only the
 * derived `currentBonusGb`).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { runWithCronOutcome } from './cronHeartbeat';
import { resolveBillingConfig } from './lib/billingConfig';
import { effectiveBonusGb, readDonationState, writeDonationState } from './lib/donationBonus';
import { resolveTrafficLimitBytes } from './lib/backends/types';

/** One page of active free users' active subs (shared by the query + the action,
 *  and annotated at the call site to break Convex's self-file inference cycle). */
type ActiveFreeSubsPage = {
  subs: {
    backend: 'remnawave' | 'outline';
    backendUserId: string;
    backendServerId: Id<'backendServers'> | null;
  }[];
  isDone: boolean;
  continueCursor: string;
};

/** Live effective bonus GB — for issuance sites resolving the free limit in an action. */
export const currentBonusGb = internalQuery({
  args: {},
  handler: async (ctx): Promise<number> => {
    const [state, cfg] = await Promise.all([
      readDonationState(ctx.db),
      resolveBillingConfig(ctx.db),
    ]);
    if (!cfg.donation.enabled) return 0;
    return effectiveBonusGb(state, cfg.donation, Date.now());
  },
});

/** A member's own settled donation totals (impact panel). Bounded: one user's
 *  orders via by_user, filtered to paid rows carrying a donation. Also returns
 *  the GB equivalent at the CURRENT rate (the raw rate itself stays server-side
 *  — see the publicConfig projection), so the client never needs it. */
export const donationTotals = internalQuery({
  args: { userId: v.id('users') },
  handler: async (
    ctx,
    { userId },
  ): Promise<{ donatedCentsTotal: number; donationCount: number; donatedGbTotal: number }> => {
    const orders = await ctx.db
      .query('billingOrders')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    let donatedCentsTotal = 0;
    let donationCount = 0;
    for (const o of orders) {
      if (o.status !== 'paid') continue;
      const cents = o.donationCents ?? 0;
      if (cents <= 0) continue;
      donatedCentsTotal += cents;
      donationCount += 1;
    }
    const cfg = await resolveBillingConfig(ctx.db);
    const donatedGbTotal = (donatedCentsTotal / 100) * cfg.donation.bonusGbPerUsd;
    return { donatedCentsTotal, donationCount, donatedGbTotal };
  },
});

/** Everything applyFreeBonus needs in one read: the effective vs last-pushed bonus
 *  and the free tiers (id + base GB) whose keys must be re-capped. */
export const applyContext = internalQuery({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    effective: number;
    applied: number;
    freeTiers: { id: Id<'tiers'>; monthlyTrafficGb: number }[];
  }> => {
    const [state, cfg] = await Promise.all([
      readDonationState(ctx.db),
      resolveBillingConfig(ctx.db),
    ]);
    const effective = cfg.donation.enabled ? effectiveBonusGb(state, cfg.donation, Date.now()) : 0;
    const freeTiers = (await ctx.db.query('tiers').collect())
      .filter((t) => t.isDefaultFree)
      .map((t) => ({ id: t._id, monthlyTrafficGb: t.monthlyTrafficGb }));
    return { effective, applied: state.appliedBonusGb, freeTiers };
  },
});

/** Persist the bonus GB last pushed to the fleet (the idempotence marker); leaves
 *  the month bucket + donated total untouched. */
export const setAppliedBonusGb = internalMutation({
  args: { appliedBonusGb: v.number() },
  handler: async (ctx, { appliedBonusGb }) => {
    const state = await readDonationState(ctx.db);
    await writeDonationState(ctx, { ...state, appliedBonusGb });
    return null;
  },
});

/**
 * One page of ACTIVE free users' active subscriptions on a tier (backend user id +
 * hosting instance), for the fleet re-cap. Mirrors lifecycle.findIdleFree's cursor
 * paginate over `by_tier_status_freekey`, prefix-scoped to (tierId, 'active') so it
 * covers every active free user (legacy rows with an unset freeKeyExpiresAt too).
 */
export const findActiveFreeSubs = internalQuery({
  args: {
    tierId: v.id('tiers'),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  // Explicit return type breaks Convex's cross-module inference cycle (applyFreeBonus
  // references this query's result), the same convention as subscriptions.ts.
  handler: async (ctx, { tierId, cursor, numItems }): Promise<ActiveFreeSubsPage> => {
    const res = await ctx.db
      .query('users')
      .withIndex('by_tier_status_freekey', (q) => q.eq('tierId', tierId).eq('status', 'active'))
      .paginate({ cursor, numItems });
    const subs: {
      backend: 'remnawave' | 'outline';
      backendUserId: string;
      backendServerId: Id<'backendServers'> | null;
    }[] = [];
    for (const u of res.page) {
      const sub = await ctx.db
        .query('subscriptions')
        .withIndex('by_user_state', (q) => q.eq('userId', u._id).eq('state', 'active'))
        .order('desc')
        .first();
      if (sub) {
        subs.push({
          backend: sub.backend,
          backendUserId: sub.backendUserId,
          backendServerId: sub.backendServerId ?? null,
        });
      }
    }
    return { subs, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

const APPLY_PAGE_SIZE = 200;
const APPLY_MAX_PAGES = 10_000; // runaway backstop (~2M free users); real fleets exit on isDone
const BULK_CHUNK = 500; // Remnawave bulk/update uuids cap

/**
 * Re-cap the free fleet's `trafficLimitBytes` to base+bonus whenever the shared
 * monthly bonus moves. Idempotent: a no-op when the effective bonus already equals
 * what was last pushed (so the hourly cron is cheap, and the month-roll reset — when
 * effective drops to 0 — pushes base back exactly once). Groups each page's
 * Remnawave keys by hosting instance and bulk-updates in ≤500-uuid chunks.
 *
 * Failure semantics: each chunk is isolated (one down panel must not abort the
 * whole run — the start-of-run heartbeat would otherwise make a wedged job look
 * healthy), and the applied marker is set ONLY after a full, zero-failure drain:
 * a partial run leaves the marker unset so the next hourly tick re-pushes
 * (idempotent — the same values), and a loud audit names the stragglers.
 */
export const applyFreeBonus = internalAction({
  args: {},
  handler: async (ctx): Promise<null> =>
    runWithCronOutcome(ctx, 'donation-bonus-reconcile', async () => {
      const { effective, applied, freeTiers } = await ctx.runQuery(
        internal.donations.applyContext,
        {},
      );
      if (effective === applied) return null; // nothing changed → no fleet push
      let failedChunks = 0;
      let exhausted = false;
      for (const tier of freeTiers) {
        const limitBytes = resolveTrafficLimitBytes(
          { monthlyTrafficGb: tier.monthlyTrafficGb, isDefaultFree: true },
          effective,
        );
        if (limitBytes === null) continue; // an unlimited free tier — nothing to cap
        let cursor: string | null = null;
        let tierDone = false;
        for (let page = 0; page < APPLY_MAX_PAGES; page++) {
          const res: ActiveFreeSubsPage = await ctx.runQuery(
            internal.donations.findActiveFreeSubs,
            {
              tierId: tier.id,
              cursor,
              numItems: APPLY_PAGE_SIZE,
            },
          );
          // Group this page's Remnawave keys by hosting instance, then bulk-update.
          const byServer = new Map<Id<'backendServers'>, string[]>();
          for (const s of res.subs) {
            if (s.backend !== 'remnawave' || !s.backendServerId) continue;
            const arr = byServer.get(s.backendServerId) ?? [];
            arr.push(s.backendUserId);
            byServer.set(s.backendServerId, arr);
          }
          for (const [serverId, ids] of byServer) {
            for (let i = 0; i < ids.length; i += BULK_CHUNK) {
              try {
                await ctx.runAction(internal.backends.bulkUpdateTrafficLimit, {
                  backendServerId: serverId,
                  backendUserIds: ids.slice(i, i + BULK_CHUNK),
                  trafficLimitBytes: limitBytes,
                });
              } catch (err) {
                failedChunks++;
                console.warn(
                  `[donations] bulk re-cap chunk failed (server ${serverId}): ${
                    err instanceof Error ? err.message : 'unknown'
                  }`,
                );
              }
            }
          }
          // Outline keys (no bulk endpoint): per-user data-limit updates, with the
          // same per-key isolation (a throw leaves the applied marker unset so the
          // next run retries, but must not abort the rest of the fleet).
          for (const s of res.subs) {
            if (s.backend !== 'outline') continue;
            try {
              await ctx.runAction(internal.backends.updateUser, {
                backend: 'outline',
                backendUserId: s.backendUserId,
                patch: { trafficLimitBytes: limitBytes },
              });
            } catch (err) {
              failedChunks++;
              console.warn(
                `[donations] outline re-cap failed for a key: ${
                  err instanceof Error ? err.message : 'unknown'
                }`,
              );
            }
          }
          if (res.isDone) {
            tierDone = true;
            break;
          }
          cursor = res.continueCursor;
        }
        if (!tierDone) exhausted = true; // hit APPLY_MAX_PAGES without draining
      }
      if (failedChunks > 0 || exhausted) {
        console.warn(
          `[donations] bonus re-cap incomplete: ${failedChunks} failed chunk(s), exhausted=${exhausted} — applied marker NOT set; next run retries`,
        );
        try {
          await ctx.runMutation(internal.audit.record, {
            actorType: 'system',
            action: 'donation.bonus_partial',
            targetType: 'donation',
            payload: { effective, failedChunks, exhausted },
          });
        } catch {
          /* the retry on the next tick is the remediation */
        }
        return null;
      }
      await ctx.runMutation(internal.donations.setAppliedBonusGb, { appliedBonusGb: effective });
      return null;
    }),
});
