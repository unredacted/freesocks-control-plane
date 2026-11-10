/**
 * Keys by country: the daily recount of the `stats:countryKeys` counter
 * (lib/countryKeyCounts.ts; docs/edges.md "Keys by country").
 *
 * The counter is bumped in the transaction that changes a key's answer or
 * guess, so the per-country numbers are current. This recount rebuilds all of
 * it exactly with the begin -> scan pages -> finish protocol of
 * lib/statusCounters.ts (bounded pages, never a whole-table read; exact under
 * concurrent writes), which heals any missed bump, and it is the only writer
 * of `none`: the active Freedom-family keys with no answer and no guess. A
 * key's family is not on its row, so that number is judged here, once a day
 * and once after every deploy. The recount judges the family of every active
 * key, so a key that is no longer of a freedom mode but still holds a country
 * (until the clean-up clears it) is counted nowhere.
 *
 * Nothing here returns or logs anything about a key: numbers only.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { runWithCronOutcome } from './cronHeartbeat';
import { resolveCensoredCountries } from './lib/censoredCountries';
import {
  COUNTRY_KEY_COUNTED_AT_KEY,
  COUNTRY_KEY_COUNTER,
  countryBucket,
  readCountryKeys,
  type CountryKeyCounts,
  type CountryKeysView,
} from './lib/countryKeyCounts';
import { familyReads, memberFamilyOf } from './lib/memberFamily';
import {
  beginCounterReconcile,
  finishCounterReconcile,
  scanCounterPage,
} from './lib/statusCounters';

/**
 * Rows per page. Judging a key reads its member (one read per active key);
 * the rest of what a family needs is read once per page.
 */
const PAGE = 400;

export const beginReconcile = internalMutation({
  args: {},
  handler: async (ctx): Promise<number> => beginCounterReconcile(ctx, COUNTRY_KEY_COUNTER),
});

export const scanPage = internalMutation({
  args: { pageSize: v.optional(v.number()) },
  handler: async (ctx, { pageSize }) => {
    const reads = familyReads();
    return scanCounterPage(
      ctx,
      COUNTRY_KEY_COUNTER,
      async (row): Promise<CountryKeyCounts> => {
        if (row.state !== 'active') return {};
        // Only a Freedom key is counted, with a country or without. A key
        // whose mode left the freedom family keeps its answer or guess until
        // the clean-up reaches it (memberCountry.cleanStoredCountries): it is
        // in none of the numbers meanwhile.
        const family = await memberFamilyOf(ctx.db, row, undefined, reads);
        if (family !== 'freedom') return {};
        return { [countryBucket(row) ?? 'none']: 1 };
      },
      pageSize ?? PAGE,
    );
  },
});

export const finishReconcile = internalMutation({
  args: { token: v.number() },
  handler: async (ctx, { token }): Promise<boolean> => {
    const applied = await finishCounterReconcile(ctx, COUNTRY_KEY_COUNTER, token);
    if (!applied) return false;
    const value = JSON.stringify({ at: Date.now() });
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', COUNTRY_KEY_COUNTED_AT_KEY))
      .unique();
    if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
    else
      await ctx.db.insert('appState', {
        key: COUNTRY_KEY_COUNTED_AT_KEY,
        value,
        updatedAt: Date.now(),
      });
    return true;
  },
});

/** The counts as the Countries pages show them (listed countries, the opt-out, the rest). */
export const view = internalQuery({
  args: {},
  handler: async (ctx): Promise<CountryKeysView> =>
    readCountryKeys(ctx.db, (await resolveCensoredCountries(ctx.db)).codes),
});

/** Recount every key (idempotent, self-healing). Daily, and once after a deploy. */
export const reconcile = internalAction({
  args: {},
  handler: async (ctx): Promise<{ applied: boolean; rows: number }> =>
    runWithCronOutcome(ctx, 'country-keys-reconcile', async () => {
      const token: number = await ctx.runMutation(internal.countryKeyCounts.beginReconcile, {});
      let rows = 0;
      for (let i = 0; i < 100_000; i++) {
        const res: { done: boolean; rows: number } = await ctx.runMutation(
          internal.countryKeyCounts.scanPage,
          {},
        );
        rows += res.rows;
        if (res.done) break;
      }
      const applied: boolean = await ctx.runMutation(internal.countryKeyCounts.finishReconcile, {
        token,
      });
      if (!applied) console.warn('[country-keys-reconcile] superseded by a newer run; skipped');
      return { applied, rows };
    }),
});
