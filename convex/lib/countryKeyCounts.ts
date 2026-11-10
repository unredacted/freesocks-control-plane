/**
 * How many keys are set to each country (docs/edges.md "Keys by country";
 * docs/privacy.md "Where a member connects from"): a maintained counter, so an
 * admin page never reads the `subscriptions` table to answer "how many members
 * connect from there".
 *
 * COUNTS ONLY. The counter holds a number per country and nothing about any
 * key: no key, member, support ID or node. A key is counted once, by what it
 * holds while it is active:
 *
 *   c:<CC>   the member's own answer (`sniRegion`) is that country
 *   c:ZZ     the member chose the opt-out
 *   g:<CC>   no answer, and the stored guess (`regionSeenCountry`) is that country
 *   none     a Freedom-family key with neither (counted once a day, below)
 *
 * Only keys of a Freedom-family mode carry a country at all
 * (lib/memberCountry.ts), so the first three count Freedom keys by
 * construction. They move in the transaction that changes the row
 * (`bumpCountryKeys`), from a pure function of the row (`countryBucket`).
 * `none` cannot: which family a key is in is read from the mode pools, its
 * node's mode and its member's stored mode, none of which is on the row, so a
 * key changes family without a write to it. The daily recount
 * (convex/countryKeyCounts.ts) judges every active key and writes `none`; the
 * same recount rebuilds the per-country numbers exactly, so a missed bump
 * heals there.
 */
import type { DatabaseReader, MutationCtx } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { ELSEWHERE } from './memberCountry';
import { applyCounterDeltas, readCounter, type CounterSpec } from './statusCounters';

export const COUNTRY_KEY_COUNTS_KEY = 'stats:countryKeys';
/** When the last full recount finished (`{ at }`): `none` is as of then. */
export const COUNTRY_KEY_COUNTED_AT_KEY = 'stats:countryKeys:countedAt';

/** `c:<CC>` | `g:<CC>` | `none`, each a number of keys. */
export type CountryKeyCounts = Record<string, number>;

const BUCKET = /^[cg]:[A-Z]{2}$/;

export const COUNTRY_KEY_COUNTER: CounterSpec<CountryKeyCounts, 'subscriptions'> = {
  key: COUNTRY_KEY_COUNTS_KEY,
  table: 'subscriptions',
  zero: { none: 0 },
  // Keys held a country before the counter existed: nothing is known until the
  // first recount, and a bump before it has nothing to add to.
  legacyInitialized: false,
  createOnBump: false,
  dynamicKey: (k) => BUCKET.test(k),
};

type CountryRow = Pick<Doc<'subscriptions'>, 'state' | 'sniRegion' | 'regionSeenCountry'>;

/**
 * Where a row is counted, from the row alone: its answer, else its guess,
 * else nowhere. Only an active key counts (a replaced key keeps its fields
 * through its grace, beside the key that carried them on).
 */
export function countryBucket(row: CountryRow): string | null {
  if (row.state !== 'active') return null;
  const bucket = row.sniRegion
    ? `c:${row.sniRegion}`
    : row.regionSeenCountry
      ? `g:${row.regionSeenCountry}`
      : null;
  return bucket && BUCKET.test(bucket) ? bucket : null;
}

/** A row's place moved (`from`/`to` null: not counted). Every write that changes it calls this. */
export async function bumpCountryKeys(
  ctx: MutationCtx,
  changes: readonly { from: string | null; to: string | null; creationTime: number }[],
): Promise<void> {
  await applyCounterDeltas(
    ctx,
    COUNTRY_KEY_COUNTER,
    changes
      .filter((c) => c.from !== c.to)
      .map((c) => {
        const delta: CountryKeyCounts = {};
        if (c.from) delta[c.from] = (delta[c.from] ?? 0) - 1;
        if (c.to) delta[c.to] = (delta[c.to] ?? 0) + 1;
        return { delta, creationTime: c.creationTime };
      }),
  );
}

/** One row before and after a write (`after` null: the row is gone). */
export async function bumpCountryKeysForRow(
  ctx: MutationCtx,
  before: (CountryRow & { _creationTime: number }) | null,
  after: (CountryRow & { _creationTime: number }) | null,
): Promise<void> {
  const row = before ?? after;
  if (!row) return;
  await bumpCountryKeys(ctx, [
    {
      from: before ? countryBucket(before) : null,
      to: after ? countryBucket(after) : null,
      creationTime: row._creationTime,
    },
  ]);
}

export interface CountryKeysView {
  /** A full recount has finished: until then nothing is known. */
  counted: boolean;
  /** When the last full recount finished (`neither` is as of then). */
  countedAt: number | null;
  /** Per listed country: keys whose member answered it, and keys guessed there. */
  byCountry: Record<string, { answered: number; guessed: number }>;
  /** Keys whose member chose the opt-out. */
  optOut: number;
  /** Freedom keys with no answer and no guess, as of the last recount. */
  neither: number;
  /** Keys guessed in a country that is not on the list (any-country guesses). */
  otherGuessed: number;
}

/** The counter as the Countries pages read it: numbers per listed country, and the rest. */
export function countryKeysView(
  counts: CountryKeyCounts,
  initialized: boolean,
  countedAt: number | null,
  listed: readonly string[],
): CountryKeysView {
  const of = (k: string) => Math.max(0, counts[k] ?? 0);
  const byCountry: CountryKeysView['byCountry'] = {};
  for (const cc of listed) byCountry[cc] = { answered: of(`c:${cc}`), guessed: of(`g:${cc}`) };
  let otherGuessed = 0;
  for (const k of Object.keys(counts))
    if (k.startsWith('g:') && !listed.includes(k.slice(2))) otherGuessed += of(k);
  return {
    counted: initialized,
    countedAt: initialized ? countedAt : null,
    byCountry,
    optOut: of(`c:${ELSEWHERE}`),
    neither: of('none'),
    otherGuessed,
  };
}

export async function readCountryKeys(
  db: DatabaseReader,
  listed: readonly string[],
): Promise<CountryKeysView> {
  const { counts, initialized } = await readCounter(db, COUNTRY_KEY_COUNTER);
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', COUNTRY_KEY_COUNTED_AT_KEY))
    .unique();
  let countedAt: number | null = null;
  try {
    const at = row ? (JSON.parse(row.value) as { at?: unknown }).at : null;
    if (typeof at === 'number' && Number.isFinite(at)) countedAt = at;
  } catch {
    countedAt = null;
  }
  return countryKeysView(counts, initialized, countedAt, listed);
}
