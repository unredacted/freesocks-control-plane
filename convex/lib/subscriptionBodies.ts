/**
 * The fronted route's per-UA body cache (`subscriptionBodies`, one row per
 * key and User-Agent, at most SUB_CACHE_MAX per key). It lives beside the
 * `subscriptions` row instead of inside it: a delivery stamp, a country guess
 * or any other patch to the key then neither rewrites nor re-reads up to four
 * full configuration bodies, and a body write leaves the cached reads of the
 * key alone.
 *
 * The old home was the row's `subCache` blob. Until a row's blob has been
 * copied across (by the first body written for the key, or by
 * convex/subscriptionBodies.ts `migrateLegacy`) the route still reads it; the
 * release after drops the field.
 *
 * Entries are stored serialized and never parsed here beyond the few fields the
 * store itself judges (ua, at, region, lane): the route's further fields
 * (format version, edge token, render epoch, validity, snapshot) pass through
 * untouched. See SubCacheEntry in convex/http.ts.
 */
import type { DatabaseReader, MutationCtx } from '../_generated/server';
import type { Doc, Id } from '../_generated/dataModel';
import { readStateJson } from './appStateJson';

/**
 * How many UA formats a key keeps (Review #11): several apps on one key (phone
 * and desktop, distinct UAs) don't evict each other into a refetch on every
 * request. Small: a short-TTL in-front cache, not durable storage.
 */
export const SUB_CACHE_MAX = 4;

/**
 * Set by the rollback step (convex/subscriptionBodies.ts `clearForRollback`)
 * before it deletes anything: no body is written while it is set, so none can
 * come back behind the drain. A deploy of this build lifts it (`resume`).
 */
export const BODIES_PAUSED_KEY = 'subscriptionBodies:paused';

export async function bodiesPaused(db: DatabaseReader): Promise<boolean> {
  return (await readStateJson<boolean>(db, BODIES_PAUSED_KEY)) === true;
}

/** A key never holds more rows than this, whatever went wrong before. */
const ROWS_READ_CAP = 32;

/** The fields of a cached entry the store looks at; everything else passes through. */
export interface BodyEntry {
  ua: string;
  at: number;
  /** The stored country the body was shaped for (convex/memberCountry.ts). */
  region?: string | null;
  /** The account's address lane it was rendered for (convex/edgeLanes.ts). */
  lane?: 'open' | 'trusted' | null;
}

/** One serialized entry, or null when it is not one. */
export function parseEntry(raw: string): BodyEntry | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const e = parsed as Partial<BodyEntry>;
    return typeof e.ua === 'string' && typeof e.at === 'number' ? (parsed as BodyEntry) : null;
  } catch {
    return null;
  }
}

/** A row's old `subCache` blob as entries (tolerates the legacy single-entry form). */
export function legacyEntries(blob: string | null | undefined): BodyEntry[] {
  if (!blob) return [];
  try {
    const parsed = JSON.parse(blob) as unknown;
    const list = Array.isArray(parsed)
      ? (parsed as unknown[])
      : parsed && typeof parsed === 'object'
        ? [parsed]
        : [];
    return list.filter(
      (e): e is BodyEntry =>
        !!e &&
        typeof e === 'object' &&
        typeof (e as BodyEntry).ua === 'string' &&
        typeof (e as BodyEntry).at === 'number',
    );
  } catch {
    return [];
  }
}

/** Every body row of a key (bounded: at most SUB_CACHE_MAX by construction). */
export function bodyRowsOf(
  db: DatabaseReader,
  subscriptionId: Id<'subscriptions'>,
): Promise<Doc<'subscriptionBodies'>[]> {
  return db
    .query('subscriptionBodies')
    .withIndex('by_subscription_ua', (q) => q.eq('subscriptionId', subscriptionId))
    .take(ROWS_READ_CAP);
}

/** This UA's body row, if any: one indexed read, no other UA's body loaded. */
export function bodyRowFor(
  db: DatabaseReader,
  subscriptionId: Id<'subscriptions'>,
  ua: string,
): Promise<Doc<'subscriptionBodies'> | null> {
  return db
    .query('subscriptionBodies')
    .withIndex('by_subscription_ua', (q) => q.eq('subscriptionId', subscriptionId).eq('ua', ua))
    .first();
}

/**
 * The serialized entries that may answer this UA: the table's row, else (until
 * the key's old blob is copied across) the blob's entry for the UA. Reads the
 * subscription row only in the second case, so a migrated key's lookup never
 * depends on the row.
 */
export async function entriesForUa(
  db: DatabaseReader,
  subscriptionId: Id<'subscriptions'>,
  ua: string,
  sub?: Doc<'subscriptions'> | null,
): Promise<string[]> {
  const row = await bodyRowFor(db, subscriptionId, ua);
  if (row) return [row.entry];
  const legacy = sub === undefined ? await db.get(subscriptionId) : sub;
  if (!legacy?.subCache) return [];
  return legacyEntries(legacy.subCache)
    .filter((e) => e.ua === ua)
    .map((e) => JSON.stringify(e));
}

const regionOf = (e: BodyEntry): string | undefined =>
  typeof e.region === 'string' ? e.region : undefined;

/**
 * Merge into a key's bodies: `incoming` (when given) takes its UA's slot, the
 * rest keep theirs while `allowed`, and only the most recent SUB_CACHE_MAX stay
 * (newest first by fetch time; an incoming entry older than all of them is not
 * kept). The key's old blob, if it still has one, is folded in and cleared, so
 * this is also the lazy migration. Rows that are kept as they were are not
 * rewritten. Serializable: concurrent writes for distinct UAs never clobber.
 * Writes nothing while a rollback has paused the table (`BODIES_PAUSED_KEY`).
 */
export async function storeBodies(
  ctx: MutationCtx,
  sub: Doc<'subscriptions'>,
  opts: {
    incoming?: { entry: BodyEntry; raw: string };
    allowed?: (e: BodyEntry) => boolean;
  } = {},
): Promise<void> {
  // A rollback is draining the table: write nothing (the old blob stays).
  if (await bodiesPaused(ctx.db)) return;
  const allowed = opts.allowed ?? (() => true);
  const rows = await bodyRowsOf(ctx.db, sub._id);
  const rowUas = new Set(rows.map((r) => r.ua));
  type Candidate = { entry: BodyEntry; raw: string; row?: Doc<'subscriptionBodies'> };
  const existing: Candidate[] = [];
  for (const row of rows) {
    const entry = parseEntry(row.entry);
    if (entry) existing.push({ entry, raw: row.entry, row });
  }
  for (const entry of legacyEntries(sub.subCache))
    if (!rowUas.has(entry.ua)) existing.push({ entry, raw: JSON.stringify(entry) });
  const incoming = opts.incoming;
  const keep: Candidate[] = [
    ...(incoming ? [incoming] : []),
    ...existing.filter((c) => c.entry.ua !== incoming?.entry.ua && allowed(c.entry)),
  ]
    .sort((a, b) => b.entry.at - a.entry.at)
    .slice(0, SUB_CACHE_MAX);
  // One kept candidate per UA (a legacy blob could repeat one; the newest wins).
  const byUa = new Map<string, Candidate>();
  for (const c of keep) if (!byUa.has(c.entry.ua)) byUa.set(c.entry.ua, c);
  const written = new Set<string>();
  for (const row of rows) {
    const kept = byUa.get(row.ua);
    if (!kept || written.has(row.ua)) {
      await ctx.db.delete(row._id);
      continue;
    }
    written.add(row.ua);
    if (kept.row?._id === row._id) continue; // unchanged
    await ctx.db.patch(row._id, {
      at: kept.entry.at,
      region: regionOf(kept.entry),
      entry: kept.raw,
    });
  }
  for (const [ua, c] of byUa) {
    if (written.has(ua)) continue;
    await ctx.db.insert('subscriptionBodies', {
      subscriptionId: sub._id,
      ua,
      at: c.entry.at,
      ...(regionOf(c.entry) !== undefined ? { region: regionOf(c.entry) } : {}),
      entry: c.raw,
    });
  }
  if (sub.subCache !== undefined) await ctx.db.patch(sub._id, { subCache: undefined });
}

/** Drop every body of a key (an in-place move, a deleted key, a purged account). */
export async function dropBodies(
  ctx: MutationCtx,
  subscriptionId: Id<'subscriptions'>,
): Promise<void> {
  for (const row of await bodyRowsOf(ctx.db, subscriptionId)) await ctx.db.delete(row._id);
}

/**
 * Keep only the bodies that may stay under the key's stored country: those
 * shaped for no country, or for `stored` (convex/memberCountry.ts, the one
 * invariant: a stored copy of the member's country never outlives it).
 */
export async function keepBodiesFor(
  ctx: MutationCtx,
  subscriptionId: Id<'subscriptions'>,
  stored: string | null,
): Promise<void> {
  const shaped = await ctx.db
    .query('subscriptionBodies')
    .withIndex('by_subscription_region', (q) =>
      q.eq('subscriptionId', subscriptionId).gte('region', ''),
    )
    .take(ROWS_READ_CAP);
  for (const row of shaped) if (row.region !== stored) await ctx.db.delete(row._id);
}
