/**
 * A country on its own addresses (pure; unit-tested). docs/edges.md "A country
 * on its own addresses" is the contract; in short:
 *
 *  - A node may cut a country over (`relays.ownPools[]`): its members are
 *    handed the node's addresses made for that country first, for the primary
 *    and the backup, and a shared address only as a fallback (when theirs is
 *    blocked there or cannot be handed out, or as the backup when they have
 *    only one).
 *  - Once the cutover has settled (one refresh interval and the revalidation
 *    window, as the steering vetoes wait), that country's evidence never
 *    replaces a shared address on the node (veto `own_pool`).
 *  - Its own addresses spend its own budget: replacements per node, per
 *    transport, per UTC day, outside the node's daily cap, its cooldown and the
 *    fleet's caps. A node's value wins over the country's, which wins over the
 *    fleet's; 0 = never automatic. An operator's replace is counted, never refused.
 */
import { assignEndpoints, type AssignOptions, type PublishedEdge } from './assignment';
import { EDGE_PICK_SAMPLE, sampleSeat } from './edgePick';

/** A cut-over country as stored (`relays.ownPools[]`). */
export interface OwnPool {
  code: string;
  since: number;
  stale?: { at: number; keys: number };
}

/** The countries cut over on a node (any age). */
export function ownCodesOf(o: { ownPools?: readonly OwnPool[] }): string[] {
  return (o.ownPools ?? []).map((p) => p.code);
}

/**
 * The countries whose cutover has settled: members of theirs who refresh hold
 * their own addresses by now, so their evidence may stop moving shared ones.
 */
export function settledOwnCodes(
  o: { ownPools?: readonly OwnPool[] },
  settleMs: number,
  now: number,
): string[] {
  return (o.ownPools ?? []).filter((p) => now - p.since >= settleMs).map((p) => p.code);
}

/** Whether an address belongs to a country cut over on its node (its audience names one). */
export function isOwnAddress(
  edge: { audience?: readonly string[] | null },
  own: readonly string[],
): boolean {
  return !!edge.audience?.length && edge.audience.some((c) => own.includes(c));
}

/** The budget's key for one address: its countries and its transport. */
export function ownBudgetKey(audience: readonly string[], listenerId: string): string {
  return `${[...new Set(audience)].sort().join(' ')}|${listenerId}`;
}

/**
 * Replacements a day allowed for an address made for `audience`: the node's
 * own value, else the strictest of its countries' values, else the fleet's.
 */
export function ownBudgetPerDay(
  origin: { audienceReplacesPerDay?: number },
  audience: readonly string[],
  cfg: { replacesPerDay: number; replacesPerDayByCountry: Record<string, number> },
): number {
  if (origin.audienceReplacesPerDay !== undefined) return origin.audienceReplacesPerDay;
  const byCountry = audience
    .map((c) => cfg.replacesPerDayByCountry[c])
    .filter((n): n is number => n !== undefined);
  return byCountry.length > 0 ? Math.min(...byCountry) : cfg.replacesPerDay;
}

/** Replacements already made today under one key (UTC day key, as `rotationsDayKey`). */
export function ownReplacesToday(
  origin: { audienceReplaces?: ReadonlyArray<{ key: string; day: string; count: number }> },
  key: string,
  today: string,
): number {
  const hit = (origin.audienceReplaces ?? []).find((r) => r.key === key && r.day === today);
  return hit?.count ?? 0;
}

/** The node's counts with one more under `key` today (other days dropped). */
export function withOwnReplace(
  origin: { audienceReplaces?: ReadonlyArray<{ key: string; day: string; count: number }> },
  key: string,
  today: string,
): Array<{ key: string; day: string; count: number }> {
  const kept = (origin.audienceReplaces ?? []).filter((r) => r.day === today && r.key !== key);
  return [...kept, { key, day: today, count: ownReplacesToday(origin, key, today) + 1 }];
}

/** What cutting a country over changes for its members on one node, over synthetic seats. */
export interface CutoverRehearsal {
  /** Seats that are handed anything at all. */
  sampled: number;
  /** Seats whose primary or backup address changes. */
  moved: number;
  /** Seats handed at least one shared address, before and after. */
  sharedBefore: number;
  sharedAfter: number;
}

/**
 * The rehearsal of a cutover (the preview before an operator cuts a country
 * over): each synthetic seat steered by `country`, assigned as today and as
 * with the country on its own addresses. Synthetic seats, no member row.
 */
export function cutoverRehearsal(
  published: readonly PublishedEdge[],
  country: string,
  opts: Omit<AssignOptions, 'edgeCountry' | 'ownPool'>,
  sample = EDGE_PICK_SAMPLE,
): CutoverRehearsal {
  const out: CutoverRehearsal = { sampled: 0, moved: 0, sharedBefore: 0, sharedAfter: 0 };
  const isShared = (id: string | undefined) =>
    id !== undefined && !published.find((e) => e.edgeId === id)?.audience?.includes(country);
  for (let i = 0; i < sample; i++) {
    const seat = sampleSeat(i);
    const was = assignEndpoints(seat, published, { ...opts, edgeCountry: country });
    const now = assignEndpoints(seat, published, { ...opts, edgeCountry: country, ownPool: true });
    const ids = (a: typeof was) => [a.primary?.edge.edgeId, a.backup?.edge.edgeId];
    const [wp, wb] = ids(was);
    const [np, nb] = ids(now);
    if (!wp && !np) continue;
    out.sampled++;
    if (wp !== np || wb !== nb) out.moved++;
    if (isShared(wp) || isShared(wb)) out.sharedBefore++;
    if (isShared(np) || isShared(nb)) out.sharedAfter++;
  }
  return out;
}
