/**
 * When the block detector last evaluated an origin (`relayEvalStamps`, one row
 * per origin). Kept off the `relays` row so the 5-min detector pass writes the
 * origin only when its suspicion changes (convex/edgeDetector.ts
 * `recordEvaluation`); this stamp moves every pass and only the admin origin
 * view reads it.
 */
import type { DatabaseReader, MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';

async function stampRow(db: DatabaseReader, relayId: Id<'relays'>) {
  return db
    .query('relayEvalStamps')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .unique();
}

export async function stampEvaluation(
  ctx: MutationCtx,
  relayId: Id<'relays'>,
  now: number,
): Promise<void> {
  const row = await stampRow(ctx.db, relayId);
  if (row) await ctx.db.patch(row._id, { lastEvalAt: now });
  else await ctx.db.insert('relayEvalStamps', { relayId, lastEvalAt: now });
}

/** The last evaluation of an origin: its own stamp, else the suspicion's (an
 *  origin last evaluated before the stamp existed). Null = never evaluated. */
export async function lastEvalAtOf(
  db: DatabaseReader,
  relay: Pick<Doc<'relays'>, '_id' | 'suspicion'>,
): Promise<number | null> {
  const row = await stampRow(db, relay._id);
  return row?.lastEvalAt ?? relay.suspicion?.lastEvalAt ?? null;
}

/** Drop an origin's stamp (the origin is being removed). */
export async function deleteEvalStamp(ctx: MutationCtx, relayId: Id<'relays'>): Promise<void> {
  const row = await stampRow(ctx.db, relayId);
  if (row) await ctx.db.delete(row._id);
}
