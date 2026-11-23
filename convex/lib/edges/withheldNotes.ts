/**
 * When member renders last left entries out on an origin (`relayWithheldNotes`,
 * one row per origin; edgeHostHides.noteWithheld). Kept off the `relays` row:
 * the note can move once a minute while renders keep withholding, and every
 * write to a `relays` row both drops the cached queries that read it (the
 * delivery route's render context among them) and collides with the other
 * writers of that row. Same pattern as `relayEvalStamps` (lib/edges/evalStamps.ts).
 *
 * Reads fall back to the legacy `relays.withheldEntries` for an origin noted
 * before this table existed; nothing writes that field any more.
 */
import type { DatabaseReader, MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';

export interface WithheldNote {
  at: number;
  since: number;
  count: number;
  remarks: string[];
}

async function noteRow(db: DatabaseReader, relayId: Id<'relays'>) {
  return db
    .query('relayWithheldNotes')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .unique();
}

/** The origin's own note row, without the legacy fallback. */
export async function ownWithheldNote(
  db: DatabaseReader,
  relayId: Id<'relays'>,
): Promise<WithheldNote | null> {
  const row = await noteRow(db, relayId);
  return row ? { at: row.at, since: row.since, count: row.count, remarks: row.remarks } : null;
}

/** The origin's latest note: its own row, else the legacy field. Null = never noted. */
export async function withheldNoteOf(
  db: DatabaseReader,
  relay: Pick<Doc<'relays'>, '_id' | 'withheldEntries'>,
): Promise<WithheldNote | null> {
  return (await ownWithheldNote(db, relay._id)) ?? relay.withheldEntries ?? null;
}

export async function writeWithheldNote(
  ctx: MutationCtx,
  relayId: Id<'relays'>,
  note: WithheldNote,
): Promise<void> {
  const row = await noteRow(ctx.db, relayId);
  if (row) await ctx.db.patch(row._id, note);
  else await ctx.db.insert('relayWithheldNotes', { relayId, ...note });
}

/** Drop an origin's note (the origin is being removed). */
export async function deleteWithheldNote(ctx: MutationCtx, relayId: Id<'relays'>): Promise<void> {
  const row = await noteRow(ctx.db, relayId);
  if (row) await ctx.db.delete(row._id);
}
