/**
 * Shared relay guards and pool-side helpers used by relays.ts,
 * relayListeners.ts, edges.ts and the rotation machine. Kept out of relays.ts
 * so the listener module and the relay module can import each other's
 * public surface without a cycle.
 */
import { ConvexError } from 'convex/values';
import type { DatabaseReader, MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import { internal } from '../../_generated/api';
import { isTerminalPhase } from './rotation';
import { EDGE_LIVE_STATUSES, LIVE_EDGE_SCAN_LIMIT } from './pool';

/**
 * Every NON-DESTROYED edge of a relay, read through the `(relayId, status)`
 * index one status at a time and bounded per status.
 */
export async function liveEdgesOfRelay(
  db: DatabaseReader,
  relayId: Id<'relays'>,
): Promise<Doc<'edges'>[]> {
  const out: Doc<'edges'>[] = [];
  for (const status of EDGE_LIVE_STATUSES) {
    const rows = await db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', relayId).eq('status', status))
      .take(LIVE_EDGE_SCAN_LIMIT);
    out.push(...rows);
  }
  return out;
}

/** Nothing bypasses a quarantine (docs/edges.md): the operator resolves it first. */
export function assertNotQuarantined(origin: Doc<'relays'>) {
  if (origin.quarantine) {
    throw new ConvexError({
      code: 'edge.quarantined',
      message: 'Origin is quarantined; resolve it first',
    });
  }
}

/**
 * The shared gate for every pool / edge / listener write that is NOT the
 * running rotation itself: refused while the origin is quarantined, a
 * rotation is in flight, or a restore workflow runs (its raw-body checks
 * assume the pool and the listeners hold still; `edge.restore_in_progress`).
 */
export async function assertNoRotationOrQuarantine(db: DatabaseReader, origin: Doc<'relays'>) {
  assertNotQuarantined(origin);
  if (origin.restore) {
    throw new ConvexError({
      code: 'edge.restore_in_progress',
      message: 'A restore workflow is running on this origin; wait for it to finish',
    });
  }
  if (origin.activeRotationId) {
    const rot = await db.get(origin.activeRotationId);
    if (rot && !isTerminalPhase(rot.phase)) {
      throw new ConvexError({
        code: 'edge.rotation_running',
        message: 'A rotation is running on this origin; wait for it to finish',
      });
    }
  }
}

/** Members must stop receiving an edge that left the pool: refresh the S3 mirrors once. */
export async function scheduleMirrorRefresh(ctx: MutationCtx) {
  await ctx.scheduler.runAfter(0, internal.storage.refreshActiveMirrors, {});
}

/**
 * A change that alters what subscribers should receive: bump the relay's
 * publication epoch (the /sub cache token + assignment) and refresh mirrors.
 */
export async function bumpEpochAndRefresh(ctx: MutationCtx, origin: Doc<'relays'>) {
  await ctx.db.patch(origin._id, {
    publicationEpoch: origin.publicationEpoch + 1,
    updatedAt: Date.now(),
  });
  await scheduleMirrorRefresh(ctx);
}
