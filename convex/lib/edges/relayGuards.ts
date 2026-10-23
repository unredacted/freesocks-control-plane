/**
 * Shared origin guards and pool-side helpers used by origins.ts,
 * relayListeners.ts, edges.ts and the rotation machine. Kept out of origins.ts
 * so the listener module and the origin module can import each other's
 * public surface without a cycle.
 */
import { ConvexError } from 'convex/values';
import type { DatabaseReader, MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import { internal } from '../../_generated/api';
import { isTerminalPhase } from './rotation';
import { isTerminalRunState } from './setupRuns';
import { EDGE_LIVE_STATUSES, LIVE_EDGE_SCAN_LIMIT } from './pool';

/**
 * Every NON-DESTROYED edge of an origin, read through the `(relayId, status)`
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

/**
 * While a guided setup run (first protection or re-protect) is still running
 * on an origin, only its own rotations touch the pool (`startRotation` refuses
 * every other start). The operator's direct pool writes (publish / unpublish
 * by hand, an import that publishes, a rebalance) are refused the same way, so
 * a run never loses the committed address members are served through, or the
 * slot it made for its new one, under its feet. An origin a FINISHED run left
 * owned (a failed or cancelled first protection) stays open to them: publishing
 * by hand there is the recovery `require-edges` documents.
 */
export async function assertNoRunningSetup(db: DatabaseReader, origin: Doc<'relays'>) {
  if (await setupRunLiveOn(db, origin))
    throw new ConvexError({
      code: 'edge.setup_owned',
      message: 'A guided setup run is working on this origin; let it finish or cancel it',
    });
}

/** Whether a guided setup run is working on a setup-owned origin now (false when none owns it). */
export async function setupRunLiveOn(
  db: DatabaseReader,
  origin: Pick<Doc<'relays'>, 'setupOwned' | 'backendServerId' | 'nodeName'>,
): Promise<boolean> {
  if (!origin.setupOwned || !origin.backendServerId || !origin.nodeName) return false;
  const runs = await db
    .query('edgeSetupRuns')
    .withIndex('by_origin', (q) =>
      q.eq('backendServerId', origin.backendServerId!).eq('nodeName', origin.nodeName!),
    )
    .collect(); // a node's runs: operator-scale
  return runs.some((r) => !isTerminalRunState(r.state));
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
 * Server management claims an origin (`origin:<id>` in `panelClaims`) while it
 * changes the config profile one of the origin's listeners is bound to, and
 * holds the claim until the listeners are back in step. Every workflow that
 * moves the pool, the listeners or the Hosts refuses meanwhile: a rotation
 * started between the backend write and the listener update would snapshot a
 * listener that is about to change under it.
 */
export async function assertNoRelayPanelClaim(db: DatabaseReader, origin: Doc<'relays'>) {
  if (!origin.backendServerId) return;
  // A node rename moves this origin's node name and Host remarks step by step.
  if (origin.renaming)
    throw new ConvexError({
      code: 'edge.panel_op_running',
      message: 'This node is being renamed; wait for it to finish',
    });
  const claim = await db
    .query('panelClaims')
    .withIndex('by_server_key', (q) =>
      q.eq('backendServerId', origin.backendServerId!).eq('key', `relay:${origin._id}`),
    )
    .unique();
  if (claim)
    throw new ConvexError({
      code: 'edge.panel_op_running',
      message: 'A server change is updating this node; wait for it to finish',
    });
}

/**
 * The shared gate for every pool / edge / listener write that is NOT the
 * running rotation itself: refused while the origin is quarantined, a
 * rotation is in flight, or a restore workflow runs (its raw-body checks
 * assume the pool and the listeners hold still; `edge.restore_in_progress`).
 */
export async function assertNoRotationOrQuarantine(db: DatabaseReader, origin: Doc<'relays'>) {
  assertNotQuarantined(origin);
  await assertNoRelayPanelClaim(db, origin);
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

/**
 * Members must stop receiving what changed (an edge left the pool, a node was
 * closed, a binding claimed or released): every mirrored key is rendered again
 * in ONE full pass from the first key to the last (`storage.drainMirrors`),
 * not the six-hourly sweep's window of a few thousand keys. Requests while a
 * pass runs coalesce into one more round of it.
 */
export async function scheduleMirrorRefresh(ctx: MutationCtx) {
  await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, { cursor: null, pass: 'start' });
}

/**
 * A change that alters what subscribers should receive: bump the origin's
 * publication epoch (the /sub cache token + assignment) and refresh mirrors.
 */
export async function bumpEpochAndRefresh(ctx: MutationCtx, origin: Doc<'relays'>) {
  await ctx.db.patch(origin._id, {
    publicationEpoch: origin.publicationEpoch + 1,
    updatedAt: Date.now(),
  });
  await scheduleMirrorRefresh(ctx);
}
