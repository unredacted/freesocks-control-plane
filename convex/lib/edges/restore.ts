/**
 * Starting the persisted RESTORE workflow (`relays.restore`; driven by
 * convex/edgeRestore.ts). Shared by `relays.requestDelete` (purpose
 * `delete_relay`) and `edgeRestore.start`, and kept out of both so neither
 * imports the other.
 */
import { ConvexError } from 'convex/values';
import type { DatabaseReader, MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import { writeAuditLog } from '../audit';

export type RestorePurpose = 'cancel_setup' | 'release_requirement' | 'delete_relay';
export type RestorePhase = NonNullable<Doc<'relays'>['restore']>['phase'];

export const RESTORE_PHASES: readonly RestorePhase[] = [
  'freeze',
  'settle',
  'verify_fcp_raw',
  'release_binding',
  'restore',
  'verify_direct',
  'finish',
];

export function assertNoRestore(relay: Pick<Doc<'relays'>, 'restore'>): void {
  if (relay.restore)
    throw new ConvexError({
      code: 'edge.restore_in_progress',
      message: `a ${relay.restore.purpose.replace(/_/g, ' ')} restore is in progress on this relay (phase ${relay.restore.phase})`,
    });
}

/** Whether the relay ever hid a direct Host (a hide row exists, whatever its state). */
export async function hasHideRows(db: DatabaseReader, relayId: Id<'relays'>): Promise<boolean> {
  const row = await db
    .query('edgeHostHides')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .first();
  return !!row;
}

/**
 * Persist the workflow at its first phase. Refuses a second workflow
 * (`edge.restore_in_progress`) and a quarantined relay. Audited
 * `edge.relay.restore_started`.
 */
export async function startRestoreWorkflow(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
  opts: {
    purpose: RestorePurpose;
    actorAdminId?: Id<'adminUsers'>;
    force?: boolean;
    darkCohortKeys?: string[];
  },
): Promise<void> {
  assertNoRestore(relay);
  if (relay.quarantine)
    throw new ConvexError({
      code: 'edge.quarantined',
      message: 'Origin is quarantined; resolve it first',
    });
  if (relay.deleting)
    throw new ConvexError({ code: 'edge.deleting', message: 'Relay is being deleted' });
  const now = Date.now();
  await ctx.db.patch(relay._id, {
    restore: {
      purpose: opts.purpose,
      phase: 'freeze',
      startedAt: now,
      updatedAt: now,
      attempt: 0,
      darkCohortKeys: opts.darkCohortKeys ?? [],
      ...(opts.force !== undefined ? { force: opts.force } : {}),
      ...(opts.actorAdminId ? { actorAdminId: opts.actorAdminId } : {}),
    },
    updatedAt: now,
  });
  await writeAuditLog(ctx, {
    actorType: opts.actorAdminId ? 'admin' : 'system',
    actorId: opts.actorAdminId,
    action: 'edge.relay.restore_started',
    targetType: 'relay',
    targetId: relay._id,
    payload: { relaySlug: relay.slug, purpose: opts.purpose },
  });
}
