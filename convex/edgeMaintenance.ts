/**
 * Edge maintenance switch (lib/edges/maintenance.ts): freeze admits no NEW edge
 * work while every completion path keeps running. Used by the reset drain
 * (seedEdgesReset.ts) and, later, as the operator's "pause new work" switch.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { writeAuditLog } from './lib/audit';
import { readMaintenance, writeMaintenance } from './lib/edges/maintenance';

export const state = internalQuery({
  args: {},
  handler: (ctx) => readMaintenance(ctx.db),
});

export const freeze = internalMutation({
  args: { reason: v.optional(v.string()), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { reason, actorAdminId }) => {
    const current = await readMaintenance(ctx.db);
    if (current.frozen) return current;
    const next = await writeMaintenance(ctx.db, {
      frozen: true,
      since: Date.now(),
      reason: reason?.slice(0, 200) ?? null,
    });
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'admin.edge.maintenance',
      targetType: 'app_state',
      payload: { frozen: true, reason: next.reason ?? undefined },
    });
    return next;
  },
});

export const thaw = internalMutation({
  args: { actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { actorAdminId }) => {
    const current = await readMaintenance(ctx.db);
    if (!current.frozen) return current;
    const next = await writeMaintenance(ctx.db, { frozen: false, since: null, reason: null });
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'admin.edge.maintenance',
      targetType: 'app_state',
      payload: { frozen: false },
    });
    return next;
  },
});
