/**
 * Audit log writes (ported from services/audit.ts). Insert-only. Called from
 * actions via ctx.runMutation; in-mutation callers use `writeAuditLog` from
 * lib/audit directly (Convex forbids mutation->mutation calls). Both paths run
 * the payload through the same per-action allowlist (M3, see lib/audit.ts).
 */
import { internalMutation } from './_generated/server';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

export const record = internalMutation({
  args: {
    actorType: v.union(
      v.literal('system'),
      v.literal('admin'),
      v.literal('member'),
      v.literal('anonymous'),
      v.literal('webhook'),
    ),
    action: v.string(),
    actorId: v.optional(v.string()),
    targetType: v.optional(v.string()),
    targetId: v.optional(v.string()),
    payload: v.optional(v.any()),
    requestId: v.optional(v.string()),
    ipHash: v.optional(v.string()),
  },
  handler: async (ctx, entry) => {
    await writeAuditLog(ctx, entry);
    return null;
  },
});
