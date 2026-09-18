// STUB: merged with agent H (convex/edgeRestore.ts). Signature per the PR A2
// contract; refuses so an accidental call fails loudly. The setup run machine
// reaches it only through its stage-ops seam (edgeSetupRuns.__setStageOpsForTests).
import { ConvexError, v } from 'convex/values';
import { internalMutation } from './_generated/server';

export const start = internalMutation({
  args: {
    relayId: v.id('relays'),
    purpose: v.union(
      v.literal('cancel_setup'),
      v.literal('release_requirement'),
      v.literal('delete_relay'),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (): Promise<{ ok: true }> => {
    throw new ConvexError({ code: 'edge.not_available', message: 'edgeRestore is a stub' });
  },
});
