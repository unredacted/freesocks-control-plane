// STUB: merged with agent R2 (convex/edgeTestLinks.ts). Signature per the PR A2
// contract; refuses so an accidental call fails loudly. The setup run machine
// reaches it only through its stage-ops seam (edgeSetupRuns.__setStageOpsForTests).
import { ConvexError, v } from 'convex/values';
import { internalAction } from './_generated/server';

export interface TestLink {
  link: string;
  format: 'links';
  binding: {
    edgeId: string;
    endpoint: string;
    listenerRevision: number;
    configHash: string;
    issuedAt: number;
  };
}

export const build = internalAction({
  args: { edgeId: v.id('edges') },
  handler: async (): Promise<TestLink> => {
    throw new ConvexError({ code: 'edge.not_available', message: 'edgeTestLinks is a stub' });
  },
});
