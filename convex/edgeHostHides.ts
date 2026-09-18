// STUB: merged with agent H (convex/edgeHostHides.ts). Signatures per the PR A2
// contract; every handler refuses so an accidental call fails loudly. The setup
// run machine reaches these only through its stage-ops seam, which the tests
// replace (edgeSetupRuns.__setStageOpsForTests).
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';

const stub = () =>
  new ConvexError({ code: 'edge.not_available', message: 'edgeHostHides is a stub' });

export interface HideResult {
  state: 'confirmed' | 'pending' | 'failed';
  hidden: number;
  pending: number;
  failed: number;
  reviewChanged: Array<{ uuid: string; remark: string }>;
}

export interface HideStatus {
  outstanding: number;
  confirmed: number;
  unresolved: number;
  rows: Array<{ hostUuid: string; intent: string; state: string }>;
}

export interface HostsObservation {
  listingHash: string;
  observedAt: number;
  direct: { covered: number; uncovered: number };
}

export const hide = internalAction({
  args: {
    relayId: v.id('relays'),
    runId: v.optional(v.id('edgeSetupRuns')),
    approvedUuids: v.array(v.string()),
  },
  handler: async (): Promise<HideResult> => {
    throw stub();
  },
});

export const status = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (): Promise<HideStatus> => {
    throw stub();
  },
});

export const observe = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (): Promise<HostsObservation> => {
    throw stub();
  },
});

export const settle = internalAction({
  args: { relayId: v.optional(v.id('relays')) },
  handler: async (): Promise<null> => {
    throw stub();
  },
});
