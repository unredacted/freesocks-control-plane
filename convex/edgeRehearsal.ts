// STUB: merged with agent R2 (convex/edgeRehearsal.ts). Signatures per the PR A2
// contract; both refuse so an accidental call fails loudly. The setup run
// machine reaches them only through its stage-ops seam
// (edgeSetupRuns.__setStageOpsForTests).
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import type { SetupVector } from './lib/edges/setupRuns';

export interface RehearsalResult {
  ok: boolean;
  failures: Array<{ cohortKey: string; format: string; reason: string }>;
  familiesDisabled: string[];
  proofsExpired: string[];
  vector: SetupVector;
  hostsObservation: { listingHash: string; observedAt: number; version: number };
}

const stub = () =>
  new ConvexError({ code: 'edge.not_available', message: 'edgeRehearsal is a stub' });

export const run = internalAction({
  args: { relayId: v.id('relays'), darkCohortKeys: v.array(v.string()) },
  handler: async (): Promise<RehearsalResult> => {
    throw stub();
  },
});

export const vectorNow = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (): Promise<SetupVector> => {
    throw stub();
  },
});
