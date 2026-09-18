// STUB: merged with agent H (convex/lib/edges/cohorts.ts). Signatures per the
// PR A2 contract. The stub reports NO cohorts (an empty node) so nothing here
// walks the subscriptions table; the setup plan reads membership only through
// the stage-ops seam the tests replace, and agent H's version supplies the real
// paginated walk at merge.
import type { DatabaseReader } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';

export interface Cohort {
  key: string;
  placement: string | null;
  subscriptionId: Id<'subscriptions'>;
  backendServerId: Id<'backendServers'>;
  nodeName?: string;
}

export interface CohortsResult {
  cohorts: Cohort[];
  total: number;
}

export async function cohortsForOrigin(
  _ctx: { db: DatabaseReader },
  _origin: { backendServerId: Id<'backendServers'>; nodeName?: string },
): Promise<CohortsResult> {
  return { cohorts: [], total: 0 };
}

export async function cohortsForRelay(
  ctx: { db: DatabaseReader },
  relay: Pick<Doc<'relays'>, 'backendServerId' | 'nodeName'>,
): Promise<CohortsResult> {
  if (!relay.backendServerId) return { cohorts: [], total: 0 };
  return cohortsForOrigin(ctx, {
    backendServerId: relay.backendServerId,
    nodeName: relay.nodeName,
  });
}
