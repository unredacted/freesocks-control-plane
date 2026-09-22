/**
 * The node delivery gate (pure half; `convex/nodeIntents.ts` reads the rows).
 * What keeps members away from a node that is not live is this gate, not the
 * absence of Hosts or edges: during activation both exist as CANDIDATE
 * resources. Every render carries the gate version and the committed
 * resource-set hash it was rendered under, and a route re-reads them after
 * rendering: content rendered under an older policy is never attached to a
 * newer token (docs/servers.md "Node lifecycle").
 */
import { gateOpen, type Disposition } from './activation';

export interface GateResources {
  hostUuids: string[];
  edgeIds: string[];
}

export interface NodeGate {
  state: 'open' | 'blocked';
  /** The backend-wide gate version (bumped on any disposition or resource-set change). */
  gateVersion: number;
  /** What the node is served with when open; empty when unmanaged. */
  committed: GateResources;
  /** What an activating run has enabled or published and members must not see yet. */
  candidates: GateResources;
  disposition: Disposition | null;
}

export interface GateIntentLike {
  delivery: { disposition: Disposition };
  approved?: { committed: GateResources } | null;
  maintenance?: unknown | null;
}

export interface GateRunLike {
  state: string;
  resources: GateResources;
}

/** The gate for one node given its intent (null = unmanaged) and its activating runs. */
export function nodeGateOf(
  intent: GateIntentLike | null,
  runs: readonly GateRunLike[],
  gateVersion: number,
  unmanagedClosed: boolean,
): NodeGate {
  const empty = { hostUuids: [], edgeIds: [] };
  if (!intent)
    return {
      state: unmanagedClosed ? 'blocked' : 'open',
      gateVersion,
      committed: empty,
      candidates: empty,
      disposition: null,
    };
  const candidates: GateResources = { hostUuids: [], edgeIds: [] };
  for (const r of runs) {
    if (r.state !== 'running' && r.state !== 'blocked' && r.state !== 'review') continue;
    candidates.hostUuids.push(...r.resources.hostUuids);
    candidates.edgeIds.push(...r.resources.edgeIds);
  }
  const open = gateOpen(intent.delivery.disposition) && !intent.maintenance;
  return {
    state: open ? 'open' : 'blocked',
    gateVersion,
    committed: intent.approved?.committed ?? empty,
    candidates,
    disposition: intent.delivery.disposition,
  };
}

/** Whether a body entry belongs to a candidate resource and must be dropped from member bodies. */
export function isCandidateHost(gate: NodeGate, hostUuid: string | null | undefined): boolean {
  return !!hostUuid && gate.candidates.hostUuids.includes(hostUuid);
}

export function isCandidateEdge(gate: NodeGate, edgeId: string): boolean {
  return gate.candidates.edgeIds.includes(edgeId);
}

/** The token a render is stamped with; a route re-reads it after rendering and re-renders on a move. */
export function gateToken(gate: NodeGate): string {
  const c = gate.committed;
  return `${gate.gateVersion}:${c.hostUuids.length}:${c.edgeIds.length}`;
}
