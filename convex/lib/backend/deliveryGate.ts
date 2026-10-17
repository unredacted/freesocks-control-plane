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
import { fnv1a64Hex } from '../edges/registration';

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
  /**
   * What an activation run has enabled or published that members must not
   * see: every resource of a run that never committed (running, blocked,
   * under review, superseded, failed), minus what the committed set holds.
   * A superseded run's candidate stays isolated until it is released or a
   * later commit takes it over.
   */
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

const UNCOMMITTED_RUN = new Set(['running', 'blocked', 'review', 'superseded', 'failed']);

/** The gate for one node given its intent (null = unmanaged) and its activation runs. */
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
  const committed = intent.approved?.committed ?? empty;
  const hosts = new Set<string>();
  const edges = new Set<string>();
  for (const r of runs) {
    if (!UNCOMMITTED_RUN.has(r.state)) continue;
    for (const h of r.resources.hostUuids) if (!committed.hostUuids.includes(h)) hosts.add(h);
    for (const e of r.resources.edgeIds) if (!committed.edgeIds.includes(e)) edges.add(e);
  }
  const open = gateOpen(intent.delivery.disposition) && !intent.maintenance;
  return {
    state: open ? 'open' : 'blocked',
    gateVersion,
    committed,
    candidates: { hostUuids: [...hosts].sort(), edgeIds: [...edges].sort() },
    disposition: intent.delivery.disposition,
  };
}

export function isCandidateEdge(gate: NodeGate, edgeId: string): boolean {
  return gate.candidates.edgeIds.includes(edgeId);
}

/**
 * The token a render is stamped with; a route re-reads it after rendering and
 * re-renders on a move. It names the candidate set too: a candidate published
 * or released moves the token, so a body (or a mirror object) rendered under
 * the previous set is never kept under the new one.
 */
export function gateToken(gate: NodeGate): string {
  const c = gate.committed;
  const cand = gate.candidates;
  const set =
    cand.hostUuids.length + cand.edgeIds.length === 0
      ? '0'
      : fnv1a64Hex(`${cand.hostUuids.join(',')}|${cand.edgeIds.join(',')}`);
  return `${gate.gateVersion}:${c.hostUuids.length}:${c.edgeIds.length}:${set}`;
}
