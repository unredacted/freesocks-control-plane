/**
 * Obligations: the rules for external side effects of the bootstrap
 * workflows (pure; the rows live in `panelObligations`). They follow the ops
 * ledger's rules (lib/backend/ops.ts): an obligation is persisted before the
 * call, an unresolved one is never retried and never released by the clock,
 * and a superseded owner generation never releases it.
 *
 * What is new here is settlement: when a late result finally arrives (the
 * profile create of generation A completing after generation B changed an
 * observation, a DNS record found by discovery), the outcome is reconciled
 * against what is wanted NOW, never cleaned up by rule.
 */
export type ObligationKind =
  | 'profile.create'
  | 'dns.record'
  | 'host'
  | 'node'
  | 'test_credential'
  | 'edge_publication'
  | 'mirror.withdraw'
  | 'mirror.replace'
  | 'machine_cleanup';

export type ObligationState = 'pending' | 'sent' | 'unresolved' | 'confirmed' | 'failed';
export type Ownership = 'created' | 'adopted' | 'shared';
export type ObligationVerb = 'create' | 'update' | 'delete';

export interface ObligationLike {
  kind: ObligationKind;
  identity: string;
  verb: ObligationVerb;
  ownership: Ownership;
  state: ObligationState;
  ownerGeneration: number;
}

/** What settlement decides for a resource an obligation produced or found. */
export type Settlement =
  /** The current generation still needs it: adopt and continue. */
  | { outcome: 'reuse' }
  /** Another live workflow references it: leave it alone. */
  | { outcome: 'retain'; reason: 'referenced' | 'shared' | 'adopted' | 'update' }
  /** Demonstrably unneeded, FCP created it and owns its destruction. */
  | { outcome: 'delete' };

/**
 * Reconcile a settled obligation's resource against current desired state.
 *
 * `needed`      the current generation still wants an object of this identity;
 * `referenced`  some other live workflow or row references the resource.
 */
export function settleResource(
  o: Pick<ObligationLike, 'kind' | 'verb' | 'ownership'>,
  current: { needed: boolean; referenced: boolean },
): Settlement {
  if (current.needed) return { outcome: 'reuse' };
  // An update never implies permission to delete what it updated.
  if (o.verb !== 'create') return { outcome: 'retain', reason: 'update' };
  if (o.ownership === 'shared') return { outcome: 'retain', reason: 'shared' };
  if (o.ownership === 'adopted') return { outcome: 'retain', reason: 'adopted' };
  if (current.referenced) return { outcome: 'retain', reason: 'referenced' };
  return { outcome: 'delete' };
}

/** Whether an obligation still blocks work on its identity. */
export function blocksIdentity(o: Pick<ObligationLike, 'state'>): boolean {
  return o.state === 'pending' || o.state === 'sent' || o.state === 'unresolved';
}

/**
 * A new attempt on an identity is admitted only when no obligation on that
 * identity is outstanding, whatever generation owns it. Returns the blocking
 * obligation's index or -1.
 */
export function blockingObligation(rows: readonly Pick<ObligationLike, 'state'>[]): number {
  return rows.findIndex(blocksIdentity);
}

/**
 * What a lease expiry may do with an outstanding obligation: only resume the
 * SAME attempt's discovery. Never a second create, never an opposing delete.
 */
export function onLeaseExpiry(o: Pick<ObligationLike, 'state'>): 'discover' | 'nothing' {
  return o.state === 'sent' || o.state === 'unresolved' ? 'discover' : 'nothing';
}

/** Whether a callback for `ownerGeneration` may advance the CURRENT workflow generation. */
export function callbackAdvancesCurrent(
  o: Pick<ObligationLike, 'ownerGeneration'>,
  current: number,
) {
  return o.ownerGeneration === current;
}
