/**
 * Obligations: the external side effects of the bootstrap workflows (the rows
 * live in `backendObligations`). They follow the ops ledger's rules
 * (lib/backend/ops.ts): an obligation is persisted before the call, an
 * unresolved one is never retried and never released by the clock, and a
 * superseded owner generation never releases it. A late result is settled by
 * the owning workflow's own discovery against what it wants NOW (the origin
 * DNS record by name and marker), never cleaned up by rule.
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

/** Whether an obligation still blocks work on its identity. */
export function blocksIdentity(o: Pick<ObligationLike, 'state'>): boolean {
  return o.state === 'pending' || o.state === 'sent' || o.state === 'unresolved';
}
