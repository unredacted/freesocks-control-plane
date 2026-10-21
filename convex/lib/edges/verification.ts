/**
 * Configuration-bound endpoint verification (docs/edges.md § "Publication").
 *
 * An L4 edge cannot be proven server-side: nothing in this stack opens an
 * authenticated REALITY session, and backend online bits do not identify the
 * path a member used. So an L4 endpoint is `verified` ONLY by a human, per
 * endpoint, against the exact configuration they were shown:
 *
 *   {endpoint, listenerKey, listenerRevision, configHash}
 *
 * `configHash` covers the listener's own idempotency hash, the edge's template
 * hash and its addresses / forwarding listeners, so a re-addressed edge or a
 * materially changed listener returns the endpoint to "needs a test" without
 * anybody clearing a record. On an ENROLLED node it also covers the node's
 * REALITY authentication revision (`panelNodeIntents.authRevision`, the keyed
 * digest of the transport's key, short ids and clock bounds): a key change
 * means no real client has proven the new key through this edge, so the tick
 * no longer counts. The digest is folded into the hash, never sent on its own,
 * so the binding a confirmation echoes keeps its shape. Callers resolve it
 * with `lib/edges/verificationContext.ts` (null for every other origin, which
 * leaves the hash exactly as before). The record's EXISTENCE proves nothing:
 * `verificationCurrent` is what the publication gate reads.
 *
 * Pure: no db, no clock. The hash is the repo's canonical-JSON FNV-1a token
 * (the same primitive `listenerConfigHash` / `templateHashOf` use); it is an
 * equality token, not a security primitive.
 */
import { fnv1a64Hex } from './registration';
import type { VerificationStaleReason } from '../../../src/shared/contracts/edgeCodes';

export interface VerificationEdgeLike {
  layer?: 'l4' | 'l7' | null;
  templateHash?: string | null;
  addresses: { v4?: string | null; v6?: string | null; hostname?: string | null };
  /**
   * An address family a describe reported after the edge's endpoint was
   * confirmed (`edges.learnedAddresses`): held apart, so the confirmation
   * stands and the address is not served until it is tested itself.
   */
  learnedAddresses?: { v4?: string | null; v6?: string | null } | null;
  listeners: ReadonlyArray<{
    edgePort: number;
    originAddress: string;
    originPort: number;
    transport?: 'tcp' | 'udp' | null;
  }>;
  verification?: VerificationRecord | null;
}

export interface VerificationListenerLike {
  listenerKey: string;
  revision: number;
  configHash: string;
  /**
   * The enrolled node's REALITY auth revision, or null (not an enrolled node,
   * or none derived yet). Required so no caller can forget it: resolve it
   * with `verificationListenerOf` (lib/edges/verificationContext.ts).
   */
  authRevision: string | null;
}

export interface VerificationRecord {
  rung: 'partial' | 'verified';
  by: 'admin' | 'system';
  at: number;
  endpoint: string;
  listenerKey: string;
  listenerRevision: number;
  configHash: string;
  /** `probe` = the system's `partial` rung from probe evidence (lib/edges/verifyRung.ts). */
  method: 'test_link' | 'named_connection' | 'l7_proof' | 'probe';
  /** The enrolled node's auth revision it was taken under (database only; says why it went stale). */
  authRevision?: string;
}

/** What a confirmation must echo back: the binding the operator was shown. */
export interface VerificationBinding {
  endpoint: string;
  listenerKey: string;
  listenerRevision: number;
  configHash: string;
}

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

/**
 * The endpoint an operator connects to: the IPv4 literal (what every member
 * receives) with the FIRST forwarding listener's edge port, else the IPv6
 * literal bracketed, else the fronted hostname. Null when the edge has no
 * address yet.
 */
export function verificationEndpoint(edge: VerificationEdgeLike): string | null {
  const port = edge.listeners[0]?.edgePort ?? 443;
  if (edge.addresses.v4) return `${edge.addresses.v4}:${port}`;
  if (edge.addresses.v6) return `[${edge.addresses.v6}]:${port}`;
  if (edge.addresses.hostname) return `${edge.addresses.hostname}:${port}`;
  return null;
}

/**
 * Whether RETIRING a server name leaves an operator's endpoint confirmation
 * standing. True for a REALITY listener only.
 *
 * The confirmation proves "this endpoint forwards to this transport, with this
 * key material, over this path". On REALITY the names are an allowlist the
 * node checks: taking one away changes neither the path nor the keys, and the
 * names that remain are exactly the ones that were accepted when the test was
 * made. So the retire bumps `namesRevision` (and the publication epoch) and
 * leaves `revision` alone. Without this every retire would stop the listener's
 * L4 edges rendering until a human retested them, which under edge-required
 * delivery is an outage caused by reacting to a block.
 *
 * Deliberately NOT extended to: a TLS listener (its names decide certificate
 * coverage, and an L7 front's proof binds to them), or ADDING or reactivating
 * a name by any path that has not proven the node accepts it. Those remain
 * `revision` bumps.
 */
export function nameRetireKeepsVerification(listener: { security: string }): boolean {
  return listener.security === 'reality';
}

/**
 * The configuration token a confirmation binds to. Names are NOT part of it
 * beyond what the listener hash already carries. A name change is caught by
 * the revision compare instead, except the one case above.
 */
export function verificationConfigHash(input: {
  listenerConfigHash: string;
  templateHash: string | null | undefined;
  addresses: VerificationEdgeLike['addresses'];
  listeners: VerificationEdgeLike['listeners'];
  /** An enrolled node's auth revision; absent / null leaves the hash as it always was. */
  authRevision?: string | null;
}): string {
  return fnv1a64Hex(
    canonicalJson({
      // Present only for an enrolled node (canonicalJson drops `undefined`).
      authRevision: input.authRevision ?? undefined,
      listenerConfigHash: input.listenerConfigHash,
      templateHash: input.templateHash ?? null,
      addresses: {
        v4: input.addresses.v4 ?? null,
        v6: input.addresses.v6 ?? null,
        hostname: input.addresses.hostname ?? null,
      },
      listeners: input.listeners.map((l) => ({
        edgePort: l.edgePort,
        originAddress: l.originAddress,
        originPort: l.originPort,
        transport: l.transport ?? 'tcp',
      })),
    }),
  );
}

/** The binding a client must display and echo back, or null when the edge has no address. */
export function verificationBinding(
  edge: VerificationEdgeLike,
  listener: VerificationListenerLike,
): VerificationBinding | null {
  const endpoint = verificationEndpoint(edge);
  if (!endpoint) return null;
  return {
    endpoint,
    listenerKey: listener.listenerKey,
    listenerRevision: listener.revision,
    configHash: verificationConfigHash({
      listenerConfigHash: listener.configHash,
      templateHash: edge.templateHash,
      addresses: edge.addresses,
      listeners: edge.listeners,
      authRevision: listener.authRevision,
    }),
  };
}

/** Whether an echoed binding is exactly the one the live rows derive now. */
export function bindingMatches(
  current: VerificationBinding | null,
  echoed: VerificationBinding,
): boolean {
  return (
    !!current &&
    current.endpoint === echoed.endpoint &&
    current.listenerKey === echoed.listenerKey &&
    current.listenerRevision === echoed.listenerRevision &&
    current.configHash === echoed.configHash
  );
}

/**
 * The publication gate's question: does the edge hold a `verified` record
 * taken against the listener's CURRENT revision and the edge's CURRENT
 * configuration? A `partial` record, a stale revision or a moved address all
 * answer false.
 */
export function verificationCurrent(
  edge: VerificationEdgeLike,
  listener: VerificationListenerLike,
): boolean {
  const rec = edge.verification;
  if (!rec || rec.rung !== 'verified') return false;
  return recordMatchesBinding(rec, verificationBinding(edge, listener));
}

/** Whether a record was taken against exactly the binding the live rows derive now. */
export function recordMatchesBinding(
  rec: Pick<VerificationRecord, 'endpoint' | 'listenerKey' | 'listenerRevision' | 'configHash'>,
  current: VerificationBinding | null,
): boolean {
  return (
    !!current &&
    rec.listenerKey === current.listenerKey &&
    rec.listenerRevision === current.listenerRevision &&
    rec.configHash === current.configHash &&
    rec.endpoint === current.endpoint
  );
}

/** A record exists but no longer describes the live configuration (a retest is due). */
export function verificationStale(
  edge: VerificationEdgeLike,
  listener: VerificationListenerLike,
): boolean {
  const rec = edge.verification;
  if (!rec || rec.rung !== 'verified') return false;
  return !verificationCurrent(edge, listener);
}

/**
 * Why a `verified` record no longer counts, or null while it does (or there
 * is none): `reality_key_changed` when the only thing that moved is the
 * enrolled node's REALITY authentication (its key, short ids or clock bounds:
 * no client has proven the new key through this endpoint), else
 * `verification_stale` (the address, the listener or its configuration).
 */
export function verificationStaleReason(
  edge: VerificationEdgeLike,
  listener: VerificationListenerLike,
): VerificationStaleReason | null {
  if (!verificationStale(edge, listener)) return null;
  const rec = edge.verification!;
  const recorded = rec.authRevision ?? null;
  if (recorded !== listener.authRevision) {
    const underRecordedKey = verificationBinding(edge, { ...listener, authRevision: recorded });
    if (recordMatchesBinding(rec, underRecordedKey)) return 'reality_key_changed';
  }
  return 'verification_stale';
}

/**
 * The edge as it would be once its learned address is served too: what a test
 * of that address binds to, and what the confirmation makes it.
 */
export function withLearnedAddresses<E extends VerificationEdgeLike>(edge: E): E {
  const l = edge.learnedAddresses;
  if (!l || (!l.v4 && !l.v6)) return edge;
  return {
    ...edge,
    addresses: {
      ...edge.addresses,
      ...(l.v4 ? { v4: l.v4 } : {}),
      ...(l.v6 ? { v6: l.v6 } : {}),
    },
  };
}

/** The learned address's endpoint (the one to test), or null when nothing is held. */
export function learnedEndpoint(edge: VerificationEdgeLike): string | null {
  const l = edge.learnedAddresses;
  const port = edge.listeners[0]?.edgePort ?? 443;
  if (l?.v6) return `[${l.v6}]:${port}`;
  if (l?.v4) return `${l.v4}:${port}`;
  return null;
}

/**
 * The binding a test of the learned address shows and echoes: that address as
 * the endpoint, the configuration with it served. Null when nothing is held.
 */
export function learnedBinding(
  edge: VerificationEdgeLike,
  listener: VerificationListenerLike,
): VerificationBinding | null {
  const endpoint = learnedEndpoint(edge);
  if (!endpoint) return null;
  const all = withLearnedAddresses(edge);
  return {
    endpoint,
    listenerKey: listener.listenerKey,
    listenerRevision: listener.revision,
    configHash: verificationConfigHash({
      listenerConfigHash: listener.configHash,
      templateHash: all.templateHash,
      addresses: all.addresses,
      listeners: all.listeners,
      authRevision: listener.authRevision,
    }),
  };
}

/**
 * What an ACTIVE describe's addresses do to an L4 edge whose endpoint a human
 * confirmed: a family the edge did not have is held apart (`learned`), never
 * served or hashed until its own test, so the confirmation of what IS served
 * stands (a provider reporting a second VIP must not stop the first one
 * rendering). Anything else (a changed or lost address) applies as before.
 * Pure; `next` is what the describe would apply without the hold.
 */
export function holdLearnedAddresses(
  edge: Pick<VerificationEdgeLike, 'layer' | 'addresses' | 'verification' | 'learnedAddresses'>,
  next: { v4?: string; v6?: string; hostname?: string },
): {
  addresses: { v4?: string; v6?: string; hostname?: string };
  learned: { v4?: string; v6?: string } | undefined;
} {
  const confirmed = needsEndpointVerification(edge) && edge.verification?.rung === 'verified';
  if (!confirmed) return { addresses: next, learned: undefined };
  const held4 = !edge.addresses.v4 && next.v4 ? next.v4 : undefined;
  const held6 = !edge.addresses.v6 && next.v6 ? next.v6 : undefined;
  if (!held4 && !held6) return { addresses: next, learned: undefined };
  return {
    addresses: {
      ...next,
      ...(held4 ? { v4: undefined } : {}),
      ...(held6 ? { v6: undefined } : {}),
    },
    learned: { ...(held4 ? { v4: held4 } : {}), ...(held6 ? { v6: held6 } : {}) },
  };
}

/** L4 edges need the human tick; L7 edges are verified by their authenticated proof. */
export function needsEndpointVerification(edge: Pick<VerificationEdgeLike, 'layer'>): boolean {
  return (edge.layer ?? 'l4') !== 'l7';
}
