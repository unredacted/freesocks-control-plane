/**
 * Configuration-bound endpoint verification (docs/edges.md § "Publication").
 *
 * An L4 edge cannot be proven server-side: nothing in this stack opens an
 * authenticated REALITY session, and panel online bits do not identify the
 * path a member used. So an L4 endpoint is `verified` ONLY by a human, per
 * endpoint, against the exact configuration they were shown:
 *
 *   {endpoint, listenerKey, listenerRevision, configHash}
 *
 * `configHash` covers the listener's own idempotency hash, the edge's template
 * hash and its addresses / forwarding listeners, so a re-addressed edge or a
 * materially changed listener returns the endpoint to "needs a test" without
 * anybody clearing a record. The record's EXISTENCE proves nothing:
 * `verificationCurrent` is what the publication gate reads.
 *
 * Pure: no db, no clock. The hash is the repo's canonical-JSON FNV-1a token
 * (the same primitive `listenerConfigHash` / `templateHashOf` use); it is an
 * equality token, not a security primitive.
 */
import { fnv1a64Hex } from './registration';

export interface VerificationEdgeLike {
  layer?: 'l4' | 'l7' | null;
  templateHash?: string | null;
  addresses: { v4?: string | null; v6?: string | null; hostname?: string | null };
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
}

export interface VerificationRecord {
  rung: 'partial' | 'verified';
  by: 'admin' | 'system';
  at: number;
  endpoint: string;
  listenerKey: string;
  listenerRevision: number;
  configHash: string;
  method: 'test_link' | 'named_connection' | 'l7_proof';
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
 * The configuration token a confirmation binds to. Names are NOT part of it
 * beyond what the listener hash already carries (a name retire is a listener
 * revision bump, caught by the revision compare).
 */
export function verificationConfigHash(input: {
  listenerConfigHash: string;
  templateHash: string | null | undefined;
  addresses: VerificationEdgeLike['addresses'];
  listeners: VerificationEdgeLike['listeners'];
}): string {
  return fnv1a64Hex(
    canonicalJson({
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
  const current = verificationBinding(edge, listener);
  if (!current) return false;
  return (
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

/** L4 edges need the human tick; L7 edges are verified by their authenticated proof. */
export function needsEndpointVerification(edge: Pick<VerificationEdgeLike, 'layer'>): boolean {
  return (edge.layer ?? 'l4') !== 'l7';
}
