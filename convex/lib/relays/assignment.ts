/**
 * Subscriber → endpoint ASSIGNMENT for relay origins (pure, deterministic).
 *
 * Inputs: the subscriber's opaque hash (sha-256 of the subscription's renderKey,
 * computed by the caller) and the origin's PUBLISHED edges ordered by pool
 * index, each with its slot's camouflage profile (the ordered serverNames list,
 * active + retired). Output: a primary and, when another published edge
 * exists, a backup (preferring a different provider), each with exactly ONE
 * SNI.
 *
 * Stability rules:
 *  - primary = published[ h0 mod publishedCount ]; a replacement edge inherits
 *    its predecessor's pool index, so only subscribers on that index move.
 *  - the SNI PRF runs over the profile's FULL ordered serverNames list (retired
 *    entries keep their index) so a retirement never shifts other subscribers;
 *    a subscriber whose pick is retired past its drain (or never held it)
 *    re-hashes over the ACTIVE set only.
 *  - IPv6 is an extra entry for the same endpoint, never a separate assignment.
 */

export interface AssignableSni {
  sni: string;
  status: 'active' | 'retired';
  retiredAt?: number;
  drainUntil?: number;
}

export interface PublishedEdge {
  edgeId: string;
  poolIndex: number;
  provider: string;
  slotId: string;
  slotRemark: string;
  edgePort: number;
  addresses: { v4?: string; v6?: string };
  serverNames: AssignableSni[];
}

export interface AssignedEndpoint {
  role: 'primary' | 'backup';
  edge: PublishedEdge;
  sni: string;
}

export interface Assignment {
  primary: AssignedEndpoint | null;
  backup: AssignedEndpoint | null;
}

/** FNV-1a 32-bit (matches nodePinning's; small and synchronous). */
export function fnv1a32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** First 8 hex chars of the subscriber hash as a uint32 (the pool-index seed). */
export function poolSeed(subscriberHash: string): number {
  const n = parseInt(subscriberHash.slice(0, 8), 16);
  return Number.isFinite(n) ? n >>> 0 : fnv1a32(subscriberHash);
}

/**
 * Pick one SNI for (subscriber, edge). `now` decides whether a retired pick is
 * still honoured (inside its drain window and the subscriber could have held
 * it) or re-hashed over the active set.
 */
export function pickSni(
  subscriberHash: string,
  edgeId: string,
  serverNames: readonly AssignableSni[],
  now: number,
  subscriberLastContentAt?: number | null,
): string | null {
  if (serverNames.length === 0) return null;
  const idx = fnv1a32(`${subscriberHash}:${edgeId}`) % serverNames.length;
  const pick = serverNames[idx];
  if (pick.status === 'active') return pick.sni;
  const heldIt =
    pick.retiredAt !== undefined &&
    subscriberLastContentAt !== undefined &&
    subscriberLastContentAt !== null &&
    subscriberLastContentAt < pick.retiredAt;
  const inDrain = pick.drainUntil !== undefined && now < pick.drainUntil;
  if (heldIt && inDrain) return pick.sni;
  const active = serverNames.filter((s) => s.status === 'active');
  if (active.length === 0) return null;
  return active[fnv1a32(`${subscriberHash}:${edgeId}:active`) % active.length].sni;
}

export interface AssignOptions {
  now: number;
  preferDistinctProviders: boolean;
  includeBackup: boolean;
  subscriberLastContentAt?: number | null;
}

/** Assign primary (+ backup) over the published edges sorted by pool index. */
export function assignEndpoints(
  subscriberHash: string,
  published: readonly PublishedEdge[],
  opts: AssignOptions,
): Assignment {
  const edges = [...published]
    .filter(
      (e) => e.serverNames.some((s) => s.status === 'active') && (e.addresses.v4 || e.addresses.v6),
    )
    .sort((a, b) => a.poolIndex - b.poolIndex);
  if (edges.length === 0) return { primary: null, backup: null };
  const pIdx = poolSeed(subscriberHash) % edges.length;
  const primaryEdge = edges[pIdx];
  const primarySni = pickSni(
    subscriberHash,
    primaryEdge.edgeId,
    primaryEdge.serverNames,
    opts.now,
    opts.subscriberLastContentAt,
  );
  if (!primarySni) return { primary: null, backup: null };
  const primary: AssignedEndpoint = { role: 'primary', edge: primaryEdge, sni: primarySni };
  if (!opts.includeBackup || edges.length < 2) return { primary, backup: null };
  // Backup: the next edge by pool order, preferring a different provider.
  const rest = edges.filter((_, i) => i !== pIdx);
  const ordered = [...rest.slice(pIdx), ...rest.slice(0, pIdx)];
  const backupEdge =
    (opts.preferDistinctProviders
      ? ordered.find((e) => e.provider !== primaryEdge.provider)
      : undefined) ?? ordered[0];
  const backupSni = pickSni(
    subscriberHash,
    backupEdge.edgeId,
    backupEdge.serverNames,
    opts.now,
    opts.subscriberLastContentAt,
  );
  return {
    primary,
    backup: backupSni ? { role: 'backup', edge: backupEdge, sni: backupSni } : null,
  };
}
