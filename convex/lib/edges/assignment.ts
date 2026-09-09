/**
 * Subscriber → endpoint ASSIGNMENT for relay origins (pure, deterministic).
 *
 * Inputs: the subscriber's opaque `renderKey` (a random 64-hex secret minted
 * per subscription and never exposed — passed RAW, its first 32 bits seed the
 * pool pick and the whole string feeds the SNI PRF) and the origin's PUBLISHED
 * edges ordered by pool index, each with its slot's camouflage profile (the
 * ordered serverNames list, active + retired). Output: a primary and, when
 * another assignable edge exists, a backup (preferring a different provider),
 * each with exactly ONE SNI.
 *
 * Stability rules:
 *  - primary = published[ h0 mod publishedCount ] over the FULL pool order
 *    (ineligible edges included in the modulus); when that edge is not
 *    assignable the walk continues forward in pool order, so an edge losing
 *    eligibility (profile disabled, no active name, no emittable address)
 *    moves only the subscribers that were on it. A replacement edge inherits
 *    its predecessor's pool index, so only subscribers on that index move.
 *  - the SNI PRF runs over the profile's FULL ordered serverNames list (retired
 *    entries keep their index) so a retirement never shifts other subscribers;
 *    a subscriber whose pick is retired re-hashes over the ACTIVE set only. A
 *    retired name is NEVER selected for a render — the drain only means the
 *    node keeps ACCEPTING it for clients that have not refreshed yet.
 *  - IPv6 is an extra entry for the same endpoint, never a separate assignment.
 */

import { protocolUsesSni, type SlotProtocol } from './protocols';

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
  /** The slot profile's protocol: SNI-presenting ones select a name per connection, `plain` rewrites address/port only. */
  protocol: SlotProtocol;
  edgePort: number;
  addresses: { v4?: string; v6?: string };
  /** Empty for a non-REALITY slot. */
  serverNames: AssignableSni[];
  /**
   * False when the edge is published but must not be selected (slot retired or
   * undeployed, profile disabled). It still occupies its pool index so the
   * modulus does not shift the other subscribers. Absent = eligible.
   */
  eligible?: boolean;
}

export interface AssignedEndpoint {
  role: 'primary' | 'backup';
  edge: PublishedEdge;
  /** The selected server name; null for a slot whose protocol carries none. */
  sni: string | null;
}

export interface AssignableOptions {
  /** Whether the current render rule can emit an IPv6-only edge (false → such an edge is not assignable). */
  canEmitV6?: boolean;
}

/**
 * An edge can be assigned when it is eligible, has an address the render can
 * emit (IPv4 always; IPv6 only when the rule allows it) and, when its protocol
 * presents a name, at least one ACTIVE server name.
 */
export function edgeAssignable(e: PublishedEdge, opts: AssignableOptions = {}): boolean {
  if (e.eligible === false) return false;
  const hasAddress = !!e.addresses.v4 || (opts.canEmitV6 !== false && !!e.addresses.v6);
  if (!hasAddress) return false;
  return !protocolUsesSni(e.protocol) || e.serverNames.some((s) => s.status === 'active');
}

function sniFor(
  subscriberKey: string,
  edge: PublishedEdge,
): { ok: true; sni: string | null } | { ok: false } {
  if (!protocolUsesSni(edge.protocol)) return { ok: true, sni: null };
  const sni = pickSni(subscriberKey, edge.edgeId, edge.serverNames);
  return sni ? { ok: true, sni } : { ok: false };
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

/** First 8 hex chars of the subscriber key as a uint32 (the pool-index seed). */
export function poolSeed(subscriberKey: string): number {
  const n = parseInt(subscriberKey.slice(0, 8), 16);
  return Number.isFinite(n) ? n >>> 0 : fnv1a32(subscriberKey);
}

/**
 * Pick one SNI for (subscriber, edge): the PRF index over the FULL list keeps
 * everyone else stable when a name is retired; a retired pick re-hashes over
 * the active set. Null when no name is active (the edge is then not
 * assignable — a retired name is never handed out, drain or not).
 */
export function pickSni(
  subscriberKey: string,
  edgeId: string,
  serverNames: readonly AssignableSni[],
): string | null {
  if (serverNames.length === 0) return null;
  const pick = serverNames[fnv1a32(`${subscriberKey}:${edgeId}`) % serverNames.length];
  if (pick.status === 'active') return pick.sni;
  const active = serverNames.filter((s) => s.status === 'active');
  if (active.length === 0) return null;
  return active[fnv1a32(`${subscriberKey}:${edgeId}:active`) % active.length].sni;
}

export interface AssignOptions {
  now: number;
  preferDistinctProviders: boolean;
  includeBackup: boolean;
  /** Whether the render can emit IPv6 (default true). An IPv6-only edge is skipped otherwise. */
  canEmitV6?: boolean;
  /**
   * @deprecated No longer consulted: a retired server name is never selected,
   * whoever held it. Kept so existing callers type-check; remove at will.
   */
  subscriberLastContentAt?: number | null;
}

/**
 * Assign primary (+ backup) over the published edges in pool order. The seed
 * indexes the FULL pool (assignable or not) and walks forward to the first
 * assignable edge, so a single edge turning ineligible moves only its own
 * subscribers; the backup is the next assignable edge after the primary,
 * preferring a different provider.
 */
export function assignEndpoints(
  subscriberKey: string,
  published: readonly PublishedEdge[],
  opts: AssignOptions,
): Assignment {
  const pool = [...published].sort((a, b) => a.poolIndex - b.poolIndex);
  if (pool.length === 0) return { primary: null, backup: null };
  const assignable = (e: PublishedEdge) => edgeAssignable(e, { canEmitV6: opts.canEmitV6 });
  const start = poolSeed(subscriberKey) % pool.length;
  // Walk forward (wrapping) from the seeded index to the first assignable edge.
  let pIdx = -1;
  for (let step = 0; step < pool.length; step++) {
    const i = (start + step) % pool.length;
    if (assignable(pool[i])) {
      pIdx = i;
      break;
    }
  }
  if (pIdx < 0) return { primary: null, backup: null };
  const primaryEdge = pool[pIdx];
  const primarySni = sniFor(subscriberKey, primaryEdge);
  if (!primarySni.ok) return { primary: null, backup: null };
  const primary: AssignedEndpoint = { role: 'primary', edge: primaryEdge, sni: primarySni.sni };
  if (!opts.includeBackup) return { primary, backup: null };
  // Backup: the next assignable edge after the primary in pool order,
  // preferring a different provider.
  const ordered: PublishedEdge[] = [];
  for (let step = 1; step < pool.length; step++) {
    const e = pool[(pIdx + step) % pool.length];
    if (assignable(e)) ordered.push(e);
  }
  if (ordered.length === 0) return { primary, backup: null };
  const backupEdge =
    (opts.preferDistinctProviders
      ? ordered.find((e) => e.provider !== primaryEdge.provider)
      : undefined) ?? ordered[0];
  const backupSni = sniFor(subscriberKey, backupEdge);
  return {
    primary,
    backup: backupSni.ok ? { role: 'backup', edge: backupEdge, sni: backupSni.sni } : null,
  };
}
