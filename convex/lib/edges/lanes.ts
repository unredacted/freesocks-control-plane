/**
 * Address lanes (docs/edges.md "Address enumeration"). A node with lanes on
 * keeps, per transport, a few OPEN addresses that anyone may be handed (new
 * free accounts, suspected ones) and TRUSTED addresses that only trusted
 * members ever see: paid members and accounts old enough. A censor's cheap
 * accounts see the open lane, which is expected to be blocked and has its own
 * small replacement budget; the trusted lane is what they never reach.
 *
 * The rules here keep one promise: an address any account could have been
 * handed while it was not trusted-only is never trusted. So an address is
 * trusted only when it was made after the node's lanes were last switched on
 * and had never been published before; its lane is fixed at that first
 * publication; switching lanes off makes every trusted address open for good.
 *
 * Pure.
 */

export type Lane = 'open' | 'trusted';

/** Per transport: how many open and trusted addresses the node keeps in use. */
export interface LaneTargets {
  open: number;
  trusted: number;
}

/** Bounds of one lane target per transport. */
export const LANE_TARGET_MAX = 32;

/** The node's lanes are on (an origin row, or the fields of one). */
export function lanesOn(relay: { lanes?: LaneTargets; lanesSince?: number }): boolean {
  return !!relay.lanes && relay.lanesSince !== undefined;
}

export function edgeLaneOf(e: { lane?: 'trusted' }): Lane {
  return e.lane === 'trusted' ? 'trusted' : 'open';
}

/** A paid member: a tier that is not the free one, while its membership runs. */
export function isPaidMember(
  user: { membershipExpiresAt?: number },
  tier: { isDefaultFree: boolean } | null,
  now: number,
): boolean {
  if (!tier || tier.isDefaultFree) return false;
  return user.membershipExpiresAt === undefined || user.membershipExpiresAt > now;
}

/**
 * The lane a member draws from: trusted when they pay or their account is at
 * least `promoteAfterDays` old, and they are not suspected (suspicion is the
 * one thing that takes trust away, paid or not).
 */
export function memberLane(input: {
  paid: boolean;
  createdAt: number;
  suspected: boolean;
  now: number;
  promoteAfterDays: number;
}): Lane {
  if (input.suspected) return 'open';
  if (input.paid) return 'trusted';
  return input.now - input.createdAt >= input.promoteAfterDays * 86_400_000 ? 'trusted' : 'open';
}

/**
 * The taint rule: whether this address may become trusted when it is first
 * published. Never one made before the node's lanes were (last) switched on,
 * never one published before (anyone may have been handed it), never an
 * imported one (it served before FCP knew it), never one whose address FCP
 * handed out before under another row (`seenBefore`).
 */
export function mayBeTrusted(
  edge: {
    _creationTime: number;
    publishedAt?: number;
    resources: ReadonlyArray<{ ownership?: string }>;
  },
  relay: { lanes?: LaneTargets; lanesSince?: number },
  seenBefore: boolean,
): boolean {
  if (!lanesOn(relay)) return false;
  // Strictly after: an address made in the very moment of the switch counts as before it.
  if (edge._creationTime <= relay.lanesSince!) return false;
  if (edge.publishedAt !== undefined) return false;
  if (edge.resources.some((r) => r.ownership === 'adopted')) return false;
  return !seenBefore;
}

/**
 * The lane an address takes at its FIRST publication on a transport: a
 * replacement keeps its target's lane (when it may be trusted at all); growth
 * fills the open lane first while it is empty (open members are dark without
 * one), then the trusted lane up to its target, then the open one. An address
 * that may not be trusted is open whatever the counts say.
 */
export function laneAtPublish(input: {
  mayBeTrusted: boolean;
  targets: LaneTargets;
  /** Addresses of each lane already in use on this transport (the replaced one left out). */
  inUse: { open: number; trusted: number };
  /** A replace: the lane of the address it swaps out. */
  replacing?: Lane;
}): Lane {
  if (!input.mayBeTrusted) return 'open';
  if (input.replacing) return input.replacing;
  if (input.inUse.open === 0 && input.targets.open > 0) return 'open';
  return input.inUse.trusted < input.targets.trusted ? 'trusted' : 'open';
}

export interface LaneBookEntry {
  open: number;
  trusted: number;
  openDeficit: number;
  trustedDeficit: number;
  /** Open addresses above the target (after switching lanes on, every old one is open). */
  openExcess: number;
}

/** Per transport: what each lane holds and lacks. */
export function laneBook(
  listenerIds: readonly string[],
  published: ReadonlyArray<{ listenerId: string; lane?: 'trusted' }>,
  targets: LaneTargets,
): Map<string, LaneBookEntry> {
  const out = new Map<string, LaneBookEntry>();
  for (const id of listenerIds) {
    const mine = published.filter((e) => e.listenerId === id);
    const trusted = mine.filter((e) => e.lane === 'trusted').length;
    const open = mine.length - trusted;
    out.set(id, {
      open,
      trusted,
      openDeficit: Math.max(0, targets.open - open),
      trustedDeficit: Math.max(0, targets.trusted - trusted),
      openExcess: Math.max(0, open - targets.open),
    });
  }
  return out;
}

/**
 * The published-pool size a node with lanes needs: per transport, both
 * targets, plus the open addresses still above target while the trusted lane
 * fills (they leave once it is full, `openToRetire`).
 */
export function laneDesired(
  book: ReadonlyMap<string, LaneBookEntry>,
  targets: LaneTargets,
): number {
  let n = 0;
  for (const e of book.values())
    n += Math.max(e.open, targets.open) + Math.max(e.trusted, targets.trusted);
  return n;
}

/**
 * The next open address to take out of use: on a transport whose trusted lane
 * is full, the OLDEST open one above the open target that is not its
 * transport's template address (the backend's Host points at that one). Null
 * when none should go.
 */
export function openToRetire<
  E extends { edgeId: string; listenerId: string; lane?: 'trusted'; publishedAt?: number },
>(
  book: ReadonlyMap<string, LaneBookEntry>,
  published: readonly E[],
  templateIds: ReadonlySet<string>,
): E | null {
  for (const [listenerId, e] of book) {
    if (e.trustedDeficit > 0 || e.openExcess === 0) continue;
    const pick = published
      .filter(
        (x) => x.listenerId === listenerId && x.lane !== 'trusted' && !templateIds.has(x.edgeId),
      )
      .sort((a, b) => (a.publishedAt ?? 0) - (b.publishedAt ?? 0))[0];
    if (pick) return pick;
  }
  return null;
}
