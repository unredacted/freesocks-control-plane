/**
 * Provider sets (docs/edges.md § "Provider sets"): what a node's published pool
 * must hold so every member gets a main address and a backup in different
 * failure domains. Pure; the database side reads the rows
 * (`convex/edgeProviderSets.ts`).
 *
 * A node's SET is its picks: locations (an account + a frozen placement) its
 * addresses come from. For each coverage listener:
 *  - basic coverage: at least one published edge, whatever the set says;
 *  - diversity: published edges in `min(2, G)` GROUPS, where G counts the groups
 *    among the picks that can carry the listener and are not cooling. A group
 *    is the provider (the company: one block on its ranges takes all its
 *    regions), or the location when every carrier of the listener is one
 *    provider (two regions of one network still beat one);
 *  - every pick that carries a listener holds at least one published edge.
 * A listener whose carriers make fewer than two groups is REDUCED
 * (`one_group`): reported, never hidden. A shortfall only a cooling pick could
 * fill is `cooling_only` and is not part of the deficit: automatic work never
 * reserves room for, or provisions into, a pick that cools.
 *
 * Exports:
 *   MAX_PROVIDER_PICKS                   picks per set
 *   requirementOf(listeners, picks, cooling)
 *   coverTargets(requirement, published) the fewest new (listener, pick) targets
 *   coverageDeficit(requirement, published)
 *   removableUnder(requirement, published, edgeIndex)
 */

/** Picks per set: a node is protected by at most this many locations. */
export const MAX_PROVIDER_PICKS = 6;

export interface SetPick {
  locationId: string;
  /** The provider id (the company): the diversity group. */
  provider: string;
  /** `<provider>:<placeKey>`: the group when every carrier is one provider. */
  locationKey: string;
}

export interface SetListener {
  listenerKey: string;
  /** The picks (location ids) that can carry it: layer, protocol, port, scope, usable. */
  carriers: readonly string[];
}

/** A published edge as the requirement reads it. */
export interface PublishedRef {
  listenerKey: string;
  locationId: string | null;
  provider: string | null;
  locationKey: string | null;
}

export type GroupBy = 'provider' | 'location';

export interface ListenerRequirement {
  listenerKey: string;
  groupBy: GroupBy;
  /** Diversity group -> the non-cooling carrier picks in it, in set order. */
  groups: Map<string, string[]>;
  /** `min(2, G)` over the non-cooling carriers. */
  required: number;
  /** A carrier exists but every one cools: nothing automatic can be done now. */
  coolingOnly: boolean;
  /** No pick carries it (a set exists): the operator must add one. */
  uncarried: boolean;
}

export interface Requirement {
  /** False for an origin without a set: basic coverage only, from any location. */
  hasSet: boolean;
  listeners: ListenerRequirement[];
  /** Non-cooling picks that carry at least one listener, in set order. */
  picks: string[];
  /** Listeners whose carriers (cooling or not) make fewer than two groups. */
  reduced: Array<{ listenerKey: string; reason: 'one_group' }>;
  coolingOnly: string[];
  uncarried: string[];
}

export interface Target {
  listenerKey: string;
  /** null = any location (an origin without a set, or a listener no pick carries). */
  locationId: string | null;
  /** True when it covers a listener's need (published before the pick-only ones). */
  coversListener: boolean;
}

export function groupOf(
  groupBy: GroupBy,
  ref: { provider: string | null; locationKey: string | null },
): string | null {
  if (groupBy === 'provider') return ref.provider ?? null;
  return ref.locationKey ?? null;
}

export function requirementOf(
  listeners: readonly SetListener[],
  picks: readonly SetPick[] | null,
  cooling: ReadonlySet<string> = new Set(),
): Requirement {
  if (picks === null) {
    return {
      hasSet: false,
      listeners: listeners.map((l) => ({
        listenerKey: l.listenerKey,
        groupBy: 'provider' as const,
        groups: new Map(),
        required: 0,
        coolingOnly: false,
        uncarried: false,
      })),
      picks: [],
      reduced: [],
      coolingOnly: [],
      uncarried: [],
    };
  }
  const out: ListenerRequirement[] = [];
  const reduced: Requirement['reduced'] = [];
  const carrying = new Set<string>();
  for (const l of listeners) {
    const all = picks.filter((p) => l.carriers.includes(p.locationId));
    const groupBy: GroupBy =
      new Set(all.map((p) => p.provider)).size <= 1 ? 'location' : 'provider';
    const groups = new Map<string, string[]>();
    for (const p of all) {
      if (cooling.has(p.locationId)) continue;
      const g = groupBy === 'provider' ? p.provider : p.locationKey;
      groups.set(g, [...(groups.get(g) ?? []), p.locationId]);
      carrying.add(p.locationId);
    }
    const allGroups = new Set(
      all.map((p) => (groupBy === 'provider' ? p.provider : p.locationKey)),
    );
    if (all.length > 0 && allGroups.size < 2)
      reduced.push({ listenerKey: l.listenerKey, reason: 'one_group' });
    out.push({
      listenerKey: l.listenerKey,
      groupBy,
      groups,
      required: Math.min(2, groups.size),
      coolingOnly: all.length > 0 && groups.size === 0,
      uncarried: all.length === 0,
    });
  }
  return {
    hasSet: true,
    listeners: out,
    picks: picks.map((p) => p.locationId).filter((id) => carrying.has(id)),
    reduced,
    coolingOnly: out.filter((l) => l.coolingOnly).map((l) => l.listenerKey),
    uncarried: out.filter((l) => l.uncarried).map((l) => l.listenerKey),
  };
}

/**
 * The fewest new (listener, pick) targets that meet the requirement given what
 * is published: the listener demand left after what is published, plus every
 * pick without a published edge, minus the targets that can serve both (a
 * maximum b-matching, found as a max flow: listener demand -> (listener, group)
 * with capacity one -> pick -> sink with capacity one). Each remaining unit then
 * gets one more pair. Instances are tiny (at most 8 listeners x 6 picks).
 * Targets that cover a listener come first.
 */
export function coverTargets(req: Requirement, published: readonly PublishedRef[]): Target[] {
  const listenerTargets: Target[] = [];
  const pickTargets: Target[] = [];
  // Per listener: the groups still wanted and how many.
  const need = req.listeners.map((l) => {
    const pubs = published.filter((p) => p.listenerKey === l.listenerKey);
    const have = new Set(
      pubs.map((p) => groupOf(l.groupBy, p)).filter((g): g is string => g !== null),
    );
    const fresh = [...l.groups.keys()].filter((g) => !have.has(g));
    const units = Math.min(Math.max(0, l.required - have.size), fresh.length);
    // Basic coverage on its own: a listener with nothing published and no
    // group to ask for (no set, or no pick carries it) still needs one.
    const any = pubs.length === 0 && units === 0 && !l.coolingOnly && (!req.hasSet || l.uncarried);
    return { l, fresh, units, any };
  });
  const coveredPicks = new Set(
    published.map((p) => p.locationId).filter((id): id is string => id !== null),
  );
  const residualPicks = req.picks.filter((p) => !coveredPicks.has(p));
  // Max flow over listener units x (listener, group) x residual picks.
  const matched = maxMatching(need, residualPicks);
  const pickTaken = new Set<string>();
  for (const n of need) {
    const usedGroups = new Set<string>();
    const mine = matched.filter((m) => m.listenerKey === n.l.listenerKey);
    for (const m of mine) {
      usedGroups.add(m.group);
      pickTaken.add(m.locationId);
      listenerTargets.push({
        listenerKey: n.l.listenerKey,
        locationId: m.locationId,
        coversListener: true,
      });
    }
    let left = n.units - mine.length;
    for (const g of n.fresh) {
      if (left <= 0) break;
      if (usedGroups.has(g)) continue;
      const choices = n.l.groups.get(g) ?? [];
      // A residual pick is never left here (the flow is maximum); prefer one anyway.
      const p = choices.find((c) => residualPicks.includes(c) && !pickTaken.has(c)) ?? choices[0];
      if (!p) continue;
      usedGroups.add(g);
      if (residualPicks.includes(p)) pickTaken.add(p);
      listenerTargets.push({ listenerKey: n.l.listenerKey, locationId: p, coversListener: true });
      left--;
    }
    if (n.any)
      listenerTargets.push({
        listenerKey: n.l.listenerKey,
        locationId: null,
        coversListener: true,
      });
  }
  for (const p of residualPicks) {
    if (pickTaken.has(p)) continue;
    // A listener this pick carries, preferring one whose group it adds.
    const carried = req.listeners.filter((l) =>
      [...l.groups.values()].some((ps) => ps.includes(p)),
    );
    const fresh = carried.find((l) => {
      const g = [...l.groups.entries()].find(([, ps]) => ps.includes(p))?.[0];
      return !published.some((x) => x.listenerKey === l.listenerKey && groupOf(l.groupBy, x) === g);
    });
    const l = fresh ?? carried[0];
    if (!l) continue;
    pickTaken.add(p);
    pickTargets.push({ listenerKey: l.listenerKey, locationId: p, coversListener: false });
  }
  return [...listenerTargets, ...pickTargets];
}

/** How many targets the requirement still asks for (cooling-only shortfalls excluded). */
export function coverageDeficit(req: Requirement, published: readonly PublishedRef[]): number {
  return coverTargets(req, published).length;
}

/**
 * Whether removing published edge `index` keeps the deficit where it is (or
 * lowers it): the rebalance rule. Rebalance makes room in a full pool that is
 * already short somewhere, so it cannot ask for a zero deficit after removal;
 * it asks that the removal costs no coverage.
 */
export function removableUnder(
  req: Requirement,
  published: readonly PublishedRef[],
  index: number,
): boolean {
  const without = published.filter((_, i) => i !== index);
  return coverageDeficit(req, without) <= coverageDeficit(req, published);
}

// --- max flow (tiny graphs) -------------------------------------------------------------------------

interface Need {
  l: ListenerRequirement;
  fresh: string[];
  units: number;
}

/**
 * The (listener, group, pick) assignments of a maximum flow: source -> listener
 * (its units) -> (listener, group) (one) -> residual pick (one) -> sink (one).
 * Edmonds-Karp over a dense matrix: at most 1 + 8 + 48 + 6 + 1 nodes.
 */
function maxMatching(
  need: readonly Need[],
  residualPicks: readonly string[],
): Array<{ listenerKey: string; group: string; locationId: string }> {
  const lg: Array<{ li: number; group: string }> = [];
  for (let li = 0; li < need.length; li++) {
    const n = need[li]!;
    if (n.units <= 0) continue;
    for (const g of n.fresh) lg.push({ li, group: g });
  }
  const S = 0;
  const L0 = 1;
  const G0 = L0 + need.length;
  const P0 = G0 + lg.length;
  const T = P0 + residualPicks.length;
  const size = T + 1;
  const cap: number[][] = Array.from({ length: size }, () => new Array<number>(size).fill(0));
  for (let li = 0; li < need.length; li++) cap[S]![L0 + li] = Math.max(0, need[li]!.units);
  lg.forEach((x, i) => {
    cap[L0 + x.li]![G0 + i] = 1;
    for (const p of need[x.li]!.l.groups.get(x.group) ?? []) {
      const pi = residualPicks.indexOf(p);
      if (pi >= 0) cap[G0 + i]![P0 + pi] = 1;
    }
  });
  for (let pi = 0; pi < residualPicks.length; pi++) cap[P0 + pi]![T] = 1;
  const flow: number[][] = Array.from({ length: size }, () => new Array<number>(size).fill(0));
  for (;;) {
    const prev = new Array<number>(size).fill(-1);
    prev[S] = S;
    const queue = [S];
    while (queue.length > 0 && prev[T] === -1) {
      const u = queue.shift()!;
      for (let v = 0; v < size; v++) {
        if (prev[v] === -1 && cap[u]![v]! - flow[u]![v]! > 0) {
          prev[v] = u;
          queue.push(v);
        }
      }
    }
    if (prev[T] === -1) break;
    for (let v = T; v !== S; v = prev[v]!) {
      const u = prev[v]!;
      flow[u]![v] = flow[u]![v]! + 1;
      flow[v]![u] = flow[v]![u]! - 1;
    }
  }
  const out: Array<{ listenerKey: string; group: string; locationId: string }> = [];
  lg.forEach((x, i) => {
    residualPicks.forEach((p, pi) => {
      if (flow[G0 + i]![P0 + pi]! > 0)
        out.push({ listenerKey: need[x.li]!.l.listenerKey, group: x.group, locationId: p });
    });
  });
  return out;
}
