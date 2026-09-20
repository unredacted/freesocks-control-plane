/**
 * Subscriber → endpoint ASSIGNMENT for origin origins (pure, deterministic).
 *
 * Inputs: the subscriber's opaque `renderKey` (a random 64-hex secret minted
 * per subscription and never exposed — passed RAW, its first 32 bits seed the
 * pool pick and the whole string feeds the SNI PRF) and the origin's PUBLISHED
 * edges ordered by pool index, each with its listener (the ordered server
 * names list, active + retired). Output: a primary and, when
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
 *  - that legacy PRF is a modulus over the list LENGTH, so it is stable under
 *    retirement but NOT under growth: appending one name moves almost every
 *    subscriber. A listener whose list is meant to grow opts into `hrw1`
 *    (rendezvous hashing, `pickSniHrw`): each name scores independently, so
 *    adding a name moves only the subscribers it now wins (about 1/(N+1)) and
 *    retiring one moves only its holders. The version is per listener and the
 *    legacy path is untouched when it is absent, so nobody moves by surprise.
 *  - IPv6 is an extra entry for the same endpoint, never a separate assignment.
 *  - an L7 (CDN-fronted) edge is ONE hostname: it is the address, the SNI and
 *    the HTTP Host header at once, so the profile's server names play no part
 *    in its assignment and it never carries an IPv6 entry.
 */

import { hostTargetFor } from './layers';
import type { EdgeLayer } from './providers/capabilities';
import { protocolUsesSni, type ListenerProto } from './protocols';
import type { MatchRule } from './registration';

/** Name-selection PRF versions a listener can opt into (absent = legacy modulus). */
export type SniPickVersion = 'hrw1';

export interface AssignableSni {
  sni: string;
  status: 'active' | 'retired';
  /** Curated countries where this name is KNOWN blocked: never offered there. */
  blockedIn?: string[];
  /** Curated countries where this name is proven to work. */
  provenIn?: string[];
  retiredAt?: number;
  drainUntil?: number;
}

export interface PublishedEdge {
  edgeId: string;
  poolIndex: number;
  provider: string;
  listenerId: string;
  listenerKey: string;
  /** How the renderer finds this listener's template entry in a body. */
  matchRule: MatchRule;
  /** What the listener speaks: SNI-presenting ones select a name per connection, `none` security rewrites address/port only. */
  proto: ListenerProto;
  edgePort: number;
  /** Absent = `l4` (rows written before edges could be L7 fronts). */
  layer?: EdgeLayer;
  /** L4: IP literals. L7: the fronted hostname members connect to. */
  addresses: { v4?: string; v6?: string; hostname?: string };
  /** Empty for a listener that presents no name. */
  serverNames: AssignableSni[];
  /** How one name is chosen from `serverNames`. Absent = the legacy modulus PRF. */
  sniPick?: SniPickVersion;
  /**
   * False when the edge is published but must not be selected (listener retired,
   * undeployed or disabled, no codec for the body, no template entry). It still occupies its pool index so the
   * modulus does not shift the other subscribers. Absent = eligible.
   */
  eligible?: boolean;
}

export interface AssignedEndpoint {
  role: 'primary' | 'backup';
  edge: PublishedEdge;
  /** The selected server name; null for a slot whose protocol carries none. */
  sni: string | null;
  /**
   * The HTTP Host header the renderer must write (null = the protocol carries
   * none, leave the template's own parameters alone). Comes from the same
   * `hostTargetFor` tuple the backend Host flip writes, so a render and a flip
   * can never disagree.
   */
  hostHeader: string | null;
  /**
   * Further server names for the SAME endpoint, best first after `sni`: the
   * renderer emits one more entry per name so a member whose first name is
   * blocked still holds working ones. Only ever filled for an L4 listener on
   * the `hrw1` PRF (a ranking is what makes "the next best name" stable);
   * absent everywhere else.
   */
  alternates?: { sni: string; hostHeader: string | null }[];
}

export interface AssignableOptions {
  /** Whether the current render rule can emit an IPv6-only edge (false → such an edge is not assignable). */
  canEmitV6?: boolean;
}

/**
 * The edge's layer: `layer` when the row carries one, else inferred from the
 * address shape (a hostname is only ever an L7 front's address).
 */
export function edgeLayer(e: Pick<PublishedEdge, 'layer' | 'addresses'>): EdgeLayer {
  return e.layer ?? (e.addresses.hostname ? 'l7' : 'l4');
}

/** The fronted hostname of an L7 edge; null for an L4 edge (or an L7 one still without a hostname). */
export function edgeHostname(e: Pick<PublishedEdge, 'layer' | 'addresses'>): string | null {
  return edgeLayer(e) === 'l7' ? (e.addresses.hostname ?? null) : null;
}

/**
 * An edge can be assigned when it is eligible and it has something to emit: an
 * L7 edge needs its hostname (which is also its only server name, so the
 * profile's names are not consulted); an L4 edge needs an address the render
 * can emit (IPv4 always; IPv6 only when the rule allows it) and, when its
 * protocol presents a name, at least one ACTIVE server name.
 */
export function edgeAssignable(e: PublishedEdge, opts: AssignableOptions = {}): boolean {
  if (e.eligible === false) return false;
  if (edgeLayer(e) === 'l7') return !!e.addresses.hostname;
  const hasAddress = !!e.addresses.v4 || (opts.canEmitV6 !== false && !!e.addresses.v6);
  if (!hasAddress) return false;
  return !protocolUsesSni(e.proto) || e.serverNames.some((s) => s.status === 'active');
}

function sniFor(
  subscriberKey: string,
  edge: PublishedEdge,
  where?: CountryContext,
): { ok: true; sni: string | null } | { ok: false } {
  // An L7 front terminates TLS on the CDN under its own hostname: that name is
  // the SNI, whatever the profile's (origin-facing) names say.
  const hostname = edgeHostname(edge);
  if (hostname) return { ok: true, sni: hostname };
  if (!protocolUsesSni(edge.proto)) return { ok: true, sni: null };
  const sni = pickSni(subscriberKey, edge.edgeId, edge.serverNames, edge.sniPick, where);
  return sni ? { ok: true, sni } : { ok: false };
}

/**
 * The backup's first name. On `hrw1` it is the best-ranked name the primary
 * does not already carry (falling back to the plain pick when every name is
 * taken); everywhere else it is exactly `sniFor`, so legacy output is unchanged.
 */
function backupSniFor(
  subscriberKey: string,
  edge: PublishedEdge,
  taken: ReadonlySet<string>,
  where?: CountryContext,
): { ok: true; sni: string | null } | { ok: false } {
  const plain = sniFor(subscriberKey, edge, where);
  if (!plain.ok || plain.sni === null) return plain;
  if (edge.sniPick !== 'hrw1' || edgeHostname(edge) || taken.size === 0) return plain;
  const fresh = rankSniHrw(subscriberKey, edge.edgeId, edge.serverNames, where).find(
    (n) => !taken.has(n),
  );
  return { ok: true, sni: fresh ?? plain.sni };
}

/**
 * The Host header for (edge, selected name), from the shared tuple. Assignment
 * is address-family agnostic (the render expands one endpoint into a v4 and a
 * v6 entry), so an L4 edge with only a v6 literal feeds that literal in: the
 * tuple's `host` never depends on which literal was used.
 */
function hostHeaderFor(edge: PublishedEdge, sni: string | null): string | null {
  return (
    hostTargetFor(
      {
        layer: edgeLayer(edge),
        addresses: {
          v4: edge.addresses.v4 ?? edge.addresses.v6,
          hostname: edge.addresses.hostname,
        },
        edgePort: edge.edgePort,
      },
      edge.proto,
      sni,
    )?.host ?? null
  );
}

function endpointFor(
  role: 'primary' | 'backup',
  edge: PublishedEdge,
  sni: string | null,
  alternateNames: readonly string[] = [],
): AssignedEndpoint {
  const alternates = alternateNames.map((n) => ({ sni: n, hostHeader: hostHeaderFor(edge, n) }));
  return {
    role,
    edge,
    sni,
    hostHeader: hostHeaderFor(edge, sni),
    ...(alternates.length > 0 ? { alternates } : {}),
  };
}

/**
 * The names one endpoint carries: `[first, ...alternates]`, at most `want`.
 * More than one only for an L4, name-presenting listener on `hrw1`; `avoid`
 * (the primary's names) is honoured for the backup while enough names remain,
 * so a member's entries spread over as many distinct names as the list allows.
 */
function namesFor(
  subscriberKey: string,
  edge: PublishedEdge,
  first: string | null,
  want: number,
  avoid: ReadonlySet<string> = new Set(),
  where?: CountryContext,
): string[] {
  if (first === null || want <= 1) return [];
  if (edge.sniPick !== 'hrw1' || edgeHostname(edge) || !protocolUsesSni(edge.proto)) return [];
  const ranked = rankSniHrw(subscriberKey, edge.edgeId, edge.serverNames, where).filter(
    (n) => n !== first,
  );
  const fresh = ranked.filter((n) => !avoid.has(n));
  const pool = fresh.length >= want - 1 ? fresh : [...fresh, ...ranked.filter((n) => avoid.has(n))];
  return pool.slice(0, want - 1);
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
  version?: SniPickVersion,
  where?: CountryContext,
): string | null {
  if (version === 'hrw1') return rankSniHrw(subscriberKey, edgeId, serverNames, where)[0] ?? null;
  if (serverNames.length === 0) return null;
  const pick = serverNames[fnv1a32(`${subscriberKey}:${edgeId}`) % serverNames.length];
  if (pick.status === 'active') return pick.sni;
  const active = serverNames.filter((s) => s.status === 'active');
  if (active.length === 0) return null;
  return active[fnv1a32(`${subscriberKey}:${edgeId}:active`) % active.length].sni;
}

/**
 * Where the member is, for name selection. `country` is a CURATED country code
 * (a place where names are known to be blocked selectively), or null when it is
 * unknown, not curated, or there is no request to infer it from (a mirror).
 */
export interface CountryContext {
  country: string | null;
  curated: readonly string[];
}

/**
 * 0 = preferred, 1 = acceptable, null = never offer.
 *
 *  - in a curated country: a name blocked THERE is never offered; names proven
 *    there come first, names nobody has judged there fill the rest;
 *  - anywhere else, or with no country at all: the UNIVERSAL pool, names that
 *    are not blocked in ANY curated country. A mirror has no request country
 *    and exists for exactly the people who are blocked, so it must never carry
 *    a name known blocked somewhere curated.
 */
export function countryTier(s: AssignableSni, where?: CountryContext): 0 | 1 | null {
  if (!where) return 0;
  const blocked = s.blockedIn ?? [];
  if (where.country) {
    if (blocked.includes(where.country)) return null;
    return (s.provenIn ?? []).includes(where.country) ? 0 : 1;
  }
  return blocked.some((c) => where.curated.includes(c)) ? null : 0;
}

/**
 * `hrw1`: the ACTIVE names ranked for (subscriber, edge) by rendezvous hashing,
 * best first. Each name's score depends only on (subscriber, edge, that name),
 * never on the list's length or order, which is what makes it stable: a new
 * name changes a subscriber's ranking only where it outscores their current
 * names, and a retired name simply drops out of everyone's ranking. Ties (a
 * 32-bit score can collide) break on the name so the order is total.
 */
export function rankSniHrw(
  subscriberKey: string,
  edgeId: string,
  serverNames: readonly AssignableSni[],
  where?: CountryContext,
): string[] {
  const scored: { sni: string; score: number; tier: number }[] = [];
  const seen = new Set<string>();
  for (const s of serverNames) {
    if (s.status !== 'active' || seen.has(s.sni)) continue;
    const tier = countryTier(s, where);
    if (tier === null) continue;
    seen.add(s.sni);
    scored.push({ sni: s.sni, score: fnv1a32(`${subscriberKey}:${edgeId}:${s.sni}`), tier });
  }
  // Proven names first, each tier in its own rendezvous order: a member in a
  // curated country holds proven names while enough exist, and the ranking
  // inside a tier is as stable as ever.
  scored.sort(
    (a, b) => a.tier - b.tier || b.score - a.score || (a.sni < b.sni ? -1 : a.sni > b.sni ? 1 : 0),
  );
  return scored.map((x) => x.sni);
}

export interface AssignOptions {
  now: number;
  preferDistinctProviders: boolean;
  includeBackup: boolean;
  /** Whether the render can emit IPv6 (default true). An IPv6-only edge is skipped otherwise. */
  canEmitV6?: boolean;
  /** Server names on the primary endpoint (default 1). See `AssignedEndpoint.alternates`. */
  namesPerEndpoint?: number;
  /** Server names on the backup endpoint (default 1). */
  backupNames?: number;
  /** Where the member is, for listeners on `hrw1`. Absent = no country logic at all. */
  where?: CountryContext;
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
  // An edge every one of whose names is excluded for this member's country is
  // not assignable FOR THEM: the walk moves on to the next edge.
  const assignable = (e: PublishedEdge) =>
    edgeAssignable(e, { canEmitV6: opts.canEmitV6 }) &&
    (!opts.where ||
      e.sniPick !== 'hrw1' ||
      !!edgeHostname(e) ||
      !protocolUsesSni(e.proto) ||
      rankSniHrw(subscriberKey, e.edgeId, e.serverNames, opts.where).length > 0);
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
  const primarySni = sniFor(subscriberKey, primaryEdge, opts.where);
  if (!primarySni.ok) return { primary: null, backup: null };
  const primaryAlts = namesFor(
    subscriberKey,
    primaryEdge,
    primarySni.sni,
    opts.namesPerEndpoint ?? 1,
    undefined,
    opts.where,
  );
  const primary = endpointFor('primary', primaryEdge, primarySni.sni, primaryAlts);
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
  // The backup's names avoid the primary's where the list allows it: two
  // edges sharing a blocked name would fail together.
  const taken = new Set([primarySni.sni, ...primaryAlts].filter((n): n is string => n !== null));
  const backupSni = backupSniFor(subscriberKey, backupEdge, taken, opts.where);
  if (!backupSni.ok) return { primary, backup: null };
  const backupAlts = namesFor(
    subscriberKey,
    backupEdge,
    backupSni.sni,
    opts.backupNames ?? 1,
    taken,
    opts.where,
  );
  return { primary, backup: endpointFor('backup', backupEdge, backupSni.sni, backupAlts) };
}
