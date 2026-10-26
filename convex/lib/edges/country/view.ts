/**
 * One country, everything the evidence says (pure; unit-tested). docs/edges.md
 * "The country view".
 *
 * For every origin, every listener (transport): its addresses (published edges,
 * spares, the origin itself when it opted into probing) with what they count
 * as from that country and WHY, its server names with the mark standing there
 * and what the checks from inside and member reports say, and what a member in
 * that country is handed today. Nothing here decides anything: the states are
 * the ones delivery already acts on (`edges.countryState`, the names' country
 * copies), the rest is the evidence beside them.
 *
 * "Handed" runs the assignment itself (`assignEndpoints`) over a fixed sample of
 * render keys, one listener at a time (as a body carrying only that transport),
 * with the deployment's render rule, steering and name tiers: whatever changes
 * in the assignment shows here by itself. The sample is synthetic: no member
 * row is read.
 */
import {
  assignEndpoints,
  fnv1a32,
  type Assignment,
  type CountryContext,
  type EdgePickVersion,
  type PublishedEdge,
} from '../assignment';
import type {
  CountryViewAddressBasis,
  CountryViewHandedReason,
  CountryViewNameBasis,
  RealHostReading,
} from '../../../../src/shared/contracts/edgeCodes';
import { TARGET_ADDS_FLAG_MS, type HandshakeTiming, type PairCounts } from '../sni/realHost';

export type ViewState = 'proven' | 'blocked' | 'unknown';

/**
 * Why an address counts as it does there, first that applies:
 *  - `mark`, `location_mark`: an operator's word about the edge or its location;
 *  - `checks`: the edge's own rounds with controls (address track);
 *  - `handshake`: names stopped getting through it while TCP works (handshake track);
 *  - `never_reached`: sustained unreachability (never reached from there, reached elsewhere);
 *  - `location`: its (provider, location) group is blocked there;
 *  - `probes`: no graded state; the address-level probes alone (reached = proven,
 *    failing while another country reaches it = blocked);
 *  - `none`: nothing on record.
 * Every basis but `probes` and `none` is what delivery acts on (`edges.countryState`);
 * `probes` is shown, never acted on.
 */
export type AddressBasis = CountryViewAddressBasis;

/**
 * Why a name counts as it does there: `mark` (an operator's), `checks_mark`
 * (written by the checks from inside, `autoApply`), `checks` (the checks
 * suggest it; NOT applied, nothing acts on it), `none`.
 */
export type NameBasis = CountryViewNameBasis;

type Verdict = 'reachable' | 'unreachable' | 'mixed' | 'unknown';

export interface ReachRow {
  country: string;
  verdict: Verdict;
  v6Verdict?: Verdict;
  nameVerdict?: Verdict;
  okVantages: number;
  failVantages: number;
  lastAt: number;
  wasReachable?: boolean;
  neverReached?: { checks: number; networks: number; since: number; lastAt: number };
}

/** The per-country evidence row of one edge (`edgeCountryEvidence`), as read. */
export interface EvidenceRow {
  address: {
    state: ViewState;
    reason?: string;
    decidedAt?: number;
    until?: number;
    blockedRounds: number;
  };
  handshake: {
    state: 'blocked' | 'none';
    reason?: string;
    until?: number;
    lastBatchAt?: number;
    pathBatches: readonly number[];
  };
  lastRound?: {
    at: number;
    result: string;
    reason?: string;
    ok: number;
    fail: number;
    networks: number;
    controlsOk: number;
    v6Result?: string;
  };
  combined: ViewState;
  stateUntil?: number;
}

export interface EdgeInput {
  edgeId: string;
  listenerId: string;
  layer: 'l4' | 'l7';
  provider: string | null;
  location: string | null;
  status: string;
  publication: string;
  poolIndex: number | null;
  addresses: { v4?: string; v6?: string; hostname?: string };
  /** `edges.countryState.byCountry` (raw; entries past `until` are dropped here). */
  countryState: ReadonlyArray<{
    country: string;
    state: 'proven' | 'blocked';
    until?: number;
    from: 'edge' | 'group' | 'mark';
  }>;
  reachability: readonly ReachRow[];
  /** This country's evidence row, mark, location mark and location grade. */
  evidence: EvidenceRow | null;
  mark: { state: 'proven' | 'blocked'; at: number } | null;
  locationMark: { state: 'proven' | 'blocked'; at: number } | null;
  grade: {
    state: string;
    counts: { edges: number; proven: number; blocked: number };
    until?: number;
  } | null;
}

export interface NameInput {
  name: string;
  status: 'active' | 'retired';
  drainUntil?: number;
  /** The copies on the listener (what selection reads). */
  blockedIn: readonly string[];
  provenIn: readonly string[];
}

/** What is known about a name from one country, read once per name. */
export interface NameFacts {
  family: string | null;
  qualified: boolean | null;
  mark: { state: 'proven' | 'blocked'; source: 'operator' | 'probe'; at: number } | null;
  checks: {
    latest: 'ok' | 'failing' | 'mixed' | 'none';
    okVantages: number;
    okNetworks: number;
    failVantages: number;
    failNetworks: number;
    pathFailures: number;
    suggestion: 'proven' | 'blocked' | null;
    reason: string | null;
    lastAt: number | null;
    lastOkAt: number | null;
  } | null;
  reports: { weight: number; suspect: boolean } | null;
  /** The real-host controls of the newest batch that had them (lib/edges/sni/realHost.ts). */
  realHost?: NameRealHost | null;
}

export interface NameRealHost {
  at: number;
  /** FCP's address the batch measured (`<kind>:<ref>:<address>:<port>`). */
  target: string;
  realAddress: string | null;
  reading: RealHostReading;
  counts: PairCounts;
  vantages: number;
  networks: number;
  timing: HandshakeTiming | null;
}

/**
 * What the transport's target adds to a handshake from this country, over the
 * timed real-host pairs of the transport's names (the median of the names'
 * medians, each weighted by its timed pairs). `flagged` = at least `TARGET_ADDS_MIN_PAIRS` timed pairs and
 * `TARGET_ADDS_FLAG_MS` or more: a proposal, the owner decides.
 */
export interface TargetAdds {
  ms: number;
  oursMs: number;
  realMs: number;
  pairs: number;
  names: number;
  at: number;
  flagged: boolean;
}

/** Timed pairs the flag needs (the name checks' default `minVantages`). A proposal. */
export const TARGET_ADDS_MIN_PAIRS = 3;

const medianOf = (xs: readonly number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return Math.round(s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2);
};

/**
 * The median of the names' medians, each counted once per timed pair behind
 * it: a name timed from one vantage weighs a third of one timed from three,
 * so a single outlier cannot carry the transport's figure.
 */
const pairWeightedMedian = (xs: ReadonlyArray<{ value: number; pairs: number }>) =>
  medianOf(xs.flatMap((x) => Array.from({ length: Math.max(1, x.pairs) }, () => x.value)));

/** The target leg of one transport, from its names' timed real-host pairs on its own addresses. */
function targetAddsOn(
  prefixes: readonly string[],
  names: ReadonlyArray<{ n: NameInput; f: NameFacts | null }>,
): TargetAdds | null {
  const timed = names
    .map(({ f }) => f?.realHost)
    .filter(
      (r): r is NameRealHost & { timing: HandshakeTiming } =>
        !!r?.timing && prefixes.some((p) => r.target.startsWith(p)),
    );
  if (timed.length === 0) return null;
  const weighted = (pick: (t: HandshakeTiming) => number) =>
    pairWeightedMedian(timed.map((r) => ({ value: pick(r.timing), pairs: r.timing.pairs })));
  const ms = weighted((t) => t.addsMs);
  const pairs = timed.reduce((s, r) => s + r.timing.pairs, 0);
  return {
    ms,
    oursMs: weighted((t) => t.oursMs),
    realMs: weighted((t) => t.realMs),
    pairs,
    names: timed.length,
    at: Math.max(...timed.map((r) => r.at)),
    flagged: pairs >= TARGET_ADDS_MIN_PAIRS && ms >= TARGET_ADDS_FLAG_MS,
  };
}

/** What the real-host controls of the names checked on one address say about it. */
export interface AddressRealHost {
  /** The newest of them. */
  at: number;
  /** Each name's reading, as checked on this address. */
  names: Array<{ name: string; reading: RealHostReading }>;
}

/** The names whose newest real-host batch measured the address with key prefix `prefix`. */
function realHostOn(
  prefix: string,
  names: ReadonlyArray<{ n: NameInput; f: NameFacts | null }>,
): AddressRealHost | null {
  const byName = new Map<string, { name: string; reading: RealHostReading; at: number }>();
  for (const { n, f } of names)
    if (f?.realHost?.target.startsWith(prefix))
      byName.set(n.name, { name: n.name, reading: f.realHost.reading, at: f.realHost.at });
  const hits = [...byName.values()];
  if (hits.length === 0) return null;
  return {
    at: Math.max(...hits.map((h) => h.at)),
    names: hits.map(({ name, reading }) => ({ name, reading })),
  };
}

export interface ListenerInput {
  listenerId: string;
  key: string;
  protocol: string;
  streamTransport: string;
  security: string;
  usable: boolean;
  sniPick: 'hrw1' | null;
  names: readonly NameInput[];
}

export interface OriginInput {
  relayId: string;
  slug: string;
  label: string | null;
  kind: string;
  nodeName: string | null;
  enabled: boolean;
  /** The origin itself, when it opted into probing (`probeNode`). */
  direct: { address: string; reachability: readonly ReachRow[] } | null;
  listeners: readonly ListenerInput[];
  /** Active edges (any publication), for the address rows. */
  edges: readonly EdgeInput[];
  /** The published pool as the assignment sees it (`publishedEdgesOf`, ineligible kept). */
  published: readonly PublishedEdge[];
  /** How the origin walks its pool (`relays.edgePick`); absent = the legacy walk. */
  edgePick?: EdgePickVersion;
}

export interface ViewSettings {
  now: number;
  country: string;
  curated: readonly string[];
  /** `delivery.country.steer`: freedom-family members' addresses ordered by their country. */
  steering: boolean;
  /** `edge.render.enabled`: members of a covered node are handed rendered bodies at all. */
  render: boolean;
  rule: {
    includeBackup: boolean;
    canEmitV6: boolean;
    namesPerEndpoint: number;
    backupNames: number;
  };
  preferDistinctProviders: boolean;
  minProvenForExclusive: number;
  /** Render keys sampled for "handed" (default `HANDED_SAMPLE`). */
  sample?: number;
}

/** Synthetic render keys the "handed" shares are computed over. */
export const HANDED_SAMPLE = 240;

// --- addresses ----------------------------------------------------------------------------------

function reachIn(rows: readonly ReachRow[], country: string): ReachRow | null {
  return rows.find((r) => r.country === country) ?? null;
}

/**
 * The address-level probes alone, from one country: reached = proven; failing
 * while ANOTHER country reaches it = blocked (one that nowhere reaches is
 * broken, not blocked); anything else unknown. Shown, never acted on.
 */
export function probesState(rows: readonly ReachRow[], country: string): ViewState {
  const here = reachIn(rows, country);
  if (!here) return 'unknown';
  if (here.verdict === 'reachable') return 'proven';
  if (here.verdict !== 'unreachable') return 'unknown';
  return rows.some((r) => r.country !== country && r.verdict === 'reachable')
    ? 'blocked'
    : 'unknown';
}

/** What an edge counts as there, and why (see `AddressBasis`). */
export function addressState(
  e: Pick<EdgeInput, 'countryState' | 'evidence' | 'mark' | 'reachability'>,
  country: string,
  now: number,
): { state: ViewState; basis: AddressBasis; until: number | null } {
  const live = e.countryState.find(
    (c) => c.country === country && (c.until === undefined || c.until > now),
  );
  if (live) {
    const until = live.until ?? null;
    if (live.from === 'mark')
      return { state: live.state, basis: e.mark ? 'mark' : 'location_mark', until };
    if (live.from === 'group') return { state: live.state, basis: 'location', until };
    const ev = e.evidence;
    if (live.state === 'blocked' && ev) {
      if (ev.address.state === 'blocked')
        return {
          state: 'blocked',
          basis: ev.address.reason === 'never_reached' ? 'never_reached' : 'checks',
          until,
        };
      if (ev.handshake.state === 'blocked') return { state: 'blocked', basis: 'handshake', until };
    }
    return { state: live.state, basis: 'checks', until };
  }
  const p = probesState(e.reachability, country);
  if (p !== 'unknown' || reachIn(e.reachability, country))
    return { state: p, basis: 'probes', until: null };
  return { state: 'unknown', basis: 'none', until: null };
}

/**
 * The IPv6 path from there, when the edge has one: the round's v6 result, else
 * the probes' by the same rule as `probesState` (failing there is a block only
 * while another country reaches it over IPv6; failing everywhere is broken).
 */
function v6StateOf(e: EdgeInput, country: string): ViewState | null {
  if (!e.addresses.v6 || !e.addresses.v4) return null;
  const r = e.evidence?.lastRound?.v6Result;
  if (r === 'proven' || r === 'blocked') return r;
  const v6 = reachIn(e.reachability, country)?.v6Verdict;
  if (v6 === 'reachable') return 'proven';
  if (
    v6 === 'unreachable' &&
    e.reachability.some((x) => x.country !== country && x.v6Verdict === 'reachable')
  )
    return 'blocked';
  return null;
}

// --- names --------------------------------------------------------------------------------------

/** What a name counts as there, and why (see `NameBasis`). */
export function nameState(
  n: Pick<NameInput, 'blockedIn' | 'provenIn'>,
  facts: NameFacts | null,
  country: string,
): { state: ViewState; basis: NameBasis } {
  // The listener's copy is what selection reads; the mark row says who wrote it.
  const copied: ViewState = n.blockedIn.includes(country)
    ? 'blocked'
    : n.provenIn.includes(country)
      ? 'proven'
      : 'unknown';
  if (copied !== 'unknown')
    return { state: copied, basis: facts?.mark?.source === 'probe' ? 'checks_mark' : 'mark' };
  const s = facts?.checks?.suggestion ?? null;
  if (s) return { state: s, basis: 'checks' };
  return { state: 'unknown', basis: 'none' };
}

/**
 * The state a name counts as for what members are handed: a mark (an
 * operator's or the checks'); a suggestion nobody applied is not judged.
 */
export function actedState(n: { state: ViewState; basis: NameBasis }): ViewState {
  return n.basis === 'checks' ? 'unknown' : n.state;
}

// --- handed -------------------------------------------------------------------------------------

/** The `i`th synthetic render key: 32 hex characters, spread over the pool seed. */
export function sampleKey(i: number): string {
  let out = '';
  for (let k = 0; k < 4; k++)
    out += fnv1a32(`country-view:${i}:${k}`).toString(16).padStart(8, '0');
  return out;
}

export interface Share {
  id: string;
  share: number;
}

export interface Handed {
  /** False when nothing is rendered for this listener (`reason` says why). */
  computed: boolean;
  reason: CountryViewHandedReason | null;
  /** Addresses ordered by this country (steering on): freedom-family members only. */
  steered: boolean;
  /** Names chosen for this country (an `hrw1` listener): freedom-family members only. */
  namesByCountry: boolean;
  sample: number;
  primary: Share[];
  backup: Share[];
  /** Every name handed on the primary endpoint (alternates included), by share of members. */
  names: Share[];
  /** Shares of members with no address at all. */
  none: number;
  /** Members holding an address blocked there, as their first address or their backup. */
  onBlockedAddress: number;
  /** Members whose FIRST address is blocked there (a subset of `onBlockedAddress`). */
  onBlockedFirst: number;
  /** Members holding a server name blocked there, on either address. */
  onBlockedName: number;
}

const round3 = (x: number) => Math.round(x * 1000) / 1000;

function shares(counts: Map<string, number>, n: number): Share[] {
  return [...counts.entries()]
    .map(([id, c]) => ({ id, share: round3(c / n) }))
    .sort((a, b) => b.share - a.share || a.id.localeCompare(b.id));
}

const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);

/**
 * What a freedom-family member in `s.country` is handed on one listener: the
 * pool with every OTHER listener's edges ineligible (a body carrying only this
 * transport), the member's country as their stored one.
 */
export function handedOn(
  origin: Pick<OriginInput, 'enabled' | 'published' | 'edgePick'>,
  listener: Pick<ListenerInput, 'listenerId' | 'sniPick'>,
  s: ViewSettings,
  blockedEdges: ReadonlySet<string>,
  blockedNames: ReadonlySet<string>,
): Handed {
  const n = s.sample ?? HANDED_SAMPLE;
  // Delivery judges per country only a country on the list (a curated one);
  // anywhere else a member gets the universal pool and no steering.
  const listed = s.curated.includes(s.country);
  const base: Handed = {
    computed: false,
    reason: null,
    steered: s.steering && listed,
    namesByCountry: listener.sniPick === 'hrw1' && listed,
    sample: 0,
    primary: [],
    backup: [],
    names: [],
    none: 0,
    onBlockedAddress: 0,
    onBlockedFirst: 0,
    onBlockedName: 0,
  };
  if (!s.render) return { ...base, reason: 'render_off' };
  if (!origin.enabled) return { ...base, reason: 'origin_disabled' };
  const pool = origin.published.map((e) =>
    e.listenerId === listener.listenerId ? e : { ...e, eligible: false },
  );
  if (!pool.some((e) => e.listenerId === listener.listenerId && e.eligible !== false))
    return { ...base, reason: 'no_published' };
  const where: CountryContext = { country: listed ? s.country : null, curated: s.curated };
  const primary = new Map<string, number>();
  const backup = new Map<string, number>();
  const names = new Map<string, number>();
  let none = 0;
  let onBlockedAddress = 0;
  let onBlockedFirst = 0;
  let onBlockedName = 0;
  const namesOf = (e: Assignment['primary']) =>
    e ? [e.sni, ...(e.alternates ?? []).map((x) => x.sni)].filter((x): x is string => !!x) : [];
  for (let i = 0; i < n; i++) {
    const a: Assignment = assignEndpoints(sampleKey(i), pool, {
      now: s.now,
      preferDistinctProviders: s.preferDistinctProviders,
      ...(origin.edgePick ? { edgePick: origin.edgePick } : {}),
      includeBackup: s.rule.includeBackup,
      canEmitV6: s.rule.canEmitV6,
      namesPerEndpoint: s.rule.namesPerEndpoint,
      backupNames: s.rule.backupNames,
      where,
      edgeCountry: s.steering && listed ? s.country : null,
      minProvenForExclusive: s.minProvenForExclusive,
    });
    if (!a.primary) {
      none++;
      continue;
    }
    bump(primary, a.primary.edge.edgeId);
    if (a.backup) bump(backup, a.backup.edge.edgeId);
    const firstBlocked = blockedEdges.has(a.primary.edge.edgeId);
    if (firstBlocked) onBlockedFirst++;
    if (firstBlocked || (a.backup && blockedEdges.has(a.backup.edge.edgeId))) onBlockedAddress++;
    const held = namesOf(a.primary);
    for (const name of new Set(held)) bump(names, name);
    if ([...held, ...namesOf(a.backup)].some((x) => blockedNames.has(x))) onBlockedName++;
  }
  return {
    ...base,
    computed: true,
    sample: n,
    primary: shares(primary, n),
    backup: shares(backup, n),
    names: shares(names, n),
    none: round3(none / n),
    onBlockedAddress: round3(onBlockedAddress / n),
    onBlockedFirst: round3(onBlockedFirst / n),
    onBlockedName: round3(onBlockedName / n),
  };
}

// --- the view -----------------------------------------------------------------------------------

export interface AddressView {
  edgeId: string | null;
  kind: 'edge' | 'origin';
  layer: 'l4' | 'l7';
  provider: string | null;
  location: string | null;
  publication: string | null;
  poolIndex: number | null;
  /** The member-facing address: the hostname of an L7 front, else IPv4, else IPv6. */
  address: string;
  /** The IPv6 address beside an IPv4 one, with its own state from there (null = not known). */
  v6: { address: string; state: ViewState | null } | null;
  state: ViewState;
  basis: AddressBasis;
  until: number | null;
  evidence: {
    mark: { state: 'proven' | 'blocked'; at: number; scope: 'edge' | 'location' } | null;
    grade: EdgeInput['grade'];
    address: EvidenceRow['address'] | null;
    handshake: (Omit<EvidenceRow['handshake'], 'pathBatches'> & { batches: number }) | null;
    round: EvidenceRow['lastRound'] | null;
    probes: ReachRow | null;
    /** The real-host controls of the names checked on it (null: none). */
    realHost: AddressRealHost | null;
  };
  /** Shares of the sampled members holding it as primary / backup. */
  handed: { primary: number; backup: number };
}

export interface NameView {
  name: string;
  family: string | null;
  status: 'active' | 'retired';
  drainUntil: number | null;
  qualified: boolean | null;
  state: ViewState;
  basis: NameBasis;
  markAt: number | null;
  /** A member in this country may be offered it (never a name blocked there on an `hrw1` listener). */
  offered: boolean;
  checks: NameFacts['checks'];
  reports: NameFacts['reports'];
  realHost: NameRealHost | null;
  handed: number;
}

export interface ListenerView {
  listenerId: string;
  key: string;
  protocol: string;
  streamTransport: string;
  security: string;
  usable: boolean;
  addresses: AddressView[];
  names: NameView[];
  members: Handed;
  /** What the transport's target adds to a handshake from there (null: no timed pair). */
  targetAdds: TargetAdds | null;
}

export interface OriginView {
  relayId: string;
  slug: string;
  label: string | null;
  kind: string;
  nodeName: string | null;
  enabled: boolean;
  listeners: ListenerView[];
  /** The origin itself, when it opted into probing (null otherwise). */
  direct: AddressView | null;
  /** Every published address of it is blocked there (or it has none while edges cover it). */
  atRisk: boolean;
}

export interface Totals {
  addresses: Record<ViewState, number>;
  names: Record<ViewState, number>;
  originsAtRisk: number;
  /** The newest piece of evidence of any kind from there (null = none). */
  lastEvidenceAt: number | null;
}

const zero = (): Record<ViewState, number> => ({ proven: 0, blocked: 0, unknown: 0 });

function edgeAddress(e: EdgeInput): string {
  return e.addresses.hostname ?? e.addresses.v4 ?? e.addresses.v6 ?? '';
}

function edgeView(
  e: EdgeInput,
  country: string,
  now: number,
  handed: { primary: Map<string, number>; backup: Map<string, number> },
  realHost: AddressRealHost | null,
): AddressView {
  const st = addressState(e, country, now);
  const v6 = e.addresses.v4 && e.addresses.v6 ? e.addresses.v6 : null;
  const ev = e.evidence;
  return {
    edgeId: e.edgeId,
    kind: 'edge',
    layer: e.layer,
    provider: e.provider,
    location: e.location,
    publication: e.publication,
    poolIndex: e.poolIndex,
    address: edgeAddress(e),
    v6: v6 ? { address: v6, state: v6StateOf(e, country) } : null,
    ...st,
    evidence: {
      mark: e.mark
        ? { ...e.mark, scope: 'edge' }
        : e.locationMark
          ? { ...e.locationMark, scope: 'location' }
          : null,
      grade: e.grade,
      address: ev && ev.address.decidedAt !== undefined ? ev.address : null,
      handshake:
        ev && (ev.handshake.state === 'blocked' || ev.handshake.lastBatchAt !== undefined)
          ? {
              state: ev.handshake.state,
              ...(ev.handshake.reason ? { reason: ev.handshake.reason } : {}),
              ...(ev.handshake.until !== undefined ? { until: ev.handshake.until } : {}),
              ...(ev.handshake.lastBatchAt !== undefined
                ? { lastBatchAt: ev.handshake.lastBatchAt }
                : {}),
              batches: ev.handshake.pathBatches.length,
            }
          : null,
      round: ev?.lastRound ?? null,
      probes: reachIn(e.reachability, country),
      realHost,
    },
    handed: {
      primary: handed.primary.get(e.edgeId) ?? 0,
      backup: handed.backup.get(e.edgeId) ?? 0,
    },
  };
}

function originAddressView(
  d: NonNullable<OriginInput['direct']>,
  country: string,
  realHost: AddressRealHost | null,
): AddressView {
  const probes = reachIn(d.reachability, country);
  const state = probesState(d.reachability, country);
  return {
    edgeId: null,
    kind: 'origin',
    layer: 'l4',
    provider: null,
    location: null,
    publication: null,
    poolIndex: null,
    address: d.address,
    v6: null,
    state,
    basis: probes ? 'probes' : 'none',
    until: null,
    evidence: {
      mark: null,
      grade: null,
      address: null,
      handshake: null,
      round: null,
      probes,
      realHost,
    },
    handed: { primary: 0, backup: 0 },
  };
}

/** Newest timestamp in an address's evidence. */
function newestOf(a: AddressView): number | null {
  const ts = [
    a.evidence.mark?.at,
    a.evidence.address?.decidedAt,
    a.evidence.handshake?.lastBatchAt,
    a.evidence.round?.at,
    a.evidence.probes?.lastAt,
    a.evidence.realHost?.at,
  ].filter((t): t is number => typeof t === 'number');
  return ts.length > 0 ? Math.max(...ts) : null;
}

export interface CountryViewResult {
  origins: OriginView[];
  totals: Totals;
}

/**
 * Build the view of one country. `facts(name)` answers what is known about a
 * name from there (null = nothing). Addresses: published first in pool
 * order, then the other active edges (spares, standbys) by id.
 */
export function buildCountryView(
  origins: readonly OriginInput[],
  facts: (name: string) => NameFacts | null,
  s: ViewSettings,
): CountryViewResult {
  const totals: Totals = {
    addresses: zero(),
    names: zero(),
    originsAtRisk: 0,
    lastEvidenceAt: null,
  };
  const noteAt = (t: number | null | undefined) => {
    if (typeof t === 'number') totals.lastEvidenceAt = Math.max(totals.lastEvidenceAt ?? 0, t);
  };
  const seenNames = new Map<string, ViewState>();
  const out: OriginView[] = [];
  for (const o of origins) {
    const listeners: ListenerView[] = [];
    let published = 0;
    let publishedBlocked = 0;
    for (const l of o.listeners) {
      const edges = o.edges
        .filter((e) => e.listenerId === l.listenerId)
        .sort((a, b) => {
          const pa = a.publication === 'published' ? 0 : 1;
          const pb = b.publication === 'published' ? 0 : 1;
          return (
            pa - pb ||
            (a.poolIndex ?? Infinity) - (b.poolIndex ?? Infinity) ||
            a.edgeId.localeCompare(b.edgeId)
          );
        });
      const blockedEdges = new Set(
        edges
          .filter((e) => addressState(e, s.country, s.now).state === 'blocked')
          .map((e) => e.edgeId),
      );
      const nameViews0 = l.names
        .filter((n) => n.status === 'active' || (n.drainUntil ?? 0) > s.now)
        .map((n) => ({ n, f: facts(n.name) }));
      const blockedNames = new Set(
        nameViews0
          .filter(({ n, f }) => {
            const st = nameState(n, f, s.country);
            return st.state === 'blocked' && st.basis !== 'checks';
          })
          .map(({ n }) => n.name),
      );
      const members = handedOn(o, l, s, blockedEdges, blockedNames);
      const primaryShare = new Map(members.primary.map((x) => [x.id, x.share]));
      const backupShare = new Map(members.backup.map((x) => [x.id, x.share]));
      const nameShare = new Map(members.names.map((x) => [x.id, x.share]));
      const addresses = edges.map((e) =>
        edgeView(
          e,
          s.country,
          s.now,
          { primary: primaryShare, backup: backupShare },
          realHostOn(`edge:${e.edgeId}:`, nameViews0),
        ),
      );
      for (const a of addresses) {
        if (a.publication === 'published') {
          totals.addresses[a.state]++;
          published++;
          if (a.state === 'blocked') publishedBlocked++;
        }
        noteAt(newestOf(a));
      }
      const names: NameView[] = nameViews0.map(({ n, f }) => {
        const st = nameState(n, f, s.country);
        const offered =
          n.status === 'active' && (l.sniPick !== 'hrw1' || !n.blockedIn.includes(s.country));
        if (n.status === 'active' && !seenNames.has(n.name)) seenNames.set(n.name, actedState(st));
        noteAt(f?.mark?.at);
        noteAt(f?.checks?.lastAt);
        noteAt(f?.realHost?.at);
        return {
          name: n.name,
          family: f?.family ?? null,
          status: n.status,
          drainUntil: n.drainUntil ?? null,
          qualified: f?.qualified ?? null,
          ...st,
          markAt: f?.mark?.at ?? null,
          offered,
          checks: f?.checks ?? null,
          reports: f?.reports ?? null,
          realHost: f?.realHost ?? null,
          handed: nameShare.get(n.name) ?? 0,
        };
      });
      listeners.push({
        listenerId: l.listenerId,
        key: l.key,
        protocol: l.protocol,
        streamTransport: l.streamTransport,
        security: l.security,
        usable: l.usable,
        addresses,
        names,
        members,
        // Its names measured on its own addresses (an edge of it, or the origin itself).
        targetAdds: targetAddsOn(
          [...edges.map((e) => `edge:${e.edgeId}:`), `relay:${o.relayId}:`],
          nameViews0,
        ),
      });
    }
    const direct = o.direct
      ? originAddressView(
          o.direct,
          s.country,
          realHostOn(
            `relay:${o.relayId}:`,
            o.listeners.flatMap((l) => l.names.map((n) => ({ n, f: facts(n.name) }))),
          ),
        )
      : null;
    if (direct) noteAt(newestOf(direct));
    const atRisk = o.enabled && published > 0 && publishedBlocked === published;
    if (atRisk) totals.originsAtRisk++;
    out.push({
      relayId: o.relayId,
      slug: o.slug,
      label: o.label,
      kind: o.kind,
      nodeName: o.nodeName,
      enabled: o.enabled,
      listeners,
      direct,
      atRisk,
    });
  }
  for (const st of seenNames.values()) totals.names[st]++;
  return { origins: out, totals };
}
