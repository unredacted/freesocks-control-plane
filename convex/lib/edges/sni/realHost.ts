/**
 * Real-host controls (pure; unit-tested), docs/edges.md "Real-host controls".
 *
 * A check from inside a country presents a server name to one of FCP's own
 * addresses. Its control here is the same name presented to the name's REAL
 * site (its public DNS answer), from the same vantage, in the same batch. Read
 * together, per vantage:
 *
 *  - both work                                    -> `works`
 *  - both fail                                    -> `name_blocked` (the name is blocked
 *                                                    wherever it goes)
 *  - the real site works, ours fails to connect   -> `address_blocked` (our address)
 *  - the real site works, ours connects but the
 *    handshake with the name fails or resets      -> `ip_name_match` (the censor likely checks
 *                                                    the name against its real address or network)
 *  - the real site fails, ours works              -> `ours_only` (the real site's address is
 *                                                    blocked, the name passes on ours)
 *  - anything else                                -> `inconclusive`
 *
 * "Both fail" counts only from a vantage that got through for something else
 * in the batch (another name, or a real site): a vantage that reaches nothing
 * says nothing. Where the source did not say at which stage ours failed, a
 * working or failing TCP reading of our address from that country (the
 * per-country checks' newest path reading, paired in time) decides the stage.
 * The reading is evidence only: nothing here changes a mark or a grade.
 */
import type { NameOutcome, NameStage } from '../probes/nameCheck';
import type { RealHostPair, RealHostReading } from '../../../../src/shared/contracts/edgeCodes';
import { networkOf } from './vantage';

export type { RealHostPair, RealHostReading };

export interface PairReading {
  asn?: string;
  network?: string;
  outcome: NameOutcome;
  stage?: NameStage;
  vantage?: string;
  /** Phase timings: the TCP connect, and the TLS handshake after it. */
  tcpMs?: number;
  tlsMs?: number;
}

/** One stored measurement of a batch, ours or the real site's. */
export interface PairMeasurement {
  name: string;
  source: string;
  role: 'ours' | 'real';
  /** A real-site measurement: the address its vantages dialled. */
  realAddress?: string;
  results: readonly PairReading[];
}

/** The path was open for that name: a completed handshake, or an answer without TLS details. */
const reached = (o: NameOutcome) => o === 'ok' || o === 'answered';
/** What a censor's interference looks like (a refusal included: an RST to the SYN). */
const failed = (o: NameOutcome) =>
  o === 'reset' || o === 'timeout' || o === 'cert_mismatch' || o === 'refused';

/**
 * Where OUR check failed: as reported, else from the TCP reading of the
 * address there. A failure after the handshake (`response`: TLS completed,
 * then no answer) is neither: the name got through, so it says nothing here.
 */
function oursStage(r: PairReading, tcp: 'works' | 'fails' | null): 'connect' | 'handshake' | null {
  if (r.outcome === 'refused') return 'connect';
  if (r.outcome === 'cert_mismatch') return 'handshake';
  if (r.stage === 'connect') return 'connect';
  if (r.stage === 'handshake') return 'handshake';
  if (r.stage === 'response') return null;
  if (tcp === 'works') return 'handshake';
  if (tcp === 'fails') return 'connect';
  return null;
}

/** One vantage's pair, read. `reachedElse`: that vantage got through for something else in the batch. */
export function pairClass(
  ours: PairReading,
  real: PairReading,
  o: { reachedElse: boolean; tcp: 'works' | 'fails' | null },
): RealHostPair {
  if (reached(ours.outcome) && reached(real.outcome)) return 'works';
  if (reached(ours.outcome) && failed(real.outcome)) return 'ours_only';
  if (failed(ours.outcome) && failed(real.outcome))
    return o.reachedElse ? 'name_blocked' : 'inconclusive';
  if (reached(real.outcome) && failed(ours.outcome)) {
    const stage = oursStage(ours, o.tcp);
    if (stage === 'connect') return 'address_blocked';
    if (stage === 'handshake') return 'ip_name_match';
  }
  return 'inconclusive';
}

export interface PairCounts {
  works: number;
  nameBlocked: number;
  addressBlocked: number;
  ipNameMatch: number;
  oursOnly: number;
  inconclusive: number;
}

const COUNT_KEY: Record<RealHostPair, keyof PairCounts> = {
  works: 'works',
  name_blocked: 'nameBlocked',
  address_blocked: 'addressBlocked',
  ip_name_match: 'ipNameMatch',
  ours_only: 'oursOnly',
  inconclusive: 'inconclusive',
};

export const EMPTY_COUNTS: PairCounts = {
  works: 0,
  nameBlocked: 0,
  addressBlocked: 0,
  ipNameMatch: 0,
  oursOnly: 0,
  inconclusive: 0,
};

export interface RealHostSummary {
  reading: RealHostReading;
  counts: PairCounts;
  /** Decisive pairs (every class but `inconclusive`) and the distinct networks among them. */
  vantages: number;
  networks: number;
  /** The real site's address every pair of this reading dialled (null: not recorded). */
  realAddress: string | null;
  /** What the handshakes took beyond their TCP connect (null: no timed pair). See `timingOf`. */
  timing: HandshakeTiming | null;
}

/**
 * Handshake timing from one vantage, both handshakes completed. The TLS phase
 * (after the TCP connect) of the real site is about one round trip
 * (ClientHello to ServerHello) plus the site's own work, and the TCP connect
 * stands in for that round trip. FCP's REALITY address hands an
 * unauthenticated handshake through the node to the transport's target, so
 * its TLS phase also carries the node-to-target round trip. "Beyond one round
 * trip" = TLS phase minus TCP connect, per side; the per-vantage difference is
 * what the target adds, which a censor can measure as well as FCP can.
 */
export interface HandshakeTiming {
  /** Timed pairs the medians rest on. */
  pairs: number;
  /** Median handshake time beyond one round trip: FCP's address, the real site. */
  oursMs: number;
  realMs: number;
  /** Median per-vantage difference (ours minus real): what the target adds. */
  addsMs: number;
}

/** A proposal (the owner decides): what the target adds before it reads as a tell. */
export const TARGET_ADDS_FLAG_MS = 50;

function median(xs: readonly number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return Math.round(s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2);
}

/** The TLS phase beyond one round trip (the TCP connect), when both phases were measured. */
function beyondRoundTrip(r: PairReading): number | null {
  return r.tcpMs !== undefined && r.tlsMs !== undefined ? r.tlsMs - r.tcpMs : null;
}

/** Timing over the pairs of one reading that both completed with phase timings. */
export function timingOf(pairs: ReadonlyArray<[PairReading, PairReading]>): HandshakeTiming | null {
  const ours: number[] = [];
  const real: number[] = [];
  const adds: number[] = [];
  for (const [a, b] of pairs) {
    if (!reached(a.outcome) || !reached(b.outcome)) continue;
    const x = beyondRoundTrip(a);
    const y = beyondRoundTrip(b);
    if (x === null || y === null) continue;
    ours.push(x);
    real.push(y);
    adds.push(x - y);
  }
  if (adds.length === 0) return null;
  return { pairs: adds.length, oursMs: median(ours), realMs: median(real), addsMs: median(adds) };
}

/** A majority needs this share of the decisive pairs. */
const MAJORITY = 2 / 3;

/** Counts -> a reading: thin below the floors, the class holding two thirds, else mixed. */
export function readingOf(
  counts: PairCounts,
  networks: number,
  o: { minVantages: number; minNetworks: number },
): RealHostReading {
  const decisive: Array<[RealHostReading, number]> = [
    ['works', counts.works],
    ['name_blocked', counts.nameBlocked],
    ['address_blocked', counts.addressBlocked],
    ['ip_name_match', counts.ipNameMatch],
    ['ours_only', counts.oursOnly],
  ];
  const total = decisive.reduce((s, [, n]) => s + n, 0);
  if (total < o.minVantages || networks < o.minNetworks) return 'thin';
  const [top, n] = [...decisive].sort((a, b) => b[1] - a[1])[0]!;
  return n >= total * MAJORITY ? top : 'mixed';
}

/** Pair one source's readings of `name`: by vantage key, else by network, in order. */
function pairsOf(
  ours: readonly PairReading[],
  real: readonly PairReading[],
): Array<[PairReading, PairReading]> {
  const out: Array<[PairReading, PairReading]> = [];
  const left = [...real];
  for (const r of ours) {
    let i = r.vantage ? left.findIndex((x) => x.vantage === r.vantage) : -1;
    if (i < 0 && !r.vantage) i = left.findIndex((x) => !x.vantage && networkOf(x) === networkOf(r));
    if (i < 0) continue;
    out.push([r, left[i]!]);
    left.splice(i, 1);
  }
  return out;
}

/**
 * What one batch says about `name` from its real-host pairs. Each source
 * resolves the real site on its own, so sources that dialled DIFFERENT real
 * addresses are never pooled: the reading is that of the address whose pairs
 * are the most decisive (ties: the address first in order). Null when the
 * batch holds no real-site check of the name (nothing to read).
 */
export function readRealHost(
  name: string,
  batch: readonly PairMeasurement[],
  o: { minVantages: number; minNetworks: number; tcp: 'works' | 'fails' | null },
): RealHostSummary | null {
  const reals = batch.filter((m) => m.role === 'real' && m.name === name);
  if (reals.length === 0) return null;
  const bySite = new Map<string, Set<string>>();
  for (const m of reals) {
    const site = m.realAddress ?? '';
    bySite.set(site, (bySite.get(site) ?? new Set()).add(m.source));
  }
  let best: RealHostSummary | null = null;
  for (const [site, sources] of [...bySite.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const s = readSources(name, batch, sources, site || null, o);
    if (!best || s.vantages > best.vantages) best = s;
  }
  return best;
}

/** The pairs of `name` from these sources only (one real address), read. */
function readSources(
  name: string,
  batch: readonly PairMeasurement[],
  sources: ReadonlySet<string>,
  realAddress: string | null,
  o: { minVantages: number; minNetworks: number; tcp: 'works' | 'fails' | null },
): RealHostSummary {
  const counts: PairCounts = { ...EMPTY_COUNTS };
  const networks = new Set<string>();
  const all: Array<[PairReading, PairReading]> = [];
  for (const source of sources) {
    const of = batch.filter((m) => m.source === source);
    const ours = of.filter((m) => m.role === 'ours' && m.name === name).flatMap((m) => m.results);
    const real = of.filter((m) => m.role === 'real' && m.name === name).flatMap((m) => m.results);
    // Which vantages (or networks, without a key) got through for anything else in the batch.
    const elsewhere = of
      .filter((m) => m.name !== name)
      .flatMap((m) => m.results)
      .filter((r) => reached(r.outcome));
    const pairs = pairsOf(ours, real);
    all.push(...pairs);
    for (const [a, b] of pairs) {
      const reachedElse = elsewhere.some((x) =>
        a.vantage && x.vantage ? x.vantage === a.vantage : networkOf(x) === networkOf(a),
      );
      const c = pairClass(a, b, { reachedElse, tcp: o.tcp });
      counts[COUNT_KEY[c]]++;
      // A vantage that names neither an ASN nor a network adds a pair, never a network.
      const net = networkOf(a);
      if (c !== 'inconclusive' && net !== 'unknown') networks.add(net);
    }
  }
  const vantages =
    counts.works +
    counts.nameBlocked +
    counts.addressBlocked +
    counts.ipNameMatch +
    counts.oursOnly;
  return {
    reading: readingOf(counts, networks.size, o),
    counts,
    vantages,
    networks: networks.size,
    realAddress,
    timing: timingOf(all),
  };
}
