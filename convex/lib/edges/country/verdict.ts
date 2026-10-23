/**
 * Checks of an edge from each censored country (pure; unit-tested).
 * docs/edges.md "Countries: checks and delivery".
 *
 * A ROUND is the runs one request made for one edge: every enabled source,
 * every listener port, every address family. Each external run also asked a
 * few uncensored CONTROL countries in the same measurement, and FCP's own
 * internal check is one more control. A round says, per checked country:
 *
 *   proven   enough vantages on enough networks reached the edge (and, where
 *            TLS applies, FCP's own TLS check with the real name passed);
 *   blocked  every vantage with evidence failed, the spread is met, and the
 *            controls reached the edge in the same round;
 *   down     every vantage failed but the controls did not work either: the
 *            edge is broken, not blocked;
 *   unknown  too few vantages or networks, or a mixed answer.
 *
 * A source that ERRORS is no evidence: a failed or timed-out run adds nothing,
 * and thin evidence is `unknown`, never `blocked`.
 *
 * Two tracks per (edge, country) are kept apart: the ADDRESS track (rounds,
 * with hysteresis) and the HANDSHAKE track (#126 name batches in which no
 * name got through, each paired with a working TCP reading of the same
 * address). A TCP round never clears a handshake block: both succeed while a
 * country blocks every name on the address.
 */
import type { ProbeProtocol } from '../probes/types';
import type { NameOutcome } from '../probes/nameCheck';
import { NAME_FAILURES } from '../sni/vantage';

export type RoundResult = 'proven' | 'blocked' | 'down' | 'unknown';
/** What the in-country vantages alone say about the path (pairing reads it). */
export type TcpReading = 'works' | 'fails' | 'thin' | 'mixed';
export type PathFamily = 4 | 6 | 'name';
export type TrackState = 'proven' | 'blocked' | 'unknown';

export interface CountryCheckConfig {
  minProbes: number;
  minNetworks: number;
  minControls: number;
}

export interface RoundRunResult {
  country: string;
  asn?: string;
  network?: string;
  ok: boolean;
  control?: boolean;
}

/** One run of a round, as the verdict needs it. */
export interface RoundRun {
  source: string;
  status: 'requested' | 'running' | 'finished' | 'failed' | 'timeout';
  family: PathFamily;
  port: number;
  /** What was dialled (an IP literal or a name). */
  address: string;
  probeProtocol: ProbeProtocol;
  results: ReadonlyArray<RoundRunResult>;
}

export interface PathVerdict {
  family: PathFamily;
  port: number;
  address: string;
  result: RoundResult;
  reason: string | null;
  tcp: TcpReading;
  ok: number;
  fail: number;
  networks: number;
  controlsOk: number;
}

export interface RoundVerdict {
  result: RoundResult;
  reason: string | null;
  ok: number;
  fail: number;
  networks: number;
  controlsOk: number;
  /** The IPv6 path's result when the round also measured one beside IPv4. */
  v6Result?: RoundResult;
  paths: PathVerdict[];
}

/** Failures above this share of the evidence, with some vantage working, are a mixed answer. */
export const MIXED_SHARE = 1 / 3;

/**
 * A vantage's network, normalized (`AS13335`, or a lower-cased network name),
 * or null when the source did not say. A vantage without one never adds a
 * network: a measurement service is no evidence that its probes sit in
 * distinct networks, so missing metadata cannot manufacture the spread.
 */
export function networkIdOf(r: { asn?: string; network?: string }): string | null {
  const digits = r.asn?.trim().replace(/^as/i, '');
  if (digits && /^\d+$/.test(digits)) return `AS${Number(digits)}`;
  const net = r.network?.trim().toLowerCase();
  return net ? `net:${net}` : null;
}

const distinctNetworks = (rows: ReadonlyArray<{ asn?: string; network?: string }>) =>
  new Set(rows.map(networkIdOf).filter((n): n is string => n !== null)).size;
const isTls = (p: ProbeProtocol) => p === 'tls' || p === 'tls-sni' || p === 'https';
const settled = (r: RoundRun) => r.status === 'finished';

/**
 * One path (family, port) from one country. `tlsApplies`: the edge presents a
 * name (an L7 front, or an L4 edge in front of a REALITY / TLS listener), so
 * `proven` also needs FCP's own TLS check with the real name.
 */
export function pathVerdict(
  runs: readonly RoundRun[],
  country: string,
  cfg: CountryCheckConfig,
  tlsApplies: boolean,
): PathVerdict {
  const first = runs[0];
  const external = runs.filter((r) => settled(r) && r.source !== 'internal');
  const internal = runs.filter((r) => settled(r) && r.source === 'internal');
  const inCountry = external.flatMap((r) =>
    r.results.filter((x) => !x.control && x.country === country),
  );
  const okRows = inCountry.filter((x) => x.ok);
  const ok = okRows.length;
  const fail = inCountry.length - ok;
  const networks = distinctNetworks(inCountry);
  const okNetworks = distinctNetworks(okRows);
  const controlsOk =
    external.reduce((n, r) => n + r.results.filter((x) => x.control && x.ok).length, 0) +
    (internal.some((r) => r.results.some((x) => x.ok)) ? 1 : 0);
  const total = ok + fail;
  const thin = total < cfg.minProbes || networks < cfg.minNetworks;
  const tcp: TcpReading = thin
    ? 'thin'
    : ok === 0
      ? 'fails'
      : fail / total > MIXED_SHARE
        ? 'mixed'
        : ok >= cfg.minProbes && okNetworks >= cfg.minNetworks
          ? 'works'
          : 'thin';
  let result: RoundResult;
  let reason: string | null = null;
  if (tcp === 'thin') {
    result = 'unknown';
    reason = total === 0 ? 'no_evidence' : 'too_few';
  } else if (tcp === 'mixed') {
    result = 'unknown';
    reason = 'mixed';
  } else if (tcp === 'fails') {
    if (controlsOk >= cfg.minControls) result = 'blocked';
    else {
      result = 'down';
      reason = 'controls_failed';
    }
  } else if (!tlsApplies) {
    result = 'proven';
  } else {
    const tlsRuns = internal.filter((r) => isTls(r.probeProtocol));
    if (tlsRuns.some((r) => r.results.length > 0 && r.results.every((x) => x.ok))) {
      result = 'proven';
    } else {
      result = 'unknown';
      reason = tlsRuns.some((r) => r.results.length > 0) ? 'tls_failed' : 'tls_unchecked';
    }
  }
  return {
    family: first?.family ?? 4,
    port: first?.port ?? 0,
    address: first?.address ?? '',
    result,
    reason,
    tcp,
    ok,
    fail,
    networks,
    controlsOk,
  };
}

const RANK: Record<RoundResult, number> = { proven: 0, unknown: 1, down: 2, blocked: 3 };

/** The worst of several paths: one blocked listener port blocks the slot. */
export function worstPath(paths: readonly PathVerdict[]): PathVerdict | null {
  let worst: PathVerdict | null = null;
  for (const p of paths) if (!worst || RANK[p.result] > RANK[worst.result]) worst = p;
  return worst;
}

/**
 * One round from one country. The result follows the IPv4 paths (what every
 * member is handed), or the name paths of an L7 front, or IPv6 when that is
 * all the edge has; the IPv6 path beside IPv4 is reported as `v6Result`.
 */
export function roundVerdict(
  runs: readonly RoundRun[],
  country: string,
  cfg: CountryCheckConfig,
  tlsApplies: boolean,
): RoundVerdict {
  const groups = new Map<string, RoundRun[]>();
  for (const r of runs) {
    const k = `${r.family}|${r.port}`;
    groups.set(k, [...(groups.get(k) ?? []), r]);
  }
  const paths = [...groups.values()].map((g) => pathVerdict(g, country, cfg, tlsApplies));
  const ofFamily = (f: PathFamily) => paths.filter((p) => p.family === f);
  const primary = ofFamily(4).length > 0 ? 4 : ofFamily('name').length > 0 ? 'name' : 6;
  const worst = worstPath(ofFamily(primary));
  const v6 = primary !== 6 ? worstPath(ofFamily(6)) : null;
  if (!worst)
    return {
      result: 'unknown',
      reason: 'no_evidence',
      ok: 0,
      fail: 0,
      networks: 0,
      controlsOk: 0,
      paths,
    };
  return {
    result: worst.result,
    reason: worst.reason,
    ok: worst.ok,
    fail: worst.fail,
    networks: worst.networks,
    controlsOk: worst.controlsOk,
    ...(v6 ? { v6Result: v6.result } : {}),
    paths,
  };
}

// --- the address track -------------------------------------------------------------------------

export interface AddressTrack {
  state: TrackState;
  reason?: string;
  /** The last round that decided or re-confirmed the state; absent = never decided. */
  decidedAt?: number;
  until?: number;
  blockedRounds: number;
  lastBlockedAt?: number;
  repeatAt?: number;
}

export const EMPTY_ADDRESS_TRACK: AddressTrack = { state: 'unknown', blockedRounds: 0 };

export interface AddressTrackOptions {
  /** Blocked rounds needed before a proven (or undecided) edge counts as blocked. */
  blockedRounds: number;
  windowMs: number;
  /** Two blocked rounds closer than this are one look. */
  repeatMs: number;
  /** The edge's group is already blocked in this country. */
  groupBlocked: boolean;
  /** The country-wide guard holds new blocks there. */
  countryWideHold: boolean;
  /**
   * The address has never been reached from there and is held unreachable long
   * enough while another address of its node is reached from there
   * (lib/edges/probes/verdict.ts `sustainedCountries`): blocked without a
   * repeat, on any round that is not `proven` or `down`.
   */
  sustained?: boolean;
}

const strip = <T extends object>(o: T, ...keys: Array<keyof T>): T => {
  const out = { ...o };
  for (const k of keys) delete out[k];
  return out;
};

/**
 * The address track after one round. The newest DECIDED result stands;
 * `unknown` and `down` never override it (hysteresis, so a thin country does
 * not flap members). proven -> blocked needs `blockedRounds` blocked rounds at
 * least `repeatMs` apart (the repeat is scheduled); blocked -> proven takes one
 * round. A never-decided edge whose group is already blocked there is blocked
 * on its first round. A `sustained` one (never reached from there, for hours,
 * while the node's other addresses are) is blocked on a blocked or an
 * undecided round, and stays blocked while it holds; a `down` round (the
 * controls failed too) never makes it a block.
 */
export function nextAddressTrack(
  prev: AddressTrack,
  round: { result: RoundResult; reason: string | null; at: number },
  o: AddressTrackOptions,
): AddressTrack {
  const { at } = round;
  if (round.result === 'proven')
    return { state: 'proven', decidedAt: at, until: at + o.windowMs, blockedRounds: 0 };
  const sustained = o.sustained === true && round.result !== 'down';
  if (round.result === 'blocked' || sustained) {
    if (o.countryWideHold)
      return { ...strip(prev, 'repeatAt'), reason: 'country_wide' } satisfies AddressTrack;
    if (prev.state === 'blocked')
      return {
        ...strip(prev, 'repeatAt'),
        reason: prev.reason ?? 'blocked',
        decidedAt: at,
        until: at + o.windowMs,
        ...(round.result === 'blocked'
          ? { blockedRounds: prev.blockedRounds + 1, lastBlockedAt: at }
          : {}),
      };
    if (round.result !== 'blocked')
      return {
        ...strip(prev, 'repeatAt'),
        state: 'blocked',
        reason: 'never_reached',
        decidedAt: at,
        until: at + o.windowMs,
      };
    const counts =
      prev.blockedRounds === 0 ||
      prev.lastBlockedAt === undefined ||
      at - prev.lastBlockedAt >= o.repeatMs;
    const blockedRounds = counts ? prev.blockedRounds + 1 : prev.blockedRounds;
    const lastBlockedAt = counts ? at : prev.lastBlockedAt!;
    const inherited = prev.decidedAt === undefined && o.groupBlocked;
    if (blockedRounds >= o.blockedRounds || inherited || sustained)
      return {
        state: 'blocked',
        reason:
          blockedRounds >= o.blockedRounds
            ? 'blocked'
            : sustained
              ? 'never_reached'
              : 'group_blocked',
        decidedAt: at,
        until: at + o.windowMs,
        blockedRounds,
        lastBlockedAt,
      };
    return {
      ...prev,
      reason: 'needs_repeat',
      blockedRounds,
      lastBlockedAt,
      repeatAt: lastBlockedAt + o.repeatMs,
    };
  }
  // unknown / down: a decided state stands; an undecided one says why. A
  // repeat that came back without an answer is not asked again at once: the
  // regular cadence goes on, and the blocked rounds counted so far still count.
  const next: AddressTrack = strip(prev, 'repeatAt');
  return prev.state === 'unknown' ? { ...next, reason: round.reason ?? undefined } : next;
}

/** A decided address state past its `until` lapses to unknown (`expired`). */
export function expireAddressTrack(prev: AddressTrack, now: number): AddressTrack {
  if (prev.state === 'unknown' || prev.until === undefined || prev.until > now) return prev;
  return {
    state: 'unknown',
    reason: 'expired',
    ...(prev.decidedAt !== undefined ? { decidedAt: prev.decidedAt } : {}),
    blockedRounds: 0,
  };
}

// --- the handshake track -----------------------------------------------------------------------

export interface HandshakeTrack {
  state: 'blocked' | 'none';
  reason?: string;
  decidedAt?: number;
  until?: number;
  /** When the paired `path` batches that count towards a block finished. */
  pathBatches: number[];
  lastBatchAt?: number;
}

export const EMPTY_HANDSHAKE_TRACK: HandshakeTrack = { state: 'none', pathBatches: [] };

/** What one finished name batch says about its address from its country. */
export type BatchReading = 'path' | 'recovery' | 'none';

const MAX_PATH_BATCHES = 10;

/**
 * The handshake track after one name batch. A `path` batch (no name got
 * through) counts only when PAIRED with a working TCP reading of the same
 * address; two such batches at least `repeatMs` apart block (one when the
 * group is already blocked there). It clears ONLY by recovery (names reached
 * the address from enough vantages), expiry or a mark: a TCP round never
 * clears it.
 */
export function nextHandshakeTrack(
  prev: HandshakeTrack,
  b: { reading: BatchReading; at: number; paired: boolean },
  o: { windowMs: number; repeatMs: number; groupBlocked: boolean },
): HandshakeTrack {
  const { at } = b;
  if (b.reading === 'none') return { ...prev, lastBatchAt: at };
  if (b.reading === 'recovery')
    return { state: 'none', reason: 'recovered', pathBatches: [], lastBatchAt: at };
  if (!b.paired) return { ...prev, reason: 'no_tcp_pairing', lastBatchAt: at };
  const inWindow = prev.pathBatches.filter((t) => at - t <= o.windowMs);
  const last = inWindow.length > 0 ? Math.max(...inWindow) : null;
  const pathBatches = (
    last === null || at - last >= o.repeatMs ? [...inWindow, at] : inWindow
  ).slice(-MAX_PATH_BATCHES);
  if (prev.state === 'blocked' || pathBatches.length >= 2 || o.groupBlocked)
    return {
      state: 'blocked',
      reason: 'handshake',
      decidedAt: at,
      until: at + o.windowMs,
      pathBatches,
      lastBatchAt: at,
    };
  return { ...prev, reason: 'needs_repeat', pathBatches, lastBatchAt: at };
}

export function expireHandshakeTrack(prev: HandshakeTrack, now: number): HandshakeTrack {
  if (prev.state !== 'blocked' || prev.until === undefined || prev.until > now) return prev;
  return {
    state: 'none',
    reason: 'expired',
    pathBatches: [],
    ...(prev.lastBatchAt !== undefined ? { lastBatchAt: prev.lastBatchAt } : {}),
  };
}

/** Blocked if either track is; proven only when the address is and the handshake is not blocked. */
export function combinedState(a: AddressTrack, h: HandshakeTrack): TrackState {
  if (a.state === 'blocked' || h.state === 'blocked') return 'blocked';
  return a.state === 'proven' ? 'proven' : 'unknown';
}

/**
 * How long the COMBINED state itself holds, for every copy of it (the edge's
 * `countryState`, the group grade): a block while ANY blocking track still
 * does (the latest of them), a proof while the address proof does. This is not
 * the expiry worker's clock (`trackUntil`, the earliest decided track): an
 * address proof lapsing must not end a handshake block that still stands.
 */
export function stateUntil(a: AddressTrack, h: HandshakeTrack): number | undefined {
  const state = combinedState(a, h);
  if (state === 'proven') return a.until;
  if (state !== 'blocked') return undefined;
  const xs = [
    a.state === 'blocked' ? a.until : undefined,
    h.state === 'blocked' ? h.until : undefined,
  ].filter((x): x is number => x !== undefined);
  return xs.length > 0 ? Math.max(...xs) : undefined;
}

/** The earliest expiry among the decided tracks (the expiry worker's clock). */
export function trackUntil(a: AddressTrack, h: HandshakeTrack): number | undefined {
  const xs = [
    a.state !== 'unknown' ? a.until : undefined,
    h.state === 'blocked' ? h.until : undefined,
  ].filter((x): x is number => x !== undefined);
  return xs.length > 0 ? Math.min(...xs) : undefined;
}

// --- reading a name batch ----------------------------------------------------------------------

export interface BatchMeasurement {
  name: string;
  /** The service that measured it: one source's names are measured from the same probes. */
  source: string;
  results: ReadonlyArray<{ asn?: string; network?: string; outcome: NameOutcome }>;
}

const reached = (o: NameOutcome) => o === 'ok' || o === 'answered';

/**
 * Distinct vantages behind the results that `pick` keeps. Every name of a
 * batch is measured from the SAME probes of a source (sniVantageOps), so the
 * count is, per source, the most any one name got, summed over the sources:
 * adding names to a batch can never make more vantages out of the same probes.
 */
function batchVantages(
  measurements: readonly BatchMeasurement[],
  pick: (o: NameOutcome) => boolean,
): number {
  const bySource = new Map<string, number>();
  for (const m of measurements) {
    const n = m.results.filter((r) => pick(r.outcome)).length;
    bySource.set(m.source, Math.max(bySource.get(m.source) ?? 0, n));
  }
  return [...bySource.values()].reduce((a, b) => a + b, 0);
}

/**
 * One finished batch (every source settled) of names on one address from one
 * country: `path` when no name got through at all and the failures look like
 * interference from enough vantages on enough networks; `recovery` when names
 * reached the address from enough vantages on enough networks; else `none`.
 */
export function batchReading(
  measurements: readonly BatchMeasurement[],
  o: { minVantages: number; minNetworks: number },
): { reading: BatchReading; vantages: number; networks: number } {
  const all = measurements.flatMap((m) => m.results);
  const ok = all.filter((r) => reached(r.outcome));
  if (ok.length > 0) {
    const vantages = batchVantages(measurements, reached);
    const networks = distinctNetworks(ok);
    const reading = vantages >= o.minVantages && networks >= o.minNetworks ? 'recovery' : 'none';
    return { reading, vantages, networks };
  }
  const failing = all.filter((r) => NAME_FAILURES.has(r.outcome));
  const vantages = batchVantages(measurements, (x) => NAME_FAILURES.has(x));
  const networks = distinctNetworks(failing);
  const reading =
    vantages >= o.minVantages && networks >= o.minNetworks ? ('path' as const) : 'none';
  return { reading, vantages, networks };
}
