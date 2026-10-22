/**
 * What the probe evidence says about an L4 edge (docs/edges.md § "Publication"
 * and § "Probe sources and verdicts"). Evidence is read PER ADDRESS FAMILY,
 * and each family is one of:
 *
 *   refused  real evidence about the address: an outside source agreed it is
 *            unreachable over that family (sourceVerdict's agreement rule),
 *            or FCP's own protocol-shape check over it failed;
 *   reached  some source connected over it, and none refused;
 *   unknown  every source settled without being able to test it (FCP's host
 *            has no route for the family, a service takes no IPv6 literal, a
 *            refused or timed-out measurement). Never "refused": a run that
 *            could not test leaves no result (probes/types.ts `RunOutcome`);
 *   pending  evidence may still come.
 *
 * Two readings of it:
 *
 *   partialRungFor   the edge's `partial` rung (refreshPartialRung): provider
 *                    health + ≥ agreementVantages distinct outside vantages
 *                    reachable + a passing shape check over one family, and no
 *                    family refused. Three rungs exist: `partial` (this),
 *                    `verified` (ONLY by a human, per endpoint:
 *                    lib/edges/verification.ts), `unreachable`.
 *   outsideCheckFor  the guided run's stage 4: once its own round settled, an
 *                    address passes when a family was reached and none refused;
 *                    a family nothing could test is reported (`notChecked`),
 *                    never failed.
 *
 * The shape check is `tls-sni` for a REALITY / TLS listener, bare `tcp` for a
 * plaintext one. `partial` is the CEILING here: a forwarder aimed at the
 * camouflage site passes `tls-sni` (it presents the camouflage target's own
 * certificate), and any TCP answer passes `tcp`. Nothing here is authentication
 * evidence, so no code path in this module (or anywhere server-side) ever
 * returns `verified` for an L4 edge.
 *
 * Pure: takes the rows, returns a word.
 */
import { runOutcome, type AddressFamily, type ProbeProtocol } from './probes/types';

export type PartialRung = 'partial' | 'unreachable' | 'pending';

export interface RungListenerLike {
  security: 'none' | 'tls' | 'reality';
}

export interface RungReachabilityRow {
  country: string;
  source: string;
  verdict: 'reachable' | 'unreachable' | 'mixed' | 'unknown';
  port?: number;
  /** The observed family; absent on a legacy IPv4 row (or a name, `addressKind: 'name'`). */
  ipVersion?: 4 | 6;
  addressKind?: 'ip' | 'name';
  /** Vantages that connected (one alone leaves the source verdict `unknown`, still a reach). */
  okCount?: number;
}

export interface RungProbeRun {
  source: string;
  status: 'requested' | 'running' | 'finished' | 'failed' | 'timeout';
  probeProtocol?: ProbeProtocol;
  results: ReadonlyArray<{ ok: boolean }>;
  /** Newest wins; rows without it keep their given order. */
  requestedAt?: number;
  /** The run's family; absent on a legacy IPv4 run (or a name, `addressKind: 'name'`). */
  ipVersion?: 4 | 6;
  addressKind?: 'ip' | 'name';
  port?: number;
}

/** The internal protocol-shape probe a listener needs behind an L4 edge. */
export function shapeProtocolFor(listener: RungListenerLike): ProbeProtocol {
  return listener.security === 'none' ? 'tcp' : 'tls-sni';
}

function familyOf(r: { ipVersion?: 4 | 6; addressKind?: 'ip' | 'name' }): AddressFamily | null {
  if (r.ipVersion !== undefined) return r.ipVersion;
  return r.addressKind === 'name' ? null : 4;
}

/**
 * FCP's own shape check over one family: per listener port, the newest
 * internal run of the expected protocol that is EVIDENCE (a run that could not
 * test is skipped, never a failure). Any failing port fails the family.
 */
function shapeOf(
  listener: RungListenerLike,
  family: AddressFamily,
  runs: ReadonlyArray<RungProbeRun>,
): 'ok' | 'fail' | 'none' {
  const expected = shapeProtocolFor(listener);
  const newest = new Map<number, RungProbeRun>();
  const shapeRuns = runs
    .filter(
      (r) =>
        r.source === 'internal' &&
        (r.probeProtocol ?? 'tcp') === expected &&
        familyOf(r) === family &&
        runOutcome(r) === 'evidence',
    )
    .sort((a, b) => (b.requestedAt ?? 0) - (a.requestedAt ?? 0));
  for (const r of shapeRuns) if (!newest.has(r.port ?? -1)) newest.set(r.port ?? -1, r);
  if (newest.size === 0) return 'none';
  return [...newest.values()].every((r) => r.results.every((x) => x.ok)) ? 'ok' : 'fail';
}

interface FamilyEvidence {
  refused: boolean;
  reached: boolean;
  /** The `partial` rung's bar: enough distinct outside vantages AND a passing shape check. */
  strong: boolean;
}

function evidenceOf(
  listener: RungListenerLike,
  family: AddressFamily,
  rows: ReadonlyArray<RungReachabilityRow>,
  runs: ReadonlyArray<RungProbeRun>,
  agreementVantages: number,
): FamilyEvidence {
  // Outside rows only: the internal source speaks through its shape runs.
  const outside = rows.filter(
    (r) => r.source !== 'internal' && r.country !== 'XX' && familyOf(r) === family,
  );
  const shape = shapeOf(listener, family, runs);
  const vantages = new Set(
    outside.filter((r) => r.verdict === 'reachable').map((r) => `${r.country}/${r.source}`),
  );
  return {
    refused: shape === 'fail' || outside.some((r) => r.verdict === 'unreachable'),
    reached:
      shape === 'ok' ||
      outside.some(
        (r) => r.verdict === 'reachable' || r.verdict === 'mixed' || (r.okCount ?? 0) > 0,
      ),
    strong: shape === 'ok' && vantages.size >= Math.max(1, agreementVantages),
  };
}

/** Families any evidence speaks about (the rung has no list of its own). */
function familiesIn(
  rows: ReadonlyArray<RungReachabilityRow>,
  runs: ReadonlyArray<RungProbeRun>,
): AddressFamily[] {
  const seen = new Set<AddressFamily>();
  for (const r of [...rows, ...runs]) {
    const f = familyOf(r);
    if (f !== null) seen.add(f);
  }
  return [...seen].sort();
}

export function partialRungFor(
  listener: RungListenerLike,
  input: {
    providerHealthy: boolean;
    reachability: ReadonlyArray<RungReachabilityRow>;
    probeRuns: ReadonlyArray<RungProbeRun>;
    agreementVantages: number;
  },
): PartialRung {
  const evidence = familiesIn(input.reachability, input.probeRuns).map((f) =>
    evidenceOf(listener, f, input.reachability, input.probeRuns, input.agreementVantages),
  );
  // A refusal over any family settles it: the address is not usable from
  // somewhere it should be, whatever else says. A shape check that fails is an
  // outage of the front (a REALITY edge that cannot present the camouflage
  // certificate is not serving anyone), not "pending".
  if (evidence.some((e) => e.refused)) return 'unreachable';
  if (!input.providerHealthy) return 'pending';
  return evidence.some((e) => e.strong) ? 'partial' : 'pending';
}

export type FamilyCheck = 'reached' | 'refused' | 'unknown' | 'pending';

export interface OutsideCheck {
  verdict: 'passed' | 'unreachable' | 'pending';
  families: Array<{ family: AddressFamily; check: FamilyCheck }>;
  /** Families no source could test: "not checked from outside over IPv6" on the run card. */
  notChecked: AddressFamily[];
}

/**
 * Stage 4 of a guided run, for one L4 address.
 *
 * Before the stage asked for its own round (`roundSince` absent), only the
 * rung's strong evidence on record passes a family (a reused spare). After,
 * a family waits while a run of that round over it is in flight (until
 * `final`: the stage's wait is over), then reads `reached` or `unknown`.
 * Any refusal answers `unreachable` at once. The address passes when no
 * family is refused or pending, the provider's health allows it, and it does
 * so even with families nobody could test: the operator's own test link
 * (stage 4b) still comes before anything is published.
 */
export function outsideCheckFor(
  listener: RungListenerLike,
  input: {
    /** The families the address is probed over. */
    families: ReadonlyArray<AddressFamily>;
    providerHealthy: boolean;
    reachability: ReadonlyArray<RungReachabilityRow>;
    /** Runs of EVERY source (the in-flight ones too). */
    probeRuns: ReadonlyArray<RungProbeRun>;
    agreementVantages: number;
    /** When the stage asked for its own round. */
    roundSince?: number;
    final?: boolean;
  },
): OutsideCheck {
  const families = input.families.map((family) => {
    const ev = evidenceOf(
      listener,
      family,
      input.reachability,
      input.probeRuns,
      input.agreementVantages,
    );
    let check: FamilyCheck;
    if (ev.refused) check = 'refused';
    else if (input.roundSince === undefined) check = ev.strong ? 'reached' : 'pending';
    else if (
      !input.final &&
      input.probeRuns.some(
        (r) =>
          familyOf(r) === family &&
          (r.requestedAt ?? 0) >= input.roundSince! &&
          runOutcome(r) === 'in_flight',
      )
    )
      check = 'pending';
    else check = ev.reached ? 'reached' : 'unknown';
    return { family, check };
  });
  const notChecked = families.filter((f) => f.check === 'unknown').map((f) => f.family);
  if (families.some((f) => f.check === 'refused'))
    return { verdict: 'unreachable', families, notChecked };
  if (
    families.length === 0 ||
    families.some((f) => f.check === 'pending') ||
    !input.providerHealthy
  )
    return { verdict: 'pending', families, notChecked };
  return { verdict: 'passed', families, notChecked };
}
