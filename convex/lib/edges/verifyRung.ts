/**
 * The `partial` verification rung of an L4 edge, derived from probe evidence
 * (docs/edges.md § "Publication"). Three rungs exist:
 *
 *   partial      provider health + outside reachability (≥ agreementVantages
 *                distinct vantages reachable, none unreachable) + a protocol-
 *                SHAPE check branched by listener security: `tls-sni` for a
 *                REALITY / TLS listener, bare `tcp` for a plaintext one.
 *   verified     ONLY by a human, per endpoint (lib/edges/verification.ts).
 *   unreachable  outside probes fail, or the shape check fails.
 *
 * `partial` is the CEILING this function can reach: a forwarder aimed at the
 * camouflage site passes `tls-sni` (it presents the camouflage target's own
 * certificate), and any TCP answer passes `tcp`. Nothing here is authentication
 * evidence, so no code path in this module (or anywhere server-side) ever
 * returns `verified` for an L4 edge.
 *
 * Pure: takes the rows, returns a word.
 */
import type { ProbeProtocol } from './probes/types';

export type PartialRung = 'partial' | 'unreachable' | 'pending';

export interface RungListenerLike {
  security: 'none' | 'tls' | 'reality';
}

export interface RungReachabilityRow {
  country: string;
  source: string;
  verdict: 'reachable' | 'unreachable' | 'mixed' | 'unknown';
  port?: number;
}

export interface RungProbeRun {
  source: string;
  status: 'requested' | 'running' | 'finished' | 'failed' | 'timeout';
  probeProtocol?: ProbeProtocol;
  results: ReadonlyArray<{ ok: boolean }>;
  /** Newest wins; rows without it keep their given order. */
  requestedAt?: number;
}

/** The internal protocol-shape probe a listener needs behind an L4 edge. */
export function shapeProtocolFor(listener: RungListenerLike): ProbeProtocol {
  return listener.security === 'none' ? 'tcp' : 'tls-sni';
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
  // Any outside verdict of `unreachable` settles it: the address is not usable
  // from somewhere it should be, whatever else says.
  const outside = input.reachability.filter((r) => r.source !== 'internal' && r.country !== 'XX');
  if (outside.some((r) => r.verdict === 'unreachable')) return 'unreachable';
  // The shape check: the newest FINISHED internal run of the expected protocol.
  // Its failure is an outage of the front (a REALITY edge that cannot present
  // the camouflage certificate is not serving anyone), not "pending".
  const expected = shapeProtocolFor(listener);
  const shapeRuns = input.probeRuns
    .filter((r) => r.source === 'internal' && (r.probeProtocol ?? 'tcp') === expected)
    .sort((a, b) => (b.requestedAt ?? 0) - (a.requestedAt ?? 0));
  const finished = shapeRuns.filter((r) => r.status === 'finished');
  const shapeVerdict: 'ok' | 'fail' | 'none' =
    finished.length === 0
      ? shapeRuns.some((r) => r.status === 'failed' || r.status === 'timeout')
        ? 'fail'
        : 'none'
      : finished[0].results.length > 0 && finished[0].results.every((x) => x.ok)
        ? 'ok'
        : 'fail';
  if (shapeVerdict === 'fail') return 'unreachable';
  if (!input.providerHealthy) return 'pending';
  const vantages = new Set(
    outside.filter((r) => r.verdict === 'reachable').map((r) => `${r.country}/${r.source}`),
  );
  if (vantages.size < Math.max(1, input.agreementVantages)) return 'pending';
  if (shapeVerdict !== 'ok') return 'pending';
  return 'partial';
}
