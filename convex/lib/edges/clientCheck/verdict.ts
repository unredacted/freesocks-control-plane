/**
 * The client check's verdict on one address (docs/edges.md § "FCP's own client
 * check"). Pure.
 *
 * An engine's session through the address is judged against a CONTROL: the same
 * engine through an address members already use for the same transport (from
 * outside the country, a censor's block does not apply there). So an address is
 * never blamed for what the node itself does: when the node refuses sing-box
 * (no `minClientVer` on Xray 26, a release that wants an ML-KEM key share), it
 * refuses it through every address, and the new one is as good as the old.
 *
 *   passed                every engine connected, out of the node
 *   passed_with_refusals  at least one engine connected; each one refused here
 *                         is refused through the control too (or, with no
 *                         usable control, is one the REALITY verdict predicts)
 *   address_failed        an engine that connects through the control does not
 *                         here, or no engine connects and the control works
 *   egress_mismatch       a session connected but came out somewhere else:
 *                         the address reaches another node that knows the
 *                         credential, not this one
 *   node_unreachable      nothing connects here or through the control: the
 *                         check cannot tell the address from the node
 *
 * Egress: a connected engine's egress must equal the control's egress for that
 * engine, or one of the node's known addresses (its origin address and the
 * names it was found under). A node that leaves through a second address is
 * still recognised through the control.
 */
import type {
  ClientCheckEngine,
  ClientCheckSessionCode,
  ClientCheckVerdict,
} from '../../../../src/shared/contracts/edgeCodes';
import { canonicalIp } from '../ip';

export interface EngineRun {
  engine: ClientCheckEngine;
  ok: boolean;
  code: ClientCheckSessionCode;
  egressIp: string | null;
  engineVersion: string | null;
}

export interface EngineVerdict {
  engine: ClientCheckEngine;
  code: ClientCheckSessionCode;
  engineVersion: string | null;
  /** Null when the session did not connect. */
  egress: 'matched' | 'mismatch' | null;
  /** Refused here, and refused through the control too (or predicted): not the address's doing. */
  excused: boolean;
}

export interface ClientCheckJudgement {
  verdict: ClientCheckVerdict;
  ok: boolean;
  engines: EngineVerdict[];
}

function same(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  return (canonicalIp(a) ?? a) === (canonicalIp(b) ?? b);
}

function egressMatches(run: EngineRun, control: EngineRun | undefined, expected: string[]) {
  if (control?.ok && same(run.egressIp, control.egressIp)) return true;
  return expected.some((e) => same(run.egressIp, e));
}

/**
 * Whether a control session is needed to judge these runs: an engine failed,
 * or one connected with an egress that is not among the node's known addresses.
 */
export function needsControl(runs: EngineRun[], expectedEgress: string[]): boolean {
  return runs.some((r) => !r.ok || !egressMatches(r, undefined, expectedEgress));
}

export function judge(input: {
  candidate: EngineRun[];
  /** The same engines through the control address; null when none was checked. */
  control: EngineRun[] | null;
  expectedEgress: string[];
  /** Engines the REALITY verdict says this transport refuses (`relays.realityClients`). */
  expectedRefusals: ClientCheckEngine[];
}): ClientCheckJudgement {
  const control = input.control;
  const controlUsable = !!control && control.some((r) => r.ok);
  const controlOf = (e: ClientCheckEngine) => control?.find((r) => r.engine === e);
  const engines: EngineVerdict[] = input.candidate.map((r) => {
    const k = controlOf(r.engine);
    return {
      engine: r.engine,
      code: r.code,
      engineVersion: r.engineVersion,
      egress: r.ok ? (egressMatches(r, k, input.expectedEgress) ? 'matched' : 'mismatch') : null,
      excused: !r.ok && (controlUsable ? !!k && !k.ok : input.expectedRefusals.includes(r.engine)),
    };
  });
  const verdict = ((): ClientCheckVerdict => {
    if (engines.some((e) => e.egress === 'mismatch')) return 'egress_mismatch';
    const connected = engines.filter((e) => e.egress === 'matched').length;
    if (connected === 0) return control && !controlUsable ? 'node_unreachable' : 'address_failed';
    const failed = engines.filter((e) => e.egress === null);
    if (failed.length === 0) return 'passed';
    return failed.every((e) => e.excused) ? 'passed_with_refusals' : 'address_failed';
  })();
  return {
    verdict,
    ok: verdict === 'passed' || verdict === 'passed_with_refusals',
    engines,
  };
}
