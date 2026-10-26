/**
 * Reading one candidate's check (pure; unit-tested; docs/edges.md "Finding
 * names"). The verdict is qualification's own (`judgeHandshake`,
 * `qualificationNetworkCode`); these helpers only shape what goes around it.
 */
import { addressFamily } from '../../ip';
import { allOnNetwork, onNetwork, type NetworkPrefixes } from '../../networks';
import type { HandshakeResult } from '../family';

export type OnNetwork = 'all' | 'some' | 'none' | 'unknown';

/**
 * Where a name's COMPLETE answer set (every A and every AAAA) lies: `all` on
 * the network, `some`, `none`, or `unknown` without a network. One answer off
 * the network is enough to fail it, whichever family it is in.
 */
export function answersOnNetwork(
  answers: readonly string[],
  p: NetworkPrefixes | null | undefined,
): OnNetwork {
  if (!p) return 'unknown';
  if (answers.length === 0) return 'none';
  if (allOnNetwork(answers, p)) return 'all';
  return answers.some((ip) => onNetwork(ip, p)) ? 'some' : 'none';
}

/**
 * The addresses shown with a candidate, cut to `max` only AFTER the full set
 * was judged: the ones on the network when there is one, IPv4 first, sorted
 * (so the first is a stable "address it lives on" across checks).
 */
export function shownAnswers(
  answers: readonly string[],
  p: NetworkPrefixes | null | undefined,
  max = 4,
): string[] {
  const kept = p ? answers.filter((ip) => onNetwork(ip, p)) : [...answers];
  const fam = (ip: string) => (addressFamily(ip) === 'v4' ? 0 : 1);
  return [...new Set(kept)].sort((a, b) => fam(a) - fam(b) || a.localeCompare(b)).slice(0, max);
}

/**
 * For a network candidate the name IS the would-be target, so the network
 * check's "target off the network" is the name's own `q_off_network`.
 */
export function ownTargetCode(code: string | null): string | null {
  return code === 'q_target_off_network' ? 'q_off_network' : code;
}

/** An answer where the server refused the offered group (not a failure to reach it). */
const REFUSED_RE = /^ERR_SSL_|ALERT|HANDSHAKE|NO_SHARED|WRONG_VERSION|UNSUPPORTED_PROTOCOL/i;

/**
 * One of the two extra handshakes (an X25519-only or an X25519MLKEM768-only
 * offer): `true` when TLS 1.3 completed with it, `false` when the server
 * refused it, and no answer (`error`) when the server could not be reached.
 * Never a qualification verdict.
 */
export function extraFact(r: HandshakeResult): { value?: boolean; error?: string } {
  if (r.ok) return { value: r.protocol === 'TLSv1.3' };
  const e = r.error ?? 'error';
  if (REFUSED_RE.test(e)) return { value: false };
  return { error: e.slice(0, 40) };
}
