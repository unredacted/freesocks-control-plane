/**
 * FCP's own test of a send (docs/edges.md "FCP's own test of a send"): the
 * timing, the bounds, and where one node stands, read from its `client_check`
 * receipts (sniAutoConfirm.ts). Pure; unit-tested.
 */
import type {
  ClientCheckEngine,
  ClientCheckVerdict,
} from '../../../../src/shared/contracts/edgeCodes';

/** After the backend is seen to hold a send: the nodes restart Xray to take it. */
export const AUTO_FIRST_DELAY_MS = 60_000;
/** A test that did not pass is tried again no sooner than this (the sweep runs every 5 minutes). */
export const AUTO_RETRY_MS = 10 * 60_000;
/** Tests of one send on one node that may not pass before FCP leaves it to a person. */
export const AUTO_MAX_FAILURES = 4;
/**
 * How long FCP's receipt holds: the runs a sweep staggers, the check's 90 s
 * and the link. A receipt still `issued` after it lapsed belongs to a run
 * that died; it counts as one that did not pass.
 */
export const AUTO_RECEIPT_TTL_MS = 8 * 60_000;
/** One check holds the service for at most its 90 s budget: runs are this far apart. */
export const AUTO_STAGGER_MS = 100_000;
/** Tests one sweep starts (3 fit in the 5 minutes between sweeps). */
export const AUTO_PER_SWEEP = 3;

/** The verdicts that say the node did not take the name (not "could not tell"). */
const FAILING: ReadonlySet<ClientCheckVerdict> = new Set(['address_failed', 'egress_mismatch']);

/** What the view and the sweep read of one `client_check` receipt. */
export interface AutoReceipt {
  state: 'issued' | 'confirmed' | 'expired' | 'superseded' | 'failed';
  sni: string;
  issuedAt: number;
  expiresAt: number;
  check?: {
    at: number;
    verdict: ClientCheckVerdict | null;
    code: string | null;
    engines: Array<{ engine: ClientCheckEngine; code: string }>;
  };
}

export type AutoTestState =
  | 'testing'
  | 'passed'
  | 'failed'
  | 'could_not_check'
  | 'voided'
  | 'stopped';

export interface AutoTestView {
  state: AutoTestState;
  at: number;
  sni: string;
  failures: number;
  verdict: ClientCheckVerdict | null;
  code: string | null;
  engines: Array<{ engine: ClientCheckEngine; code: string }>;
}

const running = (r: AutoReceipt, now: number) => r.state === 'issued' && now <= r.expiresAt;

/** Tests that did not pass: a verdict against, nothing learned, or a run that died. */
export function autoFailures(rows: readonly AutoReceipt[], now: number): number {
  return rows.filter(
    (r) =>
      r.state === 'failed' || r.state === 'expired' || (r.state === 'issued' && now > r.expiresAt),
  ).length;
}

/** Where FCP's test of one send stands on one node (null: it never tested there). */
export function autoTestOf(rows: readonly AutoReceipt[], now: number): AutoTestView | null {
  if (rows.length === 0) return null;
  const newest = rows.reduce((a, b) => (b.issuedAt > a.issuedAt ? b : a));
  const failures = autoFailures(rows, now);
  const base = {
    at: newest.check?.at ?? newest.issuedAt,
    sni: newest.sni,
    failures,
    verdict: newest.check?.verdict ?? null,
    code: newest.check?.code ?? null,
    engines: newest.check?.engines ?? [],
  };
  if (running(newest, now)) return { ...base, state: 'testing' };
  if (newest.state === 'confirmed') return { ...base, state: 'passed' };
  if (failures >= AUTO_MAX_FAILURES) return { ...base, state: 'stopped' };
  if (newest.state === 'superseded') return { ...base, state: 'voided' };
  if (newest.state === 'failed' && newest.check?.verdict && FAILING.has(newest.check.verdict))
    return { ...base, state: 'failed' };
  // A run that died, or no verdict (the service, the link, the time, a node that answered nothing).
  return { ...base, state: 'could_not_check', code: base.code ?? (newest.check ? null : 'lapsed') };
}

/**
 * Whether the sweep may start a test of this send on this node now: none is
 * running, it has not used up its tries, and the last one that did not pass
 * is old enough. After a pass it may go straight on (the next name, when names
 * prove only themselves).
 */
export function autoTestDue(rows: readonly AutoReceipt[], now: number): boolean {
  if (rows.some((r) => running(r, now))) return false;
  if (autoFailures(rows, now) >= AUTO_MAX_FAILURES) return false;
  if (rows.length === 0) return true;
  const newest = rows.reduce((a, b) => (b.issuedAt > a.issuedAt ? b : a));
  return newest.state === 'confirmed' || now - newest.issuedAt >= AUTO_RETRY_MS;
}
