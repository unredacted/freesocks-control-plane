/**
 * L7 auto-trust (docs/edges.md § "Runbooks" > qualify a provider account).
 *
 * An L7 front carries an AUTHENTICATED end-to-end proof (`frontQualification`,
 * bound to the listener revision + intent), so an account that has produced a
 * current proof on one of its active edges has demonstrated exactly what the
 * manual "Mark qualified" runbook asks for. The rule therefore trusts such an
 * account automatically, with version-bound evidence:
 *
 *   - L7 accounts ONLY. An L4 edge has no authenticated proof and never will
 *     (lib/edges/verifyRung.ts): L4 accounts are trusted only by an operator.
 *   - the proof must be current: `ok`, unexpired, and taken against the
 *     listener's CURRENT revision;
 *   - the edge's `templateHash` must equal the account's effective template
 *     hash NOW (a template change after the proof means the proof covers a
 *     configuration the account no longer provisions);
 *   - the account must have been tested AFTER its last credential change;
 *   - when an account it depends on (its DNS account) changed credentials or
 *     settings, BOTH the test and the proof must postdate that change
 *     (`dependencyChangedAt`): a proof taken through the old dependency says
 *     nothing about the new one;
 *   - no `autoQualifyHold` (a manual untrust holds the rule off).
 *
 * The rule only ever says "trust"; every existing invalidation (credential or
 * settings edit, template change) stays where it is. Pure: rows in, verdict out.
 */

export interface AutoQualifyAccount {
  layer: 'l4' | 'l7';
  qualified: boolean;
  autoQualifyHold?: boolean | null;
  lastTestOkAt?: number | null;
  lastTestError?: string | null;
  credentialsChangedAt?: number | null;
  /** When an account this one depends on (its DNS account) last changed. */
  dependencyChangedAt?: number | null;
  /** The hash of the template the account provisions with NOW. */
  effectiveTemplateHash: string;
}

export interface AutoQualifyEdge {
  id: string;
  status: string;
  layer: 'l4' | 'l7';
  templateHash?: string | null;
  listenerId: string;
  /** The listener's CURRENT revision (read from the listener row, not the proof). */
  listenerRevision: number;
  endpoint: string | null;
  frontQualification?: {
    ok: boolean;
    checkedAt: number;
    expiresAt: number;
    binding: { listenerId: string; listenerRevision: number };
  } | null;
}

export interface AutoQualifyEvidence {
  edgeId: string;
  endpoint: string;
  accountTestedAt: number;
  templateHash: string;
  listenerId: string;
  listenerRevision: number;
  proofCheckedAt: number;
}

export type AutoQualifyDecision =
  | { ok: true; evidence: AutoQualifyEvidence }
  | {
      ok: false;
      code:
        | 'not_l7'
        | 'already_qualified'
        | 'hold'
        | 'account_untested'
        | 'tested_before_credential_change'
        | 'tested_before_dependency_change'
        | 'no_current_proof'
        | 'proof_before_dependency_change'
        | 'template_mismatch';
    };

/** Whether a proof is current for the listener's revision at `now`. */
export function proofCurrent(edge: AutoQualifyEdge, now: number): boolean {
  const q = edge.frontQualification;
  return (
    !!q &&
    q.ok &&
    q.expiresAt > now &&
    q.binding.listenerId === edge.listenerId &&
    q.binding.listenerRevision === edge.listenerRevision
  );
}

export function autoQualifyDecision(
  account: AutoQualifyAccount,
  edges: ReadonlyArray<AutoQualifyEdge>,
  now: number,
): AutoQualifyDecision {
  if (account.layer !== 'l7') return { ok: false, code: 'not_l7' };
  if (account.qualified) return { ok: false, code: 'already_qualified' };
  if (account.autoQualifyHold) return { ok: false, code: 'hold' };
  const testedAt = account.lastTestOkAt ?? 0;
  if (!testedAt || account.lastTestError) return { ok: false, code: 'account_untested' };
  if (account.credentialsChangedAt && testedAt < account.credentialsChangedAt)
    return { ok: false, code: 'tested_before_credential_change' };
  const dependencyChangedAt = account.dependencyChangedAt ?? 0;
  if (dependencyChangedAt && testedAt <= dependencyChangedAt)
    return { ok: false, code: 'tested_before_dependency_change' };
  const current = edges.filter(
    (e) => e.status === 'active' && e.layer === 'l7' && e.endpoint && proofCurrent(e, now),
  );
  if (current.length === 0) return { ok: false, code: 'no_current_proof' };
  const proven = current.filter(
    (e) => !dependencyChangedAt || e.frontQualification!.checkedAt > dependencyChangedAt,
  );
  if (proven.length === 0) return { ok: false, code: 'proof_before_dependency_change' };
  const matching = proven.filter((e) => (e.templateHash ?? null) === account.effectiveTemplateHash);
  if (matching.length === 0) return { ok: false, code: 'template_mismatch' };
  // The most recently proven edge is the evidence.
  const best = [...matching].sort(
    (a, b) => (b.frontQualification?.checkedAt ?? 0) - (a.frontQualification?.checkedAt ?? 0),
  )[0];
  return {
    ok: true,
    evidence: {
      edgeId: best.id,
      endpoint: best.endpoint!,
      accountTestedAt: testedAt,
      templateHash: account.effectiveTemplateHash,
      listenerId: best.listenerId,
      listenerRevision: best.listenerRevision,
      proofCheckedAt: best.frontQualification!.checkedAt,
    },
  };
}
