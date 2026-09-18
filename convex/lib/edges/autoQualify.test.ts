import { describe, expect, test } from 'vitest';
import { autoQualifyDecision, proofCurrent, type AutoQualifyEdge } from './autoQualify';

const NOW = 1_000_000;

function account(over: Partial<Parameters<typeof autoQualifyDecision>[0]> = {}) {
  return {
    layer: 'l7' as const,
    qualified: false,
    lastTestOkAt: NOW - 10_000,
    effectiveTemplateHash: 'th1',
    ...over,
  };
}

function edge(over: Partial<AutoQualifyEdge> = {}): AutoQualifyEdge {
  return {
    id: 'e1',
    status: 'active',
    layer: 'l7',
    templateHash: 'th1',
    listenerId: 'l1',
    listenerRevision: 2,
    endpoint: 'front.example:443',
    frontQualification: {
      ok: true,
      checkedAt: NOW - 1000,
      expiresAt: NOW + 60_000,
      binding: { listenerId: 'l1', listenerRevision: 2 },
    },
    ...over,
  };
}

describe('autoQualifyDecision', () => {
  test('trusts an L7 account with a current proof on a template-matching active edge', () => {
    const d = autoQualifyDecision(account(), [edge()], NOW);
    expect(d.ok).toBe(true);
    if (d.ok)
      expect(d.evidence).toEqual({
        edgeId: 'e1',
        endpoint: 'front.example:443',
        accountTestedAt: NOW - 10_000,
        templateHash: 'th1',
        listenerId: 'l1',
        listenerRevision: 2,
        proofCheckedAt: NOW - 1000,
      });
  });

  test('L4 accounts are never auto-trusted, whatever their edges show', () => {
    const d = autoQualifyDecision(account({ layer: 'l4' }), [edge({ layer: 'l4' })], NOW);
    expect(d).toEqual({ ok: false, code: 'not_l7' });
  });

  test('a template change after the proof is an evidence mismatch (case 7)', () => {
    const d = autoQualifyDecision(account({ effectiveTemplateHash: 'th2' }), [edge()], NOW);
    expect(d).toEqual({ ok: false, code: 'template_mismatch' });
  });

  test('the proof must be current: ok, unexpired and against the listener revision', () => {
    expect(
      autoQualifyDecision(
        account(),
        [edge({ frontQualification: { ...edge().frontQualification!, ok: false } })],
        NOW,
      ),
    ).toEqual({ ok: false, code: 'no_current_proof' });
    expect(
      autoQualifyDecision(
        account(),
        [edge({ frontQualification: { ...edge().frontQualification!, expiresAt: NOW - 1 } })],
        NOW,
      ),
    ).toEqual({ ok: false, code: 'no_current_proof' });
    expect(autoQualifyDecision(account(), [edge({ listenerRevision: 3 })], NOW)).toEqual({
      ok: false,
      code: 'no_current_proof',
    });
    expect(autoQualifyDecision(account(), [edge({ status: 'draining' })], NOW)).toEqual({
      ok: false,
      code: 'no_current_proof',
    });
    expect(proofCurrent(edge(), NOW)).toBe(true);
    expect(proofCurrent(edge({ frontQualification: null }), NOW)).toBe(false);
  });

  test('the hold, an untested account and a test older than the credential change all refuse', () => {
    expect(autoQualifyDecision(account({ autoQualifyHold: true }), [edge()], NOW)).toEqual({
      ok: false,
      code: 'hold',
    });
    expect(autoQualifyDecision(account({ lastTestOkAt: null }), [edge()], NOW)).toEqual({
      ok: false,
      code: 'account_untested',
    });
    expect(autoQualifyDecision(account({ lastTestError: 'auth_failed' }), [edge()], NOW)).toEqual({
      ok: false,
      code: 'account_untested',
    });
    expect(
      autoQualifyDecision(account({ credentialsChangedAt: NOW - 5000 }), [edge()], NOW),
    ).toEqual({ ok: false, code: 'tested_before_credential_change' });
    expect(autoQualifyDecision(account({ qualified: true }), [edge()], NOW)).toEqual({
      ok: false,
      code: 'already_qualified',
    });
  });

  test('the most recently proven matching edge is the evidence', () => {
    const d = autoQualifyDecision(
      account(),
      [
        edge({ id: 'old', frontQualification: { ...edge().frontQualification!, checkedAt: 5 } }),
        edge({ id: 'new', frontQualification: { ...edge().frontQualification!, checkedAt: 9 } }),
        edge({ id: 'other-template', templateHash: 'th9' }),
      ],
      NOW,
    );
    expect(d.ok && d.evidence.edgeId).toBe('new');
  });
});
