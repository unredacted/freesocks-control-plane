import { describe, expect, test } from 'vitest';
import { pickAccount, type AccountCandidate } from './rotation';

const acct = (over: Partial<AccountCandidate>): AccountCandidate => ({
  id: 'a',
  provider: 'gcore',
  qualified: true,
  priority: 0,
  dailyAllocationBudget: 6,
  allocationsToday: 0,
  maxLiveEdges: 10,
  liveEdges: 0,
  ...over,
});

describe('pickAccount', () => {
  test('a zero daily budget means unlimited, matching reserveAllocation', () => {
    const r = pickAccount([acct({ dailyAllocationBudget: 0, allocationsToday: 40 })], 'gcore');
    expect(r).toMatchObject({ ok: true, account: { id: 'a' } });
  });

  test('a spent budget or a full live-edge cap exhausts the account', () => {
    expect(pickAccount([acct({ allocationsToday: 6 })], 'gcore')).toEqual({
      ok: false,
      code: 'accounts_exhausted',
    });
    expect(pickAccount([acct({ liveEdges: 10 })], 'gcore')).toEqual({
      ok: false,
      code: 'accounts_exhausted',
    });
  });

  test('lowest priority number first, then fewest live edges; unqualified accounts never', () => {
    const r = pickAccount(
      [
        acct({ id: 'busy', priority: 1, liveEdges: 3 }),
        acct({ id: 'idle', priority: 1, liveEdges: 1 }),
        acct({ id: 'later', priority: 2 }),
        acct({ id: 'unq', priority: 0, qualified: false }),
      ],
      'gcore',
    );
    expect(r).toMatchObject({ ok: true, account: { id: 'idle' } });
    expect(pickAccount([acct({ qualified: false })], 'gcore')).toEqual({
      ok: false,
      code: 'no_qualified_account',
    });
    expect(pickAccount([acct({})], 'ovh')).toEqual({ ok: false, code: 'no_account_for_provider' });
  });
});
