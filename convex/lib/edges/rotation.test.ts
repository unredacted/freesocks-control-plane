import { describe, expect, test } from 'vitest';
import {
  accountsForSlot,
  l7SelectionAllowed,
  pickAccount,
  pickStandby,
  type AccountCandidate,
  type StandbyCandidate,
} from './rotation';

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

describe('accountsForSlot', () => {
  const accounts = [
    { id: 'l4', provider: 'upcloud' },
    { id: 'cf', provider: 'cloudflare' },
    { id: 'fastly', provider: 'fastly' },
  ];

  test('only accounts whose LAYER the chain allows are candidates', () => {
    // A plaintext origin is L7-only: an L4 forwarder cannot add the TLS the
    // front terminated, so no L4 account may be picked for it.
    expect(
      accountsForSlot(accounts, { layers: ['l7'], protocol: 'ws', allowL7: true }).map((a) => a.id),
    ).toEqual(['cf', 'fastly']);
    expect(
      accountsForSlot(accounts, { layers: ['l4'], protocol: 'tls', allowL7: true }).map(
        (a) => a.id,
      ),
    ).toEqual(['l4']);
  });

  test('an L7 provider that cannot carry the protocol is excluded', () => {
    // Fastly's WebSocket path is not a gRPC path.
    expect(
      accountsForSlot(accounts, { layers: ['l7'], protocol: 'grpc', allowL7: true }).map(
        (a) => a.id,
      ),
    ).toEqual(['cf']);
  });

  test('the L7 gate removes every L7 account from AUTOMATIC selection', () => {
    expect(
      accountsForSlot(accounts, { layers: ['l4', 'l7'], protocol: 'ws', allowL7: false }).map(
        (a) => a.id,
      ),
    ).toEqual(['l4']);
    // An L7-only slot then has nothing to pick, which the caller reports as a
    // veto instead of silently routing it to an L4 account.
    expect(accountsForSlot(accounts, { layers: ['l7'], protocol: 'ws', allowL7: false })).toEqual(
      [],
    );
  });
});

describe('l7SelectionAllowed', () => {
  test('follows edge.l7.autoSelect, which ships off', () => {
    expect(l7SelectionAllowed({ l7: { autoSelect: false } })).toBe(false);
    expect(l7SelectionAllowed({ l7: { autoSelect: true } })).toBe(true);
  });
});

describe('pickStandby', () => {
  const standby = (over: Partial<StandbyCandidate>): StandbyCandidate => ({
    id: 'e1',
    slotId: 's1',
    provider: 'upcloud',
    accountId: null,
    status: 'active',
    publication: 'unpublished',
    health: 'unknown',
    hasAddress: true,
    ...over,
  });

  test('a standby without the address of its own layer is not compatible', () => {
    expect(pickStandby([standby({})], 's1', [], null, false)).toMatchObject({ id: 'e1' });
    expect(pickStandby([standby({ hasAddress: false })], 's1', [], null, false)).toBeNull();
  });
});
