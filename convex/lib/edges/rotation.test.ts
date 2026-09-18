import { describe, expect, test } from 'vitest';
import {
  accountsForSlot,
  l7SelectionAllowed,
  pickAccount,
  pickSlot,
  pickStandby,
  slotEligible,
  type AccountCandidate,
  type SlotCandidate,
  type StandbyCandidate,
} from './rotation';
import type { ListenerProto } from './protocols';

const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const GRPC: ListenerProto = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' };
const TLS: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'tls' };
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const HY2: ListenerProto = { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' };

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
      accountsForSlot(accounts, { layers: ['l7'], proto: WS, allowL7: true }).map((a) => a.id),
    ).toEqual(['cf', 'fastly']);
    expect(
      accountsForSlot(accounts, { layers: ['l4'], proto: TLS, allowL7: true }).map((a) => a.id),
    ).toEqual(['l4']);
  });

  test('an L7 provider that cannot carry the protocol is excluded', () => {
    // Fastly's WebSocket path is not a gRPC path.
    expect(
      accountsForSlot(accounts, { layers: ['l7'], proto: GRPC, allowL7: true }).map((a) => a.id),
    ).toEqual(['cf']);
  });

  test('the L7 gate removes every L7 account from AUTOMATIC selection', () => {
    expect(
      accountsForSlot(accounts, { layers: ['l4', 'l7'], proto: WS, allowL7: false }).map(
        (a) => a.id,
      ),
    ).toEqual(['l4']);
    // An L7-only slot then has nothing to pick, which the caller reports as a
    // veto instead of silently routing it to an L4 account.
    expect(accountsForSlot(accounts, { layers: ['l7'], proto: WS, allowL7: false })).toEqual([]);
  });
});

describe('accountsForSlot: transport carriage', () => {
  test('a UDP listener needs a provider that declares udp; none does today, so no account qualifies', () => {
    const accounts = [
      { id: 'l4', provider: 'upcloud' },
      { id: 'g', provider: 'gcore' },
      { id: 'cf', provider: 'cloudflare' },
    ];
    expect(accountsForSlot(accounts, { layers: ['l4', 'l7'], proto: HY2, allowL7: true })).toEqual(
      [],
    );
    // A plain (Shadowsocks) or REALITY listener is carried by every L4 forwarder and no L7 front.
    for (const proto of [SS, REALITY]) {
      expect(
        accountsForSlot(accounts, { layers: ['l4', 'l7'], proto, allowL7: true }).map((a) => a.id),
      ).toEqual(['l4', 'g']);
    }
  });
});

describe('slotEligible + pickSlot (proto-aware)', () => {
  const slot = (over: Partial<SlotCandidate>): SlotCandidate => ({
    slotId: 's1',
    slotKey: 'a',
    proto: REALITY,
    provider: '',
    deployed: true,
    retired: false,
    profileEnabled: true,
    activeSnis: 2,
    ...over,
  });

  test('an SNI-presenting listener needs an active name; a plain one does not', () => {
    expect(slotEligible(slot({ activeSnis: 0 }))).toBe(false);
    expect(slotEligible(slot({ proto: SS, activeSnis: 0 }))).toBe(true);
    expect(slotEligible(slot({ proto: WS, activeSnis: 0 }))).toBe(false);
    expect(slotEligible(slot({ deployed: false }))).toBe(false);
    expect(slotEligible(slot({ retired: true }))).toBe(false);
    expect(slotEligible(slot({ profileEnabled: false }))).toBe(false);
  });

  test('pickSlot: eligible only, distinct provider first when preferred, then the preference, then key order', () => {
    const slots = [
      slot({ slotId: 'b', slotKey: 'b', provider: 'gcore' }),
      slot({ slotId: 'a', slotKey: 'a', provider: 'upcloud' }),
      slot({ slotId: 'c', slotKey: 'c', provider: '', activeSnis: 0 }),
    ];
    // `c` has no active name → ineligible. gcore is already published → upcloud wins when distinct is preferred.
    expect(pickSlot(slots, ['gcore'], true, null)?.slotId).toBe('a');
    expect(pickSlot(slots, ['gcore'], true, 'gcore')?.slotId).toBe('a');
    // Without the distinct preference, the relay's preference decides, else key order.
    expect(pickSlot(slots, ['gcore'], false, 'gcore')?.slotId).toBe('b');
    expect(pickSlot(slots, [], false, null)?.slotId).toBe('a');
    expect(pickSlot([slot({ activeSnis: 0 })], [], true, null)).toBeNull();
    // A provider-free plain listener can always host a distinct provider.
    expect(
      pickSlot(
        [slot({ slotId: 'p', slotKey: 'p', proto: SS, activeSnis: 0 })],
        ['gcore', 'upcloud'],
        true,
        null,
      )?.slotId,
    ).toBe('p');
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
