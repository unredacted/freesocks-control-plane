import { describe, expect, test } from 'vitest';
import {
  MAX_EVENT_DETAIL_CHARS,
  accountsForSlot,
  appendEvent,
  l7SelectionAllowed,
  nextFailure,
  withProviderAnswer,
  pickAccount,
  pickSlot,
  pickLocation,
  pickStandby,
  slotEligible,
  type AccountCandidate,
  type SetLocationCandidate,
  type SlotCandidate,
  type StandbyCandidate,
} from './rotation';
import type { ListenerProto } from './protocols';
import { frontsAllowed } from './providers/capabilities';

const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const GRPC: ListenerProto = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' };
const TLS: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'tls' };
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const HY2: ListenerProto = { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' };

const acct = (over: Partial<AccountCandidate>): AccountCandidate => ({
  id: 'a',
  locationId: 'loc-a',
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

  test('a candidate is a location: its own trust and cap count, the account budget too', () => {
    // Two locations of one account: the trusted one with room is picked.
    const r = pickAccount(
      [
        acct({ locationId: 'full', locationMaxLiveEdges: 2, locationLiveEdges: 2 }),
        acct({ locationId: 'untrusted', qualified: false }),
        acct({ locationId: 'room', locationMaxLiveEdges: 2, locationLiveEdges: 1 }),
      ],
      'gcore',
    );
    expect(r).toMatchObject({ ok: true, account: { id: 'a', locationId: 'room' } });
    // A location without its own cap is limited by the account alone.
    expect(
      pickAccount([acct({ locationMaxLiveEdges: null, locationLiveEdges: 50 })], 'gcore'),
    ).toMatchObject({ ok: true });
    // Equal accounts: the location with fewer live edges first.
    expect(
      pickAccount(
        [
          acct({ locationId: 'busy', locationLiveEdges: 3 }),
          acct({ locationId: 'quiet', locationLiveEdges: 0 }),
        ],
        'gcore',
      ),
    ).toMatchObject({ ok: true, account: { locationId: 'quiet' } });
    expect(pickAccount([acct({ locationMaxLiveEdges: 1, locationLiveEdges: 1 })], 'gcore')).toEqual(
      { ok: false, code: 'accounts_exhausted' },
    );
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
      accountsForSlot(accounts, {
        layers: ['l7'],
        proto: WS,
        allowL7: true,
        dnsProvidersFront: true,
      }).map((a) => a.id),
    ).toEqual(['cf', 'fastly']);
    expect(
      accountsForSlot(accounts, {
        layers: ['l4'],
        proto: TLS,
        allowL7: true,
        dnsProvidersFront: true,
      }).map((a) => a.id),
    ).toEqual(['l4']);
  });

  test('an L7 provider that cannot carry the protocol is excluded', () => {
    // Fastly's WebSocket path is not a gRPC path.
    expect(
      accountsForSlot(accounts, {
        layers: ['l7'],
        proto: GRPC,
        allowL7: true,
        dnsProvidersFront: true,
      }).map((a) => a.id),
    ).toEqual(['cf']);
  });

  test('the L7 gate removes every L7 account from AUTOMATIC selection', () => {
    expect(
      accountsForSlot(accounts, {
        layers: ['l4', 'l7'],
        proto: WS,
        allowL7: false,
        dnsProvidersFront: true,
      }).map((a) => a.id),
    ).toEqual(['l4']);
    // An L7-only slot then has nothing to pick, which the caller reports as a
    // veto instead of silently routing it to an L4 account.
    expect(
      accountsForSlot(accounts, {
        layers: ['l7'],
        proto: WS,
        allowL7: false,
        dnsProvidersFront: true,
      }),
    ).toEqual([]);
  });

  test('a DNS account fronts nothing while DNS providers may not front, whoever is choosing', () => {
    // The default: the Cloudflare account holds DNS records for other fronts.
    expect(
      accountsForSlot(accounts, {
        layers: ['l4', 'l7'],
        proto: WS,
        allowL7: true,
        dnsProvidersFront: false,
      }).map((a) => a.id),
    ).toEqual(['l4', 'fastly']);
    // gRPC is carried by no remaining L7 front.
    expect(
      accountsForSlot(accounts, {
        layers: ['l7'],
        proto: GRPC,
        allowL7: true,
        dnsProvidersFront: false,
      }),
    ).toEqual([]);
    expect(frontsAllowed('cloudflare', false)).toBe(false);
    expect(frontsAllowed('cloudflare', true)).toBe(true);
    for (const id of ['upcloud', 'gcore', 'scaleway', 'ovh', 'fastly'])
      expect(frontsAllowed(id, false)).toBe(true);
  });
});

describe('accountsForSlot: transport carriage', () => {
  test('a UDP listener needs a provider that declares udp; none does today, so no account qualifies', () => {
    const accounts = [
      { id: 'l4', provider: 'upcloud' },
      { id: 'g', provider: 'gcore' },
      { id: 'cf', provider: 'cloudflare' },
    ];
    expect(
      accountsForSlot(accounts, {
        layers: ['l4', 'l7'],
        proto: HY2,
        allowL7: true,
        dnsProvidersFront: true,
      }),
    ).toEqual([]);
    // A plain (Shadowsocks) or REALITY listener is carried by every L4 forwarder and no L7 front.
    for (const proto of [SS, REALITY]) {
      expect(
        accountsForSlot(accounts, {
          layers: ['l4', 'l7'],
          proto,
          allowL7: true,
          dnsProvidersFront: true,
        }).map((a) => a.id),
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
    // Without the distinct preference, the origin's preference decides, else key order.
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

  test('a replace moves away from the target provider first, then its location', () => {
    const same = standby({ id: 'same', provider: 'gcore', locationKey: 'gcore:r1' });
    const otherPlace = standby({ id: 'place', provider: 'gcore', locationKey: 'gcore:r2' });
    const otherProvider = standby({ id: 'prov', provider: 'ovh', locationKey: 'ovh:r9' });
    const avoid = { avoid: { provider: 'gcore', locationKey: 'gcore:r1' } };
    expect(
      pickStandby([same, otherPlace, otherProvider], 's1', [], null, false, null, avoid)?.id,
    ).toBe('prov');
    expect(pickStandby([same, otherPlace], 's1', [], null, false, null, avoid)?.id).toBe('place');
    expect(pickStandby([same], 's1', [], null, false, null, avoid)?.id).toBe('same');
  });

  test('automatic work skips a cooling or outside location; a named spare is that one or nothing', () => {
    const a = standby({ id: 'a', locationId: 'loc-a' });
    const b = standby({ id: 'b', locationId: 'loc-b' });
    const skip = { skipLocations: new Set(['loc-a']) };
    expect(pickStandby([a, b], 's1', [], null, false, null, skip)?.id).toBe('b');
    expect(pickStandby([a], 's1', [], null, false, null, skip)).toBeNull();
    expect(pickStandby([a, b], 's1', [], null, false, null, { spareEdgeId: 'a' })?.id).toBe('a');
    expect(pickStandby([b], 's1', [], null, false, null, { spareEdgeId: 'a' })).toBeNull();
  });
});

describe('pickLocation', () => {
  const cand = (over: Partial<SetLocationCandidate>): SetLocationCandidate => ({
    id: 'acct',
    locationId: 'loc',
    provider: 'gcore',
    qualified: true,
    priority: 0,
    dailyAllocationBudget: 0,
    allocationsToday: 0,
    maxLiveEdges: 10,
    liveEdges: 0,
    setOrder: 0,
    lowersDeficit: false,
    providerNew: false,
    locationKeyNew: false,
    ...over,
  });
  test('ranks what a pick adds: deficit, a new provider, a new location, set order, fewest live', () => {
    const r = pickLocation([
      cand({ locationId: 'first', setOrder: 0 }),
      cand({ locationId: 'newloc', setOrder: 2, locationKeyNew: true }),
      cand({ locationId: 'newprov', setOrder: 3, providerNew: true }),
      cand({ locationId: 'fills', setOrder: 4, lowersDeficit: true }),
    ]);
    expect(r.ok && r.account.locationId).toBe('fills');
    const s = pickLocation([
      cand({ locationId: 'first', setOrder: 0 }),
      cand({ locationId: 'newloc', setOrder: 2, locationKeyNew: true }),
      cand({ locationId: 'newprov', setOrder: 3, providerNew: true }),
    ]);
    expect(s.ok && s.account.locationId).toBe('newprov');
  });
  test('untrusted only on request; exhausted capacity is accounts_exhausted', () => {
    expect(pickLocation([cand({ qualified: false })])).toEqual({
      ok: false,
      code: 'no_qualified_account',
    });
    expect(pickLocation([cand({ qualified: false })], { allowUnqualified: true }).ok).toBe(true);
    expect(pickLocation([cand({ liveEdges: 10 })])).toEqual({
      ok: false,
      code: 'accounts_exhausted',
    });
  });
});

describe('the provider answer on a failed create', () => {
  test('a later failure without its own answer keeps the last one; a new answer replaces it', () => {
    const refused = {
      step: 'backend',
      code: 'ScalewayError',
      status: 400,
      detail: 'server refused',
    };
    expect(nextFailure(refused, { step: 'provisioning', code: 'step_retries_exhausted' })).toEqual({
      step: 'provisioning',
      code: 'step_retries_exhausted',
      detail: 'server refused',
    });
    expect(nextFailure(refused, { step: 'lb', code: 'x', detail: 'other' }).detail).toBe('other');
    expect(nextFailure(undefined, { step: 'lb' })).toEqual({ step: 'lb' });
  });

  test('the event detail carries it, and an event keeps room for it', () => {
    expect(withProviderAnswer('step backend threw: ScalewayError 400', undefined)).toBe(
      'step backend threw: ScalewayError 400',
    );
    const long = withProviderAnswer('step backend threw: x', 'y'.repeat(600));
    expect(long).toContain('. The provider answered: yyy');
    const [ev] = appendEvent([], { at: 1, level: 'warn', code: 'progress', detail: long });
    expect(ev!.detail).toBe(long);
    expect(long.length).toBeLessThanOrEqual(MAX_EVENT_DETAIL_CHARS);
  });
});
