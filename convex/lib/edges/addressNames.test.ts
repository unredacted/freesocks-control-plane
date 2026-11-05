import { describe, expect, test } from 'vitest';
import {
  ADDRESS_NAME_TTL_S,
  addressNameMarker,
  desiredNameRecords,
  mayMoveName,
  mintAddressName,
  nameTargetOf,
  pickNameZone,
  planNameRecords,
  type MoveFacts,
} from './addressNames';
import { isFirstLevelUnder } from './hostname';
import { parseNameZones, sanitizeNameZones } from '../edgeConfig';

const ZONE = 'names.example';
const DAY = 86_400_000;

describe('a name for an address', () => {
  test('two words, one label under the zone, the same for the same seed', () => {
    const a = mintAddressName('fcp-node-one-ab12', ZONE, 0);
    expect(a).toMatch(/^[a-z]{4,9}-[a-z]{4,9}\.names\.example$/);
    expect(isFirstLevelUnder(a, ZONE)).toBe(true);
    expect(mintAddressName('fcp-node-one-ab12', ZONE, 0)).toBe(a);
    // The next generation is another pair; another zone too.
    expect(mintAddressName('fcp-node-one-ab12', ZONE, 1)).not.toBe(a);
    expect(mintAddressName('fcp-node-one-ab12', 'other.example', 0).split('.')[0]).not.toBe(
      a.split('.')[0],
    );
  });

  test('the marker names the row, so it survives a move', () => {
    expect(addressNameMarker('k123')).toBe('fcp-name:k123');
  });

  test('records: A for IPv4, AAAA for IPv6, nothing else', () => {
    expect(desiredNameRecords('a-b.names.example', { v4: '198.51.100.1' })).toEqual([
      { type: 'A', name: 'a-b.names.example', content: '198.51.100.1' },
    ]);
    expect(
      desiredNameRecords('a-b.names.example', { v4: '198.51.100.1', v6: '2001:db8::1' }),
    ).toHaveLength(2);
    expect(ADDRESS_NAME_TTL_S).toBeLessThanOrEqual(60);
  });
});

describe('the zone a name goes in', () => {
  test("the one the node uses least, then the deployment's least", () => {
    expect(
      pickNameZone(
        [
          { locationId: 'zone0000001', onOrigin: 1, inFleet: 0 },
          { locationId: 'zone0000002', onOrigin: 0, inFleet: 9 },
        ],
        'seed',
      ),
    ).toBe('zone0000002');
    expect(
      pickNameZone(
        [
          { locationId: 'zone0000001', onOrigin: 1, inFleet: 5 },
          { locationId: 'zone0000002', onOrigin: 1, inFleet: 2 },
        ],
        'seed',
      ),
    ).toBe('zone0000002');
  });

  test('a renewed name leaves its zone unless it is the only one', () => {
    const zones = [
      { locationId: 'zone0000001', onOrigin: 0, inFleet: 0 },
      { locationId: 'zone0000002', onOrigin: 3, inFleet: 3 },
    ];
    expect(pickNameZone(zones, 'seed', 'zone0000001')).toBe('zone0000002');
    expect(pickNameZone(zones.slice(0, 1), 'seed', 'zone0000001')).toBe('zone0000001');
    expect(pickNameZone([], 'seed')).toBeNull();
  });

  test('the setting keeps ids only, once each', () => {
    expect(parseNameZones('k17abcdefgh  k17abcdefgh, bad k27abcdefgh')).toEqual([
      'k17abcdefgh',
      'k27abcdefgh',
    ]);
    expect(sanitizeNameZones(['k17abcdefgh', 4, 'k17abcdefgh'])).toEqual(['k17abcdefgh']);
    expect(sanitizeNameZones(undefined)).toEqual([]);
  });
});

describe('what a pass writes', () => {
  const NAME = 'a-b.names.example';
  const M = addressNameMarker('k1');
  const want = desiredNameRecords(NAME, { v4: '198.51.100.2', v6: '2001:db8::2' });
  const rec = (over: Record<string, unknown>) => ({
    id: 'r1',
    type: 'A',
    name: NAME,
    content: '198.51.100.2',
    proxied: false,
    comment: M,
    ...over,
  });

  test('nothing there: create both', () => {
    const p = planNameRecords([], want, M, NAME);
    expect(p).toEqual({
      kind: 'steps',
      steps: [
        { action: 'create', record: want[0] },
        { action: 'create', record: want[1] },
      ],
      kept: [],
    });
  });

  test('ours with the old address: changed in place; a duplicate a lost answer left goes', () => {
    const p = planNameRecords(
      [
        rec({ id: 'r1', content: '198.51.100.9' }),
        rec({ id: 'r2', content: '198.51.100.9' }),
        rec({ id: 'r3', type: 'AAAA', content: '2001:db8::2' }),
      ],
      want,
      M,
      NAME,
    );
    expect(p).toEqual({
      kind: 'steps',
      steps: [
        { action: 'update', id: 'r1', record: want[0] },
        { action: 'delete', id: 'r2' },
      ],
      kept: [{ type: 'AAAA', id: 'r3', content: '2001:db8::2' }],
    });
  });

  test('a family the address lost is deleted', () => {
    const p = planNameRecords(
      [rec({ id: 'r1' }), rec({ id: 'r3', type: 'AAAA', content: '2001:db8::2' })],
      want.slice(0, 1),
      M,
      NAME,
    );
    expect(p).toMatchObject({ kind: 'steps', steps: [{ action: 'delete', id: 'r3' }] });
  });

  test('anything FCP did not write at the name is a conflict, never touched', () => {
    expect(planNameRecords([rec({ comment: 'someone' })], want, M, NAME)).toEqual({
      kind: 'conflict',
      reason: 'foreign',
    });
    expect(planNameRecords([rec({ type: 'CNAME', content: 'x.example' })], want, M, NAME)).toEqual({
      kind: 'conflict',
      reason: 'cname',
    });
    expect(planNameRecords([rec({ proxied: true })], want, M, NAME)).toEqual({
      kind: 'conflict',
      reason: 'proxied',
    });
  });
});

describe('a replacement takes the name', () => {
  const now = 100 * DAY;
  const facts = (over: Partial<MoveFacts> = {}): MoveFacts => ({
    enabled: true,
    moveQuietDays: 30,
    eligibleZones: ['zone0000001'],
    now,
    name: { state: 'live', zoneLocationId: 'zone0000001' },
    from: { listenerId: 'l1', lane: 'open' },
    to: { listenerId: 'l1', lane: 'open', layer: 'l4', v4: '198.51.100.3' },
    ...over,
  });

  test('moves: same listener, same lane, never moved', () => {
    expect(mayMoveName(facts())).toEqual({ move: true });
  });

  test('moves again only once the quiet window has passed', () => {
    const recent = facts({
      name: { state: 'live', zoneLocationId: 'zone0000001', movedAt: now - 3 * DAY },
    });
    expect(mayMoveName(recent)).toEqual({ move: false, reason: 'moved_recently' });
    const old = facts({
      name: { state: 'live', zoneLocationId: 'zone0000001', movedAt: now - 31 * DAY },
    });
    expect(mayMoveName(old)).toEqual({ move: true });
  });

  test('never between audiences: everyone holding the name would dial the new address', () => {
    const to = { listenerId: 'l1', lane: 'open' as const, layer: 'l4' as const, v4: 'x' };
    expect(mayMoveName(facts({ to: { ...to, audience: ['IR'] } }))).toEqual({
      move: false,
      reason: 'other_audience',
    });
    expect(
      mayMoveName(
        facts({
          from: { listenerId: 'l1', lane: 'open', audience: ['RU', 'IR'] },
          to: { ...to, audience: ['IR', 'RU'] },
        }),
      ),
    ).toEqual({ move: true });
    expect(mayMoveName(facts({ to: { ...to, audience: [] } }))).toEqual({ move: true });
  });

  test('never across lanes, listeners or into a zone no longer eligible', () => {
    expect(
      mayMoveName(facts({ to: { listenerId: 'l1', lane: 'trusted', layer: 'l4', v4: 'x' } })),
    ).toEqual({ move: false, reason: 'other_lane' });
    expect(
      mayMoveName(facts({ to: { listenerId: 'l2', lane: 'open', layer: 'l4', v4: 'x' } })),
    ).toEqual({ move: false, reason: 'other_listener' });
    expect(mayMoveName(facts({ eligibleZones: [] }))).toEqual({
      move: false,
      reason: 'zone_not_eligible',
    });
  });

  test('off, 0 days, no name, no IPv4: nothing moves', () => {
    expect(mayMoveName(facts({ enabled: false }))).toMatchObject({ reason: 'names_off' });
    expect(mayMoveName(facts({ moveQuietDays: 0 }))).toMatchObject({ reason: 'names_off' });
    expect(mayMoveName(facts({ name: null }))).toMatchObject({ reason: 'no_name' });
    expect(
      mayMoveName(facts({ name: { state: 'removing', zoneLocationId: 'zone0000001' } })),
    ).toMatchObject({ reason: 'no_name' });
    expect(
      mayMoveName(facts({ to: { listenerId: 'l1', lane: 'open', layer: 'l4', v4: null } })),
    ).toMatchObject({ reason: 'no_address' });
  });
});

describe('what a name should hold now', () => {
  test('a serving address: its IPs; an ending one: nothing; anything else: leave it', () => {
    expect(nameTargetOf({ status: 'active', addresses: { v4: '198.51.100.4' } })).toEqual({
      kind: 'serve',
      v4: '198.51.100.4',
      v6: null,
    });
    expect(nameTargetOf({ status: 'draining', addresses: { v4: '198.51.100.4' } }).kind).toBe(
      'serve',
    );
    for (const status of ['destroying', 'destroyed', 'failed', 'cancelled'])
      expect(nameTargetOf({ status, addresses: { v4: '198.51.100.4' } })).toEqual({
        kind: 'remove',
      });
    expect(nameTargetOf(null)).toEqual({ kind: 'remove' });
    expect(nameTargetOf({ status: 'quarantined', addresses: { v4: '198.51.100.4' } })).toEqual({
      kind: 'hold',
    });
  });
});
