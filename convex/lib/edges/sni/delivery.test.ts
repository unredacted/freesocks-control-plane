/**
 * Where a family's name stands on its way to members (docs/edges.md "A
 * transport's names"): one answer per name, the counts that add it up, and the
 * small decisions around managing a transport's names.
 */
import { describe, expect, test } from 'vitest';
import {
  combineDeliveries,
  countDeliveries,
  familySlugForTransport,
  nameDelivery,
  nodeCounts,
  placeFromNode,
  suggestNetwork,
  type DeliveryName,
} from './delivery';

const usable = (name: string): DeliveryName => ({ name, status: 'active', qualification: 'ok' });
const facts = (o: Partial<Parameters<typeof nameDelivery>[1]> = {}) => ({
  bound: true,
  onBackend: new Set<string>(),
  provable: new Set<string>(),
  nodes: [] as Set<string>[],
  ...o,
});

describe('a name on its way to members', () => {
  test('off, failing and checking come before anything about the backend', () => {
    const f = facts({ nodes: [new Set(['a.example'])] });
    expect(nameDelivery({ ...usable('a.example'), status: 'retired' }, f).state).toBe('off');
    expect(nameDelivery({ ...usable('a.example'), status: 'burned' }, f).state).toBe('off');
    expect(nameDelivery({ ...usable('a.example'), status: 'suspended' }, f).state).toBe('failing');
    expect(nameDelivery({ ...usable('a.example'), qualification: 'failed' }, f).state).toBe(
      'failing',
    );
    expect(nameDelivery({ ...usable('a.example'), qualification: 'pending' }, f).state).toBe(
      'checking',
    );
  });

  test('in use on every node; waiting for a test where a confirmed rollout carries it', () => {
    const two = [new Set(['a.example', 'b.example']), new Set(['a.example'])];
    const f = facts({
      onBackend: new Set(['a.example', 'b.example', 'c.example']),
      provable: new Set(['a.example', 'b.example', 'c.example']),
      nodes: two,
    });
    expect(nameDelivery(usable('a.example'), f)).toEqual({ state: 'in_use', inUseOn: 2, nodes: 2 });
    expect(nameDelivery(usable('b.example'), f)).toEqual({
      state: 'waiting_test',
      inUseOn: 1,
      nodes: 2,
    });
    expect(nameDelivery(usable('c.example'), f).state).toBe('waiting_test');
  });

  test('to send while not on the backend; idle where no step can take it on now', () => {
    expect(nameDelivery(usable('n.example'), facts()).state).toBe('to_send');
    // A family bound to nothing.
    expect(nameDelivery(usable('n.example'), facts({ bound: false })).state).toBe('idle');
    // On the backend outside any confirmed rollout: the next rollout covers it.
    expect(
      nameDelivery(
        usable('n.example'),
        facts({ onBackend: new Set(['n.example']), nodes: [new Set()] }),
      ).state,
    ).toBe('idle');
    // In use on one node, not provable: in use (partly).
    expect(
      nameDelivery(usable('n.example'), facts({ nodes: [new Set(['n.example']), new Set()] })),
    ).toEqual({ state: 'in_use', inUseOn: 1, nodes: 2 });
  });

  test('the counts add up every state, and each node counts only usable names', () => {
    expect(countDeliveries(['in_use', 'in_use', 'to_send', 'failing', 'off'])).toEqual({
      inUse: 2,
      waitingTest: 0,
      toSend: 1,
      idle: 0,
      checking: 0,
      failing: 1,
      off: 1,
    });
    const names = [
      usable('a.example'),
      usable('b.example'),
      { ...usable('c.example'), qualification: 'pending' as const },
      { ...usable('d.example'), qualification: 'failed' as const },
      { ...usable('e.example'), status: 'retired' as const },
    ];
    // Handed out is in use whatever its check says now (a name being checked
    // again is still what members get); a test only proves usable names.
    expect(
      nodeCounts(
        names,
        new Set(['b.example', 'd.example']),
        new Set(['a.example', 'c.example', 'e.example']),
      ),
    ).toEqual({ inUse: 2, waitingTest: 1, pending: ['b.example'] });
  });
});

describe('a family bound to several transports', () => {
  test('each transport answers for itself; the step still needed somewhere wins', () => {
    const unbound = { state: 'idle' as const, inUseOn: 0, nodes: 0 };
    // A rollout confirmed on transport A only: proof there, a send still due on B.
    const onA = nameDelivery(
      usable('c.example'),
      facts({
        onBackend: new Set(['c.example']),
        provable: new Set(['c.example']),
        nodes: [new Set()],
      }),
    );
    const onB = nameDelivery(usable('c.example'), facts({ nodes: [new Set()] }));
    expect([onA.state, onB.state]).toEqual(['waiting_test', 'to_send']);
    expect(combineDeliveries([onA, onB], unbound)).toEqual({
      state: 'waiting_test',
      inUseOn: 0,
      nodes: 2,
    });
    // In use on A, to send on B: still a send to make.
    const used = nameDelivery(usable('c.example'), facts({ nodes: [new Set(['c.example'])] }));
    expect(combineDeliveries([used, onB], unbound)).toEqual({
      state: 'to_send',
      inUseOn: 1,
      nodes: 2,
    });
    // In use everywhere it can be: in use.
    expect(combineDeliveries([used, used], unbound).state).toBe('in_use');
    expect(combineDeliveries([], unbound)).toBe(unbound);
  });
});

describe('managing a transport', () => {
  const nets = [
    { slug: 'one', ranges: ['192.0.2.'] },
    { slug: 'two', ranges: ['198.51.100.'] },
  ];
  const on = (ip: string, n: (typeof nets)[number]) => n.ranges.some((r) => ip.startsWith(r));

  test('a network is suggested only when it holds the target and every address in use', () => {
    expect(suggestNetwork(['192.0.2.10'], ['192.0.2.7'], nets, on)?.slug).toBe('one');
    expect(suggestNetwork(['192.0.2.10'], [], nets, on)?.slug).toBe('one');
    // The addresses in use are elsewhere: a network the target is on would be refused at bind.
    expect(suggestNetwork(['192.0.2.10'], ['198.51.100.7'], nets, on)).toBeNull();
    // The target is off every network: every name would fail its check there.
    expect(suggestNetwork(['203.0.113.5'], ['192.0.2.7'], nets, on)).toBeNull();
    expect(suggestNetwork([], ['192.0.2.7'], nets, on)).toBeNull();
  });

  test("a network's place comes from the node: its country, the city its location is named after", () => {
    expect(placeFromNode('us', 'Example City, ST')).toEqual({
      country: 'US',
      city: 'Example City',
    });
    expect(placeFromNode('DE', null)).toEqual({ country: 'DE' });
    expect(placeFromNode('DE', 'Rack 4 (cage 2)')).toEqual({ country: 'DE' });
    expect(placeFromNode('', 'Example City')).toBeNull();
    expect(placeFromNode(undefined, undefined)).toBeNull();
  });

  test('a family id from the transport tag', () => {
    expect(familySlugForTransport('VLESS_REALITY')).toBe('vless-reality');
    expect(familySlugForTransport('__REALITY 8443__')).toBe('reality-8443');
    expect(familySlugForTransport('x'.repeat(60))).toHaveLength(34);
    expect(familySlugForTransport('-')).toBe('names');
  });
});
