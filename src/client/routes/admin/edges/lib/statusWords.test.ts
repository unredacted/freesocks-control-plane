import { describe, expect, test } from 'vitest';
import type { OriginStatus } from '../../../../../shared/contracts/edges';
import { deliveryWords, fleetSentence, originSentence, statusOf } from './statusWords';

const status = (over: Partial<OriginStatus> = {}): OriginStatus => ({
  kind: 'protected',
  dot: 'green',
  code: null,
  runId: null,
  runKind: null,
  step: null,
  published: 1,
  standbys: 0,
  offline: 0,
  worstHealth: 'online',
  layers: ['l4'],
  attention: false,
  delivery: { kind: 'serving', code: null },
  ...over,
});

describe('originSentence', () => {
  test('a live run speaks first, in four plain steps', () => {
    expect(
      originSentence(status({ kind: 'setting-up', runId: 'r', runKind: 'protect', step: 2 })),
    ).toBe('Setting up, step 2 of 4.');
    expect(
      originSentence(
        status({
          kind: 'needs-you',
          runId: 'r',
          runKind: 'protect',
          step: 4,
          code: 'node_not_approved',
        }),
      ),
    ).toBe('Every address works. Waiting for you to approve go-live.');
    expect(
      originSentence(
        status({ kind: 'needs-you', runId: 'r', runKind: 'protect', step: 3, code: 'try_it' }),
      ),
    ).toBe('Setting up, step 3 of 4. It needs you.');
  });

  test('a re-protect says members keep what they have', () => {
    expect(
      originSentence(status({ kind: 'setting-up', runId: 'r', runKind: 'reprotect', step: 1 })),
    ).toBe('Protecting again, step 1 of 4. Members keep what they have.');
    expect(
      originSentence(
        status({ kind: 'needs-you', runId: 'r', runKind: 'reprotect', step: 3, code: 'try_it' }),
      ),
    ).toBe('Protecting again, step 3 of 4. It needs you.');
  });

  test('every other kind', () => {
    expect(originSentence(status({ kind: 'removing', code: 'restore' }))).toBe(
      'Removing protection.',
    );
    expect(originSentence(status({ kind: 'removing', code: 'deleting' }))).toBe('Being removed.');
    expect(originSentence(status({ kind: 'paused', dot: 'red' }))).toBe(
      'Paused for safety. It needs you.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'offline', offline: 2 }))).toBe(
      '2 addresses are offline.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'offline', offline: 1 }))).toBe(
      '1 address is offline.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'members_dark' }))).toMatch(
      /It needs you\.$/,
    );
    expect(originSentence(status({ kind: 'off' }))).toBe('Protection is switched off (Advanced).');
    expect(originSentence(status({ kind: 'not-live', published: 1 }))).toBe(
      'Address ready, not live yet. Members still use the direct address.',
    );
    expect(originSentence(status({ kind: 'not-live', published: 0 }))).toBe(
      'Not protected yet. Members use the direct address.',
    );
    expect(originSentence(status({ kind: 'unprotected', published: 0 }))).toBe(
      'No address in use. Members get nothing.',
    );
    expect(originSentence(status({ published: 2, standbys: 1 }))).toBe(
      'Protected. 2 addresses in use, 1 spare.',
    );
    expect(originSentence(status({ published: 1 }))).toBe('Protected. 1 address in use.');
  });
});

describe('fleetSentence', () => {
  test('what matters most, then the count', () => {
    expect(fleetSentence(null)).toBe('');
    expect(fleetSentence({ kind: 'empty', dot: 'grey', count: 0, total: 0, protected: 0 })).toBe(
      'No node is protected yet.',
    );
    expect(
      fleetSentence({ kind: 'needs-you', dot: 'amber', count: 1, total: 3, protected: 2 }),
    ).toBe('1 node needs you.');
    expect(
      fleetSentence({ kind: 'needs-you', dot: 'amber', count: 2, total: 3, protected: 1 }),
    ).toBe('2 nodes need you.');
    expect(
      fleetSentence({ kind: 'setting-up', dot: 'blue', count: 1, total: 2, protected: 1 }),
    ).toBe('Setting up 1 node.');
    expect(
      fleetSentence({ kind: 'not-live', dot: 'amber', count: 2, total: 2, protected: 0 }),
    ).toBe('2 nodes are not live yet.');
    expect(
      fleetSentence({ kind: 'protected', dot: 'green', count: 1, total: 1, protected: 1 }),
    ).toBe('Your node is protected.');
    expect(
      fleetSentence({ kind: 'protected', dot: 'green', count: 6, total: 6, protected: 6 }),
    ).toBe('All 6 nodes protected.');
    expect(fleetSentence({ kind: 'partial', dot: 'green', count: 1, total: 3, protected: 1 })).toBe(
      '1 of 3 nodes protected.',
    );
  });
});

describe('deliveryWords', () => {
  test('one headline per kind; a reason and a fix only when something is wrong', () => {
    expect(deliveryWords({ kind: 'manual', code: null }).headline).toBe('Nothing to deliver');
    expect(deliveryWords({ kind: 'direct', code: null }).headline).toBe(
      'Members use the direct address',
    );
    const serving = deliveryWords({ kind: 'serving', code: null });
    expect([serving.tone, serving.reason]).toEqual(['success', null]);
    const dark = deliveryWords({ kind: 'dark', code: 'empty_pool' });
    expect(dark.tone).toBe('danger');
    expect(dark.reason).toBeTruthy();
    expect(deliveryWords({ kind: 'degraded', code: 'entry_mismatch' }).tone).toBe('warning');
    for (const k of ['manual', 'direct', 'serving', 'degraded', 'dark'] as const) {
      const w = deliveryWords({ kind: k, code: k === 'dark' ? 'relay_disabled' : null });
      expect(`${w.headline} ${w.detail} ${w.reason ?? ''}`).not.toMatch(/—/);
    }
  });
});

test('statusOf finds one origin by slug', () => {
  const s = status();
  expect(statusOf([{ relayId: 'r1', relaySlug: 'a', status: s }], 'a')).toBe(s);
  expect(statusOf([], 'a')).toBeNull();
  expect(statusOf(undefined, 'a')).toBeNull();
});
