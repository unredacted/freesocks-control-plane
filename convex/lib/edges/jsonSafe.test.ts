import { describe, expect, test } from 'vitest';
import { convexToJson } from 'convex/values';
import { jsonSafe } from './jsonSafe';

describe('jsonSafe', () => {
  test('an SDK object with Dates, undefined and functions becomes plain Convex data', () => {
    const created = new Date('2026-10-21T10:00:00.000Z');
    const raw = {
      lb: {
        id: 'lb-1',
        createdAt: created,
        updatedAt: new Date(Number.NaN),
        description: undefined,
        toString: () => 'x',
        instances: [{ createdAt: created, ip: undefined }],
        ['$schema']: 'dropped',
        ['naïve']: 'dropped',
      },
      stats: null,
      counts: new Map([['a', 1n]]),
      tags: new Set(['t']),
      ratio: Number.POSITIVE_INFINITY,
    };
    const out = jsonSafe(raw);
    expect(out).toEqual({
      lb: {
        id: 'lb-1',
        createdAt: '2026-10-21T10:00:00.000Z',
        updatedAt: null,
        instances: [{ createdAt: '2026-10-21T10:00:00.000Z' }],
      },
      stats: null,
      counts: { a: '1' },
      tags: ['t'],
      ratio: null,
    });
    // Convex accepts it as a value, and it round-trips through JSON unchanged.
    expect(() => convexToJson(out as never)).not.toThrow();
    expect(JSON.parse(JSON.stringify(out))).toEqual(out);
    // What the Scaleway SDK hands back is refused as it is (the live view bug).
    expect(() => convexToJson({ lb: { createdAt: created } } as never)).toThrow(/Date/);
  });

  test('plain data comes back equal; undefined in a list is null; a cycle is cut', () => {
    const plain = { a: [1, 'b', true, null, { c: 2 }] };
    expect(jsonSafe(plain)).toEqual(plain);
    expect(jsonSafe([1, undefined])).toEqual([1, null]);
    const loop: Record<string, unknown> = { id: 'x' };
    loop.self = loop;
    expect(jsonSafe(loop)).toEqual({ id: 'x', self: '[circular]' });
    // The same object twice (not a cycle) is copied twice.
    const shared = { n: 1 };
    expect(jsonSafe({ a: shared, b: shared })).toEqual({ a: { n: 1 }, b: { n: 1 } });
    expect(jsonSafe(undefined)).toBeNull();
  });
});
