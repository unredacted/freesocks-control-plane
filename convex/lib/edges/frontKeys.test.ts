import { describe, expect, test } from 'vitest';
import { FRONT_KEYS_EVERY_MS, frontKeysDue, frontKeysFor, keyInUse, keyIsStale } from './frontKeys';

describe('the keys that still hold a front (pure)', () => {
  const rec = { at: 1_000, since: 500, stale: 4, total: 10 };

  test('a node is counted again hourly, and at once when its binding was claimed again', () => {
    expect(frontKeysDue(undefined, 500, 0)).toBe(true);
    expect(frontKeysDue(rec, 500, rec.at + FRONT_KEYS_EVERY_MS - 1)).toBe(false);
    expect(frontKeysDue(rec, 500, rec.at + FRONT_KEYS_EVERY_MS)).toBe(true);
    expect(frontKeysDue(rec, 900, rec.at + 1)).toBe(true);
  });

  test('only an edge render handed out since the claim proves a key moved', () => {
    expect(keyIsStale({}, 500)).toBe(true);
    expect(keyIsStale({ lastRenderedAt: 499 }, 500)).toBe(true);
    expect(keyIsStale({ lastRenderedAt: 500 }, 500)).toBe(false);
    // A key last served before `lastRenderedAt` existed: its snapshot's time stands in.
    expect(keyIsStale({ lastRender: { at: 600 } }, 500)).toBe(false);
    expect(keyIsStale({ lastRenderedAt: 400, lastRender: { at: 450 } }, 500)).toBe(true);
  });

  test('a superseded key counts while its grace runs', () => {
    expect(keyInUse({ state: 'active' }, 1_000)).toBe(true);
    expect(keyInUse({ state: 'disabled', deletedAt: 1_001 }, 1_000)).toBe(true);
    expect(keyInUse({ state: 'disabled', deletedAt: 1_000 }, 1_000)).toBe(false);
    expect(keyInUse({ state: 'disabled' }, 1_000)).toBe(false);
    expect(keyInUse({ state: 'deleted', deletedAt: 2_000 }, 1_000)).toBe(false);
  });

  test('a count speaks only for the claim it was made against', () => {
    expect(frontKeysFor(rec, { updatedAt: 500 })).toEqual({ stale: 4, total: 10, at: 1_000 });
    expect(frontKeysFor(rec, { updatedAt: 501 })).toBeNull();
    expect(frontKeysFor(rec, null)).toBeNull();
    expect(frontKeysFor(undefined, { updatedAt: 500 })).toBeNull();
  });
});
