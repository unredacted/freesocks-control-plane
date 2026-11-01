import { describe, expect, test } from 'vitest';
import { FRONT_KEYS_EVERY_MS, frontKeysDue, frontKeysFor, keyIsStale } from './frontKeys';

describe('the keys that still hold a front (pure)', () => {
  const rec = { at: 1_000, since: 500, stale: 4, total: 10 };

  test('a node is counted again at most hourly', () => {
    expect(frontKeysDue(undefined, 0)).toBe(true);
    expect(frontKeysDue(rec, rec.at + FRONT_KEYS_EVERY_MS - 1)).toBe(false);
    expect(frontKeysDue(rec, rec.at + FRONT_KEYS_EVERY_MS)).toBe(true);
  });

  test('a key that never fetched, or last fetched before the claim, still holds it', () => {
    expect(keyIsStale(undefined, 500)).toBe(true);
    expect(keyIsStale(499, 500)).toBe(true);
    expect(keyIsStale(500, 500)).toBe(false);
  });

  test('a count speaks only for the claim it was made against', () => {
    expect(frontKeysFor(rec, { updatedAt: 500 })).toEqual({ stale: 4, total: 10, at: 1_000 });
    expect(frontKeysFor(rec, { updatedAt: 501 })).toBeNull();
    expect(frontKeysFor(rec, null)).toBeNull();
    expect(frontKeysFor(undefined, { updatedAt: 500 })).toBeNull();
  });
});
