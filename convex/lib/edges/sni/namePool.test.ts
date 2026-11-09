/**
 * The country page's note of which Globalping probes a country's name checks
 * use: stored safely, and shown only while it still describes the checks.
 */
import { describe, expect, test } from 'vitest';
import { currentNamePool, parseNamePool, type NotedNamePool } from './namePool';

const H = 3_600_000;
const AT = Date.parse('2026-11-05T00:00:00Z');
const NOTE: NotedNamePool = {
  at: AT,
  mode: 'topped_up',
  eyeball: 2,
  total: 9,
  limit: 3,
  needs: 3,
  networks: 'home_first',
};
const NOW = {
  at: AT + H,
  globalping: true,
  limit: 3,
  needs: 3,
  networks: 'home_first' as const,
  intervalHours: 72,
};

describe('the stored note', () => {
  test('round-trips, and anything else reads as none', () => {
    expect(parseNamePool(JSON.stringify(NOTE))).toEqual(NOTE);
    expect(parseNamePool('not json')).toBeNull();
    expect(parseNamePool(JSON.stringify({ ...NOTE, mode: 'other' }))).toBeNull();
    expect(parseNamePool(JSON.stringify({ ...NOTE, total: -1 }))).toBeNull();
    const { networks: _drop, ...noSetting } = NOTE;
    expect(parseNamePool(JSON.stringify(noSetting))).toBeNull();
    expect(parseNamePool(JSON.stringify({ ...NOTE, networks: 'other' }))).toBeNull();
  });

  test('a note from before the network setting: the old switch on was home first, off any', () => {
    const { networks: _drop, ...old } = NOTE;
    expect(parseNamePool(JSON.stringify({ ...old, preferEyeball: true }))).toEqual(NOTE);
    expect(parseNamePool(JSON.stringify({ ...old, preferEyeball: false }))).toEqual({
      ...NOTE,
      networks: 'any',
    });
    // Under the new default (home only) an old note no longer describes the checks.
    expect(
      currentNamePool(parseNamePool(JSON.stringify({ ...old, preferEyeball: true })), {
        ...NOW,
        networks: 'home',
      }),
    ).toBeNull();
  });
});

describe('shown only while it describes the checks', () => {
  test('current', () => {
    expect(currentNamePool(NOTE, NOW)).toEqual(NOTE);
  });

  test('Globalping no longer a name-check source, or no note', () => {
    expect(currentNamePool(NOTE, { ...NOW, globalping: false })).toBeNull();
    expect(currentNamePool(null, NOW)).toBeNull();
  });

  test('older than two check intervals (at least a day)', () => {
    expect(currentNamePool(NOTE, { ...NOW, at: AT + 144 * H })).toEqual(NOTE);
    expect(currentNamePool(NOTE, { ...NOW, at: AT + 145 * H })).toBeNull();
    expect(currentNamePool(NOTE, { ...NOW, intervalHours: 6, at: AT + 24 * H })).toEqual(NOTE);
    expect(currentNamePool(NOTE, { ...NOW, intervalHours: 6, at: AT + 25 * H })).toBeNull();
  });

  test('the limit, the floor or the network setting changed since', () => {
    expect(currentNamePool(NOTE, { ...NOW, limit: 4 })).toBeNull();
    expect(currentNamePool(NOTE, { ...NOW, needs: 2 })).toBeNull();
    expect(currentNamePool(NOTE, { ...NOW, networks: 'any' })).toBeNull();
    expect(currentNamePool(NOTE, { ...NOW, networks: 'home' })).toBeNull();
  });
});
