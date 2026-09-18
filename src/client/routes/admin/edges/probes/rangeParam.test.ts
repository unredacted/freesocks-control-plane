import { describe, expect, it } from 'vitest';
import { DEFAULT_PROBE_RANGE, decodeProbeRange, encodeProbeRange } from './rangeParam';

const DAY = 86_400_000;

describe('probe range URL param', () => {
  it('keeps the default out of the address', () => {
    expect(encodeProbeRange(DEFAULT_PROBE_RANGE)).toBe('');
    expect(decodeProbeRange('')).toEqual(DEFAULT_PROBE_RANGE);
    expect(decodeProbeRange(null)).toEqual(DEFAULT_PROBE_RANGE);
  });

  it('round-trips every preset by name', () => {
    for (const [name, ms] of [
      ['24h', DAY],
      ['30d', 30 * DAY],
      ['90d', 90 * DAY],
    ] as const) {
      expect(encodeProbeRange({ kind: 'window', windowMs: ms })).toBe(name);
      expect(decodeProbeRange(name)).toEqual({ kind: 'window', windowMs: ms });
    }
    expect(decodeProbeRange('7d')).toEqual(DEFAULT_PROBE_RANGE);
  });

  it('round-trips a non-preset window and a custom from/to range', () => {
    const win = { kind: 'window', windowMs: 3 * DAY } as const;
    expect(decodeProbeRange(encodeProbeRange(win))).toEqual(win);
    const custom = { kind: 'range', fromMs: 1_788_000_000_000, toMs: 1_788_600_000_000 } as const;
    expect(encodeProbeRange(custom)).toBe('1788000000000-1788600000000');
    expect(decodeProbeRange(encodeProbeRange(custom))).toEqual(custom);
  });

  it('falls back to the default on anything unreadable', () => {
    for (const bad of ['nope', 'w0', 'w-5', '10-5', '5-5', '1e3-2e3', '-', '12-']) {
      expect(decodeProbeRange(bad)).toEqual(DEFAULT_PROBE_RANGE);
    }
  });
});
