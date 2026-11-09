/**
 * `PATCH sni/config` writes (pure): every numeric `edge.sni.*` knob has a
 * bound, and a value outside it is clamped before it is stored, whichever
 * block it sits in. Wrong types and unknown keys are ignored.
 */
import { describe, expect, test } from 'vitest';
import {
  SNI_BOUNDS,
  SNI_HUNT_BOUNDS,
  SNI_HUNT_KEYS,
  SNI_KEYS,
  SNI_VANTAGE_BOUNDS,
  SNI_VANTAGE_KEYS,
  sniConfigWrites,
  sniHuntConfigWrites,
  sniVantageConfigWrites,
} from './sniConfig';

type Bounds = Record<string, { min: number; max: number }>;
const stored = (writes: { key: string; value: string }[], key: string) =>
  JSON.parse(writes.find((w) => w.key === key)!.value) as unknown;

const BLOCKS = [
  {
    name: 'base',
    keys: SNI_KEYS as Record<string, string>,
    bounds: SNI_BOUNDS as Bounds,
    bools: ['enabled', 'autoConfirm'],
    writes: sniConfigWrites,
  },
  {
    name: 'vantage',
    keys: SNI_VANTAGE_KEYS as Record<string, string>,
    bounds: SNI_VANTAGE_BOUNDS as Bounds,
    bools: ['enabled', 'sources.globalping', 'sources.ripeatlas', 'autoApply', 'realHost'],
    writes: sniVantageConfigWrites,
  },
  {
    name: 'hunt',
    keys: SNI_HUNT_KEYS as Record<string, string>,
    bounds: SNI_HUNT_BOUNDS as Bounds,
    bools: ['enabled'],
    writes: sniHuntConfigWrites,
  },
] as const;

describe.each(BLOCKS)('the $name block', ({ keys, bounds, bools, writes }) => {
  test('every knob that is not a switch has a bound', () => {
    const numeric = Object.keys(keys).filter((k) => !(bools as readonly string[]).includes(k));
    expect(numeric.sort()).toEqual(Object.keys(bounds).sort());
  });

  test.each(Object.keys(bounds))('%s is clamped to its bound and rounded', (path) => {
    const { min, max } = bounds[path]!;
    const key = keys[path]!;
    expect(stored(writes({ [path]: max + 1000 }).writes, key)).toBe(max);
    expect(stored(writes({ [path]: min - 1000 }).writes, key)).toBe(min);
    expect(stored(writes({ [path]: min + 0.4 }).writes, key)).toBe(min);
  });

  test('wrong types and unknown keys write nothing', () => {
    const patch: Record<string, unknown> = { unknown: 5 };
    for (const p of Object.keys(bounds)) patch[p] = '12';
    for (const p of bools) if (!p.includes('.')) patch[p] = 'yes';
    patch[Object.keys(bounds)[0]!] = Number.NaN;
    expect(writes(patch)).toEqual({ writes: [], changedKeys: [] });
  });
});
