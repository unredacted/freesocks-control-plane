import { describe, expect, test } from 'vitest';
import type { SniConfigView } from '../../../../../../shared/contracts/sni';
import {
  SNI_BOUNDS,
  SNI_DEFAULTS,
  SNI_HUNT_BOUNDS,
  SNI_HUNT_DEFAULTS,
  SNI_VANTAGE_BOUNDS,
  SNI_VANTAGE_DEFAULTS,
} from '../../../../../../../convex/lib/sniConfig';
import {
  KNOB_GROUPS,
  KNOBS,
  changedFromDefault,
  groupErrors,
  groupPatch,
  knobError,
  knobRange,
  knobValue,
  knobsOf,
  type KnobGroup,
} from './sniKnobs';

const SERVER: Record<
  KnobGroup,
  { bounds: Record<string, { min: number; max: number }>; defaults: Record<string, unknown> }
> = {
  lists: { bounds: SNI_BOUNDS, defaults: SNI_DEFAULTS as unknown as Record<string, unknown> },
  find: {
    bounds: SNI_HUNT_BOUNDS,
    defaults: SNI_HUNT_DEFAULTS as unknown as Record<string, unknown>,
  },
  checks: {
    bounds: SNI_VANTAGE_BOUNDS,
    defaults: SNI_VANTAGE_DEFAULTS as unknown as Record<string, unknown>,
  },
};

const view = (over: Partial<Record<KnobGroup, Record<string, number>>> = {}): SniConfigView =>
  ({
    config: { ...SNI_DEFAULTS, ...over.lists },
    vantage: { ...SNI_VANTAGE_DEFAULTS, ...over.checks },
    hunt: { ...SNI_HUNT_DEFAULTS, ...over.find },
    vantageSources: { globalping: true, ripeatlas: false },
  }) as SniConfigView;

describe('the catalog', () => {
  test.each(KNOB_GROUPS.map((g) => g.id))(
    '%s: every numeric knob the server bounds is on the page, with its bounds and default',
    (group) => {
      const { bounds, defaults } = SERVER[group];
      const knobs = knobsOf(group);
      expect(knobs.map((k) => k.key).sort()).toEqual(Object.keys(bounds).sort());
      for (const k of knobs) {
        expect({ min: k.min, max: k.max }).toEqual(bounds[k.key]);
        expect(k.default).toBe(defaults[k.key]);
      }
    },
  );

  test('ids are unique; no dash of any kind and never "names" in the words', () => {
    expect(new Set(KNOBS.map((k) => k.id)).size).toBe(KNOBS.length);
    const words = [
      ...KNOBS.flatMap((k) => [k.label, k.help, k.unit]),
      ...KNOB_GROUPS.flatMap((g) => [g.title, g.description]),
    ];
    for (const w of words) {
      expect(w).not.toMatch(/[–—]/);
      expect(w).not.toMatch(/\bnames?\b/i);
    }
  });
});

describe('values and errors', () => {
  const qualify = KNOBS.find((k) => k.id === 'lists.qualifyPerTick')!;
  test('a value now, and the default when the server sent none', () => {
    expect(knobValue(view({ lists: { qualifyPerTick: 7 } }), qualify)).toBe(7);
    const noHunt = { ...view(), hunt: undefined } as SniConfigView;
    expect(
      knobValue(
        noHunt,
        KNOBS.find((k) => k.id === 'find.depth')!,
      ),
    ).toBe(300_000);
  });

  test('the range line and the error say the bounds', () => {
    expect(knobRange(qualify)).toBe('Default 40. From 1 to 200.');
    expect(knobError(qualify, '40')).toBeNull();
    expect(knobError(qualify, ' 200 ')).toBeNull();
    expect(knobError(qualify, '0')).toBe('A whole number from 1 to 200.');
    expect(knobError(qualify, '201')).toBe('A whole number from 1 to 200.');
    expect(knobError(qualify, '4.5')).toBe('A whole number from 1 to 200.');
    expect(knobError(qualify, '')).toBe('A whole number from 1 to 200.');
    const depth = KNOBS.find((k) => k.id === 'find.depth')!;
    expect(knobError(depth, '250,000')).toBeNull();
  });

  test('www. lookups never go past the sites searched', () => {
    const values = { 'find.depth': '1000', 'find.wwwDepth': '2000' };
    const all: Record<string, string> = {};
    for (const k of knobsOf('find')) all[k.id] = String(k.default);
    expect(groupErrors('find', { ...all, ...values })).toEqual({
      'find.wwwDepth': 'No more than the top sites searched.',
    });
    expect(groupErrors('find', all)).toEqual({});
  });
});

describe('groupPatch', () => {
  test('only what changed, in its block', () => {
    const v = view();
    expect(groupPatch('lists', {}, v)).toBeNull();
    expect(groupPatch('lists', { 'lists.qualifyPerTick': '40' }, v)).toBeNull();
    expect(groupPatch('lists', { 'lists.qualifyPerTick': '60' }, v)).toEqual({
      qualifyPerTick: 60,
    });
    expect(groupPatch('find', { 'find.depth': '500,000' }, v)).toEqual({
      hunt: { depth: 500_000 },
    });
    expect(groupPatch('checks', { 'checks.hourlyBudget': '0' }, v)).toEqual({
      vantage: { hourlyBudget: 0 },
    });
  });

  test('nothing is sent while a field cannot be saved', () => {
    expect(
      groupPatch('lists', { 'lists.qualifyPerTick': '60', 'lists.requalifyHours': '0' }, view()),
    ).toBeNull();
  });

  test('changed from default', () => {
    expect(changedFromDefault('checks', view())).toBe(0);
    expect(changedFromDefault('checks', view({ checks: { minVantages: 5, minNetworks: 3 } }))).toBe(
      2,
    );
  });
});
