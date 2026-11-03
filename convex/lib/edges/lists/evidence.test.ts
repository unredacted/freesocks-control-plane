import { describe, expect, test } from 'vitest';
import { countryOf, listStanding } from '../sni/hunt/evidence';
import { listBlocks, resolveSuggestion } from '../sni/vantage';

const NOW = Date.UTC(2026, 10, 2);
const allow = { cc: 'RU', regime: 'allowlist' as const };
const block = { cc: 'RU', regime: 'blocklist' as const };

describe('lists in the country part of a score', () => {
  test('a list stands in where no reading and no OONI answer', () => {
    expect(countryOf({ onLists: [allow] }, ['RU'], NOW).points).toBe(15);
    expect(countryOf({ onLists: [block] }, ['RU'], NOW).points).toBe(5);
    // Lists that disagree decide nothing.
    expect(countryOf({ onLists: [allow, block] }, ['RU'], NOW).points).toBeUndefined();
    // A list for another country says nothing here.
    expect(countryOf({ onLists: [{ cc: 'IR', regime: 'allowlist' }] }, ['RU'], NOW).points).toBe(
      undefined,
    );
    // Lists add no penalty.
    expect(countryOf({ onLists: [block] }, ['RU'], NOW).penalty).toBe(0);
  });

  test('a reading from inside and OONI come first', () => {
    const ooniOk = { at: NOW, exact: [{ cc: 'RU', status: 'ok' }] };
    expect(countryOf({ ooni: ooniOk, onLists: [block] }, ['RU'], NOW).points).toBe(20);
    const interference = [{ cc: 'RU', at: NOW, reading: 'interference' }];
    const r = countryOf({ countries: interference, onLists: [allow] }, ['RU'], NOW);
    expect(r.points).toBe(0);
    expect(r.penalty).toBe(8);
  });

  test('the mean is over every curated country', () => {
    expect(countryOf({ onLists: [allow] }, ['RU', 'IR'], NOW).points).toBe(12.5);
  });

  test('listStanding', () => {
    expect(listStanding([allow], 'RU')).toEqual({ value: 0.75, regimes: 'allow' });
    expect(listStanding([block], 'RU')).toEqual({ value: 0.25, regimes: 'block' });
    expect(listStanding([allow, block], 'RU')).toEqual({ value: 0.5, regimes: 'both' });
    expect(listStanding(null, 'RU')).toBeNull();
  });
});

describe('the one suggestion rule', () => {
  const probeBlocked = { suggestion: 'blocked' as const, reason: null, basis: null };
  const probeNone = { suggestion: null, reason: 'needs_repeat' as const, basis: null };

  test('the checks win when they suggest anything', () => {
    expect(resolveSuggestion(probeBlocked, { blocks: false })).toMatchObject({
      suggestion: 'blocked',
      provenance: 'probe',
    });
    expect(
      resolveSuggestion({ suggestion: 'proven', reason: null, basis: null }, { blocks: true }),
    ).toMatchObject({ suggestion: 'proven', provenance: 'probe' });
  });

  test('a block list suggests blocked when the checks suggest nothing, never proven', () => {
    expect(resolveSuggestion(probeNone, { blocks: true })).toEqual({
      suggestion: 'blocked',
      reason: null,
      basis: null,
      provenance: 'list',
    });
    expect(resolveSuggestion(null, { blocks: true }).provenance).toBe('list');
  });

  test('reason keeps saying why nothing is suggested; no list means nothing from lists', () => {
    expect(resolveSuggestion(probeNone, null)).toEqual({ ...probeNone, provenance: null });
    expect(resolveSuggestion(null, { blocks: false })).toEqual({
      suggestion: null,
      reason: 'no_data',
      basis: null,
      provenance: null,
    });
  });

  test('a block list blocks only where no list of what works disagrees', () => {
    expect(listBlocks([block], 'RU')).toBe(true);
    expect(listBlocks([block, allow], 'RU')).toBe(false);
    expect(listBlocks([block], 'IR')).toBe(false);
    expect(listBlocks(undefined, 'RU')).toBe(false);
  });
});
