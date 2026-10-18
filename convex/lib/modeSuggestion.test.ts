import { describe, expect, test } from 'vitest';
import { suggestModeFor, type SuggestibleMode } from './modeSuggestion';

const MODES: SuggestibleMode[] = [
  { id: 'ws', isCensorshipRecommended: false, available: true },
  { id: 'reality', isCensorshipRecommended: true, available: true },
  { id: 'xhttp', isCensorshipRecommended: false, available: true },
];
const base = { listed: ['IR', 'RU'], modes: MODES, defaultId: 'ws' };

describe('suggestModeFor', () => {
  test('elsewhere, or with no country, the default', () => {
    expect(suggestModeFor({ ...base, country: null, cells: null })).toBe('ws');
    expect(suggestModeFor({ ...base, country: 'DE', cells: { reality: 'available' } })).toBe('ws');
  });

  test('a listed country with no row gets the censorship-recommended mode', () => {
    expect(suggestModeFor({ ...base, country: 'IR', cells: null })).toBe('reality');
  });

  test('available beats partial; blocked and missing cells never win', () => {
    expect(
      suggestModeFor({ ...base, country: 'IR', cells: { ws: 'partial', xhttp: 'available' } }),
    ).toBe('xhttp');
    expect(
      suggestModeFor({ ...base, country: 'IR', cells: { reality: 'blocked', ws: 'partial' } }),
    ).toBe('ws');
  });

  test('ties go to the recommended mode, then the default, then catalog order', () => {
    const all = { ws: 'available', reality: 'available', xhttp: 'available' } as const;
    expect(suggestModeFor({ ...base, country: 'IR', cells: all })).toBe('reality');
    expect(
      suggestModeFor({ ...base, country: 'IR', cells: { ws: 'available', xhttp: 'available' } }),
    ).toBe('ws');
    expect(
      suggestModeFor({
        ...base,
        defaultId: 'reality',
        modes: MODES.map((m) => ({ ...m, isCensorshipRecommended: false })),
        country: 'IR',
        cells: { ws: 'partial', xhttp: 'partial' },
      }),
    ).toBe('ws');
  });

  test('a mode the backend does not serve is never suggested', () => {
    const modes = MODES.map((m) => (m.id === 'reality' ? { ...m, available: false } : m));
    expect(suggestModeFor({ ...base, modes, country: 'IR', cells: { reality: 'available' } })).toBe(
      'ws',
    );
    expect(suggestModeFor({ ...base, modes, country: 'IR', cells: null })).toBe('ws');
  });

  test('every cell blocked: the recommended mode, else the default', () => {
    const blocked = { ws: 'blocked', reality: 'blocked', xhttp: 'blocked' } as const;
    expect(suggestModeFor({ ...base, country: 'RU', cells: blocked })).toBe('reality');
    expect(
      suggestModeFor({
        ...base,
        modes: MODES.map((m) => ({ ...m, isCensorshipRecommended: false })),
        country: 'RU',
        cells: blocked,
      }),
    ).toBe('ws');
  });
});
