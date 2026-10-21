import { describe, expect, test } from 'vitest';
import { catalogAge, catalogStale, zoneChoices } from './zones';

const entry = (
  items: Array<{ id: string; label: string; facts?: Record<string, string> }>,
  at: number | null,
) => ({
  items,
  truncated: false,
  refreshedAt: at,
  error: null,
  errorDetail: null,
});

describe('zoneChoices', () => {
  test("the catalog's zones and the account's own zone locations, active first, then by name", () => {
    const catalog = {
      kinds: {
        zones: entry(
          [
            { id: 'z2', label: 'example.net', facts: { status: 'pending' } },
            { id: 'z1', label: 'example.org', facts: { status: 'active' } },
          ],
          1,
        ),
      },
    };
    const locations = [
      { placement: { zoneId: 'z1', zoneName: 'example.org' } },
      // A zone the last listing missed (or that predates it) is still offered.
      { placement: { zoneId: 'z3', zoneName: 'b.example.org' } },
      // An L4 location names no zone.
      { placement: { zone: 'de-fra1' } },
    ];
    expect(zoneChoices(catalog, locations)).toEqual([
      { id: 'z3', name: 'b.example.org', status: null, located: true },
      { id: 'z1', name: 'example.org', status: 'active', located: true },
      { id: 'z2', name: 'example.net', status: 'pending', located: false },
    ]);
  });

  test('nothing listed and no locations is an empty menu', () => {
    expect(zoneChoices(undefined, [])).toEqual([]);
    expect(zoneChoices({ kinds: {} }, [])).toEqual([]);
  });
});

describe('catalog freshness', () => {
  const view = (at: number | null) => ({
    kinds: { zones: entry([], at), tlsConfigurations: entry([], at === null ? null : at - 5) },
    staleAfterMs: 1_000,
  });

  test('the age is the newest listing of any kind; never listed is stale', () => {
    expect(catalogAge(view(10_000))).toBe(10_000);
    expect(catalogAge(view(null))).toBeNull();
    expect(catalogStale(view(null), 20_000)).toBe(true);
    expect(catalogStale(view(10_000), 10_500)).toBe(false);
    expect(catalogStale(view(10_000), 11_001)).toBe(true);
    // Nothing loaded yet: nothing to decide.
    expect(catalogStale(undefined)).toBe(false);
  });
});
