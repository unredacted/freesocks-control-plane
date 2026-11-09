import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { apiClient } from '@client/lib/api';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import CountriesPage from './CountriesPage.svelte';
import { DELIVERY_KEYS } from './delivery';

const loaded = <T>(data: T) => ({
  isPending: false,
  isError: false,
  error: null,
  data,
  refetch: () => Promise.resolve(),
});

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  countryViewSummaryQuery: () =>
    loaded({
      generatedAt: Date.now(),
      switches: {
        probes: true,
        countryChecks: true,
        steering: true,
        render: true,
        names: true,
        nameChecks: true,
        realHost: true,
      },
      controls: [],
      origins: 0,
      countries: [],
      sources: [],
    }),
}));

const SETTINGS = {
  'delivery.country.detect': false,
  'delivery.country.ask': false,
  'delivery.country.steer': true,
  'delivery.country.latency': false,
  'delivery.country.stickyDays': 30,
  'delivery.country.refreshHours': 6,
  'delivery.country.ownExitRanges': [],
  'delivery.country.exits': [],
  'subscription.siteName': 'Svc',
};

vi.mock('@client/lib/queries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/queries')>()),
  adminCensoredCountriesQuery: () =>
    loaded({
      countries: [{ code: 'AA', checkEdges: true, checkNamesInside: false }],
      stored: true,
      max: 40,
      legacyChanged: [],
    }),
  appSettingsQuery: () => loaded(SETTINGS),
  configQuery: () => loaded({ locations: [{ code: 'loc-a', label: 'Alpha' }] }),
}));

let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  vi.restoreAllMocks();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);

describe('CountriesPage', () => {
  test('holds the list editor, with what the list drives above it, and the Delivery card', () => {
    app = mountWithQuery(new QueryClient(), CountriesPage, {});
    flushSync();
    const text = document.body.textContent ?? '';
    expect(text).toContain(
      'This list also drives the sign-up "Where are you connecting from?" choice, the status page matrix and the mode suggestion.',
    );
    expect(text).toContain('Censored countries');
    expect(text).toContain('Check SNIs from inside');
    expect(text).toContain('Delivery: where members connect from');
    expect(text).toContain('Exit location for each country');
    expect(button('Add a country')).toBeDefined();
    expect(button('Save delivery')?.disabled).toBe(true);
  });

  test('Delivery saves only its own settings', async () => {
    const patch = vi.spyOn(apiClient, 'patch').mockResolvedValue({ settings: SETTINGS } as never);
    app = mountWithQuery(new QueryClient(), CountriesPage, {});
    flushSync();
    const ask = [...document.querySelectorAll('label')].find((l) =>
      l.textContent?.includes('Ask members where they connect from'),
    );
    ask!.querySelector<HTMLButtonElement>('button[role="checkbox"]')!.click();
    flushSync();
    button('Save delivery')!.click();
    await vi.waitFor(() => expect(patch).toHaveBeenCalled());
    const body = patch.mock.calls[0]![1] as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([...DELIVERY_KEYS].sort());
    expect(body['delivery.country.ask']).toBe(true);
  });
});
