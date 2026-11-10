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

const ZERO = { proven: 0, blocked: 0, unknown: 0 };
/** One listed country as the summary gives it, with its key counts. */
const country = (code: string, keys: { answered: number; guessed: number }) => ({
  country: code,
  listed: { checkEdges: true, checkNamesInside: false, nameChecksRun: false },
  probes: { asked: true, windowMs: 0, sources: [] },
  totals: { addresses: ZERO, names: ZERO, originsAtRisk: 0, lastEvidenceAt: null },
  worstOnBlocked: null,
  meantFor: { locations: 0, blocked: 0 },
  snis: { used: 0, onlyHere: 0, preferred: 0 },
  keys,
});
const summary = vi.hoisted(() => ({
  countries: [] as unknown[],
  keys: {
    counted: false,
    countedAt: null as number | null,
    optOut: 0,
    neither: 0,
    otherGuessed: 0,
  },
}));

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
      countries: summary.countries,
      keys: summary.keys,
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
  summary.countries = [];
  summary.keys = { counted: false, countedAt: null, optOut: 0, neither: 0, otherGuessed: 0 };
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

  test('each country says how many keys are set to it, with what no country owns below', () => {
    summary.countries = [
      country('AA', { answered: 1180, guessed: 32 }),
      country('BB', { answered: 0, guessed: 0 }),
    ];
    summary.keys = {
      counted: true,
      countedAt: Date.now() - 2 * 3_600_000,
      optOut: 40,
      neither: 20150,
      otherGuessed: 0,
    };
    app = mountWithQuery(new QueryClient(), CountriesPage, {});
    flushSync();
    const rows = [...document.querySelectorAll('ul[aria-label="Countries"] > li')].map(
      (li) => li.textContent ?? '',
    );
    expect(rows[0]).toContain(
      "1,212 keys are set to it: 1,180 by the member's own answer, 32 by FCP's guess.",
    );
    expect(rows[1]).toContain('No key is set to it.');
    const below = document.querySelector('section[aria-label="Keys by country"]')!;
    expect(below.textContent).toContain('40 keys have the opt-out');
    expect(below.textContent).toContain(
      '20,150 keys of freedom modes have no answer and no guess.',
    );
    expect(below.textContent).toContain('A key of a privacy mode carries no country');
    // Counts only: the numbers lead to no key and no member.
    expect(below.querySelector('a, button')).toBeNull();
  });

  test('before the first count a row gives no number, and the page says why', () => {
    summary.countries = [country('AA', { answered: 0, guessed: 0 })];
    app = mountWithQuery(new QueryClient(), CountriesPage, {});
    flushSync();
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('No key is set to it.');
    expect(text).toContain('Keys by country are not counted yet.');
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
