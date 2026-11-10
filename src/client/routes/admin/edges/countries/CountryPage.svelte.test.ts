import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { CountryViewResponse } from '@shared/contracts/edges';
import { apiClient } from '@client/lib/api';
import { countryViewQuery } from '@client/lib/edgesApi';
import { adminCensoredCountriesQuery, appSettingsQuery } from '@client/lib/queries';
import { router } from '@client/stores/router.svelte';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import CountryPage from './CountryPage.svelte';

const loaded = <T>(data: T) => ({
  isPending: false,
  isError: false,
  error: null,
  data,
  refetch: () => Promise.resolve(),
});

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  countryViewQuery: vi.fn(),
  edgeCountriesQuery: () => ({
    isPending: false,
    isError: false,
    data: {
      enabled: true,
      countries: ['AA'],
      controls: [],
      groups: [],
      edges: [],
      marks: [],
      sources: [],
    },
  }),
  probeMatrixQuery: () => ({
    isPending: false,
    isError: false,
    data: { countries: ['AA', 'BB'], targets: [] },
  }),
}));

vi.mock('@client/lib/queries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/queries')>()),
  adminCensoredCountriesQuery: vi.fn(),
  appSettingsQuery: vi.fn(),
  configQuery: () => ({
    isPending: false,
    isError: false,
    data: { locations: [{ code: 'loc-a', label: 'Alpha' }] },
  }),
}));

vi.mock('@client/lib/countryListsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/countryListsApi')>()),
  countryListsQuery: () => ({ isPending: false, isError: false, data: { lists: [] } }),
}));

const ZERO = { proven: 0, blocked: 0, unknown: 0 };
function view(over: Partial<CountryViewResponse> = {}): CountryViewResponse {
  return {
    country: 'AA',
    generatedAt: Date.now(),
    listed: { checkEdges: true, checkNamesInside: false, nameChecksRun: false },
    probes: { asked: true, windowMs: 0, sources: [] },
    switches: {
      probes: true,
      countryChecks: true,
      steering: true,
      render: true,
      names: true,
      nameChecks: true,
      realHost: false,
    },
    controls: [],
    curated: false,
    totals: {
      addresses: ZERO,
      names: ZERO,
      originsAtRisk: 0,
      lastEvidenceAt: null,
    },
    origins: [],
    snis: [],
    meantFor: [],
    exits: [],
    keys: { counted: true, countedAt: Date.now() - 3_600_000, answered: 180, guessed: 32 },
    namePool: null,
    sources: [],
    ...over,
  };
}

const LIST = {
  countries: [
    { code: 'AA', checkEdges: true, checkNamesInside: false },
    { code: 'BB', checkEdges: false, checkNamesInside: true },
  ],
  stored: true,
  max: 40,
  legacyChanged: [],
};

let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  vi.restoreAllMocks();
  router.navigate('/', { replace: true, scroll: false });
});

function open(path: string, v: CountryViewResponse, list = LIST) {
  router.navigate(path, { replace: true, scroll: false });
  vi.mocked(countryViewQuery).mockReturnValue(loaded(v) as never);
  vi.mocked(adminCensoredCountriesQuery).mockReturnValue(loaded(list) as never);
  vi.mocked(appSettingsQuery).mockReturnValue(
    loaded({ 'delivery.country.exits': [{ country: 'BB', locations: ['loc-a'] }] }) as never,
  );
  app = mountWithQuery(new QueryClient(), CountryPage, { code: 'AA' });
  flushSync();
}

const text = () => document.body.textContent ?? '';
const sectionLinks = () =>
  [...document.querySelectorAll('nav[aria-label="Sections"] a')].map((a) => ({
    label: a.textContent?.trim(),
    href: a.getAttribute('href'),
    current: a.getAttribute('aria-current') === 'page',
  }));

describe('CountryPage', () => {
  test('opens on Summary, with the section bar and one line per section', () => {
    open('/admin/servers/countries/AA', view());
    const links = sectionLinks();
    expect(links.map((l) => l.label)).toEqual([
      'Summary',
      'Addresses for this country',
      'SNIs',
      'Lists',
      'Probes',
      'Checks from here',
      'Exit',
    ]);
    expect(links[0]).toMatchObject({ current: true, href: '/admin/servers/countries/AA' });
    expect(links[5]!.href).toBe('/admin/servers/countries/AA?section=checks');
    expect(text()).toContain('Edges are checked from here. SNIs are not checked from inside.');
    expect(text()).toContain('Least-loaded location.');
    expect(text()).toContain('Mark an address for this country');
  });

  test('Summary says how many keys are set to the country, and what that leaves out', () => {
    open('/admin/servers/countries/AA', view());
    expect(text()).toContain(
      "212 keys are set to this country: 180 by the member's own answer, 32 by FCP's guess.",
    );
    expect(text()).toContain('A key of a privacy mode carries no country');
    expect(text()).toContain('never answered and was never guessed is counted for no country');
    // Counts only: nothing leads from the number to a key or a member.
    const card = document.querySelector('[aria-label="Keys set to this country"]')!;
    expect(card.querySelector('a, button')).toBeNull();
  });

  test('a country off the list gets no count of its own', () => {
    open(
      '/admin/servers/countries/AA',
      view({ listed: null, keys: { counted: true, countedAt: 1, answered: 0, guessed: 0 } }),
    );
    expect(text()).toContain(
      'Keys are counted per country only for countries on the censored-country list.',
    );
    expect(text()).not.toContain('No key is set to this country.');
  });

  test('before the first count it says so, never zero', () => {
    open(
      '/admin/servers/countries/AA',
      view({ keys: { counted: false, countedAt: null, answered: 0, guessed: 0 } }),
    );
    expect(text()).toContain('Keys by country are not counted yet.');
    expect(text()).not.toContain('No key is set to this country.');
  });

  test("SNIs: the country's own list comes first", () => {
    const sni = {
      name: 'cover.example',
      family: 'fam-a',
      familyLabel: 'Fam A',
      state: 'proven' as const,
      basis: 'checks' as const,
      scope: 'only_here' as const,
      blockedElsewhere: [],
      handed: 3,
      transports: 1,
      preferred: false,
      preferDoubt: null,
    };
    open('/admin/servers/countries/AA?section=snis', view({ curated: true, snis: [sni] }));
    expect(text()).toContain('SNIs in AA');
    expect(text()).toContain('cover.example');
  });

  test('Checks from here: a switch saves the whole list with only that switch changed', async () => {
    const put = vi.spyOn(apiClient, 'put').mockResolvedValue(LIST as never);
    open('/admin/servers/countries/AA?section=checks', view());
    expect(sectionLinks().find((l) => l.current)?.label).toBe('Checks from here');
    expect(text()).toContain('Whoever runs one sees the address and the SNI.');
    const inside = document.querySelector<HTMLButtonElement>(
      'button[role="switch"][id$="checkNamesInside"]',
    );
    expect(inside).not.toBeNull();
    inside!.click();
    await vi.waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0]![0]).toBe('/api/v1/admin/censored-countries');
    expect(put.mock.calls[0]![1]).toEqual({
      countries: [
        { code: 'AA', checkEdges: true, checkNamesInside: true },
        { code: 'BB', checkEdges: false, checkNamesInside: true },
      ],
    });
  });

  test('a country off the list cannot be marked, and can be added from Checks from here', async () => {
    const put = vi.spyOn(apiClient, 'put').mockResolvedValue(LIST as never);
    open('/admin/servers/countries/AA?section=checks', view({ listed: null }), {
      ...LIST,
      countries: [LIST.countries[1]!],
    });
    const button = (label: string) =>
      [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);
    expect(button('Mark an address for this country')?.disabled).toBe(true);
    expect(text()).toContain('is not on the censored-country list');
    button('Add it to the list')!.click();
    await vi.waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0]![1]).toEqual({
      countries: [
        { code: 'BB', checkEdges: false, checkNamesInside: true },
        { code: 'AA', checkEdges: true, checkNamesInside: false },
      ],
    });
  });

  test('Exit: saves only this country row, keeping the others', async () => {
    const patch = vi.spyOn(apiClient, 'patch').mockResolvedValue({ settings: {} } as never);
    open('/admin/servers/countries/AA?section=exit', view());
    const first = document.querySelector<HTMLSelectElement>('select[aria-label$="location 1"]')!;
    first.value = 'loc-a';
    first.dispatchEvent(new Event('change', { bubbles: true }));
    flushSync();
    [...document.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Save exit')!
      .click();
    await vi.waitFor(() => expect(patch).toHaveBeenCalled());
    expect(patch.mock.calls[0]![1]).toEqual({
      'delivery.country.exits': [
        { country: 'BB', locations: ['loc-a'] },
        { country: 'AA', locations: ['loc-a'] },
      ],
    });
  });
});
