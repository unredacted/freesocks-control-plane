import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type {
  CountryListDetail,
  CountryListsResponse,
  CountryListVersion,
  CountryListView,
} from '../../../../../shared/contracts/countryLists';
import {
  countryListQuery,
  countryListsQuery,
  decideCountryListVersion,
  updateCountryList,
} from '@client/lib/countryListsApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import ListPage from './ListPage.svelte';
import ListsPage from './ListsPage.svelte';

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  networksQuery: () => ({ isPending: false, isError: false, data: { networks: [] } }),
  familiesQuery: () => ({ isPending: false, isError: false, data: { families: [] } }),
}));

vi.mock('@client/lib/countryListsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/countryListsApi')>()),
  countryListQuery: vi.fn(),
  countryListsQuery: vi.fn(),
  decideCountryListVersion: vi.fn(),
  updateCountryList: vi.fn(),
}));

const loaded = <T>(data: T) => ({
  isPending: false,
  isError: false,
  error: null,
  data,
  refetch: () => Promise.resolve(),
});

const version = (over: Partial<CountryListVersion> = {}): CountryListVersion => ({
  id: 'v1',
  at: '2026-11-02T10:00:00.000Z',
  source: 'upload',
  status: 'held',
  heldReasons: ['first_version'],
  counts: {
    entries: 4,
    names: 1,
    wildcards: 1,
    v4Ranges: 1,
    v6Ranges: 0,
    v4: 256,
    v6: 0,
    invalid: 1,
    nonPublic: 0,
    tooBroad: 0,
    capped: 0,
  },
  diff: null,
  samples: ['not a name!'],
  failure: null,
  decidedAt: null,
  byPerson: false,
  ...over,
});

const LIST: CountryListView = {
  id: 'l1',
  label: 'Mobile',
  country: 'RU',
  regime: 'allowlist',
  networks: [],
  source: { kind: 'paste' },
  fetchEveryHours: 24,
  enabled: true,
  active: null,
  held: version(),
  busy: null,
  lastFetch: null,
  confirmedAt: null,
  fresh: false,
  feeds: [],
  watchEdges: false,
  preferNames: false,
};

let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  vi.clearAllMocks();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);

describe('ListPage', () => {
  test('a version waiting says why, and Use it decides it', async () => {
    const detail: CountryListDetail = {
      enabled: true,
      staleDays: 30,
      list: LIST,
      versions: [version()],
      edges: null,
      preferSwitch: false,
      prefer: null,
    };
    vi.mocked(countryListQuery).mockReturnValue(loaded(detail) as never);
    vi.mocked(decideCountryListVersion).mockResolvedValue({ ok: true });
    app = mountWithQuery(new QueryClient(), ListPage, { id: 'l1' });
    flushSync();
    const text = document.body.textContent ?? '';
    expect(text).toContain('A version waits for you');
    expect(text).toContain('This is the first version. Look it over before FCP uses it.');
    expect(text).toContain('1 hostname, 1 wildcard, 1 IPv4 range (256 addresses).');
    expect(text).toContain('Left out: 1 line that could not be read.');
    expect(text).toContain('not a name!');
    expect(text).toContain('Paste a new copy');
    expect(text).toContain('Hostnames as SNI candidates');
    expect(text).toContain('Its hostnames go nowhere.');
    button('Use it')!.click();
    await vi.waitFor(() =>
      expect(decideCountryListVersion).toHaveBeenCalledWith('l1', 'v1', 'approve'),
    );
  });
});

describe('ListPage, Prefer its SNIs', () => {
  const detail = (over: Partial<CountryListDetail> = {}): CountryListDetail => ({
    enabled: true,
    staleDays: 30,
    list: {
      ...LIST,
      held: null,
      active: version({ status: 'active', heldReasons: [] }),
      confirmedAt: new Date().toISOString(),
      fresh: true,
    },
    versions: [],
    edges: null,
    preferSwitch: true,
    prefer: { inUse: 2, preferred: 0, curated: true },
    ...over,
  });
  const prefer = () =>
    document.querySelector<HTMLButtonElement>('button[role="switch"][id$="-prefer"]')!;

  test('off: says so, counts what the list holds, and asks before turning on', async () => {
    vi.mocked(countryListQuery).mockReturnValue(loaded(detail()) as never);
    vi.mocked(updateCountryList).mockResolvedValue({ ok: true });
    app = mountWithQuery(new QueryClient(), ListPage, { id: 'l1' });
    flushSync();
    const text = () => document.body.textContent ?? '';
    expect(text()).toContain('Prefer its SNIs');
    expect(text()).toContain('Off. This list changes nothing members get.');
    expect(text()).toContain('2 SNIs in use are on this list.');
    expect(prefer().getAttribute('aria-checked')).toBe('false');
    prefer().click();
    flushSync();
    // Nothing is sent until the question is answered.
    expect(updateCountryList).not.toHaveBeenCalled();
    expect(text()).toContain('Members elsewhere get what they got.');
    button('Prefer its SNIs')!.click();
    await vi.waitFor(() =>
      expect(updateCountryList).toHaveBeenCalledWith('l1', { preferNames: true }),
    );
  });

  test('on, with the deployment switch off: says nothing is preferred and points at Settings', () => {
    const d = detail({ preferSwitch: false });
    vi.mocked(countryListQuery).mockReturnValue(
      loaded({ ...d, list: { ...d.list, preferNames: true } }) as never,
    );
    app = mountWithQuery(new QueryClient(), ListPage, { id: 'l1' });
    flushSync();
    const text = document.body.textContent ?? '';
    expect(prefer().getAttribute('aria-checked')).toBe('true');
    expect(text).toContain(
      'Nothing is preferred until "Prefer SNIs on allowlists" is on in Settings, Country lists.',
    );
    expect(text).toContain('Open Settings.');
    expect(text).toContain('Prefers its SNIs');
  });

  test('a block list has no such switch', () => {
    const d = detail({ prefer: null });
    vi.mocked(countryListQuery).mockReturnValue(
      loaded({ ...d, list: { ...d.list, regime: 'blocklist' } }) as never,
    );
    app = mountWithQuery(new QueryClient(), ListPage, { id: 'l1' });
    flushSync();
    expect(document.body.textContent).not.toContain('Prefer its SNIs');
  });
});

describe('ListsPage', () => {
  test('lists each list with its state, and says when lists are off', () => {
    const lists: CountryListsResponse = {
      enabled: false,
      staleDays: 30,
      defaultFetchHours: 24,
      lists: [
        LIST,
        {
          ...LIST,
          id: 'l2',
          label: 'Ranges',
          source: { kind: 'url', url: 'https://example.com/list.txt' },
          held: null,
          active: version({ status: 'active', heldReasons: [] }),
          confirmedAt: new Date().toISOString(),
          fresh: true,
        },
      ],
    };
    vi.mocked(countryListsQuery).mockReturnValue(loaded(lists) as never);
    app = mountWithQuery(new QueryClient(), ListsPage, {});
    flushSync();
    const text = document.body.textContent ?? '';
    expect(text).toContain('Country lists are off');
    expect(text).toContain('Waiting for you');
    expect(text).toContain('In use');
    expect(text).toContain('Fetched from example.com every 24 hours.');
    expect(text).toContain('Look something up');
  });
});
