import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { SniCandidateRow, SniHuntScopeView } from '../../../../../shared/contracts/sni';
import { fetchHuntScope } from '@client/lib/sniApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import AddSuggestionsDialog from './AddSuggestionsDialog.svelte';

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  fetchHuntScope: vi.fn(),
}));

const row = (name: string): SniCandidateRow => ({
  id: `c-${name}`,
  name,
  site: name,
  sources: ['cert'],
  rank: 1234,
  state: 'new',
  inFamily: null,
  check: {
    at: '2026-10-27T00:00:00.000Z',
    code: null,
    tlsVersion: 'TLSv1.3',
    alpn: 'h2',
    answers: { v4: 1, v6: 0, onNetwork: 'all' },
    shown: ['192.0.2.1'],
    dialled: '192.0.2.1',
    port: 443,
  },
  extra: null,
  passes: 1,
  baseScore: 20,
  score: 40,
  parts: null,
  listed: true,
  timing: null,
  own: null,
  ooni: null,
  countries: [],
  firstSeenAt: '2026-10-27T00:00:00.000Z',
});

const view = (...names: string[]): SniHuntScopeView => ({
  scope: {
    kind: 'family',
    slug: 'list-a',
    label: 'List A',
    network: null,
    target: null,
    hunt: null,
  },
  candidates: names.map(row),
  page: { cursor: null, done: true },
  groups: [],
  counts: { new: names.length, failing: 0, gone: 0, ignored: 0, added: 0, unchecked: 0, usable: 0 },
  families: [],
  ct: [],
});

let offered: SniHuntScopeView;
let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({ open: true, family: 'list-a', label: 'List A' });

beforeEach(() => {
  offered = view('a.site.example', 'b.site.example', 'c.site.example');
  vi.mocked(fetchHuntScope).mockImplementation(async () => offered);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  props.open = true;
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const text = () => document.body.textContent ?? '';
const box = (name: string) =>
  document.querySelector<HTMLButtonElement>(`[aria-label="Pick ${name}"]`)!;
const show = () => {
  app = mountWithQuery(client, AddSuggestionsDialog, props);
};

describe('Add suggestions', () => {
  test('opens on waiting suggestions, every one picked', async () => {
    show();
    await vi.waitFor(() => expect(text()).toContain('3 of 3 picked'));
    for (const n of ['a.site.example', 'b.site.example', 'c.site.example']) {
      expect(text()).toContain(n);
      expect(box(n).getAttribute('aria-checked')).toBe('true');
    }
    expect(text()).toContain('Add 3 names');
  });

  test('a refetch picks a new name, drops a gone one and keeps an unpick', async () => {
    show();
    await vi.waitFor(() => expect(text()).toContain('3 of 3 picked'));
    box('b.site.example').click();
    flushSync();
    expect(text()).toContain('2 of 3 picked');

    offered = view('a.site.example', 'b.site.example', 'd.site.example');
    await client.refetchQueries();
    await vi.waitFor(() => expect(text()).toContain('d.site.example'));
    expect(text()).not.toContain('c.site.example');
    expect(box('a.site.example').getAttribute('aria-checked')).toBe('true');
    expect(box('b.site.example').getAttribute('aria-checked')).toBe('false');
    expect(box('d.site.example').getAttribute('aria-checked')).toBe('true');
    expect(text()).toContain('2 of 3 picked');
  });

  test('closing forgets the unpicks', async () => {
    show();
    await vi.waitFor(() => expect(text()).toContain('3 of 3 picked'));
    box('a.site.example').click();
    flushSync();
    expect(text()).toContain('2 of 3 picked');

    props.open = false;
    flushSync();
    props.open = true;
    await vi.waitFor(() => expect(text()).toContain('3 of 3 picked'));
  });
});
