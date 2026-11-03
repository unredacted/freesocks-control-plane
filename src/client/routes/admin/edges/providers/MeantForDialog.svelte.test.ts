import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type {
  EdgeLocationAdmin,
  EdgeProviderAccountAdmin,
} from '../../../../../shared/contracts/edges';
import { estimateLocationCountries, setLocationCountries } from '../../../../lib/edgesApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import MeantForDialog from './MeantForDialog.svelte';

vi.mock('../../../../lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../lib/edgesApi')>()),
  estimateLocationCountries: vi.fn(),
  setLocationCountries: vi.fn(),
}));
vi.mock('@client/lib/queries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/queries')>()),
  adminCensoredCountriesQuery: () => ({
    isPending: false,
    isError: false,
    data: {
      countries: [
        { code: 'IR', checkEdges: true, checkNamesInside: false },
        { code: 'RU', checkEdges: true, checkNamesInside: false },
      ],
      stored: true,
      max: 40,
      legacyChanged: [],
    },
  }),
}));

const account = { id: 'acc1', name: 'Account' } as EdgeProviderAccountAdmin;
const location = { id: 'loc1', label: 'Place', meantFor: ['RU'] } as EdgeLocationAdmin;

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({ open: true, account, location });

beforeEach(() => {
  vi.mocked(estimateLocationCountries)
    .mockReset()
    .mockResolvedValue({
      valid: true,
      code: null,
      steering: true,
      countries: [
        {
          country: 'IR',
          nodes: [{ relaySlug: 'node-a', label: null, sampled: 600, moved: 450 }],
        },
      ],
    });
  vi.mocked(setLocationCountries)
    .mockReset()
    .mockResolvedValue({ ok: true, changed: true, codes: ['RU', 'IR'], nodes: 1 });
  client = new QueryClient();
  props.open = true;
  app = mountWithQuery(client, MeantForDialog, props);
  flushSync();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const box = (name: string) =>
  [...document.querySelectorAll('label')]
    .find((l) => l.textContent?.trim() === name)!
    .querySelector<HTMLElement>('[role="checkbox"]')!;
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label)!;

describe('Countries a location is meant for', () => {
  test('opens on what the location is meant for, nothing to save yet', () => {
    expect(box('Russia').getAttribute('aria-checked')).toBe('true');
    expect(box('Iran').getAttribute('aria-checked')).toBe('false');
    expect(button('Save countries').disabled).toBe(true);
    expect(estimateLocationCountries).not.toHaveBeenCalled();
  });

  test('a change asks who would move, says it, and saves the new list', async () => {
    box('Iran').click();
    flushSync();
    expect(box('Iran').getAttribute('aria-checked')).toBe('true');
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain(
        'Iran: about 75% on node-a of members get a different first address.',
      ),
    );
    expect(vi.mocked(estimateLocationCountries).mock.calls[0]).toEqual([
      'acc1',
      'loc1',
      ['RU', 'IR'],
    ]);
    button('Save countries').click();
    await vi.waitFor(() =>
      expect(vi.mocked(setLocationCountries).mock.calls[0]).toEqual(['acc1', 'loc1', ['RU', 'IR']]),
    );
  });
});
