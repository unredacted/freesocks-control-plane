import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { EdgeListMarks as Marks } from '../../../../../shared/contracts/countryLists';
import { edgeListMarksQuery, markEdgeAddressSeen } from '@client/lib/countryListsApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import EdgeListMarks from './EdgeListMarks.svelte';

vi.mock('@client/lib/countryListsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/countryListsApi')>()),
  edgeListMarksQuery: vi.fn(),
  markEdgeAddressSeen: vi.fn(),
}));

let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  vi.clearAllMocks();
});

const row = (over: Partial<Marks['lists'][number]['addresses'][number]>) => ({
  family: 'v4' as const,
  address: '192.0.2.10',
  state: 'listed' as const,
  since: null,
  checkedAt: null,
  markId: 'm4',
  leftAt: null,
  needsLook: false,
  ...over,
});

function mount(data: Marks) {
  vi.mocked(edgeListMarksQuery).mockReturnValue({
    isPending: false,
    isError: false,
    data,
    dataUpdatedAt: Date.now(),
  } as never);
  app = mountWithQuery(new QueryClient(), EdgeListMarks, { edgeId: 'e1' });
  flushSync();
}

describe('EdgeListMarks', () => {
  test('an address that left a list has Seen it, which tells the server', async () => {
    vi.mocked(markEdgeAddressSeen).mockResolvedValue({ ok: true });
    mount({
      enabled: true,
      lists: [
        {
          listId: 'l1',
          label: 'Works',
          country: 'RU',
          checked: true,
          fresh: true,
          enabled: true,
          addresses: [
            row({ state: 'left', needsLook: true, leftAt: 1_800_000_000_000 }),
            row({ family: 'v6', address: '2001:db8::10', state: 'not_listed', markId: 'm6' }),
          ],
        },
      ],
    });
    const text = document.body.textContent ?? '';
    expect(text).toContain('Lists of what works');
    expect(text).toContain('Works');
    expect(text).toContain('Left it.');
    expect(text).toContain('Not on it, and never was.');
    const buttons = [...document.querySelectorAll('button')].filter(
      (b) => b.textContent?.trim() === 'Seen it',
    );
    expect(buttons).toHaveLength(1);
    buttons[0]!.click();
    await vi.waitFor(() =>
      expect(markEdgeAddressSeen).toHaveBeenCalledWith('l1', 'm4', 1_800_000_000_000),
    );
  });

  test('says why a list is not checked now, and shows nothing when no list watches', () => {
    mount({
      enabled: false,
      lists: [
        {
          listId: 'l1',
          label: 'Works',
          country: 'RU',
          checked: false,
          fresh: true,
          enabled: true,
          addresses: [row({})],
        },
      ],
    });
    expect(document.body.textContent).toContain('Not checked now: country lists are off.');
    unmount(app!);
    app = null;
    mount({ enabled: true, lists: [] });
    expect(document.body.textContent ?? '').not.toContain('Lists of what works');
  });
});
