import { QueryClient } from '@tanstack/svelte-query';
import { createRawSnippet, flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { providersQuery, relayProvidersQuery, templatesQuery } from '@client/lib/edgesApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import NodeProvidersCard from './NodeProvidersCard.svelte';

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  relayProvidersQuery: vi.fn(),
  providersQuery: vi.fn(),
  templatesQuery: vi.fn(),
}));

let app: ReturnType<typeof mountWithQuery> | null = null;

/** The node's address rows, as NodeEdgesPanel hands them (one line per call here). */
const calls: Array<[string | null, string[]]> = [];
const rows = createRawSnippet((location: () => string | null, known: () => string[]) => {
  calls.push([location(), known()]);
  return { render: () => `<ul><li>row for ${location() ?? 'every address'}</li></ul>` };
});

function mount(set: Record<string, unknown>): string {
  vi.mocked(relayProvidersQuery).mockReturnValue(set as never);
  vi.mocked(providersQuery).mockReturnValue({ data: { accounts: [] } } as never);
  vi.mocked(templatesQuery).mockReturnValue({ data: { templates: [] } } as never);
  app = mountWithQuery(new QueryClient(), NodeProvidersCard, {
    relay: { id: 'r1', slug: 'node-a' },
    busy: false,
    onRunStarted: () => {},
    rows,
  } as never);
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  calls.length = 0;
});

describe('NodeProvidersCard without its locations', () => {
  test('while the locations load, every address is listed ungrouped', () => {
    const text = mount({ isPending: true, isError: false, data: undefined });
    expect(text).toContain('Loading the locations');
    expect(text).toContain('row for every address');
    expect(calls).toEqual([[null, []]]);
  });

  test('when the locations cannot be read, the addresses and a retry both show', () => {
    const refetch = vi.fn();
    const text = mount({
      isPending: false,
      isError: true,
      error: new Error('boom'),
      data: undefined,
      refetch,
    });
    expect(text).toContain('row for every address');
    const retry = [...document.querySelectorAll('button')].find((b) =>
      /try again|retry/i.test(b.textContent ?? ''),
    );
    expect(retry).toBeTruthy();
  });
});
