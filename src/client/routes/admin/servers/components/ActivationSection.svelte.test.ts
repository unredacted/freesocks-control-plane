import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { reviewQuery } from '@client/lib/serversApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import ActivationSection from './ActivationSection.svelte';

vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  reviewQuery: vi.fn(),
}));

/** A fronted node closed by a maintenance that was finished: no protection run is open. */
const closedNode = (patch: Record<string, unknown> = {}) => ({
  id: 'i1',
  name: 'node-a',
  nodeUuid: 'n1',
  stage: 'awaiting_approval',
  disposition: 'staged',
  state: 'ready',
  code: null,
  maintenance: false,
  retirement: null,
  protection: null,
  adopted: false,
  modeEnabled: true,
  mode: { slug: 'freedom-reality', name: 'Freedom-Reality', shape: { fronting: 'edge-l4' } },
  origin: { hostname: null, dns: null },
  ...patch,
});

function reviewWith(atOnce: 'kept' | 'external' | null) {
  return {
    isPending: false,
    isError: false,
    error: null,
    refetch: () => Promise.resolve(),
    data: {
      reviewHash: 'h1',
      blockers: atOnce ? [] : ['servers.standbys_missing'],
      stage: 'awaiting_approval',
      shape: {
        listeners: [{ listenerKey: 'reality', accountId: 'a1', templateHash: 't1' }],
        addressTuples: [],
        configRevision: 'abcdef12',
        subscriptionTemplates: {},
      },
      display: {
        standbys: [
          {
            listenerKey: 'reality',
            layer: 'l4',
            endpoint: '198.51.100.7:443',
            accountName: 'L4',
            locationLabel: 'Place',
          },
        ],
        atOnce,
      },
    },
  };
}

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(atOnce: 'kept' | 'external' | null, intent = closedNode()) {
  vi.mocked(reviewQuery)
    .mockClear()
    .mockReturnValue(reviewWith(atOnce) as never);
  client = new QueryClient();
  app = mountWithQuery(client, ActivationSection, {
    slug: 'panel',
    intent: intent as never,
    origin: true,
  });
  flushSync();
}
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

describe('a fronted node closed with no protection open', () => {
  test('whose approval reuses its addresses shows the approval card, not Protect again', () => {
    mount('kept');
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/Closed\. Approve it to reopen it on the addresses it already has\./);
    expect(text).toMatch(/What you approve/);
    expect(text).toMatch(/members get 198\.51\.100\.7:443/);
    expect(text).not.toMatch(/Protect again makes new addresses/);
    // The review is read for this node only.
    expect(vi.mocked(reviewQuery).mock.calls[0]![1]()).toBe('i1');
  });

  test('under maintenance the card carries Finish maintenance once', () => {
    mount('kept', closedNode({ maintenance: true, disposition: 'unavailable' }));
    const finish = [...document.querySelectorAll('button')].filter(
      (b) => b.textContent?.trim() === 'Finish maintenance',
    );
    expect(finish).toHaveLength(1);
    expect(document.body.textContent).toMatch(/Closed for maintenance/);
  });

  test('with nothing to reuse it still says to protect it again', () => {
    mount(null);
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/Protect again makes new addresses/);
    expect(text).not.toMatch(/What you approve/);
  });

  test('a live node never reads the review here', () => {
    mount(null, closedNode({ stage: 'live', disposition: 'live' }));
    expect(vi.mocked(reviewQuery).mock.calls.every((c) => c[1]() === null)).toBe(true);
  });
});
