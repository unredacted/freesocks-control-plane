import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import EdgesHome from './EdgesHome.svelte';

/** What a test changes about the mocked reads. */
const flags = vi.hoisted(() => ({ attentionFails: false, panelOk: true }));

/** A query result as the pages read it. */
const q = (data: unknown) => ({
  data,
  isPending: false,
  isError: false,
  error: null,
  dataUpdatedAt: Date.now(),
  refetch: () => Promise.resolve(),
});

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  edgeSummaryQuery: () =>
    q({
      counts: {
        relays: 0,
        published: 0,
        suspected: 0,
        rotating: 0,
        quarantined: 0,
        unreachableEdges: 0,
        needsOperator: 0,
      },
      relays: [],
      generatedAt: new Date().toISOString(),
    }),
  attentionQuery: () =>
    flags.attentionFails
      ? {
          data: undefined,
          isPending: false,
          isError: true,
          error: new Error('down'),
          dataUpdatedAt: 0,
          refetch: () => Promise.resolve(),
        }
      : q({
          items: [
            {
              id: 'block:e1',
              kind: 'block_suspected',
              severity: 'warning',
              relaySlug: 'node-a',
              relayId: 'r1',
              edgeId: 'e1',
              listenerKey: null,
              accountId: null,
              rotationId: null,
              code: null,
              facts: {},
              action: 'open_relay',
              since: null,
            },
          ],
          origins: [],
          fleet: null,
          generatedAt: new Date().toISOString(),
        }),
  edgeConfigQuery: () => q(undefined),
  clientCheckStatusQuery: () => q(undefined),
  setupStatusQuery: () => q({ complete: true, steps: [] }),
  countryViewSummaryQuery: () =>
    q({
      countries: [
        {
          country: 'XA',
          totals: { originsAtRisk: 0, addresses: { blocked: 1 }, names: { blocked: 0 } },
          meantFor: { locations: 0, blocked: 0 },
        },
      ],
    }),
  providersQuery: () => q({ accounts: [] }),
  probeSummaryQuery: () => q(undefined),
  maintenanceQuery: () => q({ frozen: false, reason: null, since: null }),
  freedomDeliveryQuery: () => q({ on: false, since: null }),
  relayTimelineQuery: () => q(undefined),
}));

vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  serverSummaryQuery: () =>
    q({
      config: { 'manage.enabled': true, 'manage.observe': true },
      instances: [{ slug: 'main', name: 'Main', observable: true, writable: true, setUp: true }],
    }),
  serverTreeQuery: () =>
    q({
      state: { ok: flags.panelOk },
      nodes: [{ nodeUuid: 'n1', name: 'node-a', online: true, isDisabled: false, transports: [] }],
      profiles: [],
      unattached: { addresses: [] },
    }),
  intentsQuery: () =>
    q({
      intents: [{ nodeUuid: 'n1', name: 'node-a' }],
      holds: [{ id: 'h1', heldNodeNames: ['node-a'], since: new Date().toISOString() }],
    }),
  setupQuery: () => q({ exists: true, state: 'ready', running: false, code: null }),
  opsQuery: () => q({ ops: [] }),
  portChangesQuery: () => q({ changes: [] }),
}));

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  transportsQuery: () => q(undefined),
}));

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
  flags.attentionFails = false;
  flags.panelOk = true;
});

async function mountHome() {
  client = new QueryClient();
  app = mountWithQuery(client, EdgesHome, {});
  flushSync();
  await tick();
  flushSync();
}

describe('Overview', () => {
  test('one sentence, one merged Action needed list, the switches and the tiles', async () => {
    await mountHome();

    const text = document.body.textContent ?? '';
    expect(document.querySelector('[role="status"]')?.textContent).toMatch(
      /1 node online\. 2 things need you\./,
    );
    // Edge attention and the backend's hold, in one list.
    const rows = document.querySelectorAll('ul[aria-label="Action needed"] > li');
    expect(rows).toHaveLength(2);
    expect(rows[1]?.textContent).toMatch(/node-a is held closed since a profile change/);
    // Automatic work: new work, Freedom, and both panel switches.
    expect(text).toMatch(/New work is running/);
    expect(text).toMatch(/Freedom modes only through edges/);
    expect(text).toMatch(/Read panels every 10 minutes/);
    expect(text).toMatch(/Changes from here/);
    // Tiles.
    const tiles = [...document.querySelectorAll('ul[aria-label="Figures"] > li')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(tiles[0]).toMatch(/Nodes 1 · \? · 0/);
    expect(tiles[1]).toMatch(/Countries 1 of 1/);
    // No fronted node yet: the offer to front one.
    expect(text).toMatch(/A fronted node gives members a provider address/);
  });

  test('a failed edge attention read shows inline; the backend rows still list', async () => {
    flags.attentionFails = true;
    await mountHome();
    const rows = document.querySelectorAll('ul[aria-label="Action needed"] > li');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.textContent).toMatch(/node-a is held closed/);
    expect(
      [...document.querySelectorAll('button')].some((b) => b.textContent?.trim() === 'Retry'),
    ).toBe(true);
  });

  test('a failed panel read is not counted as online and is listed as Action needed', async () => {
    flags.panelOk = false;
    await mountHome();
    expect(document.querySelector('[role="status"]')?.textContent).toMatch(
      /Node status could not be read\. 3 things need you\./,
    );
    expect(document.body.textContent).toMatch(/The panel could not be read/);
  });
});
