/**
 * The node page's "Replace address": with several addresses in use it asks
 * which one, then opens that address's replace dialog (for a normal replace,
 * for "Replace now", and with a held spare to put in its place); with one
 * address in use it opens the dialog at once.
 */
import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { EdgeAdmin } from '@shared/contracts/edges';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import NodeEdgesPanel from './NodeEdgesPanel.svelte';

// jsdom has no Web Animations: a row's Details slides open with one.
Element.prototype.animate ??= function () {
  const a = { cancel() {}, finish() {}, onfinish: null as null | (() => void), currentTime: 0 };
  queueMicrotask(() => a.onfinish?.());
  return a as never;
};

/** What a test changes about the mocked reads. */
const data = vi.hoisted(() => ({
  edges: [] as unknown[],
  items: [] as unknown[],
  spares: [] as unknown[],
}));

/** A query result as the pages read it. */
const q = (d: unknown) => ({
  data: d,
  isPending: false,
  isError: false,
  error: null,
  dataUpdatedAt: Date.now(),
  refetch: () => Promise.resolve(),
});

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  relayLookupQuery: () =>
    q({
      id: 'r1',
      slug: 'node-a',
      label: 'Node A',
      origin: { kind: 'manual' },
      autoRotate: true,
      autoReplaceHolds: [],
      desiredPublished: 2,
      drainMinutes: 1440,
      edgePick: 'legacy',
      lanes: null,
      activeRotationId: null,
    }),
  attentionQuery: () =>
    q({
      items: data.items,
      origins: [{ slug: 'node-a', kind: 'ok', dot: 'ok', runId: null, failedRunId: null }],
      fleet: null,
      generatedAt: new Date().toISOString(),
    }),
  relayListenersQuery: () =>
    q({ listeners: [{ id: 'l1', listenerKey: 'k1', retired: false, transport: 'tcp' }] }),
  relayEdgesQuery: () => q(data.edges),
  relayProvidersQuery: () =>
    q({ picks: [], spares: data.spares, missing: [], pool: null, websocketNode: false }),
  edgeConfigQuery: () => q(undefined),
  edgeCountriesQuery: () => q(undefined),
  clientCheckStatusQuery: () => q({ configured: false }),
  relayTimelineQuery: () => q(undefined),
  providersQuery: () => q({ accounts: [] }),
  templatesQuery: () => q({ templates: [] }),
  preflightRelay: () => Promise.resolve({ blockers: [], warnings: [], wouldSelect: null }),
}));

function edge(id: string, v4: string, over: Record<string, unknown> = {}): EdgeAdmin {
  return {
    id,
    name: `edge-${id}`,
    status: 'active',
    publication: 'published',
    listenerId: 'l1',
    locationId: null,
    lane: null,
    audience: [],
    layer: 'l4',
    managed: true,
    health: 'online',
    reachability: { byCountry: [] },
    addresses: { v4, v6: null, hostname: null },
    verification: { required: true, current: true, stale: false },
    clientCheck: null,
    drainUntil: null,
    burnedAt: null,
    ...over,
  } as never;
}

let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(): void {
  app = mountWithQuery(new QueryClient(), NodeEdgesPanel, {
    slug: 'node-a',
    activity: false,
  } as never);
  flushSync();
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  data.edges = [];
  data.items = [];
  data.spares = [];
});

const button = (name: RegExp | string, root: ParentNode = document) =>
  [...root.querySelectorAll<HTMLElement>('button, [role="menuitem"]')].find((b) =>
    typeof name === 'string'
      ? (b.textContent ?? '').trim() === name
      : name.test(b.textContent ?? ''),
  );

/** The open dialogs' titles, in the order they are in the document. */
const dialogTitles = () =>
  [
    ...document.querySelectorAll('[role="alertdialog"][data-state="open"] [data-slot$="title"]'),
  ].map((t) => (t.textContent ?? '').trim());

/** The open dialog (one that just closed may still be in the document). */
const dialog = () => document.querySelector('[role="alertdialog"][data-state="open"]')!;

async function settle(): Promise<void> {
  flushSync();
  await tick();
  await new Promise((r) => setTimeout(r, 0));
  flushSync();
}

async function click(el: HTMLElement | undefined): Promise<void> {
  expect(el, 'the control to click is on the page').toBeTruthy();
  el!.click();
  await settle();
}

/** "Replace now, address is blocked" sits in the More menu. */
async function openMore(): Promise<void> {
  const more = document.querySelector<HTMLElement>('[aria-label="More edge actions"]');
  expect(more).toBeTruthy();
  more!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
  await settle();
}

describe('NodeEdgesPanel: Replace address', () => {
  test('several addresses in use: picking one opens its replace dialog', async () => {
    data.edges = [edge('e1', '192.0.2.1'), edge('e2', '192.0.2.2'), edge('e3', '192.0.2.3')];
    mount();
    await click(button('Replace address'));
    expect(dialogTitles()).toEqual(['Which address?']);

    await click(button('192.0.2.2', dialog()));
    expect(dialogTitles()).toEqual(['Replace 192.0.2.2?']);
  });

  test('several addresses in use: "Replace now" asks which, then opens its dialog', async () => {
    data.edges = [edge('e1', '192.0.2.1'), edge('e2', '192.0.2.2')];
    mount();
    await openMore();
    await click(button(/Replace now, address is blocked/));
    expect(dialogTitles()).toEqual(['Which address?']);

    await click(button('192.0.2.1', dialog()));
    expect(dialogTitles()).toEqual(['Replace 192.0.2.1 now?']);
  });

  test('one address in use: straight to its replace dialog, for both kinds', async () => {
    data.edges = [edge('e1', '192.0.2.1')];
    mount();
    await click(button('Replace address'));
    expect(dialogTitles()).toEqual(['Replace 192.0.2.1?']);
    await click(button('Cancel', dialog()));
    expect(dialogTitles()).toEqual([]);

    await openMore();
    await click(button(/Replace now, address is blocked/));
    expect(dialogTitles()).toEqual(['Replace 192.0.2.1 now?']);
  });

  test('a held spare: picking the address to replace starts the dialog on that spare', async () => {
    data.edges = [
      edge('e1', '192.0.2.1'),
      edge('e2', '192.0.2.2'),
      edge('s1', '192.0.2.9', { publication: 'unpublished' }),
    ];
    data.spares = [{ edgeId: 's1', takesSlot: false }];
    data.items = [
      {
        id: 'pool:r1',
        kind: 'pool_below_desired',
        severity: 'info',
        relaySlug: 'node-a',
        relayId: 'r1',
        edgeId: 's1',
        listenerKey: 'k1',
        accountId: null,
        rotationId: null,
        code: 'pool_reserved',
        facts: {},
        action: 'open_relay',
        since: null,
      },
    ];
    mount();
    await click(button(/Put it in use/));
    expect(dialogTitles()).toEqual(['192.0.2.9 stays a spare']);
    await click(button('Replace address', dialog()));
    expect(dialogTitles()).toEqual(['Which address?']);

    await click(button('192.0.2.2', dialog()));
    expect(dialogTitles()).toEqual(['Replace 192.0.2.2?']);
    // The dialog starts on the held spare, not on Automatic.
    expect(document.body.textContent).toContain('The spare 192.0.2.9');
  });
});
