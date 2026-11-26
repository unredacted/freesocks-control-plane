import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { AttentionItem } from '@shared/contracts/edges';
import { acknowledgeForeignEdit, releaseHold } from '@client/lib/serversApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import ActionNeeded from './ActionNeeded.svelte';
import type { OverviewRow } from './overviewModel';

vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  releaseHold: vi.fn(),
  acknowledgeForeignEdit: vi.fn(),
}));

const item: AttentionItem = {
  id: 'block:e1',
  kind: 'block_suspected',
  severity: 'critical',
  relaySlug: 'node-a',
  relayId: 'r1',
  edgeId: 'e1',
  listenerKey: null,
  listenerTag: null,
  accountId: null,
  rotationId: null,
  code: null,
  facts: {},
  action: 'open_relay',
  since: null,
};

const rows: OverviewRow[] = [
  { key: 'edge:block:e1', source: 'edge', severity: 'critical', item },
  {
    key: 'main:hold:h1',
    source: 'servers',
    severity: 'warning',
    title: 'Node held closed',
    chip: null,
    text: 'node-b is held closed.',
    action: { kind: 'release', label: 'Release', slug: 'main', holdId: 'h1' },
  },
  {
    key: 'main:edit:p1',
    source: 'servers',
    severity: 'warning',
    title: 'Profile edited on the panel',
    chip: { kind: 'backend', label: 'Main panel' },
    text: 'Profile was edited on the backend.',
    detail: 'Check it, then press Seen it.',
    action: { kind: 'seen', label: 'Seen it', slug: 'main', profileUuid: 'p1' },
  },
  {
    key: 'country:XA:at-risk',
    source: 'country',
    severity: 'info',
    title: 'No working address in a country',
    chip: { kind: 'country', label: 'Country A' },
    text: 'One node has no working address there.',
    action: { kind: 'link', label: 'Open country', href: '/admin/servers/countries/XA' },
  },
];

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(max?: number) {
  vi.mocked(releaseHold)
    .mockReset()
    .mockResolvedValue({ ok: true } as never);
  vi.mocked(acknowledgeForeignEdit)
    .mockReset()
    .mockResolvedValue({ ok: true } as never);
  client = new QueryClient();
  app = mountWithQuery(client, ActionNeeded, { rows, onAction: vi.fn(), ...(max ? { max } : {}) });
  flushSync();
}
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);

describe('The merged Action needed list', () => {
  test('every source in one list, in the order given, an edge row drawn by AttentionList', () => {
    mount();
    const items = [...document.querySelectorAll('ul[aria-label="Action needed"] > li')];
    expect(items).toHaveLength(4);
    // The edge row is AttentionList's own: its title, who it is about, its button.
    expect(items[0]?.textContent).toMatch(/Block suspected/);
    expect(items[0]?.textContent).toMatch(/node-a/);
    expect(items[1]?.textContent).toMatch(/Node held closed/);
    expect(items[1]?.textContent).toMatch(/node-b is held closed/);
    expect(items[2]?.textContent).toMatch(/Main panel/);
    expect(items[3]?.textContent).toMatch(/Country A/);
    expect(button('Open country')).toBeDefined();
  });

  test('Release and Seen it call the backend', async () => {
    mount();
    button('Release')!.click();
    await vi.waitFor(() => expect(releaseHold).toHaveBeenCalledWith('main', 'h1'));
    button('Seen it')!.click();
    await vi.waitFor(() => expect(acknowledgeForeignEdit).toHaveBeenCalledWith('main', 'p1'));
  });

  test('a failed edge attention read shows inline, and the other rows still list', () => {
    vi.mocked(releaseHold).mockReset();
    client = new QueryClient();
    app = mountWithQuery(client, ActionNeeded, {
      rows: rows.slice(1),
      onAction: vi.fn(),
      edgeError: new Error('down'),
      onEdgeRetry: vi.fn(),
    });
    flushSync();
    expect(document.querySelectorAll('ul[aria-label="Action needed"] > li')).toHaveLength(3);
    expect(document.body.textContent).not.toMatch(/No action needed/);
    expect(button('Retry')).toBeDefined();
  });

  test('with only the failed edge read, it never says no action is needed', () => {
    client = new QueryClient();
    app = mountWithQuery(client, ActionNeeded, {
      rows: [],
      onAction: vi.fn(),
      edgeError: new Error('down'),
    });
    flushSync();
    expect(document.body.textContent).not.toMatch(/No action needed/);
  });

  test('the longer words wait behind the row toggle', () => {
    mount();
    expect(document.body.textContent).not.toMatch(/Check it, then press Seen it/);
    const toggle = [...document.querySelectorAll<HTMLButtonElement>('button[aria-expanded]')].find(
      (b) => b.getAttribute('aria-label')?.includes('Profile edited on the panel'),
    )!;
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    toggle.click();
    flushSync();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(document.body.textContent).toMatch(/Check it, then press Seen it/);
  });

  test('rows of one kind are one line that opens to list them', () => {
    client = new QueryClient();
    const second = { ...item, id: 'block:e2', relaySlug: 'node-c', edgeId: 'e2' };
    app = mountWithQuery(client, ActionNeeded, {
      rows: [
        rows[0]!,
        { key: 'edge:block:e2', source: 'edge', severity: 'critical', item: second } as OverviewRow,
      ],
      onAction: vi.fn(),
    });
    flushSync();
    const items = [...document.querySelectorAll('ul[aria-label="Action needed"] > li')];
    expect(items).toHaveLength(1);
    expect(items[0]?.textContent).toMatch(/Block suspected/);
    expect(items[0]?.textContent).toMatch(/node-a, node-c/);
    expect(document.querySelector('ul[aria-label="Needs attention"]')).toBeNull();
    items[0]!.querySelector<HTMLButtonElement>('button[aria-expanded]')!.click();
    flushSync();
    expect(document.querySelectorAll('ul[aria-label="Needs attention"] > li')).toHaveLength(2);
    expect(document.body.textContent).toMatch(/1 critical/);
  });

  test('beyond max, the rest wait behind Show all', () => {
    mount(2);
    expect(document.querySelectorAll('ul[aria-label="Action needed"] > li')).toHaveLength(2);
    button('Show all 4')!.click();
    flushSync();
    expect(document.querySelectorAll('ul[aria-label="Action needed"] > li')).toHaveLength(4);
  });
});
