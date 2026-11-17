import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { intentsQuery, modeTwinAction, setupQuery } from '@client/lib/serversApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import ModeTwinsCard from './ModeTwinsCard.svelte';

vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  intentsQuery: vi.fn(),
  modeTwinAction: vi.fn(),
  setupQuery: vi.fn(),
}));

type Twin = {
  tag: string;
  port: number;
  path: string;
  detaching: boolean;
  attached: boolean;
} | null;

const mode = (over: Record<string, unknown> = {}) => ({
  slug: 'freedom-ws',
  name: 'Freedom-WebSocket',
  shape: { transport: 'ws', fronting: 'edge-l7' },
  tag: 'FREEDOM_WEBSOCKET',
  transport: { port: 8443, path: '/ws', serverNames: [], target: null },
  twin: null as Twin,
  twinCandidates: [] as { tag: string; port: number; path: string }[],
  ...over,
});
const reality = {
  slug: 'privacy-reality',
  name: 'Privacy-Reality',
  shape: { transport: 'reality', fronting: 'direct' },
  tag: 'PRIVACY_REALITY',
  transport: { port: 443, path: null, serverNames: [], target: null },
  twin: null,
  twinCandidates: [],
};
const node = (name: string, twin: string | null) => ({
  id: name,
  name,
  mode: { slug: 'freedom-ws' },
  retirement: null,
  twin: twin ? { state: twin } : null,
});

let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(
  modes: unknown[],
  nodes: unknown[] | null = [],
  canWrite = true,
): { text: () => string; button: (label: string) => HTMLButtonElement | undefined } {
  vi.mocked(setupQuery).mockReturnValue({
    data: { modes, profile: { name: 'FreeSocks-Config', uuid: 'p1' } },
  } as never);
  // `null`: the node list is still loading, or could not be read.
  vi.mocked(intentsQuery).mockReturnValue(
    (nodes ? { data: { intents: nodes } } : { data: undefined, isError: true }) as never,
  );
  vi.mocked(modeTwinAction).mockReset().mockResolvedValue({ op: null });
  app = mountWithQuery(new QueryClient(), ModeTwinsCard, { slug: 'panel', canWrite });
  flushSync();
  return {
    text: () => (document.body.textContent ?? '').replace(/\s+/g, ' '),
    button: (label) =>
      [...document.body.querySelectorAll('button')].find((b) => b.textContent?.trim() === label),
  };
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('the encrypted twins of a backend’s modes', () => {
  test('nothing for a backend without a WebSocket mode behind a CDN', () => {
    const v = mount([reality]);
    expect(v.text().trim()).toBe('');
  });

  test('no twin and nothing to make one from: offers to add an encrypted transport', () => {
    const v = mount([reality, mode()]);
    expect(v.text()).toContain('Encryption behind a CDN');
    expect(v.text()).toContain('Freedom-WebSocket');
    expect(v.text()).not.toContain('Privacy-Reality');
    expect(v.text()).toContain('no encrypted WebSocket transport to make one from');
    expect(v.button('Add an encrypted transport')).toBeDefined();
    expect(v.button('Make it the twin')).toBeUndefined();
  });

  test('an encrypted transport on the profile is offered, and making it the twin asks the server', async () => {
    const v = mount([
      mode({ twinCandidates: [{ tag: 'FREEDOM_WEBSOCKET_E', port: 8444, path: '/wse' }] }),
    ]);
    expect(v.text()).toContain('Freedom WebSocket E (port 8444, path /wse)');
    v.button('Make it the twin')!.click();
    await tick();
    expect(vi.mocked(modeTwinAction)).toHaveBeenCalledWith('panel', 'freedom-ws', {
      action: 'attach',
      transportTag: 'FREEDOM_WEBSOCKET_E',
    });
  });

  test('a twin says how many of the mode’s nodes serve it, and can be taken away', () => {
    const twin = {
      tag: 'FREEDOM_WEBSOCKET_E',
      port: 8444,
      path: '/wse',
      detaching: false,
      attached: true,
    };
    const v = mount(
      [mode({ twin })],
      [node('node-a', 'serving'), node('node-b', null), node('node-c', 'activating')],
    );
    expect(v.text()).toContain('1 of 3 nodes serve it.');
    expect(v.button('Take it away')).toBeDefined();
    expect(v.button('Make it the twin')).toBeUndefined();
    expect(v.button('Add an encrypted transport')).toBeUndefined();
  });

  test('while the node list is unknown it does not claim that no node serves the twin', () => {
    const twin = {
      tag: 'FREEDOM_WEBSOCKET_E',
      port: 8444,
      path: '/wse',
      detaching: false,
      attached: true,
    };
    const v = mount([mode({ twin })], null);
    expect(v.text()).toContain('Encrypted twin: Freedom WebSocket E, port 8444, path /wse.');
    expect(v.text()).not.toMatch(/No node|nodes? serves?/);
  });

  test('an attach that did not land offers the same attach again', async () => {
    const twin = {
      tag: 'FREEDOM_WEBSOCKET_E',
      port: 8444,
      path: '/wse',
      detaching: false,
      attached: false,
    };
    const v = mount([mode({ twin })], [node('node-a', null)]);
    expect(v.text()).toContain('the change did not land');
    expect(v.text()).not.toContain('Turn it on from a node’s page');
    expect(v.button('Take it away')).toBeDefined();
    v.button('Try again')!.click();
    await tick();
    expect(vi.mocked(modeTwinAction)).toHaveBeenCalledWith('panel', 'freedom-ws', {
      action: 'attach',
      transportTag: 'FREEDOM_WEBSOCKET_E',
    });
  });

  test('without the right to change the backend it only says where things stand', () => {
    const v = mount(
      [mode({ twinCandidates: [{ tag: 'FREEDOM_WEBSOCKET_E', port: 8444, path: '/wse' }] })],
      [],
      false,
    );
    expect(v.text()).toContain('No encrypted twin.');
    expect(document.body.querySelectorAll('button')).toHaveLength(0);
  });
});
