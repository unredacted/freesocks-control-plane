import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { SniTransport, SniTransportNode } from '../../../../../shared/contracts/sni';
import { buildNameTestLink } from '@client/lib/sniApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import TestNameDialog from './TestNameDialog.svelte';

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  buildNameTestLink: vi.fn(),
}));

const send: NonNullable<SniTransport['send']> = {
  rolloutId: 'r1',
  generation: 2,
  phase: 'panel_confirmed',
  witness: null,
};
const node: SniTransportNode = {
  relaySlug: 'relay-a',
  nodeUuid: 'n1',
  nodeName: 'Node A',
  inUse: 3,
  waitingTest: 2,
  pending: ['a.site.example', 'b.site.example'],
  testable: [
    { edgeId: 'e1', name: 'Address one' },
    { edgeId: 'e2', name: 'Address two' },
  ],
  autoTest: null,
};

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({ open: true, send, node });

beforeEach(() => {
  // Never answers: what matters here is which link each request asks for.
  vi.mocked(buildNameTestLink)
    .mockReset()
    .mockReturnValue(new Promise(() => {}));
  client = new QueryClient();
  props.open = true;
  app = mountWithQuery(client, TestNameDialog, props);
  flushSync();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const select = (label: string) => {
  const l = [...document.querySelectorAll('label')].find((x) => x.textContent?.includes(label))!;
  return l.querySelector('select')!;
};
const choose = (label: string, value: string) => {
  const s = select(label);
  s.value = value;
  s.dispatchEvent(new Event('change', { bubbles: true }));
  flushSync();
};

describe('Test one name', () => {
  test('opening asks for one link, through the first address, for the first name', () => {
    expect(vi.mocked(buildNameTestLink).mock.calls).toEqual([['r1', 'e1', 'a.site.example']]);
  });

  test('another address or name is kept and asked for', () => {
    choose('Through', 'e2');
    expect(select('Through').value).toBe('e2');
    expect(vi.mocked(buildNameTestLink).mock.lastCall).toEqual(['r1', 'e2', 'a.site.example']);

    choose('Name', 'b.site.example');
    expect(select('Through').value).toBe('e2');
    expect(select('Name').value).toBe('b.site.example');
    expect(vi.mocked(buildNameTestLink).mock.lastCall).toEqual(['r1', 'e2', 'b.site.example']);
    expect(buildNameTestLink).toHaveBeenCalledTimes(3);
  });

  test('reopening starts again from the first address and name', () => {
    choose('Through', 'e2');
    props.open = false;
    flushSync();
    props.open = true;
    flushSync();
    expect(select('Through').value).toBe('e1');
    expect(vi.mocked(buildNameTestLink).mock.lastCall).toEqual(['r1', 'e1', 'a.site.example']);
  });
});
