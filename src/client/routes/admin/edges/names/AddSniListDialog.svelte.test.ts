import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import type { SniTransport } from '../../../../../shared/contracts/sni';
import { createFamily, manageTransport, previewManage, sniKeys } from '@client/lib/sniApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import AddSniListDialog from './AddSniListDialog.svelte';
import type { AddListFrom } from './lib/addList';

vi.mock('@client/lib/sniApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/sniApi')>()),
  createFamily: vi.fn(),
  // Refetching after a write is not what these tests are about (and never fetches).
  invalidateSni: vi.fn(),
  manageTransport: vi.fn(),
  previewManage: vi.fn(),
}));

const transport: SniTransport = {
  transportUuid: 't-1',
  tag: 'REALITY_IN',
  profileUuid: 'p-1',
  profileName: 'Default',
  port: 443,
  coverSite: 'cover.example:443',
  listed: 2,
  profileNodes: [],
  list: null,
  send: null,
  nodes: [],
  sameCoverSite: [],
};

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const onAdded = vi.fn();
const props = $state<{ open: boolean; from: AddListFrom; onAdded: (slug: string) => void }>({
  open: true,
  from: { kind: 'site' },
  onAdded,
});

beforeEach(() => {
  vi.mocked(createFamily).mockResolvedValue({});
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // The network picker reads the networks: fresh in the cache, never fetched.
  client.setQueryData(sniKeys.networks, { networks: [{ slug: 'net-a', label: 'Network A' }] });
  props.open = true;
  onAdded.mockReset();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
  vi.mocked(createFamily).mockReset();
});

const text = () => document.body.textContent ?? '';
const input = (label: string) => {
  const l = [...document.querySelectorAll('label')].find((x) => x.textContent?.trim() === label)!;
  return document.getElementById(l.getAttribute('for')!) as HTMLInputElement;
};
const type = (label: string, value: string) => {
  const el = input(label);
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
};
const button = (name: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === name)!;
const show = (from: AddListFrom) => {
  props.from = from;
  app = mountWithQuery(client, AddSniListDialog, props);
  flushSync();
};

describe('Add an SNI list', () => {
  test('prefilled from a found site: one click adds exactly that list', async () => {
    show({
      kind: 'site',
      prefill: { coverSite: 'www.site.example', port: 443, requireH2: true, network: 'net-a' },
    });
    expect(text()).toContain('Add an SNI list');
    expect(input('Cover site').value).toBe('www.site.example');
    expect(input('Name').value).toBe('site.example');
    expect(input('Short id').value).toBe('site-example');
    button('Add').click();
    await vi.waitFor(() => expect(onAdded).toHaveBeenCalledWith('site-example'));
    expect(createFamily).toHaveBeenCalledWith({
      slug: 'site-example',
      label: 'site.example',
      targetAddress: 'www.site.example',
      targetPort: 443,
      requireH2: true,
      network: 'net-a',
    });
  });

  test('blank: the short id follows the cover site until edited, and an SNIs page is refused', async () => {
    show({ kind: 'site' });
    type('Cover site', 'other.example');
    expect(input('Short id').value).toBe('other-example');
    type('Short id', 'checks');
    expect(text()).toContain('"checks" is the address of an SNIs page. Pick another.');
    type('Cover site', 'third.example');
    expect(input('Short id').value).toBe('checks');
    button('Add').click();
    flushSync();
    expect(createFamily).not.toHaveBeenCalled();
  });

  test("from a port: the server's suggestion, then one call that takes the port's SNIs in", async () => {
    vi.mocked(previewManage).mockResolvedValue({
      dryRun: true,
      coverSite: 'cover.example:443',
      resolved: true,
      network: { slug: 'net-a', label: 'Network A' },
      label: 'REALITY_IN SNIs',
    });
    vi.mocked(manageTransport).mockResolvedValue({
      dryRun: false,
      family: 'reality-in',
      created: true,
      bindingId: 'b-1',
      imported: { added: 2, lines: [], capped: 0 },
      placeSet: false,
      cert: null,
    } as unknown as Awaited<ReturnType<typeof manageTransport>>);
    show({ kind: 'port', backendSlug: 'panel-a', transport, nodeUuid: 'n-1' });
    expect(text()).toContain('From REALITY_IN, port 443.');
    await vi.waitFor(() => expect(text()).toContain('Keep SNIs on Network A.'));
    button('Add the list').click();
    await vi.waitFor(() => expect(onAdded).toHaveBeenCalledWith('reality-in'));
    expect(manageTransport).toHaveBeenCalledWith({
      backendSlug: 'panel-a',
      transportUuid: 't-1',
      network: 'net-a',
      label: 'REALITY_IN SNIs',
      requireH2: false,
      nodeUuid: 'n-1',
    });
  });
});
