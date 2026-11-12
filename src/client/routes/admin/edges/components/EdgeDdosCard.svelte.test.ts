import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { EdgeDdosView } from '../../../../../shared/contracts/edges';
import { changeEdgeDdos, fetchEdgeDdos } from '@client/lib/edgesApi';
import { ApiCallError } from '@client/lib/api';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import EdgeDdosCard from './EdgeDdosCard.svelte';

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  fetchEdgeDdos: vi.fn(),
  changeEdgeDdos: vi.fn(),
}));

const VIEW: EdgeDdosView = {
  available: true,
  templates: [
    { id: 7, name: 'TCP generic', description: 'Any TCP service' },
    { id: 9, name: 'Game server', description: null },
  ],
  profiles: [],
  addresses: { v4: '192.0.2.10' },
  price: { feature: 'Advanced DDoS Protection', per30d: 60, currency: 'EUR' },
  unread: [],
};
const ON: EdgeDdosView = {
  ...VIEW,
  profiles: [
    {
      id: '41',
      address: '192.0.2.10',
      active: true,
      bgp: true,
      status: 'Updated',
      error: null,
      templateId: 7,
      templateName: 'TCP generic',
    },
  ],
};

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(canChange = true) {
  client = new QueryClient();
  app = mountWithQuery(client, EdgeDdosCard, { edgeId: 'e1', canChange });
  flushSync();
}
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
  vi.mocked(fetchEdgeDdos).mockReset();
  vi.mocked(changeEdgeDdos).mockReset();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);
const text = () => document.body.textContent ?? '';

describe('An edge DDoS card', () => {
  test('reads nothing until asked, then shows the region, the price and that it is unprotected', async () => {
    vi.mocked(fetchEdgeDdos).mockResolvedValue(VIEW);
    mount();
    expect(fetchEdgeDdos).not.toHaveBeenCalled();
    button('Check protection')!.click();
    await vi.waitFor(() => expect(text()).toContain('Not protected.'));
    expect(text()).toContain('offers it');
    expect(text()).toContain('60 EUR per 30 days');
    // Two profiles and none chosen: nothing to turn on yet.
    expect(button('Turn on')!.disabled).toBe(true);
  });

  test('turns on with the chosen profile and BGP', async () => {
    vi.mocked(fetchEdgeDdos).mockResolvedValue(VIEW);
    vi.mocked(changeEdgeDdos).mockResolvedValue({ state: 'done', view: ON });
    mount();
    button('Check protection')!.click();
    await vi.waitFor(() => expect(text()).toContain('Not protected.'));
    const select = document.querySelector<HTMLSelectElement>('#edge-ddos-profile')!;
    select.value = '9';
    select.dispatchEvent(new Event('change'));
    flushSync();
    button('Turn on')!.click();
    await vi.waitFor(() =>
      expect(changeEdgeDdos).toHaveBeenCalledWith('e1', {
        action: 'enable',
        profileTemplate: '9',
        bgp: true,
      }),
    );
    await vi.waitFor(() => expect(button('Turn off')).toBeDefined());
    expect(text()).toContain('Profile TCP generic, BGP on');
  });

  test("a refusal reads in words under the card, not the server's code", async () => {
    vi.mocked(fetchEdgeDdos).mockResolvedValue({ ...VIEW, templates: [VIEW.templates[0]!] });
    vi.mocked(changeEdgeDdos).mockRejectedValue(
      new ApiCallError(400, { error: { code: 'ddos_unavailable', message: 'gcore ddos' } }),
    );
    mount();
    button('Check protection')!.click();
    await vi.waitFor(() => expect(button('Turn on')!.disabled).toBe(false));
    button('Turn on')!.click();
    await vi.waitFor(() => expect(text()).toContain('No DDoS protection here.'));
  });

  test('an address that cannot change shows what it has and no controls', async () => {
    vi.mocked(fetchEdgeDdos).mockResolvedValue(ON);
    mount(false);
    button('Check protection')!.click();
    await vi.waitFor(() => expect(text()).toContain('Profile TCP generic'));
    expect(button('Turn off')).toBeUndefined();
    expect(text()).toContain('Protection can change only on an address FCP manages that is up.');
  });
});
