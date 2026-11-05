import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { clientCheckStatusQuery } from '@client/lib/edgesApi';
import type { EdgeAdmin, EdgeCountriesResponse } from '@shared/contracts/edges';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import AddressRow from './AddressRow.svelte';

// jsdom has no Web Animations: Details slides open with one.
Element.prototype.animate ??= function () {
  const a = { cancel() {}, finish() {}, onfinish: null as null | (() => void), currentTime: 0 };
  queueMicrotask(() => a.onfinish?.());
  return a as never;
};

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  clientCheckStatusQuery: vi.fn(),
}));

function edge(over: Record<string, unknown> = {}): EdgeAdmin {
  return {
    id: 'e1',
    name: 'edge-1',
    status: 'active',
    publication: 'published',
    lane: null,
    layer: 'l4',
    managed: true,
    health: 'online',
    reachability: { byCountry: [{ verdict: 'reachable' }] },
    addresses: { v4: '192.0.2.10', v6: '2001:db8::10', hostname: null },
    verification: { required: true, current: true, stale: false },
    clientCheck: null,
    drainUntil: null,
    burnedAt: null,
    ...over,
  } as never;
}

const countries = {
  enabled: true,
  countries: ['CN', 'IR', 'AE'],
  controls: [],
  groups: [],
  edges: [],
  marks: [
    { scope: 'edge', edgeId: 'e1', country: 'CN', state: 'proven' },
    { scope: 'edge', edgeId: 'e1', country: 'IR', state: 'blocked' },
  ],
  sources: [],
} as unknown as EdgeCountriesResponse;

let app: ReturnType<typeof mountWithQuery> | null = null;
const onTest = vi.fn();

function mount(props: Record<string, unknown>): string {
  vi.mocked(clientCheckStatusQuery).mockReturnValue({ data: { configured: false } } as never);
  app = mountWithQuery(new QueryClient(), AddressRow, { onTest, ...props } as never);
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  onTest.mockReset();
});

describe('AddressRow', () => {
  test('one line: both address forms, what it is, the countries by state', () => {
    const text = mount({ edge: edge(), countries });
    expect(text).toContain('192.0.2.10');
    expect(text).toContain('2001:db8::10');
    expect(text).toContain('In use, tested');
    expect(text).toMatch(/Blocked: IR · Works: CN · Not checked yet: AE/);
    // The full per-country lines wait behind Details.
    expect(text).not.toContain('Your mark');
  });

  test('Details opens the checks and each country in full', () => {
    mount({ edge: edge(), countries });
    const details = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Details'),
    )!;
    expect(details.getAttribute('aria-expanded')).toBe('false');
    details.click();
    flushSync();
    const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
    expect(details.getAttribute('aria-expanded')).toBe('true');
    expect(text).toContain('Provider check:');
    expect(text).toContain('Reachable from outside.');
    expect(text).toContain('Iran');
  });

  test('an untested spare offers Test it on the row', () => {
    const text = mount({
      edge: edge({
        publication: 'unpublished',
        verification: { required: true, current: false, stale: false },
      }),
      transport: 'VLESS + REALITY',
    });
    expect(text).toContain('Spare, not tested yet · VLESS + REALITY');
    const test = [...document.querySelectorAll('button')].find(
      (b) => b.textContent?.trim() === 'Test it',
    )!;
    test.click();
    expect(onTest).toHaveBeenCalledWith('e1');
  });
});
