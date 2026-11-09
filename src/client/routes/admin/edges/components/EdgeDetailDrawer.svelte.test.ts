import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { EdgeAdmin, EdgeConfigView, EdgeDetail } from '../../../../../shared/contracts/edges';
import {
  edgeConfigQuery,
  edgeCountriesQuery,
  edgeDetailQuery,
  providersQuery,
  renewEdgeName,
} from '@client/lib/edgesApi';
import { ApiCallError } from '@client/lib/api';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import EdgeDetailDrawer from './EdgeDetailDrawer.svelte';

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  edgeConfigQuery: vi.fn(),
  edgeCountriesQuery: vi.fn(),
  edgeDetailQuery: vi.fn(),
  providersQuery: vi.fn(),
  renewEdgeName: vi.fn(),
}));

// What the watched lists say about the address: none watch it here.
vi.mock('@client/lib/countryListsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/countryListsApi')>()),
  edgeListMarksQuery: () => ({
    isPending: false,
    isError: false,
    data: { enabled: false, lists: [] },
  }),
}));

const loaded = <T>(data: T) => ({
  isPending: false,
  isError: false,
  error: null,
  data,
  refetch: () => Promise.resolve(),
});

/** An active L4 address FCP owns, planned before names were on: it has none. */
const EDGE = {
  id: 'e1',
  relayId: 'r1',
  name: 'address-one',
  provider: null,
  managed: true,
  layer: 'l4',
  status: 'active',
  statusChangedAt: '2026-11-01T00:00:00.000Z',
  createdAt: '2026-11-01T00:00:00.000Z',
  publication: 'published',
  publishedAt: '2026-11-01T00:00:00.000Z',
  health: 'online',
  lastHealthAt: null,
  reachability: null,
  progress: { done: 4, total: 4, percent: 100 },
  failure: null,
  locationId: null,
  placeKey: null,
  choices: null,
  front: null,
  poolIndex: 0,
  addresses: { v4: '192.0.2.10', v6: null, hostname: null },
  drainUntil: null,
  burnedAt: null,
  destroyedAt: null,
  destroyAttempts: 0,
  readiness: null,
  frontQualification: null,
  listeners: [],
  resources: [],
} as unknown as EdgeAdmin;

const settings = (enabled: boolean) =>
  ({
    config: { names: { enabled, zones: ['zone-a'], moveQuietDays: 30 } },
    nameZones: [{ id: 'zone-a', zone: 'example.org', account: 'DNS' }],
  }) as unknown as EdgeConfigView;

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(namesOn: boolean) {
  const detail: EdgeDetail = { edge: EDGE, live: null, probes: [], name: null };
  vi.mocked(edgeDetailQuery).mockReturnValue(loaded(detail) as never);
  vi.mocked(edgeConfigQuery).mockReturnValue(loaded(settings(namesOn)) as never);
  vi.mocked(edgeCountriesQuery).mockReturnValue(loaded({ countries: [] }) as never);
  vi.mocked(providersQuery).mockReturnValue(loaded({ accounts: [], optionSchemas: {} }) as never);
  vi.mocked(renewEdgeName).mockReset().mockResolvedValue({ ok: true });
  client = new QueryClient();
  app = mountWithQuery(client, EdgeDetailDrawer, { edgeId: 'e1', onClose: () => {} });
  flushSync();
}
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);

describe('An address with no name', () => {
  test('hostnames on: Give it a hostname asks the server for its first hostname', async () => {
    mount(true);
    expect(document.body.textContent).toContain('It has none, so members get its IPs.');
    button('Give it a hostname')!.click();
    await vi.waitFor(() => expect(renewEdgeName).toHaveBeenCalledWith('e1'));
  });

  test('a refusal although names look on says why under the button', async () => {
    mount(true);
    vi.mocked(renewEdgeName).mockRejectedValue(
      new ApiCallError(409, { error: { code: 'edge.names_off', message: 'off' } }),
    );
    button('Give it a hostname')!.click();
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain('No chosen zone can take a hostname now.'),
    );
    expect(button('Give it a hostname')).toBeDefined();
  });

  test('names off: says why in place of the button', () => {
    mount(false);
    expect(button('Give it a hostname')).toBeUndefined();
    expect(document.body.textContent).toContain('Hostnames for load balancer addresses are off.');
  });
});
