import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  EDGE_CONFIG_BOUNDS,
  EDGE_DEFAULTS,
  flattenEdgeConfig,
} from '../../../../../convex/lib/edgeConfig';
import { edgeConfigQuery } from '@client/lib/edgesApi';
import { router } from '@client/stores/router.svelte';
import { mountWithQuery } from '../../../testing/mountWithQuery';
import EdgesSettings from './EdgesSettings.svelte';

const loaded = <T>(data: T) => ({
  isPending: false,
  isError: false,
  error: null,
  data,
  refetch: () => Promise.resolve(),
});
const pending = () => ({ isPending: true, isError: false, data: undefined });

vi.mock('@client/lib/edgesApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/edgesApi')>()),
  edgeConfigQuery: vi.fn(),
  freedomDeliveryQuery: () => ({
    isPending: false,
    isError: false,
    data: { on: false, since: null },
  }),
  freedomPreviewQuery: () => pending(),
  clientCheckStatusQuery: () => pending(),
  maintenanceQuery: () => pending(),
  deliveryBindingsQuery: () => pending(),
  trustSummaryQuery: () => pending(),
}));
vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  serverSummaryQuery: () => ({
    isPending: false,
    isError: false,
    data: { config: { 'manage.observe': true, 'manage.enabled': false }, instances: [] },
  }),
}));

function configView(over: Record<string, unknown> = {}) {
  const config = structuredClone(EDGE_DEFAULTS) as unknown as Record<string, unknown>;
  Object.assign(config, over);
  return {
    config,
    secrets: { globalpingToken: false, ripeAtlasKey: false },
    families: Object.keys(EDGE_DEFAULTS.render.clients),
    bounds: EDGE_CONFIG_BOUNDS,
    defaults: flattenEdgeConfig(EDGE_DEFAULTS),
    nameZones: [],
  };
}

let app: ReturnType<typeof mountWithQuery> | null = null;

async function mount(url: string, view = configView()): Promise<string> {
  router.navigate(url, { replace: true });
  vi.mocked(edgeConfigQuery).mockReturnValue(loaded(view) as never);
  app = mountWithQuery(new QueryClient(), EdgesSettings, {});
  flushSync();
  await tick();
  return text();
}
const text = () => (document.body.textContent ?? '').replace(/\s+/g, ' ');
const rowIds = () =>
  [...document.querySelectorAll('[id^="setting-"]')].map((el) => el.id.replace(/^setting-/, ''));

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  window.matchMedia = vi.fn().mockReturnValue({ matches: true }) as never;
  window.scrollTo = vi.fn() as never;
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('Settings, one searchable page', () => {
  test('shows every group, with the cards and the panel switches moved in', async () => {
    const t = await mount('/admin/servers/settings');
    for (const label of [
      'Automatic work',
      'Replacement timing',
      'Trust and open addresses',
      'Block detection',
      'Country checks',
      'Address hostnames',
      'Freedom modes only through edges',
      'Edge-required places',
      "FCP's own client check",
      'Backend panels',
      'Read panels every ten minutes',
      'Changes from here',
    ]) {
      expect(t).toContain(label);
    }
    expect(t).not.toMatch(/[–—]/);
  });

  test('a search looks in every group and leaves only what matches', async () => {
    const t = await mount('/admin/servers/settings?group=maintenance&q=drain');
    expect(t).toContain('Drain time');
    expect(t).toContain('Drain time of a burned edge');
    expect(t).not.toContain('Evaluation window');
    expect(t).not.toContain('Backend panels');
    expect(t).toMatch(/\d+ settings match, in every group\./);
    expect(rowIds()).toContain('drainMinutes');
  });

  test('one group without a search', async () => {
    const t = await mount('/admin/servers/settings?group=detection');
    expect(t).toContain('Evaluation window');
    expect(t).not.toContain('Drain time');
    expect(rowIds().every((id) => id.startsWith('detect-'))).toBe(true);
  });

  test('"Show changed only" keeps what differs from its default, marked Changed', async () => {
    const t = await mount(
      '/admin/servers/settings?changed=1',
      configView({ drainMinutes: EDGE_DEFAULTS.drainMinutes + 5 }),
    );
    expect(rowIds()).toEqual(['drainMinutes', 'manage-observe']);
    expect(t).toContain('Changed');
    expect(t).not.toContain('Evaluation window');
  });

  test('says so when nothing matches', async () => {
    const t = await mount('/admin/servers/settings?q=zzzzqqqq');
    expect(t).toContain('No setting matches. Try another word.');
    expect(t).toContain('Show every setting');
  });

  test('a deep link to a field opens its group and scrolls to it', async () => {
    await mount('/admin/servers/settings?group=probes&q=nothing&field=detect.windowMinutes');
    await tick();
    flushSync();
    expect(router.search).toContain('group=detection');
    expect(router.search).not.toContain('q=');
    expect(document.getElementById('setting-detect-windowMinutes')).not.toBeNull();
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
  });
});
