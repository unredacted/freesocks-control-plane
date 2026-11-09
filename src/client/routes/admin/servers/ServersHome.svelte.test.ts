import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { router } from '@client/stores/router.svelte';
import { mountWithQuery } from '../../../testing/mountWithQuery';
import ServersHome from './ServersHome.svelte';

// The probe chart's library reads a media query when it loads; jsdom has none.
vi.hoisted(() => {
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent: () => false,
  })) as never;
});

/**
 * The Nodes page end to end against canned API answers: two backends, a
 * direct node, a fronted node and an origin added by hand in one table.
 */
const NOW = '2026-11-09T00:00:00.000Z';
const state = { observedAt: NOW, attemptedAt: NOW, ok: true, errorCode: null, counts: null };
const instance = (id: string, slug: string, name: string) => ({
  ...state,
  id,
  slug,
  name,
  backend: 'remnawave',
  isActive: true,
  observable: true,
  writable: true,
  setUp: true,
});
const node = (nodeUuid: string, name: string, usersOnline: number) => ({
  nodeUuid,
  name,
  address: null,
  port: null,
  countryCode: 'NL',
  online: true,
  isDisabled: false,
  usersOnline,
  tags: [],
  xrayVersion: null,
  frontKeys: null,
  profile: { profileUuid: 'p', name: 'Default', transportCount: 1, changedAt: null },
  transports: [{ tag: 't', realityPublicKeyMismatch: false, modeGroups: [], addresses: [] }],
});
const tree = (id: string, slug: string, nodes: unknown[]) => ({
  instance: { id, slug, name: slug },
  observable: true,
  state,
  nodes,
  profiles: [],
  modeGroups: [],
  addresses: [],
  unattached: { profiles: [], addresses: [] },
});
const relay = (slug: string, origin: unknown, publishedCount: number) => ({
  id: `id-${slug}`,
  slug,
  label: null,
  origin,
  originAddress: 'x',
  locationCode: null,
  enabled: true,
  publishedCount,
  desiredPublished: 2,
  publishedEdgeIds: [],
  standbyEdgeIds: [],
  quarantine: null,
  deleting: false,
  suspicion: null,
  qualificationCredential: false,
});
const status = (published: number) => ({
  kind: 'protected',
  dot: 'green',
  code: null,
  runId: null,
  runKind: null,
  step: null,
  published,
  standbys: 1,
  offline: 0,
  worstHealth: 'online',
  layers: ['l4'],
  attention: false,
  delivery: { kind: 'serving', code: null },
  failedRunId: null,
  fronted: true,
});

const ANSWERS: Record<string, unknown> = {
  '/api/v1/admin/servers/summary': {
    config: { 'manage.observe': true, 'manage.enabled': false },
    instances: [instance('b-1', 'panel-a', 'Panel A'), instance('b-2', 'panel-b', 'Panel B')],
  },
  '/api/v1/admin/servers/panel-a/tree': tree('b-1', 'panel-a', [
    node('n-1', 'node-direct', 12),
    node('n-2', 'node-fronted', 30),
  ]),
  '/api/v1/admin/servers/panel-b/tree': tree('b-2', 'panel-b', [node('n-3', 'node-b', 5)]),
  '/api/v1/admin/servers/panel-a/nodes/intents': { intents: [], holds: [] },
  '/api/v1/admin/servers/panel-b/nodes/intents': { intents: [], holds: [] },
  '/api/v1/admin/servers/panel-a/ops': { ops: [] },
  '/api/v1/admin/servers/panel-b/ops': { ops: [] },
  '/api/v1/admin/servers/panel-a/port-changes': { changes: [] },
  '/api/v1/admin/servers/panel-b/port-changes': { changes: [] },
  '/api/v1/admin/edges/summary': {
    counts: {},
    relays: [
      {
        relay: relay(
          'node-fronted',
          { kind: 'panel-node', backendServerId: 'b-1', nodeName: 'node-fronted', nodeUuid: 'n-2' },
          3,
        ),
        pool: [],
        standbys: 1,
        draining: 0,
        needsOperator: 0,
        rotation: null,
      },
      {
        relay: relay('office-box', { kind: 'manual' }, 1),
        pool: [],
        standbys: 0,
        draining: 0,
        needsOperator: 0,
        rotation: null,
      },
    ],
    generatedAt: NOW,
  },
  '/api/v1/admin/edges/attention': {
    items: [],
    origins: [
      { relayId: 'id-node-fronted', relaySlug: 'node-fronted', status: status(3) },
      { relayId: 'id-office-box', relaySlug: 'office-box', status: status(1) },
    ],
    fleet: null,
  },
  '/api/v1/admin/edges/providers': { accounts: [] },
};

vi.mock('@client/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/api')>()),
  apiClient: {
    get: (path: string) =>
      path in ANSWERS ? Promise.resolve(ANSWERS[path]) : Promise.reject(new Error(`no ${path}`)),
    post: () => Promise.reject(new Error('no writes')),
    patch: () => Promise.reject(new Error('no writes')),
    put: () => Promise.reject(new Error('no writes')),
    delete: () => Promise.reject(new Error('no writes')),
  },
}));

let app: ReturnType<typeof mountWithQuery> | null = null;

async function mount(url: string): Promise<string> {
  router.navigate(url, { replace: true });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  app = mountWithQuery(client, ServersHome, {} as never);
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 0));
    await tick();
  }
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('Nodes', () => {
  test('one table across both backends, with fronted, direct and hand-added rows', async () => {
    const text = await mount('/admin/servers/nodes');
    for (const name of ['node-direct', 'node-fronted', 'node-b', 'office-box'])
      expect(text).toContain(name);
    expect(text).toContain('3 fronted, 1 spare');
    expect(text).toContain('Direct');
    expect(text).toContain('Added by hand');
    expect(text).toContain('Backend: all');
    expect(text).toContain('Panel A');
    expect(text).toContain('Technical columns');
    expect(text).not.toContain('Provider check');
  });

  test('filters: Fronted, Added by hand and one backend', async () => {
    let text = await mount('/admin/servers/nodes?show=fronted');
    expect(text).toContain('node-fronted');
    expect(text).not.toContain('node-direct');
    unmount(app!);
    text = await mount('/admin/servers/nodes?show=by-hand');
    expect(text).toContain('office-box');
    expect(text).not.toContain('node-fronted');
    unmount(app!);
    text = await mount('/admin/servers/nodes?backend=panel-b');
    expect(text).toContain('node-b');
    expect(text).not.toContain('node-direct');
    expect(text).toContain('Backend: Panel B');
  });

  test('technical columns bring the All origins columns', async () => {
    const text = await mount('/admin/servers/nodes?columns=technical');
    expect(text).toContain('Provider check');
    expect(text).toContain('Qualification');
    expect(text).toContain('Members dark');
    expect(text).toContain('No origin: members connect directly.');
  });
});
