import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { OriginAdmin, OriginStatus } from '@shared/contracts/edges';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import type { NodeRow } from '../lib/nodesTable';
import NodesTable from './NodesTable.svelte';

const NOW = '2026-11-09T00:00:00.000Z';
const relay = (slug: string) =>
  OriginAdmin.parse({
    id: `id-${slug}`,
    slug,
    origin: { kind: 'manual' },
    originAddress: '198.51.100.10',
    locationCode: null,
    hostMode: 'none',
    delivery: 'edge-required',
    enabled: true,
    autoRotate: false,
    providerPreference: null,
    desiredPublished: 2,
    standbyPerRelay: 0,
    cooldownMinutes: 120,
    maxRotationsPerDay: 3,
    drainMinutes: 60,
    publicationEpoch: 1,
    publishedEdgeIds: [],
    publishedCount: 1,
    standbyEdgeIds: [],
    activeRotationId: null,
    cooldownUntil: null,
    rotationsToday: 0,
    lastRotatedAt: null,
    quarantine: null,
    deleting: false,
    suspicion: null,
    updatedAt: NOW,
  });
const status = OriginStatus.parse({
  kind: 'protected',
  dot: 'green',
  code: null,
  runId: null,
  runKind: null,
  step: null,
  published: 3,
  standbys: 1,
  offline: 0,
  worstHealth: 'online',
  layers: ['l4'],
  attention: false,
  delivery: { kind: 'serving', code: null },
  failedRunId: null,
  fronted: true,
});

const base: NodeRow = {
  key: 'node:a:n-1',
  kind: 'node',
  byHand: false,
  name: 'node-one',
  machine: 'vm-a1',
  backend: { slug: 'panel-a', name: 'Panel A' },
  nodeUuid: 'n-1',
  countryCode: 'NL',
  modes: ['Freedom'],
  usersOnline: 412,
  origin: null,
  status: null,
  dot: 'green',
  sentence: 'Online, 412 people connected.',
  attention: false,
  retiring: false,
  adoptable: false,
  runId: null,
};

let app: ReturnType<typeof mountWithQuery> | null = null;
const onAdopt = vi.fn();
const onOpenRun = vi.fn();

function mount(props: Record<string, unknown>): string {
  app = mountWithQuery(new QueryClient(), NodesTable, {
    technical: false,
    showBackend: false,
    canAdopt: () => true,
    onAdopt,
    onOpenRun,
    onProvision: vi.fn(),
    onProbe: vi.fn(),
    ...props,
  } as never);
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  onAdopt.mockReset();
  onOpenRun.mockReset();
});

describe('NodesTable', () => {
  test('a direct node: name, machine name, mode, Direct, users online, its sentence, a link', () => {
    const text = mount({ rows: [base] });
    expect(text).toContain('node-one');
    expect(text).toContain('vm-a1');
    expect(text).toContain('Freedom');
    expect(text).toContain('Direct');
    expect(text).toContain('412');
    expect(text).toContain('Online, 412 people connected.');
    expect(text).not.toContain('Panel A');
    const link = document.querySelector('a[href="/admin/servers/nodes/n-1?backend=panel-a"]');
    expect(link?.textContent?.trim()).toBe('node-one');
    expect(text).not.toContain('Provider check');
  });

  test('a fronted origin added by hand, with more than one backend and the technical columns', () => {
    const text = mount({
      rows: [
        { ...base, backend: { slug: 'panel-a', name: 'Panel A' } },
        {
          ...base,
          key: 'origin:m',
          kind: 'origin',
          byHand: true,
          name: 'Office box',
          machine: null,
          backend: null,
          nodeUuid: null,
          usersOnline: null,
          origin: {
            relay: relay('manual-a'),
            pool: [],
            standbys: 1,
            draining: 0,
            needsOperator: 0,
            rotation: null,
          },
          status,
          runId: 'run-1',
        },
      ],
      technical: true,
      showBackend: true,
    });
    expect(text).toContain('Panel A');
    expect(text).toContain('Added by hand');
    expect(text).toContain('3 fronted, 1 spare');
    expect(text).toContain('Provider check');
    expect(text).toContain('manual-a');
    expect(text).toContain('No origin: members connect directly.');
    const progress = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Show progress'),
    )!;
    progress.click();
    expect(onOpenRun).toHaveBeenCalledWith('run-1');
  });

  test('Adopt shows only when the row can be adopted and the page allows it', () => {
    expect(mount({ rows: [{ ...base, adoptable: true }] })).toContain('Adopt as an enrolled node');
    const button = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Adopt'),
    )!;
    button.click();
    expect(onAdopt).toHaveBeenCalledOnce();
    unmount(app!);
    app = null;
    document.body.innerHTML = '';
    expect(mount({ rows: [{ ...base, adoptable: true }], canAdopt: () => false })).not.toContain(
      'Adopt',
    );
  });
});
