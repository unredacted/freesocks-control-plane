import { describe, expect, test } from 'vitest';
import { OriginAdmin, OriginStatus } from '../../../../../shared/contracts/edges';
import type { NodeIntentView, NodeView } from '../../../../../shared/contracts/servers';
import {
  addressesWords,
  buildNodeRows,
  filterCounts,
  filterNodeRows,
  parseLayer,
  parseShow,
  pickStatus,
  rowHref,
  rowMatches,
  searchMatches,
  type BackendInput,
  type OriginRow,
} from './nodesTable';
import { backendOf, serversPaths } from './routes';

const NOW = '2026-11-09T00:00:00.000Z';

const node = (over: Partial<NodeView> = {}): NodeView =>
  ({
    nodeUuid: 'n-1',
    name: 'node-one',
    address: null,
    port: null,
    countryCode: 'NL',
    online: true,
    isDisabled: false,
    usersOnline: 4,
    tags: [],
    xrayVersion: null,
    frontKeys: null,
    profile: { profileUuid: 'p', name: 'Default', transportCount: 1, changedAt: null },
    transports: [{ modeGroups: [{ groupUuid: 'g', name: 'free' }] }],
    ...over,
  }) as unknown as NodeView;

const intent = (over: Partial<NodeIntentView> = {}): NodeIntentView =>
  ({
    id: 'i-1',
    name: 'node-one',
    machineName: null,
    mode: { slug: 'freedom', name: 'Freedom', shape: { transport: 'reality', fronting: 'direct' } },
    modeEnabled: true,
    state: 'ready',
    code: null,
    stage: 'live',
    disposition: 'live',
    machineRevision: 1,
    appliedRevision: 1,
    roleSeenAt: null,
    nodeUuid: 'n-1',
    addressUuids: [],
    adopted: false,
    origin: { hostname: null, dns: 'none' },
    maintenance: false,
    run: null,
    protection: null,
    retirement: null,
    extraModes: [],
    registeredAt: NOW,
    updatedAt: NOW,
    ...over,
  }) as unknown as NodeIntentView;

function origin(slug: string, over: Record<string, unknown> = {}, rowOver = {}): OriginRow {
  return {
    relay: OriginAdmin.parse({
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
      publishedCount: 0,
      standbyEdgeIds: [],
      activeRotationId: null,
      cooldownUntil: null,
      rotationsToday: 0,
      lastRotatedAt: null,
      quarantine: null,
      deleting: false,
      suspicion: null,
      updatedAt: NOW,
      ...over,
    }),
    pool: [],
    standbys: 0,
    draining: 0,
    needsOperator: 0,
    rotation: null,
    ...rowOver,
  };
}
const panelNode = (nodeUuid: string | null, nodeName = 'node-one') => ({
  origin: { kind: 'panel-node', backendServerId: 'b-1', nodeName, nodeUuid },
});

const status = (over: Partial<OriginStatus> = {}): OriginStatus =>
  OriginStatus.parse({
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
    ...over,
  });

const backend = (over: Partial<BackendInput> = {}): BackendInput => ({
  instance: { id: 'b-1', slug: 'panel-a', name: 'Panel A' },
  nodes: [node()],
  intents: [intent()],
  ...over,
});

describe('params', () => {
  test('show and layer: unknown values fall back, technical filters need the columns', () => {
    expect(parseShow('fronted', false)).toBe('fronted');
    expect(parseShow('by-hand', false)).toBe('by-hand');
    expect(parseShow('nope', false)).toBe('all');
    expect(parseShow(null, false)).toBe('all');
    expect(parseShow('dark', false)).toBe('all');
    expect(parseShow('dark', true)).toBe('dark');
    expect(parseLayer('l7', true)).toBe('l7');
    expect(parseLayer('l7', false)).toBe('all');
    expect(parseLayer('l9', true)).toBe('all');
  });

  test('the Backend chip only keeps a backend that exists', () => {
    const list = [{ slug: 'a' }, { slug: 'b' }];
    expect(backendOf('?backend=b', list)).toBe('b');
    expect(backendOf('?backend=gone', list)).toBeNull();
    expect(backendOf('', list)).toBeNull();
  });

  test('the Nodes path spells its params in a fixed order, encoded', () => {
    expect(serversPaths.nodes({ show: 'fronted' })).toBe('/admin/servers/nodes?show=fronted');
    expect(serversPaths.nodes({ front: '1', backend: 'a b', node: 'u' })).toBe(
      '/admin/servers/nodes?backend=a%20b&front=1&node=u',
    );
    expect(serversPaths.nodes({ columns: 'technical', add: 'origin' })).toBe(
      '/admin/servers/nodes?columns=technical&add=origin',
    );
    expect(serversPaths.nodes({ run: 'r1', show: '' })).toBe('/admin/servers/nodes?run=r1');
  });
});

describe('addressesWords', () => {
  test('direct, none yet, fronted with spares and offline ones', () => {
    expect(addressesWords(null, null)).toBe('Direct');
    expect(addressesWords(origin('a'), status({ published: 0, standbys: 0 }))).toBe('None yet');
    expect(addressesWords(origin('a'), status())).toBe('3 fronted, 1 spare');
    expect(addressesWords(origin('a'), status({ standbys: 2 }))).toBe('3 fronted, 2 spares');
    expect(addressesWords(origin('a'), status({ published: 2, standbys: 0, offline: 1 }))).toBe(
      '2 fronted, 1 offline',
    );
    // While the server's status loads, the summary's own counts speak.
    expect(addressesWords(origin('a', { publishedCount: 2 }, { standbys: 1 }), null)).toBe(
      '2 fronted, 1 spare',
    );
  });
});

describe('pickStatus', () => {
  test('the worst dot wins, the earlier one on a tie', () => {
    expect(
      pickStatus([
        { dot: 'green', sentence: 'a' },
        { dot: 'amber', sentence: 'b' },
        { dot: 'red', sentence: 'c' },
      ]).sentence,
    ).toBe('c');
    expect(
      pickStatus([null, { dot: 'amber', sentence: 'first' }, { dot: 'amber', sentence: 'second' }])
        .sentence,
    ).toBe('first');
    expect(pickStatus([{ dot: 'green', sentence: 'ok' }]).sentence).toBe('ok');
    expect(pickStatus([]).dot).toBe('grey');
  });
});

describe('buildNodeRows', () => {
  test('a direct node: its mode, machine name, users online and its own sentence', () => {
    const [row] = buildNodeRows({
      backends: [backend({ intents: [intent({ machineName: 'vm-a1' })] })],
      origins: [],
      statuses: new Map(),
    });
    expect(row).toMatchObject({
      kind: 'node',
      name: 'node-one',
      machine: 'vm-a1',
      backend: { slug: 'panel-a', name: 'Panel A' },
      modes: ['Freedom'],
      usersOnline: 4,
      origin: null,
      dot: 'green',
      sentence: 'Online, 4 people connected.',
      attention: false,
      adoptable: false,
    });
    expect(rowHref(row!)).toBe('/admin/servers/nodes/n-1?backend=panel-a');
  });

  test('a node without an enrolled node: its mode groups, and it can be adopted', () => {
    const [row] = buildNodeRows({
      backends: [backend({ intents: [] })],
      origins: [],
      statuses: new Map(),
    });
    expect(row!.modes).toEqual(['free']);
    expect(row!.adoptable).toBe(true);
  });

  test('a fronted node joins its origin by uuid; the origin says what is wrong', () => {
    const o = origin('node-one', panelNode('n-1'));
    const [row, ...rest] = buildNodeRows({
      backends: [backend()],
      origins: [o],
      statuses: new Map([
        ['node-one', status({ kind: 'needs-you', dot: 'amber', code: 'offline', offline: 1 })],
      ]),
    });
    expect(rest).toHaveLength(0);
    expect(row!.origin?.relay.slug).toBe('node-one');
    expect(row!.dot).toBe('amber');
    expect(row!.sentence).toBe('1 address is offline.');
    expect(row!.attention).toBe(true);
    expect(rowMatches(row!, 'fronted')).toBe(true);
    expect(rowMatches(row!, 'direct')).toBe(false);
  });

  test('an origin made before node uuids were recorded joins by name', () => {
    const rows = buildNodeRows({
      backends: [backend()],
      origins: [origin('old', panelNode(null, 'node-one'))],
      statuses: new Map(),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.origin?.relay.slug).toBe('old');
  });

  test('an offline node outranks a fronted green origin; a stage that waits outranks a green node', () => {
    const [offline] = buildNodeRows({
      backends: [backend({ nodes: [node({ online: false })] })],
      origins: [origin('node-one', panelNode('n-1'))],
      statuses: new Map([['node-one', status()]]),
    });
    expect(offline!.dot).toBe('red');
    expect(offline!.sentence).toBe('The backend cannot reach this node.');
    const [waiting] = buildNodeRows({
      backends: [backend({ intents: [intent({ stage: 'awaiting_approval' })] })],
      origins: [],
      statuses: new Map(),
    });
    expect(waiting!.sentence).toBe('Waiting for your approval.');
    expect(waiting!.attention).toBe(true);
  });

  test('a restart is not an outage', () => {
    const [row] = buildNodeRows({
      backends: [backend({ nodes: [node({ online: false })], restarting: () => true })],
      origins: [],
      statuses: new Map(),
    });
    expect(row!.dot).toBe('amber');
    expect(row!.sentence).toMatch(/Restarting/);
  });

  test("the backend's Action needed marks its node", () => {
    const [row] = buildNodeRows({
      backends: [backend({ attentionNodes: new Set(['n-1']) })],
      origins: [],
      statuses: new Map(),
    });
    expect(row!.attention).toBe(true);
  });

  test('a node whose panel row is gone while it retires stays listed', () => {
    const rows = buildNodeRows({
      backends: [
        backend({
          nodes: [],
          intents: [intent({ retirement: { stage: 'draining' } as NodeIntentView['retirement'] })],
        }),
      ],
      origins: [],
      statuses: new Map(),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: 'retiring', retiring: true, usersOnline: null });
    expect(rowMatches(rows[0]!, 'retiring')).toBe(true);
    // Retired is done: no row.
    const done = buildNodeRows({
      backends: [
        backend({
          nodes: [],
          intents: [intent({ retirement: { stage: 'retired' } as NodeIntentView['retirement'] })],
        }),
      ],
      origins: [],
      statuses: new Map(),
    });
    expect(done).toHaveLength(0);
  });

  test('origins added by hand, and a node origin no tree lists, get rows of their own', () => {
    const rows = buildNodeRows({
      backends: [backend()],
      origins: [
        origin('manual-a', { label: 'Office box' }),
        origin('gone', panelNode('n-gone', 'node-gone')),
      ],
      statuses: new Map([
        ['manual-a', status({ runId: 'run-1', kind: 'setting-up', dot: 'blue' })],
      ]),
    });
    expect(rows).toHaveLength(3);
    const manual = rows.find((r) => r.origin?.relay.slug === 'manual-a')!;
    expect(manual).toMatchObject({
      kind: 'origin',
      byHand: true,
      name: 'Office box',
      runId: 'run-1',
    });
    expect(rowHref(manual)).toBe('/admin/servers/origins/manual-a');
    expect(rowMatches(manual, 'by-hand')).toBe(true);
    expect(rowMatches(manual, 'fronted')).toBe(false);
    const gone = rows.find((r) => r.origin?.relay.slug === 'gone')!;
    expect(gone).toMatchObject({ byHand: false, name: 'node-gone', backend: { slug: 'panel-a' } });
    expect(rowHref(gone)).toBe('/admin/servers/origins/gone');
  });

  test('a stopped first fronting keeps its run reachable', () => {
    const [row] = buildNodeRows({
      backends: [],
      origins: [origin('m')],
      statuses: new Map([
        [
          'm',
          status({
            kind: 'needs-you',
            dot: 'amber',
            code: 'setup_run_failed',
            failedRunId: 'run-9',
          }),
        ],
      ]),
    });
    expect(row!.runId).toBe('run-9');
  });
});

describe('filters', () => {
  const rows = buildNodeRows({
    backends: [
      backend({ nodes: [node(), node({ nodeUuid: 'n-2', name: 'node-two', countryCode: null })] }),
      backend({
        instance: { id: 'b-2', slug: 'panel-b', name: 'Panel B' },
        nodes: [node({ nodeUuid: 'n-3', name: 'node-three' })],
        intents: [],
      }),
    ],
    origins: [
      origin('node-two', {
        ...panelNode('n-2', 'node-two'),
        quarantine: { rotationId: 'r', since: NOW, reason: 'x' },
      }),
      origin('manual-a', { label: 'Office box' }),
    ],
    statuses: new Map([
      [
        'node-two',
        status({ layers: ['l7'], delivery: { kind: 'dark', code: null }, published: 0 }),
      ],
      ['manual-a', status({ layers: ['l4'] })],
    ]),
  });

  test('chips, layers and the technical filters', () => {
    const names = (f: Parameters<typeof filterNodeRows>[1]) =>
      filterNodeRows(rows, f).map((r) => r.name);
    expect(names({ show: 'all' })).toEqual(['node-one', 'node-two', 'node-three', 'Office box']);
    expect(names({ show: 'fronted' })).toEqual(['node-two']);
    expect(names({ show: 'direct' })).toEqual(['node-one', 'node-three']);
    expect(names({ show: 'by-hand' })).toEqual(['Office box']);
    expect(names({ show: 'dark' })).toEqual(['node-two']);
    expect(names({ show: 'quarantined' })).toEqual(['node-two']);
    expect(names({ show: 'unpublished' })).toEqual(['node-two']);
    expect(names({ show: 'all', layer: 'l4' })).toEqual(['Office box']);
    expect(names({ show: 'all', layer: 'l7' })).toEqual(['node-two']);
  });

  test('the Backend chip keeps one backend, and rows of no backend', () => {
    expect(filterNodeRows(rows, { show: 'all', backend: 'panel-b' }).map((r) => r.name)).toEqual([
      'node-three',
      'Office box',
    ]);
  });

  test('search: name, machine name, origin slug or label', () => {
    expect(searchMatches(rows[0]!, '')).toBe(true);
    expect(searchMatches(rows[0]!, 'ONE')).toBe(true);
    expect(filterNodeRows(rows, { show: 'all', query: 'office' }).map((r) => r.name)).toEqual([
      'Office box',
    ]);
    expect(filterNodeRows(rows, { show: 'all', query: 'manual-a' })).toHaveLength(1);
    expect(filterNodeRows(rows, { show: 'all', query: 'zzz' })).toHaveLength(0);
  });

  test('counts per chip', () => {
    const c = filterCounts(rows);
    expect(c.all).toBe(4);
    expect(c.fronted).toBe(1);
    expect(c.direct).toBe(2);
    expect(c['by-hand']).toBe(1);
    expect(c.retiring).toBe(0);
  });
});
