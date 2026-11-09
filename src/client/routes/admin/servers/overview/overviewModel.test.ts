import { describe, expect, test } from 'vitest';
import type { AttentionItem } from '@shared/contracts/edges';
import {
  atRiskCount,
  backendNodeCounts,
  oldestRead,
  unadoptedCount,
  freedomSummary,
  mergeActivity,
  mergeAttention,
  overviewTiles,
  statusSentence,
  type BackendInput,
  type CountryInput,
  type OverviewRow,
  type ProviderInput,
  type TilesInput,
} from './overviewModel';

const NOW = Date.parse('2026-11-09T12:00:00Z');

const edge = (id: string, severity: AttentionItem['severity']): AttentionItem => ({
  id,
  kind: 'block_suspected',
  severity,
  relaySlug: 'node-a',
  relayId: 'r1',
  edgeId: null,
  listenerKey: null,
  listenerTag: null,
  accountId: null,
  rotationId: null,
  code: null,
  facts: {},
  action: 'open_relay',
  since: null,
});

const backend = (over: Partial<BackendInput> = {}): BackendInput => ({
  slug: 'main',
  name: 'Main panel',
  canWrite: true,
  manageOn: true,
  setUp: true,
  setupRow: null,
  holds: [],
  needs: [],
  names: [],
  portChanges: [],
  ops: [],
  unadopted: 0,
  readFailed: false,
  ...over,
});

const country = (code: string, over: Partial<CountryInput['totals']> = {}, blockedFor = 0) =>
  ({
    country: code,
    totals: { originsAtRisk: 0, addresses: { blocked: 0 }, names: { blocked: 0 }, ...over },
    meantFor: { locations: blockedFor, blocked: blockedFor },
  }) satisfies CountryInput;

const provider = (over: Partial<ProviderInput> = {}, spend = 0, cap: number | null = 90) =>
  ({
    id: 'acc1',
    name: 'Account B',
    enabled: true,
    cost: {
      currency: 'EUR',
      monthlyCap: cap,
      spend: {
        totals: spend > 0 ? [{ currency: 'EUR', monthly: spend }] : [],
        unpriced: 0,
        monthly: spend,
        atCap: cap !== null && spend >= cap,
      },
    },
    ...over,
  }) satisfies ProviderInput;

const merge = (over: Partial<Parameters<typeof mergeAttention>[0]> = {}) =>
  mergeAttention({ edge: [], backends: [], countries: [], providers: [], now: NOW, ...over });

const plain = (rows: OverviewRow[]) =>
  rows.map((r) => (r.source === 'edge' ? `edge:${r.item.id}` : r.key));

describe('mergeAttention', () => {
  test('nothing to do is an empty list', () => {
    expect(merge()).toEqual([]);
    expect(merge({ backends: [backend()], countries: [country('XA')] })).toEqual([]);
  });

  test('ranks by severity and keeps the server order of edge attention within one', () => {
    const rows = merge({
      edge: [edge('e1', 'warning'), edge('e2', 'critical'), edge('e3', 'warning')],
      backends: [
        backend({
          needs: [
            { key: 'key:n1:tag', text: 'Key mismatch.', nodeUuid: 'n1' },
            { key: 'unattached-addresses', text: 'Points at nothing.' },
          ],
        }),
      ],
      countries: [country('XB', { originsAtRisk: 2 })],
      providers: [provider({}, 85)],
    });
    expect(plain(rows)).toEqual([
      'edge:e2',
      'main:key:n1:tag',
      'country:XB:at-risk',
      'edge:e1',
      'edge:e3',
      'main:unattached-addresses',
      'provider:acc1:near-cap',
    ]);
  });

  test('a hold can be released only when changes are allowed', () => {
    const hold = { id: 'h1', heldNodeNames: ['node-a'], since: '2026-11-09T11:00:00Z' };
    const [row] = merge({ backends: [backend({ holds: [hold] })] });
    expect(row).toMatchObject({
      source: 'servers',
      severity: 'warning',
      action: { kind: 'release', slug: 'main', holdId: 'h1' },
    });
    expect(row?.source !== 'edge' && row?.text).toBe(
      'node-a is held closed since a profile change 1 hour ago. Check it yourself, then release the hold.',
    );
    const [readOnly] = merge({ backends: [backend({ holds: [hold], canWrite: false })] });
    expect(readOnly).toMatchObject({ action: { kind: 'link', href: '/admin/servers/nodes' } });
  });

  test('an edit made on the backend offers Seen it', () => {
    const [row] = merge({
      backends: [backend({ needs: [{ key: 'edit:p1', text: 'Profile was edited.' }] })],
    });
    expect(row).toMatchObject({
      severity: 'warning',
      action: { kind: 'seen', label: 'Seen it', slug: 'main', profileUuid: 'p1' },
    });
  });

  test('setup rows only while changes are on', () => {
    expect(merge({ backends: [backend({ setupRow: 'Not set up.', manageOn: false })] })).toEqual(
      [],
    );
    expect(plain(merge({ backends: [backend({ setupRow: 'Not set up.' })] }))).toEqual([
      'main:setup',
    ]);
    expect(plain(merge({ backends: [backend({ setUp: false })] }))).toEqual(['main:not-set-up']);
  });

  test('a change of unknown outcome is critical; settled changes are not listed', () => {
    const rows = merge({
      backends: [
        backend({
          ops: [
            {
              id: 'o1',
              kind: 'node',
              verb: 'restart',
              label: 'node-a',
              state: 'outcome_unknown',
              errorCode: null,
            },
            {
              id: 'o2',
              kind: 'node',
              verb: 'restart',
              label: 'node-b',
              state: 'done',
              errorCode: null,
            },
          ],
        }),
      ],
    });
    expect(plain(rows)).toEqual(['main:op:o1']);
    expect(rows[0]).toMatchObject({ severity: 'critical', action: { label: 'Settle it' } });
  });

  test('port changes: waiting on you, or settled badly in the last day', () => {
    const base = {
      transportTag: 'VLESS_REALITY',
      fromPort: 443,
      toPort: 8443,
      code: null,
      updatedAt: '2026-11-09T10:00:00Z',
    };
    const rows = merge({
      backends: [
        backend({
          portChanges: [
            {
              ...base,
              id: 'p1',
              state: 'waiting',
              nodes: [
                { name: 'a', confirmedBy: 'operator', state: 'waiting' },
                { name: 'b', confirmedBy: 'role', state: 'waiting' },
              ],
            },
            {
              ...base,
              id: 'p2',
              state: 'waiting',
              nodes: [{ name: 'b', confirmedBy: 'role', state: 'waiting' }],
            },
            { ...base, id: 'p3', state: 'recovered', nodes: [] },
            { ...base, id: 'p4', state: 'refused', nodes: [], updatedAt: '2026-11-07T10:00:00Z' },
          ],
        }),
      ],
    });
    expect(plain(rows)).toEqual(['main:port:p1', 'main:port:p3']);
    expect(rows[0]?.source !== 'edge' && rows[0]?.text).toBe(
      'Move VLESS_REALITY from port 443 to 8443: open the port on 1 node no role reports for, then confirm it.',
    );
  });

  test('SNI rows lead to the node or the SNI list', () => {
    const rows = merge({
      backends: [
        backend({
          names: [
            { key: 'names-suggest:t1', text: 'T: 2 suggested SNIs to add.', nodeUuid: 'n1' },
            { key: 'names-failing:t1', text: 'T: 1 SNI no longer served.', family: 'list-a' },
          ],
        }),
      ],
    });
    expect(rows).toMatchObject([
      {
        key: 'main:names-failing:t1',
        source: 'snis',
        severity: 'warning',
        chip: { kind: 'sni', label: 'SNIs' },
        action: { label: 'Open the SNI list', href: '/admin/servers/snis/lists/list-a' },
      },
      {
        key: 'main:names-suggest:t1',
        severity: 'info',
        action: { label: 'Open node', href: '/admin/servers/nodes/n1?backend=main' },
      },
    ]);
  });

  test('a backend chip shows only with more than one backend', () => {
    const one = merge({ backends: [backend({ unadopted: 2 })] });
    expect(one[0]).toMatchObject({ chip: null, action: { href: '/admin/servers/nodes' } });
    expect(one[0]?.source !== 'edge' && one[0]?.text).toBe(
      '2 nodes serve members without being enrolled. Adopt them so FCP can look after them.',
    );
    const two = merge({
      backends: [backend({ unadopted: 1 }), backend({ slug: 'second', name: 'Second' })],
    });
    expect(two[0]).toMatchObject({
      chip: { kind: 'backend', label: 'Main panel' },
      action: { href: '/admin/servers/nodes?backend=main' },
    });
  });

  test('countries: no working address is critical, a blocked location for it a warning', () => {
    const rows = merge({
      countries: [
        country('XA', { originsAtRisk: 1 }, 1),
        country('XB', {}, 2),
        country('XC', { addresses: { blocked: 3 } }),
      ],
    });
    expect(rows).toMatchObject([
      {
        key: 'country:XA:at-risk',
        severity: 'critical',
        text: 'One node has no working address there.',
        action: { href: '/admin/servers/countries/XA' },
      },
      {
        key: 'country:XB:location',
        severity: 'warning',
        text: '2 locations set for it are blocked there.',
      },
    ]);
  });

  test('providers: at the cap, close to it, or neither', () => {
    expect(merge({ providers: [provider({}, 50)] })).toEqual([]);
    expect(merge({ providers: [provider({}, 95, null)] })).toEqual([]);
    expect(merge({ providers: [provider({ enabled: false }, 95)] })).toEqual([]);
    expect(merge({ providers: [provider({}, 90)] })).toMatchObject([
      {
        key: 'provider:acc1:cap',
        severity: 'warning',
        chip: { kind: 'provider', label: 'Account B' },
        text: 'At its cost cap (about €90.00 a month of its €90.00 cap). It makes no new address until the cap is raised.',
        action: { label: 'Open account', href: '/admin/servers/providers/acc1' },
      },
    ]);
    expect(merge({ providers: [provider({}, 81)] })).toMatchObject([
      { severity: 'info', text: 'Close to its cost cap: about €81.00 a month of its €90.00 cap.' },
    ]);
  });
});

describe('statusSentence', () => {
  const fleet = { protected: 4, total: 5 };
  test('nodes online, fronted, and what needs you', () => {
    expect(statusSentence({ nodes: { online: 6, total: 6 }, fleet, rows: [] })).toEqual({
      dot: 'green',
      text: '6 nodes online, 4 fronted. Nothing needs you.',
    });
    expect(
      statusSentence({
        nodes: { online: 5, total: 6 },
        fleet,
        rows: [{ severity: 'warning' }, { severity: 'info' }],
      }),
    ).toEqual({ dot: 'amber', text: '5 of 6 nodes online, 4 fronted. 2 things need you.' });
    expect(
      statusSentence({
        nodes: { online: 1, total: 1 },
        fleet: null,
        rows: [{ severity: 'critical' }],
      }),
    ).toEqual({ dot: 'red', text: '1 node online. 1 thing needs you.' });
  });

  test('no node reachable is red; nothing at all is grey', () => {
    expect(statusSentence({ nodes: { online: 0, total: 2 }, fleet: null, rows: [] }).dot).toBe(
      'red',
    );
    expect(statusSentence({ nodes: null, fleet: null, rows: [] })).toEqual({
      dot: 'grey',
      text: 'No nodes yet. Nothing needs you.',
    });
    expect(statusSentence({ nodes: null, fleet: { protected: 2, total: 2 }, rows: [] })).toEqual({
      dot: 'green',
      text: '2 nodes fronted. Nothing needs you.',
    });
  });

  test('a loaded empty fleet says "0 fronted"; not loaded says nothing about fronting', () => {
    const nodes = { online: 3, total: 3 };
    expect(statusSentence({ nodes, fleet: { protected: 0, total: 0 }, rows: [] }).text).toBe(
      '3 nodes online, 0 fronted. Nothing needs you.',
    );
    expect(statusSentence({ nodes, fleet: null, rows: [] }).text).toBe(
      '3 nodes online. Nothing needs you.',
    );
    expect(statusSentence({ nodes: null, fleet: { protected: 0, total: 0 }, rows: [] })).toEqual({
      dot: 'grey',
      text: 'No nodes yet. Nothing needs you.',
    });
  });

  test('a source that could not be read is never green', () => {
    const nodes = { online: 3, total: 3 };
    expect(statusSentence({ nodes, fleet: null, rows: [], incomplete: true }).dot).toBe('amber');
    expect(
      statusSentence({
        nodes: null,
        fleet: null,
        rows: [{ severity: 'critical' }],
        nodesUnread: true,
      }),
    ).toEqual({ dot: 'red', text: 'Node status could not be read. 1 thing needs you.' });
  });
});

describe('per-source helpers', () => {
  const node = (over: Partial<{ online: boolean; isDisabled: boolean }> = {}) => ({
    online: true,
    isDisabled: false,
    ...over,
  });

  test('node counts leave out disabled nodes, and are not counted after a failed panel read', () => {
    const nodes = [node(), node({ online: false }), node({ isDisabled: true, online: false })];
    expect(backendNodeCounts({ state: { ok: true }, nodes })).toEqual({ online: 1, total: 2 });
    expect(backendNodeCounts({ state: { ok: null }, nodes })).toEqual({ online: 1, total: 2 });
    expect(backendNodeCounts({ state: { ok: false }, nodes })).toBeNull();
    expect(backendNodeCounts(null)).toBeNull();
  });

  test('a failed panel read is critical in Action needed', () => {
    const [row] = merge({ backends: [backend({ readFailed: true })] });
    expect(row).toMatchObject({
      key: 'main:read-failed',
      severity: 'critical',
      text: 'The panel could not be read, so its node status may be out of date.',
      action: { href: '/admin/servers/nodes' },
    });
  });

  test('nodes not enrolled leave out disabled ones and match intents by uuid or name', () => {
    const nodes = [
      { nodeUuid: 'n1', name: 'a', isDisabled: false },
      { nodeUuid: 'n2', name: 'b', isDisabled: false },
      { nodeUuid: 'n3', name: 'c', isDisabled: true },
      { nodeUuid: 'n4', name: 'd', isDisabled: false },
    ];
    expect(
      unadoptedCount(nodes, [
        { nodeUuid: 'n1', name: 'x' },
        { nodeUuid: null, name: 'b' },
      ]),
    ).toBe(1);
  });

  test('at risk counts only fronted nodes with a red dot', () => {
    expect(
      atRiskCount([
        { status: { fronted: true, dot: 'red' } },
        { status: { fronted: false, dot: 'red' } },
        { status: { fronted: true, dot: 'amber' } },
      ]),
    ).toBe(1);
  });

  test('the oldest read of the sources that have data', () => {
    expect(oldestRead([0, 0])).toBe(0);
    expect(oldestRead([3000, 0, 1000, 2000])).toBe(1000);
  });
});

describe('overviewTiles', () => {
  const base = {
    nodes: { online: 6, total: 6 },
    fleet: { protected: 4, total: 4 },
    atRisk: 1,
    countries: [country('XA', { addresses: { blocked: 1 } }), country('XB'), country('XC')],
    providers: [provider({}, 38), provider({ id: 'acc2', name: 'Free CDN', cost: null })],
    probe: { usedLastHour: 41, hourlyBudget: 100, enabled: true },
  };

  test('the four tiles with their figures and links', () => {
    expect(overviewTiles(base)).toEqual([
      {
        id: 'nodes',
        label: 'Nodes',
        value: '6 · 4 · 1',
        hint: 'Online · fronted · at risk',
        tone: 'danger',
        href: '/admin/servers/nodes',
      },
      {
        id: 'countries',
        label: 'Countries',
        value: '1 of 3',
        hint: 'With a block now',
        tone: 'warning',
        href: '/admin/servers/countries',
      },
      {
        id: 'spend',
        label: 'Spend a month',
        value: '€38.00 / €90.00',
        hint: 'Estimated from live addresses, against the caps.',
        tone: 'neutral',
        href: '/admin/servers/providers',
      },
      {
        id: 'probes',
        label: 'Probe budget',
        value: '41%',
        hint: '41 of 100 probe runs used in the last hour.',
        tone: 'neutral',
        href: '/admin/servers/probes',
      },
    ]);
  });

  test('figures not loaded read "?"', () => {
    const tiles = overviewTiles({
      nodes: null,
      fleet: null,
      atRisk: null,
      countries: null,
      providers: null,
      probe: { usedLastHour: null, hourlyBudget: null, enabled: null },
    });
    expect(tiles.map((t) => t.value)).toEqual(['? · ? · ?', '?', '?', '?']);
  });

  test('spend: never added across currencies, unpriced said, a cap reached is toned', () => {
    const usd = provider({
      id: 'acc3',
      name: 'C',
      cost: {
        currency: 'USD',
        monthlyCap: null,
        spend: {
          totals: [{ currency: 'USD', monthly: 10 }],
          unpriced: 2,
          monthly: 10,
          atCap: false,
        },
      },
    });
    const spend = overviewTiles({ ...base, providers: [provider({}, 90), usd] })[2];
    expect(spend).toMatchObject({
      value: '€90.00 / €90.00 + $10.00',
      hint: 'Estimated from live addresses, against the caps. 2 addresses without a price.',
      tone: 'warning',
    });
    expect(overviewTiles({ ...base, providers: [] })[2]).toMatchObject({
      value: 'None',
      hint: 'No live address costs anything now.',
    });
  });

  test('spend: a switched-off account still bills its live addresses, but its cap is left out', () => {
    const off = provider({ id: 'acc4', name: 'Off', enabled: false }, 20, 50);
    off.cost!.spend.unpriced = 1;
    expect(overviewTiles({ ...base, providers: [provider({}, 38), off] })[2]).toMatchObject({
      value: '€58.00 / €90.00',
      hint: 'Estimated from live addresses, against the caps. 1 address without a price.',
    });
  });

  test('probe budget: off, none, full', () => {
    const probe = (p: Partial<TilesInput['probe']>) =>
      overviewTiles({ ...base, probe: { ...base.probe, ...p } })[3];
    expect(probe({ enabled: false })).toMatchObject({ value: 'Off', tone: 'muted' });
    expect(probe({ hourlyBudget: 0 })).toMatchObject({ value: 'None', tone: 'warning' });
    expect(probe({ usedLastHour: 100 })).toMatchObject({ value: '100%', tone: 'danger' });
    expect(probe({ usedLastHour: null })).toMatchObject({ value: 'of 100' });
  });
});

describe('mergeActivity', () => {
  const entry = (id: string, action: string, createdAt: string, subject?: string) => ({
    id,
    action,
    payload: null,
    createdAt,
    ...(subject ? { subject } : {}),
  });
  const op = (id: string, label: string, at: string, state: 'done' | 'refused' = 'done') => ({
    id,
    kind: 'node' as const,
    verb: 'restart',
    label,
    state,
    errorCode: null,
    open: false,
    createdAt: at,
    settledAt: at,
  });

  test('newest first across nodes and backends, check results left out', () => {
    const out = mergeActivity({
      timelines: [
        {
          slug: 'node-a',
          name: 'Node A',
          href: '/admin/servers/nodes/n1',
          entries: [
            entry('1', 'admin.edge.rotate', '2026-11-09T10:00:00Z'),
            entry('2', 'probe.verdict', '2026-11-09T11:00:00Z'),
            entry('3', 'edge.country.state', '2026-11-09T11:30:00Z'),
            entry('4', 'relay.updated', '2026-11-09T11:40:00Z', 'probe'),
          ],
        },
      ],
      backends: [{ slug: 'main', name: 'Main', ops: [op('o1', 'node-a', '2026-11-09T10:30:00Z')] }],
    });
    expect(out).toEqual([
      {
        key: 'o:main:o1',
        at: '2026-11-09T10:30:00Z',
        who: 'Backend',
        text: 'Restart node node-a. Done, and seen on the backend.',
        href: '/admin/servers/nodes',
        dot: 'green',
      },
      {
        key: 't:node-a:1',
        at: '2026-11-09T10:00:00Z',
        who: 'Node A',
        text: 'Replacement requested',
        href: '/admin/servers/nodes/n1',
        dot: null,
      },
    ]);
  });

  test('repeated changes fold into one line, and the list is capped', () => {
    const ops = [
      op('a', 'x', '2026-11-09T10:03:00Z', 'refused'),
      op('b', 'x', '2026-11-09T10:02:00Z', 'refused'),
      op('c', 'x', '2026-11-09T10:01:00Z', 'refused'),
      op('d', 'y', '2026-11-09T10:00:00Z'),
    ];
    const out = mergeActivity({ timelines: [], backends: [{ slug: 'main', name: 'Main', ops }] });
    expect(out.map((e) => e.key)).toEqual(['o:main:a', 'o:main:d']);
    expect(out[0]?.text).toBe(
      'Restart node x (3 times). The backend refused it. Nothing was changed.',
    );
    expect(
      mergeActivity({ timelines: [], backends: [{ slug: 'main', name: 'Main', ops }], max: 1 }),
    ).toHaveLength(1);
  });

  test('with more than one backend, each change names its backend', () => {
    const out = mergeActivity({
      timelines: [],
      backends: [
        { slug: 'a', name: 'First', ops: [op('1', 'x', '2026-11-09T10:00:00Z')] },
        { slug: 'b', name: 'Second', ops: [] },
      ],
    });
    expect(out[0]).toMatchObject({ who: 'First', href: '/admin/servers/nodes?backend=a' });
  });
});

describe('freedomSummary', () => {
  const p = (
    withheldNodes: number,
    affectedMembers: number,
    cutOffMembers: number,
    on = false,
  ) => ({
    on,
    approximate: false,
    totals: { withheldNodes, affectedMembers, cutOffMembers },
  });
  test('says what it holds back', () => {
    expect(freedomSummary(p(0, 0, 0))).toBe('Every node of a freedom mode is fronted.');
    expect(freedomSummary(p(1, 0, 0))).toBe(
      '1 node would be held back from freedom members. No member is on them now.',
    );
    expect(freedomSummary(p(2, 5, 2, true))).toBe(
      '2 nodes are held back from freedom members. 3 members move to a fronted node at their next refresh, and 2 members get nothing until their node is fronted.',
    );
    expect(freedomSummary({ ...p(1, 1, 1), approximate: true })).toBe(
      '1 node would be held back from freedom members. 1 member gets nothing until their node is fronted. At least, as the count stopped early.',
    );
  });
});
