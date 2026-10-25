/**
 * The country view (pure): what an address and a name count as from one
 * country and why, and what a member there is handed, computed by the
 * assignment itself over a sample of render keys.
 */
import { describe, expect, test } from 'vitest';
import type { PublishedEdge } from '../assignment';
import {
  addressState,
  buildCountryView,
  handedOn,
  nameState,
  probesState,
  sampleKey,
  type EdgeInput,
  type NameFacts,
  type OriginInput,
  type ReachRow,
  type ViewSettings,
} from './view';

const NOW = 1_800_000_000_000;
const H = 3_600_000;

const reach = (country: string, verdict: ReachRow['verdict'], extra: Partial<ReachRow> = {}) => ({
  country,
  verdict,
  okVantages: verdict === 'reachable' ? 3 : 0,
  failVantages: verdict === 'unreachable' ? 3 : 0,
  lastAt: NOW - H,
  ...extra,
});

function edge(over: Partial<EdgeInput> = {}): EdgeInput {
  return {
    edgeId: 'e1',
    listenerId: 'L',
    layer: 'l4',
    provider: 'p1',
    location: 'Loc 1',
    status: 'active',
    publication: 'published',
    poolIndex: 0,
    addresses: { v4: '198.51.100.1' },
    countryState: [],
    reachability: [],
    evidence: null,
    mark: null,
    locationMark: null,
    grade: null,
    ...over,
  };
}

const track = (state: 'proven' | 'blocked' | 'unknown', reason?: string) => ({
  address: {
    state,
    ...(reason ? { reason } : {}),
    decidedAt: NOW - H,
    until: NOW + 24 * H,
    blockedRounds: state === 'blocked' ? 2 : 0,
  },
  handshake: { state: 'none' as const, pathBatches: [] },
  combined: state,
});

describe('probesState', () => {
  test('reached = proven; failing while another country reaches it = blocked', () => {
    expect(probesState([reach('IR', 'reachable')], 'IR')).toBe('proven');
    expect(probesState([reach('IR', 'unreachable'), reach('DE', 'reachable')], 'IR')).toBe(
      'blocked',
    );
  });
  test('failing everywhere is broken, not blocked; mixed and absent say nothing', () => {
    expect(probesState([reach('IR', 'unreachable'), reach('RU', 'unreachable')], 'IR')).toBe(
      'unknown',
    );
    expect(probesState([reach('IR', 'mixed'), reach('DE', 'reachable')], 'IR')).toBe('unknown');
    expect(probesState([reach('DE', 'reachable')], 'IR')).toBe('unknown');
  });
});

describe('addressState', () => {
  test('a live graded state wins over the probes, with the basis it came from', () => {
    const probes = [reach('IR', 'reachable')];
    const st = (over: Partial<EdgeInput>) => addressState(edge(over), 'IR', NOW);
    expect(
      st({
        reachability: probes,
        countryState: [{ country: 'IR', state: 'blocked', from: 'mark' }],
        mark: { state: 'blocked', at: NOW },
      }),
    ).toEqual({ state: 'blocked', basis: 'mark', until: null });
    expect(st({ countryState: [{ country: 'IR', state: 'blocked', from: 'mark' }] }).basis).toBe(
      'location_mark',
    );
    expect(
      st({ countryState: [{ country: 'IR', state: 'blocked', from: 'group', until: NOW + H }] }),
    ).toEqual({ state: 'blocked', basis: 'location', until: NOW + H });
    expect(
      st({
        countryState: [{ country: 'IR', state: 'blocked', from: 'edge', until: NOW + H }],
        evidence: track('blocked', 'never_reached'),
      }).basis,
    ).toBe('never_reached');
    expect(
      st({
        countryState: [{ country: 'IR', state: 'blocked', from: 'edge', until: NOW + H }],
        evidence: track('blocked', 'blocked'),
      }).basis,
    ).toBe('checks');
    const handshake = {
      ...track('proven'),
      handshake: { state: 'blocked' as const, pathBatches: [NOW - H], lastBatchAt: NOW - H },
      combined: 'blocked' as const,
    };
    expect(
      st({
        countryState: [{ country: 'IR', state: 'blocked', from: 'edge', until: NOW + H }],
        evidence: handshake,
      }).basis,
    ).toBe('handshake');
    expect(
      st({
        countryState: [{ country: 'IR', state: 'proven', from: 'edge', until: NOW + H }],
        evidence: track('proven'),
      }),
    ).toEqual({ state: 'proven', basis: 'checks', until: NOW + H });
  });

  test('IPv6 beside IPv4: blocked only while another country reaches it over IPv6', () => {
    const dual = (rows: ReachRow[]) =>
      buildCountryView(
        [
          {
            relayId: 'r1',
            slug: 's',
            label: null,
            kind: 'panel-node',
            nodeName: null,
            enabled: true,
            direct: null,
            listeners: [
              {
                listenerId: 'L',
                key: 'a',
                protocol: 'vless',
                streamTransport: 'raw',
                security: 'reality',
                usable: true,
                sniPick: null,
                names: [],
              },
            ],
            edges: [
              edge({ addresses: { v4: '198.51.100.1', v6: '2001:db8::1' }, reachability: rows }),
            ],
            published: [],
          },
        ],
        () => null,
        { ...SETTINGS, render: false },
      ).origins[0]!.listeners[0]!.addresses[0]!.v6;
    const v6 = (country: string, v6Verdict: ReachRow['verdict']) => ({
      ...reach(country, 'reachable'),
      v6Verdict,
    });
    expect(dual([v6('IR', 'unreachable'), v6('DE', 'reachable')])?.state).toBe('blocked');
    // Unreachable over IPv6 everywhere: broken, not blocked.
    expect(dual([v6('IR', 'unreachable'), v6('DE', 'unreachable')])?.state).toBeNull();
    expect(dual([v6('IR', 'reachable')])?.state).toBe('proven');
  });

  test('a state past its until reads as not graded (the probes, else nothing)', () => {
    const lapsed = [
      { country: 'IR', state: 'blocked' as const, from: 'edge' as const, until: NOW - 1 },
    ];
    expect(addressState(edge({ countryState: lapsed }), 'IR', NOW)).toEqual({
      state: 'unknown',
      basis: 'none',
      until: null,
    });
    expect(
      addressState(edge({ countryState: lapsed, reachability: [reach('IR', 'mixed')] }), 'IR', NOW),
    ).toEqual({ state: 'unknown', basis: 'probes', until: null });
  });
});

describe('nameState', () => {
  const facts = (over: Partial<NameFacts> = {}): NameFacts => ({
    family: 'f',
    qualified: true,
    mark: null,
    checks: null,
    reports: null,
    ...over,
  });
  test('the listener copy is the state; the mark row says who wrote it', () => {
    expect(nameState({ blockedIn: ['IR'], provenIn: [] }, facts(), 'IR')).toEqual({
      state: 'blocked',
      basis: 'mark',
    });
    expect(
      nameState(
        { blockedIn: [], provenIn: ['IR'] },
        facts({ mark: { state: 'proven', source: 'probe', at: NOW } }),
        'IR',
      ),
    ).toEqual({ state: 'proven', basis: 'checks_mark' });
  });
  test('an unapplied suggestion shows as the checks basis; nothing = unknown', () => {
    const checks = {
      latest: 'failing' as const,
      okVantages: 0,
      okNetworks: 0,
      failVantages: 3,
      failNetworks: 2,
      pathFailures: 0,
      suggestion: 'blocked' as const,
      reason: null,
      lastAt: NOW,
      lastOkAt: null,
    };
    expect(nameState({ blockedIn: [], provenIn: [] }, facts({ checks }), 'IR')).toEqual({
      state: 'blocked',
      basis: 'checks',
    });
    expect(nameState({ blockedIn: ['RU'], provenIn: [] }, null, 'IR')).toEqual({
      state: 'unknown',
      basis: 'none',
    });
  });
});

const PROTO = { protocol: 'vless', streamTransport: 'raw', security: 'reality' } as const;
const NAMES = ['n1.example', 'n2.example', 'n3.example'];

function pub(over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number }): PublishedEdge {
  return {
    provider: 'p1',
    listenerId: 'L',
    listenerKey: 'a',
    matchRule: { kind: 'remark', remark: 'a' },
    proto: PROTO,
    edgePort: 443,
    layer: 'l4',
    addresses: { v4: `198.51.100.${over.poolIndex + 1}` },
    serverNames: NAMES.map((sni) => ({ sni, status: 'active' as const })),
    ...over,
  } as PublishedEdge;
}

const SETTINGS: ViewSettings = {
  now: NOW,
  country: 'IR',
  curated: ['IR', 'RU'],
  steering: false,
  render: true,
  rule: { includeBackup: true, canEmitV6: true, namesPerEndpoint: 3, backupNames: 1 },
  preferDistinctProviders: true,
  minProvenForExclusive: 1,
  sample: 200,
};

describe('handedOn', () => {
  const blockedOne = [
    pub({ edgeId: 'a', poolIndex: 0, blockedIn: ['IR'] }),
    pub({ edgeId: 'b', poolIndex: 1, provider: 'p2' }),
  ];

  test('steering off: members are spread over every address, the blocked one included', () => {
    const h = handedOn(
      { enabled: true, published: blockedOne },
      { listenerId: 'L', sniPick: null },
      SETTINGS,
      new Set(['a']),
      new Set(),
    );
    expect(h.computed).toBe(true);
    expect(h.sample).toBe(200);
    expect(h.primary.map((p) => p.id).sort()).toEqual(['a', 'b']);
    expect(h.onBlockedFirst).toBeGreaterThan(0.2);
    expect(h.onBlockedFirst).toBeLessThan(0.8);
    // Two addresses, one blocked: every member holds it, first or as the backup.
    expect(h.onBlockedAddress).toBe(1);
    expect(h.none).toBe(0);
  });

  test('steering on: nobody gets the address blocked there first while another works', () => {
    const h = handedOn(
      { enabled: true, published: blockedOne },
      { listenerId: 'L', sniPick: null },
      { ...SETTINGS, steering: true },
      new Set(['a']),
      new Set(),
    );
    expect(h.primary).toEqual([{ id: 'b', share: 1 }]);
    expect(h.onBlockedFirst).toBe(0);
    // ... and it is still everyone's backup, which counts as holding it.
    expect(h.backup).toEqual([{ id: 'a', share: 1 }]);
    expect(h.onBlockedAddress).toBe(1);
    expect(h.steered).toBe(true);
  });

  test('a country off the list: the universal pool, no steering, whatever the switch says', () => {
    // One listener: both edges carry the same names (the copies ride on the listener).
    const serverNames = NAMES.map((sni) => ({
      sni,
      status: 'active' as const,
      ...(sni === 'n1.example' ? { blockedIn: ['IR'] } : {}),
    }));
    const named = [
      pub({ edgeId: 'a', poolIndex: 0, blockedIn: ['IR'], sniPick: 'hrw1', serverNames }),
      pub({ edgeId: 'b', poolIndex: 1, provider: 'p2', sniPick: 'hrw1', serverNames }),
    ];
    const h = handedOn(
      { enabled: true, published: named },
      { listenerId: 'L', sniPick: 'hrw1' },
      { ...SETTINGS, country: 'DE', steering: true },
      new Set(),
      new Set(),
    );
    expect(h.steered).toBe(false);
    expect(h.namesByCountry).toBe(false);
    // Not steered: members still land on the address blocked in IR.
    expect(h.primary.map((p) => p.id).sort()).toEqual(['a', 'b']);
    // The universal pool never carries a name blocked in any listed country.
    expect(h.names.map((x) => x.id)).not.toContain('n1.example');
  });

  test('names: an hrw1 transport never hands a name blocked there; the legacy pick still does', () => {
    const named = [
      pub({
        edgeId: 'a',
        poolIndex: 0,
        sniPick: 'hrw1',
        serverNames: NAMES.map((sni) => ({
          sni,
          status: 'active' as const,
          ...(sni === 'n1.example' ? { blockedIn: ['IR'] } : {}),
        })),
      }),
    ];
    const hrw = handedOn(
      { enabled: true, published: named },
      { listenerId: 'L', sniPick: 'hrw1' },
      SETTINGS,
      new Set(),
      new Set(['n1.example']),
    );
    expect(hrw.namesByCountry).toBe(true);
    expect(hrw.names.map((n) => n.id)).not.toContain('n1.example');
    expect(hrw.onBlockedName).toBe(0);
    const legacy = handedOn(
      {
        enabled: true,
        published: named.map((e) => ({ ...e, sniPick: undefined })),
      },
      { listenerId: 'L', sniPick: null },
      SETTINGS,
      new Set(),
      new Set(['n1.example']),
    );
    expect(legacy.names.map((n) => n.id)).toContain('n1.example');
    expect(legacy.onBlockedName).toBeGreaterThan(0);
  });

  test('another transport’s addresses are never handed on this one; nothing rendered says why', () => {
    const pool = [
      pub({ edgeId: 'a', poolIndex: 0 }),
      pub({ edgeId: 'x', poolIndex: 1, listenerId: 'OTHER', listenerKey: 'o' }),
    ];
    const h = handedOn(
      { enabled: true, published: pool },
      { listenerId: 'L', sniPick: null },
      SETTINGS,
      new Set(),
      new Set(),
    );
    expect(h.primary).toEqual([{ id: 'a', share: 1 }]);
    expect(h.backup).toEqual([]);
    expect(
      handedOn(
        { enabled: true, published: pool },
        { listenerId: 'L', sniPick: null },
        { ...SETTINGS, render: false },
        new Set(),
        new Set(),
      ).reason,
    ).toBe('render_off');
    expect(
      handedOn(
        { enabled: false, published: pool },
        { listenerId: 'L', sniPick: null },
        SETTINGS,
        new Set(),
        new Set(),
      ).reason,
    ).toBe('origin_disabled');
    expect(
      handedOn(
        { enabled: true, published: pool },
        { listenerId: 'NONE', sniPick: null },
        SETTINGS,
        new Set(),
        new Set(),
      ).reason,
    ).toBe('no_published');
  });

  test('the sample keys are fixed, distinct and 32 hex characters', () => {
    const keys = Array.from({ length: 50 }, (_, i) => sampleKey(i));
    expect(new Set(keys).size).toBe(50);
    for (const k of keys) expect(k).toMatch(/^[0-9a-f]{32}$/);
    expect(sampleKey(7)).toBe(sampleKey(7));
  });
});

describe('buildCountryView', () => {
  const origin = (over: Partial<OriginInput> = {}): OriginInput => ({
    relayId: 'r1',
    slug: 'node-one',
    label: null,
    kind: 'panel-node',
    nodeName: 'node-one',
    enabled: true,
    direct: null,
    listeners: [
      {
        listenerId: 'L',
        key: 'a',
        protocol: 'vless',
        streamTransport: 'raw',
        security: 'reality',
        usable: true,
        sniPick: null,
        names: NAMES.map((name) => ({
          name,
          status: 'active' as const,
          blockedIn: name === 'n2.example' ? ['IR'] : [],
          provenIn: [],
        })),
      },
    ],
    edges: [
      edge({
        edgeId: 'a',
        countryState: [{ country: 'IR', state: 'blocked', from: 'mark' }],
        mark: { state: 'blocked', at: NOW - 2 * H },
      }),
      edge({ edgeId: 'b', poolIndex: 1, reachability: [reach('IR', 'reachable')] }),
      edge({ edgeId: 'spare', publication: 'standby', poolIndex: null }),
    ],
    published: [
      pub({ edgeId: 'a', poolIndex: 0, blockedIn: ['IR'] }),
      pub({ edgeId: 'b', poolIndex: 1 }),
    ],
    ...over,
  });

  test('addresses in pool order (spares after), names, handed shares and totals', () => {
    const v = buildCountryView([origin()], () => null, SETTINGS);
    const l = v.origins[0]!.listeners[0]!;
    expect(l.addresses.map((a) => [a.edgeId, a.state, a.basis])).toEqual([
      ['a', 'blocked', 'mark'],
      ['b', 'proven', 'probes'],
      ['spare', 'unknown', 'none'],
    ]);
    expect(l.addresses[0]!.handed.primary + l.addresses[1]!.handed.primary).toBeCloseTo(1, 2);
    expect(l.addresses[2]!.handed).toEqual({ primary: 0, backup: 0 });
    expect(l.names.find((n) => n.name === 'n2.example')).toMatchObject({
      state: 'blocked',
      basis: 'mark',
      offered: true,
    });
    // Only the published addresses count.
    expect(v.totals.addresses).toEqual({ proven: 1, blocked: 1, unknown: 0 });
    expect(v.totals.names).toEqual({ proven: 0, blocked: 1, unknown: 2 });
    expect(v.totals.originsAtRisk).toBe(0);
    expect(v.totals.lastEvidenceAt).toBe(NOW - H);
    expect(v.origins[0]!.atRisk).toBe(false);
  });

  test('every published address blocked there puts the origin at risk', () => {
    const o = origin();
    const all = o.edges.map((e) =>
      e.publication === 'published'
        ? {
            ...e,
            countryState: [{ country: 'IR', state: 'blocked' as const, from: 'group' as const }],
          }
        : e,
    );
    const v = buildCountryView([{ ...o, edges: all }], () => null, SETTINGS);
    expect(v.origins[0]!.atRisk).toBe(true);
    expect(v.totals.originsAtRisk).toBe(1);
  });

  test('what the transport’s target adds: its names measured on its own addresses only', () => {
    const timed = (addsMs: number, target: string): NameFacts => ({
      family: 'f',
      qualified: true,
      mark: null,
      checks: null,
      reports: null,
      realHost: {
        at: NOW - H,
        target,
        realAddress: '192.0.2.50',
        reading: 'works',
        counts: {
          works: 3,
          nameBlocked: 0,
          addressBlocked: 0,
          ipNameMatch: 0,
          oursOnly: 0,
          inconclusive: 0,
        },
        vantages: 3,
        networks: 2,
        timing: { pairs: 2, oursMs: addsMs + 5, realMs: 5, addsMs },
      },
    });
    const facts: Record<string, NameFacts> = {
      'n1.example': timed(120, 'edge:a:198.51.100.1:443'),
      'n2.example': timed(80, 'edge:b:198.51.100.1:443'),
      // Measured on another transport's address: not this transport's target.
      'n3.example': timed(900, 'edge:elsewhere:198.51.100.9:443'),
    };
    const v = buildCountryView([origin()], (n) => facts[n] ?? null, SETTINGS);
    expect(v.origins[0]!.listeners[0]!.targetAdds).toEqual({
      ms: 100,
      oursMs: 105,
      realMs: 5,
      pairs: 4,
      names: 2,
      at: NOW - H,
      flagged: true,
    });
    const quiet = buildCountryView(
      [origin()],
      (n) => (n === 'n1.example' ? timed(20, 'edge:a:198.51.100.1:443') : null),
      SETTINGS,
    );
    expect(quiet.origins[0]!.listeners[0]!.targetAdds).toMatchObject({ ms: 20, flagged: false });
  });

  test('a retired name still draining is listed; one past its drain is not', () => {
    const o = origin();
    const l = o.listeners[0]!;
    const names = [
      ...l.names,
      {
        name: 'old.example',
        status: 'retired' as const,
        drainUntil: NOW + H,
        blockedIn: [],
        provenIn: [],
      },
      {
        name: 'gone.example',
        status: 'retired' as const,
        drainUntil: NOW - H,
        blockedIn: [],
        provenIn: [],
      },
    ];
    const v = buildCountryView([{ ...o, listeners: [{ ...l, names }] }], () => null, SETTINGS);
    const listed = v.origins[0]!.listeners[0]!.names.map((n) => n.name);
    expect(listed).toContain('old.example');
    expect(listed).not.toContain('gone.example');
    expect(v.origins[0]!.listeners[0]!.names.find((n) => n.name === 'old.example')!.offered).toBe(
      false,
    );
  });
});
