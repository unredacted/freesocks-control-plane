import { describe, expect, test } from 'vitest';
import { pickInstance, resolveServersRoute, serversPaths } from './routes';
import {
  blockerWords,
  firewallNodeWords,
  portChangeTitle,
  portChangeWords,
  portChangeable,
  protectionWords,
  setupWords,
  stageWords,
  standbyWords,
  templateWords,
} from './words';
import {
  WORDED_CODES,
  ago,
  foreignEditWords,
  inboundSummary,
  namesDelta,
  nodeWords,
  needsYou,
  quietNotes,
  nodeNotes,
  fleetSentence,
  countryLabel,
  observedWords,
  opTitle,
  opWords,
  parseNames,
  serverErrorWords,
  serverNamesLabel,
} from './words';

const inbound = (over: Record<string, unknown> = {}) => ({
  tag: 'reality-in',
  transportUuid: 'i-1',
  protocol: 'vless',
  port: 443 as number | null,
  listen: null,
  network: 'tcp',
  security: 'reality',
  serverNames: ['a.example', 'b.example'] as string[] | null,
  realityTarget: 'target.example:443',
  tlsServerName: null,
  path: null,
  serviceName: null,
  realityPublicKey: 'pk',
  realityPublicKeyMismatch: false,
  addresses: [{ remark: 'h' }] as never[],
  modeGroups: [{ groupUuid: 's', name: 'free' }],
  ...over,
});

const node = (over: Record<string, unknown> = {}) => ({
  nodeUuid: 'n-1',
  name: 'node-one',
  online: true,
  isDisabled: false,
  usersOnline: 4,
  profile: { profileUuid: 'p', name: 'Default', transportCount: 1, changedAt: null },
  transports: [inbound()],
  ...over,
});

describe('nodeWords', () => {
  test('one dot and one sentence per situation, worst first', () => {
    expect(nodeWords(node() as never)).toEqual({
      dot: 'green',
      sentence: 'Online, 4 people connected.',
    });
    expect(nodeWords(node({ usersOnline: 1 }) as never).sentence).toBe(
      'Online, 1 person connected.',
    );
    expect(nodeWords(node({ online: false }) as never).dot).toBe('red');
    expect(nodeWords(node({ transports: [] }) as never).dot).toBe('amber');
    expect(nodeWords(node({ profile: null, transports: [] }) as never).sentence).toMatch(
      /No config profile/,
    );
    // Off wins over everything: it is a decision, not a fault.
    expect(nodeWords(node({ isDisabled: true, online: false }) as never).dot).toBe('grey');
  });
});

describe('transport words', () => {
  test('summary', () => {
    expect(inboundSummary(inbound())).toBe('VLESS over TCP, REALITY, port 443');
    expect(inboundSummary(inbound({ network: 'raw', security: 'none', port: null }))).toBe(
      'VLESS over TCP, no TLS, several ports',
    );
    expect(inboundSummary(inbound({ network: 'ws', security: 'tls', port: 8443 }))).toBe(
      'VLESS over WS, TLS, port 8443',
    );
  });

  test('server name count', () => {
    expect(serverNamesLabel(inbound())).toBe('2 server names');
    expect(serverNamesLabel(inbound({ serverNames: ['a.example'] }))).toBe('1 server name');
    expect(serverNamesLabel(inbound({ serverNames: [] }))).toBe('No server names');
    expect(serverNamesLabel(inbound({ serverNames: null }))).toBeNull();
  });
});

describe('observedWords', () => {
  const NOW = Date.parse('2026-01-01T12:00:00Z');
  const state = (over: Record<string, unknown>) => ({
    observedAt: null,
    attemptedAt: null,
    ok: null,
    errorCode: null,
    counts: null,
    ...over,
  });
  test('never read, read, failed with and without an older picture', () => {
    expect(observedWords(state({}) as never, false, NOW)).toMatch(/turn on regular reading/);
    expect(observedWords(state({}) as never, true, NOW)).toMatch(/every ten minutes/);
    expect(
      observedWords(state({ ok: true, observedAt: '2026-01-01T11:55:00Z' }) as never, true, NOW),
    ).toBe('Read 5 minutes ago.');
    expect(
      observedWords(state({ ok: false, observedAt: '2026-01-01T10:00:00Z' }) as never, true, NOW),
    ).toBe('The last read failed. Showing what was read 2 hours ago.');
    expect(observedWords(state({ ok: false }) as never, true, NOW)).toMatch(/could not be read/);
  });
  test('ago', () => {
    expect(ago(10_000)).toBe('just now');
    expect(ago(60_000)).toBe('1 minute ago');
    expect(ago(3_600_000)).toBe('1 hour ago');
    expect(ago(3 * 86_400_000)).toBe('3 days ago');
  });
});

describe('what the page says', () => {
  const tree = (nodes: unknown[], over: Record<string, unknown> = {}) =>
    ({ nodes, profiles: [], unattached: { profiles: [], addresses: [] }, ...over }) as never;

  test('the instance in one sentence', () => {
    expect(fleetSentence([])).toEqual({ dot: 'grey', text: 'No nodes on this backend yet.' });
    expect(fleetSentence([node({ usersOnline: 3 }), node()] as never)).toEqual({
      dot: 'green',
      text: 'All 2 nodes are online, 7 people connected.',
    });
    expect(fleetSentence([node({ usersOnline: 1 })] as never).text).toBe(
      'The node is online, 1 person connected.',
    );
    expect(fleetSentence([node({ usersOnline: 1 }), node({ online: false })] as never)).toEqual({
      dot: 'amber',
      text: '1 of 2 nodes online, 1 person connected. The backend cannot reach the other one.',
    });
    expect(fleetSentence([node({ online: false })] as never).dot).toBe('red');
    // A node turned off on purpose is not "unreachable".
    expect(fleetSentence([node(), node({ isDisabled: true, online: false })] as never).dot).toBe(
      'green',
    );
  });

  test('needs you: only what is broken, one line each', () => {
    expect(needsYou(tree([node()]))).toEqual([]);
    const rows = needsYou(
      tree(
        [
          node({
            transports: [
              inbound({ realityPublicKeyMismatch: true, addresses: [], modeGroups: [] }),
            ],
          }),
        ],
        {
          profiles: [
            { profileUuid: 'p-1', name: 'Default', foreignEditAt: '2026-01-01T00:00:00Z' },
          ],
          unattached: { profiles: ['Old profile'], addresses: ['a', 'b', 'c', 'd', 'e'] },
        },
      ),
    );
    expect(rows.map((r) => r.key)).toEqual([
      'key:n-1:reality-in',
      'edit:p-1',
      'unattached-addresses',
    ]);
    expect(rows[0]!.nodeUuid).toBe('n-1');
    expect(rows[2]!.text).toBe(
      'a, b, c and 2 more point at a transport no node serves. People given them cannot connect.',
    );
  });

  test('quiet notes: one unused transport on three nodes is one line', () => {
    const unused = (name: string) =>
      node({
        nodeUuid: name,
        name,
        transports: [inbound({ tag: 'VLESS_XHTTP_CDN', addresses: [], modeGroups: [] })],
      });
    expect(quietNotes(tree([unused('a'), unused('b'), unused('c')]))).toEqual([
      'VLESS_XHTTP_CDN is unused on every node: no address and no mode group.',
    ]);
    expect(
      quietNotes(
        tree([unused('a'), node({ nodeUuid: 'b', name: 'b' })], {
          unattached: { profiles: ['Default-Profile'], addresses: [] },
        }),
      ),
    ).toEqual([
      'VLESS_XHTTP_CDN is unused on a: no address and no mode group.',
      'No node runs Default-Profile.',
    ]);
    expect(quietNotes(tree([node({ transports: [inbound({ modeGroups: [] })] })]))).toEqual([
      'reality-in is unused on node-one: in no mode group.',
    ]);
    expect(quietNotes(tree([node()]))).toEqual([]);
  });

  test("a node's own notes, and its country", () => {
    expect(nodeNotes(node({ transports: [inbound({ addresses: [] })] }) as never)).toEqual([
      'reality-in has no address for members.',
    ]);
    expect(countryLabel('XX')).toBeNull();
    expect(countryLabel(null)).toBeNull();
    expect(countryLabel('nl')).toBe('Netherlands');
  });

  test('house style: no em-dash, no API path, no bare code word', () => {
    const all = [
      ...needsYou(
        tree(
          [
            node({
              transports: [
                inbound({ realityPublicKeyMismatch: true, addresses: [], modeGroups: [] }),
              ],
            }),
          ],
          {
            profiles: [{ profileUuid: 'p', name: 'Default', foreignEditAt: 'x' }],
            unattached: { profiles: ['p'], addresses: ['h'] },
          },
        ),
      ).map((n) => n.text),
      ...quietNotes(tree([node({ transports: [inbound({ addresses: [], modeGroups: [] })] })])),
      fleetSentence([node(), node({ online: false })] as never).text,
      nodeWords(node({ online: false }) as never).sentence,
      nodeWords(node({ profile: null }) as never).sentence,
    ].join('\n');
    expect(all).not.toMatch(/—|–/);
    expect(all).not.toMatch(/\/api\//);
    // (transport tags such as reality-in are the backend's own names, not code words)
    expect(all.replace(/reality-in/g, '')).not.toMatch(/[a-z]+_[a-z]+/);
  });
});

describe('routes', () => {
  test('paths and instance selection', () => {
    expect(serversPaths.home()).toBe('/admin/servers');
    expect(serversPaths.home({ instance: 'backend a' })).toBe(
      '/admin/servers?instance=backend%20a',
    );
    expect(serversPaths.node('n 1', { instance: 'p' })).toBe(
      '/admin/servers/nodes/n%201?instance=p',
    );
    expect(resolveServersRoute('/admin/servers')).toEqual({ page: 'home' });
    expect(resolveServersRoute('/admin/servers/nodes/n%201')).toEqual({
      page: 'node',
      uuid: 'n 1',
    });
    expect(resolveServersRoute('/admin/servers/x')).toEqual({ page: 'not-found' });
    const list = [
      { slug: 'outline-a', observable: false },
      { slug: 'panel-a', observable: true },
    ];
    expect(pickInstance('?instance=outline-a', list)).toBe('outline-a');
    expect(pickInstance('?instance=gone', list)).toBe('panel-a');
    expect(pickInstance('', list)).toBe('panel-a');
    expect(pickInstance('', [{ slug: 'outline-a', observable: false }])).toBe('outline-a');
    expect(pickInstance('', [])).toBeNull();
  });
});

describe('write wording', () => {
  // Codes that are never shown as a refusal: an op's own outcome notes, an
  // internal guard, and answers only the node role's token ever receives.
  const NOT_SHOWN = new Set([
    'servers.adopted_existing',
    'servers.never_sent',
    'servers.recovered',
    'servers.claim_not_held',
    'servers.observe_failed',
    'servers.reservation_conflict',
  ]);

  test('every refusal the server can answer has its own words', () => {
    const sources = import.meta.glob(
      [
        '../../../../../../convex/backend*.ts',
        '../../../../../../convex/node*.ts',
        '../../../../../../convex/lib/backend/*.ts',
        '!**/*.test.ts',
      ],
      { query: '?raw', import: 'default', eager: true },
    ) as Record<string, string>;
    const codes = new Set<string>();
    for (const text of Object.values(sources))
      for (const m of text.matchAll(/'(servers\.[a-z_]+)'/g)) codes.add(m[1]!);
    expect(codes.size).toBeGreaterThan(20);
    const unworded = [...codes].filter((c) => !NOT_SHOWN.has(c) && !WORDED_CODES.includes(c));
    expect(unworded).toEqual([]);
  });

  test('no em-dashes, and no code leaks into the copy', () => {
    for (const code of WORDED_CODES) {
      const words = serverErrorWords(code);
      expect(words).not.toMatch(/—|servers\./);
    }
  });

  test('an edit made elsewhere says what may now be wrong, without blame', () => {
    const words = foreignEditWords('Default', '5 minutes ago');
    expect(words).toMatch(/^Default was changed on the backend 5 minutes ago, not from here/);
    expect(words).not.toMatch(/—/);
  });

  test('a change in words', () => {
    const op = { kind: 'node', verb: 'restart', label: 'node-one', errorCode: null } as const;
    expect(opTitle({ ...op, state: 'done' })).toBe('Restart node node-one');
    expect(opTitle({ ...op, kind: 'host', verb: 'reorder', state: 'done' })).toBe(
      'Reorder addresses',
    );
    expect(opWords({ ...op, state: 'waiting_for_nodes' }).dot).toBe('amber');
    expect(opWords({ ...op, state: 'outcome_unknown' }).dot).toBe('red');
    expect(
      opWords({ ...op, state: 'done', errorCode: 'servers.adopted_existing' }).sentence,
    ).toMatch(/already there/);
    expect(opWords({ ...op, state: 'refused', errorCode: 'servers.never_sent' }).sentence).toMatch(
      /Never sent/,
    );
    // A refusal FCP made itself names its reason; only the backend's own is "the backend refused it".
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.profile_changed' }).sentence,
    ).toMatch(/Preview again/);
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.nothing_to_change' }).sentence,
    ).toMatch(/already had exactly this/);
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.panel_refused' }).sentence,
    ).toMatch(/backend refused/);
  });

  test('server names are parsed from lines or commas, in order, without repeats', () => {
    expect(parseNames(' a.example\nb.example, a.example\n\n c.example ')).toEqual([
      'a.example',
      'b.example',
      'c.example',
    ]);
    expect(namesDelta(['a', 'b'], ['b', 'c', 'd'])).toBe('2 added, 1 removed');
    expect(namesDelta(['a', 'b'], ['b', 'a'])).toBe('Same names, new order');
  });
});

describe('enrolled nodes', () => {
  const base = {
    disposition: 'staged',
    state: 'ready',
    code: null,
    maintenance: false,
    retirement: null,
  };
  test('one sentence per stage, live only when served', () => {
    expect(stageWords({ ...base, stage: 'registered' }).dot).toBe('grey');
    expect(stageWords({ ...base, stage: 'machine_ready' })).toEqual({
      dot: 'amber',
      sentence: 'The machine is ready. Test the connection, then approve.',
    });
    expect(stageWords({ ...base, stage: 'live', disposition: 'live' })).toEqual({
      dot: 'green',
      sentence: 'Live for members.',
    });
    expect(stageWords({ ...base, stage: 'live', disposition: 'unavailable' }).dot).toBe('amber');
    expect(stageWords({ ...base, stage: 'live', maintenance: true }).sentence).toMatch(
      /maintenance/,
    );
    expect(
      stageWords({ ...base, stage: 'live', retirement: { stage: 'needs_admin' } }).sentence,
    ).toMatch(/decision/);
    expect(
      stageWords({
        ...base,
        stage: 'registered',
        state: 'blocked',
        code: 'servers.origin_name_taken',
      }).dot,
    ).toBe('red');
  });
  test('a fronted node goes live through its protection in Edges', () => {
    const fronted = { ...base, mode: { shape: { fronting: 'edge-l4' } } };
    expect(stageWords({ ...fronted, stage: 'machine_ready' }).sentence).toBe(
      'The machine is ready. Protect it from Edges to go live.',
    );
    expect(
      stageWords({
        ...fronted,
        stage: 'machine_ready',
        protection: { state: 'running', need: null },
      }).sentence,
    ).toBe('Being protected in Edges.');
    expect(
      stageWords({
        ...fronted,
        stage: 'machine_ready',
        protection: { state: 'needs_you', need: 'node_not_approved' },
      }),
    ).toEqual({ dot: 'amber', sentence: 'Tested. Waiting for you to approve go-live.' });
    expect(
      stageWords({
        ...fronted,
        stage: 'live',
        disposition: 'live',
        protection: { state: 'needs_you', need: 'node_not_approved' },
      }).sentence,
    ).toMatch(/^Live\. .*approve go-live/);
    expect(stageWords({ ...fronted, stage: 'awaiting_approval' }).sentence).toMatch(
      /approve go-live in its protection progress/,
    );
    // A direct node ignores a protection it cannot have.
    expect(
      stageWords({
        ...base,
        mode: { shape: { fronting: 'direct' } },
        stage: 'machine_ready',
        protection: { state: 'needs_you', need: 'node_not_approved' },
      }).sentence,
    ).toBe('The machine is ready. Test the connection, then approve.');
    expect(protectionWords({ state: 'needs_you', need: 'node_not_approved' })).toMatch(
      /Approve go-live below/,
    );
    expect(protectionWords({ state: 'running', need: null })).toMatch(/carries on by itself/);
    // Approved: the run's parked need is stale until it wakes, so the stage speaks.
    const approved = { state: 'needs_you', need: 'node_not_approved' };
    expect(protectionWords(approved, 'activating')).toMatch(/^Approved\./);
    expect(stageWords({ ...fronted, stage: 'activating', protection: approved }).sentence).toMatch(
      /^Releasing to members/,
    );
  });
  test('the approval card in words', () => {
    expect(
      standbyWords({
        listenerKey: 'main',
        layer: 'l4',
        endpoint: '203.0.113.7:443',
        accountName: 'Main account',
      }),
    ).toBe('main: members get 203.0.113.7:443, an address in Main account.');
    expect(
      standbyWords({ listenerKey: 'ws', layer: 'l7', endpoint: null, accountName: null }),
    ).toBe('ws: members get a new address.');
    expect(blockerWords('servers.stage')).toMatch(/approved/);
    expect(blockerWords('servers.maintenance_required')).toMatch(/^Put the node in maintenance/);
    expect(blockerWords('servers.template_drifted')).toBe(
      serverErrorWords('servers.template_drifted'),
    );
    for (const code of ['servers.stage', 'servers.maintenance_required'])
      expect(blockerWords(code)).not.toMatch(/—|servers\./);
  });
  test('the setup row', () => {
    expect(setupWords({ exists: false, state: null, code: null, running: false })).toMatch(
      /not set up/,
    );
    expect(setupWords({ exists: true, state: 'ready', code: null, running: false })).toBeNull();
    expect(
      setupWords({
        exists: true,
        state: 'pending',
        code: 'servers.obligation_unresolved',
        running: true,
      }),
    ).toBe('Setting up the backend.');
  });
  test('no em-dashes in any of it', () => {
    for (const stage of [
      'registered',
      'bootstrap_available',
      'machine_applied',
      'machine_ready',
      'candidates_verified',
      'awaiting_approval',
      'activating',
      'live',
    ]) {
      expect(stageWords({ ...base, stage }).sentence).not.toMatch(/—/);
      expect(
        stageWords({ ...base, stage, mode: { shape: { fronting: 'edge-l4' } } }).sentence,
      ).not.toMatch(/—/);
    }
  });
});

describe('port changes in words', () => {
  const change = {
    transportTag: 'PRIVACY_REALITY',
    fromPort: 443,
    toPort: 8443,
    code: null,
    nodes: [
      { name: 'node-a', confirmedBy: 'role' as const, state: 'waiting' },
      { name: 'stranger', confirmedBy: 'operator' as const, state: 'confirmed' },
    ],
  };

  test('says what waits, and that nothing is sent until then', () => {
    expect(portChangeTitle(change)).toBe('Move PRIVACY_REALITY from port 443 to 8443');
    expect(portChangeWords({ ...change, state: 'waiting' })).toEqual({
      dot: 'amber',
      sentence: 'Nothing is sent until every node lets port 8443 in. Waiting for 1 node.',
    });
    const all = change.nodes.map((n) => ({ ...n, state: 'confirmed' }));
    expect(
      portChangeWords({ ...change, nodes: all, state: 'waiting', code: 'servers.op_running' })
        .sentence,
    ).toMatch(/another change to this profile/);
    expect(portChangeWords({ ...change, state: 'applied' }).dot).toBe('green');
    // A recovery says nothing about whether the port moved.
    expect(portChangeWords({ ...change, state: 'recovered' })).toMatchObject({ dot: 'red' });
    expect(portChangeWords({ ...change, state: 'recovered' }).sentence).toMatch(/is not known/);
    expect(
      portChangeWords({ ...change, state: 'refused', code: 'servers.profile_changed' }).sentence,
    ).toMatch(/^Not sent: The profile changed/);
  });

  test('tells the operator who confirms each node, and how', () => {
    expect(firewallNodeWords({ confirmedBy: 'role', state: 'waiting' }, 8443)).toMatch(
      /Run the role on this node/,
    );
    expect(firewallNodeWords({ confirmedBy: 'operator', state: 'waiting' }, 8443)).toMatch(
      /confirm it here/,
    );
    expect(firewallNodeWords({ confirmedBy: 'role', state: 'confirmed' }, 8443)).toBe(
      'Lets port 8443 in.',
    );
  });

  test('no em-dashes in any of it', () => {
    const states = ['waiting', 'applying', 'applied', 'refused', 'cancelled', 'recovered'] as const;
    for (const state of states)
      expect(portChangeWords({ ...change, state }).sentence).not.toMatch(/—/);
    for (const k of ['reality', 'xhttp-reality', 'ws']) expect(templateWords(k)).not.toMatch(/—/);
  });
});

test('a port is changed here only on a public, single-port transport', () => {
  expect(portChangeable({ port: 443, listen: '::' })).toBe(true);
  expect(portChangeable({ port: 443, listen: null })).toBe(true);
  expect(portChangeable({ port: 8443, listen: '127.0.0.1' })).toBe(false);
  expect(portChangeable({ port: 8443, listen: '[::1]' })).toBe(false);
  expect(portChangeable({ port: null, listen: '0.0.0.0' })).toBe(false);
});
