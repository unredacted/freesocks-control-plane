import { describe, expect, test } from 'vitest';
import { pickInstance, resolveServersRoute, serversPaths } from './routes';
import {
  blockerWords,
  firewallNodeWords,
  portChangeTitle,
  portChangeWords,
  portChangeable,
  protectionWords,
  renameWords,
  retireConfirmWords,
  retirementSteps,
  setupWords,
  stageWords,
  standbyWords,
  templateWords,
} from './words';
import {
  WORDED_CODES,
  ago,
  inboundSummary,
  namesDelta,
  nodeWords,
  needsYou,
  quietNotes,
  nodeNotes,
  fleetSentence,
  intentRestarting,
  nodesBeingChanged,
  countryLabel,
  opRepeatKey,
  opRepeatWords,
  opTitle,
  opWords,
  parseNames,
  serverErrorWords,
  serverNamesLabel,
  frontsHint,
  splitAddresses,
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

describe('ago', () => {
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

  test("the operator's own fronts are split from the addresses members get, in order", () => {
    const a = (remark: string, operatorFront: boolean) => ({ remark, operatorFront });
    expect(
      splitAddresses([a('lb-1', true), a('node-one-relay-a', false), a('lb-2', true)]),
    ).toEqual({
      members: [a('node-one-relay-a', false)],
      fronts: [a('lb-1', true), a('lb-2', true)],
    });
    expect(frontsHint(1)).toBe(
      "Members get this node's edges instead. Once its traffic stops, delete this front at its provider, and its address here.",
    );
    expect(frontsHint(2)).toMatch(/delete these fronts at their provider/);
    // With the count of the node's keys that have not fetched since it went live.
    expect(frontsHint(3, { stale: 1204, total: 2050 })).toBe(
      "Members get this node's edges instead. 1,204 of its 2,050 keys have not fetched since it went live: those apps still use these fronts until the member updates the subscription in the app. Once their traffic stops, delete these fronts at their provider, and their addresses here.",
    );
    expect(frontsHint(1, { stale: 1, total: 1 })).toMatch(/1 of its 1 key has not fetched/);
    expect(frontsHint(1, { stale: 0, total: 9 })).toBe(
      "Members get this node's edges instead, and every key on it has fetched since it went live. Delete this front at its provider, and its address here.",
    );
  });

  test('a transport whose only addresses are fronts left out has none for members', () => {
    const fronts = [{ remark: 'lb-1', operatorFront: true }] as never[];
    expect(nodeNotes(node({ transports: [inbound({ addresses: fronts })] }) as never)).toEqual([
      'reality-in has no address for members.',
    ]);
    expect(quietNotes(tree([node({ transports: [inbound({ addresses: fronts })] })]))).toEqual([
      'reality-in is unused on node-one: no address for members.',
    ]);
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
      frontsHint(1),
      frontsHint(2),
      frontsHint(2, { stale: 5, total: 9 }),
      frontsHint(1, { stale: 0, total: 9 }),
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

  test('a run of the same change folds to one line that says how often', () => {
    const op = {
      kind: 'host',
      verb: 'create',
      label: 'node-one',
      state: 'refused',
      errorCode: 'servers.never_sent',
      open: false,
    } as const;
    expect(opRepeatWords(op, 40).sentence).toBe('Tried 40 times, never sent. Nothing was changed.');
    expect(opRepeatWords(op, 1).sentence).toBe(opWords(op).sentence);
    expect(opRepeatWords({ ...op, state: 'done', errorCode: null }, 3).sentence).toBe(
      '3 times in a row. Done, and seen on the backend.',
    );
    // An open change keeps its own line (it has buttons); settled twins share a key.
    expect(opRepeatKey({ ...op, open: true })).toBeNull();
    expect(opRepeatKey(op)).toBe(opRepeatKey({ ...op }));
    expect(opRepeatKey(op)).not.toBe(opRepeatKey({ ...op, label: 'node-two' }));
  });

  test('a node restarting for a change softens the headline instead of turning it red', () => {
    const node = (name: string, online: boolean) => ({
      name,
      online,
      isDisabled: false,
      usersOnline: online ? 2 : 0,
    });
    const nodes = [node('a', false)];
    expect(fleetSentence(nodes).dot).toBe('red');
    const soft = fleetSentence(nodes, () => true);
    expect(soft.dot).toBe('amber');
    expect(soft.text).toBe('1 node is restarting while a change is applied. Back in a moment.');
    const mixed = fleetSentence(
      [node('a', true), node('b', false), node('c', false)],
      (n) => n.name === 'b',
    );
    expect(mixed.text).toBe(
      '1 of 3 nodes online, 2 people connected. 1 restarting while a change is applied, and the backend cannot reach 1 more.',
    );
    // Without a restart the words are unchanged.
    expect(fleetSentence([node('a', true), node('b', false)]).text).toBe(
      '1 of 2 nodes online, 2 people connected. The backend cannot reach the other one.',
    );
    const now = Date.parse('2026-10-17T10:00:00Z');
    const intent = {
      state: 'ready',
      machineRevision: 2,
      appliedRevision: 2,
      roleSeenAt: '2026-10-17T09:00:00Z',
      run: null,
    };
    expect(intentRestarting(intent, now)).toBe(false);
    expect(intentRestarting({ ...intent, roleSeenAt: '2026-10-17T09:59:00Z' }, now)).toBe(true);
    expect(intentRestarting({ ...intent, appliedRevision: 1 }, now)).toBe(true);
    expect(intentRestarting({ ...intent, state: 'pending' }, now)).toBe(true);
    expect(intentRestarting({ ...intent, run: { state: 'running' } }, now)).toBe(true);
    // Only the nodes an open change waits on are restarting, never the whole backend.
    const changed = nodesBeingChanged([
      { open: true, state: 'waiting_for_nodes', asyncNodeUuids: ['n1'] },
      { open: false, state: 'done', asyncNodeUuids: ['n2'] },
      { open: true, state: 'working', asyncNodeUuids: ['n3'] },
    ]);
    expect([...changed]).toEqual(['n1']);
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

describe('retiring a node', () => {
  const now = Date.parse('2026-10-17T10:00:00Z');
  const r = (over: Record<string, unknown> = {}) => ({
    stage: 'draining',
    code: null as string | null,
    step: null as string | null,
    requestedBy: 'admin' as 'admin' | 'role',
    decision: false,
    since: '2026-10-17T09:48:00Z' as string | null,
    ...over,
  });
  const current = (steps: ReturnType<typeof retirementSteps>) =>
    steps.find((s) => s.state === 'current') ?? null;

  test('the confirm says members lose the node at once, and who wipes the machine', () => {
    const fcp = retireConfirmWords({ adopted: false });
    expect(fcp).toMatch(/^Members lose this node at once/);
    expect(fcp).toMatch(/every 5 minutes/);
    expect(fcp).toMatch(/node role wipes the machine/);
    expect(retireConfirmWords({ adopted: true })).toMatch(/you confirm here/);
    for (const w of [fcp, retireConfirmWords({ adopted: true })]) expect(w).not.toMatch(/—/);
  });

  test('an admin retirement walks the ladder; the step the server recorded is the current one', () => {
    const steps = retirementSteps(
      { adopted: false, retirement: r({ step: 'origin', code: 'servers.relay_draining' }) },
      now,
    );
    // An admin's own request needs no decision step.
    expect(steps.map((s) => s.key)).toEqual([
      'closed',
      'edges',
      'addresses',
      'dns',
      'panel',
      'wipe',
      'retired',
    ]);
    expect(steps[0]!.state).toBe('done');
    const c = current(steps)!;
    expect(c.key).toBe('edges');
    expect(c.why).toBe(
      'Its edges are still being taken down. FCP looks again every 5 minutes (this step started 12 minutes ago).',
    );
    expect(steps.filter((s) => s.state === 'todo').map((s) => s.key)).toEqual([
      'addresses',
      'dns',
      'panel',
      'wipe',
      'retired',
    ]);
    expect(
      current(retirementSteps({ adopted: false, retirement: r({ step: 'credentials' }) }, now))!
        .key,
    ).toBe('edges');
    expect(
      current(
        retirementSteps(
          { adopted: false, retirement: r({ step: 'dns', code: 'servers.obligation_unresolved' }) },
          now,
        ),
      )!.key,
    ).toBe('dns');
    expect(
      current(retirementSteps({ adopted: false, retirement: r({ step: 'panel_row' }) }, now))!.key,
    ).toBe('panel');
  });

  test('a role request waits for the decision; the wipe step names who acts', () => {
    const asked = retirementSteps(
      { adopted: false, retirement: r({ stage: 'needs_admin', requestedBy: 'role' }) },
      now,
    );
    expect(current(asked)!.key).toBe('decision');
    expect(current(asked)!.why).toMatch(/serves members meanwhile/);
    expect(current(asked)!.why).toMatch(/reject the request/);
    // The node is closed only once the request is decided.
    expect(asked.map((s) => s.key).slice(0, 2)).toEqual(['decision', 'closed']);
    expect(asked.find((s) => s.key === 'closed')!.state).toBe('todo');
    // Once decided, the decision is a done step.
    const decided = retirementSteps(
      { adopted: false, retirement: r({ requestedBy: 'role', decision: true, step: 'dns' }) },
      now,
    );
    expect(decided.find((s) => s.key === 'decision')!.state).toBe('done');
    // A plain role request (never live, nothing outstanding) never asked anyone.
    const plain = retirementSteps(
      { adopted: false, retirement: r({ requestedBy: 'role', step: 'addresses' }) },
      now,
    );
    expect(plain.map((s) => s.key)).not.toContain('decision');
    const role = retirementSteps(
      { adopted: false, retirement: r({ stage: 'ready_to_wipe' }) },
      now,
    );
    expect(current(role)!.label).toBe('The node role wipes the machine');
    expect(current(role)!.why).toMatch(/node role to wipe/);
    const adopted = retirementSteps(
      { adopted: true, retirement: r({ stage: 'ready_to_wipe' }) },
      now,
    );
    expect(current(adopted)!.label).toBe('You confirm the machine is gone');
    expect(current(adopted)!.why).toMatch(/The machine is gone/);
  });

  test('a request an earlier release recorded already closed the node: only the decision is left', () => {
    const legacy = retirementSteps(
      {
        adopted: false,
        disposition: 'retiring',
        retirement: r({ stage: 'needs_admin', requestedBy: 'role' }),
      },
      now,
    );
    expect(legacy.map((s) => s.key).slice(0, 2)).toEqual(['closed', 'decision']);
    expect(legacy[0]!.state).toBe('done');
    expect(current(legacy)!.key).toBe('decision');
    expect(current(legacy)!.why).toMatch(/already get the unavailable answer/);
    expect(current(legacy)!.why).not.toMatch(/reject/);
  });

  test('retired: every step done, nothing waits; an unworded code still reads as an error', () => {
    const done = retirementSteps({ adopted: false, retirement: r({ stage: 'retired' }) }, now);
    expect(done.every((s) => s.state === 'done' && s.why === null)).toBe(true);
    const odd = retirementSteps(
      { adopted: false, retirement: r({ step: 'addresses', code: 'servers.op_refused:x' }) },
      now,
    );
    expect(current(odd)!.why).toMatch(/^It stopped on an error \(servers\.op_refused:x\)\./);
    const fresh = retirementSteps(
      { adopted: false, retirement: r({ stage: 'requested', since: null }) },
      now,
    );
    expect(current(fresh)!.why).toBe('Under way. FCP looks again every 5 minutes.');
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
    // A role's request leaves the node serving until the admin decides.
    expect(
      stageWords({
        ...base,
        stage: 'live',
        disposition: 'live',
        retirement: { stage: 'needs_admin' },
      }).sentence,
    ).toBe('The node role asked to retire it. It serves members until you decide.');
    expect(
      stageWords({
        ...base,
        stage: 'live',
        disposition: 'retiring',
        retirement: { stage: 'needs_admin' },
      }).sentence,
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
      standbyWords({
        listenerKey: 'main',
        layer: 'l4',
        endpoint: '203.0.113.7:443',
        accountName: 'Main account',
        locationLabel: 'Region A',
      }),
    ).toBe('main: members get 203.0.113.7:443, an address in Main account (Region A).');
    expect(
      standbyWords({
        listenerKey: 'ws',
        layer: 'l7',
        endpoint: 'ws.example.org',
        accountName: 'CDN',
        locationLabel: 'Anycast',
      }),
    ).toBe('ws: members get ws.example.org, a CDN name in CDN.');
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

test('a rename in words: where it stands, and that members keep connecting', () => {
  const r = { from: 'node-a', to: 'node-b', code: null };
  expect(renameWords({ ...r, state: 'running', step: 'hosts' })).toEqual({
    dot: 'amber',
    sentence:
      'Being renamed from node-a to node-b. Renaming the addresses that carry its name. Members keep connecting.',
  });
  expect(
    renameWords({ ...r, state: 'running', step: 'backend', code: 'servers.op_uncertain' }).sentence,
  ).toMatch(/Waiting for a change on the backend to settle/);
  expect(renameWords({ ...r, state: 'done', step: 'done' }).sentence).toBe('Renamed from node-a.');
  expect(
    renameWords({
      ...r,
      state: 'running',
      step: 'hosts',
      code: 'servers.rename_host_refused',
      refusedHosts: [{ remark: 'node-a | x.example', code: 'servers.panel_refused' }],
    }),
  ).toMatchObject({
    dot: 'red',
    sentence: expect.stringMatching(/refused to rename node-a \| x\.example.*retry/),
  });
  expect(
    renameWords({ ...r, state: 'failed', step: 'backend', code: 'servers.panel_refused' }).sentence,
  ).toMatch(/^Not renamed to node-b: /);
  for (const step of ['backend', 'hosts', 'subscriptions', 'done'] as const)
    expect(renameWords({ ...r, state: 'running', step }).sentence).not.toMatch(/—/);
});
