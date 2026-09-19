import { describe, expect, test } from 'vitest';
import { pickInstance, resolveServersRoute, serversPaths } from './routes';
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
  inboundUuid: 'i-1',
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
  hosts: [{ remark: 'h' }] as never[],
  squads: [{ squadUuid: 's', name: 'free' }],
  ...over,
});

const node = (over: Record<string, unknown> = {}) => ({
  nodeUuid: 'n-1',
  name: 'node-one',
  online: true,
  isDisabled: false,
  usersOnline: 4,
  profile: { profileUuid: 'p', name: 'Default', inboundCount: 1, changedAt: null },
  inbounds: [inbound()],
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
    expect(nodeWords(node({ inbounds: [] }) as never).dot).toBe('amber');
    expect(nodeWords(node({ profile: null, inbounds: [] }) as never).sentence).toMatch(
      /No config profile/,
    );
    // Off wins over everything: it is a decision, not a fault.
    expect(nodeWords(node({ isDisabled: true, online: false }) as never).dot).toBe('grey');
  });
});

describe('inbound words', () => {
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
    ({ nodes, profiles: [], unattached: { profiles: [], hosts: [] }, ...over }) as never;

  test('the instance in one sentence', () => {
    expect(fleetSentence([])).toEqual({ dot: 'grey', text: 'No nodes on this panel yet.' });
    expect(fleetSentence([node({ usersOnline: 3 }), node()] as never)).toEqual({
      dot: 'green',
      text: 'All 2 nodes are online, 7 people connected.',
    });
    expect(fleetSentence([node({ usersOnline: 1 })] as never).text).toBe(
      'The node is online, 1 person connected.',
    );
    expect(fleetSentence([node({ usersOnline: 1 }), node({ online: false })] as never)).toEqual({
      dot: 'amber',
      text: '1 of 2 nodes online, 1 person connected. The panel cannot reach the other one.',
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
        [node({ inbounds: [inbound({ realityPublicKeyMismatch: true, hosts: [], squads: [] })] })],
        {
          profiles: [
            { profileUuid: 'p-1', name: 'Default', foreignEditAt: '2026-01-01T00:00:00Z' },
          ],
          unattached: { profiles: ['Old profile'], hosts: ['a', 'b', 'c', 'd', 'e'] },
        },
      ),
    );
    expect(rows.map((r) => r.key)).toEqual(['key:n-1:reality-in', 'edit:p-1', 'unattached-hosts']);
    expect(rows[0]!.nodeUuid).toBe('n-1');
    expect(rows[2]!.text).toBe(
      'a, b, c and 2 more point at an inbound no node serves. People given them cannot connect.',
    );
  });

  test('quiet notes: one unused inbound on three nodes is one line', () => {
    const unused = (name: string) =>
      node({
        nodeUuid: name,
        name,
        inbounds: [inbound({ tag: 'VLESS_XHTTP_CDN', hosts: [], squads: [] })],
      });
    expect(quietNotes(tree([unused('a'), unused('b'), unused('c')]))).toEqual([
      'VLESS_XHTTP_CDN is unused on every node: no address and no squad.',
    ]);
    expect(
      quietNotes(
        tree([unused('a'), node({ nodeUuid: 'b', name: 'b' })], {
          unattached: { profiles: ['Default-Profile'], hosts: [] },
        }),
      ),
    ).toEqual([
      'VLESS_XHTTP_CDN is unused on a: no address and no squad.',
      'No node runs Default-Profile.',
    ]);
    expect(quietNotes(tree([node({ inbounds: [inbound({ squads: [] })] })]))).toEqual([
      'reality-in is unused on node-one: in no squad.',
    ]);
    expect(quietNotes(tree([node()]))).toEqual([]);
  });

  test("a node's own notes, and its country", () => {
    expect(nodeNotes(node({ inbounds: [inbound({ hosts: [] })] }) as never)).toEqual([
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
              inbounds: [inbound({ realityPublicKeyMismatch: true, hosts: [], squads: [] })],
            }),
          ],
          {
            profiles: [{ profileUuid: 'p', name: 'Default', foreignEditAt: 'x' }],
            unattached: { profiles: ['p'], hosts: ['h'] },
          },
        ),
      ).map((n) => n.text),
      ...quietNotes(tree([node({ inbounds: [inbound({ hosts: [], squads: [] })] })])),
      fleetSentence([node(), node({ online: false })] as never).text,
      nodeWords(node({ online: false }) as never).sentence,
      nodeWords(node({ profile: null }) as never).sentence,
    ].join('\n');
    expect(all).not.toMatch(/—|–/);
    expect(all).not.toMatch(/\/api\//);
    // (inbound tags such as reality-in are the panel's own names, not code words)
    expect(all.replace(/reality-in/g, '')).not.toMatch(/[a-z]+_[a-z]+/);
  });
});

describe('routes', () => {
  test('paths and instance selection', () => {
    expect(serversPaths.home()).toBe('/admin/servers');
    expect(serversPaths.home({ instance: 'panel a' })).toBe('/admin/servers?instance=panel%20a');
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
        '../../../../../../convex/panel*.ts',
        '../../../../../../convex/lib/panel/*.ts',
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
    expect(words).toMatch(/^Default was changed on the panel 5 minutes ago, not from here/);
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
    // A refusal FCP made itself names its reason; only the panel's own is "the panel refused it".
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.profile_changed' }).sentence,
    ).toMatch(/Preview again/);
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.nothing_to_change' }).sentence,
    ).toMatch(/already had exactly this/);
    expect(
      opWords({ ...op, state: 'refused', errorCode: 'servers.panel_refused' }).sentence,
    ).toMatch(/panel refused/);
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
