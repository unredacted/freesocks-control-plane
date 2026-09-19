import { describe, expect, test } from 'vitest';
import { pickInstance, serversPaths } from './routes';
import {
  WORDED_CODES,
  ago,
  inboundSummary,
  namesDelta,
  nodeWords,
  notices,
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

describe('notices', () => {
  test('nothing to say about a healthy instance', () => {
    expect(notices({ nodes: [node()] as never, unattached: { profiles: [], hosts: [] } })).toEqual(
      [],
    );
  });

  test('names what is wrong in plain words', () => {
    const out = notices({
      nodes: [
        node({
          inbounds: [inbound({ realityPublicKeyMismatch: true, hosts: [], squads: [] })],
        }),
      ] as never,
      unattached: { profiles: ['Old profile'], hosts: ['a', 'b', 'c', 'd', 'e'] },
    });
    expect(out.map((n) => n.tone)).toEqual(['warn', 'info', 'info', 'warn', 'info']);
    expect(out[0]!.text).toMatch(/does not match its private key/);
    expect(out[3]!.text).toBe(
      'a, b, c and 2 more point at an inbound no node serves. People given them cannot connect.',
    );
    expect(out[4]!.text).toBe('No node runs Old profile.');
  });

  test('house style: no em-dash, no API path, no bare code word', () => {
    const all = [
      ...notices({
        nodes: [
          node({ inbounds: [inbound({ realityPublicKeyMismatch: true, hosts: [], squads: [] })] }),
        ] as never,
        unattached: { profiles: ['p'], hosts: ['h'] },
      }).map((n) => n.text),
      nodeWords(node({ online: false }) as never).sentence,
      nodeWords(node({ profile: null }) as never).sentence,
    ].join('\n');
    expect(all).not.toMatch(/—|–/);
    expect(all).not.toMatch(/\/api\//);
    expect(all).not.toMatch(/[a-z]+_[a-z]+/);
  });
});

describe('routes', () => {
  test('paths and instance selection', () => {
    expect(serversPaths.home()).toBe('/admin/servers');
    expect(serversPaths.home({ instance: 'panel a' })).toBe('/admin/servers?instance=panel%20a');
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
