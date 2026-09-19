import { describe, expect, test } from 'vitest';
import { pickInstance, serversPaths } from './routes';
import { ago, inboundSummary, nodeWords, notices, observedWords, serverNamesLabel } from './words';

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
