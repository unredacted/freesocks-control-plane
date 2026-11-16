/**
 * A listener's ENCRYPTED TWIN in a member body (docs/backends.md "VLESS
 * Encryption"): the same node behind the same addresses, once plain and once
 * with VLESS Encryption inside the stream. The backend renders both Hosts into
 * a body; these tests pin which of them each app is handed, in what order and
 * under what name, and that neither template ever leaves as it came.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { clientEncryption, generateVlessEncryption } from '../../backend/vlessEncryption';
import { defaultClientRule, sanitizeClientRule, RENDER_CLIENT_FAMILIES } from '../../edgeConfig';
import { twinRemarksOf } from '../listenerEncryption';
import type { ListenerProto } from '../protocols';
import { effectiveRule, ruleForDelivery } from '../render';
import { EDGE_DEFAULTS } from '../../edgeConfig';
import { AUTO_GROUP_NAME, plainFallbackName } from '../../../../src/shared/entryNames';
import type { EncryptionRule } from '../../../../src/shared/encryptionRule';
import { renderClash } from './clash';
import { renderLinks } from './links';
import { renderSingbox } from './singbox';
import {
  resolveMatchers,
  type MatchableEntry,
  type RenderEndpoint,
  type RenderMatcher,
  type RenderRuleInput,
} from './types';

const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const UUID = '11111111-2222-4333-8444-555555555555';
/** What the backend Hosts carry: the listener's template front. */
const TEMPLATE_FRONT = 'front-0.edge.example';
const FRONT_A = 'front-a.edge.example';
const FRONT_B = 'front-b.edge.example';
const PLAIN = 'node-a-relay-a1';
const TWIN = 'node-a-relay-e9';
const ENCRYPTION = clientEncryption(generateVlessEncryption().decryption)!;
const A = '🌐 via CDN 1';
const B = '🌐 via CDN 2';

const matcher: RenderMatcher = {
  listenerKey: 'a1',
  rule: { kind: 'remark', remark: PLAIN },
  encrypted: { remarks: [TWIN] },
  proto: WS,
  originAddress: '192.0.2.10',
  originPort: 443,
};

const endpoint = (role: 'primary' | 'backup', address: string, label: string): RenderEndpoint => ({
  role,
  label,
  edgeId: `edge-${role}`,
  listenerKey: 'a1',
  address,
  family: 'name',
  port: 443,
  sni: address,
  hostHeader: address,
});
const endpoints = [endpoint('primary', FRONT_A, A), endpoint('backup', FRONT_B, B)];

const rule = (encryption?: EncryptionRule, autoGroup = false): RenderRuleInput => ({
  autoGroup,
  dropTemplateEntries: true,
  maxEntries: 0,
  order: 'primary-first',
  ...(encryption ? { encryption } : {}),
});

// --- link lists ---------------------------------------------------------------

const link = (remark: string, path: string, encryption: string, address = TEMPLATE_FRONT) =>
  `vless://${UUID}@${address}:443?encryption=${encryption}&security=tls&sni=${address}&type=ws&host=${address}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`;
const plainLink = link(PLAIN, '/ws', 'none');
const twinLink = link(TWIN, '/ws-e', ENCRYPTION);
const otherLink = link('node-b-ws', '/ws', 'none', 'elsewhere.example');

/** Each emitted link as what a member sees: its name, where it goes, and how. */
function linksOut(body: string) {
  return body
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      const u = new URL(l);
      return {
        name: decodeURIComponent(u.hash.slice(1)),
        address: u.hostname,
        host: u.searchParams.get('host'),
        sni: u.searchParams.get('sni'),
        path: u.searchParams.get('path'),
        encryption: u.searchParams.get('encryption'),
      };
    });
}
const encryptedAt = (name: string, address: string) => ({
  name,
  address,
  host: address,
  sni: address,
  path: '/ws-e',
  encryption: ENCRYPTION,
});
const plainAt = (name: string, address: string) => ({
  name,
  address,
  host: address,
  sni: address,
  path: '/ws',
  encryption: 'none',
});

describe('a link list', () => {
  const body = [plainLink, twinLink, otherLink].join('\n');
  const render = (r: RenderRuleInput, b = body) =>
    renderLinks({ body: b, matchers: [matcher], endpoints, rule: r });

  test('by default: the encrypted entry of every front first, then the plain ones, named for who they are for', () => {
    const out = render(rule());
    expect(out.applied).toBe(true);
    expect(out.emitted).toBe(4);
    expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true, encrypted: true }]);
    const got = linksOut(out.body);
    expect(got.slice(0, 4)).toEqual([
      encryptedAt(A, FRONT_A),
      encryptedAt(B, FRONT_B),
      plainAt(plainFallbackName(A), FRONT_A),
      plainAt(plainFallbackName(B), FRONT_B),
    ]);
    expect(plainFallbackName(A)).toBe('🌐 via CDN 1 · Old apps');
    // Neither template leaves as it came, and what is not a template passes.
    expect(out.body).not.toContain(TEMPLATE_FRONT);
    expect(got[4]).toMatchObject({ name: 'node-b-ws', address: 'elsewhere.example' });
    expect(got).toHaveLength(5);
  });

  test('`only`: the encrypted entries alone', () => {
    const got = linksOut(render(rule('only')).body);
    expect(got.slice(0, 2)).toEqual([encryptedAt(A, FRONT_A), encryptedAt(B, FRONT_B)]);
    expect(got).toHaveLength(3);
    expect(got.some((g) => g.encryption === 'none' && g.address !== 'elsewhere.example')).toBe(
      false,
    );
  });

  test('`plain`: the plain entries alone, under their ordinary names', () => {
    const out = render(rule('plain'));
    const got = linksOut(out.body);
    expect(got.slice(0, 2)).toEqual([plainAt(A, FRONT_A), plainAt(B, FRONT_B)]);
    expect(got).toHaveLength(3);
    // The twin's template is dropped all the same.
    expect(out.body).not.toContain('mlkem768x25519plus');
  });

  test('a body without the twin (a node that has none yet) is rendered as it always was', () => {
    for (const r of [rule(), rule('only'), rule('plain')]) {
      const out = render(r, [plainLink, otherLink].join('\n'));
      expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true }]);
      expect(linksOut(out.body).slice(0, 2)).toEqual([plainAt(A, FRONT_A), plainAt(B, FRONT_B)]);
    }
  });

  test('a body with the twin alone (the plain Host kept out of this format) still resolves, encrypted', () => {
    const b = [twinLink, otherLink].join('\n');
    for (const r of [rule(), rule('only')]) {
      const out = render(r, b);
      expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true, encrypted: true }]);
      expect(linksOut(out.body).slice(0, 2)).toEqual([
        encryptedAt(A, FRONT_A),
        encryptedAt(B, FRONT_B),
      ]);
    }
    // A family that must not get the encrypted entry gets nothing to use, and
    // the template still does not leave.
    const none = render(rule('plain'), b);
    expect(none.emitted).toBe(0);
    expect(none.body).not.toContain(TEMPLATE_FRONT);
  });

  test('an entry under the twin name that is NOT encrypted is never handed out as the twin', () => {
    const fake = link(TWIN, '/ws-e', 'none');
    const out = render(rule(), [plainLink, fake].join('\n'));
    expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true }]);
    const got = linksOut(out.body);
    expect(got).toEqual([plainAt(A, FRONT_A), plainAt(B, FRONT_B)]);
    expect(out.body).not.toContain('ws-e');
  });

  test('a cap counts connections: a fallback rides with its entry, so no app is left without one', () => {
    const out = render({ ...rule(), maxEntries: 1 });
    expect(linksOut(out.body).slice(0, 2)).toEqual([
      encryptedAt(A, FRONT_A),
      plainAt(plainFallbackName(A), FRONT_A),
    ]);
    expect(out.emitted).toBe(2);
  });

  test('a renamed node: the twin is still found under the name it had', () => {
    const renamed: RenderMatcher = {
      ...matcher,
      rule: { kind: 'remark', remark: 'node-z-relay-a1' },
      legacyRemarks: [PLAIN],
      encrypted: { remarks: ['node-z-relay-e9', TWIN] },
    };
    const out = renderLinks({ body, matchers: [renamed], endpoints, rule: rule('only') });
    expect(linksOut(out.body).slice(0, 2)).toEqual([
      encryptedAt(A, FRONT_A),
      encryptedAt(B, FRONT_B),
    ]);
  });
});

// --- Clash --------------------------------------------------------------------

const clashProxy = (name: string, path: string, encryption?: string) => ({
  name,
  type: 'vless',
  server: TEMPLATE_FRONT,
  port: 443,
  uuid: UUID,
  tls: true,
  servername: TEMPLATE_FRONT,
  network: 'ws',
  'ws-opts': { path, headers: { Host: TEMPLATE_FRONT } },
  ...(encryption ? { encryption } : {}),
});
const clashBody = (proxies: unknown[]) =>
  YAML.stringify({
    proxies,
    'proxy-groups': [
      { name: 'Proxy', type: 'select', proxies: proxies.map((p) => (p as { name: string }).name) },
    ],
    rules: ['MATCH,Proxy'],
  });

describe('a Clash body', () => {
  const body = clashBody([clashProxy(PLAIN, '/ws'), clashProxy(TWIN, '/ws-e', ENCRYPTION)]);
  const render = (r: RenderRuleInput, b = body) => {
    const out = renderClash({ body: b, matchers: [matcher], endpoints, rule: r });
    const doc = YAML.parse(out.body) as {
      proxies: Array<Record<string, any>>;
      'proxy-groups': Array<Record<string, any>>;
    };
    return { out, doc, auto: doc['proxy-groups'].find((g) => g.name === AUTO_GROUP_NAME) };
  };
  const order = [A, B, plainFallbackName(A), plainFallbackName(B)];

  test('by default: both entries per front, and the auto group takes the first that works, in order', () => {
    const { out, doc, auto } = render(rule(undefined, true));
    expect(out.emitted).toBe(4);
    expect(doc.proxies.map((p) => p.name)).toEqual(order);
    expect(doc.proxies.map((p) => p.encryption)).toEqual([
      ENCRYPTION,
      ENCRYPTION,
      undefined,
      undefined,
    ]);
    expect(doc.proxies.map((p) => p['ws-opts'].path)).toEqual(['/ws-e', '/ws-e', '/ws', '/ws']);
    expect(doc.proxies.map((p) => p.server)).toEqual([FRONT_A, FRONT_B, FRONT_A, FRONT_B]);
    expect(doc.proxies.every((p) => p['ws-opts'].headers.Host === p.server)).toBe(true);
    // Equally fast entries: "the fastest" would be either of a pair.
    expect(auto).toMatchObject({ type: 'fallback', proxies: order });
    expect(auto).not.toHaveProperty('tolerance');
    // The member's own group lists the auto group, then every entry.
    expect(doc['proxy-groups'].find((g) => g.name === 'Proxy')!.proxies).toEqual([
      AUTO_GROUP_NAME,
      ...order,
    ]);
    expect(out.body).not.toContain(TEMPLATE_FRONT);
    expect(out.body).not.toContain(TWIN);
  });

  test('`only` and `plain`: one kind of entry, so the group picks the fastest as before', () => {
    const only = render(rule('only', true));
    expect(only.doc.proxies.map((p) => p.name)).toEqual([A, B]);
    expect(only.doc.proxies.every((p) => p.encryption === ENCRYPTION)).toBe(true);
    expect(only.auto).toMatchObject({ type: 'url-test', tolerance: 50, proxies: [A, B] });

    const plain = render(rule('plain', true));
    expect(plain.doc.proxies.map((p) => p.name)).toEqual([A, B]);
    expect(plain.doc.proxies.some((p) => 'encryption' in p)).toBe(false);
    expect(plain.auto).toMatchObject({ type: 'url-test', proxies: [A, B] });
    expect(plain.out.body).not.toContain('mlkem768x25519plus');
  });

  test('a body without the twin keeps the fastest-entry group', () => {
    const { doc, auto } = render(rule(undefined, true), clashBody([clashProxy(PLAIN, '/ws')]));
    expect(doc.proxies.map((p) => p.name)).toEqual([A, B]);
    expect(auto).toMatchObject({ type: 'url-test', tolerance: 50 });
  });

  test('a group the body already calls the auto group becomes the ordered one too', () => {
    const withAuto = YAML.stringify({
      proxies: [clashProxy(PLAIN, '/ws'), clashProxy(TWIN, '/ws-e', ENCRYPTION)],
      'proxy-groups': [
        {
          name: AUTO_GROUP_NAME,
          type: 'url-test',
          proxies: [PLAIN, TWIN],
          url: 'https://www.gstatic.com/generate_204',
          interval: 300,
          tolerance: 50,
        },
      ],
    });
    const { auto } = render(rule(undefined, true), withAuto);
    expect(auto).toMatchObject({ type: 'fallback', proxies: order });
    expect(auto).not.toHaveProperty('tolerance');
  });
});

// --- sing-box -----------------------------------------------------------------

describe('a sing-box body', () => {
  const outbound = (tag: string, path: string) => ({
    type: 'vless',
    tag,
    server: TEMPLATE_FRONT,
    server_port: 443,
    uuid: UUID,
    tls: { enabled: true, server_name: TEMPLATE_FRONT },
    transport: { type: 'ws', path, headers: { Host: TEMPLATE_FRONT } },
  });
  const body = (outbounds: unknown[]) =>
    JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: outbounds.map((o) => (o as any).tag) },
        ...outbounds,
        { type: 'direct', tag: 'direct' },
      ],
    });

  test('gets the plain entries, as the backend leaves the twin out of this format', () => {
    const out = renderSingbox({
      body: body([outbound(PLAIN, '/ws')]),
      matchers: [matcher],
      endpoints,
      rule: rule(),
    });
    const tags = (JSON.parse(out.body).outbounds as any[])
      .filter((o) => o.type === 'vless')
      .map((o) => o.tag);
    expect(tags).toEqual([A, B]);
  });

  test('an outbound under the twin name would be the encrypted transport spoken plainly: dropped, never copied', () => {
    const out = renderSingbox({
      body: body([outbound(PLAIN, '/ws'), outbound(TWIN, '/ws-e')]),
      matchers: [matcher],
      endpoints,
      rule: rule(),
    });
    const cfg = JSON.parse(out.body) as { outbounds: any[] };
    const vless = cfg.outbounds.filter((o) => o.type === 'vless');
    expect(vless.map((o) => o.tag)).toEqual([A, B]);
    expect(vless.every((o) => o.transport.path === '/ws')).toBe(true);
    expect(out.body).not.toContain('ws-e');
    expect(out.body).not.toContain(TWIN);
  });
});

// --- matching -----------------------------------------------------------------

describe('resolveMatchers', () => {
  const entry = (
    identity: string,
    over: Partial<MatchableEntry<string>> = {},
  ): MatchableEntry<string> => ({
    entry: identity,
    identity,
    address: TEMPLATE_FRONT,
    port: 443,
    supported: () => true,
    agrees: () => true,
    ...over,
  });
  const same = (a: string, b: string) => a === b;

  test('a twin sits at its listener own address and is never read as the plain entry', () => {
    // An address rule would otherwise see two entries at the origin and give up.
    const byAddress: RenderMatcher = {
      ...matcher,
      rule: { kind: 'address' },
      originAddress: TEMPLATE_FRONT,
    };
    const r = resolveMatchers(
      [entry('anything'), entry(TWIN, { encrypted: true })],
      [byAddress],
      same,
    );
    expect(r.matches).toEqual([{ listenerKey: 'a1', matched: true, encrypted: true }]);
    expect(r.templates.get('a1')).toBe('anything');
    expect(r.encrypted.get('a1')).toBe(TWIN);
  });

  test('a listener whose plain entry speaks something else is not rescued by its twin', () => {
    const r = resolveMatchers(
      [entry(PLAIN, { agrees: () => false }), entry(TWIN, { encrypted: true })],
      [matcher],
      same,
    );
    expect(r.matches).toEqual([{ listenerKey: 'a1', matched: false, reason: 'entry_mismatch' }]);
    expect(r.encrypted.size).toBe(0);
    // It is still a template to drop.
    expect(r.twinEntries.has(TWIN)).toBe(true);
  });

  test('a twin that speaks another transport than its listener is not used', () => {
    const r = resolveMatchers(
      [entry(PLAIN), entry(TWIN, { encrypted: true, agrees: () => false })],
      [matcher],
      same,
    );
    expect(r.matches).toEqual([{ listenerKey: 'a1', matched: true }]);
    expect(r.encrypted.size).toBe(0);
  });
});

// --- the listener and the rule ------------------------------------------------

describe('twinRemarksOf', () => {
  const listener = {
    listenerKey: 'a1',
    matchRule: { kind: 'remark' as const, remark: PLAIN },
    encryptedTwin: {
      key: 'e9',
      panelBinding: { inboundTag: 'WS_E', configProfileUuid: 'p', configProfileInboundUuid: 'i' },
    },
  };
  test("is the listener's own remark with the twin's key, and follows its renames", () => {
    expect(twinRemarksOf(listener)).toEqual([TWIN]);
    expect(
      twinRemarksOf({
        ...listener,
        matchRule: { kind: 'remark', remark: 'node-z-relay-a1' },
        formerRemarks: [PLAIN, 'an-operator-name'],
      }),
    ).toEqual(['node-z-relay-e9', TWIN]);
  });
  test('nothing without a twin, or for a listener not found by such a remark', () => {
    expect(twinRemarksOf({ ...listener, encryptedTwin: undefined })).toEqual([]);
    expect(twinRemarksOf({ ...listener, matchRule: { kind: 'address' } })).toEqual([]);
    expect(
      twinRemarksOf({ ...listener, matchRule: { kind: 'remark', remark: 'my-own-host' } }),
    ).toEqual([]);
  });
});

describe('the rule per client family', () => {
  test('apps nobody has seen work with an encrypted entry are not handed one', () => {
    const got = Object.fromEntries(
      RENDER_CLIENT_FAMILIES.map((f) => [f, defaultClientRule(f).encryption]),
    );
    expect(got).toEqual({
      singbox: 'plain',
      hiddify: 'plain',
      other: 'plain',
      mihomo: 'prefer',
      'xray-links': 'prefer',
      happ: 'prefer',
      streisand: 'prefer',
      v2rayng: 'prefer',
    });
  });

  test('a rule stored before the setting existed takes its family default; a stored one holds', () => {
    const { encryption: _gone, ...stored } = defaultClientRule('mihomo');
    void _gone;
    expect(sanitizeClientRule(stored, 'mihomo').encryption).toBe('prefer');
    expect(sanitizeClientRule(stored, 'other').encryption).toBe('plain');
    expect(sanitizeClientRule({ ...stored, encryption: 'only' }, 'mihomo').encryption).toBe('only');
    expect(sanitizeClientRule({ ...stored, encryption: 'loud' }, 'mihomo').encryption).toBe(
      'prefer',
    );
  });

  test('reaches the renderer, and a single key is never given a fallback beside it', () => {
    const r = effectiveRule(EDGE_DEFAULTS.render, defaultClientRule('mihomo'));
    expect(r.encryption).toBe('prefer');
    expect(ruleForDelivery(r, 'single-key').encryption).toBe('plain');
    expect(ruleForDelivery({ ...r, encryption: 'only' }, 'single-key').encryption).toBe('only');
  });
});
