/**
 * The pure origin renderer under the edge-required delivery policy: each
 * listener's template entry is found by its match rule and verified against
 * what the listener speaks, the subscriber's assigned edges replace it, and
 * the result is judged (`delivery`): an empty pool, a missing / ambiguous /
 * disagreeing template or ANY outgoing entry at the origin address is
 * `unavailable`, never a body a member may receive.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { EDGE_DEFAULTS, defaultClientRule } from '../edgeConfig';
import type { AssignedEndpoint, PublishedEdge } from './assignment';
import {
  effectiveRule,
  matchListeners,
  renderEntries,
  renderEntriesChecked,
  renderEdgeEndpoints,
} from './render';
import { applyEdgeRender } from './renderPipeline';
import { decodeBase64Loose, encodeBase64 } from './render/base64';
import type { RenderMatcher } from './render/types';
import { parseProxyUri, rewriteProxyUri } from './render/uri';
import type { ListenerProto } from './protocols';

const NODE = 'node-a';
const TEMPLATE = `${NODE}-relay-a1`;
const OTHER_NODE_WS = 'node-b-ws';
const ORIGIN = '192.0.2.10';
const UUID = '11111111-2222-3333-4444-555555555555';
const REALITY_QS =
  'security=reality&encryption=none&pbk=PUBKEY_BASE64&fp=chrome&sni=old.example&sid=abcd1234&type=tcp&flow=xtls-rprx-vision';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const HY2: ListenerProto = { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' };
const TUIC: ListenerProto = { protocol: 'tuic', streamTransport: 'udp', security: 'tls' };

const templateLink = `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${encodeURIComponent(TEMPLATE)}`;
// Another node's entry, NOT at the origin: passes through untouched.
const otherLink = `vless://${UUID}@edge.example:443?encryption=none&type=ws&path=%2Fws&host=edge.example&security=tls&sni=edge.example#${OTHER_NODE_WS}`;

function matcher(over: Partial<RenderMatcher> = {}): RenderMatcher {
  return {
    listenerKey: 'a1',
    rule: { kind: 'remark', remark: TEMPLATE },
    proto: REALITY,
    originAddress: ORIGIN,
    originPort: 443,
    ...over,
  };
}
const matchers = [matcher()];

const edgeA: PublishedEdge = {
  edgeId: 'eA',
  poolIndex: 0,
  provider: 'gcore',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: TEMPLATE },
  proto: REALITY,
  edgePort: 443,
  addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
  serverNames: [{ sni: 'cdn-a.example', status: 'active' }],
};
const edgeB: PublishedEdge = {
  ...edgeA,
  edgeId: 'eB',
  poolIndex: 1,
  provider: 'scaleway',
  addresses: { v4: '203.0.113.20' },
};

const assigned: { primary: AssignedEndpoint; backup: AssignedEndpoint } = {
  primary: { role: 'primary', edge: edgeA, sni: 'cdn-a.example', hostHeader: null },
  backup: { role: 'backup', edge: edgeB, sni: 'cdn-b.example', hostHeader: null },
};
const EMPTY = { primary: null, backup: null };

// A member on an `hrw1` listener holds further server names per endpoint.
const withNames: { primary: AssignedEndpoint; backup: AssignedEndpoint } = {
  primary: {
    ...assigned.primary,
    alternates: [
      { sni: 'cdn-c.example', hostHeader: null },
      { sni: 'cdn-d.example', hostHeader: null },
    ],
  },
  backup: assigned.backup,
};

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const linksRule = effectiveRule(cfg, defaultClientRule('v2rayng'));
const autoRule = effectiveRule(cfg, defaultClientRule('singbox'));
const mihomoRule = effectiveRule(cfg, defaultClientRule('mihomo'));

const render = (body: string, over: Partial<Parameters<typeof renderEdgeEndpoints>[0]> = {}) =>
  renderEdgeEndpoints({
    body,
    matchers,
    assigned,
    rule: linksRule,
    originAddress: ORIGIN,
    ...over,
  });

const qsOf = (line: string) =>
  new URLSearchParams(
    line.slice(line.indexOf('?') + 1, line.indexOf('#') < 0 ? undefined : line.indexOf('#')),
  );

describe('rewriteProxyUri', () => {
  test('replaces host/port/sni/remark, brackets v6, keeps REALITY params intact', () => {
    const out = rewriteProxyUri(parseProxyUri(templateLink)!, {
      address: '2001:db8::10',
      port: 443,
      sni: 'cdn-a.example',
      label: 'FreeSocks Primary (IPv6)',
    });
    expect(out.startsWith(`vless://${UUID}@[2001:db8::10]:443?`)).toBe(true);
    const qs = qsOf(out);
    expect(qs.get('sni')).toBe('cdn-a.example');
    expect(qs.get('pbk')).toBe('PUBKEY_BASE64');
    expect(qs.get('sid')).toBe('abcd1234');
    expect(qs.get('flow')).toBe('xtls-rprx-vision');
    expect(qs.get('security')).toBe('reality');
    expect(decodeURIComponent(out.slice(out.indexOf('#') + 1))).toBe('FreeSocks Primary (IPv6)');
    // Trojan lines are rewritable too; a vmess blob has no host:port and never parses.
    expect(
      rewriteProxyUri(parseProxyUri('trojan://x@y:1?security=tls&sni=node.example#z')!, {
        address: 'a',
        port: 1,
        sni: null,
        label: 'l',
      }),
    ).toBe('trojan://x@a:1?security=tls&sni=node.example#l');
    expect(parseProxyUri('vmess://eyJhZGQiOiJ4In0=')).toBeNull();
  });

  test('a null sni (no-name listener) swaps address/port only and leaves the TLS name alone', () => {
    const tls = `vless://${UUID}@${ORIGIN}:443?encryption=none&security=tls&sni=node.example&type=tcp#${encodeURIComponent(TEMPLATE)}`;
    const out = rewriteProxyUri(parseProxyUri(tls)!, {
      address: '203.0.113.10',
      port: 443,
      sni: null,
      label: 'P',
    });
    const qs = qsOf(out);
    expect(out).toContain('@203.0.113.10:443?');
    expect(qs.get('sni')).toBe('node.example');
    expect(qs.get('security')).toBe('tls');
  });

  test('an ss:// link WITH a path (Outline) is rewritten host:port only, userinfo and path untouched', () => {
    const ss = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@${ORIGIN}:8388/?outline=1#${encodeURIComponent(TEMPLATE)}`;
    const out = rewriteProxyUri(parseProxyUri(ss)!, {
      address: '203.0.113.10',
      port: 9000,
      sni: null,
      label: 'Key',
    });
    expect(out).toBe(
      'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@203.0.113.10:9000/?outline=1#Key',
    );
  });

  test('hysteria2 / tuic links get the selected name in `sni`, credentials untouched', () => {
    const hy2 = rewriteProxyUri(parseProxyUri(`hy2://pw@${ORIGIN}:443?sni=node.example#r`)!, {
      address: '203.0.113.10',
      port: 443,
      sni: 'cdn-a.example',
      label: 'P',
    });
    expect(hy2).toBe('hy2://pw@203.0.113.10:443?sni=cdn-a.example#P');
    const tuic = rewriteProxyUri(
      parseProxyUri(`tuic://${UUID}:pw@${ORIGIN}:443?sni=node.example&congestion_control=bbr#r`)!,
      { address: '203.0.113.10', port: 443, sni: 'cdn-a.example', label: 'P' },
    );
    expect(tuic.startsWith(`tuic://${UUID}:pw@203.0.113.10:443?`)).toBe(true);
    expect(qsOf(tuic).get('sni')).toBe('cdn-a.example');
    expect(qsOf(tuic).get('congestion_control')).toBe('bbr');
  });
});

describe('renderEntries', () => {
  test('emits v4 + v6 per endpoint in both mode, only v4 when off, primary first', () => {
    const both = renderEntries(assigned, linksRule, false);
    expect(both.map((e) => [e.role, e.family, e.label, e.listenerKey])).toEqual([
      ['primary', 'v4', 'FreeSocks Primary', 'a1'],
      ['primary', 'v6', 'FreeSocks Primary (IPv6)', 'a1'],
      ['backup', 'v4', 'FreeSocks Backup', 'a1'],
    ]);
    const off = renderEntries(assigned, { ...linksRule, ipv6Mode: 'off' }, false);
    expect(off.every((e) => e.family === 'v4')).toBe(true);
    const autoOnly = renderEntries(assigned, { ...linksRule, ipv6Mode: 'auto-group-only' }, false);
    expect(autoOnly.every((e) => e.family === 'v4')).toBe(true);
    expect(
      renderEntries(assigned, { ...linksRule, ipv6Mode: 'auto-group-only' }, true).some(
        (e) => e.family === 'v6',
      ),
    ).toBe(true);
  });

  test('an endpoint at the origin address is never emitted (leak guard)', () => {
    const leaky: PublishedEdge = { ...edgeA, addresses: { v4: ORIGIN } };
    const entries = renderEntries(
      {
        primary: { role: 'primary', edge: leaky, sni: 'x.example', hostHeader: null },
        backup: null,
      },
      linksRule,
      false,
      ORIGIN,
    );
    expect(entries).toEqual([]);
  });
});

describe('link-list rendering', () => {
  test('plain list: template replaced by labelled primary/backup entries, other lines untouched, one SNI each', () => {
    const out = render([otherLink, templateLink].join('\n'));
    expect(out.applied).toBe(true);
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.leaked).toBe(0);
    expect(out.originEntries).toBe(0);
    expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true }]);
    const lines = out.body.split('\n');
    expect(lines[0]).toBe(otherLink);
    expect(lines).toHaveLength(4);
    expect(lines.some((l) => l.includes(`#${encodeURIComponent(TEMPLATE)}`))).toBe(false);
    const primary = lines[1];
    expect(primary).toContain('@203.0.113.10:443?');
    expect(primary).toContain('sni=cdn-a.example');
    expect(primary.endsWith(`#${encodeURIComponent('FreeSocks Primary')}`)).toBe(true);
    expect(lines[2]).toContain('@[2001:db8::10]:443?');
    expect(lines[3]).toContain('@203.0.113.20:443?');
    expect(lines[3]).toContain('sni=cdn-b.example');
    // Credentials preserved byte-for-byte; the origin never appears.
    expect(primary).toContain(`${UUID}@`);
    expect(primary).toContain('pbk=PUBKEY_BASE64');
    expect(out.body).not.toContain(ORIGIN);
  });

  test('a no-name listener (shadowsocks) renders address/port only and keeps userinfo + path in every format', () => {
    const ssTemplate = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@${ORIGIN}:8388/?outline=1#${encodeURIComponent(TEMPLATE)}`;
    const ssEdge: PublishedEdge = { ...edgeA, proto: SS, serverNames: [] };
    const ssAssigned = {
      primary: { role: 'primary' as const, edge: ssEdge, sni: null, hostHeader: null },
      backup: null,
    };
    const ssMatchers = [matcher({ proto: SS, originPort: 8388 })];
    const links = render(ssTemplate, { matchers: ssMatchers, assigned: ssAssigned });
    expect(links.delivery).toEqual({ kind: 'serve' });
    const lines = links.body.split('\n');
    expect(lines).toHaveLength(2); // v4 + v6 of the one edge
    expect(lines[0]).toBe(
      'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@203.0.113.10:443/?outline=1#FreeSocks%20Primary',
    );
    expect(lines[1]).toContain('@[2001:db8::10]:443/?outline=1#');
    const sb = render(
      JSON.stringify({
        outbounds: [
          {
            type: 'shadowsocks',
            tag: TEMPLATE,
            server: ORIGIN,
            server_port: 8388,
            method: 'chacha20-ietf-poly1305',
            password: 'example-password',
          },
          { type: 'selector', tag: 'proxy', outbounds: [TEMPLATE] },
        ],
      }),
      { matchers: ssMatchers, assigned: ssAssigned, rule: autoRule },
    );
    expect(sb.delivery).toEqual({ kind: 'serve' });
    const doc = JSON.parse(sb.body) as { outbounds: Array<Record<string, unknown>> };
    const emitted = doc.outbounds.find((o) => o.server === '203.0.113.10')!;
    expect(emitted).toMatchObject({ type: 'shadowsocks', password: 'example-password' });
    expect(emitted.tls).toBeUndefined();
  });

  test('hysteria2 / tuic templates get the selected name in `sni`', () => {
    for (const [proto, line] of [
      [HY2, `hysteria2://pw@${ORIGIN}:443?sni=node.example#${encodeURIComponent(TEMPLATE)}`],
      [
        TUIC,
        `tuic://${UUID}:pw@${ORIGIN}:443?sni=node.example&congestion_control=bbr#${encodeURIComponent(TEMPLATE)}`,
      ],
    ] as const) {
      const edge: PublishedEdge = { ...edgeA, proto, addresses: { v4: '203.0.113.10' } };
      const out = render(line, {
        matchers: [matcher({ proto })],
        assigned: {
          primary: { role: 'primary', edge, sni: 'cdn-a.example', hostHeader: null },
          backup: null,
        },
      });
      expect(out.delivery).toEqual({ kind: 'serve' });
      const emitted = out.body.split('\n')[0];
      expect(emitted).toContain('@203.0.113.10:443?');
      expect(qsOf(emitted).get('sni')).toBe('cdn-a.example');
    }
  });

  test('base64-wrapped list stays base64 and renders identically for the same input', () => {
    const body = btoa([templateLink, otherLink].join('\n'));
    const out1 = render(body);
    const out2 = render(body);
    expect(out1.applied).toBe(true);
    expect(out1.body).toBe(out2.body);
    const decoded = atob(out1.body);
    expect(decoded.split('\n')).toHaveLength(4);
    expect(decoded).toContain(OTHER_NODE_WS);
  });

  test('a base64 list with a non-ASCII remark round-trips (bytes, not latin1)', () => {
    const cyrillic = `vless://${UUID}@198.51.100.9:443?encryption=none&type=tcp#${encodeURIComponent('Прямое подключение')}`;
    const body = encodeBase64([templateLink, cyrillic].join('\n'));
    const out = render(body);
    expect(out.applied).toBe(true);
    const decoded = decodeBase64Loose(out.body)!;
    expect(decoded.split('\n')).toHaveLength(4);
    expect(decoded).toContain(encodeURIComponent('Прямое подключение'));
    expect(decoded).toContain('FreeSocks%20Primary');
  });

  test('no template line: nothing applied, the body is refused as no_match (never served as-is)', () => {
    const out = render(otherLink);
    expect(out).toMatchObject({ applied: false, body: otherLink, emitted: 0 });
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'no_match' });
    expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: false, reason: 'no_match' }]);
  });

  test('empty pool: unavailable:empty_pool whatever the family flags say, and never an empty body', () => {
    const body = [otherLink, templateLink].join('\n');
    for (const rule of [
      linksRule,
      { ...linksRule, dropTemplateEntries: false },
      { ...linksRule, enabled: false },
      { ...linksRule, enabled: false, dropTemplateEntries: false },
    ]) {
      const out = render(body, { assigned: EMPTY, rule });
      expect(out).toMatchObject({ applied: false, emitted: 0 });
      expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'empty_pool' });
      expect(out.body.length).toBeGreaterThan(0);
    }
  });

  test('a template with a scheme the renderer cannot rewrite (vmess blob) is entry_unsupported → refused', () => {
    const vmessTemplate = `vmess://eyJhZGQiOiIxOTIuMC4yLjEwIn0=#${encodeURIComponent(TEMPLATE)}`;
    const body = [otherLink, vmessTemplate].join('\n');
    expect(matchListeners(body, matchers).matches).toEqual([
      { listenerKey: 'a1', matched: false, reason: 'entry_unsupported' },
    ]);
    const out = render(body);
    expect(out.applied).toBe(false);
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
  });

  test('a template whose security / type disagree with the listener is entry_mismatch', () => {
    // A plain-TLS link where the listener claims REALITY: the wrong transport matched.
    const tlsLink = `vless://${UUID}@${ORIGIN}:443?encryption=none&security=tls&sni=node.example&type=tcp#${encodeURIComponent(TEMPLATE)}`;
    const out = render(tlsLink);
    expect(out.applied).toBe(false);
    expect(out.listeners).toEqual([
      { listenerKey: 'a1', matched: false, reason: 'entry_mismatch' },
    ]);
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
    // The stream transport must agree too (a ws link for a raw listener).
    const wsLink = `vless://${UUID}@${ORIGIN}:443?encryption=none&security=reality&pbk=P&sid=s&type=ws&path=%2Fws#${encodeURIComponent(TEMPLATE)}`;
    expect(matchListeners(wsLink, matchers).matches?.[0]).toMatchObject({
      reason: 'entry_mismatch',
    });
  });

  test('match by `address` rule: the entry at the origin address:port is the template, whatever its remark', () => {
    const unremarked = `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${encodeURIComponent('whatever')}`;
    const byAddress = [matcher({ rule: { kind: 'address' } })];
    const out = render([otherLink, unremarked].join('\n'), { matchers: byAddress });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.listeners).toEqual([{ listenerKey: 'a1', matched: true }]);
    expect(out.body).not.toContain('whatever');
    expect(out.body).toContain('FreeSocks%20Primary');
    // A different port at the same address is not this listener.
    const otherPort = `vless://${UUID}@${ORIGIN}:8443?${REALITY_QS}#x`;
    expect(matchListeners(otherPort, byAddress).matches).toEqual([
      { listenerKey: 'a1', matched: false, reason: 'no_match' },
    ]);
  });

  test('match by `whole-body` rule: a single-entry body is the template; two entries are ambiguous', () => {
    const wholeBody = [matcher({ rule: { kind: 'whole-body' } })];
    const single = `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${encodeURIComponent('Direct')}`;
    const out = render(single, { matchers: wholeBody });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.body.split('\n')).toHaveLength(3);
    expect(out.body).not.toContain('Direct');
    const two = render([single, otherLink].join('\n'), { matchers: wholeBody });
    expect(two.delivery).toEqual({ kind: 'unavailable', reason: 'ambiguous_match' });
    expect(two.listeners).toEqual([
      { listenerKey: 'a1', matched: false, reason: 'ambiguous_match' },
    ]);
  });

  test('leak_detected: an assigned edge at the origin is dropped, a retained origin entry refuses the body', () => {
    // Every assigned edge points at the origin: nothing emittable → leak_detected.
    const leaky: PublishedEdge = { ...edgeA, addresses: { v4: ORIGIN } };
    const out = render(templateLink, {
      assigned: {
        primary: { role: 'primary', edge: leaky, sni: 'cdn-a.example', hostHeader: null },
        backup: null,
      },
    });
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
    // A direct entry at the origin survives the rewrite in the body → refused.
    const direct = `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${encodeURIComponent(`${NODE}-reality`)}`;
    const retained = render([templateLink, direct].join('\n'));
    expect(retained.applied).toBe(true);
    expect(retained.originEntries).toBe(1);
    expect(retained.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
    // Keeping the template line (drop off) keeps the origin in the body → refused too.
    const kept = render(templateLink, { rule: { ...linksRule, dropTemplateEntries: false } });
    expect(kept.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
  });

  test('single-key delivery: exactly one entry, no backup, and no auto group in a sing-box body', () => {
    const ssTemplate = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@${ORIGIN}:8388/?outline=1#Key`;
    const ssEdge: PublishedEdge = { ...edgeA, proto: SS, serverNames: [] };
    const ssB: PublishedEdge = { ...edgeB, proto: SS, serverNames: [] };
    const ssAssigned = {
      primary: { role: 'primary' as const, edge: ssEdge, sni: null, hostHeader: null },
      backup: { role: 'backup' as const, edge: ssB, sni: null, hostHeader: null },
    };
    const ssMatchers = [matcher({ proto: SS, originPort: 8388, rule: { kind: 'whole-body' } })];
    const out = render(ssTemplate, {
      matchers: ssMatchers,
      assigned: ssAssigned,
      deliveryStyle: 'single-key',
    });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.emitted).toBe(1);
    expect(out.body.split('\n')).toHaveLength(1);
    expect(out.body).toContain('@203.0.113.10:443/?outline=1#');
    expect(out.body).not.toContain('Backup');
    const sb = render(
      JSON.stringify({
        outbounds: [
          {
            type: 'shadowsocks',
            tag: 'Key',
            server: ORIGIN,
            server_port: 8388,
            method: 'm',
            password: 'p',
          },
          { type: 'selector', tag: 'proxy', outbounds: ['Key'] },
        ],
      }),
      { matchers: ssMatchers, assigned: ssAssigned, rule: autoRule, deliveryStyle: 'single-key' },
    );
    expect(sb.delivery).toEqual({ kind: 'serve' });
    expect(sb.emitted).toBe(1);
    const tags = (JSON.parse(sb.body) as { outbounds: Array<{ tag: string }> }).outbounds.map(
      (o) => o.tag,
    );
    expect(tags).not.toContain('FreeSocks Auto');
    expect(tags.filter((t) => t.startsWith('FreeSocks'))).toEqual(['FreeSocks Primary']);
  });

  test('an unsupported body shape is unavailable:unsupported_format', () => {
    const out = render('<html>landing</html>');
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'unsupported_format' });
    expect(out.applied).toBe(false);
  });

  test('URL-safe, unpadded base64 bodies render and come back standard base64', () => {
    const plain = [templateLink, otherLink].join('\n');
    const urlSafe = btoa(plain).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const out = render(urlSafe);
    expect(out.applied).toBe(true);
    expect(out.body).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const decoded = atob(out.body);
    expect(decoded).toContain('FreeSocks%20Primary');
    expect(decoded).not.toContain(encodeURIComponent(TEMPLATE));
  });
});

describe('further server names per endpoint', () => {
  test('renderEntries: one more IPv4 entry per name, no IPv6 sibling, numbered labels', () => {
    const entries = renderEntries(withNames, autoRule, true, ORIGIN);
    expect(entries.map((e) => [e.label, e.family, e.sni, e.variant ?? 0])).toEqual([
      ['FreeSocks Primary', 'v4', 'cdn-a.example', 0],
      ['FreeSocks Primary (IPv6)', 'v6', 'cdn-a.example', 0],
      ['FreeSocks Backup', 'v4', 'cdn-b.example', 0],
      ['FreeSocks Primary 2', 'v4', 'cdn-c.example', 1],
      ['FreeSocks Primary 3', 'v4', 'cdn-d.example', 2],
    ]);
  });

  test('link list: each name is its own line, pbk / sid / flow untouched', () => {
    const out = render(templateLink, { assigned: withNames });
    const lines = out.body.split('\n').filter((l) => l.startsWith('vless://'));
    expect(lines.map((l) => qsOf(l).get('sni'))).toEqual([
      'cdn-a.example',
      'cdn-a.example', // the IPv6 sibling of the first name
      'cdn-b.example',
      'cdn-c.example',
      'cdn-d.example',
    ]);
    for (const l of lines) {
      expect(qsOf(l).get('pbk')).toBe(new URLSearchParams(REALITY_QS).get('pbk'));
      expect(qsOf(l).get('sid')).toBe(new URLSearchParams(REALITY_QS).get('sid'));
      expect(l).not.toContain(ORIGIN);
    }
    expect(decodeURIComponent(lines[3].split('#')[1])).toBe('FreeSocks Primary 2');
  });

  test('an entry cap drops the further names before it drops a role', () => {
    // Three first-name entries exist (primary, its IPv6 sibling, backup): a cap
    // of three keeps exactly those and cuts both further names.
    const capped = { ...linksRule, maxEntries: 3 };
    const out = render(templateLink, { assigned: withNames, rule: capped });
    const lines = out.body.split('\n').filter((l) => l.startsWith('vless://'));
    expect(lines.map((l) => decodeURIComponent(l.split('#')[1]))).toEqual([
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
    ]);
  });

  test('a single-key delivery stays one entry', () => {
    const out = render(templateLink, { assigned: withNames, deliveryStyle: 'single-key' });
    expect(out.emitted).toBe(1);
  });

  test('the origin address never leaks through a further name', () => {
    const leaking = {
      primary: {
        ...withNames.primary,
        edge: { ...edgeA, addresses: { v4: ORIGIN } },
      },
      backup: null,
    };
    expect(renderEntriesChecked(leaking, linksRule, false, ORIGIN)).toEqual({
      entries: [],
      leaked: 1,
    });
  });
});

describe('applyEdgeRender: IPv6-only edges', () => {
  const v6Only: PublishedEdge = {
    ...edgeA,
    edgeId: 'e6',
    poolIndex: 0,
    addresses: { v6: '2001:db8::6' },
  };
  const dual: PublishedEdge = { ...edgeB, poolIndex: 1 };
  const ctxFor = (rule: typeof linksRule, published: PublishedEdge[]) => ({
    epoch: 1,
    matchers,
    published,
    rule,
    preferDistinctProviders: true,
    originAddress: ORIGIN,
  });

  test('ipv6Mode off: a v6-only edge is not assignable — the dual-stack neighbour renders instead', () => {
    const rule = { ...linksRule, ipv6Mode: 'off' as const };
    const out = applyEdgeRender(ctxFor(rule, [v6Only, dual]), templateLink, 'ab'.repeat(32), {
      now: Date.now(),
    });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.emitted).toBe(1);
    expect(out.body).toContain(`@${edgeB.addresses.v4}:443?`);
    expect(out.body).not.toContain('2001:db8::6');
    expect(out.snapshot).toEqual({ listenerKeys: ['a1'], primaryEdgeId: 'eB', backupEdgeId: null });
  });

  test('ipv6Mode off with ONLY a v6-only edge: nothing is assignable, so delivery is unavailable', () => {
    const rule = { ...linksRule, ipv6Mode: 'off' as const };
    const out = applyEdgeRender(
      ctxFor(rule, [v6Only]),
      [otherLink, templateLink].join('\n'),
      'ab'.repeat(32),
      { now: Date.now() },
    );
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'empty_pool' });
    expect(out.snapshot.primaryEdgeId).toBeNull();
  });

  test('ipv6Mode both: the v6-only edge renders as a single bracketed entry', () => {
    const out = applyEdgeRender(ctxFor(linksRule, [v6Only]), templateLink, 'ab'.repeat(32), {
      now: Date.now(),
    });
    expect(out.emitted).toBe(1);
    expect(out.body).toContain('@[2001:db8::6]:443?');
  });
});

describe('sing-box rendering', () => {
  const singbox = {
    log: { level: 'info' },
    outbounds: [
      {
        tag: '→ Remnawave',
        type: 'selector',
        outbounds: [TEMPLATE, OTHER_NODE_WS],
        default: TEMPLATE,
        interrupt_exist_connections: true,
      },
      {
        type: 'vless',
        tag: TEMPLATE,
        server: ORIGIN,
        server_port: 443,
        uuid: UUID,
        flow: 'xtls-rprx-vision',
        tls: {
          enabled: true,
          server_name: 'old.example',
          utls: { enabled: true, fingerprint: 'chrome' },
          reality: { enabled: true, public_key: 'PUBKEY', short_id: 'abcd1234' },
        },
      },
      {
        type: 'vless',
        tag: OTHER_NODE_WS,
        server: 'edge.example',
        server_port: 443,
        uuid: 'x',
        transport: { type: 'ws' },
      },
      { tag: 'direct', type: 'direct' },
    ],
    route: { rules: [{ outbound: 'direct', ip_is_private: true }] },
  };
  const renderSb = (doc: unknown, over: Partial<Parameters<typeof renderEdgeEndpoints>[0]> = {}) =>
    render(JSON.stringify(doc), { rule: autoRule, ...over });

  test('further server names become further outbounds, all inside the auto group', () => {
    const out = renderSb(singbox, { assigned: withNames });
    const doc = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const emitted = doc.outbounds.filter(
      (o) => o.type === 'vless' && String(o.tag).startsWith('FreeSocks'),
    );
    expect(emitted.map((o) => [o.tag, (o.tls as { server_name: string }).server_name])).toEqual([
      ['FreeSocks Primary', 'cdn-a.example'],
      ['FreeSocks Primary (IPv6)', 'cdn-a.example'],
      ['FreeSocks Backup', 'cdn-b.example'],
      ['FreeSocks Primary 2', 'cdn-c.example'],
      ['FreeSocks Primary 3', 'cdn-d.example'],
    ]);
    // Same endpoint, same keys: only the name differs.
    for (const o of emitted.slice(3)) {
      expect(o).toMatchObject({ server: '203.0.113.10', server_port: 443, uuid: UUID });
      expect((o.tls as { reality: { public_key: string } }).reality.public_key).toBe('PUBKEY');
    }
    const auto = doc.outbounds.find((o) => o.type === 'urltest') as { outbounds: string[] };
    expect(auto.outbounds).toEqual(emitted.map((o) => o.tag));
  });

  test('clones the template outbound per endpoint, adds the auto group with exactly the emitted tags, makes it the selector default', () => {
    const out = renderSb(singbox);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const cfg = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const tags = cfg.outbounds.map((o) => o.tag);
    expect(tags).not.toContain(TEMPLATE);
    expect(tags).toContain(OTHER_NODE_WS);
    expect(tags).toContain('direct');
    const emitted = cfg.outbounds.filter(
      (o) => o.type === 'vless' && String(o.tag).startsWith('FreeSocks'),
    );
    expect(emitted.map((o) => o.tag)).toEqual([
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
    ]);
    expect(emitted[0]).toMatchObject({ server: '203.0.113.10', server_port: 443, uuid: UUID });
    expect((emitted[0].tls as { server_name: string }).server_name).toBe('cdn-a.example');
    expect((emitted[0].tls as { reality: { public_key: string } }).reality.public_key).toBe(
      'PUBKEY',
    );
    expect(emitted[1]).toMatchObject({ server: '2001:db8::10' });
    const auto = cfg.outbounds.find((o) => o.tag === 'FreeSocks Auto')!;
    expect(auto).toMatchObject({ type: 'urltest' });
    expect(auto.outbounds).toEqual(emitted.map((o) => o.tag));
    const selector = cfg.outbounds.find((o) => o.type === 'selector')!;
    expect(selector.outbounds).toEqual([
      'FreeSocks Auto',
      ...emitted.map((o) => o.tag),
      OTHER_NODE_WS,
    ]);
    expect(selector.default).toBe('FreeSocks Auto');
    expect(JSON.parse(out.body).route).toEqual(singbox.route);
    expect(out.body).not.toContain(ORIGIN);
  });

  test('a template tag still referenced elsewhere (detour, route.final, rules) is rewritten to the rendered fallback, never served', () => {
    const withRefs = {
      ...singbox,
      outbounds: [...singbox.outbounds, { type: 'http', tag: 'helper', detour: TEMPLATE }],
      route: {
        final: TEMPLATE,
        rules: [
          { outbound: 'direct', ip_is_private: true },
          { outbound: TEMPLATE, domain_suffix: ['example.org'] },
        ],
      },
    };
    const out = renderSb(withRefs);
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.body).not.toContain(JSON.stringify(TEMPLATE));
    const cfg = JSON.parse(out.body) as {
      outbounds: Array<Record<string, unknown>>;
      route: { final: string; rules: Array<{ outbound: string }> };
    };
    expect(cfg.outbounds.find((o) => o.tag === 'helper')?.detour).toBe('FreeSocks Auto');
    expect(cfg.route.final).toBe('FreeSocks Auto');
    expect(cfg.route.rules.map((r) => r.outbound)).toEqual(['direct', 'FreeSocks Auto']);
  });

  test('a template outbound whose tls / transport disagree with the listener is entry_mismatch', () => {
    const plainTls = {
      ...singbox,
      outbounds: singbox.outbounds.map((o) =>
        o.tag === TEMPLATE
          ? { ...o, tls: { enabled: true, server_name: 'old.example' } } // no reality block
          : o,
      ),
    };
    const out = renderSb(plainTls);
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
    // A vmess outbound has no codec for any listener.
    const vmess = {
      ...singbox,
      outbounds: singbox.outbounds.map((o) => (o.tag === TEMPLATE ? { ...o, type: 'vmess' } : o)),
    };
    expect(matchListeners(JSON.stringify(vmess), matchers).matches?.[0]).toMatchObject({
      reason: 'entry_unsupported',
    });
  });

  test('empty pool: unavailable:empty_pool regardless of the family flags; the body is never emptied', () => {
    for (const rule of [
      autoRule,
      { ...autoRule, dropTemplateEntries: false },
      { ...autoRule, enabled: false },
    ]) {
      const out = renderSb(singbox, { assigned: EMPTY, rule });
      expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'empty_pool' });
      expect(out.applied).toBe(false);
      expect(out.body).toBe(JSON.stringify(singbox));
    }
  });

  test('label / auto-group collisions with existing tags are suffixed deterministically', () => {
    const colliding = {
      ...singbox,
      outbounds: [
        ...singbox.outbounds,
        { type: 'vless', tag: 'FreeSocks Primary', server: 'z', server_port: 1 },
        { type: 'vless', tag: 'FreeSocks Auto', server: 'z', server_port: 1 }, // NOT a group
      ],
    };
    const out = renderSb(colliding);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const cfg = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const tags = cfg.outbounds.map((o) => o.tag as string);
    expect(new Set(tags).size).toBe(tags.length);
    expect(tags).toContain('FreeSocks Primary (2)');
    expect(tags).toContain('FreeSocks Auto (2)');
    const auto = cfg.outbounds.find((o) => o.tag === 'FreeSocks Auto (2)')!;
    expect(auto.type).toBe('urltest');
    expect(auto.outbounds).toEqual([
      'FreeSocks Primary (2)',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
    ]);
    const selector = cfg.outbounds.find((o) => o.type === 'selector')!;
    expect(selector.default).toBe('FreeSocks Auto (2)');
  });

  test('autoGroup OFF: an operator group named like the auto group keeps its type and members (R7)', () => {
    const withOperatorGroup = {
      ...singbox,
      outbounds: [
        ...singbox.outbounds,
        { type: 'selector', tag: 'FreeSocks Auto', outbounds: [TEMPLATE, OTHER_NODE_WS] },
      ],
    };
    const out = renderSb(withOperatorGroup, { rule: { ...autoRule, autoGroup: false } });
    expect(out.delivery).toEqual({ kind: 'serve' });
    const cfg = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const operator = cfg.outbounds.find((o) => o.tag === 'FreeSocks Auto')!;
    expect(operator.type).toBe('selector');
    expect(operator.outbounds).toEqual([
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
      OTHER_NODE_WS,
    ]);
    // With the auto group ON the same group IS adopted.
    const on = renderSb(withOperatorGroup);
    const adopted = (
      JSON.parse(on.body) as { outbounds: Array<Record<string, unknown>> }
    ).outbounds.find((o) => o.tag === 'FreeSocks Auto')!;
    expect(adopted.type).toBe('urltest');
  });

  test('renders are byte-identical for identical input', () => {
    expect(renderSb(singbox).body).toBe(renderSb(singbox).body);
  });
});

describe('clash / mihomo rendering', () => {
  const clash = `mixed-port: 7890
mode: global
proxies: # LEAVE THIS LINE!
  - name: ${TEMPLATE}
    type: vless
    server: ${ORIGIN}
    port: 443
    uuid: ${UUID}
    udp: true
    tls: true
    servername: old.example
    network: tcp
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY
      short-id: abcd1234
  - name: ${OTHER_NODE_WS}
    type: vless
    server: edge.example
    port: 443
    uuid: x
    network: ws
proxy-groups:
  - name: '→ Remnawave'
    type: select
    proxies:
      - ${TEMPLATE}
      - ${OTHER_NODE_WS}
rules:
  - MATCH,→ Remnawave
`;
  const renderClash = (
    body: string,
    over: Partial<Parameters<typeof renderEdgeEndpoints>[0]> = {},
  ) => render(body, { rule: mihomoRule, ...over });

  test('further server names become further proxies, all inside the url-test group', () => {
    const out = renderClash(clash, { assigned: withNames });
    const doc = YAML.parse(out.body) as {
      proxies: Array<Record<string, unknown>>;
      'proxy-groups': Array<{ type: string; proxies: string[] }>;
    };
    const emitted = doc.proxies.filter((p) => String(p.name).startsWith('FreeSocks'));
    expect(emitted.map((p) => [p.name, p.servername])).toEqual([
      ['FreeSocks Primary', 'cdn-a.example'],
      ['FreeSocks Primary (IPv6)', 'cdn-a.example'],
      ['FreeSocks Backup', 'cdn-b.example'],
      ['FreeSocks Primary 2', 'cdn-c.example'],
      ['FreeSocks Primary 3', 'cdn-d.example'],
    ]);
    const auto = doc['proxy-groups'].find((g) => g.type === 'url-test')!;
    expect(auto.proxies).toEqual(emitted.map((p) => p.name));
  });

  test('clones the template proxy, adds a url-test group first and keeps the rest', () => {
    const out = renderClash(clash);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = YAML.parse(out.body) as {
      proxies: Array<Record<string, unknown>>;
      'proxy-groups': Array<Record<string, unknown>>;
      rules: string[];
    };
    expect(doc.proxies.map((p) => p.name)).toEqual([
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
      OTHER_NODE_WS,
    ]);
    expect(doc.proxies[0]).toMatchObject({
      server: '203.0.113.10',
      port: 443,
      servername: 'cdn-a.example',
      flow: 'xtls-rprx-vision',
    });
    expect((doc.proxies[0]['reality-opts'] as { 'public-key': string })['public-key']).toBe(
      'PUBKEY',
    );
    expect(doc.proxies[2]).toMatchObject({ server: '203.0.113.20', servername: 'cdn-b.example' });
    expect(doc['proxy-groups'][0]).toMatchObject({
      name: 'FreeSocks Auto',
      type: 'url-test',
      proxies: ['FreeSocks Primary', 'FreeSocks Primary (IPv6)', 'FreeSocks Backup'],
    });
    expect(doc['proxy-groups'][1].proxies).toEqual([
      'FreeSocks Auto',
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
      OTHER_NODE_WS,
    ]);
    expect(doc.rules).toEqual(['MATCH,→ Remnawave']);
    expect(out.body).not.toContain(TEMPLATE);
    expect(out.body).not.toContain(ORIGIN);
  });

  test('a body without proxies has no template: refused as no_match', () => {
    const out = renderClash('mixed-port: 7890\nproxies: []\n');
    expect(out.applied).toBe(false);
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'no_match' });
  });

  test('a rule targeting the template by name is rewritten to the auto group (token match, never a substring scan)', () => {
    const superset = `${TEMPLATE}-mirror`;
    const body = clash
      .replace(
        'rules:\n  - MATCH,→ Remnawave\n',
        `rules:\n  - DOMAIN-SUFFIX,example.org,${TEMPLATE}\n  - MATCH,→ Remnawave\n`,
      )
      .replace(
        `  - name: ${OTHER_NODE_WS}`,
        `  - name: ${superset}\n    type: vless\n    server: s.example\n    port: 443\n    uuid: y\n  - name: ${OTHER_NODE_WS}`,
      );
    const out = renderClash(body);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = YAML.parse(out.body) as { proxies: Array<{ name: string }>; rules: string[] };
    expect(doc.rules).toEqual(['DOMAIN-SUFFIX,example.org,FreeSocks Auto', 'MATCH,→ Remnawave']);
    expect(doc.proxies.map((p) => p.name)).toContain(superset);
    expect(doc.proxies.map((p) => p.name)).not.toContain(TEMPLATE);
  });

  test('empty pool: unavailable:empty_pool whatever the family flags', () => {
    const body = clash.replace('rules:\n', `rules:\n  - DOMAIN-SUFFIX,example.org,${TEMPLATE}\n`);
    for (const rule of [
      mihomoRule,
      { ...mihomoRule, dropTemplateEntries: false },
      { ...mihomoRule, enabled: false },
    ]) {
      const out = renderClash(body, { assigned: EMPTY, rule });
      expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'empty_pool' });
      expect(out.applied).toBe(false);
    }
  });

  test('a template proxy whose keys disagree with the listener is entry_mismatch', () => {
    // No reality-opts: a plain TLS proxy where the listener claims REALITY.
    const body = clash.replace(
      '    reality-opts:\n      public-key: PUBKEY\n      short-id: abcd1234\n',
      '',
    );
    const out = renderClash(body);
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
  });

  test('a tls template without servername gets one set (Mihomo would otherwise present the edge IP)', () => {
    const body = clash.replace('    servername: old.example\n', '');
    const out = renderClash(body);
    const doc = YAML.parse(out.body) as { proxies: Array<Record<string, unknown>> };
    expect(doc.proxies[0]).toMatchObject({ server: '203.0.113.10', servername: 'cdn-a.example' });
    // trojan-style proxies use `sni`.
    const TROJAN: ListenerProto = { protocol: 'trojan', streamTransport: 'raw', security: 'tls' };
    const trojan = clash
      .replace(`    type: vless\n    server: ${ORIGIN}`, `    type: trojan\n    server: ${ORIGIN}`)
      .replace('    servername: old.example\n', '')
      .replace('    reality-opts:\n      public-key: PUBKEY\n      short-id: abcd1234\n', '');
    const trojanEdge: PublishedEdge = { ...edgeA, proto: TROJAN };
    const out2 = renderClash(trojan, {
      matchers: [matcher({ proto: TROJAN })],
      assigned: {
        primary: { role: 'primary', edge: trojanEdge, sni: 'cdn-a.example', hostHeader: null },
        backup: null,
      },
    });
    expect(out2.delivery).toEqual({ kind: 'serve' });
    const doc2 = YAML.parse(out2.body) as { proxies: Array<Record<string, unknown>> };
    expect(doc2.proxies[0]).toMatchObject({ type: 'trojan', sni: 'cdn-a.example' });
    expect(doc2.proxies[0].servername).toBeUndefined();
  });

  test('autoGroup OFF: an operator group named like the auto group keeps its type and members (R7)', () => {
    const body = clash.replace(
      "  - name: '→ Remnawave'",
      `  - name: FreeSocks Auto\n    type: select\n    proxies:\n      - ${TEMPLATE}\n      - ${OTHER_NODE_WS}\n  - name: '→ Remnawave'`,
    );
    const out = renderClash(body, { rule: { ...mihomoRule, autoGroup: false } });
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = YAML.parse(out.body) as {
      'proxy-groups': Array<{ name: string; type: string; proxies: string[] }>;
    };
    const operator = doc['proxy-groups'].find((g) => g.name === 'FreeSocks Auto')!;
    expect(operator.type).toBe('select');
    expect(operator.proxies).toEqual([
      'FreeSocks Primary',
      'FreeSocks Primary (IPv6)',
      'FreeSocks Backup',
      OTHER_NODE_WS,
    ]);
    const on = renderClash(body);
    const adopted = (
      YAML.parse(on.body) as { 'proxy-groups': Array<{ name: string; type: string }> }
    )['proxy-groups'].find((g) => g.name === 'FreeSocks Auto')!;
    expect(adopted.type).toBe('url-test');
  });

  test('label / auto-group collisions with existing proxy names are suffixed', () => {
    const body = clash.replace(
      `  - name: ${OTHER_NODE_WS}`,
      `  - name: FreeSocks Primary\n    type: vless\n    server: s.example\n    port: 443\n    uuid: y\n  - name: FreeSocks Auto\n    type: vless\n    server: s.example\n    port: 443\n    uuid: y\n  - name: ${OTHER_NODE_WS}`,
    );
    const out = renderClash(body);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = YAML.parse(out.body) as {
      proxies: Array<{ name: string }>;
      'proxy-groups': Array<{ name: string; type: string; proxies: string[] }>;
    };
    const names = [...doc.proxies.map((p) => p.name), ...doc['proxy-groups'].map((g) => g.name)];
    expect(new Set(names).size).toBe(names.length);
    expect(doc['proxy-groups'][0]).toMatchObject({
      name: 'FreeSocks Auto (2)',
      type: 'url-test',
      proxies: ['FreeSocks Primary (2)', 'FreeSocks Primary (IPv6)', 'FreeSocks Backup'],
    });
  });
});
