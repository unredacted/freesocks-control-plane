import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { EDGE_DEFAULTS, defaultClientRule } from '../edgeConfig';
import type { AssignedEndpoint, PublishedEdge } from './assignment';
import { effectiveRule, renderEntries, renderEdgeEndpoints } from './render';
import { rewriteVlessLine } from './render/links';

const NODE = 'node-a';
const TEMPLATE = `${NODE}-relay-a1`;
const OTHER_NODE_WS = 'node-b-ws';
const REALITY_QS =
  'security=reality&encryption=none&pbk=PUBKEY_BASE64&fp=chrome&sni=old.example&sid=abcd1234&type=tcp&flow=xtls-rprx-vision';

const templateLink = `vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?${REALITY_QS}#${encodeURIComponent(TEMPLATE)}`;
const otherLink = `vless://11111111-2222-3333-4444-555555555555@edge.example:443?encryption=none&type=ws&path=%2Fws&host=edge.example&security=tls&sni=edge.example#${OTHER_NODE_WS}`;

const edgeA: PublishedEdge = {
  edgeId: 'eA',
  poolIndex: 0,
  provider: 'gcore',
  slotId: 's1',
  slotRemark: TEMPLATE,
  edgePort: 443,
  addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
  protocol: 'reality',
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
  primary: { role: 'primary', edge: edgeA, sni: 'cdn-a.example' },
  backup: { role: 'backup', edge: edgeB, sni: 'cdn-b.example' },
};

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const linksRule = effectiveRule(cfg, defaultClientRule('v2rayng'));
const autoRule = effectiveRule(cfg, defaultClientRule('singbox'));

describe('rewriteVlessLine', () => {
  test('replaces host/port/sni/remark, brackets v6, keeps REALITY params intact', () => {
    const out = rewriteVlessLine(templateLink, {
      address: '2001:db8::10',
      port: 443,
      sni: 'cdn-a.example',
      label: 'FreeSocks Primary (IPv6)',
    })!;
    expect(out.startsWith('vless://11111111-2222-3333-4444-555555555555@[2001:db8::10]:443?')).toBe(
      true,
    );
    const qs = new URLSearchParams(out.slice(out.indexOf('?') + 1, out.indexOf('#')));
    expect(qs.get('sni')).toBe('cdn-a.example');
    expect(qs.get('pbk')).toBe('PUBKEY_BASE64');
    expect(qs.get('sid')).toBe('abcd1234');
    expect(qs.get('flow')).toBe('xtls-rprx-vision');
    expect(qs.get('security')).toBe('reality');
    expect(decodeURIComponent(out.slice(out.indexOf('#') + 1))).toBe('FreeSocks Primary (IPv6)');
    // Trojan / Shadowsocks lines are rewritable too (passthrough slots); vmess blobs are not.
    expect(
      rewriteVlessLine('trojan://x@y:1?security=tls&sni=node.example#z', {
        address: 'a',
        port: 1,
        sni: null,
        label: 'l',
      }),
    ).toBe('trojan://x@a:1?security=tls&sni=node.example#l');
    expect(
      rewriteVlessLine('vmess://eyJhZGQiOiJ4In0=', { address: 'a', port: 1, sni: 's', label: 'l' }),
    ).toBeNull();
  });

  test('a null sni (passthrough slot) swaps address/port only and leaves the TLS name alone', () => {
    const tls = `vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?encryption=none&security=tls&sni=node.example&type=tcp#${encodeURIComponent(TEMPLATE)}`;
    const out = rewriteVlessLine(tls, {
      address: '203.0.113.10',
      port: 443,
      sni: null,
      label: 'P',
    })!;
    const qs = new URLSearchParams(out.slice(out.indexOf('?') + 1, out.indexOf('#')));
    expect(out).toContain('@203.0.113.10:443?');
    expect(qs.get('sni')).toBe('node.example');
    expect(qs.get('security')).toBe('tls');
  });
});

describe('renderEntries', () => {
  test('emits v4 + v6 per endpoint in both mode, only v4 when off, primary first', () => {
    const both = renderEntries(assigned, linksRule, false);
    expect(both.map((e) => [e.role, e.family, e.label])).toEqual([
      ['primary', 'v4', 'FreeSocks Primary'],
      ['primary', 'v6', 'FreeSocks Primary (IPv6)'],
      ['backup', 'v4', 'FreeSocks Backup'],
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
});

describe('link-list rendering', () => {
  test('plain list: template replaced by labelled primary/backup entries, other lines untouched, one SNI each', () => {
    const body = [otherLink, templateLink].join('\n');
    const out = renderEdgeEndpoints({
      body,
      templateRemarks: [TEMPLATE],
      assigned,
      rule: linksRule,
    });
    expect(out.applied).toBe(true);
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
    // Credentials preserved byte-for-byte.
    expect(primary).toContain('11111111-2222-3333-4444-555555555555@');
    expect(primary).toContain('pbk=PUBKEY_BASE64');
  });

  test('a plain-protocol slot renders address/port and keeps the template SNI in every format', () => {
    const tcpTemplate = `vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?encryption=none&security=tls&sni=node.example&type=tcp#${encodeURIComponent(TEMPLATE)}`;
    const tcpEdge: PublishedEdge = { ...edgeA, protocol: 'plain', serverNames: [] };
    const tcpAssigned = {
      primary: { role: 'primary' as const, edge: tcpEdge, sni: null },
      backup: null,
    };
    const links = renderEdgeEndpoints({
      body: tcpTemplate,
      templateRemarks: [TEMPLATE],
      assigned: tcpAssigned,
      rule: linksRule,
    });
    expect(links.applied).toBe(true);
    const line = links.body.split('\n')[0];
    expect(line).toContain('@203.0.113.10:443?');
    expect(line).toContain('sni=node.example');
    const sb = renderEdgeEndpoints({
      body: JSON.stringify({
        outbounds: [
          {
            type: 'vless',
            tag: TEMPLATE,
            server: '192.0.2.10',
            server_port: 443,
            tls: { enabled: true, server_name: 'node.example' },
          },
          { type: 'selector', tag: 'proxy', outbounds: [TEMPLATE] },
        ],
      }),
      templateRemarks: [TEMPLATE],
      assigned: tcpAssigned,
      rule: autoRule,
    });
    expect(sb.applied).toBe(true);
    const doc = JSON.parse(sb.body) as { outbounds: Array<Record<string, unknown>> };
    const emitted = doc.outbounds.find((o) => o.server === '203.0.113.10')!;
    expect((emitted.tls as { server_name: string }).server_name).toBe('node.example');
  });

  test('base64-wrapped list stays base64 and renders identically for the same input', () => {
    const body = btoa([templateLink, otherLink].join('\n'));
    const out1 = renderEdgeEndpoints({
      body,
      templateRemarks: [TEMPLATE],
      assigned,
      rule: linksRule,
    });
    const out2 = renderEdgeEndpoints({
      body,
      templateRemarks: [TEMPLATE],
      assigned,
      rule: linksRule,
    });
    expect(out1.applied).toBe(true);
    expect(out1.body).toBe(out2.body);
    const decoded = atob(out1.body);
    expect(decoded.split('\n')).toHaveLength(4);
    expect(decoded).toContain(OTHER_NODE_WS);
  });

  test('no template line → untouched; disabled → untouched', () => {
    const out = renderEdgeEndpoints({
      body: otherLink,
      templateRemarks: [TEMPLATE],
      assigned,
      rule: linksRule,
    });
    expect(out).toMatchObject({ applied: false, body: otherLink, reason: 'no_template_lines' });
    const off = renderEdgeEndpoints({
      body: templateLink,
      templateRemarks: [TEMPLATE],
      assigned,
      rule: { ...linksRule, enabled: false },
    });
    expect(off).toMatchObject({ applied: false, reason: 'disabled' });
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
        server: '192.0.2.10',
        server_port: 443,
        uuid: '11111111-2222-3333-4444-555555555555',
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

  test('clones the template outbound per endpoint, adds the auto group with exactly the emitted tags, makes it the selector default', () => {
    const out = renderEdgeEndpoints({
      body: JSON.stringify(singbox),
      templateRemarks: [TEMPLATE],
      assigned,
      rule: autoRule,
    });
    expect(out.applied).toBe(true);
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
    expect(emitted[0]).toMatchObject({
      server: '203.0.113.10',
      server_port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
    });
    expect((emitted[0].tls as { server_name: string; reality: unknown }).server_name).toBe(
      'cdn-a.example',
    );
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
    // Route rules untouched.
    expect(JSON.parse(out.body).route).toEqual(singbox.route);
  });

  test('a template tag still referenced elsewhere → fail-open untouched', () => {
    const withDetour = {
      ...singbox,
      outbounds: [...singbox.outbounds, { type: 'http', tag: 'helper', detour: TEMPLATE }],
    };
    const out = renderEdgeEndpoints({
      body: JSON.stringify(withDetour),
      templateRemarks: [TEMPLATE],
      assigned,
      rule: autoRule,
    });
    expect(out).toMatchObject({ applied: false, reason: 'dangling_template_reference' });
  });

  test('renders are byte-identical for identical input', () => {
    const a = renderEdgeEndpoints({
      body: JSON.stringify(singbox),
      templateRemarks: [TEMPLATE],
      assigned,
      rule: autoRule,
    });
    const b = renderEdgeEndpoints({
      body: JSON.stringify(singbox),
      templateRemarks: [TEMPLATE],
      assigned,
      rule: autoRule,
    });
    expect(a.body).toBe(b.body);
  });
});

describe('clash / mihomo rendering', () => {
  const clash = `mixed-port: 7890
mode: global
proxies: # LEAVE THIS LINE!
  - name: ${TEMPLATE}
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
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

  test('clones the template proxy, adds a url-test group first and keeps the rest', () => {
    const rule = effectiveRule(cfg, defaultClientRule('mihomo'));
    const out = renderEdgeEndpoints({ body: clash, templateRemarks: [TEMPLATE], assigned, rule });
    expect(out.applied).toBe(true);
    const doc = YAML.parse(out.body) as {
      proxies: Array<Record<string, unknown>>;
      'proxy-groups': Array<Record<string, unknown>>;
      rules: string[];
    };
    const names = doc.proxies.map((p) => p.name);
    expect(names).toEqual([
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
  });

  test('a body without proxies passes through', () => {
    const out = renderEdgeEndpoints({
      body: 'mixed-port: 7890\nproxies: []\n',
      templateRemarks: [TEMPLATE],
      assigned,
      rule: autoRule,
    });
    expect(out.applied).toBe(false);
  });
});
