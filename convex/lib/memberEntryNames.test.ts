import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { addressRemark, remarkTag } from './backend/hostRemark';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import {
  DEFAULT_SITE_NAME,
  ENTRY_NAME_SEP,
  entryCode,
  entryKey,
  entryNamingFrom,
  memberPlace,
  memberSiteName,
  planEntryNames,
  relabelMemberEntries,
  type EntryNaming,
} from './memberEntryNames';
import { pinSubscriptionToNode } from './nodePinning';

// Example names only (the generated three-word shape, made up here).
const NODE_A = 'quiet-amber-falcon';
// Shorter than NODE_A: a remark that needs the server name's tag under one
// name carries the full name under the other.
const NODE_B = 'brisk-otter';
const NAMES = ['www.decoy-a.example', 'cdn.decoy-b.example', 'static.decoy-c.example'];
const ADDR_A = '192.0.2.10';
const ADDR_B = '198.51.100.20';
const NAMING: EntryNaming = { siteName: 'FreeSocks', place: 'Example City' };
const BASE = `FreeSocks${ENTRY_NAME_SEP}Example City`;

function link(node: string, sni: string, address = ADDR_A): string {
  const remark = addressRemark(node, sni);
  return `vless://11111111-2222-3333-4444-555555555555@${address}:443?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=PUBKEY&sid=ab#${encodeURIComponent(remark)}`;
}

/** Each line's name (decoded fragment) keyed by its server name. */
function labelsBySni(body: string): Map<string, string> {
  const text = body.trim().startsWith('vless://') ? body : decodeBase64Loose(body)!;
  const out = new Map<string, string>();
  for (const line of text.split('\n').filter(Boolean)) {
    const sni = new URL(line).searchParams.get('sni')!;
    out.set(sni, decodeURIComponent(line.slice(line.indexOf('#') + 1)));
  }
  return out;
}

/** No node name and no server name in any name; the node name nowhere at all. */
function expectNeutral(body: string, labels: Iterable<string>, nodes = [NODE_A, NODE_B]): void {
  for (const label of labels) {
    for (const node of nodes) expect(label).not.toContain(node);
    for (const name of NAMES) expect(label).not.toContain(name);
    expect(label).not.toContain('|');
  }
  for (const node of nodes) expect(body).not.toContain(node);
}

function singbox(node: string): Record<string, unknown> {
  const tags = NAMES.map((n) => addressRemark(node, n));
  return {
    log: { level: 'error' },
    dns: { servers: [{ tag: 'remote', address: 'tls://1.1.1.1', detour: tags[0] }] },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 1080 }],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags], default: tags[0] },
      { type: 'urltest', tag: 'auto', outbounds: tags },
      ...tags.map((tag, i) => ({
        type: 'vless',
        tag,
        server: ADDR_A,
        server_port: 443,
        uuid: '11111111-2222-3333-4444-555555555555',
        tls: { enabled: true, server_name: NAMES[i], reality: { enabled: true } },
      })),
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'proxy', rules: [{ domain_suffix: ['example.org'], outbound: tags[1] }] },
  };
}

function clash(node: string): string {
  const names = NAMES.map((n) => addressRemark(node, n));
  return YAML.stringify({
    'mixed-port': 1080,
    proxies: names.map((name, i) => ({
      name,
      type: 'vless',
      server: ADDR_A,
      port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      servername: NAMES[i],
      'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'ab' },
    })),
    'proxy-groups': [
      { name: 'proxy', type: 'select', proxies: ['auto', ...names, 'DIRECT'] },
      { name: 'auto', type: 'url-test', proxies: names },
    ],
    rules: [`DOMAIN-SUFFIX,example.org,${names[2]}`, 'MATCH,proxy'],
  });
}

describe('relabelMemberEntries: every format', () => {
  test('a link list: every node-named entry gets a distinct neutral label, nothing else changes', () => {
    const body = NAMES.map((n) => link(NODE_A, n)).join('\n');
    const out = relabelMemberEntries(body, NAMING);
    expect(out.renamed).toBe(3);
    const labels = labelsBySni(out.content);
    expect(new Set(labels.values()).size).toBe(3);
    for (const [sni, label] of labels)
      expect(label).toBe(`${BASE}${ENTRY_NAME_SEP}${entryCode(remarkTag(sni))}`);
    expectNeutral(out.content, labels.values());
    // Everything before the fragment (address, credential, server name) is untouched.
    const before = (s: string) => s.split('\n').map((l) => l.slice(0, l.indexOf('#')));
    expect(before(out.content)).toEqual(before(body));
  });

  test('a base64-wrapped link list comes back base64, relabelled', () => {
    const plain = NAMES.map((n) => link(NODE_A, n)).join('\n');
    const out = relabelMemberEntries(encodeBase64(plain), NAMING);
    expect(out.content.startsWith('vless://')).toBe(false);
    expect(decodeBase64Loose(out.content)).toBe(relabelMemberEntries(plain, NAMING).content);
    expectNeutral(decodeBase64Loose(out.content)!, labelsBySni(out.content).values());
  });

  test('CRLF line ends are kept', () => {
    const body = NAMES.map((n) => link(NODE_A, n)).join('\r\n');
    const out = relabelMemberEntries(body, NAMING).content;
    expect(
      out
        .split('\n')
        .slice(0, -1)
        .every((l) => l.endsWith('\r')),
    ).toBe(true);
    expect(out).not.toContain(NODE_A);
  });

  test('sing-box: tags renamed, every group, default, rule and detour still resolves', () => {
    const out = relabelMemberEntries(JSON.stringify(singbox(NODE_A)), NAMING);
    expect(out.renamed).toBe(3);
    const cfg = JSON.parse(out.content) as {
      outbounds: Array<{ tag: string; type: string; outbounds?: string[]; default?: string }>;
      route: { final: string; rules: Array<{ outbound: string }> };
      dns: { servers: Array<{ detour: string }> };
    };
    const tags = new Set(cfg.outbounds.map((o) => o.tag));
    for (const o of cfg.outbounds) {
      for (const m of o.outbounds ?? []) expect(tags.has(m)).toBe(true);
      if (o.default) expect(tags.has(o.default)).toBe(true);
    }
    expect(tags.has(cfg.route.final)).toBe(true);
    for (const r of cfg.route.rules) expect(tags.has(r.outbound)).toBe(true);
    expect(tags.has(cfg.dns.servers[0].detour)).toBe(true);
    const vless = cfg.outbounds.filter((o) => o.type === 'vless').map((o) => o.tag);
    expect(vless.every((t) => t.startsWith(`${BASE}${ENTRY_NAME_SEP}`))).toBe(true);
    // Groups and built-ins keep their names.
    expect([...tags]).toEqual(expect.arrayContaining(['proxy', 'auto', 'direct']));
    expectNeutral(out.content, vless);
  });

  test('Clash / Mihomo: proxy names renamed, every group member and rule target resolves', () => {
    const out = relabelMemberEntries(clash(NODE_A), NAMING);
    expect(out.renamed).toBe(3);
    const doc = YAML.parse(out.content) as {
      proxies: Array<{ name: string; servername: string }>;
      'proxy-groups': Array<{ name: string; proxies: string[] }>;
      rules: string[];
    };
    const known = new Set([
      'DIRECT',
      ...doc.proxies.map((p) => p.name),
      ...doc['proxy-groups'].map((g) => g.name),
    ]);
    for (const g of doc['proxy-groups']) for (const m of g.proxies) expect(known.has(m)).toBe(true);
    for (const r of doc.rules) expect(known.has(r.split(',').at(-1)!)).toBe(true);
    expect(doc.proxies.map((p) => p.servername)).toEqual(NAMES);
    expectNeutral(
      out.content,
      doc.proxies.map((p) => p.name),
    );
  });

  test('an Xray JSON config list: each config’s remarks', () => {
    const list = NAMES.map((n) => ({
      remarks: addressRemark(NODE_A, n),
      outbounds: [{ tag: 'proxy', protocol: 'vless' }],
    }));
    const out = relabelMemberEntries(JSON.stringify(list), NAMING);
    const remarks = (JSON.parse(out.content) as Array<{ remarks: string }>).map((c) => c.remarks);
    expect(new Set(remarks).size).toBe(3);
    expectNeutral(out.content, remarks);
  });

  test('role-written remarks (<node>-reality, -ws-<hash>, -relay-<slot>) are relabelled too', () => {
    const body = [
      `vless://u@${ADDR_A}:443?security=reality&sni=${NAMES[0]}#${NODE_A}-reality`,
      `vless://u@${ADDR_A}:443?type=ws&sni=${NAMES[1]}#${NODE_A}-ws-6a536a`,
      `vless://u@${ADDR_A}:443?security=reality&sni=${NAMES[2]}#${NODE_A}-relay-a`,
    ].join('\n');
    const out = relabelMemberEntries(body, NAMING);
    expect(out.renamed).toBe(3);
    expectNeutral(out.content, labelsBySni(out.content).values());
  });
});

describe('relabelMemberEntries: labels', () => {
  test('one entry is the site name and place alone; no place leaves it out', () => {
    expect(labelsBySni(relabelMemberEntries(link(NODE_A, NAMES[0]), NAMING).content)).toEqual(
      new Map([[NAMES[0], BASE]]),
    );
    const noPlace = relabelMemberEntries(link(NODE_A, NAMES[0]), {
      siteName: 'FreeSocks',
      place: null,
    });
    expect([...labelsBySni(noPlace.content).values()]).toEqual(['FreeSocks']);
  });

  test('entries that name no node keep their names (edge labels, placeholders)', () => {
    const body = [
      link(NODE_A, NAMES[0]),
      `vless://u@203.0.113.5:443?security=reality&sni=${NAMES[1]}#FreeSocks%20Primary`,
      'vless://u@0.0.0.0:1#Subscription%20expired',
    ].join('\n');
    const lines = relabelMemberEntries(body, NAMING).content.split('\n');
    expect(lines[1]).toBe(body.split('\n')[1]);
    expect(lines[2]).toBe(body.split('\n')[2]);
    expect(decodeURIComponent(lines[0].split('#')[1])).toBe(BASE);
  });

  test('a new label never takes a name the body already uses', () => {
    const body = [
      link(NODE_A, NAMES[0]),
      `vless://u@203.0.113.5:443#${encodeURIComponent(BASE)}`,
    ].join('\n');
    const lines = relabelMemberEntries(body, NAMING).content.split('\n');
    expect(decodeURIComponent(lines[0].split('#')[1])).toBe(`${BASE} (2)`);
  });

  test('off, unknown shapes and garbage come back verbatim', () => {
    const body = NAMES.map((n) => link(NODE_A, n)).join('\n');
    expect(relabelMemberEntries(body, null)).toEqual({ content: body, renamed: 0 });
    for (const other of [
      '<html></html>',
      '{"error":"x"}',
      '{not json',
      'just text',
      '',
      'proxies: [',
    ]) {
      expect(relabelMemberEntries(other, NAMING).content).toBe(other);
    }
  });
});

describe('relabelMemberEntries: stable across refreshes', () => {
  const body = NAMES.map((n) => link(NODE_A, n)).join('\n');
  const first = labelsBySni(relabelMemberEntries(body, NAMING).content);

  test('the same body gives the same labels', () => {
    expect(labelsBySni(relabelMemberEntries(body, NAMING).content)).toEqual(first);
  });

  test('order does not matter', () => {
    const reversed = NAMES.map((n) => link(NODE_A, n))
      .reverse()
      .join('\n');
    expect(labelsBySni(relabelMemberEntries(reversed, NAMING).content)).toEqual(first);
  });

  test('another server name coming or going leaves the others alone', () => {
    const more = [...NAMES, 'img.decoy-d.example'].map((n) => link(NODE_A, n)).join('\n');
    const after = labelsBySni(relabelMemberEntries(more, NAMING).content);
    for (const [sni, label] of first) expect(after.get(sni)).toBe(label);
    const fewer = NAMES.slice(0, 2)
      .map((n) => link(NODE_A, n))
      .join('\n');
    const less = labelsBySni(relabelMemberEntries(fewer, NAMING).content);
    for (const [sni, label] of less) expect(label).toBe(first.get(sni));
  });

  test('a node rename keeps every label (the code comes from the server name)', () => {
    // NAMES[2] is a tag under NODE_A, the full name under NODE_B.
    expect(addressRemark(NODE_A, NAMES[2])).not.toContain(NAMES[2]);
    expect(addressRemark(NODE_B, NAMES[2])).toContain(NAMES[2]);
    const renamed = NAMES.map((n) => link(NODE_B, n)).join('\n');
    expect(labelsBySni(relabelMemberEntries(renamed, NAMING).content)).toEqual(first);
  });

  test('a long server name (remark carries its tag) still gets a stable label', () => {
    const long = `${'a'.repeat(40)}.decoy.example`;
    const one = relabelMemberEntries(
      [link(NODE_A, long), link(NODE_A, NAMES[0])].join('\n'),
      NAMING,
    );
    const two = relabelMemberEntries(
      [link(NODE_A, NAMES[0]), link(NODE_A, long)].join('\n'),
      NAMING,
    );
    expect(labelsBySni(one.content)).toEqual(labelsBySni(two.content));
    expect(one.content).not.toContain(NODE_A);
  });

  test('colliding codes: each collider carries its own long code, whoever it collides with', () => {
    // Three keys sharing one short code (searched, not assumed).
    const byCode = new Map<string, string[]>();
    let trio: string[] | null = null;
    for (let i = 0; !trio; i++) {
      const key = `n${i}.decoy.example`;
      const list = [...(byCode.get(entryCode(entryKey(key))) ?? []), key];
      byCode.set(entryCode(entryKey(key)), list);
      if (list.length === 3) trio = list;
    }
    const [a, b, c] = trio;
    const entry = (k: string) => ({ name: addressRemark(NODE_A, k), entry: k });
    const longLabel = (k: string) => `${BASE}${ENTRY_NAME_SEP}${entryCode(entryKey(k), 6)}`;
    const withB = planEntryNames([entry(a), entry(b)], new Set(), NAMING);
    const withC = planEntryNames([entry(c), entry(a)], new Set(), NAMING);
    // The label of `a` comes from `a` alone: not from its position, nor from its partner.
    expect(withB.get(entry(a).name)).toBe(longLabel(a));
    expect(withC.get(entry(a).name)).toBe(longLabel(a));
    expect(withB.get(entry(b).name)).toBe(longLabel(b));
    expect(new Set(withB.values()).size).toBe(2);
    // A new entry that collides with nobody leaves every label alone.
    const more = planEntryNames(
      [entry(a), entry(b), entry('img.decoy-d.example')],
      new Set(),
      NAMING,
    );
    expect(more.get(entry(a).name)).toBe(longLabel(a));
  });
});

describe('only FCP’s own remarks are read as nodes', () => {
  test('an operator’s display remark is left alone', () => {
    const body = [
      `vless://u@${ADDR_A}:443?security=reality&sni=${NAMES[0]}#USA%20%7C%20VLESS`,
      `vless://u@${ADDR_B}:443?security=reality&sni=${NAMES[1]}#Europe%20%7C%20VLESS`,
    ].join('\n');
    expect(relabelMemberEntries(body, NAMING)).toEqual({ content: body, renamed: 0 });
    expect(pinSubscriptionToNode(body, 'short-1')).toEqual({ content: body, node: null });
  });

  test('the remark must carry the server name the entry itself serves (or its tag)', () => {
    const remark = encodeURIComponent(addressRemark(NODE_A, NAMES[0]));
    const mismatch = `vless://u@${ADDR_A}:443?security=reality&sni=${NAMES[1]}#${remark}`;
    expect(relabelMemberEntries(mismatch, NAMING).renamed).toBe(0);
    const long = `${'a'.repeat(40)}.decoy.example`;
    const tagged = link(NODE_A, long);
    expect(decodeURIComponent(tagged.split('#')[1])).toBe(addressRemark(NODE_A, long));
    expect(relabelMemberEntries(tagged, NAMING).renamed).toBe(1);
    // A single-label server name is FCP's too when the entry carries it.
    const single = `vless://u@${ADDR_A}:443?security=reality&sni=origin-name#${encodeURIComponent(addressRemark(NODE_A, 'origin-name'))}`;
    expect(relabelMemberEntries(single, NAMING).renamed).toBe(1);
  });
});

describe('labels always encode', () => {
  test('a name cut at its length cap never splits a character', () => {
    const siteName = memberSiteName(`${'a'.repeat(31)}\u{1F30D}tail`);
    expect(Array.from(siteName)).toHaveLength(32);
    expect(() => encodeURIComponent(siteName)).not.toThrow();
    expect(memberSiteName('ab\uD800cd')).toBe('abcd');
    const out = relabelMemberEntries(link(NODE_A, NAMES[0]), { siteName, place: null });
    expect(out.renamed).toBe(1);
    expect(out.content).not.toContain(NODE_A);
  });
});

describe('pinning, then relabelling', () => {
  test('the member keeps their own node’s entries, under neutral names', () => {
    const body = [
      ...NAMES.map((n) => link(NODE_A, n, ADDR_A)),
      ...NAMES.map((n) => link(NODE_B, n, ADDR_B)),
    ].join('\n');
    for (const key of ['short-1', 'short-2', 'short-3', 'short-4']) {
      const pinned = pinSubscriptionToNode(encodeBase64(body), key);
      expect([NODE_A, NODE_B]).toContain(pinned.node);
      const address = pinned.node === NODE_A ? ADDR_A : ADDR_B;
      const out = relabelMemberEntries(pinned.content, NAMING).content;
      const decoded = decodeBase64Loose(out)!;
      const lines = decoded.split('\n');
      expect(lines).toHaveLength(3);
      expect(lines.every((l) => new URL(l).hostname === address)).toBe(true);
      expectNeutral(decoded, labelsBySni(out).values());
    }
  });
});

describe('naming from settings', () => {
  test('defaults on, with the built-in site name', () => {
    expect(entryNamingFrom({}, undefined)).toEqual({ siteName: DEFAULT_SITE_NAME, place: null });
    expect(entryNamingFrom({ 'subscription.entryNames': 'yes' }, 'Example City')).toEqual({
      siteName: DEFAULT_SITE_NAME,
      place: 'Example City',
    });
    expect(entryNamingFrom({ 'subscription.entryNames': false }, 'Example City')).toBeNull();
  });

  test('operator text is made safe for a connection name', () => {
    expect(memberSiteName('  My   Service ')).toBe('My Service');
    expect(memberSiteName('A, B | C')).toBe('A B C');
    expect(memberSiteName('')).toBe(DEFAULT_SITE_NAME);
    expect(memberSiteName(42)).toBe(DEFAULT_SITE_NAME);
    expect(memberSiteName('x'.repeat(80))).toHaveLength(32);
    expect(memberPlace('Example City, EX')).toBe('Example City');
    expect(memberPlace(' , EX')).toBeNull();
    expect(memberPlace(undefined)).toBeNull();
  });
});
