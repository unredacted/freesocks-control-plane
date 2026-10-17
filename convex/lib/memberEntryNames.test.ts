import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { addressRemark, remarkTag } from './backend/hostRemark';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { SUBSCRIPTION_TEMPLATES } from './backend/subscriptionTemplates';
import { CLASH_YAML } from './backend/subscriptionTemplates/CLASH';
import { SINGBOX_JSON } from './backend/subscriptionTemplates/SINGBOX';
import {
  backendGroupName,
  DEFAULT_SITE_NAME,
  ENTRY_NAME_SEP,
  entryCode,
  entryKey,
  entryNamingFrom,
  memberGroupName,
  memberPlace,
  memberSiteName,
  planEntryNames,
  planGroupNames,
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

describe('relabelMemberEntries: the backend’s groups', () => {
  const TEMPLATE_GROUP = '→ Remnawave';
  const SELECT = 'FreeSocks Select';
  type Obj = Record<string, unknown>;

  function vless(tag: string, sni: string, server = ADDR_A): Obj {
    return {
      type: 'vless',
      tag,
      server,
      server_port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      tls: { enabled: true, server_name: sni, reality: { enabled: true } },
    };
  }

  /** The backend's sing-box body: its template, the entries spliced into the template group. */
  function singboxFromTemplate(entries: Obj[]): Obj & { outbounds: Obj[]; route: Obj } {
    const cfg = JSON.parse(JSON.stringify(SINGBOX_JSON)) as Obj & { outbounds: Obj[]; route: Obj };
    cfg.outbounds[0].outbounds = entries.map((e) => e.tag);
    cfg.outbounds.splice(1, 0, ...entries);
    return cfg;
  }

  /** The backend's Clash body: its template, the proxies spliced in at the anchors. */
  function clashFromTemplate(proxies: Obj[], groups: Obj[] = []): Obj & { 'proxy-groups': Obj[] } {
    const doc = YAML.parse(CLASH_YAML) as Obj & { 'proxy-groups': Obj[] };
    doc.proxies = proxies;
    doc['proxy-groups'][0].proxies = proxies.map((p) => p.name);
    doc['proxy-groups'].unshift(...groups);
    return doc;
  }

  function clashProxy(name: string, sni: string, server = ADDR_A): Obj {
    return {
      name,
      type: 'vless',
      server,
      port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      servername: sni,
      'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'ab' },
    };
  }

  /** Every sing-box group member, `default`, `route.final` and rule target names an outbound. */
  function expectSingboxResolves(cfg: { outbounds: Obj[]; route: Obj }): Set<string> {
    const tags = new Set(cfg.outbounds.map((o) => o.tag as string));
    for (const o of cfg.outbounds) {
      for (const m of (o.outbounds as string[] | null) ?? []) expect(tags.has(m)).toBe(true);
      if (o.default) expect(tags.has(o.default as string)).toBe(true);
    }
    if (cfg.route.final) expect(tags.has(cfg.route.final as string)).toBe(true);
    for (const r of cfg.route.rules as Obj[])
      if (typeof r.outbound === 'string') expect(tags.has(r.outbound)).toBe(true);
    return tags;
  }

  /** Every Clash group member and rule target names a proxy, a group or a built-in. */
  function expectClashResolves(doc: { proxies: Obj[]; 'proxy-groups': Obj[]; rules: string[] }) {
    const known = new Set([
      'DIRECT',
      'REJECT',
      ...doc.proxies.map((p) => p.name as string),
      ...doc['proxy-groups'].map((g) => g.name as string),
    ]);
    for (const g of doc['proxy-groups'])
      for (const m of g.proxies as string[]) expect(known.has(m)).toBe(true);
    for (const r of doc.rules) expect(known.has(r.split(',').at(-1)!)).toBe(true);
    return known;
  }

  test('sing-box from the backend’s template: the group is "<site> Select", every reference follows', () => {
    const cfg = singboxFromTemplate(NAMES.map((n) => vless(addressRemark(NODE_A, n), n)));
    cfg.route = { ...cfg.route, final: TEMPLATE_GROUP };
    (cfg.route.rules as Obj[]).push({ domain_suffix: ['example.org'], outbound: TEMPLATE_GROUP });
    const out = relabelMemberEntries(JSON.stringify(cfg), NAMING);
    expect(out.renamed).toBe(NAMES.length + 1);
    const next = JSON.parse(out.content) as { outbounds: Obj[]; route: Obj };
    const tags = expectSingboxResolves(next);
    const selector = next.outbounds.find((o) => o.type === 'selector')!;
    expect(selector.tag).toBe(SELECT);
    expect(selector.outbounds).toHaveLength(NAMES.length);
    expect(next.route.final).toBe(SELECT);
    for (const tag of tags) expect(tag).not.toMatch(/remnawave/i);
    expectNeutral(
      out.content,
      [...tags].filter((t) => t.startsWith(`${BASE}${ENTRY_NAME_SEP}`)),
    );
  });

  test('Clash from the backend’s template: the group and its MATCH rule follow', () => {
    const doc = clashFromTemplate(NAMES.map((n) => clashProxy(addressRemark(NODE_A, n), n)));
    const out = relabelMemberEntries(YAML.stringify(doc), NAMING);
    expect(out.renamed).toBe(NAMES.length + 1);
    const next = YAML.parse(out.content) as {
      proxies: Obj[];
      'proxy-groups': Obj[];
      rules: string[];
    };
    expectClashResolves(next);
    expect(next['proxy-groups'].map((g) => g.name)).toEqual([SELECT]);
    expect(next.rules).toEqual([`MATCH,${SELECT}`]);
    expect(out.content).not.toMatch(/remnawave/i);
  });

  test('an edge-only body (no entry names a node): the group alone is renamed, apart from the edge names', () => {
    // What the edge renderer leaves: its entry under the default label, its
    // url-test group, both inside the template group.
    const edge = 'FreeSocks';
    const auto = 'FreeSocks Auto';
    const doc = clashFromTemplate(
      [clashProxy(edge, NAMES[0], '203.0.113.5')],
      [{ name: auto, type: 'url-test', proxies: [edge] }],
    );
    doc['proxy-groups'][1].proxies = [auto, edge];
    const clash = relabelMemberEntries(YAML.stringify(doc), NAMING);
    expect(clash.renamed).toBe(1);
    const next = YAML.parse(clash.content) as {
      proxies: Obj[];
      'proxy-groups': Obj[];
      rules: string[];
    };
    expectClashResolves(next);
    expect(next.proxies.map((p) => p.name)).toEqual([edge]);
    expect(next['proxy-groups'].map((g) => g.name)).toEqual([auto, SELECT]);
    expect(next['proxy-groups'][1].proxies).toEqual([auto, edge]);

    const cfg = singboxFromTemplate([vless(edge, NAMES[0], '203.0.113.5')]);
    cfg.outbounds.splice(1, 0, { type: 'urltest', tag: auto, outbounds: [edge] });
    cfg.outbounds[0].outbounds = [auto, edge];
    const singbox = relabelMemberEntries(JSON.stringify(cfg), NAMING);
    expect(singbox.renamed).toBe(1);
    const tags = expectSingboxResolves(JSON.parse(singbox.content) as typeof cfg);
    expect([...tags]).toEqual([SELECT, auto, edge, 'direct']);
  });

  test('the site name is the operator’s', () => {
    const doc = clashFromTemplate([clashProxy('FreeSocks', NAMES[0], '203.0.113.5')]);
    const out = relabelMemberEntries(YAML.stringify(doc), { siteName: 'Example VPN', place: null });
    const next = YAML.parse(out.content) as { 'proxy-groups': Obj[] };
    expect(next['proxy-groups'][0].name).toBe('Example VPN Select');
  });

  test('the new group name never takes a name the body uses (an edge label, an operator group)', () => {
    const doc = clashFromTemplate(
      [
        clashProxy(SELECT, NAMES[0], '203.0.113.5'),
        clashProxy(addressRemark(NODE_A, NAMES[1]), NAMES[1]),
      ],
      [{ name: `${SELECT} (2)`, type: 'select', proxies: [SELECT] }],
    );
    const out = relabelMemberEntries(YAML.stringify(doc), NAMING);
    const next = YAML.parse(out.content) as {
      proxies: Obj[];
      'proxy-groups': Obj[];
      rules: string[];
    };
    const known = expectClashResolves(next);
    expect(next['proxy-groups'].map((g) => g.name)).toEqual([`${SELECT} (2)`, `${SELECT} (3)`]);
    expect(next.proxies.map((p) => p.name)).toEqual([SELECT, BASE]);
    expect(known.size).toBe(2 + next.proxies.length + next['proxy-groups'].length);
  });

  test('an operator’s own groups keep their names; one named after the backend product is renamed', () => {
    const proxies = NAMES.map((n) => clashProxy(addressRemark(NODE_A, n), n));
    const names = proxies.map((p) => p.name as string);
    const doc = clashFromTemplate(proxies, [
      { name: 'Streaming', type: 'select', proxies: [TEMPLATE_GROUP, 'DIRECT'] },
      { name: 'auto', type: 'url-test', proxies: names },
      { name: 'Remnawave fallback', type: 'fallback', proxies: names },
    ]);
    const out = relabelMemberEntries(YAML.stringify(doc), NAMING);
    const next = YAML.parse(out.content) as {
      proxies: Obj[];
      'proxy-groups': Obj[];
      rules: string[];
    };
    expectClashResolves(next);
    // The template's group takes the plain name; the other follows.
    expect(next['proxy-groups'].map((g) => g.name)).toEqual([
      'Streaming',
      'auto',
      `${SELECT} (2)`,
      SELECT,
    ]);
    expect(next['proxy-groups'][0].proxies).toEqual([SELECT, 'DIRECT']);
    expect(out.content).not.toMatch(/remnawave/i);
  });

  test('off, the backend’s group name passes with the rest of the body', () => {
    const body = YAML.stringify(
      clashFromTemplate([clashProxy('FreeSocks', NAMES[0], '203.0.113.5')]),
    );
    expect(relabelMemberEntries(body, null)).toEqual({ content: body, renamed: 0 });
  });

  test('every group of every template the backend is given is recognized as the backend’s', () => {
    for (const [family, template] of Object.entries(SUBSCRIPTION_TEMPLATES)) {
      const groups =
        template.kind === 'json'
          ? (template.body as { outbounds: Obj[] }).outbounds
              .filter((o) => o.type === 'selector' || o.type === 'urltest')
              .map((o) => o.tag as string)
          : (YAML.parse(template.body) as { 'proxy-groups': Obj[] })['proxy-groups'].map(
              (g) => g.name as string,
            );
      expect(groups.length, family).toBeGreaterThan(0);
      for (const g of groups) expect(backendGroupName(g), `${family}: ${g}`).toBe(true);
    }
  });

  test('planGroupNames: the template group first, then body order; each once; other groups skipped', () => {
    const plan = planGroupNames(
      ['proxy', 'Remnawave EU', TEMPLATE_GROUP, 'Remnawave EU'],
      new Set(['proxy', 'Remnawave EU', TEMPLATE_GROUP, 'FreeSocks']),
      NAMING,
    );
    expect([...plan]).toEqual([
      [TEMPLATE_GROUP, SELECT],
      ['Remnawave EU', `${SELECT} (2)`],
    ]);
    expect(memberGroupName(NAMING)).toBe(SELECT);
    expect(backendGroupName('proxy')).toBe(false);
  });
});

describe('relabelling again, and values that are not names', () => {
  type Obj = Record<string, unknown>;
  const singboxBody = (groupTag: string, entries: Obj[]) => {
    const cfg = JSON.parse(JSON.stringify(SINGBOX_JSON)) as Obj & { outbounds: Obj[] };
    cfg.outbounds[0].tag = groupTag;
    cfg.outbounds[0].outbounds = entries.map((e) => e.tag);
    cfg.outbounds.splice(1, 0, ...entries);
    return JSON.stringify(cfg);
  };
  const vless = (tag: string, sni: string) => ({
    type: 'vless',
    tag,
    server: ADDR_A,
    server_port: 443,
    uuid: '11111111-2222-3333-4444-555555555555',
    tls: { enabled: true, server_name: sni, reality: { enabled: true } },
  });
  const clashBody = (names: string[]) => {
    const doc = YAML.parse(CLASH_YAML) as Obj & { 'proxy-groups': Obj[] };
    doc.proxies = names.map((name, i) => ({
      name,
      type: 'vless',
      server: ADDR_A,
      port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      servername: NAMES[i],
    }));
    doc['proxy-groups'][0].proxies = names;
    return YAML.stringify(doc);
  };

  test('a relabelled body relabels to itself (a cached body is relabelled again when served)', () => {
    const bodies = [
      singboxBody(
        '→ Remnawave',
        NAMES.map((n) => vless(addressRemark(NODE_A, n), n)),
      ),
      singboxBody('→ Remnawave', [vless('FreeSocks', NAMES[0])]),
      clashBody(NAMES.map((n) => addressRemark(NODE_A, n))),
      clashBody(['FreeSocks']),
    ];
    // A site name carrying the backend product's name must not add a suffix each time.
    for (const naming of [NAMING, { siteName: 'Remnawave VPN', place: null }]) {
      for (const body of bodies) {
        const once = relabelMemberEntries(body, naming);
        expect(once.renamed).toBeGreaterThan(0);
        expect(once.content).toContain(memberGroupName(naming));
        expect(relabelMemberEntries(once.content, naming)).toEqual({
          content: once.content,
          renamed: 0,
        });
      }
    }
  });

  test('a group named like the template’s cache id renames the group, never the cache id or a path', () => {
    const out = relabelMemberEntries(
      singboxBody('remnawave', [vless('FreeSocks', NAMES[0])]),
      NAMING,
    );
    expect(out.renamed).toBe(1);
    const cfg = JSON.parse(out.content) as {
      outbounds: Obj[];
      experimental: { cache_file: { cache_id: string; path: string } };
    };
    expect(cfg.outbounds[0].tag).toBe('FreeSocks Select');
    expect(cfg.experimental.cache_file).toEqual(
      (SINGBOX_JSON as { experimental: { cache_file: unknown } }).experimental.cache_file,
    );
    expect(cfg.experimental.cache_file.cache_id).toBe('remnawave');
  });
});
