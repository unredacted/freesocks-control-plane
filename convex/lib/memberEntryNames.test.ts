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
  entryKey,
  entryNamesOf,
  entryNamingFrom,
  instanceCountry,
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
const NAMING: EntryNaming = { siteName: 'FreeSocks', place: 'Example City', country: 'CA' };
const BASE = `🇨🇦 Example City${ENTRY_NAME_SEP}Direct`;
/** The n-th direct name of NAMING's place (1 = `Direct`, then `Direct 2`, …). */
const direct = (n: number) => (n === 1 ? BASE : `${BASE} ${n}`);
/** The direct name each server name gets: its number in the sorted keys. */
const directFor = (snis: readonly string[], sni: string) =>
  direct(
    snis
      .map((n) => entryKey(n))
      .sort()
      .indexOf(entryKey(sni)) + 1,
  );
// What the edge renderer names an entry (src/shared/entryNames.ts): no node in it.
const EDGE = '🇧🇷 via Example Town';

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
    // Numbered in the sorted order of the server names (their remark tags here).
    for (const [sni, label] of labels) expect(label).toBe(directFor(NAMES, sni));
    expect([...labels.values()].sort()).toEqual([direct(1), direct(2), direct(3)]);
    expect(remarkTag(NAMES[0])).toBe(entryKey(NAMES[0]));
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
    expect(vless.every((t) => t.startsWith(BASE))).toBe(true);
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

  test("an operator's hand-built front (<node>-relay) is relabelled, never shown as the remark", () => {
    const out = relabelMemberEntries(
      `vless://u@${ADDR_A}:443?security=reality&sni=${NAMES[0]}#${NODE_A}-relay`,
      NAMING,
    );
    expect(out.renamed).toBe(1);
    expectNeutral(out.content, labelsBySni(out.content).values());
  });
});

describe('relabelMemberEntries: labels', () => {
  test('one entry is the flag, the place and Direct; what is unknown is left out', () => {
    expect(labelsBySni(relabelMemberEntries(link(NODE_A, NAMES[0]), NAMING).content)).toEqual(
      new Map([[NAMES[0], '🇨🇦 Example City · Direct']]),
    );
    const named = (naming: EntryNaming) => [
      ...labelsBySni(relabelMemberEntries(link(NODE_A, NAMES[0]), naming).content).values(),
    ];
    // Neither a place nor a flag: the site name leads, never a bare "Direct"
    // (Clash's DIRECT, sing-box's `direct`).
    expect(named({ siteName: 'FreeSocks', place: null })).toEqual(['FreeSocks · Direct']);
    expect(named({ siteName: 'FreeSocks', place: 'Example City' })).toEqual([
      'Example City · Direct',
    ]);
    expect(named({ siteName: 'FreeSocks', place: null, country: 'CA' })).toEqual(['🇨🇦 · Direct']);
    // A private-use code ("unknown" to many backends) draws no flag.
    expect(named({ siteName: 'FreeSocks', place: 'Example City', country: 'XX' })).toEqual([
      'Example City · Direct',
    ]);
    // No site name in any entry: it names the group alone.
    expect(named(NAMING)[0]).not.toContain('FreeSocks');
  });

  test('n server names: Direct, Direct 2, Direct 3, the same in every format', () => {
    const want = new Map(NAMES.map((n) => [n, directFor(NAMES, n)]));
    const links = labelsBySni(
      relabelMemberEntries(NAMES.map((n) => link(NODE_A, n)).join('\n'), NAMING).content,
    );
    expect(links).toEqual(want);
    const sb = JSON.parse(
      relabelMemberEntries(JSON.stringify(singbox(NODE_A)), NAMING).content,
    ) as {
      outbounds: Array<{ type: string; tag: string; tls?: { server_name: string } }>;
    };
    expect(
      new Map(
        sb.outbounds.filter((o) => o.type === 'vless').map((o) => [o.tls!.server_name, o.tag]),
      ),
    ).toEqual(want);
    const cl = YAML.parse(relabelMemberEntries(clash(NODE_A), NAMING).content) as {
      proxies: Array<{ name: string; servername: string }>;
    };
    expect(new Map(cl.proxies.map((p) => [p.servername, p.name]))).toEqual(want);
    const xray = NAMES.map((n) => ({
      remarks: addressRemark(NODE_A, n),
      outbounds: [
        {
          tag: 'proxy',
          protocol: 'vless',
          streamSettings: { realitySettings: { serverName: n } },
        },
      ],
    }));
    const xr = JSON.parse(relabelMemberEntries(JSON.stringify(xray), NAMING).content) as Array<{
      remarks: string;
    }>;
    expect(xr.map((c) => c.remarks)).toEqual(NAMES.map((n) => want.get(n)));
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

  test('a server name sorted after the others coming or going leaves them alone; one before moves them', () => {
    const keys = NAMES.map((n) => entryKey(n)).sort();
    const find = (ok: (key: string) => boolean) => {
      for (let i = 0; ; i++)
        if (ok(entryKey(`n${i}.decoy-d.example`))) return `n${i}.decoy-d.example`;
    };
    const late = find((k) => k > keys.at(-1)!);
    const after = labelsBySni(
      relabelMemberEntries([...NAMES, late].map((n) => link(NODE_A, n)).join('\n'), NAMING).content,
    );
    for (const [sni, label] of first) expect(after.get(sni)).toBe(label);
    expect(after.get(late)).toBe(direct(4));
    // The tradeoff against the old fixed codes: a name sorted first moves the rest by one.
    const early = find((k) => k < keys[0]);
    const moved = labelsBySni(
      relabelMemberEntries([early, ...NAMES].map((n) => link(NODE_A, n)).join('\n'), NAMING)
        .content,
    );
    expect(moved.get(early)).toBe(direct(1));
    for (const sni of NAMES) expect(moved.get(sni)).toBe(directFor([early, ...NAMES], sni));
  });

  test('a node rename keeps every label (the number comes from the server name)', () => {
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

  test('the same server name under two nodes shares a number; the second takes (2)', () => {
    const entry = (node: string, k: string) => ({ name: addressRemark(node, k), entry: k });
    const plan = planEntryNames(
      [entry(NODE_A, NAMES[0]), entry(NODE_B, NAMES[0]), entry(NODE_A, NAMES[1])],
      new Set(),
      NAMING,
    );
    const one = directFor(NAMES.slice(0, 2), NAMES[0]);
    // Which of the two takes the suffix follows their old names (sorted): stable, not body order.
    expect(
      [plan.get(entry(NODE_A, NAMES[0]).name), plan.get(entry(NODE_B, NAMES[0]).name)].sort(),
    ).toEqual([one, `${one} (2)`]);
    expect(plan.get(entry(NODE_A, NAMES[1]).name)).toBe(directFor(NAMES.slice(0, 2), NAMES[1]));
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
    expect(entryNamingFrom({}, undefined)).toEqual({
      siteName: DEFAULT_SITE_NAME,
      place: null,
      country: null,
    });
    expect(entryNamingFrom({ 'subscription.entryNames': 'yes' }, 'Example City', 'ca')).toEqual({
      siteName: DEFAULT_SITE_NAME,
      place: 'Example City',
      country: 'CA',
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

  test('the flag is the country every node of the instance reports, else none', () => {
    expect(instanceCountry(['CA', 'ca', undefined])).toBe('CA');
    expect(instanceCountry(['CA', 'NZ'])).toBeNull();
    expect(instanceCountry(['XX', undefined, ''])).toBeNull();
    expect(instanceCountry([])).toBeNull();
  });
});

describe('relabelMemberEntries: the backend’s groups', () => {
  const TEMPLATE_GROUP = '→ Remnawave';
  const SELECT = 'FreeSocks';
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

  test('sing-box from the backend’s template: the group is the site name, every reference follows', () => {
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
      [...tags].filter((t) => t.startsWith(BASE)),
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
    // What the edge renderer leaves: its named entry, its url-test group, both
    // inside the template group.
    const edge = EDGE;
    const auto = '⚡ Auto (fastest)';
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
    const doc = clashFromTemplate([clashProxy(EDGE, NAMES[0], '203.0.113.5')]);
    const out = relabelMemberEntries(YAML.stringify(doc), { siteName: 'Example VPN', place: null });
    const next = YAML.parse(out.content) as { 'proxy-groups': Obj[] };
    expect(next['proxy-groups'][0].name).toBe('Example VPN');
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
    const body = YAML.stringify(clashFromTemplate([clashProxy(EDGE, NAMES[0], '203.0.113.5')]));
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
      new Set(['proxy', 'Remnawave EU', TEMPLATE_GROUP, EDGE]),
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
      singboxBody('→ Remnawave', [vless(EDGE, NAMES[0])]),
      clashBody(NAMES.map((n) => addressRemark(NODE_A, n))),
      clashBody([EDGE]),
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
    // A backend the template re-sync has not reached yet still names its cache
    // after the product: the same word as the group.
    const body = JSON.parse(singboxBody('remnawave', [vless(EDGE, NAMES[0])])) as {
      experimental: { cache_file: Obj };
    };
    const oldCache = {
      ...body.experimental.cache_file,
      path: 'remnawave.db',
      cache_id: 'remnawave',
    };
    body.experimental.cache_file = oldCache;
    const out = relabelMemberEntries(JSON.stringify(body), NAMING);
    expect(out.renamed).toBe(1);
    const cfg = JSON.parse(out.content) as {
      outbounds: Obj[];
      experimental: { cache_file: Obj };
    };
    expect(cfg.outbounds[0].tag).toBe('FreeSocks');
    expect(cfg.experimental.cache_file).toEqual(oldCache);
  });
});

describe('entryNamesOf (the admin preview)', () => {
  test('lists entries and groups in body order, in every format', () => {
    const naming: EntryNaming = { siteName: 'FreeSocks', place: 'Example City', country: 'CA' };
    const links = relabelMemberEntries(link(NODE_A, NAMES[0]), naming).content;
    expect(entryNamesOf(links)).toEqual({ entries: [BASE], groups: [] });
    expect(entryNamesOf(encodeBase64(links))).toEqual({ entries: [BASE], groups: [] });
    const sb = entryNamesOf(relabelMemberEntries(JSON.stringify(singbox(NODE_A)), naming).content);
    expect(sb.groups).toEqual(['proxy', 'auto']);
    expect(sb.entries).toHaveLength(3);
    const cl = entryNamesOf(relabelMemberEntries(clash(NODE_A), naming).content);
    expect(cl.groups).toEqual(['proxy', 'auto']);
    expect(cl.entries.every((e) => e.startsWith(BASE))).toBe(true);
    expect(entryNamesOf(JSON.stringify([{ remarks: EDGE }]))).toEqual({
      entries: [EDGE],
      groups: [],
    });
    expect(entryNamesOf('<html>')).toEqual({ entries: [], groups: [] });
  });
});
