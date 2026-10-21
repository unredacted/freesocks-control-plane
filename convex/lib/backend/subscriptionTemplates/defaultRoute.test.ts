import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { relabelMemberEntries } from '../../memberEntryNames';
import { addressRemark } from '../hostRemark';
import { CLASH_YAML } from './CLASH';
import { defaultRouteFaults } from './defaultRoute';
import { SUBSCRIPTION_TEMPLATES, TEMPLATE_FAMILIES, type TemplateFamily } from './index';
import { MIHOMO_YAML } from './MIHOMO';
import { SINGBOX_JSON } from './SINGBOX';

type Obj = Record<string, unknown>;

/** The selector group of every template FCP ships (renamed in what members receive). */
const TEMPLATE_GROUP = '→ Remnawave';
const NODE = 'quiet-amber-falcon';
const SNI = 'www.decoy-a.example';
const ENTRY = addressRemark(NODE, SNI);

const text = (family: TemplateFamily) => {
  const d = SUBSCRIPTION_TEMPLATES[family];
  return d.kind === 'yaml' ? d.body : JSON.stringify(d.body);
};

/** What the backend makes of a template for one key: one entry, spliced into the group. */
function memberBody(family: TemplateFamily): string {
  const d = SUBSCRIPTION_TEMPLATES[family];
  if (d.kind === 'json') {
    const cfg = JSON.parse(JSON.stringify(d.body)) as { outbounds: Obj[] };
    cfg.outbounds[0]!.outbounds = [ENTRY];
    cfg.outbounds.splice(1, 0, {
      type: 'vless',
      tag: ENTRY,
      server: '192.0.2.10',
      server_port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      tls: { enabled: true, server_name: SNI, reality: { enabled: true } },
    });
    return JSON.stringify(cfg);
  }
  const doc = YAML.parse(d.body) as { proxies: Obj[]; 'proxy-groups': Obj[] };
  doc.proxies = [
    {
      name: ENTRY,
      type: 'vless',
      server: '192.0.2.10',
      port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      servername: SNI,
      'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'ab' },
    },
  ];
  doc['proxy-groups'][0]!.proxies = [ENTRY];
  return YAML.stringify(doc);
}

describe('the default route of every template FCP ships', () => {
  test('the Clash and Mihomo templates route by rule', () => {
    // Global mode ignores `rules:` and sends a member's traffic through the
    // engine's GLOBAL group, which is DIRECT unless the member changes it.
    for (const body of [CLASH_YAML, MIHOMO_YAML]) {
      expect(body).toMatch(/^mode: rule$/m);
      expect((YAML.parse(body) as Obj).mode).toBe('rule');
    }
  });

  test('every template sends unmatched traffic to its proxy group', () => {
    for (const family of TEMPLATE_FAMILIES)
      expect(defaultRouteFaults(text(family), TEMPLATE_GROUP), family).toEqual([]);
  });

  test('so does the body a member receives from each, with the group renamed', () => {
    for (const family of TEMPLATE_FAMILIES) {
      const body = memberBody(family);
      expect(defaultRouteFaults(body, TEMPLATE_GROUP), family).toEqual([]);
      const served = relabelMemberEntries(body, { siteName: 'FreeSocks', place: null });
      expect(served.renamed, family).toBeGreaterThan(0);
      expect(defaultRouteFaults(served.content, 'FreeSocks Select'), family).toEqual([]);
    }
  });
});

describe('defaultRouteFaults', () => {
  const clash = (edit: (doc: Obj & { rules: string[]; 'proxy-groups': Obj[] }) => void) => {
    const doc = YAML.parse(memberBody('MIHOMO')) as Obj & {
      rules: string[];
      'proxy-groups': Obj[];
    };
    edit(doc);
    return YAML.stringify(doc);
  };
  const singbox = (edit: (cfg: Obj & { outbounds: Obj[]; route: Obj }) => void) => {
    const cfg = JSON.parse(memberBody('SINGBOX')) as Obj & { outbounds: Obj[]; route: Obj };
    edit(cfg);
    return JSON.stringify(cfg);
  };

  test('a Clash body that does not route by rule', () => {
    expect(defaultRouteFaults(MIHOMO_YAML.replace('mode: rule', 'mode: global'))).toEqual([
      'mode is "global", not rule',
    ]);
    expect(defaultRouteFaults(clash((d) => (d.mode = 'direct')))).toEqual([
      'mode is "direct", not rule',
    ]);
    expect(defaultRouteFaults(clash((d) => delete d.mode))).toEqual(['mode is null, not rule']);
    expect(defaultRouteFaults(clash((d) => (d.mode = 'Rule')))).toEqual([]);
  });

  test('a Clash body whose catch-all is missing, early, or not the proxy group', () => {
    expect(
      defaultRouteFaults(clash((d) => (d.rules = ['DOMAIN-SUFFIX,example.org,DIRECT']))),
    ).toEqual(['no MATCH rule: unmatched traffic goes DIRECT']);
    expect(defaultRouteFaults(clash((d) => (d.rules = ['MATCH,DIRECT'])))).toEqual([
      'MATCH goes to DIRECT, not a proxy group',
    ]);
    expect(defaultRouteFaults(clash((d) => (d.rules = ['MATCH,GLOBAL'])))).toEqual([
      'MATCH goes to GLOBAL, not a proxy group',
    ]);
    expect(
      defaultRouteFaults(clash((d) => d.rules.push('DOMAIN-SUFFIX,example.org,DIRECT'))),
    ).toEqual(['MATCH is not the one last rule']);
    expect(defaultRouteFaults(memberBody('MIHOMO'), 'FreeSocks Select')).toEqual([
      `MATCH goes to ${TEMPLATE_GROUP}, not FreeSocks Select`,
    ]);
  });

  test('a Clash proxy group that reaches DIRECT by default', () => {
    const first = clash((d) => (d['proxy-groups'][0]!.proxies = ['DIRECT', ENTRY]));
    expect(defaultRouteFaults(first)).toEqual([`${TEMPLATE_GROUP} reaches DIRECT by default`]);
    // A member may still pick DIRECT by hand; it is just never the default.
    expect(
      defaultRouteFaults(clash((d) => (d['proxy-groups'][0]!.proxies = [ENTRY, 'DIRECT']))),
    ).toEqual([]);
    const nested = clash((d) => {
      d['proxy-groups'][0]!.proxies = ['Auto'];
      d['proxy-groups'].push({ name: 'Auto', type: 'url-test', proxies: [ENTRY, 'DIRECT'] });
    });
    expect(defaultRouteFaults(nested)).toEqual([`${TEMPLATE_GROUP} reaches DIRECT by default`]);
  });

  test('a sing-box body whose default outbound is not the proxy group', () => {
    expect(defaultRouteFaults(singbox((c) => (c.route.final = 'direct')))).toEqual([
      'the default outbound is direct, not a proxy group',
    ]);
    expect(defaultRouteFaults(singbox((c) => c.outbounds.reverse()))).toEqual([
      'the default outbound is direct, not a proxy group',
    ]);
    expect(defaultRouteFaults(singbox((c) => (c.route.final = ENTRY)))).toEqual([
      `the default outbound is ${ENTRY}, not a proxy group`,
    ]);
    expect(defaultRouteFaults(singbox((c) => (c.route.final = 'missing')))).toEqual([
      'the default outbound is missing, not a proxy group',
    ]);
    expect(defaultRouteFaults(JSON.stringify({ outbounds: [] }))).toEqual([
      'the default outbound is missing, not a proxy group',
    ]);
    // An explicit final to the group is as good as the group first.
    expect(
      defaultRouteFaults(
        singbox((c) => {
          c.outbounds.reverse();
          c.route.final = TEMPLATE_GROUP;
        }),
        TEMPLATE_GROUP,
      ),
    ).toEqual([]);
  });

  test('a sing-box group that reaches direct by default, or a clash API not in rule mode', () => {
    const chosen = singbox((c) => {
      c.outbounds[0]!.outbounds = [ENTRY, 'direct'];
      c.outbounds[0]!.default = 'direct';
    });
    expect(defaultRouteFaults(chosen)).toEqual([`${TEMPLATE_GROUP} reaches direct by default`]);
    const auto = singbox((c) => {
      c.outbounds[0]!.type = 'urltest';
      c.outbounds[0]!.outbounds = [ENTRY, 'direct'];
    });
    expect(defaultRouteFaults(auto)).toEqual([`${TEMPLATE_GROUP} reaches direct by default`]);
    const global = singbox((c) => {
      (c.experimental as { clash_api: Obj }).clash_api.default_mode = 'global';
    });
    expect(defaultRouteFaults(global)).toEqual(['clash_api default_mode is "global", not rule']);
    expect(SINGBOX_JSON.experimental.clash_api.default_mode).toBe('rule');
  });

  test('a body that is neither format', () => {
    expect(defaultRouteFaults('{not json')).toEqual(['not JSON']);
    expect(defaultRouteFaults('[]')).toEqual(['not a Clash config']);
    expect(defaultRouteFaults('vless://x@192.0.2.1:443')).toEqual(['not a Clash config']);
  });
});
