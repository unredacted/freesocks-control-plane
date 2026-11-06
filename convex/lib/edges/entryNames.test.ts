/**
 * The names members read in their apps (src/shared/entryNames.ts), end to end:
 * every case of the scheme rendered by the edge renderer and finished by the
 * member relabel step, in each format a member body comes in (a link list,
 * sing-box JSON, Mihomo / Clash YAML). An Xray JSON config list carries direct
 * entries only (the renderer refuses it, last test here); its direct names are
 * covered with the other formats in lib/memberEntryNames.test.ts.
 */
import { describe, expect, test } from 'vitest';
import {
  AUTO_GROUP_NAME,
  entryBase,
  entryName,
  flagEmoji,
  placeCountry,
  placeLetter,
  subscriptionTitle,
  type MemberPlace,
} from '../../../src/shared/entryNames';
import { EDGE_DEFAULTS, defaultClientRule } from '../edgeConfig';
import { entryNamesOf, relabelMemberEntries } from '../memberEntryNames';
import type { AssignedEndpoint, PublishedEdge } from './assignment';
import { previewBody } from './preview';
import type { ListenerProto } from './protocols';
import { effectiveRule, renderEdgeEndpoints } from './render';

const TEMPLATE = 'node-a-relay-a1';
const ORIGIN = '192.0.2.10';
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const RULES = {
  links: effectiveRule(cfg, defaultClientRule('v2rayng')),
  'singbox-json': effectiveRule(cfg, defaultClientRule('singbox')),
  'clash-yaml': effectiveRule(cfg, defaultClientRule('mihomo')),
} as const;
type Format = keyof typeof RULES;
const FORMATS = Object.keys(RULES) as Format[];

const CITY = { name: 'Example City', country: 'BR' };
const TOWN = { name: 'Example Town', country: 'NZ' };

function l4(
  id: string,
  over: Partial<PublishedEdge> & Pick<PublishedEdge, 'addresses'>,
): PublishedEdge {
  return {
    edgeId: id,
    poolIndex: 0,
    provider: 'example',
    listenerId: 'l1',
    listenerKey: 'a1',
    matchRule: { kind: 'remark', remark: TEMPLATE },
    proto: REALITY,
    edgePort: 443,
    serverNames: [{ sni: 'cdn-a.example', status: 'active' }],
    ...over,
  };
}
function l7(id: string, hostname: string): PublishedEdge {
  return {
    ...l4(id, { addresses: { hostname } }),
    proto: WS,
    layer: 'l7',
    serverNames: [],
    // A front's location never names it (the renderer reads no place for L7).
    memberPlace: TOWN,
  };
}
const at = (
  role: 'primary' | 'backup',
  edge: PublishedEdge,
  alternates?: string[],
): AssignedEndpoint => ({
  role,
  edge,
  sni: edge.addresses.hostname ?? 'cdn-a.example',
  hostHeader: edge.addresses.hostname ?? null,
  ...(alternates ? { alternates: alternates.map((sni) => ({ sni, hostHeader: null })) } : {}),
});

/** What a member's app lists for the body FCP serves: rendered, then relabelled. */
function served(
  format: Format,
  primary: AssignedEndpoint,
  backup: AssignedEndpoint | null = null,
  exit: MemberPlace | null = null,
): { entries: string[]; groups: string[] } {
  const proto = primary.edge.proto;
  const out = renderEdgeEndpoints({
    body: previewBody(format, [TEMPLATE], proto),
    matchers: [
      {
        listenerKey: 'a1',
        rule: { kind: 'remark', remark: TEMPLATE },
        proto,
        originAddress: ORIGIN,
        originPort: 443,
      },
    ],
    assigned: { primary, backup },
    rule: RULES[format],
    originAddress: ORIGIN,
    exit,
  });
  expect(out.delivery, format).toEqual({ kind: 'serve' });
  const names = entryNamesOf(
    relabelMemberEntries(out.body, { siteName: 'FreeSocks', place: null }).content,
  );
  // Unique within the body, whatever the case.
  const all = [...names.entries, ...names.groups];
  expect(new Set(all).size, format).toBe(all.length);
  return names;
}

/** The same names in every format; the link list in exactly this order. */
function expectEverywhere(
  primary: AssignedEndpoint,
  backup: AssignedEndpoint | null,
  links: string[],
  exit: MemberPlace | null = null,
): void {
  expect(served('links', primary, backup, exit).entries).toEqual(links);
  for (const format of ['singbox-json', 'clash-yaml'] as const)
    expect(served(format, primary, backup, exit).entries.sort(), format).toEqual([...links].sort());
}

describe('the naming function', () => {
  test('flags are regional-indicator pairs; private-use codes draw none', () => {
    expect(flagEmoji('br')).toBe('🇧🇷');
    expect(flagEmoji('CA')).toBe('🇨🇦');
    // Private use, unassigned, withdrawn, malformed: no country, no flag.
    for (const c of ['XX', 'ZZ', 'AA', 'QM', 'QZ', 'AB', 'AN', 'T1', 'USA', '', null]) {
      expect(placeCountry(c), String(c)).toBeNull();
      expect(flagEmoji(c), String(c)).toBeNull();
    }
    expect(placeCountry(' nz ')).toBe('NZ');
  });

  test('every route and form', () => {
    const us = { name: 'Example City', country: 'CA' };
    expect(entryBase({ kind: 'direct', place: us, n: 1 })).toBe('🇨🇦 Example City · Direct');
    expect(entryBase({ kind: 'direct', place: us, n: 2 })).toBe('🇨🇦 Example City · Direct 2');
    expect(entryBase({ kind: 'relay', place: CITY, letter: null })).toBe('🇧🇷 via Example City');
    expect(entryBase({ kind: 'relay', place: CITY, letter: 'B' })).toBe('🇧🇷 via Example City B');
    expect(
      entryBase({ kind: 'relay', place: { name: 'Example City', country: null }, letter: null }),
    ).toBe('via Example City');
    // No member-facing name: no flag either, always a letter.
    expect(entryBase({ kind: 'relay', place: { name: null, country: 'BR' }, letter: null })).toBe(
      'via relay A',
    );
    expect(entryBase({ kind: 'cdn', n: 2 })).toBe('🌐 via CDN 2');
    const r = { kind: 'relay' as const, place: CITY, letter: null };
    expect(entryName(r, { form: 'domain' })).toBe('🇧🇷 via Example City · Domain');
    expect(entryName(r, { form: 'ipv4', spare: 2 })).toBe('🇧🇷 via Example City · IPv4 #2');
    expect(entryName(r, { spare: 3 })).toBe('🇧🇷 via Example City #3');
    expect(placeLetter(0)).toBe('A');
    expect(placeLetter(25)).toBe('Z');
    expect(placeLetter(26)).toBe('AA');
    for (const name of [entryName(r, { form: 'ipv6' }), entryBase({ kind: 'cdn', n: 1 })]) {
      expect(name).not.toMatch(/[,|]/);
      expect(() => encodeURIComponent(name)).not.toThrow();
    }
  });

  test('the subscription title', () => {
    expect(subscriptionTitle('FreeSocks', 'Freedom XHTTP')).toBe('FreeSocks · Freedom XHTTP');
    expect(subscriptionTitle('FreeSocks', null)).toBe('FreeSocks');
  });
});

describe('Freedom through an L4 relay address', () => {
  const named = l4('eA', {
    addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
    addressName: 'shiny-orchestra.names.example',
    memberPlace: CITY,
  });

  test('a named address with IPv4 and IPv6: Domain, IPv4 and IPv6, in every format', () => {
    expectEverywhere(at('primary', named), null, [
      '🇧🇷 via Example City · Domain',
      '🇧🇷 via Example City · IPv4',
      '🇧🇷 via Example City · IPv6',
    ]);
  });

  test('no name, IPv4 and IPv6: IPv4 and IPv6', () => {
    const ips = l4('eA', {
      addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
      memberPlace: CITY,
    });
    expectEverywhere(at('primary', ips), null, [
      '🇧🇷 via Example City · IPv4',
      '🇧🇷 via Example City · IPv6',
    ]);
  });

  test('IPv4 only: one form, no tag', () => {
    const v4 = l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY });
    expectEverywhere(at('primary', v4), null, ['🇧🇷 via Example City']);
  });

  test('a location with no member-facing name: via relay A, no flag', () => {
    const bare = l4('eA', { addresses: { v4: '203.0.113.10', v6: '2001:db8::10' } });
    expectEverywhere(at('primary', bare), null, ['via relay A · IPv4', 'via relay A · IPv6']);
    // A country alone draws no flag.
    const countryOnly = l4('eA', {
      addresses: { v4: '203.0.113.10' },
      memberPlace: { country: 'BR' },
    });
    expectEverywhere(at('primary', countryOnly), null, ['via relay A']);
  });

  test('two addresses, one place: letters in body order; two unnamed: relay A and B', () => {
    const a = l4('eA', {
      addresses: { v4: '203.0.113.10' },
      addressName: 'a.names.example',
      memberPlace: CITY,
    });
    const b = l4('eB', {
      addresses: { v4: '203.0.113.20' },
      addressName: 'b.names.example',
      memberPlace: CITY,
    });
    expectEverywhere(at('primary', a), at('backup', b), [
      '🇧🇷 via Example City A · Domain',
      '🇧🇷 via Example City B · Domain',
      '🇧🇷 via Example City A · IPv4',
      '🇧🇷 via Example City B · IPv4',
    ]);
    const x = l4('eA', { addresses: { v4: '203.0.113.10' } });
    const y = l4('eB', { addresses: { v4: '203.0.113.20' } });
    expectEverywhere(at('primary', x), at('backup', y), ['via relay A', 'via relay B']);
    // Two places: no letter.
    const town = l4('eB', { addresses: { v4: '203.0.113.20' }, memberPlace: TOWN });
    expectEverywhere(at('primary', { ...a, addressName: undefined }), at('backup', town), [
      '🇧🇷 via Example City',
      '🇳🇿 via Example Town',
    ]);
  });

  test('spare server names, only where an auto group hides them: #2 on the form they dial', () => {
    const spares = ['cdn-c.example', 'cdn-d.example'];
    const cases: Array<[PublishedEdge, string[]]> = [
      [named, ['🇧🇷 via Example City · Domain #2', '🇧🇷 via Example City · Domain #3']],
      [
        l4('eA', { addresses: { v4: '203.0.113.10', v6: '2001:db8::10' }, memberPlace: CITY }),
        ['🇧🇷 via Example City · IPv4 #2', '🇧🇷 via Example City · IPv4 #3'],
      ],
      [
        l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY }),
        ['🇧🇷 via Example City #2', '🇧🇷 via Example City #3'],
      ],
    ];
    for (const [edge, want] of cases) {
      for (const format of ['singbox-json', 'clash-yaml'] as const) {
        const got = served(format, at('primary', edge, spares)).entries;
        expect(got.slice(-2), format).toEqual(want);
      }
      // A link list carries the first server name only: no spare.
      expect(
        served('links', at('primary', edge, spares)).entries.some((n) => n.includes('#')),
      ).toBe(false);
    }
  });
});

describe('Freedom through an L7 CDN front', () => {
  test('one front: 🌐 via CDN 1, one form, no place and no provider', () => {
    expectEverywhere(at('primary', l7('eF', 'front-a.example')), null, ['🌐 via CDN 1']);
  });

  test('two fronts: numbered in body order', () => {
    expectEverywhere(
      at('primary', l7('eF', 'front-a.example')),
      at('backup', l7('eG', 'front-b.example')),
      ['🌐 via CDN 1', '🌐 via CDN 2'],
    );
    // Backup first: the backup is the first front the body holds.
    const backupFirst = { ...RULES.links, order: 'backup-first' as const };
    const out = renderEdgeEndpoints({
      body: previewBody('links', [TEMPLATE], WS),
      matchers: [
        {
          listenerKey: 'a1',
          rule: { kind: 'remark', remark: TEMPLATE },
          proto: WS,
          originAddress: ORIGIN,
          originPort: 443,
        },
      ],
      assigned: {
        primary: at('primary', l7('eF', 'front-a.example')),
        backup: at('backup', l7('eG', 'front-b.example')),
      },
      rule: backupFirst,
      originAddress: ORIGIN,
    });
    const lines = out.body.split('\n');
    expect(lines[0]).toContain('front-b.example');
    expect(entryNamesOf(out.body).entries).toEqual(['🌐 via CDN 1', '🌐 via CDN 2']);
  });
});

describe("with the node's own place (the exit) leading every name", () => {
  const EXIT: MemberPlace = { name: 'Example Port', country: 'CA' };

  test('the naming function: exit first with its flag, then via the front', () => {
    expect(entryBase({ kind: 'relay', place: CITY, letter: null, exit: EXIT })).toBe(
      '🇨🇦 Example Port via Example City',
    );
    expect(entryBase({ kind: 'relay', place: CITY, letter: 'B', exit: EXIT })).toBe(
      '🇨🇦 Example Port via Example City B',
    );
    // The front's own country never shows a flag beside the exit's.
    expect(entryBase({ kind: 'relay', place: CITY, letter: null, exit: EXIT })).not.toContain('🇧🇷');
    expect(
      entryBase({ kind: 'relay', place: { name: null, country: 'BR' }, letter: null, exit: EXIT }),
    ).toBe('🇨🇦 Example Port via relay A');
    expect(entryBase({ kind: 'cdn', n: 2, exit: EXIT })).toBe('🇨🇦 Example Port via CDN 2');
    // An exit with no country: its name alone.
    expect(entryBase({ kind: 'cdn', n: 1, exit: { name: 'Example Port', country: null } })).toBe(
      'Example Port via CDN 1',
    );
    expect(
      entryName(
        { kind: 'relay', place: CITY, letter: null, exit: EXIT },
        { form: 'domain', spare: 2 },
      ),
    ).toBe('🇨🇦 Example Port via Example City · Domain #2');
  });

  test('an exit without a name is not shown: the name reads as before', () => {
    for (const exit of [null, undefined, { name: null, country: 'CA' }]) {
      expect(entryBase({ kind: 'relay', place: CITY, letter: null, exit })).toBe(
        '🇧🇷 via Example City',
      );
      expect(entryBase({ kind: 'cdn', n: 1, exit })).toBe('🌐 via CDN 1');
    }
  });

  test('an L4 address in every format: Domain, IPv4, IPv6', () => {
    const named = l4('eA', {
      addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
      addressName: 'shiny-orchestra.names.example',
      memberPlace: CITY,
    });
    expectEverywhere(
      at('primary', named),
      null,
      [
        '🇨🇦 Example Port via Example City · Domain',
        '🇨🇦 Example Port via Example City · IPv4',
        '🇨🇦 Example Port via Example City · IPv6',
      ],
      EXIT,
    );
  });

  test('two places, two letters, a location with no name', () => {
    const a = l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY });
    const b = l4('eB', { addresses: { v4: '203.0.113.20' }, memberPlace: CITY });
    const town = l4('eB', { addresses: { v4: '203.0.113.20' }, memberPlace: TOWN });
    const bare = l4('eB', { addresses: { v4: '203.0.113.20' } });
    expectEverywhere(
      at('primary', a),
      at('backup', b),
      ['🇨🇦 Example Port via Example City A', '🇨🇦 Example Port via Example City B'],
      EXIT,
    );
    expectEverywhere(
      at('primary', a),
      at('backup', town),
      ['🇨🇦 Example Port via Example City', '🇨🇦 Example Port via Example Town'],
      EXIT,
    );
    expectEverywhere(
      at('primary', a),
      at('backup', bare),
      ['🇨🇦 Example Port via Example City', '🇨🇦 Example Port via relay A'],
      EXIT,
    );
  });

  test('spare server names keep their #n', () => {
    const edge = l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY });
    for (const format of ['singbox-json', 'clash-yaml'] as const)
      expect(
        served(format, at('primary', edge, ['cdn-c.example']), null, EXIT).entries.slice(-1),
        format,
      ).toEqual(['🇨🇦 Example Port via Example City #2']);
  });

  test('CDN fronts: numbered after the exit, never the CDN or a place', () => {
    expectEverywhere(
      at('primary', l7('eF', 'front-a.example')),
      at('backup', l7('eG', 'front-b.example')),
      ['🇨🇦 Example Port via CDN 1', '🇨🇦 Example Port via CDN 2'],
      EXIT,
    );
  });

  test('groups keep their names', () => {
    const edge = l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY });
    for (const format of ['singbox-json', 'clash-yaml'] as const)
      expect(served(format, at('primary', edge), null, EXIT).groups.sort(), format).toEqual(
        [AUTO_GROUP_NAME, 'FreeSocks'].sort(),
      );
  });
});

describe('groups', () => {
  const edge = l4('eA', { addresses: { v4: '203.0.113.10' }, memberPlace: CITY });
  test('the url-test group is ⚡ Auto (fastest); the backend’s selector takes the bare site name', () => {
    for (const format of ['singbox-json', 'clash-yaml'] as const)
      expect(served(format, at('primary', edge)).groups.sort(), format).toEqual(
        [AUTO_GROUP_NAME, 'FreeSocks'].sort(),
      );
    expect(served('links', at('primary', edge)).groups).toEqual([]);
  });
});

describe('formats the renderer does not write', () => {
  test('an Xray JSON config list is refused under an edge (never named, never served)', () => {
    const out = renderEdgeEndpoints({
      body: JSON.stringify([{ remarks: TEMPLATE, outbounds: [] }]),
      matchers: [],
      assigned: {
        primary: at('primary', l4('eA', { addresses: { v4: '203.0.113.10' } })),
        backup: null,
      },
      rule: RULES.links,
      originAddress: ORIGIN,
    });
    // Read as a list with no share link in it: refused, whatever the reason says.
    expect(out.delivery.kind).toBe('unavailable');
  });
});
