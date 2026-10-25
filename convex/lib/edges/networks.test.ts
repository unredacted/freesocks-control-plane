/**
 * Networks (lib/edges/networks.ts): membership is local, against ranges only.
 * Fixtures use documentation ranges (RFC 5737, RFC 3849) and private ASNs.
 */
import { describe, expect, test } from 'vitest';
import {
  allOnNetwork,
  announcedPrefixesUrl,
  edgeNetworkVerdict,
  mergePrefixes,
  normalizeAsn,
  normalizePrefix,
  onNetwork,
  parseAnnouncedPrefixes,
  qualificationNetworkCode,
} from './networks';

const NET = { v4: ['192.0.2.0/24', '198.51.100.0/25'], v6: ['2001:db8:10::/48'] };

describe('ASNs and ranges', () => {
  test('an ASN in any of the usual spellings', () => {
    expect(normalizeAsn('AS64500')).toBe(64500);
    expect(normalizeAsn('as64500')).toBe(64500);
    expect(normalizeAsn(64500)).toBe(64500);
    expect(normalizeAsn(' 64500 ')).toBe(64500);
    for (const bad of ['', 'AS', 'AS-1', '0', 'x64500', 4_294_967_296, 1.5, null])
      expect(normalizeAsn(bad)).toBeNull();
  });
  test('a range is an address and a length', () => {
    expect(normalizePrefix('192.0.2.0/24')).toBe('192.0.2.0/24');
    expect(normalizePrefix('2001:DB8::/32')).toBe('2001:db8:0:0:0:0:0:0/32');
    expect(normalizePrefix('192.0.2.1')).toBeNull();
    expect(normalizePrefix('192.0.2.0/33')).toBeNull();
    expect(normalizePrefix(7)).toBeNull();
  });
  test('merged: split by family, deduplicated, sorted, capped', () => {
    const m = mergePrefixes([
      ['198.51.100.0/25', '192.0.2.0/24', 'junk', '2001:db8:10::/48'],
      ['192.0.2.0/24'],
    ]);
    expect(m).toEqual({
      v4: ['192.0.2.0/24', '198.51.100.0/25'],
      v6: ['2001:db8:10:0:0:0:0:0/48'],
      truncated: false,
    });
    const capped = mergePrefixes([['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']], 2);
    expect(capped.v4).toHaveLength(2);
    expect(capped.truncated).toBe(true);
  });
});

describe('membership', () => {
  test('an address is on the network when a range of its own family holds it', () => {
    expect(onNetwork('192.0.2.77', NET)).toBe(true);
    expect(onNetwork('198.51.100.127', NET)).toBe(true);
    expect(onNetwork('198.51.100.128', NET)).toBe(false);
    expect(onNetwork('2001:db8:10:ff::1', NET)).toBe(true);
    expect(onNetwork('[2001:db8:10::1]', NET)).toBe(true);
    expect(onNetwork('2001:db8:11::1', NET)).toBe(false);
    expect(onNetwork('203.0.113.9', NET)).toBe(false);
    expect(onNetwork('site.example', NET)).toBe(false);
  });
  test('all on it: at least one, and every one', () => {
    expect(allOnNetwork(['192.0.2.1', '2001:db8:10::1'], NET)).toBe(true);
    expect(allOnNetwork(['192.0.2.1', '203.0.113.1'], NET)).toBe(false);
    expect(allOnNetwork([], NET)).toBe(false);
  });
  test('an edge: every address it serves, unknown without one or without ranges', () => {
    expect(edgeNetworkVerdict({ v4: '192.0.2.5' }, NET)).toBe('on');
    expect(edgeNetworkVerdict({ v4: '192.0.2.5', v6: '2001:db8:10::5' }, NET)).toBe('on');
    // Its IPv6 entry would show a name next to an address of another network.
    expect(edgeNetworkVerdict({ v4: '192.0.2.5', v6: '2001:db8:99::5' }, NET)).toBe('off');
    expect(edgeNetworkVerdict({ v4: '203.0.113.5' }, NET)).toBe('off');
    expect(edgeNetworkVerdict({}, NET)).toBe('unknown');
    expect(edgeNetworkVerdict({ v4: '192.0.2.5' }, { v4: [], v6: [] })).toBe('unknown');
    expect(edgeNetworkVerdict({ v4: '192.0.2.5' }, null)).toBe('unknown');
  });
  test('qualification: the target first, then the name', () => {
    expect(qualificationNetworkCode(['192.0.2.1'], ['192.0.2.9', '2001:db8:10::9'], NET)).toBe(
      null,
    );
    expect(qualificationNetworkCode(['203.0.113.1'], ['192.0.2.9'], NET)).toBe(
      'q_target_off_network',
    );
    expect(qualificationNetworkCode(['192.0.2.1'], ['192.0.2.9', '203.0.113.9'], NET)).toBe(
      'q_off_network',
    );
    // A name that does not resolve is not a site on the network.
    expect(qualificationNetworkCode(['192.0.2.1'], [], NET)).toBe('q_off_network');
  });
});

describe('the announced-ranges answer', () => {
  test('parsed into ranges; anything else is an error, never an empty network', () => {
    expect(
      parseAnnouncedPrefixes({
        status: 'ok',
        data: { prefixes: [{ prefix: '192.0.2.0/24' }, { prefix: 'bad' }, {}] },
      }),
    ).toEqual({ ok: true, prefixes: ['192.0.2.0/24'] });
    expect(parseAnnouncedPrefixes({ data: { prefixes: [] } })).toEqual({ ok: true, prefixes: [] });
    for (const bad of [null, {}, { data: {} }, { data: { prefixes: 'x' } }])
      expect(parseAnnouncedPrefixes(bad)).toEqual({ ok: false, error: 'bad_answer' });
  });
  test('the request names the ASN and nothing else', () => {
    expect(announcedPrefixesUrl(64500)).toBe(
      'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500',
    );
  });
});
