/**
 * The country page's sections: `?section=` picks one (Summary otherwise), the
 * address picker lists each edge once, and the Summary lines read plainly.
 */
import { describe, expect, it } from 'vitest';
import type {
  CountryMarkRow,
  CountryViewAddress,
  CountryViewMeantFor,
  CountryViewOrigin,
  CountryViewTotals,
} from '@shared/contracts/edges';
import { edgesPaths, resolveEdgesRoute } from '../lib/routes';
import {
  COUNTRY_SECTIONS,
  addressesDigest,
  checksDigest,
  countrySectionOf,
  exitDigest,
  markableAddresses,
  snisDigest,
} from './sections';

const totals = (over: Partial<CountryViewTotals> = {}): CountryViewTotals => ({
  addresses: { proven: 2, blocked: 1, unknown: 0 },
  names: { proven: 3, blocked: 1, unknown: 2 },
  originsAtRisk: 0,
  lastEvidenceAt: null,
  ...over,
});

const address = (edgeId: string | null, addr: string, kind: 'edge' | 'origin' = 'edge') =>
  ({ edgeId, kind, address: addr }) as unknown as CountryViewAddress;

const origin = (
  slug: string,
  listeners: Array<{ key: string; addresses: CountryViewAddress[] }>,
  label: string | null = null,
) =>
  ({
    slug,
    label,
    nodeName: null,
    listeners: listeners.map((l) => ({
      ...l,
      listenerId: l.key,
      names: [],
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
    })),
  }) as unknown as CountryViewOrigin;

describe('?section=', () => {
  it('picks a known section, else Summary', () => {
    expect(countrySectionOf('checks')).toBe('checks');
    expect(countrySectionOf('exit')).toBe('exit');
    expect(countrySectionOf(null)).toBe('summary');
    expect(countrySectionOf('')).toBe('summary');
    expect(countrySectionOf('nope')).toBe('summary');
  });

  it('runs in the order the design gives', () => {
    expect(COUNTRY_SECTIONS.map((s) => s.label)).toEqual([
      'Summary',
      'Addresses for this country',
      'SNIs',
      'Lists',
      'Probes',
      'Checks from here',
      'Exit',
    ]);
  });

  it('is a search param on the country page, which still resolves to the country', () => {
    const href = edgesPaths.country('ir', { section: 'checks' });
    expect(href).toBe('/admin/servers/countries/IR?section=checks');
    expect(edgesPaths.country('IR', { section: null })).toBe('/admin/servers/countries/IR');
    expect(resolveEdgesRoute(href.split('?')[0]!)).toEqual({ page: 'country', code: 'IR' });
  });
});

describe('the address picker', () => {
  const marks: CountryMarkRow[] = [
    { scope: 'edge', edgeId: 'e2', groupKey: null, country: 'AA', state: 'blocked', at: null },
    { scope: 'edge', edgeId: 'e1', groupKey: null, country: 'BB', state: 'proven', at: null },
  ];
  const origins = [
    origin(
      'n1',
      [
        {
          key: '443',
          addresses: [address('e1', 'a.example'), address(null, '192.0.2.1', 'origin')],
        },
        { key: '8443', addresses: [address('e1', 'a.example'), address('e2', 'b.example')] },
      ],
      'Node one',
    ),
    origin('n2', [{ key: '443', addresses: [address('e3', 'c.example')] }]),
  ];

  it('lists each edge address once, in page order, never the node itself', () => {
    const got = markableAddresses(origins, marks, 'AA');
    expect(got.map((a) => a.edgeId)).toEqual(['e1', 'e2', 'e3']);
    expect(got[0]!.where).toBe('Node one · VLESS · raw · REALITY');
    expect(got[2]!.where).toBe('n2 · VLESS · raw · REALITY');
  });

  it("shows only this country's own mark", () => {
    const got = markableAddresses(origins, marks, 'AA');
    expect(got.find((a) => a.edgeId === 'e1')!.mark).toBeNull();
    expect(got.find((a) => a.edgeId === 'e2')!.mark).toBe('blocked');
  });
});

describe('Summary lines', () => {
  const loc = (blocked: boolean) => ({ blocked }) as CountryViewMeantFor;

  it('addresses: nodes at risk and the locations set for the country', () => {
    expect(addressesDigest(totals(), [])).toBe('No location is set for this country.');
    expect(addressesDigest(totals({ originsAtRisk: 2 }), [loc(false)])).toBe(
      '2 nodes have no working address here. 1 location is set for it.',
    );
    expect(addressesDigest(totals(), [loc(true), loc(false)])).toBe(
      '1 of 2 locations set for it is blocked here.',
    );
  });

  it('SNIs', () => {
    expect(snisDigest(totals())).toBe('3 work here, 1 blocked, 2 not judged.');
    expect(snisDigest(totals({ names: { proven: 0, blocked: 0, unknown: 0 } }))).toBe(
      'No SNI in use.',
    );
  });

  it('checks', () => {
    expect(checksDigest(null)).toContain('Not on the censored-country list');
    expect(checksDigest({ checkEdges: true, checkNamesInside: false })).toBe(
      'Edges are checked from here. SNIs are not checked from inside.',
    );
    // On for the country, but no source runs: the digest says so, as the Checks section does.
    expect(checksDigest({ checkEdges: true, checkNamesInside: true, nameChecksRun: false })).toBe(
      'Edges are checked from here. SNI checks from inside are on, but none runs now.',
    );
  });

  it('exit', () => {
    expect(exitDigest([], true)).toBe('Least-loaded location.');
    expect(exitDigest(['Alpha', 'Beta'], true)).toBe('Alpha, then Beta.');
    expect(exitDigest(['Alpha'], false)).toContain('ordering by country is off');
  });

  it('carry no dash and no "meant for"', () => {
    const all = [
      addressesDigest(totals({ originsAtRisk: 1 }), [loc(true)]),
      snisDigest(totals()),
      checksDigest(null),
      exitDigest(['A'], false),
      ...COUNTRY_SECTIONS.map((s) => s.label),
    ];
    for (const s of all) {
      expect(s).not.toMatch(/[–—]/);
      expect(s).not.toMatch(/meant for/i);
    }
  });
});
