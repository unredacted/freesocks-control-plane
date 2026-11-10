import { describe, expect, test } from 'vitest';
import {
  coverSiteKind,
  createBody,
  draftFrom,
  draftProblem,
  seedFrom,
  slugFor,
  slugProblem,
} from './addList';
import { SNI_LIST_SLUG, sniListSlugFor } from '../../../../../../shared/contracts/sni';

describe('slugFor', () => {
  test('a cover site suggests its short id', () => {
    expect(slugFor('www.example.co.uk')).toBe('example-co-uk');
    expect(slugFor(' Site.Example:8443 ')).toBe('site-example');
    expect(slugFor('192.0.2.1')).toBe('192-0-2-1');
    expect(slugFor('')).toBe('');
    expect(slugFor(`${'a'.repeat(39)}.example`)).toBe('a'.repeat(39));
  });

  test('an IPv6 literal keeps its last group; only a bracketed one has a port', () => {
    expect(slugFor('2001:db8::1')).toBe('2001-db8-1');
    expect(slugFor('[2001:db8::1]')).toBe('2001-db8-1');
    expect(slugFor('[2001:db8::1]:8443')).toBe('2001-db8-1');
    expect(slugFor('192.0.2.1:8443')).toBe('192-0-2-1');
  });
});

describe('sniListSlugFor: the one rule for a suggested short id and for a rename', () => {
  test("a list's name gives its slug the way a cover site does", () => {
    expect(sniListSlugFor('  Shared cover A  ')).toBe('shared-cover-a');
    // The name the dialog suggests for a cover site gives the slug it suggests.
    expect(sniListSlugFor('site.example')).toBe(slugFor('www.site.example'));
    expect(sniListSlugFor('A / B: second')).toBe('a-b-second');
    expect(sniListSlugFor('x'.repeat(60))).toBe('x'.repeat(40));
    // No letter or digit: no slug (the server refuses such a rename).
    expect(sniListSlugFor(' *** ')).toBe('');
    for (const name of ['Shared cover A', 'site.example', 'x'.repeat(60), '9 lives'])
      expect(sniListSlugFor(name)).toMatch(SNI_LIST_SLUG);
  });
});

describe('coverSiteKind', () => {
  test('a hostname, or an IP literal of either family', () => {
    expect(coverSiteKind('site.example')).toBe('hostname');
    expect(coverSiteKind(' www.site.example ')).toBe('hostname');
    expect(coverSiteKind('192.0.2.1')).toBe('ipv4');
    expect(coverSiteKind('2001:db8::1')).toBe('ipv6');
    expect(coverSiteKind('[2001:db8::1]')).toBe('ipv6');
    expect(coverSiteKind('2001:db8:0:0:0:0:0:1')).toBe('ipv6');
    expect(coverSiteKind('::ffff:192.0.2.1')).toBe('ipv6');
  });

  test('anything else is none of them', () => {
    for (const bad of [
      '',
      'localhost',
      'a site.example',
      'site.example/path',
      '1.2.3',
      '256.0.0.1',
      '2001:db8:::1',
      '2001:db8::1::2',
      '12345::1',
      'site.example:443:1',
    ])
      expect(coverSiteKind(bad)).toBeNull();
  });
});

describe('draftFrom', () => {
  test('blank: port 443, anywhere, HTTP/2 not required', () => {
    expect(draftFrom()).toEqual({
      label: '',
      slug: '',
      coverSite: '',
      port: '443',
      requireH2: false,
      network: '',
    });
  });

  test('a found site suggests the name and the short id; what is given wins', () => {
    expect(draftFrom({ coverSite: 'www.site.example', requireH2: true, network: 'net-a' })).toEqual(
      {
        label: 'site.example',
        slug: 'site-example',
        coverSite: 'www.site.example',
        port: '443',
        requireH2: true,
        network: 'net-a',
      },
    );
    expect(
      draftFrom({ coverSite: 'site.example', label: 'Mine', slug: 'mine', port: 8443 }),
    ).toMatchObject({ label: 'Mine', slug: 'mine', port: '8443' });
  });
});

describe('slugProblem', () => {
  test('lowercase letters, digits and dashes, never an SNIs page', () => {
    expect(slugProblem('site-example')).toBeNull();
    expect(slugProblem('')).toBe('Give it a short id.');
    expect(slugProblem('Site')).toMatch(/^Lowercase/);
    expect(slugProblem('-site')).toMatch(/^Lowercase/);
    expect(slugProblem('a'.repeat(41))).toMatch(/^Lowercase/);
    for (const page of ['find', 'checks', 'settings'])
      expect(slugProblem(page)).toBe(`"${page}" is the address of an SNIs page. Pick another.`);
  });
});

describe('draftProblem', () => {
  const ok = draftFrom({ coverSite: 'site.example' });
  test('a complete draft passes', () => expect(draftProblem(ok)).toBeNull());
  test('an IP literal is a cover site too, IPv6 included (as a seed may give it)', () => {
    expect(draftProblem(draftFrom({ coverSite: '192.0.2.1' }))).toBeNull();
    expect(draftProblem(draftFrom({ coverSite: '2001:db8::1' }))).toBeNull();
    expect(draftProblem(draftFrom({ coverSite: '[2001:db8::1]' }))).toBeNull();
  });
  test('the first problem, in the order of the form', () => {
    expect(draftProblem({ ...ok, label: ' ' })).toBe('Give the list a name.');
    expect(draftProblem({ ...ok, slug: 'find' })).toMatch(/address of an SNIs page/);
    expect(draftProblem({ ...ok, coverSite: 'localhost' })).toMatch(/^The cover site/);
    expect(draftProblem({ ...ok, coverSite: 'a site.example' })).toMatch(/^The cover site/);
    expect(draftProblem({ ...ok, coverSite: '1.2.3' })).toMatch(/^The cover site/);
    expect(draftProblem({ ...ok, port: '0' })).toBe('The port is a number from 1 to 65535.');
    expect(draftProblem({ ...ok, port: '70000' })).toBe('The port is a number from 1 to 65535.');
    expect(draftProblem({ ...ok, port: '44a' })).toBe('The port is a number from 1 to 65535.');
  });
  test('no dash of any kind in the words', () => {
    const words = [
      draftProblem({ ...ok, label: '' }),
      slugProblem(''),
      slugProblem('X'),
      slugProblem('find'),
      draftProblem({ ...ok, coverSite: '' }),
      draftProblem({ ...ok, port: '' }),
    ];
    for (const w of words) expect(w).not.toMatch(/[–—]/);
  });
});

describe('createBody', () => {
  test('trimmed, the port a number, the network only when one is picked', () => {
    const d = { ...draftFrom({ coverSite: ' site.example ' }), slug: ' site ', label: ' Site ' };
    expect(createBody(d)).toEqual({
      slug: 'site',
      label: 'Site',
      targetAddress: 'site.example',
      targetPort: 443,
      requireH2: false,
    });
    expect(createBody({ ...d, network: 'net-a' }).network).toBe('net-a');
  });

  test('an IPv6 cover site is sent bare, as the server reads it', () => {
    const d = draftFrom({ coverSite: '[2001:db8::1]' });
    expect(createBody(d).targetAddress).toBe('2001:db8::1');
    expect(createBody(draftFrom({ coverSite: '2001:db8::1' })).targetAddress).toBe('2001:db8::1');
  });
});

describe('seedFrom', () => {
  test("a seed's list: every value from the seed, its short id locked", () => {
    const from = seedFrom({
      slug: 'seed-list',
      label: 'Seed list',
      targetAddress: '2001:db8::1',
      targetPort: 443,
      requireH2: true,
      network: 'net-a',
      names: ['a.site.example'],
    });
    expect(from).toEqual({
      kind: 'site',
      lockSlug: true,
      prefill: {
        slug: 'seed-list',
        label: 'Seed list',
        coverSite: '2001:db8::1',
        port: 443,
        requireH2: true,
        network: 'net-a',
      },
    });
    expect(from.kind === 'site' && draftProblem(draftFrom(from.prefill))).toBeNull();
  });
});
