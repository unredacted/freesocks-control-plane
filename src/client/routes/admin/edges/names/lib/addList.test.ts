import { describe, expect, test } from 'vitest';
import { createBody, draftFrom, draftProblem, slugFor, slugProblem } from './addList';

describe('slugFor', () => {
  test('a cover site suggests its short id', () => {
    expect(slugFor('www.example.co.uk')).toBe('example-co-uk');
    expect(slugFor(' Site.Example:8443 ')).toBe('site-example');
    expect(slugFor('192.0.2.1')).toBe('192-0-2-1');
    expect(slugFor('')).toBe('');
    expect(slugFor(`${'a'.repeat(39)}.example`)).toBe('a'.repeat(39));
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
  test('the first problem, in the order of the form', () => {
    expect(draftProblem({ ...ok, label: ' ' })).toBe('Give the list a name.');
    expect(draftProblem({ ...ok, slug: 'find' })).toMatch(/address of an SNIs page/);
    expect(draftProblem({ ...ok, coverSite: 'localhost' })).toMatch(/^The cover site/);
    expect(draftProblem({ ...ok, coverSite: 'a site.example' })).toMatch(/^The cover site/);
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
});
