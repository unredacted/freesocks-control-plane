import { describe, expect, it } from 'vitest';
import { newTokenHref, parseNewTokenParams } from './tokenPrefill';

const parse = (href: string) => parseNewTokenParams(new URL(href, 'https://x.test').searchParams);

describe('new-token deep link', () => {
  it('round-trips a scope and a name', () => {
    const href = newTokenHref({ scope: 'admin:edges:register', name: 'node role: origin-a' });
    expect(href.startsWith('/admin/tokens?new=1&')).toBe(true);
    expect(parse(href)).toMatchObject({
      scopes: ['admin:edges:register'],
      name: 'node role: origin-a',
    });
  });

  it('does nothing without new=1', () => {
    expect(parse('/admin/tokens?scope=admin:edges:register')).toBeNull();
    expect(parse('/admin/tokens')).toBeNull();
  });

  it('ignores unknown scopes, dedupes, and caps the name', () => {
    const got = parse(
      `/admin/tokens?new=1&scope=admin:root,admin:status:read&scope=admin:status:read&name=${'n'.repeat(300)}`,
    );
    expect(got?.scopes).toEqual(['admin:status:read']);
    expect(got?.name.length).toBe(128);
  });

  it('opens an empty dialog when only new=1 is given', () => {
    expect(parse('/admin/tokens?new=1')).toMatchObject({ scopes: [], name: '' });
  });

  it('carries the registration boundary presets (deduped, empty entries dropped)', () => {
    const href = newTokenHref({
      scope: 'admin:edges:register',
      servers: ['srv1', 'srv2'],
      nodes: ['node-one'],
    });
    const parsed = parseNewTokenParams(new URL(href, 'https://fcp.example').searchParams);
    expect(parsed).toMatchObject({ servers: ['srv1', 'srv2'], nodes: ['node-one'] });
    expect(parseNewTokenParams(new URLSearchParams('new=1&servers=a,,a,b&nodes='))).toMatchObject({
      servers: ['a', 'b'],
      nodes: [],
    });
  });
});
