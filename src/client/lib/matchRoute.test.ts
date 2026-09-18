import { describe, expect, test } from 'vitest';
import { matchRoute } from './matchRoute';

describe('matchRoute', () => {
  test('exact static paths match with empty params', () => {
    expect(matchRoute('/admin/edges', '/admin/edges')).toEqual({ params: {} });
    expect(matchRoute('/admin/edges', '/admin/edges/')).toEqual({ params: {} });
  });

  test('a static path never matches a longer or shorter one', () => {
    expect(matchRoute('/admin/edges', '/admin/edges/setup')).toBeNull();
    expect(matchRoute('/admin/edges/setup', '/admin/edges')).toBeNull();
    expect(matchRoute('/admin/edges', '/admin')).toBeNull();
  });

  test('a :param captures exactly one segment', () => {
    expect(matchRoute('/admin/edges/relays/:slug', '/admin/edges/relays/node-a')).toEqual({
      params: { slug: 'node-a' },
    });
    expect(matchRoute('/admin/edges/relays/:slug', '/admin/edges/relays')).toBeNull();
    expect(matchRoute('/admin/edges/relays/:slug', '/admin/edges/relays/a/b')).toBeNull();
  });

  test('several params and mixed static segments', () => {
    expect(matchRoute('/a/:x/b/:y', '/a/1/b/2')).toEqual({ params: { x: '1', y: '2' } });
    expect(matchRoute('/a/:x/b/:y', '/a/1/c/2')).toBeNull();
  });

  test('param values are URL-decoded; a malformed escape is kept verbatim', () => {
    expect(matchRoute('/p/:id', '/p/hello%20world')).toEqual({ params: { id: 'hello world' } });
    expect(matchRoute('/p/:id', '/p/%E0%A4%A')).toEqual({ params: { id: '%E0%A4%A' } });
  });

  test('a query string or hash on the pathname is ignored', () => {
    expect(matchRoute('/admin/edges/relays/:slug', '/admin/edges/relays/x?tab=edges')).toEqual({
      params: { slug: 'x' },
    });
    expect(matchRoute('/admin/edges', '/admin/edges#top')).toEqual({ params: {} });
  });

  test('the providers pair from the section table dispatches unambiguously', () => {
    expect(matchRoute('/admin/edges/providers', '/admin/edges/providers')).not.toBeNull();
    expect(matchRoute('/admin/edges/providers', '/admin/edges/providers/acc1')).toBeNull();
    expect(matchRoute('/admin/edges/providers/:id', '/admin/edges/providers/acc1')).toEqual({
      params: { id: 'acc1' },
    });
    expect(matchRoute('/admin/edges/providers/:id', '/admin/edges/providers')).toBeNull();
  });
});
