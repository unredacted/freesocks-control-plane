/**
 * Pure route-pattern matcher for the client router. `'/admin/edges/relays/:slug'`
 * style patterns; one `:name` segment captures exactly one path segment
 * (URL-decoded). No regexes, no wildcards, no optional segments: every route
 * in this SPA is a fixed depth, and a pattern that says less is easier to
 * audit than one that says more.
 *
 * Lives outside `stores/router.svelte.ts` so it is unit-testable without the
 * Svelte compiler; the router re-exports it.
 *
 * Exports: `matchRoute(pattern, pathname)` -> `{ params } | null`, `RouteMatch`.
 */
export type RouteMatch = { params: Record<string, string> };

function segments(path: string): string[] {
  return path.split('/').filter((s) => s.length > 0);
}

function decode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

export function matchRoute(pattern: string, pathname: string): RouteMatch | null {
  const want = segments(pattern);
  // Only the path is matched: a caller passing `router.pathname` never has a
  // query string, but a stray `?` or `#` must not turn a match into a miss.
  const got = segments(pathname.split(/[?#]/, 1)[0] ?? '');
  if (want.length !== got.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    const w = want[i]!;
    const g = got[i]!;
    if (w.startsWith(':')) {
      const name = w.slice(1);
      if (!name) return null;
      params[name] = decode(g);
    } else if (w !== g) {
      return null;
    }
  }
  return { params };
}
