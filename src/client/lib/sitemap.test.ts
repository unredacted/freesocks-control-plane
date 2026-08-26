// @vitest-environment node
//
// Pins public/sitemap.xml + public/robots.txt to the SPA's public route set and
// to the Caddy templating that expands their host placeholders. The expected
// route list is DERIVED from App.svelte's route switch, so adding or removing a
// route there fails this test until the sitemap (or NON_INDEXABLE below) is
// updated too — the same must-stay-in-sync convention as the telemetry
// ROUTE_ALLOWLIST in convex/lib/umami.ts.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';

const root = resolve(__dirname, '../../..');
const sitemap = readFileSync(resolve(root, 'public/sitemap.xml'), 'utf8');
const robots = readFileSync(resolve(root, 'public/robots.txt'), 'utf8');
const caddyfile = readFileSync(resolve(root, 'Caddyfile'), 'utf8');
const appSvelte = readFileSync(resolve(root, 'src/client/App.svelte'), 'utf8');

// Caddy expands this per request; the committed files must carry it verbatim so
// every deployment serves same-host canonical URLs.
const HOST = '{{placeholder "http.request.host"}}';

// Routes App.svelte renders that must stay OUT of the sitemap (auth-gated, no
// indexable content). /admin and the non-SPA surfaces (/api, /cap) never appear
// as pathname literals in the route switch and are asserted on robots directly.
const NON_INDEXABLE = ['/account', '/login'];

// The actual route switch: every `router.pathname === '/x'` literal.
const routerRoutes = [...appSvelte.matchAll(/router\.pathname === '([^']+)'/g)].map(
  (m) => m[1] ?? '',
);
const indexableRoutes = routerRoutes.filter((route) => !NON_INDEXABLE.includes(route));

describe('sitemap.xml', () => {
  test('route extraction from App.svelte found the route switch', () => {
    // Guards the regex above: a route-switch refactor that stops matching must
    // fail loudly here, not let the sitemap assertions pass vacuously.
    expect(routerRoutes).toContain('/');
    expect(routerRoutes.length).toBeGreaterThanOrEqual(3);
  });

  test('is a sitemaps.org urlset with an XML declaration', () => {
    expect(sitemap.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(sitemap).toContain('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
    expect(sitemap.trimEnd().endsWith('</urlset>')).toBe(true);
    // Every <url> holds exactly one <loc> (structural sanity without a parser;
    // XML comments stripped so prose mentioning the tags doesn't count).
    const noComments = sitemap.replace(/<!--[\s\S]*?-->/g, '');
    expect(noComments.match(/<url>/g)?.length).toBe(noComments.match(/<loc>/g)?.length);
  });

  test('lists exactly the indexable App.svelte routes, host-templated over https', () => {
    const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    expect([...locs].sort()).toEqual(
      indexableRoutes.map((route) => `https://${HOST}${route}`).sort(),
    );
  });
});

describe('robots.txt', () => {
  test('references the host-templated sitemap URL', () => {
    expect(robots).toContain(`Sitemap: https://${HOST}/sitemap.xml`);
  });

  test('disallows the non-content surfaces as bare prefixes', () => {
    // Bare prefixes (no trailing slash): robots exclusions are path-prefix
    // matches, and a slash-terminated `Disallow: /api/` would leave the exact
    // URL `/api` crawlable (it misses Caddy's /api/* handler and falls through
    // to the SPA with a 200).
    for (const path of [...NON_INDEXABLE, '/admin', '/api', '/cap']) {
      expect(robots).toContain(`Disallow: ${path}\n`);
    }
    // No disallow may prefix-shadow an indexable route (e.g. a hypothetical
    // `Disallow: /get` would block the public /get-account).
    const disallows = [...robots.matchAll(/^Disallow: (\S+)/gm)].map((m) => m[1] ?? '');
    for (const route of indexableRoutes.filter((r) => r !== '/')) {
      expect(disallows.some((d) => route.startsWith(d))).toBe(false);
    }
  });
});

describe('Caddyfile templating', () => {
  test('templates both files across the .txt and .xml MIME variants', () => {
    expect(caddyfile).toContain('@seoFiles path /robots.txt /sitemap.xml');
    expect(caddyfile).toMatch(
      /templates @seoFiles \{\s*mime text\/plain text\/xml application\/xml\s*\}/,
    );
  });
});
