// @vitest-environment node
//
// Pins public/sitemap.xml + public/robots.txt to the SPA's public route set and
// to the Caddy templating that expands their host placeholders. Adding or
// removing a public member-facing route (App.svelte's route switch) must update
// PUBLIC_ROUTES here alongside the sitemap itself (and the telemetry
// ROUTE_ALLOWLIST in convex/lib/umami.ts).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';

const root = resolve(__dirname, '../../..');
const sitemap = readFileSync(resolve(root, 'public/sitemap.xml'), 'utf8');
const robots = readFileSync(resolve(root, 'public/robots.txt'), 'utf8');
const caddyfile = readFileSync(resolve(root, 'Caddyfile'), 'utf8');

// Caddy expands this per request; the committed file must carry it verbatim so
// every deployment serves same-host canonical URLs.
const HOST = '{{placeholder "http.request.host"}}';

// The indexable public routes. Auth-gated and non-content surfaces (/account,
// /login, /admin, /api, /cap) stay out of the sitemap and disallowed in robots.
const PUBLIC_ROUTES = ['/', '/get-account', '/status'];

describe('sitemap.xml', () => {
  test('is a sitemaps.org urlset with an XML declaration', () => {
    expect(sitemap.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(sitemap).toContain('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
    expect(sitemap.trimEnd().endsWith('</urlset>')).toBe(true);
    // Every <url> holds exactly one <loc> (structural sanity without a parser;
    // XML comments stripped so prose mentioning the tags doesn't count).
    const noComments = sitemap.replace(/<!--[\s\S]*?-->/g, '');
    expect(noComments.match(/<url>/g)?.length).toBe(noComments.match(/<loc>/g)?.length);
  });

  test('lists exactly the public routes, host-templated over https', () => {
    const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    expect(locs).toEqual(PUBLIC_ROUTES.map((route) => `https://${HOST}${route}`));
  });
});

describe('robots.txt', () => {
  test('references the host-templated sitemap URL', () => {
    expect(robots).toContain(`Sitemap: https://${HOST}/sitemap.xml`);
  });

  test('disallows the non-content surfaces', () => {
    for (const path of ['/account', '/login', '/admin', '/api/', '/cap/']) {
      expect(robots).toContain(`Disallow: ${path}`);
    }
    // /account must not shadow the public /get-account route (robots Disallow
    // is a path-prefix match, so this only holds while the literal differs).
    expect(robots).not.toContain('Disallow: /get');
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
