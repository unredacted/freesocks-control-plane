import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('OpenAPI surface', () => {
  it('serves /api/openapi.json with key paths declared', async () => {
    const res = await SELF.fetch('https://example.com/api/openapi.json');
    expect(res.status).toBe(200);
    const spec = (await res.json()) as { openapi: string; paths: Record<string, unknown> };
    expect(spec.openapi).toMatch(/^3\./);
    expect(spec.paths).toHaveProperty('/api/v1/me');
    expect(spec.paths).toHaveProperty('/api/v1/subscription');
    expect(spec.paths).toHaveProperty('/api/v1/account');
    expect(spec.paths).toHaveProperty('/api/v1/admin/tiers');
    expect(spec.paths).toHaveProperty('/api/v1/admin/tokens');
    expect(spec.paths).toHaveProperty('/api/v1/admin/users');
    expect(spec.paths).toHaveProperty('/api/v1/admin/audit');
    expect(spec.paths).toHaveProperty('/api/healthz');
  });

  it('redirects /api/docs to the raw OpenAPI spec', async () => {
    // The old Scalar UI loaded its bundle from cdn.jsdelivr.net — that's a
    // third-party CDN and the "no external resources" policy disallows it.
    // /api/docs now hints toward the raw spec for local viewers to consume.
    const res = await SELF.fetch('https://example.com/api/docs', { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/api/openapi.json');
  });

  it('declares both apiToken and authentikJwt security schemes', async () => {
    const res = await SELF.fetch('https://example.com/api/openapi.json');
    const spec = (await res.json()) as {
      components: { securitySchemes: Record<string, unknown> };
    };
    expect(spec.components.securitySchemes).toHaveProperty('apiToken');
    expect(spec.components.securitySchemes).toHaveProperty('authentikJwt');
  });
});
