import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('API v1 prefix', () => {
  it('serves /api/healthz unversioned', async () => {
    const res = await SELF.fetch('https://example.com/api/healthz');
    expect(res.status).toBe(200);
  });

  it('rejects /api/subscription (legacy path) with 404', async () => {
    const res = await SELF.fetch('https://example.com/api/subscription', { method: 'POST' });
    // The route was moved to /api/v1/subscription; the unversioned path should not exist.
    expect(res.status).toBe(404);
  });

  it('serves /api/v1/me with anonymous identity', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/me');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authenticated: boolean };
    expect(body.authenticated).toBe(false);
  });

  it('rejects /api/v1/admin/tokens without auth (401)', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/admin/tokens');
    expect(res.status).toBe(401);
  });

  it('rejects /api/v1/admin/tokens with a bogus bearer token (401)', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/admin/tokens', {
      headers: { Authorization: 'Bearer fsv1_thisIsAFakeTokenThatDoesNotExist' },
    });
    expect(res.status).toBe(401);
  });
});
