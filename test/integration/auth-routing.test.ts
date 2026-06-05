import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

/**
 * Smoke tests that `/api/auth/login` actually routes. The user reported a 404
 * on the live worker; pinning the behavior here so a routing regression
 * never escapes CI again.
 *
 * Note: the integration env doesn't have a real Authentik backend, so we
 * accept any 2xx/3xx (the login route returns a redirect to Authentik) or
 * 5xx (the Authentik client may throw because the issuer is unreachable
 * from Miniflare's sandboxed fetch). What we MUST NOT see is 404.
 */
describe('GET /api/auth/login', () => {
  it('routes (does not 404)', async () => {
    const res = await SELF.fetch('https://example.com/api/auth/login?returnTo=/account', {
      redirect: 'manual',
    });
    expect(res.status).not.toBe(404);
  });

  it('responds to /api/auth/me', async () => {
    const res = await SELF.fetch('https://example.com/api/auth/me');
    expect(res.status).not.toBe(404);
  });
});
