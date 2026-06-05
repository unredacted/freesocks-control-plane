import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

/**
 * Anonymous free-tier issuance must refuse when the client IP can't be
 * established, rather than bucketing every such caller under a shared sentinel.
 * Under Miniflare there is no cf-connecting-ip and TRUSTED_PROXY is unset, so
 * resolveClientIp returns null → c.var.clientIp is unset → the guard fires.
 * The guard runs BEFORE turnstile.verify, so this needs no Turnstile stub.
 */
describe('Free-tier issuance requires a resolvable client IP', () => {
  it('anonymous POST without a resolvable IP → 503 freetier.ip_unresolved', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/subscription', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ turnstileToken: 'dummy' }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe('freetier.ip_unresolved');
  });
});
