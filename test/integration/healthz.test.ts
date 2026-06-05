import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('GET /api/healthz', () => {
  it('returns ok', async () => {
    const res = await SELF.fetch('https://example.com/api/healthz');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it('echoes a request id', async () => {
    const res = await SELF.fetch('https://example.com/api/healthz', {
      headers: { 'x-request-id': 'abc-123-test' },
    });
    expect(res.headers.get('x-request-id')).toBe('abc-123-test');
  });
});
