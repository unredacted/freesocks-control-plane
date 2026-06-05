import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { PublicConfig } from '../../src/shared/contracts/auth';

describe('GET /api/v1/config', () => {
  it('returns 200 and a body that parses against PublicConfig', async () => {
    const res = await SELF.fetch('https://example.com/api/v1/config');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(PublicConfig.safeParse(body).success).toBe(true);
  });
});
