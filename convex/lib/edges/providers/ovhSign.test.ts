import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { OVH_ENDPOINTS, ovhSignature, ovhSignedHeaders, sha1Hex } from './ovhSign';

describe('ovh signing', () => {
  test('sha1Hex matches node:crypto', async () => {
    const s = 'the quick brown fox';
    expect(await sha1Hex(s)).toBe(createHash('sha1').update(s).digest('hex'));
  });

  test('signature = $1$ + sha1(AS+CK+METHOD+URL+BODY+TS)', async () => {
    const input = {
      applicationSecret: 'AS-secret',
      consumerKey: 'CK-consumer',
      method: 'get',
      url: 'https://eu.api.ovh.com/1.0/me',
      body: '',
      timestamp: 1366000000,
    };
    const expected = `$1$${createHash('sha1')
      .update('AS-secret+CK-consumer+GET+https://eu.api.ovh.com/1.0/me++1366000000')
      .digest('hex')}`;
    expect(await ovhSignature(input)).toBe(expected);
    // A POST includes the exact body string.
    const body = JSON.stringify({ name: 'x' });
    const post = await ovhSignature({ ...input, method: 'POST', body });
    expect(post).toBe(
      `$1$${createHash('sha1').update(`AS-secret+CK-consumer+POST+https://eu.api.ovh.com/1.0/me+${body}+1366000000`).digest('hex')}`,
    );
  });

  test('signed headers carry the four X-Ovh headers with a skew-corrected timestamp', async () => {
    const h = await ovhSignedHeaders({
      applicationKey: 'AK',
      applicationSecret: 'AS',
      consumerKey: 'CK',
      method: 'GET',
      url: `${OVH_ENDPOINTS['ovh-eu']}/me`,
      body: '',
      skewSeconds: 7,
      nowMs: 1_700_000_000_000,
    });
    expect(h['x-ovh-application']).toBe('AK');
    expect(h['x-ovh-consumer']).toBe('CK');
    expect(h['x-ovh-timestamp']).toBe(String(1_700_000_000 + 7));
    expect(h['x-ovh-signature']).toMatch(/^\$1\$[0-9a-f]{40}$/);
    expect(h['x-ovh-signature']).not.toContain('AS');
  });
});
