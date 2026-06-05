import { describe, expect, it } from 'vitest';
import { buildSetCookie, signValue, verifySignedValue } from '../../../src/server/lib/cookies';

describe('cookies', () => {
  it('buildSetCookie sets sane defaults', () => {
    const out = buildSetCookie('s', 'v');
    expect(out).toContain('s=v');
    expect(out).toContain('Path=/');
    expect(out).toContain('HttpOnly');
    expect(out).toContain('Secure');
    expect(out).toContain('SameSite=Lax');
  });

  it('signValue / verifySignedValue round trip', async () => {
    const signed = await signValue('hello', 'k');
    expect(signed).toMatch(/^hello\.[0-9a-f]+$/);
    const verified = await verifySignedValue(signed, 'k');
    expect(verified).toBe('hello');
  });

  it('verifySignedValue rejects tampered signatures', async () => {
    const signed = await signValue('hello', 'k');
    const tampered = signed.slice(0, -1) + (signed.slice(-1) === '0' ? '1' : '0');
    expect(await verifySignedValue(tampered, 'k')).toBeNull();
  });

  it('verifySignedValue rejects wrong key', async () => {
    const signed = await signValue('hello', 'a');
    expect(await verifySignedValue(signed, 'b')).toBeNull();
  });
});
