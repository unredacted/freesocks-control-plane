import { describe, expect, it, vi } from 'vitest';
import { TurnstileVerifier } from '../../../src/server/providers/turnstile/verify';
import { Logger } from '../../../src/server/lib/logger';

const log = new Logger('error');

describe('TurnstileVerifier', () => {
  it('returns success for a valid response', async () => {
    const fakeFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ success: true, hostname: 'example.com' }),
    });
    const v = new TurnstileVerifier('secret', log, fakeFetch as unknown as typeof fetch);
    const r = await v.verify('token');
    expect(r.success).toBe(true);
    expect(r.hostname).toBe('example.com');
  });

  it('returns failure for missing token', async () => {
    const fakeFetch = vi.fn();
    const v = new TurnstileVerifier('secret', log, fakeFetch as unknown as typeof fetch);
    const r = await v.verify('');
    expect(r.success).toBe(false);
    expect(fakeFetch).not.toHaveBeenCalled();
  });

  it('returns failure on http error', async () => {
    const fakeFetch = vi.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    const v = new TurnstileVerifier('secret', log, fakeFetch as unknown as typeof fetch);
    const r = await v.verify('tok');
    expect(r.success).toBe(false);
    expect(r.errorCodes).toEqual(['http-500']);
  });

  it('handles network exceptions', async () => {
    const fakeFetch = vi.fn().mockRejectedValue(new Error('boom'));
    const v = new TurnstileVerifier('secret', log, fakeFetch as unknown as typeof fetch);
    const r = await v.verify('tok');
    expect(r.success).toBe(false);
    expect(r.errorCodes).toEqual(['exception']);
  });
});
