/// <reference types="vite/client" />
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { resolveClientIp } from './lib/http';

/**
 * A1 (launch audit): a client-supplied `cf-connecting-ip` must NOT be trusted in
 * the Caddy-direct topology, or any client can pick its own rate-limit bucket and
 * defeat the free-tier per-(IP,day) cap + the login throttle. cf-connecting-ip is
 * honoured ONLY when CF_FRONTED=true (a real Cloudflare edge in front).
 */
function req(headers: Record<string, string>): Request {
  return new Request('https://beta.freesocks.org/api/v1/account', { headers });
}

describe('resolveClientIp trust rules', () => {
  const saved = {
    CF_FRONTED: process.env.CF_FRONTED,
    TRUSTED_PROXY: process.env.TRUSTED_PROXY,
  };
  beforeEach(() => {
    delete process.env.CF_FRONTED;
    delete process.env.TRUSTED_PROXY;
  });
  afterEach(() => {
    if (saved.CF_FRONTED === undefined) delete process.env.CF_FRONTED;
    else process.env.CF_FRONTED = saved.CF_FRONTED;
    if (saved.TRUSTED_PROXY === undefined) delete process.env.TRUSTED_PROXY;
    else process.env.TRUSTED_PROXY = saved.TRUSTED_PROXY;
  });

  test('Caddy-direct (TRUSTED_PROXY=true): a forged cf-connecting-ip is ignored; XFF[0] wins', () => {
    process.env.TRUSTED_PROXY = 'true';
    const ip = resolveClientIp(
      req({ 'cf-connecting-ip': '6.6.6.6', 'x-forwarded-for': '203.0.113.7, 10.0.0.1' }),
    );
    expect(ip).toBe('203.0.113.7');
  });

  test('Caddy-direct: a lone forged cf-connecting-ip resolves to null (no spoof bucket)', () => {
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'cf-connecting-ip': '6.6.6.6' }))).toBeNull();
  });

  test('neither flag set: nothing is trusted, even a real-looking XFF', () => {
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBeNull();
    expect(resolveClientIp(req({ 'cf-connecting-ip': '203.0.113.7' }))).toBeNull();
  });

  test('CF_FRONTED=true: cf-connecting-ip is honoured (and preferred over XFF)', () => {
    process.env.CF_FRONTED = 'true';
    process.env.TRUSTED_PROXY = 'true';
    const ip = resolveClientIp(
      req({ 'cf-connecting-ip': '198.51.100.9', 'x-forwarded-for': '203.0.113.7' }),
    );
    expect(ip).toBe('198.51.100.9');
  });

  test('CF_FRONTED=true but no cf header: falls through to XFF when TRUSTED_PROXY=true', () => {
    process.env.CF_FRONTED = 'true';
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBe('203.0.113.7');
  });

  test('values are trimmed', () => {
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'x-forwarded-for': '  203.0.113.7  , 10.0.0.1' }))).toBe(
      '203.0.113.7',
    );
  });
});
