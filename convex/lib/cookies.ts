/**
 * Signed-cookie helpers (P6) — ported verbatim from src/server/lib/cookies.ts so
 * the wire format is unchanged: the cookie value is `<sid>.<hmac>`, verify splits
 * on the LAST '.', and the sid (hex) never contains a '.'. Used by the HTTP
 * actions in convex/http.ts to set/read the member + admin session cookies.
 *
 * These run inside Convex actions (Web Crypto available), so the HMAC fns are
 * async — mirror lib/crypto on the old stack.
 */
import { hmacSha256Hex, timingSafeEqual } from './crypto';

export interface CookieOptions {
  domain?: string;
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
}

export function buildSetCookie(name: string, value: string, opts: CookieOptions = {}): string {
  const parts = [`${name}=${value}`];
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  parts.push(`Path=${opts.path ?? '/'}`);
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure !== false) parts.push('Secure');
  parts.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  return parts.join('; ');
}

/** Parse a request `Cookie` header into a name→value map. */
export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const k = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (k) out[k] = val;
  }
  return out;
}

export async function signValue(value: string, key: string): Promise<string> {
  if (value.includes('.')) throw new Error('signValue: value must not contain "."');
  const sig = await hmacSha256Hex(key, value);
  return `${value}.${sig}`;
}

export async function verifySignedValue(signed: string, key: string): Promise<string | null> {
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.substring(0, idx);
  const sig = signed.substring(idx + 1);
  const expected = await hmacSha256Hex(key, value);
  return timingSafeEqual(expected, sig) ? value : null;
}
