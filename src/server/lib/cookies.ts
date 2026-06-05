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
  if (opts.path) parts.push(`Path=${opts.path}`);
  else parts.push('Path=/');
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure !== false) parts.push('Secure');
  parts.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  return parts.join('; ');
}

export async function signValue(value: string, key: string): Promise<string> {
  // The signed form is `value.sig` and verify splits on the LAST '.'. Reject
  // any value containing '.' so that split is always unambiguous (session ids
  // are hex today; this guards future callers). Keeping the '.' separator
  // avoids invalidating every existing cookie that a separator change would.
  if (value.includes('.')) {
    throw new Error('signValue: value must not contain "."');
  }
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
