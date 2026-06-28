/**
 * Crypto helpers for Convex actions (Web Crypto: crypto.subtle + getRandomValues
 * are available in actions). hmacSha256Hex matches lib/crypto.hashIp on the old
 * stack so free-tier reissue lookups stay consistent.
 */
function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function sha256Hex(input: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)));
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)));
}

/**
 * HMAC-SHA512 hex. Used to verify NOWPayments IPN callbacks (their signature is
 * HMAC-SHA512 over the key-sorted JSON body). Web Crypto, so it stays in the V8
 * action isolate (no "use node").
 */
export async function hmacSha512Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign'],
  );
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)));
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

/** URL-safe base64 of random bytes: the `fsv1_` token body + opaque ids. */
export function base64UrlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]!);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Constant-time string compare (HMAC sigs, bootstrap secret). Verifies signed
 * cookies and the admin-bootstrap secret.
 *
 * No early length-branch: a length mismatch is folded into the accumulator and
 * the loop always runs over the longer string, so the result does not short-
 * circuit on length (L1). Both call sites compare against a FIXED-length secret,
 * so this only removes a benign "your input wasn't N chars" signal — defense in
 * depth, not a known leak. Out-of-range `charCodeAt` is NaN; `|| 0` maps it to 0
 * (a real NUL also maps to 0, which XORs correctly on both sides).
 */
export function timingSafeEqual(a: string, b: string): boolean {
  let result = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) result |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return result === 0;
}
