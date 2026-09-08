/**
 * Loose base64 handling for subscription bodies. Panels and mirrors wrap the
 * link list in base64 with either alphabet (standard `+/` or URL-safe `-_`),
 * with or without `=` padding, and with or without line breaks. `atob` accepts
 * only the padded standard form, so normalise before decoding and treat any
 * decode failure as "not base64".
 */

const LOOSE_BASE64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;

/** Strip whitespace and check the alphabet (either variant, padding optional). */
export function looksLikeBase64(s: string): boolean {
  const compact = s.replace(/\s+/g, '');
  if (compact.length < 4) return false;
  if (!LOOSE_BASE64_RE.test(compact)) return false;
  // A length of 1 (mod 4) after padding removal is impossible for base64.
  return compact.replace(/=+$/, '').length % 4 !== 1;
}

/** Decode either alphabet, padded or not; null when it is not valid base64. */
export function decodeBase64Loose(s: string): string | null {
  const compact = s.replace(/\s+/g, '');
  if (!looksLikeBase64(compact)) return null;
  const std = compact.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  try {
    return atob(padded);
  } catch {
    return null;
  }
}
