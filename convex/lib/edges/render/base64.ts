/**
 * Loose base64 handling for subscription bodies. Backends and mirrors wrap the
 * link list in base64 with either alphabet (standard `+/` or URL-safe `-_`),
 * with or without `=` padding, and with or without line breaks. `atob` accepts
 * only the padded standard form, so normalise before decoding and treat any
 * decode failure as "not base64".
 *
 * `atob`/`btoa` speak latin1, not text: `atob` would hand back one mojibake
 * char per UTF-8 byte and `btoa` THROWS on any code point above U+00FF. A
 * subscription body is UTF-8 (remarks carry non-ASCII labels routinely), so the
 * conversion goes through TextDecoder/TextEncoder and base64 stays a pure
 * byte-level transport.
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
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Standard, padded base64 of the UTF-8 bytes of `s`. The inverse of
 * `decodeBase64Loose` for any text, non-ASCII included (`btoa` alone throws on
 * it), so a re-encoded body round-trips byte for byte.
 */
export function encodeBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let binary = '';
  // Chunked: String.fromCharCode(...bytes) blows the argument limit on a long body.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}
