/**
 * Referral codes: a member's shareable `FSR-XXXX-XXXX` handle. NON-SECRET — it
 * credits the referrer when a new account signs up with it and grants nothing
 * to the holder, so being guessable/enumerable is harmless (same threat model
 * as the W3 support ID). Crockford base32 (no I/L/O/U) so it transcribes
 * unambiguously; uniqueness is enforced by a serializable read-check on mint.
 */

// Crockford base32 alphabet (excludes I, L, O, U). 32 symbols → a byte masked
// with 31 maps uniformly (no modulo bias, since 32 is a power of two).
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DATA_LEN = 8;

export function generateReferralCode(): string {
  const buf = new Uint8Array(DATA_LEN);
  crypto.getRandomValues(buf);
  let s = '';
  for (const b of buf) s += ALPHABET[b & 31];
  return `FSR-${s.slice(0, 4)}-${s.slice(4, 8)}`;
}

/**
 * Canonicalize user-typed input for an exact lookup: uppercase, drop separators
 * and any leading "FSR", apply Crockford's read-alias mapping (I/L→1, O→0),
 * and re-group as `FSR-XXXX-XXXX` when 8 data chars remain. Tolerant of how a
 * user might transcribe the code; anything else simply matches nothing.
 */
export function normalizeReferralCode(input: string): string {
  let s = input.toUpperCase().replace(/[\s-]/g, '');
  if (s.startsWith('FSR')) s = s.slice(3);
  s = s.replace(/[ILO]/g, (c) => (c === 'O' ? '0' : '1'));
  if (s.length !== DATA_LEN) return `FSR-${input.toUpperCase().replace(/[\s-]/g, '')}`;
  return `FSR-${s.slice(0, 4)}-${s.slice(4, 8)}`;
}

/** Shape check for the signup field (cheap client/server guard before the
 *  normalized lookup). */
export function looksLikeReferralCode(input: string): boolean {
  const s = input.toUpperCase().replace(/[\s-]/g, '');
  const body = s.startsWith('FSR') ? s.slice(3) : s;
  return body.length === DATA_LEN;
}
