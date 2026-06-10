/**
 * W3 (launch): the SUPPORT ID — a short, permanent, collision-free, NON-SECRET
 * account handle a member can safely quote to support (e.g. when contacting us
 * to redeem a membership). It is NOT a credential: it cannot sign in and grants
 * nothing, so it being guessable/enumerable is harmless. It exists so support no
 * longer has to identify a user by the 4-digit account-number prefix (which
 * collides at scale and leaks credential entropy if more digits are shared).
 *
 * Format: `FS-XXXX-XXXX` — 8 Crockford base32 data chars (no I/L/O/U, so it's
 * unambiguous when read aloud or transcribed). 32^8 ≈ 1.1e12 values; uniqueness
 * is enforced by a serializable read-check on mint (same pattern as the account
 * hash), so collisions just retry.
 */

// Crockford base32 alphabet (excludes I, L, O, U). 32 symbols → a byte masked
// with 31 maps uniformly (no modulo bias, since 32 is a power of two).
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DATA_LEN = 8;

export function generateSupportId(): string {
  const buf = new Uint8Array(DATA_LEN);
  crypto.getRandomValues(buf);
  let s = '';
  for (const b of buf) s += ALPHABET[b & 31];
  return `FS-${s.slice(0, 4)}-${s.slice(4, 8)}`;
}

/**
 * Canonicalize user-typed input for an exact lookup: uppercase, drop separators
 * and any leading "FS", apply Crockford's read-alias mapping (I/L→1, O→0), and
 * re-group as `FS-XXXX-XXXX` when 8 data chars remain. Tolerant of how a user
 * might transcribe the code; returns the cleaned string unchanged if it isn't 8
 * data chars (so a bad input simply matches nothing).
 */
export function normalizeSupportId(input: string): string {
  let s = input.toUpperCase().replace(/[\s-]/g, '');
  if (s.startsWith('FS')) s = s.slice(2);
  s = s.replace(/[ILO]/g, (c) => (c === 'O' ? '0' : '1'));
  if (s.length !== DATA_LEN) return `FS-${input.toUpperCase().replace(/[\s-]/g, '')}`;
  return `FS-${s.slice(0, 4)}-${s.slice(4, 8)}`;
}
