/**
 * W4 (launch): membership redemption codes — `FSM-XXXX-XXXX-XXXX`. Pure helpers.
 *
 * A code is a BEARER SECRET: whoever holds it can redeem the membership, so only
 * its SHA-256 hash is ever stored (mirrors apiTokens). 12 Crockford base32 data
 * chars ≈ 60 bits of entropy — unguessable online (the redeem endpoint is hard
 * rate-limited) and fine against an offline hash search. The distinct `FSM-`
 * prefix and 12-char length keep it visually unmistakable from a 32-digit
 * account number, so a user can never confuse the two.
 */

// Crockford base32 (excludes I, L, O, U). A byte masked with 31 is uniform.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DATA_LEN = 12;
const VALID = /^FSM-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;

export function generateMembershipCode(): string {
  const buf = new Uint8Array(DATA_LEN);
  crypto.getRandomValues(buf);
  let s = '';
  for (const b of buf) s += ALPHABET[b & 31];
  return `FSM-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}

/**
 * Canonicalize user-typed input: uppercase, drop separators + a leading "FSM",
 * apply Crockford read-aliases (I/L→1, O→0), regroup as `FSM-XXXX-XXXX-XXXX`.
 * Returns the cleaned string unchanged if it isn't 12 data chars (so a malformed
 * code simply hashes to something that matches no row).
 */
export function normalizeMembershipCode(input: string): string {
  let s = input.toUpperCase().replace(/[\s-]/g, '');
  if (s.startsWith('FSM')) s = s.slice(3);
  s = s.replace(/[ILO]/g, (c) => (c === 'O' ? '0' : '1'));
  if (s.length !== DATA_LEN) return input.toUpperCase().replace(/[\s-]/g, '');
  return `FSM-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}

export function isValidMembershipCode(normalized: string): boolean {
  return VALID.test(normalized);
}

/** The admin-list display prefix (group 1), e.g. `FSM-7K3M`. Never the full code. */
export function membershipCodePrefix(normalized: string): string {
  return normalized.slice(0, 8);
}
