/**
 * Pure account-number helpers, ported from services/account-id.ts. A number is
 * 32 decimal digits (~106 bits of entropy); we persist only a keyed hash + a
 * 4-digit prefix (for admin search). The number is the member's sole login
 * credential, so it's sized to be unguessable even against offline brute-force
 * of a leaked hash column.
 *
 * The stored hash is HMAC-SHA256(ACCOUNT_ID_PEPPER, number), NOT a bare hash:
 * the pepper is a deployment secret (env, never in the DB), so a DB-only leak
 * can't be brute-forced without it. It's still deterministic, so login keeps its
 * single indexed lookup (hash the input, match `by_account_id_hash`).
 *
 * `generateAccountId` (CSPRNG) and `hashAccountId` (crypto.subtle) run in Convex
 * ACTIONS (not queries/mutations); only the resulting hash/prefix reach a mutation.
 */
import { hmacSha256Hex } from './crypto';

const DIGITS = 32;
const PREFIX_LEN = 4;
const VALID = new RegExp(`^\\d{${DIGITS}}$`);

/** Canonical form is digits-only; strip spaces and hyphens from user input. */
export function normalizeAccountId(input: string): string {
  return input.replace(/[\s-]/g, '');
}

export function isValidAccountId(normalized: string): boolean {
  return VALID.test(normalized);
}

/** Group a canonical number into space-separated quads for display. */
export function formatAccountId(canonical: string): string {
  return canonical.replace(/(\d{4})(?=\d)/g, '$1 ');
}

export function accountIdPrefix(canonical: string): string {
  return canonical.slice(0, PREFIX_LEN);
}

/**
 * Fresh 32-digit number from the CSPRNG with rejection sampling: bytes in
 * [250,255] are discarded so each accepted byte mod 10 is uniform (250 = 25×10),
 * eliminating modulo bias. Call from an action.
 */
export function generateAccountId(): string {
  let out = '';
  while (out.length < DIGITS) {
    const buf = new Uint8Array(DIGITS);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (out.length >= DIGITS) break;
      if (b >= 250) continue;
      out += (b % 10).toString();
    }
  }
  return out;
}

/**
 * The stored form: HMAC-SHA256(ACCOUNT_ID_PEPPER, normalized number). The pepper
 * is a required deployment secret; fail closed if it's missing rather than
 * silently falling back to a guessable bare hash. Call from an action.
 */
export async function hashAccountId(input: string): Promise<string> {
  const pepper = process.env.ACCOUNT_ID_PEPPER;
  if (!pepper) throw new Error('ACCOUNT_ID_PEPPER must be set (bunx convex env set ...)');
  return hmacSha256Hex(pepper, normalizeAccountId(input));
}
