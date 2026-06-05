/**
 * Pure account-number helpers, ported from services/account-id.ts. A number is
 * 16 decimal digits; we persist only its SHA-256 hash + a 4-digit prefix.
 *
 * `generateAccountId` uses the CSPRNG and `sha256Hex` uses crypto.subtle — both
 * are available in Convex ACTIONS (not in queries/mutations), so minting lives
 * in an action and only the resulting hash/prefix are handed to a mutation.
 */
const DIGITS = 16;
const PREFIX_LEN = 4;

/** Canonical form is digits-only; strip spaces and hyphens from user input. */
export function normalizeAccountId(input: string): string {
  return input.replace(/[\s-]/g, '');
}

export function isValidAccountId(normalized: string): boolean {
  return /^\d{16}$/.test(normalized);
}

/** Group a canonical number into four space-separated quads for display. */
export function formatAccountId(canonical: string): string {
  return canonical.replace(/(\d{4})(?=\d)/g, '$1 ');
}

export function accountIdPrefix(canonical: string): string {
  return canonical.slice(0, PREFIX_LEN);
}

/**
 * Fresh 16-digit number from the CSPRNG with rejection sampling: bytes in
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

/** SHA-256 hex of a canonical number (the stored form). Call from an action. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
