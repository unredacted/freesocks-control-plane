import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { users } from '../db/schema';
import { sha256Hex } from '../lib/crypto';

/**
 * Self-service account-number auth (docs/account-number-design.md).
 *
 * An account number is a 16 decimal-digit opaque credential a user can use to
 * sign back in without email/OIDC. We persist only a SHA-256 hash of the
 * canonical (digits-only) form plus a 4-digit plaintext prefix for admin
 * search; the plaintext is revealed exactly once at issuance/rotation. Login
 * hashes the submitted input and does a single indexed lookup — no enumeration.
 */

const DIGITS = 16;
const PREFIX_LEN = 4;

export interface MintedAccountId {
  /** Canonical digits-only plaintext. Show ONCE; never persisted server-side. */
  plaintext: string;
  hash: string;
  prefix: string;
}

export class AccountIdService {
  constructor(private readonly db: Db) {}

  /** Canonical form is digits-only; strip spaces and hyphens from user input. */
  static normalize(input: string): string {
    return input.replace(/[\s-]/g, '');
  }

  /** True iff the normalized input is exactly 16 decimal digits. */
  static isValidFormat(normalized: string): boolean {
    return /^\d{16}$/.test(normalized);
  }

  /** Group a canonical number into four space-separated quads for display. */
  static format(canonical: string): string {
    return canonical.replace(/(\d{4})(?=\d)/g, '$1 ');
  }

  /**
   * Generate a fresh canonical 16-digit number from the CSPRNG with rejection
   * sampling: bytes in [250,255] are discarded so each accepted byte mod 10 is
   * uniform (250 = 25×10), eliminating modulo bias.
   */
  static generate(): string {
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

  /** SHA-256 hex of a canonical number (the stored form). */
  async hash(canonical: string): Promise<string> {
    return sha256Hex(canonical);
  }

  /**
   * Mint a new account number, persist its hash + prefix on `userId`, and
   * return the one-time plaintext. Retries once on the (astronomically rare)
   * hash collision against the partial UNIQUE index. `rotate:true` stamps
   * `accountIdRotatedAt` (replacing an existing number); otherwise it stamps
   * `accountIdCreatedAt` (first assignment).
   */
  async assignToUser(userId: number, opts: { rotate?: boolean } = {}): Promise<MintedAccountId> {
    const now = Date.now();
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      const plaintext = AccountIdService.generate();
      const hash = await sha256Hex(plaintext);
      const prefix = plaintext.slice(0, PREFIX_LEN);
      try {
        await this.db
          .update(users)
          .set({
            accountIdHash: hash,
            accountIdPrefix: prefix,
            ...(opts.rotate ? { accountIdRotatedAt: now } : { accountIdCreatedAt: now }),
            updatedAt: now,
          })
          .where(eq(users.id, userId));
        return { plaintext, hash, prefix };
      } catch (err) {
        // UNIQUE(account_id_hash) collision — generate a different number.
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('account-id mint failed after retry');
  }

  /**
   * Resolve the active user that owns the submitted (already-normalized)
   * account number, by hash. Returns the user id, or null when unknown or the
   * owner is disabled/deleted. Single indexed lookup. The caller MUST still
   * rate-limit and pad timing — this method intentionally does no oracle
   * hardening of its own.
   */
  async findUserIdByAccountId(canonical: string): Promise<number | null> {
    const hash = await sha256Hex(canonical);
    const rows = await this.db
      .select()
      .from(users)
      .where(eq(users.accountIdHash, hash))
      .limit(1)
      .all();
    const row = rows[0];
    if (!row) return null;
    if (row.status === 'disabled' || row.status === 'deleted') return null;
    return row.id;
  }
}
