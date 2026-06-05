import { and, desc, eq, isNull, or, gt } from 'drizzle-orm';
import type { Db } from '../db/client';
import { apiTokens } from '../db/schema';
import { base64UrlEncode, sha256Hex } from '../lib/crypto';
import type { Logger } from '../lib/logger';
import type { ApiScope } from '../../shared/contracts/scopes';

export const TOKEN_PREFIX = 'fsv1_';
const TOKEN_RANDOM_BYTES = 32;
/** Minimum interval between `last_used_at` writes per token. Avoids hot-row updates. */
const LAST_USED_DEBOUNCE_MS = 5 * 60_000;

export interface CreateTokenInput {
  name: string;
  scopes: ApiScope[];
  subjectType: 'service' | 'user';
  subjectUserId?: number | null;
  expiresInDays?: number | null;
  createdByAdminId: number;
}

export interface CreateTokenOutput {
  id: number;
  plaintext: string;
  prefix: string;
}

export interface ResolvedToken {
  id: number;
  scopes: ApiScope[];
  subjectType: 'service' | 'user';
  subjectUserId: number | null;
  expiresAt: number | null;
  revokedAt: number | null;
  lastUsedAt: number | null;
}

export class ApiTokenService {
  constructor(
    private readonly db: Db,
    private readonly logger: Logger,
  ) {}

  async create(input: CreateTokenInput): Promise<CreateTokenOutput> {
    const random = new Uint8Array(TOKEN_RANDOM_BYTES);
    crypto.getRandomValues(random);
    const plaintext = `${TOKEN_PREFIX}${base64UrlEncode(random)}`;
    const tokenHash = await sha256Hex(plaintext);
    const tokenPrefix = plaintext.slice(0, 12); // "fsv1_" + 7 random chars
    const expiresAt = input.expiresInDays ? Date.now() + input.expiresInDays * 86_400_000 : null;
    const inserted = await this.db
      .insert(apiTokens)
      .values({
        name: input.name,
        tokenHash,
        tokenPrefix,
        createdByAdminId: input.createdByAdminId,
        scopes: JSON.stringify(input.scopes),
        subjectType: input.subjectType,
        subjectUserId: input.subjectUserId ?? null,
        expiresAt,
      })
      .returning();
    const row = inserted[0];
    if (!row) throw new Error('Token insert returned no row');
    return { id: row.id, plaintext, prefix: tokenPrefix };
  }

  async list(): Promise<(typeof apiTokens.$inferSelect)[]> {
    return this.db.select().from(apiTokens).orderBy(desc(apiTokens.createdAt)).all();
  }

  async revoke(id: number): Promise<void> {
    await this.db
      .update(apiTokens)
      .set({ revokedAt: Date.now(), updatedAt: Date.now() })
      .where(eq(apiTokens.id, id));
  }

  /**
   * Look up a plaintext token, returning a resolved token if it exists, is unrevoked, and unexpired.
   * Updates `last_used_at` no more often than once per LAST_USED_DEBOUNCE_MS to avoid hot-row writes.
   */
  async resolve(plaintext: string): Promise<ResolvedToken | null> {
    if (!plaintext.startsWith(TOKEN_PREFIX)) return null;
    const tokenHash = await sha256Hex(plaintext);
    const now = Date.now();
    const rows = await this.db
      .select()
      .from(apiTokens)
      .where(
        and(
          eq(apiTokens.tokenHash, tokenHash),
          isNull(apiTokens.revokedAt),
          or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, now)),
        ),
      )
      .limit(1)
      .all();
    const row = rows[0];
    if (!row) return null;

    if (!row.lastUsedAt || now - row.lastUsedAt > LAST_USED_DEBOUNCE_MS) {
      try {
        await this.db.update(apiTokens).set({ lastUsedAt: now }).where(eq(apiTokens.id, row.id));
      } catch (err) {
        this.logger.warn('api_token_last_used_update_failed', {
          id: row.id,
          error: String(err),
        });
      }
    }

    return {
      id: row.id,
      scopes: JSON.parse(row.scopes) as ApiScope[],
      subjectType: row.subjectType,
      subjectUserId: row.subjectUserId,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt,
      lastUsedAt: row.lastUsedAt,
    };
  }
}
