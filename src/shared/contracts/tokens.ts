import { z } from 'zod';
import { ApiScopeArray } from './scopes';

export const TokenSummary = z.object({
  id: z.number().int(),
  name: z.string(),
  tokenPrefix: z.string(),
  scopes: ApiScopeArray,
  subjectType: z.enum(['service', 'user']),
  subjectUserId: z.number().int().nullable(),
  expiresAt: z.string().datetime().nullable(),
  lastUsedAt: z.string().datetime().nullable(),
  revokedAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
});
export type TokenSummary = z.infer<typeof TokenSummary>;

export const CreateTokenRequest = z.object({
  name: z.string().min(1).max(128),
  scopes: ApiScopeArray.min(1),
  subjectType: z.enum(['service', 'user']).default('service'),
  subjectUserId: z.number().int().nullable().optional(),
  expiresInDays: z.number().int().positive().nullable().optional(),
});
export type CreateTokenRequest = z.infer<typeof CreateTokenRequest>;

export const CreateTokenResponse = z.object({
  token: TokenSummary,
  /**
   * The plaintext token. Returned ONCE on creation; never retrievable again.
   * Format: `fsv1_<43 base64url chars>`.
   */
  plaintext: z.string(),
});
export type CreateTokenResponse = z.infer<typeof CreateTokenResponse>;

export const ListTokensResponse = z.object({
  tokens: z.array(TokenSummary),
});
export type ListTokensResponse = z.infer<typeof ListTokensResponse>;
