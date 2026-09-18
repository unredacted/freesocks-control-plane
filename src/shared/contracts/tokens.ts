import { z } from 'zod';
import { ApiScopeArray } from './scopes';

export const TokenSummary = z.object({
  // Convex document ids are opaque strings.
  id: z.string(),
  name: z.string(),
  tokenPrefix: z.string(),
  scopes: ApiScopeArray,
  subjectType: z.enum(['service', 'user']),
  subjectUserId: z.string().nullable(),
  /** The registration boundary of an `admin:edges:register` token (docs/edges.md); null otherwise. */
  edgeRegistration: z
    .object({ backendServerIds: z.array(z.string()), nodeNames: z.array(z.string()) })
    .nullable()
    .default(null),
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
  subjectUserId: z.string().nullable().optional(),
  expiresInDays: z.number().int().positive().nullable().optional(),
  /** Required with the `admin:edges:register` scope, refused without it. */
  edgeRegistration: z
    .object({
      backendServerIds: z.array(z.string()).min(1),
      nodeNames: z.array(z.string()).optional(),
    })
    .optional(),
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
