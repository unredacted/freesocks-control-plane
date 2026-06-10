import { z } from 'zod';

/**
 * W2 admin rate-limit policy shape (the GET/PATCH /api/v1/admin/rate-limits
 * surface). `isDefault` flags whether the effective values equal the compiled
 * default; `default` carries the compiled default so the UI can offer a "reset".
 */
export const RateLimitPolicyAdmin = z.object({
  key: z.string(),
  max: z.number().int(),
  windowMs: z.number().int(),
  enabled: z.boolean(),
  isDefault: z.boolean(),
  default: z.object({ max: z.number().int(), windowMs: z.number().int(), enabled: z.boolean() }),
});
export type RateLimitPolicyAdmin = z.infer<typeof RateLimitPolicyAdmin>;

export const RateLimitListResponse = z.object({ policies: z.array(RateLimitPolicyAdmin) });
export type RateLimitListResponse = z.infer<typeof RateLimitListResponse>;

export const RateLimitUpdateRequest = z.object({
  policyKey: z.string(),
  max: z.number().int().min(1).max(1_000_000),
  windowMs: z.number().int().min(1000).max(7 * 86_400_000),
  enabled: z.boolean(),
});
export type RateLimitUpdateRequest = z.infer<typeof RateLimitUpdateRequest>;
