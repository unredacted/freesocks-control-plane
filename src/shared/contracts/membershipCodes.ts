import { z } from 'zod';

/**
 * W4 membership redemption codes. Member redeem + admin mint/list/revoke shapes.
 * Codes themselves (plaintext) are returned only once, at mint; the admin list
 * exposes a masked prefix, never the hash or full code.
 */

// --- member: redeem ---------------------------------------------------------

export const RedeemCodeRequest = z.object({
  code: z.string().min(1),
});
export type RedeemCodeRequest = z.infer<typeof RedeemCodeRequest>;

export const RedeemCodeResponse = z.object({
  ok: z.literal(true),
  tierSlug: z.string(),
  tierName: z.string(),
  durationDays: z.number().int(),
  membershipExpiresAt: z.string().datetime(),
});
export type RedeemCodeResponse = z.infer<typeof RedeemCodeResponse>;

// --- admin: mint / list / revoke -------------------------------------------

export const MintCodesRequest = z.object({
  tierId: z.string().min(1),
  durationDays: z.number().int().min(1).max(3650),
  count: z.number().int().min(1).max(100),
  note: z.string().max(500).optional(),
});
export type MintCodesRequest = z.infer<typeof MintCodesRequest>;

export const MintCodesResponse = z.object({
  // The plaintext codes, revealed ONCE. Never recoverable after this response.
  codes: z.array(z.string()),
  batchId: z.string(),
});
export type MintCodesResponse = z.infer<typeof MintCodesResponse>;

export const MembershipCodeAdmin = z.object({
  id: z.string(),
  codePrefix: z.string(),
  tierSlug: z.string().nullable(),
  durationDays: z.number().int(),
  status: z.enum(['active', 'redeemed', 'revoked']),
  note: z.string().nullable(),
  batchId: z.string().nullable(),
  redeemedByUserId: z.string().nullable(),
  redeemedAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
});
export type MembershipCodeAdmin = z.infer<typeof MembershipCodeAdmin>;

export const MembershipCodeListResponse = z.object({
  codes: z.array(MembershipCodeAdmin),
});
export type MembershipCodeListResponse = z.infer<typeof MembershipCodeListResponse>;
