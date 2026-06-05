import { z } from 'zod';

export const TierSlug = z.enum(['free', 'member', 'patron', 'custom']);
export type TierSlug = z.infer<typeof TierSlug>;

export const UserStatus = z.enum(['active', 'grace', 'disabled', 'deleted']);
export type UserStatus = z.infer<typeof UserStatus>;

export const SubscriptionFormat = z.enum(['auto', 'clash', 'singbox', 'v2ray', 'ssconf', 'raw']);
export type SubscriptionFormat = z.infer<typeof SubscriptionFormat>;

export const ApiError = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.unknown().optional(),
  }),
  requestId: z.string().optional(),
});
export type ApiError = z.infer<typeof ApiError>;
