import { z } from 'zod';

export const TrafficLimitStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']);
export type TrafficLimitStrategy = z.infer<typeof TrafficLimitStrategy>;

export const RemnawaveUserStatus = z.enum(['ACTIVE', 'DISABLED', 'LIMITED', 'EXPIRED']);
export type RemnawaveUserStatus = z.infer<typeof RemnawaveUserStatus>;

export const CreateUserInput = z.object({
  username: z.string().min(1).max(64),
  status: RemnawaveUserStatus.optional(),
  trafficLimitBytes: z.number().int().nonnegative().nullable().optional(),
  trafficLimitStrategy: TrafficLimitStrategy.optional(),
  expireAt: z.string().datetime().nullable().optional(),
  hwidDeviceLimit: z.number().int().nonnegative().nullable().optional(),
  description: z.string().max(255).optional(),
  tag: z.string().max(64).optional(),
  email: z.string().email().optional(),
  telegramId: z.string().optional(),
  activeInternalSquads: z.array(z.string().uuid()).optional(),
  configProfileUuid: z.string().uuid().optional(),
});
export type CreateUserInput = z.infer<typeof CreateUserInput>;

export const RemnawaveUser = z.object({
  uuid: z.string().uuid(),
  shortUuid: z.string(),
  subscriptionUuid: z.string(),
  username: z.string(),
  status: RemnawaveUserStatus,
  trafficLimitBytes: z.number().int().nonnegative().nullable(),
  trafficLimitStrategy: TrafficLimitStrategy,
  usedTrafficBytes: z.number().int().nonnegative(),
  lifetimeUsedTrafficBytes: z.number().int().nonnegative().optional(),
  expireAt: z.string().datetime().nullable(),
  hwidDeviceLimit: z.number().int().nonnegative().nullable(),
  description: z.string().nullable().optional(),
  tag: z.string().nullable().optional(),
  email: z.string().email().nullable().optional(),
  subscriptionUrl: z.string().url(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type RemnawaveUser = z.infer<typeof RemnawaveUser>;

export const UpdateUserPatch = z.object({
  status: RemnawaveUserStatus.optional(),
  trafficLimitBytes: z.number().int().nonnegative().nullable().optional(),
  trafficLimitStrategy: TrafficLimitStrategy.optional(),
  expireAt: z.string().datetime().nullable().optional(),
  hwidDeviceLimit: z.number().int().nonnegative().nullable().optional(),
  description: z.string().max(255).optional(),
  tag: z.string().max(64).optional(),
  activeInternalSquads: z.array(z.string().uuid()).optional(),
});
export type UpdateUserPatch = z.infer<typeof UpdateUserPatch>;

export const RawSubscriptionResponse = z.object({
  user: RemnawaveUser,
  rawHosts: z.array(z.unknown()).optional(),
  resolvedProxyConfigs: z.array(z.unknown()).optional(),
  links: z.array(z.string()).optional(),
});
export type RawSubscriptionResponse = z.infer<typeof RawSubscriptionResponse>;

/**
 * A registered HWID device for a Remnawave user. The exact response shape
 * varies slightly between Remnawave panel versions; this is permissive
 * (accepts unknown extra fields) so we don't break on minor upstream changes.
 */
export const HwidDevice = z.object({
  hwid: z.string(),
  deviceName: z.string().nullable().optional(),
  platform: z.string().nullable().optional(),
  firstSeenAt: z.string().datetime().nullable().optional(),
  lastSeenAt: z.string().datetime().nullable().optional(),
});
export type HwidDevice = z.infer<typeof HwidDevice>;

export const HwidDevicesResponse = z.object({
  devices: z.array(HwidDevice).default([]),
});
export type HwidDevicesResponse = z.infer<typeof HwidDevicesResponse>;
