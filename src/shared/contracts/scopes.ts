import { z } from 'zod';

/**
 * Capability vocabulary for admin-issued API tokens.
 * Wildcards are not supported in v1. List each scope explicitly.
 */
export const ApiScope = z.enum([
  // Member-equivalent scopes (a service token can act on behalf of any user when granted these)
  'subscription:read',
  'subscription:write',
  'account:read',
  'account:write',

  // Admin scopes
  'admin:tiers:read',
  'admin:tiers:write',
  'admin:users:read',
  'admin:users:write',
  'admin:admins:read',
  'admin:admins:write',
  'admin:audit:read',
  'admin:tokens:read',
  'admin:tokens:write',
  'admin:settings:read',
  'admin:settings:write',
  'admin:servers:read',
  'admin:servers:write',
  'admin:status:read',
]);
export type ApiScope = z.infer<typeof ApiScope>;

export const ApiScopeArray = z.array(ApiScope);

export const SCOPE_GROUPS = {
  member: ['subscription:read', 'subscription:write', 'account:read', 'account:write'] as const,
  admin: [
    'admin:tiers:read',
    'admin:tiers:write',
    'admin:users:read',
    'admin:users:write',
    'admin:admins:read',
    'admin:admins:write',
    'admin:audit:read',
    'admin:tokens:read',
    'admin:tokens:write',
    'admin:settings:read',
    'admin:settings:write',
    'admin:servers:read',
    'admin:servers:write',
    'admin:status:read',
  ] as const,
};
