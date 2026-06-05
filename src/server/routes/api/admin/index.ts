// This file splits the admin surface into two routers:
//   - adminAuthRouter: passkey ceremonies, mounted unversioned at /api/admin/auth
//   - adminApiRouter:  tier/user/audit/token resources, mounted versioned at /api/v1/admin
import { OpenAPIHono } from '@hono/zod-openapi';
import { Hono } from 'hono';
import type { AppEnv } from '../../../env';
import { requireAdmin } from '../../../middleware/require-admin';
import auth from './auth';
import tiers from './tiers';
import users from './users';
import audit from './audit';
import tokens from './tokens';
import settings from './settings';
import outlineServers from './outline-servers';

export const adminAuthRouter = new Hono<AppEnv>().route('/', auth);

export const adminApiRouter = new OpenAPIHono<AppEnv>();
adminApiRouter.use('*', async (c, next) => {
  // Defense-in-depth gate before per-route `requireScope(...)` checks. Three
  // outcomes:
  //   1. Admin cookie session    → pass (admin can do anything).
  //   2. Token with any admin:*  → pass; per-route requireScope refines.
  //   3. Token without admin:*   → 403 (authenticated, just not authorized
  //      anywhere in the admin tree).
  //   4. No auth at all          → requireAdmin → 401.
  // Without (3), a misconfigured route that forgot `requireScope` would be
  // reachable by any member-tier token.
  if (c.var.admin) return next();
  if (c.var.apiAuth) {
    const hasAdminScope = c.var.apiAuth.scopes.some((s) => s.startsWith('admin:'));
    if (hasAdminScope) return next();
    return c.json(
      {
        error: {
          code: 'auth.forbidden',
          message: 'Token does not carry any admin scope',
        },
      },
      403,
    );
  }
  return requireAdmin(c, next);
});
adminApiRouter.route('/tiers', tiers);
adminApiRouter.route('/users', users);
adminApiRouter.route('/audit', audit);
adminApiRouter.route('/tokens', tokens);
adminApiRouter.route('/settings', settings);
adminApiRouter.route('/outline-servers', outlineServers);
