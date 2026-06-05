import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env';
import type { ApiScope } from '../../shared/contracts/scopes';
import { ForbiddenError, UnauthenticatedError } from '../lib/errors';

/**
 * Gates a route on the caller having a particular scope.
 *
 * Acceptance:
 *   - Admin cookie session → all scopes accepted (admins are unrestricted within the CMS).
 *   - Admin/service API token → must include the required scope.
 *   - Member cookie/JWT session → accepted only for member-tier scopes (subscription:*, account:*).
 *
 * Anonymous → 401.
 */
export function requireScope(...required: ApiScope[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (c.var.admin) {
      return next();
    }
    if (c.var.apiAuth) {
      const have = new Set(c.var.apiAuth.scopes);
      const missing = required.filter((s) => !have.has(s));
      if (missing.length > 0) {
        throw new ForbiddenError('Insufficient token scope', { required, missing });
      }
      return next();
    }
    if (c.var.member) {
      const memberScopes: ApiScope[] = [
        'subscription:read',
        'subscription:write',
        'account:read',
        'account:write',
      ];
      const allowedSet = new Set<ApiScope>(memberScopes);
      const missing = required.filter((s) => !allowedSet.has(s));
      if (missing.length > 0) {
        throw new ForbiddenError('Member sessions cannot perform admin actions', {
          required,
          missing,
        });
      }
      return next();
    }
    throw new UnauthenticatedError('Authentication required');
  };
}

/**
 * Scope gate that applies ONLY to API-token callers. Anonymous callers and
 * cookie/JWT members pass through untouched — the route handler's own
 * member/anonymous branching decides their fate.
 *
 * Why this exists: a `subjectType:'user'` API token sets BOTH c.var.apiAuth
 * AND c.var.member (see bearer-auth.ts), so without this gate a user-subject
 * token that was never granted subscription:* could still act as that member
 * on routes (like /subscription) that branch only on c.var.member. Plain
 * `requireScope` is too strict here: it 401s anonymous callers, which would
 * break the intentional Turnstile path on POST /subscription.
 */
export function requireScopeIfToken(...required: ApiScope[]): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (c.var.admin) {
      return next();
    }
    if (c.var.apiAuth) {
      const have = new Set(c.var.apiAuth.scopes);
      const missing = required.filter((s) => !have.has(s));
      if (missing.length > 0) {
        throw new ForbiddenError('Insufficient token scope', { required, missing });
      }
      return next();
    }
    // No token: anonymous or a cookie/JWT member. Let the handler decide.
    return next();
  };
}
