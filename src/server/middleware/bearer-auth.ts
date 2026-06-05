import { eq } from 'drizzle-orm';
import type { MiddlewareHandler } from 'hono';
import { users } from '../db/schema';
import type { AppEnv, MemberSession } from '../env';
import { TOKEN_PREFIX } from '../services/api-tokens';

/**
 * Bearer-token authentication.
 *
 * Branches by token prefix:
 *   - `fsv1_*`  → admin/service token, looked up in api_tokens. Sets c.var.apiAuth.
 *   - otherwise → treated as an Authentik OIDC access token (JWT). Verified
 *     against Authentik's JWKS, mapped to a local user via `authentik_subject`,
 *     and exposed as a regular member session via c.var.member.
 *
 * This middleware never errors on a bad/absent token. Authorization is enforced
 * by `requireAdmin` / `requireScope` / `requireScopeIfToken` further down the chain,
 * so unauthenticated routes (healthz, OAuth ceremonies) still work.
 */
export const bearerAuthMw: MiddlewareHandler<AppEnv> = async (c, next) => {
  const header = c.req.header('authorization');
  if (!header || !header.toLowerCase().startsWith('bearer ')) {
    return next();
  }
  const token = header.slice(7).trim();
  if (!token) return next();

  const services = c.var.services;
  const logger = c.var.logger;

  if (token.startsWith(TOKEN_PREFIX)) {
    const resolved = await services.apiTokens.resolve(token);
    if (resolved) {
      c.set('apiAuth', {
        tokenId: resolved.id,
        scopes: resolved.scopes,
        subjectType: resolved.subjectType,
        subjectUserId: resolved.subjectUserId,
      });
      // If the token impersonates a user, also populate c.var.member so member-only
      // routes work transparently.
      if (resolved.subjectType === 'user' && resolved.subjectUserId) {
        const userRows = await c.var.platform.db
          .select()
          .from(users)
          .where(eq(users.id, resolved.subjectUserId))
          .limit(1)
          .all();
        const u = userRows[0];
        if (u && u.authentikSubject) {
          const session: MemberSession = {
            sessionId: `token:${resolved.id}`,
            userId: u.id,
            contactId: null,
            authentikSubject: u.authentikSubject,
            email: u.email ?? undefined,
            source: 'jwt',
          };
          c.set('member', session);
        }
      }
    } else {
      logger.debug('bearer_admin_token_unresolved', { prefix: token.slice(0, 12) });
    }
    return next();
  }

  // Treat as Authentik JWT
  try {
    const verified = await services.authentikJwt.verify(token);
    const userRows = await c.var.platform.db
      .select()
      .from(users)
      .where(eq(users.authentikSubject, verified.sub))
      .limit(1)
      .all();
    const u = userRows[0];
    if (!u) {
      // Authentik knows them but our DB doesn't yet. Auto-provision as a free-tier
      // user so first mobile login works. Paid tier later arrives via the
      // entitlement seam (setMembership).
      const tier = await services.tierPolicy.getDefaultFreeTier();
      const inserted = await c.var.platform.db
        .insert(users)
        .values({
          authentikSubject: verified.sub,
          email: verified.email ?? null,
          tierId: tier.id,
          status: 'active',
        })
        .returning();
      const newUser = inserted[0];
      if (!newUser) {
        // Insert returned no row — DB issue. Log loudly and leave the request
        // unauthenticated so downstream gates can return 401/503 cleanly rather
        // than the user proceeding silently with no member context.
        logger.error('bearer_jwt_provision_failed', {
          authentikSubject: verified.sub,
          reason: 'insert returned no row',
        });
      } else {
        c.set('member', {
          sessionId: `jwt:${verified.sub}`,
          userId: newUser.id,
          contactId: null,
          authentikSubject: verified.sub,
          email: verified.email,
          source: 'jwt',
        });
      }
    } else {
      c.set('member', {
        sessionId: `jwt:${verified.sub}`,
        userId: u.id,
        contactId: null,
        authentikSubject: verified.sub,
        email: u.email ?? verified.email,
        displayName: verified.name,
        source: 'jwt',
      });
    }
  } catch (err) {
    // Verification failed - leave context unauthenticated. Downstream gates will 401.
    logger.debug('bearer_jwt_verify_failed', { error: String(err) });
  }

  await next();
};
