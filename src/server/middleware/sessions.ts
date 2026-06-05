import { eq } from 'drizzle-orm';
import type { MiddlewareHandler } from 'hono';
import { getCookie } from 'hono/cookie';
import type { AppEnv } from '../env';
import { users } from '../db/schema';
import { verifySignedValue } from '../lib/cookies';
import type { MemberSession, AdminSession } from '../env';

export const MEMBER_COOKIE = 'fs_session';
export const ADMIN_COOKIE = 'fs_admin_session';

/** How often to re-fetch profile fields (email, displayName) from the DB. */
const SESSION_REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;

export const sessionOAuthMw: MiddlewareHandler<AppEnv> = async (c, next) => {
  const cookieValue = getCookie(c, MEMBER_COOKIE);
  if (cookieValue) {
    const platform = c.var.platform;
    const sid = await verifySignedValue(cookieValue, platform.config.SESSION_SIGNING_KEY);
    if (sid) {
      let session = await platform.kv.sessions.getJson<MemberSession>(`session:member:${sid}`);
      if (session) {
        // If the cookie session's profile snapshot is older than the refresh
        // interval, pull fresh email + (eventually) displayName from the DB.
        // The user's email is the most likely thing to drift after an
        // Authentik change; keeping it stale for up to 30 days (the cookie
        // lifetime) is a meaningful UX bug.
        const stale =
          !session.refreshedAt || Date.now() - session.refreshedAt > SESSION_REFRESH_INTERVAL_MS;
        if (stale) {
          const userRow = await platform.db
            .select()
            .from(users)
            .where(eq(users.id, session.userId))
            .limit(1)
            .all();
          const u = userRow[0];
          if (u) {
            session = {
              ...session,
              email: u.email ?? session.email,
              refreshedAt: Date.now(),
            };
            // Best-effort write-back; don't block the request on a slow KV.
            platform.waitUntil(
              platform.kv.sessions.putJson(`session:member:${sid}`, session, {
                expirationTtl: 30 * 86_400,
              }),
            );
          }
        }
        c.set('member', session);
      }
    }
  }
  await next();
};

export const sessionPasskeyMw: MiddlewareHandler<AppEnv> = async (c, next) => {
  const cookieValue = getCookie(c, ADMIN_COOKIE);
  if (cookieValue) {
    const platform = c.var.platform;
    const sid = await verifySignedValue(cookieValue, platform.config.ADMIN_SESSION_SIGNING_KEY);
    if (sid) {
      const session = await platform.kv.sessions.getJson<AdminSession>(`session:admin:${sid}`);
      if (session) c.set('admin', session);
    }
  }
  await next();
};
