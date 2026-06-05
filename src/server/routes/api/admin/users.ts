import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { and, eq, sql } from 'drizzle-orm';
import { tiers, users, subscriptions } from '../../../db/schema';
import type { AppEnv } from '../../../env';
import { requireScope } from '../../../middleware/require-scope';
import { UserAdmin, UserSearchQuery } from '../../../../shared/contracts/admin';
import { resolveActiveSubscription } from '../../../lib/current-subscription';
import { NotFoundError, ValidationError } from '../../../lib/errors';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

function rowToContract(
  u: typeof users.$inferSelect,
  tierSlug: string,
  backendUserId: string | null,
  backend: 'remnawave' | 'outline' | null,
): unknown {
  return {
    id: u.id,
    authentikSubject: u.authentikSubject,
    email: u.email,
    status: u.status,
    tierSlug,
    membershipExpiresAt: u.membershipExpiresAt
      ? new Date(u.membershipExpiresAt).toISOString()
      : null,
    backendUserId,
    backend,
    createdAt: new Date(u.createdAt).toISOString(),
  };
}

const UsersListResponse = z
  .object({ users: z.array(UserAdmin), nextCursor: z.string().nullable() })
  .openapi('UsersListResponse');
const SingleUserResponse = z.object({ user: UserAdmin }).openapi('SingleUserResponse');

const listUsersRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Users'],
  summary: 'Search users',
  security: [{ apiToken: ['admin:users:read'] }],
  request: { query: UserSearchQuery },
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: UsersListResponse } } },
  },
});

/**
 * Escape SQL LIKE wildcards in a user-supplied search term so a query like
 * `q=%` or `q=_` doesn't enumerate the entire users table. We use `\` as the
 * escape char and add an explicit ESCAPE clause to the LIKE expressions below.
 */
function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (m) => `\\${m}`);
}

router.use('/', requireScope('admin:users:read'));
router.openapi(listUsersRoute, async (c) => {
  const platform = c.var.platform;
  const data = c.req.valid('query');
  const conditions = [];
  if (data.q) {
    const safe = `%${escapeLike(data.q)}%`;
    conditions.push(
      sql`(${users.email} LIKE ${safe} ESCAPE '\\' OR ${users.authentikSubject} LIKE ${safe} ESCAPE '\\')`,
    );
  }
  if (data.status) conditions.push(eq(users.status, data.status));
  const cursorN = data.cursor ? parseInt(data.cursor, 10) : 0;
  if (cursorN) conditions.push(sql`${users.id} > ${cursorN}`);
  const rows = await platform.db
    .select()
    .from(users)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(users.id)
    .limit(data.limit + 1)
    .all();
  const hasMore = rows.length > data.limit;
  const sliced = rows.slice(0, data.limit);
  const tierMap = new Map<number, string>();
  for (const t of await c.var.services.tierPolicy.listAll()) tierMap.set(t.id, t.slug);
  // Populate backend/backendUserId from each user's active subscription. This
  // is a per-row lookup, but the admin list is paged (small `limit`) and
  // admin-only, so the extra reads are acceptable; using the shared resolver
  // keeps the precedence (currentSubscriptionId → newest active) identical to
  // the single-user and member-facing endpoints.
  const usersOut = await Promise.all(
    sliced.map(async (u) => {
      const sub = await resolveActiveSubscription(platform.db, u);
      return UserAdmin.parse(
        rowToContract(
          u,
          tierMap.get(u.tierId) ?? 'unknown',
          sub?.backendUserId ?? null,
          sub?.backend ?? null,
        ),
      );
    }),
  );
  return c.json(
    {
      users: usersOut,
      nextCursor:
        hasMore && sliced[sliced.length - 1] ? String(sliced[sliced.length - 1]!.id) : null,
    },
    200,
  );
});

const getUserRoute = createRoute({
  method: 'get',
  path: '/{id}',
  tags: ['Admin: Users'],
  summary: 'Get one user by id',
  security: [{ apiToken: ['admin:users:read'] }],
  request: { params: z.object({ id: z.string().regex(/^\d+$/) }) },
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: SingleUserResponse } } },
    404: {
      description: 'Not found',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(getUserRoute, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  const platform = c.var.platform;
  const userRow = await platform.db.select().from(users).where(eq(users.id, id)).limit(1).all();
  const u = userRow[0];
  if (!u) throw new NotFoundError('user');
  const tier = await platform.db.select().from(tiers).where(eq(tiers.id, u.tierId)).limit(1).all();
  const sub = await resolveActiveSubscription(platform.db, u);
  return c.json(
    {
      user: UserAdmin.parse(
        rowToContract(
          u,
          tier[0]?.slug ?? 'unknown',
          sub?.backendUserId ?? null,
          sub?.backend ?? null,
        ),
      ),
    },
    200,
  );
});

const OkResponse = z
  .object({ ok: z.boolean(), skipped: z.boolean().optional(), reason: z.string().optional() })
  .openapi('OkResponse');

function makeUserOpRoute(opPath: 'disable' | 'reset-traffic' | 'resync', summary: string) {
  return createRoute({
    method: 'post',
    path: `/{id}/${opPath}`,
    tags: ['Admin: Users'],
    summary,
    security: [{ apiToken: ['admin:users:write'] }],
    request: { params: z.object({ id: z.string().regex(/^\d+$/) }) },
    responses: {
      200: { description: 'OK', content: { 'application/json': { schema: OkResponse } } },
      404: {
        description: 'Not found',
        content: { 'application/json': { schema: ApiErrorResponse } },
      },
    },
  });
}

router.use('/:id/*', requireScope('admin:users:write'));

router.openapi(
  makeUserOpRoute('disable', 'Disable a user on their backend + locally'),
  async (c) => {
    const id = parseInt(c.req.valid('param').id, 10);
    const services = c.var.services;
    const platform = c.var.platform;
    const u = (await platform.db.select().from(users).where(eq(users.id, id)).limit(1).all())[0];
    if (!u) throw new NotFoundError('user');
    // Best-effort backend disable. Look up the ACTIVE subscription only —
    // tombstoned rows (24h regenerate/switch-backend grace) point at the
    // backend user the admin wanted to leave alone, and disabling them via
    // this path would yank the rug on a legitimate grace window.
    const subRow = (
      await platform.db
        .select()
        .from(subscriptions)
        .where(and(eq(subscriptions.userId, id), eq(subscriptions.state, 'active')))
        .limit(1)
        .all()
    )[0];
    if (subRow) {
      await services.backends.get(subRow.backend).updateUser(subRow.backendUserId, {
        status: 'disabled',
      });
    }
    await platform.db
      .update(users)
      .set({ status: 'disabled', disabledReason: 'admin_action', updatedAt: Date.now() })
      .where(eq(users.id, id));
    await services.audit.record({
      actorType: 'admin',
      actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
      action: 'user.disable',
      targetType: 'user',
      targetId: String(id),
      requestId: c.var.requestId,
    });
    return c.json({ ok: true }, 200);
  },
);

router.openapi(
  makeUserOpRoute('reset-traffic', "Reset the user's traffic counter on the backend"),
  async (c) => {
    const id = parseInt(c.req.valid('param').id, 10);
    const services = c.var.services;
    const platform = c.var.platform;
    const subRow = (
      await platform.db
        .select()
        .from(subscriptions)
        .where(and(eq(subscriptions.userId, id), eq(subscriptions.state, 'active')))
        .limit(1)
        .all()
    )[0];
    if (!subRow) throw new NotFoundError('subscription');
    await services.backends.get(subRow.backend).resetUserTraffic(subRow.backendUserId);
    await services.audit.record({
      actorType: 'admin',
      actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
      action: 'user.reset_traffic',
      targetType: 'user',
      targetId: String(id),
      requestId: c.var.requestId,
    });
    return c.json({ ok: true }, 200);
  },
);

// Suppress an unused-import warning when validation runs.
void ValidationError;

export default router;
