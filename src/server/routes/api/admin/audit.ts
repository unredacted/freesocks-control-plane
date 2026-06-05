import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { desc, sql } from 'drizzle-orm';
import { auditLog } from '../../../db/schema';
import type { AppEnv } from '../../../env';
import { requireScope } from '../../../middleware/require-scope';
import { AuditEntry } from '../../../../shared/contracts/admin';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

const AuditListResponse = z
  .object({ entries: z.array(AuditEntry), nextCursor: z.string().nullable() })
  .openapi('AuditListResponse');

/**
 * Cursor format: `${createdAt}:${id}` (both unsigned integers).
 *
 * Keyset pagination on `(created_at desc, id desc)` is correct under
 * concurrent inserts: a new row inserted between page-1 and page-2 has
 * `created_at >= last.created_at`, so the next-page predicate
 * `(created_at, id) < (last.created_at, last.id)` correctly excludes it.
 *
 * Pure id-based pagination breaks if rows arrive out-of-order with respect
 * to created_at (e.g. clock skew on D1, or system_time jumps).
 */
function encodeCursor(createdAt: number, id: number): string {
  return `${createdAt}:${id}`;
}
function decodeCursor(cursor: string): { createdAt: number; id: number } | null {
  const m = cursor.match(/^(\d+):(\d+)$/);
  if (!m) return null;
  return { createdAt: parseInt(m[1]!, 10), id: parseInt(m[2]!, 10) };
}

const listAuditRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Audit'],
  summary: 'List audit log entries (most-recent first)',
  security: [{ apiToken: ['admin:audit:read'] }],
  request: {
    query: z.object({
      limit: z.string().regex(/^\d+$/).optional(),
      cursor: z
        .string()
        .regex(/^\d+:\d+$/)
        .optional(),
    }),
  },
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: AuditListResponse } } },
    401: {
      description: 'Unauthenticated',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.use('/', requireScope('admin:audit:read'));
router.openapi(listAuditRoute, async (c) => {
  const platform = c.var.platform;
  const q = c.req.valid('query');
  const limit = Math.min(parseInt(q.limit ?? '100', 10), 500);
  const cursor = q.cursor ? decodeCursor(q.cursor) : null;

  const conditions = cursor
    ? sql`(${auditLog.createdAt}, ${auditLog.id}) < (${cursor.createdAt}, ${cursor.id})`
    : undefined;
  const rows = await platform.db
    .select()
    .from(auditLog)
    .where(conditions)
    .orderBy(desc(auditLog.createdAt), desc(auditLog.id))
    .limit(limit + 1)
    .all();
  const hasMore = rows.length > limit;
  const sliced = rows.slice(0, limit);
  const last = sliced[sliced.length - 1];
  return c.json(
    {
      entries: sliced.map((r) =>
        AuditEntry.parse({
          id: r.id,
          actorType: r.actorType,
          actorId: r.actorId,
          action: r.action,
          targetType: r.targetType,
          targetId: r.targetId,
          payload: r.payload ? JSON.parse(r.payload) : null,
          requestId: r.requestId,
          createdAt: new Date(r.createdAt).toISOString(),
        }),
      ),
      nextCursor: hasMore && last ? encodeCursor(last.createdAt, last.id) : null,
    },
    200,
  );
});

export default router;
