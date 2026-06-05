import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { eq } from 'drizzle-orm';
import { tiers } from '../../../db/schema';
import type { AppEnv } from '../../../env';
import { requireScope } from '../../../middleware/require-scope';
import { TierUpsert, TierAdmin } from '../../../../shared/contracts/admin';
import { ValidationError, NotFoundError } from '../../../lib/errors';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

function rowToContract(t: typeof tiers.$inferSelect): unknown {
  return {
    id: t.id,
    slug: t.slug,
    name: t.name,
    description: t.description,
    backend: t.backend,
    monthlyTrafficGb: t.monthlyTrafficGb,
    deviceLimit: t.deviceLimit,
    hwidLimit: t.hwidLimit,
    hwidEnabled: t.hwidEnabled,
    trafficStrategy: t.trafficStrategy,
    remnawaveSquadUuid: t.remnawaveSquadUuid,
    isDefaultFree: t.isDefaultFree,
    isActive: t.isActive,
    priority: t.priority,
    expirationDaysAfterMembershipLapse: t.expirationDaysAfterMembershipLapse,
    createdAt: new Date(t.createdAt).toISOString(),
    updatedAt: new Date(t.updatedAt).toISOString(),
  };
}

const TiersListResponse = z.object({ tiers: z.array(TierAdmin) }).openapi('TiersListResponse');

const listTiersRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Tiers'],
  summary: 'List all tiers',
  security: [{ apiToken: ['admin:tiers:read'] }],
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: TiersListResponse } } },
    401: {
      description: 'Unauthenticated',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

// IMPORTANT: every middleware that gates this router must be registered
// here, BEFORE any `router.openapi(...)` handler. Hono applies middleware
// in registration order to routes registered AFTER it — a `router.use(...)`
// at the bottom of the file does NOT protect handlers declared earlier.
// Read scope blankets every request; write scope is method-gated below.
router.use('/', requireScope('admin:tiers:read'));
router.use('/', async (c, next) => {
  if (c.req.method === 'POST') return requireScope('admin:tiers:write')(c, next);
  return next();
});
router.use('/:id', async (c, next) => {
  if (c.req.method === 'PATCH' || c.req.method === 'DELETE') {
    return requireScope('admin:tiers:write')(c, next);
  }
  return next();
});

router.openapi(listTiersRoute, async (c) => {
  const services = c.var.services;
  const list = await services.tierPolicy.listAll();
  return c.json({ tiers: list.map(rowToContract).map((t) => TierAdmin.parse(t)) }, 200);
});

const createTierRoute = createRoute({
  method: 'post',
  path: '/',
  tags: ['Admin: Tiers'],
  summary: 'Create a tier',
  security: [{ apiToken: ['admin:tiers:write'] }],
  request: {
    body: { content: { 'application/json': { schema: TierUpsert } }, required: true },
  },
  responses: {
    201: { description: 'Created', content: { 'application/json': { schema: TierAdmin } } },
    400: {
      description: 'Validation error',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(createTierRoute, async (c) => {
  const data = c.req.valid('json');
  const services = c.var.services;
  const inserted = await services.tierPolicy.upsert({ ...data } as never);
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'tier.create',
    targetType: 'tier',
    targetId: String(inserted.id),
    payload: { fields: Object.keys(data) },
    requestId: c.var.requestId,
  });
  return c.json(TierAdmin.parse(rowToContract(inserted)), 201);
});

const patchTierRoute = createRoute({
  method: 'patch',
  path: '/{id}',
  tags: ['Admin: Tiers'],
  summary: 'Update a tier',
  security: [{ apiToken: ['admin:tiers:write'] }],
  request: {
    params: z.object({ id: z.string().regex(/^\d+$/) }),
    body: { content: { 'application/json': { schema: TierUpsert.partial() } }, required: true },
  },
  responses: {
    200: { description: 'Updated', content: { 'application/json': { schema: TierAdmin } } },
    404: {
      description: 'Not found',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(patchTierRoute, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  const data = c.req.valid('json');
  const services = c.var.services;
  const platform = c.var.platform;
  const existing = await platform.db.select().from(tiers).where(eq(tiers.id, id)).limit(1).all();
  if (!existing[0]) throw new NotFoundError('tier');
  const merged = {
    ...existing[0],
    ...data,
    id,
  };
  const updated = await services.tierPolicy.upsert(merged as never);
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'tier.update',
    targetType: 'tier',
    targetId: String(id),
    payload: { fields: Object.keys(data) },
    requestId: c.var.requestId,
  });
  return c.json(TierAdmin.parse(rowToContract(updated)), 200);
});

const deleteTierRoute = createRoute({
  method: 'delete',
  path: '/{id}',
  tags: ['Admin: Tiers'],
  summary: 'Disable a tier (soft-delete)',
  security: [{ apiToken: ['admin:tiers:write'] }],
  request: {
    params: z.object({ id: z.string().regex(/^\d+$/) }),
  },
  responses: {
    200: {
      description: 'Disabled',
      content: { 'application/json': { schema: z.object({ ok: z.boolean() }) } },
    },
  },
});

router.openapi(deleteTierRoute, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  if (isNaN(id)) throw new ValidationError('Invalid tier id');
  const services = c.var.services;
  await services.tierPolicy.setActive(id, false);
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'tier.disable',
    targetType: 'tier',
    targetId: String(id),
    requestId: c.var.requestId,
  });
  return c.json({ ok: true }, 200);
});

// (Write-side gates are registered at the top of this file, alongside the
// read-side gate, so they actually run before the POST/PATCH/DELETE
// handlers below them in declaration order.)

export default router;
