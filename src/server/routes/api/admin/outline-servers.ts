/**
 * Admin CRUD for the `outline_servers` registry. The full `apiUrl` (which
 * contains the Outline Manager secret path segment) is never echoed back to
 * the SPA — list/get responses include `apiUrlMasked` instead.
 *
 * Includes a "test connection" endpoint that does `GET /access-keys` against
 * the proposed URL and reports the result. Useful when adding a new server
 * to catch TLS / 401 / DNS issues before saving.
 */
import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { eq } from 'drizzle-orm';
import { outlineServers } from '../../../db/schema';
import type { AppEnv } from '../../../env';
import { NotFoundError } from '../../../lib/errors';
import { requireScope } from '../../../middleware/require-scope';
import { OutlineClient } from '../../../providers/outline/client';
import { OutlineServerAdmin, OutlineServerUpsert } from '../../../../shared/contracts/admin';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

/**
 * Mask the secret path segment of an Outline Manager URL for display.
 * Pattern: `https://host:port/<secret>/...`. We keep host:port (operationally
 * useful) and replace the secret with `***` so admins can identify which
 * server is which without leaking the secret to the SPA.
 */
function maskApiUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/•••`;
  } catch {
    return '•••';
  }
}

function rowToContract(s: typeof outlineServers.$inferSelect): unknown {
  return {
    id: s.id,
    name: s.name,
    slug: s.slug,
    apiUrlMasked: maskApiUrl(s.apiUrl),
    websocketEnabled: s.websocketEnabled,
    websocketDomain: s.websocketDomain,
    prometheusUrl: s.prometheusUrl,
    isActive: s.isActive,
    priority: s.priority,
    lastHealthOkAt: s.lastHealthOkAt ? new Date(s.lastHealthOkAt).toISOString() : null,
    accessKeyCount: s.accessKeyCount,
    createdAt: new Date(s.createdAt).toISOString(),
    updatedAt: new Date(s.updatedAt).toISOString(),
  };
}

const ListResponse = z
  .object({ servers: z.array(OutlineServerAdmin) })
  .openapi('OutlineServersListResponse');

// --- list -------------------------------------------------------------------

const listRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Outline'],
  summary: 'List all registered Outline servers',
  security: [{ apiToken: ['admin:outline:read'] }],
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: ListResponse } } },
  },
});

router.use('/', requireScope('admin:outline:read'));
router.openapi(listRoute, async (c) => {
  const platform = c.var.platform;
  const rows = await platform.db.select().from(outlineServers).all();
  return c.json({ servers: rows.map((r) => OutlineServerAdmin.parse(rowToContract(r))) }, 200);
});

// --- create -----------------------------------------------------------------

const createRouteCfg = createRoute({
  method: 'post',
  path: '/',
  tags: ['Admin: Outline'],
  summary: 'Register a new Outline server',
  security: [{ apiToken: ['admin:outline:write'] }],
  request: {
    body: {
      content: { 'application/json': { schema: OutlineServerUpsert } },
      required: true,
    },
  },
  responses: {
    201: {
      description: 'Created',
      content: { 'application/json': { schema: OutlineServerAdmin } },
    },
  },
});

router.use('/', async (c, next) => {
  if (c.req.method === 'POST') return requireScope('admin:outline:write')(c, next);
  return next();
});

router.openapi(createRouteCfg, async (c) => {
  const data = c.req.valid('json');
  const services = c.var.services;
  const platform = c.var.platform;
  const inserted = await platform.db
    .insert(outlineServers)
    .values({
      name: data.name,
      slug: data.slug,
      apiUrl: data.apiUrl,
      websocketEnabled: data.websocketEnabled,
      websocketDomain: data.websocketDomain ?? null,
      prometheusUrl: data.prometheusUrl ?? null,
      isActive: data.isActive,
      priority: data.priority,
    })
    .returning();
  if (!inserted[0]) throw new Error('outline_server insert returned no rows');
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'outline_server.create',
    targetType: 'outline_server',
    targetId: String(inserted[0].id),
    // NOTE: deliberately do NOT include `apiUrl` in the audit payload — it
    // contains the secret. Only safe metadata.
    payload: { name: data.name, slug: data.slug, websocketEnabled: data.websocketEnabled },
    requestId: c.var.requestId,
  });
  return c.json(OutlineServerAdmin.parse(rowToContract(inserted[0])), 201);
});

// --- patch ------------------------------------------------------------------

const patchRouteCfg = createRoute({
  method: 'patch',
  path: '/{id}',
  tags: ['Admin: Outline'],
  summary: 'Update an Outline server registration',
  security: [{ apiToken: ['admin:outline:write'] }],
  request: {
    params: z.object({ id: z.string().regex(/^\d+$/) }),
    body: {
      content: { 'application/json': { schema: OutlineServerUpsert.partial() } },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Updated',
      content: { 'application/json': { schema: OutlineServerAdmin } },
    },
    404: {
      description: 'Not found',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.use('/:id', async (c, next) => {
  if (c.req.method === 'PATCH' || c.req.method === 'DELETE') {
    return requireScope('admin:outline:write')(c, next);
  }
  return next();
});

router.openapi(patchRouteCfg, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  const data = c.req.valid('json');
  const platform = c.var.platform;
  const services = c.var.services;
  const existing = await platform.db
    .select()
    .from(outlineServers)
    .where(eq(outlineServers.id, id))
    .limit(1)
    .all();
  if (!existing[0]) throw new NotFoundError('outline_server');
  await platform.db
    .update(outlineServers)
    .set({ ...data, updatedAt: Date.now() })
    .where(eq(outlineServers.id, id));
  const refreshed = (
    await platform.db.select().from(outlineServers).where(eq(outlineServers.id, id)).limit(1).all()
  )[0]!;
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'outline_server.update',
    targetType: 'outline_server',
    targetId: String(id),
    payload: {
      keys: Object.keys(data),
      // Never log apiUrl; the keys list is enough.
    },
    requestId: c.var.requestId,
  });
  return c.json(OutlineServerAdmin.parse(rowToContract(refreshed)), 200);
});

// --- delete -----------------------------------------------------------------

const deleteRouteCfg = createRoute({
  method: 'delete',
  path: '/{id}',
  tags: ['Admin: Outline'],
  summary: 'De-register an Outline server',
  description:
    'Removes the server from the pool. Existing subscriptions whose keys live on this ' +
    'server are NOT migrated — they continue to function (the access-key still exists ' +
    'on the upstream Outline server) but will fail on next regenerate. Use this only ' +
    'after you have migrated or grace-period-tombstoned everyone off the server.',
  security: [{ apiToken: ['admin:outline:write'] }],
  request: { params: z.object({ id: z.string().regex(/^\d+$/) }) },
  responses: {
    200: {
      description: 'Removed',
      content: { 'application/json': { schema: z.object({ ok: z.boolean() }) } },
    },
    404: {
      description: 'Not found',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(deleteRouteCfg, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  const platform = c.var.platform;
  const services = c.var.services;
  const existing = await platform.db
    .select()
    .from(outlineServers)
    .where(eq(outlineServers.id, id))
    .limit(1)
    .all();
  if (!existing[0]) throw new NotFoundError('outline_server');
  await platform.db.delete(outlineServers).where(eq(outlineServers.id, id));
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'outline_server.delete',
    targetType: 'outline_server',
    targetId: String(id),
    payload: { slug: existing[0].slug, name: existing[0].name },
    requestId: c.var.requestId,
  });
  return c.json({ ok: true }, 200);
});

// --- test connection --------------------------------------------------------

const TestRequest = z.object({
  /** Full Outline Manager URL. Tested in-place; never persisted unless the admin then saves. */
  apiUrl: z.string().url(),
});

const TestResponse = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(true), keyCount: z.number().int().nonnegative() }),
  z.object({ ok: z.literal(false), error: z.string() }),
]);

const testRouteCfg = createRoute({
  method: 'post',
  path: '/test-connection',
  tags: ['Admin: Outline'],
  summary: 'Probe an Outline Manager URL without persisting it',
  description:
    'Runs `GET /access-keys` against the supplied URL and reports the result. Lets ' +
    'admins catch TLS / auth / DNS errors before saving a new server row.',
  security: [{ apiToken: ['admin:outline:write'] }],
  request: { body: { content: { 'application/json': { schema: TestRequest } }, required: true } },
  responses: {
    200: { description: 'Probed', content: { 'application/json': { schema: TestResponse } } },
  },
});

router.use('/test-connection', requireScope('admin:outline:write'));

router.openapi(testRouteCfg, async (c) => {
  const { apiUrl } = c.req.valid('json');
  const services = c.var.services;
  const client = new OutlineClient({ apiUrl, logger: services.platform.logger, timeoutMs: 5000 });
  const result = await client.healthCheck();
  return c.json(result, 200);
});

export default router;
