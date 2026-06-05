import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { eq } from 'drizzle-orm';
import { apiTokens } from '../../../db/schema';
import type { AppEnv } from '../../../env';
import { requireScope } from '../../../middleware/require-scope';
import { NotFoundError, ValidationError } from '../../../lib/errors';
import {
  CreateTokenRequest,
  CreateTokenResponse,
  ListTokensResponse,
  TokenSummary,
} from '../../../../shared/contracts/tokens';
import type { ApiScope } from '../../../../shared/contracts/scopes';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

function rowToSummary(row: typeof apiTokens.$inferSelect): unknown {
  return {
    id: row.id,
    name: row.name,
    tokenPrefix: row.tokenPrefix,
    scopes: JSON.parse(row.scopes) as ApiScope[],
    subjectType: row.subjectType,
    subjectUserId: row.subjectUserId,
    expiresAt: row.expiresAt ? new Date(row.expiresAt).toISOString() : null,
    lastUsedAt: row.lastUsedAt ? new Date(row.lastUsedAt).toISOString() : null,
    revokedAt: row.revokedAt ? new Date(row.revokedAt).toISOString() : null,
    createdAt: new Date(row.createdAt).toISOString(),
  };
}

const listRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Tokens'],
  summary: 'List API tokens',
  security: [{ apiToken: ['admin:tokens:read'] }],
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: ListTokensResponse } } },
  },
});

// IMPORTANT: every middleware that gates this router must be registered
// here, BEFORE any `router.openapi(...)` handler. Hono applies middleware
// in registration order to routes registered AFTER it — a `router.use(...)`
// at the bottom of the file does NOT protect handlers declared earlier.
// Read scope blankets every request; write scope is method-gated below.
router.use('/', requireScope('admin:tokens:read'));
router.use('/', async (c, next) => {
  if (c.req.method === 'POST') return requireScope('admin:tokens:write')(c, next);
  return next();
});
router.use('/:id', async (c, next) => {
  if (c.req.method === 'DELETE') return requireScope('admin:tokens:write')(c, next);
  return next();
});

router.openapi(listRoute, async (c) => {
  const services = c.var.services;
  const rows = await services.apiTokens.list();
  return c.json(
    ListTokensResponse.parse({
      tokens: rows.map(rowToSummary).map((t) => TokenSummary.parse(t)),
    }),
    200,
  );
});

const createRouteCfg = createRoute({
  method: 'post',
  path: '/',
  tags: ['Admin: Tokens'],
  summary: 'Create a new API token',
  description:
    'Returns the plaintext token **once** in the response. Store it immediately; it is never retrievable again.',
  security: [{ apiToken: ['admin:tokens:write'] }],
  request: {
    body: { content: { 'application/json': { schema: CreateTokenRequest } }, required: true },
  },
  responses: {
    201: {
      description: 'Created',
      content: { 'application/json': { schema: CreateTokenResponse } },
    },
    400: {
      description: 'Validation error',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(createRouteCfg, async (c) => {
  const data = c.req.valid('json');
  const services = c.var.services;
  const admin = c.var.admin;
  const apiAuth = c.var.apiAuth;

  // Either an admin cookie session OR a service token with admin:tokens:write
  // can mint new tokens. The requireScope middleware on the route already
  // enforces "must be admin or have admin:tokens:write"; here we just pick the
  // appropriate `created_by_admin_id` value.
  //
  // For service tokens (no admin cookie session), we attribute the new token
  // to the admin who created the calling service token. This preserves the
  // audit trail back to a real human admin.
  let createdByAdminId: number;
  let actorId: string;
  if (admin) {
    createdByAdminId = admin.adminUserId;
    actorId = String(admin.adminUserId);
  } else if (apiAuth) {
    // Look up the service token's creator
    const platform = c.var.platform;
    const tokenRows = await platform.db
      .select()
      .from(apiTokens)
      .where(eq(apiTokens.id, apiAuth.tokenId))
      .limit(1)
      .all();
    const callingToken = tokenRows[0];
    if (!callingToken) {
      throw new ValidationError('Calling token not found');
    }
    createdByAdminId = callingToken.createdByAdminId;
    actorId = `token:${apiAuth.tokenId}`;
  } else {
    throw new ValidationError('Authentication required to mint tokens');
  }

  const created = await services.apiTokens.create({
    name: data.name,
    scopes: data.scopes,
    subjectType: data.subjectType,
    subjectUserId: data.subjectUserId ?? null,
    expiresInDays: data.expiresInDays ?? null,
    createdByAdminId,
  });
  await services.audit.record({
    actorType: admin ? 'admin' : 'system',
    actorId,
    action: 'token.create',
    targetType: 'api_token',
    targetId: String(created.id),
    payload: { name: data.name, scopes: data.scopes },
    requestId: c.var.requestId,
  });
  const platform = c.var.platform;
  const inserted = await platform.db
    .select()
    .from(apiTokens)
    .where(eq(apiTokens.id, created.id))
    .limit(1)
    .all();
  if (!inserted[0]) throw new Error('Failed to read back inserted token');
  return c.json(
    CreateTokenResponse.parse({
      token: TokenSummary.parse(rowToSummary(inserted[0])),
      plaintext: created.plaintext,
    }),
    201,
  );
});

const revokeRoute = createRoute({
  method: 'delete',
  path: '/{id}',
  tags: ['Admin: Tokens'],
  summary: 'Revoke a token',
  security: [{ apiToken: ['admin:tokens:write'] }],
  request: { params: z.object({ id: z.string().regex(/^\d+$/) }) },
  responses: {
    200: {
      description: 'Revoked',
      content: { 'application/json': { schema: z.object({ ok: z.boolean() }) } },
    },
    404: {
      description: 'Not found',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

// (Write-side gates are registered at the top of this file, alongside the
// read-side gate, so they actually run before the POST/DELETE handlers
// below them in declaration order.)

router.openapi(revokeRoute, async (c) => {
  const id = parseInt(c.req.valid('param').id, 10);
  const platform = c.var.platform;
  const services = c.var.services;
  const existing = await platform.db
    .select()
    .from(apiTokens)
    .where(eq(apiTokens.id, id))
    .limit(1)
    .all();
  if (!existing[0]) throw new NotFoundError('api_token');
  await services.apiTokens.revoke(id);
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'token.revoke',
    targetType: 'api_token',
    targetId: String(id),
    requestId: c.var.requestId,
  });
  return c.json({ ok: true }, 200);
});

export default router;
