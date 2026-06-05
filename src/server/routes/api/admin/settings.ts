/**
 * Admin app-settings CRUD. The settings live in the `app_settings` table and
 * are typed via `AppSettingsService` (see `services/app-settings.ts`). Each
 * key has its own Zod schema; the PATCH route validates each key's value
 * against that schema before persisting.
 */
import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import type { AppEnv } from '../../../env';
import { requireScope } from '../../../middleware/require-scope';
import { AppSettingsRecord } from '../../../../shared/contracts/admin';
import { AppSettingsService, type SettingKey } from '../../../services/app-settings';
import { z, ApiErrorResponse } from '../../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

const SettingsResponse = z.object({ settings: AppSettingsRecord }).openapi('SettingsResponse');

const getSettingsRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Admin: Settings'],
  summary: 'Get all admin-editable runtime settings',
  security: [{ apiToken: ['admin:settings:read'] }],
  responses: {
    200: { description: 'OK', content: { 'application/json': { schema: SettingsResponse } } },
  },
});

router.use('/', requireScope('admin:settings:read'));
router.openapi(getSettingsRoute, async (c) => {
  const services = c.var.services;
  const settings = await services.appSettings.getAll();
  return c.json({ settings }, 200);
});

const patchSettingsRoute = createRoute({
  method: 'patch',
  path: '/',
  tags: ['Admin: Settings'],
  summary: 'Update one or more admin-editable settings',
  description:
    'Body is a partial map of key → value. Each value is validated against the ' +
    'key-specific Zod schema; an invalid value rejects the entire patch.',
  security: [{ apiToken: ['admin:settings:write'] }],
  request: {
    body: { content: { 'application/json': { schema: AppSettingsRecord } }, required: true },
  },
  responses: {
    200: { description: 'Updated', content: { 'application/json': { schema: SettingsResponse } } },
    400: {
      description: 'Invalid setting value',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.use('/', async (c, next) => {
  if (c.req.method === 'PATCH') return requireScope('admin:settings:write')(c, next);
  return next();
});

router.openapi(patchSettingsRoute, async (c) => {
  const data = c.req.valid('json');
  const services = c.var.services;
  const adminId = c.var.admin?.adminUserId ?? null;

  // Validate each provided key's value against its schema. This is done in
  // a single pass so an invalid value on one key rejects the whole patch
  // (no partial application — admins get clear all-or-nothing semantics).
  const validated: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (!(AppSettingsService.knownKeys() as readonly string[]).includes(key)) {
      return c.json(
        {
          error: {
            code: 'settings.unknown_key',
            message: `Unknown setting key: ${key}`,
          },
        },
        400,
      );
    }
    try {
      const schema = AppSettingsService.schemaFor(key as SettingKey);
      validated[key] = schema.parse(value);
    } catch (err) {
      return c.json(
        {
          error: {
            code: 'settings.invalid_value',
            message: `Invalid value for ${key}: ${err instanceof Error ? err.message : String(err)}`,
          },
        },
        400,
      );
    }
  }

  await services.appSettings.setMany(validated as never, adminId);
  await services.audit.record({
    actorType: 'admin',
    actorId: String(c.var.admin?.adminUserId ?? c.var.apiAuth?.tokenId),
    action: 'settings.update',
    payload: { keys: Object.keys(validated) },
    requestId: c.var.requestId,
  });

  const settings = await services.appSettings.getAll();
  return c.json({ settings }, 200);
});

export default router;
