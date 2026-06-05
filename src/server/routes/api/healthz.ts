import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import type { AppEnv } from '../../env';
import { ApiErrorResponse, HealthzResponse } from '../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

const healthzRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Operational'],
  summary: 'Service health check',
  description: 'Lightweight liveness probe. Useful for monitoring tools.',
  responses: {
    200: {
      description: 'Service is up',
      content: { 'application/json': { schema: HealthzResponse } },
    },
    500: {
      description: 'Service error',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(healthzRoute, (c) => {
  return c.json(
    {
      ok: true,
      environment: c.var.platform.config.ENVIRONMENT,
      timestamp: new Date().toISOString(),
      requestId: c.var.requestId,
    },
    200,
  );
});

export default router;
