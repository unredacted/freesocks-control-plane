import { OpenAPIHono } from '@hono/zod-openapi';
import type { AppEnv } from './env';
import type { PlatformAdapter } from './platform/interface';
import { errorHandler, notFoundHandler } from './middleware/error-handler';
import { requestIdMw } from './middleware/request-id';
import { loggerMw } from './middleware/logger';
import { servicesMw } from './middleware/services';
import { sessionOAuthMw, sessionPasskeyMw } from './middleware/sessions';
import { bearerAuthMw } from './middleware/bearer-auth';
import healthz from './routes/api/healthz';
import subscription from './routes/api/subscription';
import auth from './routes/api/auth';
import account from './routes/api/account';
import { adminAuthRouter, adminApiRouter } from './routes/api/admin';
import me from './routes/api/me';
import config from './routes/api/config';
import internalCron from './routes/api/internal/cron';
import { docMeta, securitySchemes } from './openapi/registry';

export function createApp(platform: PlatformAdapter): OpenAPIHono<AppEnv> {
  const app = new OpenAPIHono<AppEnv>();

  app.use('*', requestIdMw);
  app.use('*', servicesMw(platform));
  app.use('*', loggerMw);
  app.use('*', sessionOAuthMw);
  app.use('*', sessionPasskeyMw);
  app.use('*', bearerAuthMw);

  // Unversioned: operational + browser plumbing (no consumer-facing API contract)
  app.route('/api/healthz', healthz);
  app.route('/api/auth', auth); // OAuth login/callback/logout/me
  app.route('/api/admin/auth', adminAuthRouter); // passkey register/authenticate
  app.route('/api/internal/cron', internalCron); // shared-secret-gated cron dispatcher

  // Versioned: data API surface for SPA + mobile + service tokens
  app.route('/api/v1/config', config); // public runtime config (member URLs, env, etc.)
  app.route('/api/v1/me', me); // unified identity endpoint, works with cookie or bearer
  app.route('/api/v1/subscription', subscription);
  app.route('/api/v1/account', account);
  app.route('/api/v1/admin', adminApiRouter);

  // Register security schemes
  app.openAPIRegistry.registerComponent('securitySchemes', 'apiToken', securitySchemes.apiToken);
  app.openAPIRegistry.registerComponent(
    'securitySchemes',
    'authentikJwt',
    securitySchemes.authentikJwt,
  );

  // Spec
  app.doc31('/api/openapi.json', () => ({
    ...docMeta,
    servers: [{ url: '/', description: 'Same origin' }],
  }));

  /*
   * `/api/docs` previously served a Scalar API-reference UI, but that UI
   * loads its JS bundle from `cdn.jsdelivr.net/npm/@scalar/api-reference`
   * which is a third-party CDN — violates our "no external resources"
   * policy. The raw OpenAPI spec at `/api/openapi.json` is the source of
   * truth; point any local viewer (Scalar standalone, Insomnia, Swagger
   * Editor, Stoplight Elements run from your machine) at that URL to get
   * an interactive view. `/api/docs` now redirects there as a hint.
   */
  app.get('/api/docs', (c) => c.redirect('/api/openapi.json', 302));

  app.onError(errorHandler);
  app.notFound(notFoundHandler);

  return app;
}
