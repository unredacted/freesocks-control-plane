import { z } from '@hono/zod-openapi';

/**
 * Re-export the OpenAPI-aware Zod from `@hono/zod-openapi` so call-sites can
 * attach `.openapi(name)` metadata to schemas defined elsewhere.
 *
 * Schemas in src/shared/contracts use plain `zod`. Importing `@hono/zod-openapi`
 * extends the Zod prototype with `.openapi()`, so the same schemas pick up the
 * metadata when chained at the route-definition level.
 */
export { z };

/**
 * Common error response body used across the API. Matches what error-handler.ts
 * actually emits.
 */
export const ApiErrorResponse = z
  .object({
    error: z.object({
      code: z.string(),
      message: z.string(),
      details: z.unknown().optional(),
    }),
    requestId: z.string().optional(),
  })
  .openapi('ApiError');

export const HealthzResponse = z
  .object({
    ok: z.boolean(),
    environment: z.string(),
    timestamp: z.string().datetime(),
    requestId: z.string(),
  })
  .openapi('HealthzResponse');

export const securitySchemes = {
  apiToken: {
    type: 'http' as const,
    scheme: 'bearer' as const,
    bearerFormat: 'fsv1_<random>',
    description:
      'Admin-issued API token. Format: `fsv1_<43 base64url chars>`. Generate via the admin CMS at /admin/tokens.',
  },
  authentikJwt: {
    type: 'oauth2' as const,
    flows: {
      authorizationCode: {
        authorizationUrl: '<your Authentik authorize endpoint>',
        tokenUrl: '<your Authentik token endpoint>',
        scopes: {
          openid: 'OpenID identity',
          email: 'Email address',
          profile: 'Profile info',
        },
      },
    },
    description: 'Authentik-issued JWT access token. Used by the mobile app via OAuth2 + PKCE.',
  },
};

export const docMeta = {
  openapi: '3.1.0',
  info: {
    version: '1.0.0',
    title: 'FreeSocks Control Plane API',
    description:
      'Issue subscription URLs, manage members, and operate the FreeSocks tier system. ' +
      'Two consumer auth methods: admin-issued bearer tokens (`fsv1_*`) for service ' +
      'integrations and Authentik OIDC JWTs for end-user mobile clients.',
    license: { name: 'See repository' },
  },
} as const;
