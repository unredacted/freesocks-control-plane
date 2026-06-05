import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { eq } from 'drizzle-orm';
import { users } from '../../db/schema';
import type { AppEnv } from '../../env';
import { AuthMeResponse } from '../../../shared/contracts/auth';
import { ApiErrorResponse } from '../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

const meRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Identity'],
  summary: 'Get the current member identity',
  description:
    'Returns the authenticated member, or `{ authenticated: false }` for callers without a member identity. ' +
    'Works with member cookie sessions, Authentik JWT bearer tokens, or admin/service tokens that impersonate a user.',
  security: [{ authentikJwt: [] }, { apiToken: [] }],
  responses: {
    200: {
      description: 'Identity payload',
      content: { 'application/json': { schema: AuthMeResponse } },
    },
    500: {
      description: 'Error',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(meRoute, async (c) => {
  const member = c.var.member;
  if (!member) {
    return c.json(AuthMeResponse.parse({ authenticated: false }), 200);
  }
  const services = c.var.services;
  const platform = c.var.platform;
  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  const tier = user ? await services.tierPolicy.getById(user.tierId) : null;
  if (!user || !tier) {
    return c.json(AuthMeResponse.parse({ authenticated: false }), 200);
  }
  return c.json(
    AuthMeResponse.parse({
      authenticated: true,
      member: {
        contactId: member.contactId,
        email: member.email,
        displayName: member.displayName,
        tier: { slug: tier.slug as 'free' | 'member' | 'patron' | 'custom', name: tier.name },
      },
    }),
    200,
  );
});

export default router;
