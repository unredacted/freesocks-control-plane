import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import type { AppEnv } from '../../env';
import { PublicConfig } from '../../../shared/contracts/auth';
import { z } from 'zod';

const router = new OpenAPIHono<AppEnv>();

/**
 * Returns the small set of public config values the SPA needs at runtime so
 * we don't have to bake them into the build (and so we can rotate them via
 * env vars without rebuilding). No secrets — only values that are safe to
 * expose to any caller.
 */
const configRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Public'],
  summary: 'Public runtime config consumed by the SPA',
  responses: {
    200: {
      description: 'Public config',
      content: { 'application/json': { schema: PublicConfig } },
    },
  },
});

router.openapi(configRoute, async (c) => {
  const cfg = c.var.platform.config;
  // AppSettings is KV-cached (5 min) so this is a hot read — fine to do on
  // every /config hit. The SPA caches the response client-side too.
  const settings = await c.var.services.appSettings.getAll();

  // Active tiers are also KV-cached (`tiers:all`, 5 min). Expose only the
  // public-safe limit fields so the comparison/landing UI renders the real
  // enforced numbers. Dedupe by slug (dual-backend mode can register two rows
  // per logical tier) and order by priority so cards render free → patron.
  const tierRows = await c.var.services.tierPolicy.byActiveOnly();
  const seenSlugs = new Set<string>();
  const publicTiers = [...tierRows]
    .sort((a, b) => a.priority - b.priority)
    .filter((t) => (seenSlugs.has(t.slug) ? false : (seenSlugs.add(t.slug), true)))
    .map((t) => ({
      slug: t.slug,
      name: t.name,
      monthlyTrafficGb: t.monthlyTrafficGb,
      deviceLimit: t.deviceLimit,
    }));

  // Defensive: a blank/invalid MEMBERS_*_URL override must NOT 500 this public
  // endpoint. The SPA treats both URLs as optional (membersAccountUrl is
  // optional-chained; membersJoinUrl is currently unused), so omitting an
  // invalid value degrades a CTA rather than breaking the page. Validate with
  // the same rule the contract enforces, so whatever we emit is sure to parse.
  const validUrl = (v: string | undefined, field: string): string | undefined => {
    if (v && z.string().url().safeParse(v).success) return v;
    if (v) c.var.logger.warn('public_config_invalid_url', { field });
    return undefined;
  };

  return c.json(
    PublicConfig.parse({
      membersJoinUrl: validUrl(cfg.MEMBERS_JOIN_URL, 'MEMBERS_JOIN_URL'),
      membersAccountUrl: validUrl(cfg.MEMBERS_ACCOUNT_URL, 'MEMBERS_ACCOUNT_URL'),
      freeTierTurnstileSiteKey: cfg.FREE_TIER_TURNSTILE_SITE_KEY,
      environment: cfg.ENVIRONMENT,
      tiers: publicTiers,
      backends: {
        remnawaveEnabled: settings['remnawave.enabled'],
        outlineEnabled: settings['outline.enabled'],
        defaultBackend: settings['subscription.default_backend'],
        userChoiceEnabled: settings['subscription.user_choice_enabled'],
        labels: settings['subscription.backend_labels'],
      },
    }),
    200,
  );
});

export default router;
