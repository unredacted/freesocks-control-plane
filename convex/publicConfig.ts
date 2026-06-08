/**
 * Public bootstrap config (P7): the anonymous SPA reads this to render the
 * Turnstile widget, the tier-comparison table, and the backend chooser. Ported
 * from the old PublicConfig contract. Public + safe: the Turnstile SITE key is
 * public, tier limits are public, and only the backend enabled/label subset of
 * settings is exposed (never squad/backend secrets). A plain query so it can be
 * served reactively or via the GET /api/v1/config HTTP route.
 */
import { query } from './_generated/server';

export const get = query({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('appSettings').collect();
    const settings: Record<string, unknown> = {
      'outline.enabled': false,
      'remnawave.enabled': true,
      'subscription.default_backend': 'remnawave',
      'subscription.user_choice_enabled': false,
      'subscription.backend_labels': { remnawave: 'Xray', outline: 'Outline' },
    };
    for (const row of rows) {
      if (!(row.key in settings)) continue;
      try {
        settings[row.key] = JSON.parse(row.value);
      } catch {
        /* keep default */
      }
    }

    const active = await ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    const seen = new Set<string>();
    const tiers = active
      .slice()
      .sort((a, b) => a.priority - b.priority)
      .filter((t) => (seen.has(t.slug) ? false : (seen.add(t.slug), true)))
      .map((t) => ({
        slug: t.slug,
        name: t.name,
        monthlyTrafficGb: t.monthlyTrafficGb,
        deviceLimit: t.deviceLimit,
      }));

    const labels = settings['subscription.backend_labels'] as {
      remnawave: string;
      outline: string;
    };
    const environment = (process.env.ENVIRONMENT ?? 'production') as
      | 'production'
      | 'development'
      | 'test';

    return {
      membersJoinUrl: process.env.MEMBERS_JOIN_URL || undefined,
      membersAccountUrl: process.env.MEMBERS_ACCOUNT_URL || undefined,
      freeTierTurnstileSiteKey: process.env.TURNSTILE_SITE_KEY ?? '',
      environment,
      tiers,
      backends: {
        remnawaveEnabled: settings['remnawave.enabled'] as boolean,
        outlineEnabled: settings['outline.enabled'] as boolean,
        defaultBackend: settings['subscription.default_backend'] as 'remnawave' | 'outline',
        userChoiceEnabled: settings['subscription.user_choice_enabled'] as boolean,
        labels,
      },
    };
  },
});
