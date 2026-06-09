/**
 * Seed helpers for local dev / cutover (P11) and tests. All idempotent and safe to
 * re-run. `seedCutover` is the one-shot a fresh prod deploy runs (P11): default
 * tiers + app settings + the primary Remnawave instance (from REMNAWAVE_* env, if
 * set). Additional backend instances (more Remnawave, any Outline) are added via
 * the admin CMS, since their connection config is operator-specific + secret.
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { SETTINGS_DEFAULTS } from './appSettings';

/** Insert the default-free tier if absent; return its id. */
export const seedDefaultFreeTier = internalMutation({
  args: {},
  handler: async (ctx) => {
    const existing = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', 'free'))
      .unique();
    if (existing) return existing._id;
    return ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      description: 'Anonymous, Turnstile-gated access for users in censored regions',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
  },
});

/** Insert a 'member' (paid) tier if absent; return its id. */
export const seedMemberTier = internalMutation({
  args: {},
  handler: async (ctx) => {
    const existing = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', 'member'))
      .unique();
    if (existing) return existing._id;
    return ctx.db.insert('tiers', {
      slug: 'member',
      name: 'Member',
      description: 'Standard FreeSocks supporters',
      backend: 'remnawave',
      monthlyTrafficGb: 500,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
  },
});

/** Insert each default app setting (JSON-encoded) if absent. Never overwrites admin edits. */
export const seedAppSettings = internalMutation({
  args: {},
  handler: async (ctx) => {
    let inserted = 0;
    for (const [key, value] of Object.entries(SETTINGS_DEFAULTS)) {
      const existing = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (existing) continue;
      await ctx.db.insert('appSettings', {
        key,
        value: JSON.stringify(value),
        updatedAt: Date.now(),
      });
      inserted++;
    }
    return { inserted };
  },
});

/**
 * Seed the primary Remnawave instance from REMNAWAVE_* env, if set and absent.
 * This is the one-time bridge from the old single-env-instance model to the
 * DB-managed backend instances: after the first seed, edit it (and add more) in
 * the admin CMS, and the REMNAWAVE_* env vars can be removed. No-op if the env
 * is unset (a fresh install adds instances entirely via the CMS).
 */
export const seedBackendServersFromEnv = internalMutation({
  args: {},
  handler: async (ctx) => {
    const baseUrl = process.env.REMNAWAVE_BASE_URL;
    const apiToken = process.env.REMNAWAVE_API_TOKEN;
    if (!baseUrl || !apiToken) return { inserted: 0 };
    const slug = 'remnawave-primary';
    const existing = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (existing) return { inserted: 0 };
    await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'Remnawave (primary)',
      slug,
      config: { type: 'remnawave', baseUrl, apiToken },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    return { inserted: 1 };
  },
});

/**
 * One-shot cutover seed (P11) for a FRESH backend: default-free + member tiers +
 * app settings + the primary Remnawave instance (from env). Re-runnable. Run
 * admin-passkey bootstrap + fsv1_ issuance separately (they need a browser /
 * per-operator data); add more backend instances via the admin CMS.
 */
export const seedCutover = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    freeTierId: string;
    memberTierId: string;
    settingsInserted: number;
    backendInstancesInserted: number;
  }> => {
    const freeTierId = await ctx.runMutation(internal.seed.seedDefaultFreeTier, {});
    const memberTierId = await ctx.runMutation(internal.seed.seedMemberTier, {});
    const settings = await ctx.runMutation(internal.seed.seedAppSettings, {});
    const instances = await ctx.runMutation(internal.seed.seedBackendServersFromEnv, {});
    return {
      freeTierId,
      memberTierId,
      settingsInserted: settings.inserted,
      backendInstancesInserted: instances.inserted,
    };
  },
});
