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
import { DEFAULT_CLIENTS } from './lib/clientCatalog';

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
      description: 'Anonymous, captcha-gated access for users in censored regions',
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

/**
 * The single paid tier: the FreeSocks membership. Unlimited bandwidth
 * (`monthlyTrafficGb: 0` → null traffic limit at issuance) and unlimited
 * devices (`hwidEnabled: false` → null device limit). `deviceLimit: 0` is the
 * display sentinel the SPA renders as "Unlimited". Slug stays `'member'` so the
 * billing config + existing references keep resolving it.
 */
const MEMBERSHIP_TIER = {
  slug: 'member',
  name: 'FreeSocks Membership',
  description: 'Unlimited bandwidth and devices for FreeSocks supporters',
  backend: 'remnawave' as const,
  monthlyTrafficGb: 0,
  deviceLimit: 0,
  hwidLimit: 0,
  hwidEnabled: false,
  trafficStrategy: 'NO_RESET' as const,
  isDefaultFree: false,
  isActive: true,
  priority: 10,
  expirationDaysAfterMembershipLapse: 7,
};

/** Insert the paid membership tier if absent; return its id. */
export const seedMemberTier = internalMutation({
  args: {},
  handler: async (ctx) => {
    const existing = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', 'member'))
      .unique();
    if (existing) return existing._id;
    return ctx.db.insert('tiers', { ...MEMBERSHIP_TIER, updatedAt: Date.now() });
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
 *
 * STEADY-STATE OWNERSHIP: once an `ansible-role-freesocks` deploy registers the
 * panel (`fcp_register_remnawave_panel`), the role is the single ongoing writer
 * via the idempotent `PUT …/backend-servers/by-slug/{slug}` upsert. The two do
 * not fight: this seed only inserts when the `remnawave-primary` slug is ABSENT,
 * and the role's upsert is keep-secret-on-blank, so a converge that omits the
 * apiToken preserves whatever is stored. Pick ONE source of truth for the
 * credential (env-seed for env-managed deployments, the role's vault otherwise)
 * — set the role's `fcp_remnawave_panel_slug` to match this `remnawave-primary`
 * slug to converge the same row rather than create a second instance.
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
 * app settings + the primary Remnawave instance (from env) + the recommended-
 * client catalog (seedClients). Re-runnable. Run admin-passkey bootstrap + fsv1_
 * issuance separately (they need a browser / per-operator data); add more backend
 * instances via the admin CMS.
 */
/**
 * Seed the recommended-client catalog from the compiled DEFAULT_CLIENTS.
 * Idempotent by name (skips a client that already exists), so it's safe on a
 * fresh deploy (via seedCutover) OR run once on an already-deployed instance
 * (`bunx convex run seed:seedClients '{}'`). The clientCatalog resolver also
 * falls back to DEFAULT_CLIENTS when the table is empty, so the UI is never blank.
 */
export const seedClients = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ inserted: number }> => {
    let inserted = 0;
    for (const c of DEFAULT_CLIENTS) {
      const existing = await ctx.db
        .query('clients')
        .withIndex('by_name', (q) => q.eq('name', c.name))
        .unique();
      if (existing) continue;
      await ctx.db.insert('clients', {
        name: c.name,
        platforms: c.platforms,
        backends: c.backends,
        homepageUrl: c.homepageUrl,
        schemeId: c.schemeId ?? undefined,
        hwid: c.hwid,
        openSource: c.openSource ?? false,
        license: c.license ?? undefined,
        sourceUrl: c.sourceUrl ?? undefined,
        enabled: c.enabled,
        priority: c.priority,
        updatedAt: Date.now(),
      });
      inserted++;
    }
    return { inserted };
  },
});

export const seedCutover = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    freeTierId: string;
    memberTierId: string;
    settingsInserted: number;
    backendInstancesInserted: number;
    clientsInserted: number;
  }> => {
    const freeTierId = await ctx.runMutation(internal.seed.seedDefaultFreeTier, {});
    const memberTierId = await ctx.runMutation(internal.seed.seedMemberTier, {});
    const settings = await ctx.runMutation(internal.seed.seedAppSettings, {});
    const instances = await ctx.runMutation(internal.seed.seedBackendServersFromEnv, {});
    const clients = await ctx.runMutation(internal.seed.seedClients, {});
    return {
      freeTierId,
      memberTierId,
      settingsInserted: settings.inserted,
      backendInstancesInserted: instances.inserted,
      clientsInserted: clients.inserted,
    };
  },
});
