/**
 * Seed helpers for local dev / cutover (P11) and tests. All idempotent and safe to
 * re-run. `seedCutover` is the one-shot a fresh prod deploy runs (P11): default
 * tiers + app settings + the primary Remnawave instance (from REMNAWAVE_* env, if
 * set). Additional backend instances (more Remnawave, any Outline) are added via
 * the admin CMS, since their connection config is operator-specific + secret.
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { SETTINGS_DEFAULTS } from './appSettings';
import { DEFAULT_CLIENTS } from './lib/clientCatalog';
import { freeWindowDays } from './lifecycle';
import { applyCountsDelta } from './lib/statusCounters';

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

/**
 * Bring the EXISTING `'member'` row up to the unlimited membership config (the
 * paid tier the billing flow grants). `seedMemberTier` skips-if-exists, so a beta
 * install that already has the old 500 GB / 3-device `'Member'` row needs this
 * migration. **Guarded + safe to re-run on every deploy:** once the row is
 * already unlimited (`monthlyTrafficGb === 0 && !hwidEnabled`) it's a no-op, so
 * it won't clobber later admin edits (name, squad, priority) — it only performs
 * the one-time bump from a limited row. Existing paid members pick up the new
 * limits on their next tier change / re-issue.
 */
export const reconfigureMembershipTier = internalMutation({
  args: {},
  handler: async (ctx) => {
    const existing = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', 'member'))
      .unique();
    if (!existing) {
      return { reconfigured: false as const, id: null };
    }
    // Already unlimited → leave it (and any admin customizations) alone.
    if (existing.monthlyTrafficGb === 0 && existing.hwidEnabled === false) {
      return { reconfigured: false as const, id: existing._id };
    }
    await ctx.db.patch(existing._id, { ...MEMBERSHIP_TIER, updatedAt: Date.now() });
    return { reconfigured: true as const, id: existing._id };
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

/**
 * One-time migration for the device-limit master toggle
 * (`devices.enforcementEnabled`, default OFF = unlimited-by-default). Preserves
 * prior behavior for an EXISTING deployment that was relying on per-tier device
 * limits: if the key has never been set AND the deployment already has users AND
 * some active tier opts into HWID, seed it ON. A FRESH install (no users yet)
 * is left OFF — the new unlimited-by-default posture. Idempotent (a no-op once
 * the key exists), so it's safe on every deploy.
 */
export const migrateDeviceEnforcementDefault = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ seeded: boolean }> => {
    const existing = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', 'devices.enforcementEnabled'))
      .unique();
    if (existing) return { seeded: false }; // already configured — never override
    const anyUser = await ctx.db.query('users').first();
    if (!anyUser) return { seeded: false }; // fresh install → keep the OFF default
    const tiers = await ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    if (!tiers.some((t) => t.hwidEnabled)) return { seeded: false };
    await ctx.db.insert('appSettings', {
      key: 'devices.enforcementEnabled',
      value: JSON.stringify(true),
      updatedAt: Date.now(),
    });
    return { seeded: true };
  },
});

/**
 * One-time backfill of the client-catalog open-source metadata
 * (openSource / license / sourceUrl) onto rows that predate those fields, and
 * insertion of any DEFAULT_CLIENTS entry that's missing (the new OSS additions).
 * Idempotent: an existing row is patched ONLY while it still lacks `openSource`
 * (so it never clobbers a later admin edit); missing rows are inserted once.
 * Safe on every deploy (run from deploy-entrypoint after seedCutover).
 */
export const migrateClientCatalogMeta = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ patched: number; inserted: number }> => {
    let patched = 0;
    let inserted = 0;
    for (const c of DEFAULT_CLIENTS) {
      const existing = await ctx.db
        .query('clients')
        .withIndex('by_name', (q) => q.eq('name', c.name))
        .unique();
      if (existing) {
        if (existing.openSource === undefined) {
          await ctx.db.patch(existing._id, {
            openSource: c.openSource ?? false,
            license: c.license ?? undefined,
            sourceUrl: c.sourceUrl ?? undefined,
            updatedAt: Date.now(),
          });
          patched++;
        }
        continue; // already backfilled — leave admin edits alone
      }
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
    return { patched, inserted };
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

// ---------------------------------------------------------------------------
// WS2 idle-free-lifecycle migrations. Idempotent + paginated; run post-deploy via
// `bunx convex run seed:<name>`. `backfillFreeKeyExpiresAt` seeds the idle marker
// on existing free users (without it the deactivate-idle-free sweep just ignores
// legacy users). `reclassifyDeletedFreeToInactive` is OPERATOR-CHOICE: it flips
// existing `status:'deleted'` free rows → `inactive` so previously-cleaned accounts
// can log back in (their key/S3 are already gone; a return re-issues).
// ---------------------------------------------------------------------------

const MIGRATE_PAGE = 200;

/** One page: seed `freeKeyExpiresAt` on default-free users that lack it, anchored
 *  to the user's active-sub creation (else the user's own creation) + the window,
 *  so a recently-issued key gets a FUTURE expiry (not swept) and a genuinely-old
 *  idle account gets a PAST one (swept on the first run). */
export const backfillFreeKeyExpiresAtBatch = internalMutation({
  args: { cursor: v.union(v.string(), v.null()), numItems: v.number() },
  handler: async (ctx, { cursor, numItems }) => {
    const days = await freeWindowDays(ctx.db);
    const freeTierIds = new Set(
      (await ctx.db.query('tiers').collect())
        .filter((t) => t.isDefaultFree)
        .map((t) => String(t._id)),
    );
    const res = await ctx.db.query('users').paginate({ cursor, numItems });
    let updated = 0;
    for (const u of res.page) {
      if (u.freeKeyExpiresAt != null) continue;
      if (!freeTierIds.has(String(u.tierId))) continue;
      const sub = await ctx.db
        .query('subscriptions')
        .withIndex('by_user_state', (q) => q.eq('userId', u._id).eq('state', 'active'))
        .order('desc')
        .first();
      const anchor = sub?._creationTime ?? u._creationTime;
      await ctx.db.patch(u._id, {
        freeKeyExpiresAt: anchor + days * 86_400_000,
        updatedAt: Date.now(),
      });
      updated++;
    }
    return { updated, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

export const backfillFreeKeyExpiresAt = internalAction({
  args: {},
  handler: async (ctx): Promise<{ updated: number }> => {
    let updated = 0;
    let cursor: string | null = null;
    for (let i = 0; i < 100_000; i++) {
      const res: { updated: number; isDone: boolean; continueCursor: string } =
        await ctx.runMutation(internal.seed.backfillFreeKeyExpiresAtBatch, {
          cursor,
          numItems: MIGRATE_PAGE,
        });
      updated += res.updated;
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    return { updated };
  },
});

/** One page: flip `status:'deleted'` free rows → `inactive` with a PAST
 *  `freeKeyExpiresAt` (so they stay inactive + are immediately purge-eligible),
 *  letting previously-cleaned accounts return. All `deleted` rows are free-cleanup
 *  casualties, but we still tier-guard defensively. */
export const reclassifyDeletedFreeToInactiveBatch = internalMutation({
  args: { cursor: v.union(v.string(), v.null()), numItems: v.number() },
  handler: async (ctx, { cursor, numItems }) => {
    const days = await freeWindowDays(ctx.db);
    const freeTierIds = new Set(
      (await ctx.db.query('tiers').collect())
        .filter((t) => t.isDefaultFree)
        .map((t) => String(t._id)),
    );
    const res = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) => q.eq('status', 'deleted'))
      .paginate({ cursor, numItems });
    let updated = 0;
    for (const u of res.page) {
      if (!freeTierIds.has(String(u.tierId))) continue;
      await ctx.db.patch(u._id, {
        status: 'inactive',
        freeKeyExpiresAt: u._creationTime + days * 86_400_000, // old → in the past
        updatedAt: Date.now(),
      });
      await applyCountsDelta(ctx, { statusFrom: 'deleted', statusTo: 'inactive' });
      updated++;
    }
    return { updated, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

export const reclassifyDeletedFreeToInactive = internalAction({
  args: {},
  handler: async (ctx): Promise<{ updated: number }> => {
    let updated = 0;
    let cursor: string | null = null;
    for (let i = 0; i < 100_000; i++) {
      const res: { updated: number; isDone: boolean; continueCursor: string } =
        await ctx.runMutation(internal.seed.reclassifyDeletedFreeToInactiveBatch, {
          cursor,
          numItems: MIGRATE_PAGE,
        });
      updated += res.updated;
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    return { updated };
  },
});
