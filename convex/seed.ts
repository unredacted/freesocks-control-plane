/**
 * Seed helpers for local dev / cutover (P11) and tests. All idempotent and safe to
 * re-run. `seedCutover` is the one-shot a fresh prod deploy runs (P11): default
 * tiers + app settings + the primary Remnawave instance (from REMNAWAVE_* env, if
 * set). Additional backend instances (more Remnawave, any Outline) are added via
 * the admin CMS, since their connection config is operator-specific + secret.
 */
import { internalAction, internalMutation } from './_generated/server';
import { v } from 'convex/values';
import { internal } from './_generated/api';
import { SETTINGS_DEFAULTS } from './appSettings';
import { DEFAULT_CLIENTS } from './lib/clientCatalog';
import {
  CONNECTION_MODES,
  CONNECTION_MODE_FAMILIES,
  CONNECTION_MODE_FAMILY_KEYS,
  CONNECTION_MODE_KEYS,
  LEGACY_MODE_ID_MAP,
} from './lib/connectionModes';

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
        easeOfUse: c.easeOfUse ?? undefined,
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
 * OPERATOR-RUN catalog refresh: upsert every DEFAULT_CLIENTS row by name,
 * OVERWRITING the default-managed fields (homepageUrl, easeOfUse, openSource,
 * license, sourceUrl, schemeId, hwid, platforms, backends, priority) on rows
 * that already exist - unlike seedClients, which is insert-if-missing only.
 * Use after a defaults change (e.g. the install-page URL repoints) to push it
 * to a deployed instance: `bunx convex run seed:refreshDefaultClients '{}'`.
 * Admin-added clients (names not in the defaults), each row's `enabled`
 * flag, and any admin-set `description` are left untouched (`description` is
 * deliberately NOT in the field list: the defaults don't carry one - their
 * copy lives in the SPA's i18n catalog so it translates - so a refresh must
 * not clear an admin override). NOT part of the deploy entrypoint - it would
 * clobber deliberate admin edits to default rows on every deploy.
 */
export const refreshDefaultClients = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ inserted: number; updated: number }> => {
    let inserted = 0;
    let updated = 0;
    for (const c of DEFAULT_CLIENTS) {
      const existing = await ctx.db
        .query('clients')
        .withIndex('by_name', (q) => q.eq('name', c.name))
        .unique();
      const fields = {
        platforms: c.platforms,
        backends: c.backends,
        homepageUrl: c.homepageUrl,
        schemeId: c.schemeId ?? undefined,
        hwid: c.hwid,
        openSource: c.openSource ?? false,
        license: c.license ?? undefined,
        sourceUrl: c.sourceUrl ?? undefined,
        easeOfUse: c.easeOfUse ?? undefined,
        priority: c.priority,
        updatedAt: Date.now(),
      };
      if (existing) {
        await ctx.db.patch(existing._id, fields);
        updated++;
      } else {
        await ctx.db.insert('clients', { name: c.name, enabled: c.enabled, ...fields });
        inserted++;
      }
    }
    return { inserted, updated };
  },
});

/**
 * ONE-TIME, operator-run: rename the connection-mode ids to the family/transport
 * scheme (`evade` -> `freedom-ws`, `privacy` -> `privacy-reality`) and seed the
 * new admin `enabled` toggles.
 *
 *   bunx convex run seed:migrateConnectionModeIds '{}'
 *
 * Returns `nextCursor`; while it is non-null, re-run with
 * `'{"cursor": <nextCursor>}'` until it comes back null (the user scan is paged).
 *
 * Safe and IDEMPOTENT: every step is a no-op once it has run, so a re-run (or a
 * partial run that hit a limit) can simply be repeated. Nothing here touches the
 * schema — `users.connectionModeId` is an opaque `v.optional(v.string())` — so
 * this needs no second deploy, unlike the earlier squad-drop migration.
 *
 * Ordering note: the code deployed BEFORE this runs already accepts both
 * spellings (the deprecated aliases in CONNECTION_MODES, plus the legacy-key
 * fallback in resolveModeSquadPool), so there is no window where a member's key
 * or an admin's bound pool stops resolving.
 *
 * Once this has run everywhere and the audit log shows no traffic on the old
 * ids, drop the deprecated catalog entries and this mutation (Phase 4).
 */
export const migrateConnectionModeIds = internalMutation({
  args: { limit: v.optional(v.number()), cursor: v.optional(v.number()) },
  handler: async (ctx, { limit, cursor }) => {
    const now = Date.now();
    const pageSize = Math.min(Math.max(limit ?? 500, 1), 2000);
    let usersUpdated = 0;
    let settingsRenamed = 0;
    let defaultUpdated = 0;
    let enabledSeeded = 0;

    // 1. users.connectionModeId. There is no index on connectionModeId (it is a
    //    plain optional string), so this is a bounded _creationTime-cursored scan
    //    rather than a full collect() — a whole-table collect would trip Convex's
    //    per-mutation read limit once the user table is large. Re-run with the
    //    returned `nextCursor` until it comes back null.
    const page = await ctx.db
      .query('users')
      .withIndex('by_creation_time', (q) => (cursor != null ? q.gt('_creationTime', cursor) : q))
      .take(pageSize);
    for (const user of page) {
      const current = user.connectionModeId ? LEGACY_MODE_ID_MAP[user.connectionModeId] : undefined;
      if (!current) continue;
      await ctx.db.patch(user._id, { connectionModeId: current, updatedAt: now });
      usersUpdated++;
    }
    const nextCursor =
      page.length === pageSize ? (page[page.length - 1]?._creationTime ?? null) : null;

    // The settings/flags below are fixed-size and idempotent, so running them on
    // every page is harmless and means a single-page deployment needs one call.

    // 2. appSettings key renames: the generic mode copy AND the Remnawave squad
    //    pools. Copy-then-delete; if the destination already exists (a re-run, or
    //    an admin who edited the new key first) the source is dropped and the
    //    newer value wins.
    const renameKey = async (from: string, to: string) => {
      const src = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', from))
        .unique();
      if (!src) return;
      const dst = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', to))
        .unique();
      if (dst) {
        await ctx.db.delete(src._id);
      } else {
        await ctx.db.insert('appSettings', {
          key: to,
          value: src.value,
          updatedByAdminId: src.updatedByAdminId,
          updatedAt: now,
        });
        await ctx.db.delete(src._id);
      }
      settingsRenamed++;
    };

    for (const [legacy, current] of Object.entries(LEGACY_MODE_ID_MAP)) {
      await renameKey(CONNECTION_MODE_KEYS.label(legacy), CONNECTION_MODE_KEYS.label(current));
      await renameKey(
        CONNECTION_MODE_KEYS.description(legacy),
        CONNECTION_MODE_KEYS.description(current),
      );
      await renameKey(
        `remnawave.modePlacement.${legacy}.squads`,
        `remnawave.modePlacement.${current}.squads`,
      );
    }

    // 3. The stored default, if it still names a legacy id.
    const defaultRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', CONNECTION_MODE_KEYS.defaultId))
      .unique();
    if (defaultRow) {
      try {
        const parsed: unknown = JSON.parse(defaultRow.value);
        if (typeof parsed === 'string' && LEGACY_MODE_ID_MAP[parsed]) {
          await ctx.db.patch(defaultRow._id, {
            value: JSON.stringify(LEGACY_MODE_ID_MAP[parsed]),
            updatedAt: now,
          });
          defaultUpdated = 1;
        }
      } catch {
        /* malformed → resolution already falls back to the compiled default */
      }
    }

    // 4. Seed the enable toggles EXPLICITLY rather than leaning on the compiled
    //    `defaultEnabled`, so the admin panel shows real state on day one and a
    //    later change to a compiled default can't silently flip a live mode.
    const seedFlag = async (key: string, value: boolean) => {
      const existing = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (existing) return; // never overwrite an operator's choice
      await ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: now });
      enabledSeeded++;
    };
    for (const f of CONNECTION_MODE_FAMILIES) {
      await seedFlag(CONNECTION_MODE_FAMILY_KEYS.enabled(f.id), f.defaultEnabled);
    }
    for (const m of CONNECTION_MODES) {
      if (m.deprecated) continue;
      await seedFlag(CONNECTION_MODE_KEYS.enabled(m.id), m.defaultEnabled);
    }

    return { usersUpdated, settingsRenamed, defaultUpdated, enabledSeeded, nextCursor };
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
