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
import type { Doc } from './_generated/dataModel';
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
// Phase-5 cutover migrations: connection profiles → connection modes, and the
// Remnawave squad handle → the generic `backendPlacement`. Each is idempotent +
// paginated (safe on tables of any size, safe to re-run every deploy). Together
// they clear EVERY deprecated field/row so the follow-up deploy can drop them
// from the schema — Convex validates a pushed schema against existing rows, so a
// field must be empty on all rows before it can leave the validator. The beta
// deployer runs the `migrateConnectionModes` action (below) on every `up`.
// The legacy key/field names are HARDCODED here on purpose: a migration targets
// the exact shape that existed in prod, so it stays correct even if a live
// constant is later renamed.
// ---------------------------------------------------------------------------

const MIGRATE_PAGE = 200;

function safeJsonParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/**
 * Copy each subscription's legacy `remnawaveSquadUuid` into the generic
 * `backendPlacement` (set-once — never clobber a placement already there) and
 * clear the old field. Keyset-paged by `_creationTime` (rows are patched, not
 * deleted, so they keep their slot and the cursor always advances).
 */
export const migrateSubscriptionPlacementBatch = internalMutation({
  args: { afterCreation: v.optional(v.number()) },
  handler: async (ctx, { afterCreation }) => {
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_creation_time', (q) =>
        afterCreation != null ? q.gt('_creationTime', afterCreation) : q,
      )
      .order('asc')
      .take(MIGRATE_PAGE);
    let migrated = 0;
    for (const r of rows) {
      const legacy = r.remnawaveSquadUuid;
      if (legacy === undefined) continue; // never set / already cleared
      if (r.backendPlacement == null && typeof legacy === 'string' && legacy.trim()) {
        await ctx.db.patch(r._id, { backendPlacement: legacy, remnawaveSquadUuid: undefined });
      } else {
        await ctx.db.patch(r._id, { remnawaveSquadUuid: undefined });
      }
      migrated++;
    }
    const last = rows[rows.length - 1];
    return {
      done: rows.length < MIGRATE_PAGE,
      nextCursor: last ? last._creationTime : (afterCreation ?? null),
      migrated,
      scanned: rows.length,
    };
  },
});

/**
 * Copy each user's legacy `connectionProfileId` into `connectionModeId`
 * (set-once) and clear the old field. Same keyset paging as above.
 */
export const migrateUserConnectionModeBatch = internalMutation({
  args: { afterCreation: v.optional(v.number()) },
  handler: async (ctx, { afterCreation }) => {
    const rows = await ctx.db
      .query('users')
      .withIndex('by_creation_time', (q) =>
        afterCreation != null ? q.gt('_creationTime', afterCreation) : q,
      )
      .order('asc')
      .take(MIGRATE_PAGE);
    let migrated = 0;
    for (const r of rows) {
      const legacy = r.connectionProfileId;
      if (legacy === undefined) continue;
      if (r.connectionModeId == null) {
        await ctx.db.patch(r._id, { connectionModeId: legacy, connectionProfileId: undefined });
      } else {
        await ctx.db.patch(r._id, { connectionProfileId: undefined });
      }
      migrated++;
    }
    const last = rows[rows.length - 1];
    return {
      done: rows.length < MIGRATE_PAGE,
      nextCursor: last ? last._creationTime : (afterCreation ?? null),
      migrated,
      scanned: rows.length,
    };
  },
});

/**
 * Rename the legacy `connectionProfile.*` appSettings namespace:
 *   connectionProfile.default            → connectionMode.default
 *   connectionProfile.<id>.label         → connectionMode.<id>.label
 *   connectionProfile.<id>.description   → connectionMode.<id>.description
 *   connectionProfile.<id>.squadUuids[]  ┐ merged (deduped) into the Remnawave
 *   connectionProfile.<id>.squadUuid     ┘ pool remnawave.modePlacement.<id>.squads
 * The `connectionProfile.*` range is a handful of rows — one pass. Copies to the
 * new key only if absent (never clobbers a value the new admin surface set), then
 * deletes the old row. Idempotent (a second run finds no `connectionProfile.*`).
 */
export const migrateModeAppSettings = internalMutation({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db
      .query('appSettings')
      // ['connectionProfile.', 'connectionProfile/') — '/' is the byte after '.'.
      .withIndex('by_key', (q) =>
        q.gte('key', 'connectionProfile.').lt('key', 'connectionProfile/'),
      )
      .collect();

    const moveKey = async (src: Doc<'appSettings'>, to: string) => {
      const exists = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', to))
        .unique();
      if (!exists) {
        await ctx.db.insert('appSettings', { key: to, value: src.value, updatedAt: Date.now() });
      }
      await ctx.db.delete(src._id);
    };

    const poolById = new Map<string, string[]>();
    let renamed = 0;
    let deleted = 0;
    for (const r of rows) {
      if (r.key === 'connectionProfile.default') {
        await moveKey(r, 'connectionMode.default');
        renamed++;
        continue;
      }
      const rest = r.key.slice('connectionProfile.'.length); // <id>.<field>
      const dot = rest.indexOf('.');
      if (dot < 0) continue; // malformed — leave it
      const id = rest.slice(0, dot);
      const field = rest.slice(dot + 1);
      if (field === 'label' || field === 'description') {
        await moveKey(r, `connectionMode.${id}.${field}`);
        renamed++;
      } else if (field === 'squadUuids' || field === 'squadUuid') {
        const parsed = safeJsonParse(r.value);
        const list =
          field === 'squadUuids'
            ? Array.isArray(parsed)
              ? parsed
              : []
            : typeof parsed === 'string'
              ? [parsed]
              : [];
        const acc = poolById.get(id) ?? [];
        for (const s of list) if (typeof s === 'string' && s.trim()) acc.push(s.trim());
        poolById.set(id, acc);
        await ctx.db.delete(r._id);
        deleted++;
      }
    }

    let poolsWritten = 0;
    for (const [id, list] of poolById) {
      const deduped = [...new Set(list)];
      if (deduped.length === 0) continue;
      const key = `remnawave.modePlacement.${id}.squads`;
      const existing = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (existing) {
        // Merge with any pool already bound via /admin/remnawave/mode-placements.
        const prev = safeJsonParse(existing.value);
        const merged = [
          ...new Set([
            ...(Array.isArray(prev) ? prev.filter((s): s is string => typeof s === 'string') : []),
            ...deduped,
          ]),
        ];
        await ctx.db.patch(existing._id, { value: JSON.stringify(merged), updatedAt: Date.now() });
      } else {
        await ctx.db.insert('appSettings', {
          key,
          value: JSON.stringify(deduped),
          updatedAt: Date.now(),
        });
      }
      poolsWritten++;
    }
    return { renamed, poolsWritten, deleted };
  },
});

/** Delete a page of the deprecated `remnawaveSquadStats` table (superseded by
 *  `remnawaveNodeStats`). Delete-and-repeat until empty. */
export const clearRemnawaveSquadStatsBatch = internalMutation({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('remnawaveSquadStats').take(MIGRATE_PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length, done: rows.length < MIGRATE_PAGE };
  },
});

/**
 * Drives the Phase-5 cutover: drain each paged migration to completion, then the
 * one-pass settings rename. Idempotent — a second run migrates nothing. Once this
 * has run in prod, the follow-up deploy drops the now-empty deprecated fields
 * (`subscriptions.remnawaveSquadUuid`, `users.connectionProfileId`,
 * `tiers.remnawaveSquadUuid`) + the `remnawaveSquadStats` table from the schema.
 */
export const migrateConnectionModes = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    subscriptionsMigrated: number;
    usersMigrated: number;
    settings: { renamed: number; poolsWritten: number; deleted: number };
    squadStatsRemoved: number;
  }> => {
    const GUARD = 100_000; // backstop against a non-advancing cursor

    // `res` is annotated to break the self-referential type inference: this action
    // is exported from the same module whose `internal.seed.*` types it consumes.
    type PageResult = { done: boolean; nextCursor: number | null; migrated: number };

    let subscriptionsMigrated = 0;
    let subCursor: number | null = null;
    for (let i = 0; i < GUARD; i++) {
      const res: PageResult = await ctx.runMutation(
        internal.seed.migrateSubscriptionPlacementBatch,
        { ...(subCursor != null ? { afterCreation: subCursor } : {}) },
      );
      subscriptionsMigrated += res.migrated;
      subCursor = res.nextCursor;
      if (res.done) break;
    }

    let usersMigrated = 0;
    let userCursor: number | null = null;
    for (let i = 0; i < GUARD; i++) {
      const res: PageResult = await ctx.runMutation(internal.seed.migrateUserConnectionModeBatch, {
        ...(userCursor != null ? { afterCreation: userCursor } : {}),
      });
      usersMigrated += res.migrated;
      userCursor = res.nextCursor;
      if (res.done) break;
    }

    const settings = await ctx.runMutation(internal.seed.migrateModeAppSettings, {});

    let squadStatsRemoved = 0;
    for (let i = 0; i < GUARD; i++) {
      const res: { removed: number; done: boolean } = await ctx.runMutation(
        internal.seed.clearRemnawaveSquadStatsBatch,
        {},
      );
      squadStatsRemoved += res.removed;
      if (res.done) break;
    }

    return { subscriptionsMigrated, usersMigrated, settings, squadStatsRemoved };
  },
});
