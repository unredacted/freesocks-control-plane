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
  CONNECTION_MODE_DEFAULT_KEY,
  DEFAULT_CONNECTION_MODES,
  DEFAULT_CONNECTION_MODE_FAMILIES,
  resolveModeCatalog,
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
        ipv6: c.ipv6 ?? undefined,
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
        ipv6: c.ipv6 ?? undefined,
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
 * Seed the DB-driven connection-mode catalog (families + leaf modes).
 * Idempotent; runs at every deploy via seedCutover. Catalog rows are inserted
 * ONLY while both tables are empty (the clients-seed rule inverted:
 * table-level, not per-row, so a built-in row an admin deliberately DELETED is
 * never resurrected by a later deploy).
 *
 * The 2026-07-28 migration release (deploy 1) additionally absorbed the
 * pre-refactor appSettings state (copy/enabled overrides, placement pools,
 * legacy mode ids) on that first run — a deployment coming from the old
 * catalog MUST pass through that release before this one; jumping straight
 * here starts from the compiled defaults.
 */
export const seedConnectionModes = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ familiesInserted: number; modesInserted: number }> => {
    const now = Date.now();
    let familiesInserted = 0;
    let modesInserted = 0;
    const [famAny, modeAny] = await Promise.all([
      ctx.db.query('connectionModeFamilies').first(),
      ctx.db.query('connectionModes').first(),
    ]);
    if (!famAny && !modeAny) {
      for (const f of DEFAULT_CONNECTION_MODE_FAMILIES) {
        await ctx.db.insert('connectionModeFamilies', {
          slug: f.slug,
          iconId: f.iconId,
          enabled: f.enabled,
          order: f.order,
          updatedAt: now,
        });
        familiesInserted++;
      }
      for (const m of DEFAULT_CONNECTION_MODES) {
        await ctx.db.insert('connectionModes', {
          slug: m.slug,
          familySlug: m.familySlug,
          deliveryStyle: m.deliveryStyle,
          enabled: m.enabled,
          isFamilyDefault: m.isFamilyDefault,
          isCensorshipRecommended: m.isCensorshipRecommended,
          backends: [...m.backends],
          order: m.order,
          updatedAt: now,
        });
        modesInserted++;
      }
    }
    return { familiesInserted, modesInserted };
  },
});

// The pre-rename mode ids (dropped from the wire 2026-07-28) and their
// successors. Only the cleanup mutation below still knows them.
const LEGACY_MODE_ID_SUCCESSORS: Readonly<Record<string, string>> = {
  evade: 'freedom-ws',
  privacy: 'privacy-reality',
};

/**
 * ONE-SHOT operator cleanup (deploy 2 of the DB-driven mode catalog): delete
 * the appSettings rows the 2026-07-28 migration absorbed into tables and left
 * dead for rollback safety:
 *   - `connectionMode.<id>.*` copy/enabled overrides — the DEFAULT POINTER
 *     `connectionMode.default` is KEPT (still the live default-mode store),
 *   - `connectionModeFamily.*` family overrides,
 *   - `remnawave.modePlacement.*` squad pools (now `modePlacements` rows).
 * It also re-keys any censorship-matrix cells still stored under a pre-rename
 * mode id (belt and braces for a deployment that ran an EARLY build of the
 * migration release, before its seed learned the matrix rewrite).
 *
 * GUARDED, twice — both refusals mean the deploy-1 migration never ran here
 * (this deployment jumped straight to post-shim code); deploy the 2026-07-28
 * release first:
 *   1. refuses while any user still holds a pre-rename mode id;
 *   2. refuses while a non-empty appSettings squad pool has NO modePlacements
 *      row for its (successor) slug even though that mode is still in the
 *      catalog — deleting it would destroy the only copy of the pool.
 * Idempotent: a re-run deletes nothing and returns 0.
 *
 * Run through the stack's deployer container:
 *   bunx convex run seed:cleanupLegacyModeSettings '{}'
 */
export const cleanupLegacyModeSettings = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ deleted: number; matrixCellsRekeyed: number }> => {
    for (const legacyId of Object.keys(LEGACY_MODE_ID_SUCCESSORS)) {
      const holder = await ctx.db
        .query('users')
        .withIndex('by_connection_mode', (q) => q.eq('connectionModeId', legacyId))
        .first();
      if (holder) {
        throw new Error(
          `refusing to clean up: a user still holds the pre-rename mode id "${legacyId}". ` +
            'This deployment has not run the deploy-1 migration (the 2026-07-28 release ' +
            'whose seedCutover rewrites legacy user rows) — deploy that release first.',
        );
      }
    }

    const now = Date.now();
    // The RESOLVED catalog (compiled-defaults fallback included): on a
    // deployment whose tables are still empty, the defaults are what issuance
    // resolves against, so a pool for a default slug is still load-bearing.
    const catalogSlugs = new Set((await resolveModeCatalog(ctx.db)).modes.map((m) => m.id));

    // Guard 2: verify every still-relevant squad pool was actually absorbed
    // into `modePlacements` before deleting its appSettings copy. A pool for a
    // mode the admin has since DELETED from the catalog is dead either way and
    // does not block; an emptied/absent pool has nothing to lose.
    const POOL_PREFIX = 'remnawave.modePlacement.';
    const POOL_SUFFIX = '.squads';
    const poolRows = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) =>
        q.gte('key', POOL_PREFIX).lt('key', POOL_PREFIX.slice(0, -1) + '/'),
      )
      .collect();
    for (const row of poolRows) {
      if (!row.key.endsWith(POOL_SUFFIX)) continue;
      let pool: unknown;
      try {
        pool = JSON.parse(row.value);
      } catch {
        continue; // malformed → nothing to lose
      }
      if (!Array.isArray(pool) || !pool.some((s) => typeof s === 'string' && s.trim())) continue;
      const rawId = row.key.slice(POOL_PREFIX.length, -POOL_SUFFIX.length);
      const slug = LEGACY_MODE_ID_SUCCESSORS[rawId] ?? rawId;
      if (!catalogSlugs.has(slug)) continue;
      const transferred = await ctx.db
        .query('modePlacements')
        .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', 'remnawave'))
        .unique();
      if (!transferred) {
        throw new Error(
          `refusing to clean up: the appSettings squad pool for "${rawId}" was never absorbed ` +
            `into modePlacements (mode "${slug}" has no row) — deleting it would destroy the ` +
            'only copy. Deploy the 2026-07-28 migration release first, or bind the pool via ' +
            'Admin -> Remnawave / the placement route before cleaning up.',
        );
      }
    }

    // Re-key censorship-matrix cells still stored under a pre-rename id
    // (canonical-cell-wins; a legacy spelling that IS a live catalog slug is
    // never touched). The migration release's seed does this too — this covers
    // deployments that ran an early build of it.
    let matrixCellsRekeyed = 0;
    const matrixRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', 'status.censorship'))
      .unique();
    if (matrixRow) {
      try {
        const parsed: unknown = JSON.parse(matrixRow.value);
        const rows = (parsed as { rows?: unknown })?.rows;
        if (Array.isArray(rows)) {
          for (const r of rows) {
            const cells = (r as { cells?: Record<string, unknown> })?.cells;
            if (!cells || typeof cells !== 'object') continue;
            for (const [legacy, current] of Object.entries(LEGACY_MODE_ID_SUCCESSORS)) {
              if (!(legacy in cells) || catalogSlugs.has(legacy)) continue;
              if (!(current in cells)) cells[current] = cells[legacy];
              delete cells[legacy];
              matrixCellsRekeyed++;
            }
          }
          if (matrixCellsRekeyed > 0) {
            await ctx.db.patch(matrixRow._id, { value: JSON.stringify(parsed), updatedAt: now });
          }
        }
      } catch {
        /* malformed matrix → the status page already fail-safes to empty */
      }
    }

    const prefixes = ['connectionMode.', 'connectionModeFamily.', 'remnawave.modePlacement.'];
    let deleted = 0;
    for (const prefix of prefixes) {
      const rows = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.gte('key', prefix).lt('key', prefix.slice(0, -1) + '/'))
        .collect();
      for (const row of rows) {
        if (row.key === CONNECTION_MODE_DEFAULT_KEY) continue;
        await ctx.db.delete(row._id);
        deleted++;
      }
    }
    return { deleted, matrixCellsRekeyed };
  },
});

/**
 * Assign a shared `peerGroup` to tiers still linked by the DEPRECATED pairwise
 * `peerTierId` (either direction). Idempotent: a tier that already has a group
 * is never touched; the group name is derived from the sorted slug pair so a
 * re-run converges on the same value. Runs at every deploy via seedCutover.
 */
export const seedPeerGroups = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ grouped: number }> => {
    const tiers = await ctx.db.query('tiers').collect();
    const assigned = new Map<string, string>(); // tierId -> group (this run)
    for (const t of tiers) if (t.peerGroup) assigned.set(t._id as string, t.peerGroup);
    let grouped = 0;
    for (const t of tiers) {
      if (!t.peerTierId || assigned.has(t._id as string)) continue;
      const peer = tiers.find((x) => x._id === t.peerTierId);
      if (!peer) continue;
      const group =
        assigned.get(peer._id as string) ?? `peer-${[t.slug, peer.slug].sort().join('+')}`;
      await ctx.db.patch(t._id, { peerGroup: group, updatedAt: Date.now() });
      assigned.set(t._id as string, group);
      grouped++;
      if (!assigned.has(peer._id as string)) {
        await ctx.db.patch(peer._id, { peerGroup: group, updatedAt: Date.now() });
        assigned.set(peer._id as string, group);
        grouped++;
      }
    }
    return { grouped };
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
    modeFamiliesInserted: number;
    modesInserted: number;
  }> => {
    const freeTierId = await ctx.runMutation(internal.seed.seedDefaultFreeTier, {});
    const memberTierId = await ctx.runMutation(internal.seed.seedMemberTier, {});
    const settings = await ctx.runMutation(internal.seed.seedAppSettings, {});
    const instances = await ctx.runMutation(internal.seed.seedBackendServersFromEnv, {});
    const clients = await ctx.runMutation(internal.seed.seedClients, {});
    const modes = await ctx.runMutation(internal.seed.seedConnectionModes, {});
    await ctx.runMutation(internal.seed.seedPeerGroups, {});
    return {
      freeTierId,
      memberTierId,
      settingsInserted: settings.inserted,
      backendInstancesInserted: instances.inserted,
      clientsInserted: clients.inserted,
      modeFamiliesInserted: modes.familiesInserted,
      modesInserted: modes.modesInserted,
    };
  },
});
