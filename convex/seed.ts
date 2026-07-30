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
  LEGACY_MODE_ID_MAP,
  canonicalModeId,
} from './lib/connectionModes';
import { sanitizePool } from './lib/remnawavePlacement';

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
 * Seed the DB-driven connection-mode catalog (families + leaf modes) and fold
 * the pre-refactor state in. Idempotent; runs at every deploy via seedCutover.
 *
 * Catalog rows are inserted ONLY while both tables are empty (the clients-seed
 * rule inverted: table-level, not per-row, so a built-in row an admin
 * deliberately DELETED is never resurrected by a later deploy). On that first
 * run the old appSettings state is absorbed into the rows:
 *   - `connectionMode.<id>.label/description/enabled` + the family namespace
 *     (legacy-keyed copies fold onto their successors; a current-key value
 *     wins over a legacy-key one),
 *   - `connectionMode.default` is canonicalized in place (the pointer key
 *     itself stays live — it is still the default-mode store),
 *   - `remnawave.modePlacement.<id>.squads` pools become `modePlacements`
 *     rows (canonical slug; an existing row wins — insert-if-missing).
 * The absorbed appSettings rows are LEFT IN PLACE (dead) for deploy-1
 * rollback safety; a deploy-2 cleanup mutation deletes them.
 */
export const seedConnectionModes = internalMutation({
  args: {},
  handler: async (
    ctx,
  ): Promise<{ familiesInserted: number; modesInserted: number; poolsMoved: number }> => {
    const now = Date.now();
    const readSetting = async (key: string): Promise<unknown> => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (!row) return undefined;
      try {
        return JSON.parse(row.value);
      } catch {
        return undefined;
      }
    };
    // Absorb a copy override for `slug`, preferring the current key, falling
    // back to the legacy spelling's key.
    const legacyOf: Record<string, string> = {};
    for (const [legacy, current] of Object.entries(LEGACY_MODE_ID_MAP)) legacyOf[current] = legacy;
    const absorbString = async (prefix: string, slug: string, field: string) => {
      const current = await readSetting(`${prefix}.${slug}.${field}`);
      if (typeof current === 'string' && current.trim()) return current;
      const legacy = legacyOf[slug];
      if (legacy) {
        const viaLegacy = await readSetting(`${prefix}.${legacy}.${field}`);
        if (typeof viaLegacy === 'string' && viaLegacy.trim()) return viaLegacy;
      }
      return undefined;
    };
    const absorbBool = async (prefix: string, slug: string, fallback: boolean) => {
      const current = await readSetting(`${prefix}.${slug}.enabled`);
      if (typeof current === 'boolean') return current;
      const legacy = legacyOf[slug];
      if (legacy) {
        const viaLegacy = await readSetting(`${prefix}.${legacy}.enabled`);
        if (typeof viaLegacy === 'boolean') return viaLegacy;
      }
      return fallback;
    };

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
          label: await absorbString('connectionModeFamily', f.slug, 'label'),
          description: await absorbString('connectionModeFamily', f.slug, 'description'),
          iconId: f.iconId,
          enabled: await absorbBool('connectionModeFamily', f.slug, f.enabled),
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
          label: await absorbString('connectionMode', m.slug, 'label'),
          description: await absorbString('connectionMode', m.slug, 'description'),
          enabled: await absorbBool('connectionMode', m.slug, m.enabled),
          isFamilyDefault: m.isFamilyDefault,
          isCensorshipRecommended: m.isCensorshipRecommended,
          backends: [...m.backends],
          order: m.order,
          updatedAt: now,
        });
        modesInserted++;
      }
    }

    // Canonicalize the default pointer in place (idempotent).
    const defaultRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', CONNECTION_MODE_DEFAULT_KEY))
      .unique();
    if (defaultRow) {
      try {
        const parsed: unknown = JSON.parse(defaultRow.value);
        if (typeof parsed === 'string' && LEGACY_MODE_ID_MAP[parsed]) {
          await ctx.db.patch(defaultRow._id, {
            value: JSON.stringify(LEGACY_MODE_ID_MAP[parsed]),
            updatedAt: now,
          });
        }
      } catch {
        /* malformed → resolution already falls back to the compiled default */
      }
    }

    // Move the Remnawave placement pools into modePlacements rows. Canonical
    // slugs; fold canonical keys FIRST so a legacy key never shadows one, and an
    // existing table row always wins (a re-run, or an admin/Ansible that already
    // wrote the new store). Source rows stay in place (deploy-2 deletes them).
    let poolsMoved = 0;
    const POOL_PREFIX = 'remnawave.modePlacement.';
    const POOL_SUFFIX = '.squads';
    const poolRows = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) =>
        q.gte('key', POOL_PREFIX).lt('key', POOL_PREFIX.slice(0, -1) + '/'),
      )
      .collect();
    const parsedPools = poolRows
      .filter((r) => r.key.endsWith(POOL_SUFFIX))
      .map((r) => {
        const rawId = r.key.slice(POOL_PREFIX.length, -POOL_SUFFIX.length);
        let pool: string[] = [];
        try {
          pool = sanitizePool(JSON.parse(r.value));
        } catch {
          /* malformed → skip */
        }
        return {
          slug: canonicalModeId(rawId),
          canonicalKey: canonicalModeId(rawId) === rawId,
          pool,
        };
      })
      .filter((e) => e.pool.length > 0)
      .sort((a, b) => Number(b.canonicalKey) - Number(a.canonicalKey));
    for (const entry of parsedPools) {
      const existing = await ctx.db
        .query('modePlacements')
        .withIndex('by_mode_backend', (q) =>
          q.eq('modeSlug', entry.slug).eq('backend', 'remnawave'),
        )
        .unique();
      if (existing) continue;
      await ctx.db.insert('modePlacements', {
        modeSlug: entry.slug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: entry.pool }),
        updatedAt: now,
      });
      poolsMoved++;
    }

    // Re-key the stored censorship matrix: cells written before the catalog
    // rename are keyed by the PRE-RENAME mode ids, and the matrix validity
    // filter (statusPage.sanitizeCensorshipRows) only knows live catalog
    // slugs — without this rewrite every legacy cell silently drops from
    // public/admin reads and the next editor save persists the loss.
    // Canonical-key-wins on collision; a legacy spelling that IS a live
    // catalog slug (an admin re-created it) is never touched. Idempotent, and
    // deliberately OUTSIDE the both-tables-empty guard so a deployment that
    // took an earlier build of this release is repaired on its next deploy.
    const matrixRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', 'status.censorship'))
      .unique();
    if (matrixRow) {
      try {
        const parsed: unknown = JSON.parse(matrixRow.value);
        const rows = (parsed as { rows?: unknown })?.rows;
        if (Array.isArray(rows)) {
          const liveSlugs = new Set(
            (await ctx.db.query('connectionModes').collect()).map((r) => r.slug),
          );
          let changed = false;
          for (const r of rows) {
            const cells = (r as { cells?: Record<string, unknown> })?.cells;
            if (!cells || typeof cells !== 'object') continue;
            for (const [legacy, current] of Object.entries(LEGACY_MODE_ID_MAP)) {
              if (!(legacy in cells) || liveSlugs.has(legacy)) continue;
              if (!(current in cells)) cells[current] = cells[legacy];
              delete cells[legacy];
              changed = true;
            }
          }
          if (changed) {
            await ctx.db.patch(matrixRow._id, { value: JSON.stringify(parsed), updatedAt: now });
          }
        }
      } catch {
        /* malformed matrix → the status page already fail-safes to empty */
      }
    }

    return { familiesInserted, modesInserted, poolsMoved };
  },
});

/**
 * Rewrite users still holding a PRE-RENAME connection-mode id (evade/privacy)
 * onto the successor slug. Paged (no index on connectionModeId — a bounded
 * _creationTime scan); seedCutover loops it to completion at every deploy, so
 * the migration needs no operator step and a converged deploy pays one cheap
 * page scan. Deleted (with the LEGACY_MODE_ID_MAP shim) in deploy 2.
 */
export const migrateLegacyModeUserIds = internalMutation({
  args: { limit: v.optional(v.number()), cursor: v.optional(v.number()) },
  handler: async (
    ctx,
    { limit, cursor },
  ): Promise<{ usersUpdated: number; nextCursor: number | null }> => {
    const now = Date.now();
    const pageSize = Math.min(Math.max(limit ?? 500, 1), 2000);
    let usersUpdated = 0;
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
    return { usersUpdated, nextCursor };
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
    modePoolsMoved: number;
    modeUsersUpdated: number;
  }> => {
    const freeTierId = await ctx.runMutation(internal.seed.seedDefaultFreeTier, {});
    const memberTierId = await ctx.runMutation(internal.seed.seedMemberTier, {});
    const settings = await ctx.runMutation(internal.seed.seedAppSettings, {});
    const instances = await ctx.runMutation(internal.seed.seedBackendServersFromEnv, {});
    const clients = await ctx.runMutation(internal.seed.seedClients, {});
    const modes = await ctx.runMutation(internal.seed.seedConnectionModes, {});
    await ctx.runMutation(internal.seed.seedPeerGroups, {});
    // Loop the paged legacy-id rewrite to completion (an action may chain
    // mutations): the migration runs itself at deploy, no operator step. A
    // converged deploy pays one page scan that finds nothing.
    let modeUsersUpdated = 0;
    let cursor: number | null = null;
    do {
      const page: { usersUpdated: number; nextCursor: number | null } = await ctx.runMutation(
        internal.seed.migrateLegacyModeUserIds,
        cursor != null ? { cursor } : {},
      );
      modeUsersUpdated += page.usersUpdated;
      cursor = page.nextCursor;
    } while (cursor != null);
    return {
      freeTierId,
      memberTierId,
      settingsInserted: settings.inserted,
      backendInstancesInserted: instances.inserted,
      clientsInserted: clients.inserted,
      modeFamiliesInserted: modes.familiesInserted,
      modesInserted: modes.modesInserted,
      modePoolsMoved: modes.poolsMoved,
      modeUsersUpdated,
    };
  },
});
