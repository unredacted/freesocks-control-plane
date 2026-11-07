/**
 * Registered functions over the DB-driven connection-mode catalog: the member/
 * admin reads, the admin CRUD (create/edit/delete families + modes), the
 * generic per-backend placement binding, and the generic placement dispatch
 * (resolveIssueTarget / effectiveGate) issuance routes through. All internal —
 * the public catalog ships via publicConfig.get, never a placement config.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { ConvexError, v } from 'convex/values';
import type { Doc, Id } from './_generated/dataModel';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { backendIdValidator, type BackendId } from './lib/backendIds';
import { CAPABILITIES } from './lib/backends/capabilities';
import {
  BUILT_IN_FAMILY_SLUGS,
  BUILT_IN_MODE_SLUGS,
  CONNECTION_MODE_DEFAULT_KEY,
  MODE_SLUG_RE,
  resolveDefaultModeId,
  resolveModeCatalog,
  type DeliveryStyle,
} from './lib/connectionModes';
import {
  effectiveDefaultFor,
  hasPlacementResolver,
  resolveCatalogWithAvailability,
  resolverFor,
} from './lib/placement';
import {
  FREEDOM_FAMILY,
  freedomDirectRefusal,
  freedomEdgesOnly,
} from './lib/edges/freedomDelivery';
import { poolFromConfig } from './lib/remnawavePlacement';

// --- reads --------------------------------------------------------------------

/**
 * The mode list for validation + admin/status surfaces: copy, flags, and
 * per-backend availability — NEVER a placement config. `bound` (legacy shape)
 * = bound on ≥1 placement-capable backend the mode declares.
 */
export const list = internalQuery({
  args: {},
  handler: async (ctx) => {
    const { modes, boundByBackend } = await resolveCatalogWithAvailability(ctx.db);
    return modes.map((m) => ({
      id: m.id,
      family: m.family,
      label: m.label,
      description: m.description,
      deliveryStyle: m.deliveryStyle,
      isDefault: m.isDefault,
      isFamilyDefault: m.isFamilyDefault,
      isCensorshipRecommended: m.isCensorshipRecommended,
      enabled: m.enabled,
      backends: m.backends,
      availableBackends: m.availableBackends,
      bound: m.backends.some((b) => boundByBackend.get(b)?.has(m.id) ?? false),
      fallbackModeSlug: m.fallbackModeSlug,
    }));
  },
});

/** The family catalog (admin editor + projections). */
export const families = internalQuery({
  args: {},
  handler: async (ctx) => (await resolveModeCatalog(ctx.db)).families,
});

/** The default a member who hasn't chosen is on (AccountView, the suggestion):
 *  the effective one ON THEIR BACKEND when given (what their key issues into),
 *  else the catalog-wide one; never a default no node serves while another
 *  mode is served. */
export const defaultId = internalQuery({
  args: { backend: v.optional(backendIdValidator) },
  handler: async (ctx, { backend }) => {
    const catalog = await resolveCatalogWithAvailability(ctx.db);
    const id = backend
      ? effectiveDefaultFor(catalog, backend)
      : (catalog.modes.find((m) => m.isDefault)?.id ?? null);
    return id ?? (await resolveDefaultModeId(ctx.db));
  },
});

/**
 * The fully-resolved projection of ONE member's current mode for the account
 * view — present even when the mode is admin-disabled or deleted from the
 * catalog, so the SPA can render the right delivery UI (deliveryStyle) and a
 * proper label instead of a raw slug. `available` is evaluated against the
 * member's own backend.
 */
export const memberMode = internalQuery({
  args: {
    modeId: v.union(v.string(), v.null()),
    backend: backendIdValidator,
  },
  handler: async (ctx, { modeId, backend }) => {
    const catalog = await resolveCatalogWithAvailability(ctx.db);
    const { families, modes } = catalog;
    const fallbackId = effectiveDefaultFor(catalog, backend);
    const effective =
      (modeId ? modes.find((m) => m.id === modeId) : undefined) ??
      modes.find((m) => m.id === fallbackId);
    if (!effective) {
      // Deleted-from-catalog id on an empty-ish catalog: ship a minimal echo so
      // the client still has a stable id + a sane delivery default.
      return modeId
        ? {
            id: modeId,
            deliveryStyle: 'url' as DeliveryStyle,
            label: null,
            description: null,
            family: null,
            available: false,
          }
        : null;
    }
    const family = families.find((f) => f.id === effective.family) ?? null;
    return {
      id: effective.id,
      deliveryStyle: effective.deliveryStyle,
      label: effective.label,
      description: effective.description,
      family: family ? { id: family.id, label: family.label } : null,
      available: effective.availableBackends.includes(backend),
    };
  },
});

/**
 * Validate a member's PRE-ISSUANCE mode choice (the plain preference set,
 * POST /api/v1/account/connection-mode) against the member's OWN backend —
 * the same per-(mode, backend) gate account.switchMode applies, so a choice
 * that switch-mode would refuse can't sneak in through the preference route
 * (a disabled-but-still-pooled mode, or a mode from another backend; both
 * would later wedge the member on the effective-mode regenerate gate).
 * One deliberate difference: the bring-up allowance — while NO mode is
 * available on the member's backend (nothing bound yet), an enabled +
 * applicable choice is still recorded so signup works on a fresh deploy
 * (issuance fail-softs + audits, WS1).
 */
export const validateMemberChoice = internalQuery({
  args: { userId: v.id('users'), modeId: v.string() },
  handler: async (
    ctx,
    { userId, modeId },
  ): Promise<
    { ok: true; modeId: string } | { ok: false; code: 'unknown_mode' | 'unavailable' }
  > => {
    const user = await ctx.db.get(userId);
    const tier = user ? await ctx.db.get(user.tierId) : null;
    if (!tier) return { ok: false, code: 'unknown_mode' };
    const { modes } = await resolveCatalogWithAvailability(ctx.db);
    const chosen = modes.find((m) => m.id === modeId);
    if (!chosen || !chosen.enabled || !chosen.backends.includes(tier.backend)) {
      return { ok: false, code: 'unknown_mode' };
    }
    if (!chosen.availableBackends.includes(tier.backend)) {
      const anyAvailableHere = modes.some((m) => m.availableBackends.includes(tier.backend));
      if (anyAvailableHere) return { ok: false, code: 'unavailable' };
    }
    return { ok: true, modeId: chosen.id };
  },
});

// --- generic placement dispatch -------------------------------------------------

/** The (placement, server) pair a NEW key on `backend` issues into — the
 *  generic dispatch over the placement-resolver registry. Backends with no
 *  placement concept resolve {null, null}. */
export const resolveIssueTarget = internalQuery({
  args: {
    backend: backendIdValidator,
    modeId: v.union(v.string(), v.null()),
    location: v.optional(v.union(v.string(), v.null())),
    // The exit locations of a member's own country choice on Automatic
    // (lib/countryExits.ts), tried in order when `location` is unset.
    exitLocations: v.optional(v.array(v.string())),
    onlyServerId: v.optional(v.union(v.id('backendServers'), v.null())),
    // "Anything but this one" — the member's switch-server action, so the pick
    // has to actually move the key off the placement it is on.
    excludePlacement: v.optional(v.union(v.string(), v.null())),
    // A [0,1) float minted by the calling ACTION (CSPRNG): the anti-herding
    // pick needs randomness, but a query must stay deterministic for OCC.
    rand: v.optional(v.number()),
  },
  handler: async (
    ctx,
    { backend, modeId, location, exitLocations, onlyServerId, excludePlacement, rand },
  ) => {
    const t = await resolverFor(backend).resolveTarget(ctx.db, modeId, {
      location: location ?? null,
      ...(exitLocations?.length ? { exitLocations } : {}),
      onlyServerId: (onlyServerId as string | null | undefined) ?? null,
      excludePlacement: excludePlacement ?? null,
      rand: typeof rand === 'number' ? () => rand : undefined,
    });
    const withBackup = { ...t, ...(await fallbackPlacementOf(ctx.db, backend, modeId, t)) };
    if (!withBackup.fallbackUnresolved || onlyServerId) return withBackup;
    // The pick landed on a backend that does not host the backup group: try,
    // in turn, the backends that do, so a valid target is never missed.
    const slug = await modeSlugFor(ctx.db, backend, modeId);
    const backup = slug ? (await modeRowOf(ctx.db, slug))?.fallbackModeSlug : null;
    if (!backup) return withBackup;
    for (const sid of await backendsHosting(ctx.db, backup)) {
      if (sid === t.serverId) continue;
      const alt = await resolverFor(backend).resolveTarget(ctx.db, modeId, {
        location: location ?? null,
        ...(exitLocations?.length ? { exitLocations } : {}),
        onlyServerId: sid,
        excludePlacement: excludePlacement ?? null,
        rand: typeof rand === 'number' ? () => rand : undefined,
      });
      if (!alt.placement) continue;
      const f = await fallbackPlacementOf(ctx.db, backend, modeId, alt);
      if (!f.fallbackUnresolved) return { ...alt, ...f };
    }
    return withBackup;
  },
});

/**
 * The group a key of `modeId` is ALSO placed in (its mode's
 * `fallbackModeSlug`), on the SAME backend as its own: a Hysteria key's
 * REALITY backup group. `fallbackUnresolved`: the mode names a backup that is
 * not bound there; the key must not issue without it (the caller refuses).
 */
async function fallbackPlacementOf(
  db: DatabaseReader,
  backend: BackendId,
  modeId: string | null,
  target: { placement: string | null; serverId: string | null },
): Promise<{ extraPlacements: string[]; fallbackUnresolved: boolean }> {
  if (!target.placement) return { extraPlacements: [], fallbackUnresolved: false };
  // No choice: the mode the key issues into is the effective default.
  const slug = await modeSlugFor(db, backend, modeId);
  const row = slug ? await modeRowOf(db, slug) : null;
  const fallback = row?.fallbackModeSlug;
  if (!fallback) return { extraPlacements: [], fallbackUnresolved: false };
  if (!target.serverId) return { extraPlacements: [], fallbackUnresolved: true };
  const f = await resolverFor(backend).resolveTarget(db, fallback, {
    location: null,
    onlyServerId: target.serverId,
    excludePlacement: null,
  });
  return f.placement && f.placement !== target.placement
    ? { extraPlacements: [f.placement], fallbackUnresolved: false }
    : { extraPlacements: [], fallbackUnresolved: true };
}

/** The mode a key issues into: the chosen one, else the effective default on `backend`. */
async function modeSlugFor(
  db: DatabaseReader,
  backend: BackendId,
  modeId: string | null,
): Promise<string | null> {
  return modeId ?? effectiveDefaultFor(await resolveCatalogWithAvailability(db), backend);
}

const modeRowOf = (db: DatabaseReader, slug: string) =>
  db
    .query('connectionModes')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();

/** The backends a mode's pool has a group on (attributed through the node stats). */
async function backendsHosting(db: DatabaseReader, slug: string): Promise<string[]> {
  const row = await db
    .query('modePlacements')
    .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', 'remnawave'))
    .unique();
  const out = new Set<string>();
  for (const placement of row ? poolFromConfig(row.config) : []) {
    const stats = await db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', placement))
      .unique();
    if (stats) out.add(stats.backendServerId as string);
  }
  return [...out];
}

/** The re-issue anti-downgrade gate for `backend` (see PlacementResolver). */
export const effectiveGate = internalQuery({
  args: { backend: backendIdValidator, modeId: v.union(v.string(), v.null()) },
  handler: (ctx, { backend, modeId }) => resolverFor(backend).effectiveGate(ctx.db, modeId),
});

// --- placement binding (admin:servers:write surface) ---------------------------

/**
 * Bind mode placements for ONE backend (the generic successor of the
 * Remnawave-only route, which now aliases here). Per mode the patch composes
 * backend-defined ops (Remnawave: squadUuids/addSquadUuids/removeSquadUuids);
 * unknown mode slugs are skipped, never a 400 (a stale admin tab or an Ansible
 * inventory naming a deleted mode must not break the whole converge). Config
 * contents are write-only: audited as poolBound + boundCount, returned only as
 * summaries.
 */
export const setModePlacements = internalMutation({
  args: {
    backend: backendIdValidator,
    patch: v.any(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { backend, patch, actorAdminId }) => {
    if (!hasPlacementResolver(backend)) {
      throw new ConvexError({
        code: 'validation',
        message: `backend "${backend}" has no placement configuration`,
      });
    }
    const resolver = resolverFor(backend);
    if (!patch || typeof patch !== 'object') {
      throw new ConvexError({
        code: 'validation',
        message: 'mode-placement patch must be an object',
      });
    }
    const entries = ((patch as Record<string, unknown>).modes ?? {}) as Record<string, unknown>;
    const { modes } = await resolveModeCatalog(ctx.db);
    const known = new Set(modes.map((m) => m.id));

    let applied = 0;
    for (const slug of Object.keys(entries)) {
      if (!known.has(slug)) continue; // unknown ids are ignored (never an error)
      const existing = await ctx.db
        .query('modePlacements')
        .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', backend))
        .unique();
      let nextConfig: string | null;
      try {
        nextConfig = resolver.applyConfigPatch(existing?.config ?? null, entries[slug]);
      } catch (e) {
        throw new ConvexError({
          code: 'validation',
          message: e instanceof Error ? e.message : 'invalid mode-placement config',
        });
      }
      if (nextConfig === null) continue; // no ops in this entry
      if (existing?.config === nextConfig) {
        // Already so (a setup run again places what it placed): nothing to write or log.
        applied++;
        continue;
      }
      if (existing) {
        await ctx.db.patch(existing._id, { config: nextConfig, updatedAt: Date.now() });
      } else {
        await ctx.db.insert('modePlacements', {
          modeSlug: slug,
          backend,
          config: nextConfig,
          updatedAt: Date.now(),
        });
      }
      applied++;
      const summary = resolver.summarize(nextConfig);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'admin.backend.mode_placement.update',
        targetType: 'connection_mode',
        targetId: slug,
        payload: {
          backend,
          modeSlug: slug,
          poolBound: summary.bound,
          boundCount: summary.count,
        },
      });
    }
    if (applied === 0) {
      throw new ConvexError({ code: 'validation', message: 'no recognized mode-placement fields' });
    }
    const counts = await resolver.boundCounts(ctx.db);
    return {
      bound: [...(await resolver.boundModeSlugs(ctx.db))],
      placements: Object.entries(counts).map(([modeId, boundCount]) => ({ modeId, boundCount })),
    };
  },
});

/** Per-(mode, backend) placement summaries for the admin surfaces — sizes
 *  only, never the config. */
export const placementSummaries = internalQuery({
  args: {},
  handler: async (ctx) => {
    const { modes } = await resolveModeCatalog(ctx.db);
    const out: Record<
      string,
      Array<{ backendId: BackendId; bound: boolean; boundCount: number }>
    > = {};
    for (const m of modes) {
      out[m.id] = [];
      for (const b of m.backends) {
        if (!CAPABILITIES[b].placement) continue;
        const counts = await resolverFor(b).boundCounts(ctx.db);
        const n = counts[m.id] ?? 0;
        out[m.id]!.push({ backendId: b, bound: n > 0, boundCount: n });
      }
    }
    return out;
  },
});

// --- admin CRUD (admin:settings:write surface) ----------------------------------

const familyUpsertFields = {
  label: v.optional(v.union(v.string(), v.null())),
  description: v.optional(v.union(v.string(), v.null())),
  audience: v.optional(v.union(v.string(), v.null())),
  iconId: v.optional(v.string()),
  enabled: v.optional(v.boolean()),
  order: v.optional(v.number()),
};

const modeUpsertFields = {
  family: v.optional(v.string()),
  label: v.optional(v.union(v.string(), v.null())),
  description: v.optional(v.union(v.string(), v.null())),
  deliveryStyle: v.optional(v.union(v.literal('url'), v.literal('rawConfig'))),
  enabled: v.optional(v.boolean()),
  isFamilyDefault: v.optional(v.boolean()),
  isCensorshipRecommended: v.optional(v.boolean()),
  backends: v.optional(v.array(backendIdValidator)),
  order: v.optional(v.number()),
  makeDefault: v.optional(v.boolean()),
  // The backup mode a key of this mode is also placed in; null clears it.
  fallbackModeSlug: v.optional(v.union(v.string(), v.null())),
};

/**
 * A backup mode must be another mode of the same family that offers at least
 * the same backends, and has no backup of its own (no chains): a key is placed
 * in its own group and that one group more, nothing further.
 */
async function checkFallback(
  ctx: MutationCtx,
  self: { slug: string; family: string; backends: readonly string[] },
  fallback: string,
): Promise<void> {
  if (fallback === self.slug) validationError('a mode cannot be its own backup');
  const row = await modeBySlug(ctx, fallback);
  if (!row) return validationError(`unknown backup mode "${fallback}"`);
  if (row.familySlug !== self.family) validationError('a backup mode must be in the same family');
  if (!self.backends.every((b) => row.backends.includes(b as never)))
    validationError('a backup mode must offer every backend this mode does');
  if (row.fallbackModeSlug) validationError('a backup mode cannot have a backup of its own');
  const leaning = await ctx.db
    .query('connectionModes')
    .collect()
    .then((rows) => rows.some((r) => r.fallbackModeSlug === self.slug));
  if (leaning) validationError('another mode uses this one as its backup');
}

function validationError(message: string): never {
  throw new ConvexError({ code: 'validation', message });
}

function checkSlug(slug: string): string {
  const s = slug.trim();
  if (!MODE_SLUG_RE.test(s)) {
    validationError(
      'slug must be 1-32 chars of lowercase letters, digits, and hyphens, starting alphanumeric',
    );
  }
  return s;
}

function cleanCopy(
  value: string | null | undefined,
  field: string,
  max: number,
): string | undefined {
  if (value == null) return undefined; // null/absent → clear/keep, caller decides
  const t = value.trim();
  if (t.length > max) validationError(`${field} must be at most ${max} characters`);
  return t || undefined;
}

async function familyBySlug(
  ctx: MutationCtx,
  slug: string,
): Promise<Doc<'connectionModeFamilies'> | null> {
  return ctx.db
    .query('connectionModeFamilies')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
}

async function modeBySlug(ctx: MutationCtx, slug: string): Promise<Doc<'connectionModes'> | null> {
  return ctx.db
    .query('connectionModes')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
}

/** Editing an empty-table (defaults-served) catalog first MATERIALIZES the
 *  compiled defaults as rows, so a partial edit can't strand the other
 *  defaults (the read fallback is all-or-nothing on table emptiness). */
async function materializeDefaultsIfEmpty(ctx: MutationCtx): Promise<void> {
  const [fam, mode] = await Promise.all([
    ctx.db.query('connectionModeFamilies').first(),
    ctx.db.query('connectionModes').first(),
  ]);
  if (fam || mode) return;
  const { families, modes } = await resolveModeCatalog(ctx.db); // = compiled defaults
  const now = Date.now();
  for (const f of families) {
    await ctx.db.insert('connectionModeFamilies', {
      slug: f.id,
      iconId: f.iconId,
      enabled: f.enabled,
      order: f.order,
      updatedAt: now,
    });
  }
  for (const m of modes) {
    await ctx.db.insert('connectionModes', {
      slug: m.id,
      familySlug: m.family,
      deliveryStyle: m.deliveryStyle,
      enabled: m.ownEnabled,
      isFamilyDefault: m.isFamilyDefault,
      isCensorshipRecommended: m.isCensorshipRecommended || undefined,
      backends: m.backends,
      order: m.order,
      updatedAt: now,
    });
  }
}

/**
 * Freedom modes only through edges (lib/edges/freedomDelivery.ts): a mode is
 * never put in the freedom family, or turned on there, while a backend sets it
 * up direct.
 */
async function refuseFreedomDirect(ctx: MutationCtx, slug: string): Promise<void> {
  if (!(await freedomEdgesOnly(ctx.db))) return;
  const reason = await freedomDirectRefusal(ctx.db, slug);
  if (reason)
    throw new ConvexError({ code: 'conflict', message: reason, data: { freedomModeDirect: true } });
}

/** Clear the family's previous default leaf when a new one claims the flag. */
async function clearOtherFamilyDefault(
  ctx: MutationCtx,
  familySlug: string,
  keepId: Id<'connectionModes'> | null,
): Promise<void> {
  const rows = await ctx.db.query('connectionModes').collect(); // tiny table, admin path
  for (const r of rows) {
    if (r.familySlug === familySlug && r.isFamilyDefault && r._id !== keepId) {
      await ctx.db.patch(r._id, { isFamilyDefault: false, updatedAt: Date.now() });
    }
  }
}

export const createFamily = internalMutation({
  args: {
    ...familyUpsertFields,
    slug: v.string(),
    label: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const slug = checkSlug(a.slug);
    if (await familyBySlug(ctx, slug))
      validationError(`a family with slug "${slug}" already exists`);
    const label = cleanCopy(a.label, 'label', 64);
    if (!label && !BUILT_IN_FAMILY_SLUGS.has(slug)) {
      validationError('a label is required (new ids have no built-in translation)');
    }
    const id = await ctx.db.insert('connectionModeFamilies', {
      slug,
      label,
      description: cleanCopy(a.description ?? undefined, 'description', 500),
      audience: cleanCopy(a.audience ?? undefined, 'audience', 80),
      iconId: (a.iconId ?? '').trim() || 'zap',
      enabled: a.enabled ?? true,
      order: a.order ?? 0,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode_family.create',
      targetType: 'connection_mode_family',
      targetId: slug,
      payload: { slug },
    });
    return { id: id as string, slug };
  },
});

export const updateFamily = internalMutation({
  args: {
    slug: v.string(),
    ...familyUpsertFields,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const row = await familyBySlug(ctx, a.slug);
    if (!row) validationError(`unknown family "${a.slug}"`);
    const patch: Partial<Doc<'connectionModeFamilies'>> = { updatedAt: Date.now() };
    // null clears an override back to the built-in i18n; a non-built-in family
    // must keep SOME label (raw slugs must never render).
    if (a.label !== undefined) {
      const label = a.label === null ? undefined : cleanCopy(a.label, 'label', 64);
      if (!label && !BUILT_IN_FAMILY_SLUGS.has(row.slug)) {
        validationError('a label is required (new ids have no built-in translation)');
      }
      patch.label = label;
    }
    if (a.description !== undefined) {
      patch.description =
        a.description === null ? undefined : cleanCopy(a.description, 'description', 500);
    }
    if (a.audience !== undefined) {
      patch.audience = a.audience === null ? undefined : cleanCopy(a.audience, 'audience', 80);
    }
    if (a.iconId !== undefined) patch.iconId = a.iconId.trim() || 'zap';
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.order !== undefined) patch.order = a.order;
    if (row.slug === FREEDOM_FAMILY && a.enabled === true && !row.enabled) {
      const modes = await ctx.db.query('connectionModes').collect(); // tiny table, admin path
      for (const m of modes)
        if (m.familySlug === FREEDOM_FAMILY && m.enabled) await refuseFreedomDirect(ctx, m.slug);
    }
    await ctx.db.patch(row._id, patch);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode_family.update',
      targetType: 'connection_mode_family',
      targetId: row.slug,
      payload: { slug: row.slug },
    });
    return { ok: true };
  },
});

export const removeFamily = internalMutation({
  args: { slug: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const row = await familyBySlug(ctx, a.slug);
    if (!row) validationError(`unknown family "${a.slug}"`);
    const child = await ctx.db
      .query('connectionModes')
      .collect()
      .then((rows) => rows.find((m) => m.familySlug === row.slug));
    if (child) {
      throw new ConvexError({
        code: 'conflict',
        message: `family "${row.slug}" still has modes; move or delete them first`,
      });
    }
    await ctx.db.delete(row._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode_family.delete',
      targetType: 'connection_mode_family',
      targetId: row.slug,
      payload: { slug: row.slug },
    });
    return { ok: true };
  },
});

export const createMode = internalMutation({
  args: {
    ...modeUpsertFields,
    slug: v.string(),
    label: v.string(),
    family: v.string(),
    deliveryStyle: v.union(v.literal('url'), v.literal('rawConfig')),
    backends: v.array(backendIdValidator),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const slug = checkSlug(a.slug);
    if (await modeBySlug(ctx, slug)) validationError(`a mode with slug "${slug}" already exists`);
    if (!(await familyBySlug(ctx, a.family))) validationError(`unknown family "${a.family}"`);
    if (a.backends.length === 0) validationError('a mode must declare at least one backend');
    const label = cleanCopy(a.label, 'label', 64);
    if (!label && !BUILT_IN_MODE_SLUGS.has(slug)) {
      validationError('a label is required (new ids have no built-in translation)');
    }
    if (a.family === FREEDOM_FAMILY && (a.enabled ?? true)) await refuseFreedomDirect(ctx, slug);
    if (a.fallbackModeSlug)
      await checkFallback(
        ctx,
        { slug, family: a.family, backends: a.backends },
        a.fallbackModeSlug,
      );
    const id = await ctx.db.insert('connectionModes', {
      slug,
      familySlug: a.family,
      deliveryStyle: a.deliveryStyle,
      label,
      description: cleanCopy(a.description ?? undefined, 'description', 500),
      enabled: a.enabled ?? true,
      isFamilyDefault: a.isFamilyDefault ?? false,
      isCensorshipRecommended: a.isCensorshipRecommended || undefined,
      backends: a.backends,
      order: a.order ?? 0,
      ...(a.fallbackModeSlug ? { fallbackModeSlug: a.fallbackModeSlug } : {}),
      updatedAt: Date.now(),
    });
    if (a.isFamilyDefault) await clearOtherFamilyDefault(ctx, a.family, id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode.create',
      targetType: 'connection_mode',
      targetId: slug,
      payload: { slug },
    });
    return { id: id as string, slug };
  },
});

export const updateMode = internalMutation({
  args: {
    slug: v.string(),
    ...modeUpsertFields,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const row = await modeBySlug(ctx, a.slug);
    if (!row) validationError(`unknown mode "${a.slug}"`);
    const patch: Partial<Doc<'connectionModes'>> = { updatedAt: Date.now() };
    if (a.family !== undefined) {
      if (!(await familyBySlug(ctx, a.family))) validationError(`unknown family "${a.family}"`);
      patch.familySlug = a.family;
    }
    if (a.label !== undefined) {
      const label = a.label === null ? undefined : cleanCopy(a.label, 'label', 64);
      if (!label && !BUILT_IN_MODE_SLUGS.has(row.slug)) {
        validationError('a label is required (new ids have no built-in translation)');
      }
      patch.label = label;
    }
    if (a.description !== undefined) {
      patch.description =
        a.description === null ? undefined : cleanCopy(a.description, 'description', 500);
    }
    if (a.deliveryStyle !== undefined) patch.deliveryStyle = a.deliveryStyle;
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.isFamilyDefault !== undefined) patch.isFamilyDefault = a.isFamilyDefault;
    if (a.isCensorshipRecommended !== undefined) {
      patch.isCensorshipRecommended = a.isCensorshipRecommended || undefined;
    }
    if (a.backends !== undefined) {
      if (a.backends.length === 0) validationError('a mode must declare at least one backend');
      patch.backends = a.backends;
    }
    if (a.order !== undefined) patch.order = a.order;
    if (a.fallbackModeSlug !== undefined) patch.fallbackModeSlug = a.fallbackModeSlug ?? undefined;
    // This mode may be another one's backup: it must stay in that mode's family
    // and keep offering every backend that mode does.
    if (a.family !== undefined || a.backends !== undefined) {
      const family = patch.familySlug ?? row.familySlug;
      const backends = patch.backends ?? row.backends;
      for (const r of await ctx.db.query('connectionModes').collect()) {
        if (r.fallbackModeSlug !== row.slug) continue;
        if (r.familySlug !== family)
          validationError(`"${r.slug}" uses this mode as its backup: it must stay in its family`);
        if (!r.backends.every((b) => backends.includes(b)))
          validationError(
            `"${r.slug}" uses this mode as its backup: it must keep every backend that mode offers`,
          );
      }
    }
    const fallback = a.fallbackModeSlug === undefined ? row.fallbackModeSlug : a.fallbackModeSlug;
    if (
      fallback &&
      (a.fallbackModeSlug !== undefined || a.family !== undefined || a.backends !== undefined)
    )
      await checkFallback(
        ctx,
        {
          slug: row.slug,
          family: patch.familySlug ?? row.familySlug,
          backends: patch.backends ?? row.backends,
        },
        fallback,
      );

    // Guard: disabling the resolved default in the same patch as makeDefault
    // makes no sense; and makeDefault on a mode being disabled is refused.
    if (a.makeDefault && (a.enabled === false || (!row.enabled && a.enabled === undefined))) {
      validationError('cannot make a disabled mode the default');
    }
    // Moved into the freedom family, or turned on there: never while set up direct.
    const family = patch.familySlug ?? row.familySlug;
    const enabled = patch.enabled ?? row.enabled;
    if (family === FREEDOM_FAMILY && enabled && (row.familySlug !== FREEDOM_FAMILY || !row.enabled))
      await refuseFreedomDirect(ctx, row.slug);
    await ctx.db.patch(row._id, patch);
    if (a.isFamilyDefault) {
      await clearOtherFamilyDefault(ctx, patch.familySlug ?? row.familySlug, row._id);
    }
    if (a.makeDefault) {
      await upsertSettingRow(
        ctx,
        CONNECTION_MODE_DEFAULT_KEY,
        JSON.stringify(row.slug),
        a.actorAdminId,
      );
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode.update',
      targetType: 'connection_mode',
      targetId: row.slug,
      payload: { slug: row.slug },
    });
    return { ok: true };
  },
});

export const removeMode = internalMutation({
  args: { slug: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    await materializeDefaultsIfEmpty(ctx);
    const row = await modeBySlug(ctx, a.slug);
    if (!row) validationError(`unknown mode "${a.slug}"`);
    // A mode another mode uses as its backup: its keys are placed in it too.
    const leaning = (await ctx.db.query('connectionModes').collect()).find(
      (r) => r.fallbackModeSlug === row.slug,
    );
    if (leaning) validationError(`"${leaning.slug}" uses this mode as its backup`);

    // Occupied guard: a member sitting on this slug would be silently re-homed
    // to the default on their next read — strand nobody, make the admin move
    // them (or wait) first. Indexed existence check, never a full count.
    const occupant = await ctx.db
      .query('users')
      .withIndex('by_connection_mode', (q) => q.eq('connectionModeId', row.slug))
      .first();
    if (occupant) {
      throw new ConvexError({
        code: 'conflict',
        message: 'members are currently on this mode; disable it instead of deleting',
        data: { occupied: true },
      });
    }
    // Default guard: deleting the resolved default repoints every new account —
    // make that an explicit two-step (set a new default first).
    const currentDefault = await resolveDefaultModeId(ctx.db);
    const { modes } = await resolveModeCatalog(ctx.db);
    if (row.slug === currentDefault && modes.some((m) => m.enabled && m.id !== row.slug)) {
      throw new ConvexError({
        code: 'conflict',
        message: 'this mode is the default; set another default before deleting it',
      });
    }
    // Cascade this mode's placement bindings (every backend).
    const placements = await ctx.db.query('modePlacements').collect();
    for (const p of placements) {
      if (p.modeSlug === row.slug) await ctx.db.delete(p._id);
    }
    await ctx.db.delete(row._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.connection_mode.delete',
      targetType: 'connection_mode',
      targetId: row.slug,
      payload: { slug: row.slug },
    });
    return { ok: true };
  },
});
