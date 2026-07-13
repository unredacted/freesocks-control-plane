/**
 * Recommended VPN client apps — the DB half of the member "set up your app"
 * catalog, fully CMS-managed. Mirrors convex/mirrorProviders.ts (a variable-length
 * pool with per-row CRUD), but SIMPLER: the catalog carries NO secrets, so nothing
 * is masked and — like the mirror domain — these writes are not audited (they are
 * low-risk, public config). Compiled defaults + the empty→defaults fallback live in
 * convex/lib/clientCatalog.ts; publicConfig.get ships the public projection.
 *
 * Every function is INTERNAL; the admin CMS reaches them via the admin-gated HTTP
 * layer. The per-app import URL scheme is NOT stored here — `schemeId` references a
 * tested code builder in src/client/lib/appLinks.ts (null = manual / QR import only).
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';

const backendId = v.union(v.literal('remnawave'), v.literal('outline'));
const PLATFORM_KEYS = ['android', 'ios', 'windows', 'desktop'];
// Ease-of-use rating; null clears it (treated as 'moderate' downstream).
const easeOfUse = v.union(v.literal('easy'), v.literal('moderate'), v.literal('advanced'));

function mapClient(r: Doc<'clients'>) {
  return {
    id: r._id as string,
    name: r.name,
    platforms: r.platforms,
    backends: r.backends,
    homepageUrl: r.homepageUrl,
    schemeId: r.schemeId ?? null,
    hwid: r.hwid,
    openSource: r.openSource ?? false,
    license: r.license ?? null,
    sourceUrl: r.sourceUrl ?? null,
    easeOfUse: r.easeOfUse ?? null,
    enabled: r.enabled,
    priority: r.priority,
    createdAt: new Date(r._creationTime).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

/** Keep only known platform keys, lower-cased + deduped. */
function normalizePlatforms(raw: string[] | undefined): string[] {
  if (!raw) return [];
  const seen = new Set<string>();
  for (const p of raw) {
    const k = p.trim().toLowerCase();
    if (PLATFORM_KEYS.includes(k)) seen.add(k);
  }
  return [...seen];
}

export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('clients').collect();
    return { clients: rows.sort((a, b) => a.priority - b.priority).map(mapClient) };
  },
});

export const create = internalMutation({
  args: {
    name: v.string(),
    platforms: v.array(v.string()),
    backends: v.array(backendId),
    homepageUrl: v.string(),
    // Accept null (the editor sends `x || null` for empty optional text fields).
    schemeId: v.optional(v.union(v.string(), v.null())),
    hwid: v.optional(v.boolean()),
    openSource: v.optional(v.boolean()),
    license: v.optional(v.union(v.string(), v.null())),
    sourceUrl: v.optional(v.union(v.string(), v.null())),
    easeOfUse: v.optional(v.union(easeOfUse, v.null())),
    enabled: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const name = a.name.trim();
    if (!name) throw new ConvexError({ code: 'validation', message: 'A client name is required' });
    const clash = await ctx.db
      .query('clients')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    if (clash) {
      throw new ConvexError({
        code: 'validation',
        message: `A client named "${name}" already exists`,
      });
    }
    if (!a.homepageUrl.trim()) {
      throw new ConvexError({
        code: 'validation',
        message: 'A homepage / install URL is required',
      });
    }
    const id = await ctx.db.insert('clients', {
      name,
      platforms: normalizePlatforms(a.platforms),
      backends: a.backends,
      homepageUrl: a.homepageUrl.trim(),
      schemeId: a.schemeId?.trim() || undefined,
      hwid: a.hwid ?? false,
      openSource: a.openSource ?? false,
      license: a.license?.trim() || undefined,
      sourceUrl: a.sourceUrl?.trim() || undefined,
      easeOfUse: a.easeOfUse ?? undefined,
      enabled: a.enabled ?? true,
      priority: a.priority ?? 0,
      updatedAt: Date.now(),
    });
    return mapClient((await ctx.db.get(id))!);
  },
});

export const update = internalMutation({
  args: {
    id: v.id('clients'),
    name: v.optional(v.string()),
    platforms: v.optional(v.array(v.string())),
    backends: v.optional(v.array(backendId)),
    homepageUrl: v.optional(v.string()),
    // null clears the scheme (client becomes manual / QR only).
    schemeId: v.optional(v.union(v.string(), v.null())),
    hwid: v.optional(v.boolean()),
    openSource: v.optional(v.boolean()),
    license: v.optional(v.union(v.string(), v.null())),
    sourceUrl: v.optional(v.union(v.string(), v.null())),
    easeOfUse: v.optional(v.union(easeOfUse, v.null())),
    enabled: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, { id, ...patch }) => {
    const existing = await ctx.db.get(id);
    if (!existing) throw new ConvexError({ code: 'not_found', message: 'Client not found' });
    const fields: Partial<Doc<'clients'>> = { updatedAt: Date.now() };
    if (patch.name !== undefined) {
      const name = patch.name.trim();
      if (!name)
        throw new ConvexError({ code: 'validation', message: 'A client name is required' });
      if (name !== existing.name) {
        const clash = await ctx.db
          .query('clients')
          .withIndex('by_name', (q) => q.eq('name', name))
          .unique();
        if (clash) {
          throw new ConvexError({
            code: 'validation',
            message: `A client named "${name}" already exists`,
          });
        }
      }
      fields.name = name;
    }
    if (patch.platforms !== undefined) fields.platforms = normalizePlatforms(patch.platforms);
    if (patch.backends !== undefined) fields.backends = patch.backends;
    if (patch.homepageUrl !== undefined && patch.homepageUrl.trim() !== '') {
      fields.homepageUrl = patch.homepageUrl.trim();
    }
    if (patch.schemeId !== undefined) fields.schemeId = patch.schemeId?.trim() || undefined;
    if (patch.hwid !== undefined) fields.hwid = patch.hwid;
    if (patch.openSource !== undefined) fields.openSource = patch.openSource;
    if (patch.license !== undefined) fields.license = patch.license?.trim() || undefined;
    if (patch.sourceUrl !== undefined) fields.sourceUrl = patch.sourceUrl?.trim() || undefined;
    if (patch.easeOfUse !== undefined) fields.easeOfUse = patch.easeOfUse ?? undefined;
    if (patch.enabled !== undefined) fields.enabled = patch.enabled;
    if (patch.priority !== undefined) fields.priority = patch.priority;
    await ctx.db.patch(id, fields);
    return mapClient((await ctx.db.get(id))!);
  },
});

export const remove = internalMutation({
  args: { id: v.id('clients') },
  handler: async (ctx, { id }) => {
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});

/**
 * Idempotent client upsert addressed by name (IaC / seeding). MISSING → create
 * (homepage URL required); EXISTING → patch provided fields. Mirrors
 * upsertBackendServerBySlug / mirrorProviders.upsertByName.
 */
export const upsertByName = internalMutation({
  args: {
    name: v.string(),
    platforms: v.optional(v.array(v.string())),
    backends: v.optional(v.array(backendId)),
    homepageUrl: v.optional(v.string()),
    schemeId: v.optional(v.union(v.string(), v.null())),
    hwid: v.optional(v.boolean()),
    openSource: v.optional(v.boolean()),
    license: v.optional(v.union(v.string(), v.null())),
    sourceUrl: v.optional(v.union(v.string(), v.null())),
    easeOfUse: v.optional(v.union(easeOfUse, v.null())),
    enabled: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const name = a.name.trim();
    if (!name) throw new ConvexError({ code: 'validation', message: 'A client name is required' });
    const existing = await ctx.db
      .query('clients')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    if (!existing) {
      if (!a.homepageUrl || !a.homepageUrl.trim()) {
        throw new ConvexError({
          code: 'validation',
          message: 'A new client needs a homepage / install URL',
        });
      }
      const id = await ctx.db.insert('clients', {
        name,
        platforms: normalizePlatforms(a.platforms),
        backends: a.backends ?? ['remnawave'],
        homepageUrl: a.homepageUrl.trim(),
        schemeId: a.schemeId?.trim() || undefined,
        hwid: a.hwid ?? false,
        openSource: a.openSource ?? false,
        license: a.license?.trim() || undefined,
        sourceUrl: a.sourceUrl?.trim() || undefined,
        easeOfUse: a.easeOfUse ?? undefined,
        enabled: a.enabled ?? true,
        priority: a.priority ?? 0,
        updatedAt: Date.now(),
      });
      return { ...mapClient((await ctx.db.get(id))!), created: true };
    }
    const fields: Partial<Doc<'clients'>> = { updatedAt: Date.now() };
    if (a.platforms !== undefined) fields.platforms = normalizePlatforms(a.platforms);
    if (a.backends !== undefined) fields.backends = a.backends;
    if (a.homepageUrl !== undefined && a.homepageUrl.trim() !== '')
      fields.homepageUrl = a.homepageUrl.trim();
    if (a.schemeId !== undefined) fields.schemeId = a.schemeId?.trim() || undefined;
    if (a.hwid !== undefined) fields.hwid = a.hwid;
    if (a.openSource !== undefined) fields.openSource = a.openSource;
    if (a.license !== undefined) fields.license = a.license?.trim() || undefined;
    if (a.sourceUrl !== undefined) fields.sourceUrl = a.sourceUrl?.trim() || undefined;
    if (a.easeOfUse !== undefined) fields.easeOfUse = a.easeOfUse ?? undefined;
    if (a.enabled !== undefined) fields.enabled = a.enabled;
    if (a.priority !== undefined) fields.priority = a.priority;
    await ctx.db.patch(existing._id, fields);
    return { ...mapClient((await ctx.db.get(existing._id))!), created: false };
  },
});
