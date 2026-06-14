/**
 * S3 subscription-mirror providers — the DB half of the censorship-resistance
 * hedge, fully CMS-managed (replaced the S3_MIRRORS_ENABLED / S3_PROVIDER_* env
 * scheme). A sibling of backendServers.ts: a variable-length pool of
 * secret-bearing rows.
 *
 * Every function here is INTERNAL. The actions in convex/storage.ts ("use node",
 * so they can't define queries) call `listActiveWithSecret` to get the providers
 * to upload to, and `anyActive` as the cheap issuance gate. The admin CMS reaches
 * the *masked* CRUD (no secretAccessKey ever leaves the server) via the
 * admin-gated HTTP layer. Mirroring is ACTIVE iff ≥1 row is `isActive`.
 *
 * The secret invariant mirrors backendServers: `secretAccessKey` is stored on
 * create/edit, read back ONLY by the storage actions, and surfaced to the admin
 * as a `secretAccessKeySet` boolean. `accessKeyId` is the public half of the
 * keypair (shown). Nothing here is logged.
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';

/**
 * One active provider with its full credentials, shaped exactly like
 * storage.ts's `S3Provider` (structurally identical, so it passes straight into
 * uploadToProviders). Exported + used as the explicit handler return type so the
 * shape survives Convex's cross-module codegen into the "use node" storage actions.
 */
export interface MirrorProvider {
  name: string;
  endpoint: string;
  bucket: string;
  publicUrl: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

function toProvider(r: Doc<'mirrorProviders'>): MirrorProvider {
  return {
    name: r.name,
    endpoint: r.endpoint,
    bucket: r.bucket,
    publicUrl: r.publicUrl,
    region: r.region,
    accessKeyId: r.accessKeyId,
    secretAccessKey: r.secretAccessKey,
  };
}

/** Uppercase + dedupe ISO-3166-1 alpha-2 codes; drop anything not 2 letters. */
function normalizeCountryCodes(raw: string[] | undefined): string[] {
  if (!raw) return [];
  const seen = new Set<string>();
  for (const c of raw) {
    const cc = c.trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(cc)) seen.add(cc);
  }
  return [...seen];
}

/** Admin-safe view: everything EXCEPT the secret, which becomes a boolean. */
function mapProviderAdmin(r: Doc<'mirrorProviders'>) {
  return {
    id: r._id as string,
    name: r.name,
    endpoint: r.endpoint,
    bucket: r.bucket,
    publicUrl: r.publicUrl,
    region: r.region,
    accessKeyId: r.accessKeyId,
    secretAccessKeySet: r.secretAccessKey.length > 0,
    countryCodes: r.countryCodes ?? [],
    isActive: r.isActive,
    priority: r.priority,
    createdAt: new Date(r._creationTime).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

// --- consumed by the storage actions (full secrets, internal only) -----------

/** Active providers WITH their secrets, ascending by priority. The upload set. */
export const listActiveWithSecret = internalQuery({
  args: {},
  handler: async (ctx): Promise<MirrorProvider[]> => {
    const rows = await ctx.db
      .query('mirrorProviders')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    return rows.sort((a, b) => a.priority - b.priority).map(toProvider);
  },
});

/**
 * ALL providers WITH their secrets (active or not). Used by the teardown delete
 * path so a provider that was since *deactivated* still has its stale mirror
 * objects cleaned up (uploadToProviders only ever writes to active ones).
 */
export const listAllWithSecret = internalQuery({
  args: {},
  handler: async (ctx): Promise<MirrorProvider[]> => {
    const rows = await ctx.db.query('mirrorProviders').collect();
    return rows.map(toProvider);
  },
});

/** Cheap gate: is any mirror provider configured + enabled? */
export const anyActive = internalQuery({
  args: {},
  handler: async (ctx): Promise<boolean> => {
    const one = await ctx.db
      .query('mirrorProviders')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .first();
    return one !== null;
  },
});

/**
 * Pick the next mirror provider to hand a member, given their (transient,
 * never-stored) country and the providers they've already tried. Ordering:
 * country-matched first, then global (no countryCodes), each by ascending
 * priority; providers scoped to OTHER countries only are excluded. Returns the
 * provider name (the caller re-resolves the secret via listActiveWithSecret to
 * upload) or null when none remain.
 */
export const selectNextProvider = internalQuery({
  args: { countryCode: v.union(v.string(), v.null()), tried: v.array(v.string()) },
  handler: async (ctx, { countryCode, tried }): Promise<{ name: string } | null> => {
    const triedSet = new Set(tried);
    const cc = countryCode?.trim().toUpperCase() || null;
    const active = (
      await ctx.db
        .query('mirrorProviders')
        .withIndex('by_active', (q) => q.eq('isActive', true))
        .collect()
    ).filter((p) => !triedSet.has(p.name));
    const rank = (p: Doc<'mirrorProviders'>): number => {
      const codes = p.countryCodes ?? [];
      if (cc && codes.includes(cc)) return 0; // preferred for this country
      if (codes.length === 0) return 1; // global fallback
      return 2; // scoped to other countries only — not eligible
    };
    const chosen = active
      .filter((p) => rank(p) < 2)
      .sort((a, b) => rank(a) - rank(b) || a.priority - b.priority)[0];
    return chosen ? { name: chosen.name } : null;
  },
});

// --- admin CMS (masked; the only caller is the admin-gated HTTP layer) --------

export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('mirrorProviders').collect();
    return { providers: rows.sort((a, b) => a.priority - b.priority).map(mapProviderAdmin) };
  },
});

export const create = internalMutation({
  args: {
    name: v.string(),
    endpoint: v.string(),
    bucket: v.string(),
    publicUrl: v.string(),
    region: v.optional(v.string()),
    accessKeyId: v.string(),
    secretAccessKey: v.string(),
    countryCodes: v.optional(v.array(v.string())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const name = a.name.trim();
    if (!name)
      throw new ConvexError({ code: 'validation', message: 'A provider name is required' });
    const clash = await ctx.db
      .query('mirrorProviders')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    if (clash) {
      throw new ConvexError({
        code: 'validation',
        message: `A mirror provider named "${name}" already exists`,
      });
    }
    if (!a.endpoint || !a.bucket || !a.publicUrl || !a.accessKeyId || !a.secretAccessKey) {
      throw new ConvexError({
        code: 'validation',
        message: 'endpoint, bucket, public URL, access key ID and secret are all required',
      });
    }
    const id = await ctx.db.insert('mirrorProviders', {
      name,
      endpoint: a.endpoint,
      bucket: a.bucket,
      publicUrl: a.publicUrl,
      region: a.region?.trim() || 'us-east-1',
      accessKeyId: a.accessKeyId,
      secretAccessKey: a.secretAccessKey,
      countryCodes: normalizeCountryCodes(a.countryCodes),
      isActive: a.isActive ?? true,
      priority: a.priority ?? 0,
      updatedAt: Date.now(),
    });
    return mapProviderAdmin((await ctx.db.get(id))!);
  },
});

export const update = internalMutation({
  args: {
    id: v.id('mirrorProviders'),
    name: v.optional(v.string()),
    endpoint: v.optional(v.string()),
    bucket: v.optional(v.string()),
    publicUrl: v.optional(v.string()),
    region: v.optional(v.string()),
    accessKeyId: v.optional(v.string()),
    // Write-only: a blank/absent secret keeps the stored one (the UI never
    // round-trips it), so editing other fields can't wipe the credential.
    secretAccessKey: v.optional(v.string()),
    countryCodes: v.optional(v.array(v.string())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, { id, ...patch }) => {
    const existing = await ctx.db.get(id);
    if (!existing)
      throw new ConvexError({ code: 'not_found', message: 'Mirror provider not found' });

    const fields: Partial<Doc<'mirrorProviders'>> = { updatedAt: Date.now() };
    if (patch.name !== undefined) {
      const name = patch.name.trim();
      if (!name)
        throw new ConvexError({ code: 'validation', message: 'A provider name is required' });
      if (name !== existing.name) {
        const clash = await ctx.db
          .query('mirrorProviders')
          .withIndex('by_name', (q) => q.eq('name', name))
          .unique();
        if (clash) {
          throw new ConvexError({
            code: 'validation',
            message: `A mirror provider named "${name}" already exists`,
          });
        }
      }
      fields.name = name;
    }
    if (patch.endpoint !== undefined && patch.endpoint !== '') fields.endpoint = patch.endpoint;
    if (patch.bucket !== undefined && patch.bucket !== '') fields.bucket = patch.bucket;
    if (patch.publicUrl !== undefined && patch.publicUrl !== '') fields.publicUrl = patch.publicUrl;
    if (patch.region !== undefined && patch.region.trim() !== '')
      fields.region = patch.region.trim();
    if (patch.accessKeyId !== undefined && patch.accessKeyId !== '') {
      fields.accessKeyId = patch.accessKeyId;
    }
    // Only overwrite the secret when the admin actually retyped one.
    if (patch.secretAccessKey !== undefined && patch.secretAccessKey !== '') {
      fields.secretAccessKey = patch.secretAccessKey;
    }
    if (patch.countryCodes !== undefined) {
      fields.countryCodes = normalizeCountryCodes(patch.countryCodes);
    }
    if (patch.isActive !== undefined) fields.isActive = patch.isActive;
    if (patch.priority !== undefined) fields.priority = patch.priority;

    await ctx.db.patch(id, fields);
    return mapProviderAdmin((await ctx.db.get(id))!);
  },
});

export const remove = internalMutation({
  args: { id: v.id('mirrorProviders') },
  handler: async (ctx, { id }) => {
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});
