/**
 * Admin-uploaded site images (lib/siteImage.ts has the format checks and the
 * storage layout). The HTTP routes in http.ts check the bytes before calling
 * `setHomeImage`, so these mutations only store and audit.
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import {
  HOME_IMAGE_SETTING_KEY,
  HOME_IMAGE_SLOT,
  sanitizeSiteImageRef,
  type SiteImageRef,
} from './lib/siteImage';

async function slotRows(ctx: MutationCtx, slot: string) {
  return ctx.db
    .query('siteImages')
    .withIndex('by_slot', (q) => q.eq('slot', slot))
    .collect();
}

/** The current home image's bytes for the public route; null when none is set. */
export const getHomeImage = internalQuery({
  args: {},
  handler: async (ctx) => {
    const row = await ctx.db
      .query('siteImages')
      .withIndex('by_slot', (q) => q.eq('slot', HOME_IMAGE_SLOT))
      .first();
    if (!row) return null;
    return { data: row.data, contentType: row.contentType, version: row.version };
  },
});

/** Replace the home image. The bytes were checked by the caller. */
export const setHomeImage = internalMutation({
  args: {
    data: v.bytes(),
    contentType: v.string(),
    width: v.number(),
    height: v.number(),
    version: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, args): Promise<SiteImageRef> => {
    const ref = sanitizeSiteImageRef(args);
    if (!ref) throw new Error('setHomeImage: unchecked image');
    const now = Date.now();
    const [first, ...extra] = await slotRows(ctx, HOME_IMAGE_SLOT);
    const row = {
      data: args.data,
      contentType: args.contentType,
      width: ref.width,
      height: ref.height,
      version: ref.version,
      updatedByAdminId: args.actorAdminId,
      updatedAt: now,
    };
    if (first) await ctx.db.patch(first._id, row);
    else await ctx.db.insert('siteImages', { slot: HOME_IMAGE_SLOT, ...row });
    for (const r of extra) await ctx.db.delete(r._id);
    await upsertSettingRow(ctx, HOME_IMAGE_SETTING_KEY, JSON.stringify(ref), args.actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: args.actorAdminId ?? undefined,
      action: 'admin.site.home_image.set',
      targetType: 'site',
      payload: { ...ref, bytes: args.data.byteLength, contentType: args.contentType },
    });
    return ref;
  },
});

/** Go back to the built-in image. */
export const resetHomeImage = internalMutation({
  args: { actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { actorAdminId }) => {
    for (const r of await slotRows(ctx, HOME_IMAGE_SLOT)) await ctx.db.delete(r._id);
    const setting = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', HOME_IMAGE_SETTING_KEY))
      .unique();
    if (setting) await ctx.db.delete(setting._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.site.home_image.reset',
      targetType: 'site',
    });
    return null;
  },
});
