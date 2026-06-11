import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

/**
 * Compiled-in defaults so an install with no rows still behaves. Mirrors
 * services/app-settings.ts DEFAULTS. Stored values are JSON-encoded strings
 * (matching the old format + the admin SET route), parsed on read.
 */
export const SETTINGS_DEFAULTS = {
  'outline.enabled': false,
  'remnawave.enabled': true,
  'subscription.default_backend': 'remnawave',
  'subscription.user_choice_enabled': false,
  'subscription.backend_labels': { remnawave: 'Xray', outline: 'Outline' },
  'backend.scoring.latency_weight': 1,
  'backend.scoring.key_count_weight': 100,
} as const;

// `getAll` / `get` (public queries) were deleted in pass 2: dead code (the SPA
// has no Convex client; everything reads `resolved` via the HTTP layer), and
// this table also holds the ratelimit.* policy overrides — nothing here may be
// publicly callable on the raw Convex channel.

/**
 * Settings as a typed bag with defaults applied (replaces
 * AppSettingsService.getAll). Unknown/corrupt rows fall back to the default so
 * a bad row fails closed instead of breaking reads.
 */
export const resolved = internalQuery({
  args: {},
  handler: async (ctx): Promise<Record<string, unknown>> => {
    const rows = await ctx.db.query('appSettings').collect();
    const map: Record<string, unknown> = { ...SETTINGS_DEFAULTS };
    for (const row of rows) {
      if (!(row.key in SETTINGS_DEFAULTS)) continue;
      try {
        map[row.key] = JSON.parse(row.value);
      } catch {
        /* keep the default */
      }
    }
    return map;
  },
});

/** Upsert one setting (JSON-encoded). Admin-gated at the HTTP layer. */
export const set = internalMutation({
  args: { key: v.string(), value: v.string(), updatedByAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { key, value, updatedByAdminId }) => {
    const existing = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    const now = Date.now();
    if (existing) await ctx.db.patch(existing._id, { value, updatedByAdminId, updatedAt: now });
    else await ctx.db.insert('appSettings', { key, value, updatedByAdminId, updatedAt: now });
    return null;
  },
});
