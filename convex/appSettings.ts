import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

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
  // Issuance-time node placement (Remnawave): weights for choosing the
  // least-loaded node of a mode's placement pool. usersOnline is the primary
  // signal; bandwidth defaults to 0 (usersOnline-only) until the realtime shape
  // is pinned against a live panel. Read by lib/remnawavePlacement.ts.
  'remnawave.nodePlacement.usersOnline_weight': 1,
  'remnawave.nodePlacement.bandwidth_weight': 0,
  // Free-account lifetime (days): drives both the issued key's backend expiry
  // and the cleanup-expired-free sweep. Admin-editable (replaced the
  // FREE_TIER_EXPIRY_DAYS env var).
  'freetier.expiryDays': 90,
  // Max S3 subscription mirrors a single member can provision (the opt-in
  // "trouble connecting? try a mirror" flow). Bounds at-rest copies per user.
  'mirror.maxPerUser': 3,
  // Country codes (ISO-3166-1 alpha-2) where the signup delivery picker SUGGESTS
  // "hardened privacy" instead of the default "evade censorship". Admin-tunable;
  // empty = always suggest evade. The choice itself is client-side only.
  'delivery.privacyCountries': [] as string[],
  // Master switch for per-tier device (HWID) limits. OFF (default) = FCP sends
  // hwidDeviceLimit:null for every user regardless of the tier's hwidEnabled, so
  // devices are effectively unlimited and the device UI is neutralized. ON =
  // per-tier hwidEnabled/hwidLimit apply and the connect UI gates apps by HWID
  // support. Enforcement ALSO requires HWID_DEVICE_LIMIT_ENABLED=true on the
  // Remnawave panel (FCP can't read that); see docs/backends.md.
  'devices.enforcementEnabled': false,
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

/** Upsert one setting row (JSON-encoded value) — the shared by-key upsert. */
export async function upsertSettingRow(
  ctx: MutationCtx,
  key: string,
  value: string,
  updatedByAdminId?: Id<'adminUsers'>,
): Promise<void> {
  const existing = await ctx.db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  const now = Date.now();
  if (existing) await ctx.db.patch(existing._id, { value, updatedByAdminId, updatedAt: now });
  else await ctx.db.insert('appSettings', { key, value, updatedByAdminId, updatedAt: now });
}

/** Upsert one setting (JSON-encoded). Admin-gated at the HTTP layer. */
export const set = internalMutation({
  args: { key: v.string(), value: v.string(), updatedByAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { key, value, updatedByAdminId }) => {
    await upsertSettingRow(ctx, key, value, updatedByAdminId);
    return null;
  },
});

/**
 * Atomic multi-key upsert (one transaction), so the admin settings PATCH applies a
 * whole patch or none — a mid-loop failure can't leave it half-applied with no
 * indication which half landed. (Review P3.)
 *
 * Every key is audited by NAME (never the value — some values are
 * secret-adjacent): these keys flip security-relevant behavior
 * (devices.enforcementEnabled, outline.enabled, freetier.expiryDays, …).
 */
export const setMany = internalMutation({
  args: {
    entries: v.array(v.object({ key: v.string(), value: v.string() })),
    updatedByAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { entries, updatedByAdminId }) => {
    for (const { key, value } of entries) {
      await upsertSettingRow(ctx, key, value, updatedByAdminId);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: updatedByAdminId ?? undefined,
        action: 'admin.settings.change',
        targetType: 'app_setting',
        targetId: key,
        payload: { key },
      });
    }
    return null;
  },
});
