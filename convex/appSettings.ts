import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';
import { internal } from './_generated/api';
import { REVOCATION_DEFAULTS } from './lib/revocationWatch';

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
  // is pinned against a live backend. Read by lib/remnawavePlacement.ts.
  'remnawave.nodePlacement.usersOnline_weight': 1,
  'remnawave.nodePlacement.bandwidth_weight': 0,
  // Free-account lifetime (days): drives both the issued key's backend expiry
  // and the cleanup-expired-free sweep. Admin-editable (replaced the
  // FREE_TIER_EXPIRY_DAYS env var).
  'freetier.expiryDays': 90,
  // Max S3 subscription mirrors a single member can provision (the opt-in
  // "trouble connecting? try a mirror" flow). Bounds at-rest copies per user.
  'mirror.maxPerUser': 3,
  // Master switch for per-tier device (HWID) limits. OFF (default) = FCP sends
  // hwidDeviceLimit:null for every user regardless of the tier's hwidEnabled, so
  // devices are effectively unlimited and the device UI is neutralized. ON =
  // per-tier hwidEnabled/hwidLimit apply and the connect UI gates apps by HWID
  // support. Enforcement ALSO requires HWID_DEVICE_LIMIT_ENABLED=true on the
  // Remnawave backend (FCP can't read that); see docs/backends.md.
  'devices.enforcementEnabled': false,
  // The service name members' apps show (lib/memberEntryNames.ts): every
  // connection the backend names after a node or server name is renamed to
  // `<siteName> · <location>` (plus a short code when there are several).
  // `subscription.entryNames` false serves the backend's own names.
  'subscription.siteName': 'FreeSocks',
  'subscription.entryNames': true,
  // Where members connect from (lib/memberCountry.ts, docs/privacy.md). Off: the
  // CDN country is used for one response and stored nowhere (as before). On:
  // stored as a guess on freedom-family keys of Automatic members, only when it
  // is on the censored-country list, forgotten `stickyDays` after it was last
  // seen and written again at most every `refreshHours`. `ownExitRanges`: CIDRs
  // traffic leaves the service from beyond the addresses FCP knows (a reading
  // from there is the member's app refreshing through the tunnel).
  'delivery.country.detect': false,
  // Ask a freedom-family member where they connect from (docs/privacy.md): at
  // sign-up, before the first key, and when a key with no answer gets a mirror
  // (a mirror cannot see where its reader is). The answer is the same stored
  // choice as the account card's. Off: nothing is asked (the card stays).
  'delivery.country.ask': false,
  'delivery.country.stickyDays': 30,
  'delivery.country.refreshHours': 6,
  'delivery.country.ownExitRanges': [] as string[],
  // Delivery by country (docs/edges.md): order a freedom-family member's
  // addresses by their STORED country (choice or guess), edges proven there
  // first and blocked ones last. Off: the assignment ignores countries.
  'delivery.country.steer': false,
  // Latency over the whole path (docs/edges.md): a steered member's addresses
  // nearer ones first, by the path member -> address -> node (measured where
  // probes timed it, else from distance). With detection and steering on, a
  // guess may then be any real country, and another one replaces it only after
  // a day (lib/memberCountry.ts `wideGuesses`). Off: no bands, listed guesses only.
  'delivery.country.latency': false,
  // Exit location by country (lib/countryExits.ts, docs/edges.md): per listed
  // country, up to three location codes of the member catalog, in order. A new
  // freedom-family key of a member on Automatic whose OWN country choice has an
  // entry narrows softly to them (steering on); never a guess, never a move.
  'delivery.country.exits': [] as Array<{ country: string; locations: string[] }>,
  // Suggested modes by country (lib/countryModes.ts): per country, the mode
  // slugs the picker suggests, in order; the first one the member's backend
  // serves wins over the status-page matrix. Edited on Admin → Connection modes.
  'delivery.country.modes': [] as Array<{ country: string; modes: string[] }>,
  // The revocation watch (lib/revocationWatch.ts, docs/backends.md "Revoking a
  // key with an open Hysteria connection"): a Hysteria connection opened before
  // a key is disabled or deleted stays served until the node's core restarts.
  // On: revoked Hysteria keys are watched and a node is restarted when one keeps
  // moving bytes. Off (default): nothing is watched, deletes are immediate.
  ...REVOCATION_DEFAULTS,
} as const;

// `getAll` / `get` (public queries) were deleted in pass 2: dead code (the SPA
// has no Convex client; everything reads `resolved` via the HTTP layer), and
// this table also holds the ratelimit.* policy overrides — nothing here may be
// publicly callable on the raw Convex channel.

/**
 * Settings as a typed bag with defaults applied (replaces
 * AppSettingsService.getAll). Unknown/corrupt rows fall back to the default so
 * a bad row fails closed instead of breaking reads. Per-key INDEXED reads (the
 * keys are a small compile-time set) rather than a full-table collect — this
 * runs on hot paths (publicConfig, issuance) and the table also accumulates
 * the ratelimit/billing policy namespaces we must never load here anyway.
 */
export const resolved = internalQuery({
  args: {},
  handler: async (ctx): Promise<Record<string, unknown>> => {
    const map: Record<string, unknown> = { ...SETTINGS_DEFAULTS };
    await Promise.all(
      Object.keys(SETTINGS_DEFAULTS).map(async (key) => {
        const row = await ctx.db
          .query('appSettings')
          .withIndex('by_key', (q) => q.eq('key', key))
          .unique();
        if (!row) return;
        try {
          map[key] = JSON.parse(row.value);
        } catch {
          /* keep the default */
        }
      }),
    );
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
      const before =
        key === 'delivery.country.steer' ||
        key === 'delivery.country.latency' ||
        key === 'delivery.country.detect'
          ? (
              await ctx.db
                .query('appSettings')
                .withIndex('by_key', (q) => q.eq('key', key))
                .unique()
            )?.value
          : undefined;
      await upsertSettingRow(ctx, key, value, updatedByAdminId);
      if (key === 'delivery.country.ownExitRanges')
        await ctx.scheduler.runAfter(0, internal.ownExits.refresh, {});
      // Delivery by country turned on or off: what members receive changes.
      if (key === 'delivery.country.steer' && (before === 'true') !== (value === 'true'))
        await ctx.scheduler.runAfter(0, internal.edgeRender.steeringChanged, {
          on: value === 'true',
        });
      // Latency ordering turned on or off: the order members receive changes.
      if (key === 'delivery.country.latency' && (before === 'true') !== (value === 'true'))
        await ctx.scheduler.runAfter(0, internal.edgeRender.latencyChanged, {});
      // Wide guesses ended (one of their switches went off): guesses off the
      // list and pending countries go.
      if (
        (key === 'delivery.country.latency' ||
          key === 'delivery.country.steer' ||
          key === 'delivery.country.detect') &&
        before === 'true' &&
        value !== 'true'
      )
        await ctx.scheduler.runAfter(0, internal.memberCountry.cleanStoredCountries, {});
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
