/**
 * L7 LOCATIONS migration (docs/edges.md § "Deploy notes"): a CDN account used
 * to be bound to ONE zone in its settings (Cloudflare `zoneId` / `zoneName`; a
 * Fastly account's `dnsAccountId` naming the DNS account whose zone it used,
 * plus its `tlsConfigurationId`). The zone is now its location's, so an account
 * can front in every zone its token reaches. This moves each account's zone
 * onto its existing `anycast` location and strips the keys from its settings
 * (the shared wildcard certificate a Fastly account recorded moves with its
 * zone).
 *
 * ONE transaction, idempotent (an account without legacy keys is skipped), run
 * by `seedCutover` on every deploy. Location ids never change, so provider
 * sets, open setup runs, approvals, trust, cooling and spares are untouched.
 * Edges are not touched either: each L7 edge's provisionIntent already froze
 * its zone, DNS account and TLS configuration, and every call about it reads
 * the intent. Until a deploy has run it, `lib/edges/l7Place.ts l7PlaceOf` reads the
 * legacy keys as the fallback; the follow-up cleanup drops both.
 *
 * `unmigrate` puts the legacy keys back for a rollback past this deploy, for
 * every account that still has a single location (one with a second zone has
 * no single-zone shape to go back to and is reported), with the zone's facts
 * and shared wildcard back on the account, and drops what an older schema
 * refuses (the location's check fields, the catalog). Run it before deploying
 * the older build; a rollback past provider options then runs
 * `edgeProviderAccounts.purgeOptionsForRollback`.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { legacySettingsOf, EDGE_LEGACY_SETTINGS } from './lib/edges/accountSettings';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import { ANYCAST_PLACE, placementHashOf } from './lib/edges/locations';
import { parseIntent } from './lib/edges/intent';
import { liveEdgesOfLocation, locationsOfAccount } from './edgeLocations';

type Account = Doc<'edgeProviderAccounts'>;
type Location = Doc<'edgeLocations'>;

interface LegacyPlace {
  zoneId?: string;
  zoneName?: string;
  dnsAccountId?: string;
  tlsConfigurationId?: string;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** The L7 accounts of the deployment (the table is operator-scale). */
async function l7Accounts(ctx: { db: DatabaseReader }): Promise<Account[]> {
  return (await ctx.db.query('edgeProviderAccounts').collect()).filter(
    (a) => edgeLayerOf(a.provider) === 'l7',
  );
}

function hasLegacy(a: Account): boolean {
  return (
    Object.keys(legacySettingsOf(a.provider, a.settings as Record<string, unknown>)).length > 0
  );
}

/** Where a location's placement already names a zone (migrated, or created since). */
function placed(l: Location): boolean {
  return !!str((l.placement as { zoneId?: unknown }).zoneId);
}

/**
 * The legacy place of an account, read from the snapshot taken before any row
 * was patched (a Fastly account's zone lives on its DNS account, which this
 * same transaction migrates).
 */
function legacyPlaceOf(a: Account, snapshot: Map<string, Account>): LegacyPlace {
  const s = a.settings as Record<string, unknown>;
  if (a.provider === 'cloudflare') return { zoneId: str(s.zoneId), zoneName: str(s.zoneName) };
  const dnsAccountId = str(s.dnsAccountId);
  const dns = dnsAccountId ? snapshot.get(dnsAccountId) : undefined;
  const ds = (dns?.settings ?? {}) as Record<string, unknown>;
  return {
    dnsAccountId,
    zoneId: str(ds.zoneId),
    zoneName: str(ds.zoneName),
    tlsConfigurationId: str(s.tlsConfigurationId),
  };
}

/** A DNS account migrated earlier keeps its zone on its location: read it there. */
async function zoneOfMigratedDns(
  ctx: { db: DatabaseReader },
  dnsAccountId: string,
): Promise<{ zoneId?: string; zoneName?: string }> {
  const id = ctx.db.normalizeId('edgeProviderAccounts', dnsAccountId);
  if (!id) return {};
  const rows = (await locationsOfAccount(ctx.db, id)).filter(placed);
  if (rows.length !== 1) return {};
  const p = rows[0].placement as { zoneId?: string; zoneName?: string };
  return { zoneId: p.zoneId, zoneName: p.zoneName };
}

export const migrate = internalMutation({
  args: {},
  handler: async (ctx) => {
    const accounts = await l7Accounts(ctx);
    const snapshot = new Map(accounts.map((a) => [a._id as string, a]));
    let moved = 0;
    let created = 0;
    const incomplete: string[] = [];
    let edgesDiffer = 0;
    const now = Date.now();
    for (const a of accounts) {
      if (!hasLegacy(a)) continue;
      const place = legacyPlaceOf(a, snapshot);
      if (a.provider === 'fastly' && place.dnsAccountId && !place.zoneId)
        Object.assign(place, await zoneOfMigratedDns(ctx, place.dnsAccountId));
      if (!place.zoneId || !place.zoneName || (a.provider === 'fastly' && !place.dnsAccountId)) {
        // Nothing complete to move: the keys stay until an operator gives the
        // account a location of its own (the status read lists it).
        incomplete.push(a.name);
        continue;
      }
      const placement = {
        type: a.provider,
        zoneId: place.zoneId,
        zoneName: place.zoneName,
        ...(a.provider === 'fastly'
          ? {
              dnsAccountId: place.dnsAccountId,
              ...(place.tlsConfigurationId ? { tlsConfigurationId: place.tlsConfigurationId } : {}),
            }
          : {}),
      };
      const placementHash = placementHashOf(placement);
      const rows = await locationsOfAccount(ctx.db, a._id);
      const target =
        rows.find((l) => l.placementHash === placementHash) ??
        rows.find((l) => l.placeKey === ANYCAST_PLACE && !placed(l));
      // The account's observed zone facts belong to the zone now.
      const observed =
        a.provider === 'cloudflare' && a.observedSettings
          ? { observed: a.observedSettings, observedAt: a.observedAt ?? now }
          : {};
      let locationId: Id<'edgeLocations'>;
      if (target) {
        locationId = target._id;
        if (target.placementHash !== placementHash) {
          await ctx.db.patch(target._id, {
            placement: placement as never,
            placementHash,
            ...(target.label === 'Anycast' ? { label: place.zoneName } : {}),
            ...observed,
            updatedAt: now,
          });
          moved++;
        }
      } else {
        locationId = await ctx.db.insert('edgeLocations', {
          accountId: a._id,
          provider: a.provider,
          placeKey: ANYCAST_PLACE,
          placement: placement as never,
          placementHash,
          label: place.zoneName,
          enabled: true,
          qualified: false,
          ...observed,
          createdAt: now,
          updatedAt: now,
        });
        if (!a.defaultLocationId) await ctx.db.patch(a._id, { defaultLocationId: locationId });
        created++;
      }
      // The shared wildcard certificate the account recorded is its zone's.
      const shared = a.sharedCertificate;
      if (shared && shared.name === `*.${place.zoneName}`) {
        const loc = await ctx.db.get(locationId);
        if (loc && !loc.sharedCertificate)
          await ctx.db.patch(locationId, { sharedCertificate: shared });
      }
      const stripped = Object.fromEntries(
        Object.entries(a.settings as Record<string, unknown>).filter(
          ([k]) => !EDGE_LEGACY_SETTINGS[a.provider].includes(k),
        ),
      );
      await ctx.db.patch(a._id, {
        settings: stripped as never,
        ...(shared ? { sharedCertificate: undefined } : {}),
        updatedAt: now,
      });
      // For the report only: a live edge whose frozen zone or TLS
      // configuration differs from the location's (an account edited while it
      // had edges, where nothing locked that) keeps its own intent.
      const loc = await ctx.db.get(locationId);
      for (const e of loc ? await liveEdgesOfLocation(ctx.db, loc) : []) {
        const intent = parseIntent(e.provisionIntent);
        if (
          intent &&
          (intent.zoneId !== place.zoneId ||
            (intent.tlsConfigurationId ?? null) !== (place.tlsConfigurationId ?? null))
        )
          edgesDiffer++;
      }
    }
    if (moved + created + incomplete.length > 0)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.locations.l7_migrated',
        targetType: 'app_state',
        payload: { moved, created, incomplete: incomplete.length, edgesDiffer },
      });
    return { moved, created, incomplete, edgesDiffer };
  },
});

/**
 * Read-only readiness of the migration and of its cleanup: accounts still
 * carrying legacy keys (the cleanup needs zero), L7 locations naming no zone,
 * and whether anything is in flight on an L7 account (a quiet moment is the
 * time to deploy).
 */
export const status = internalQuery({
  args: {},
  handler: async (ctx) => {
    const accounts = await l7Accounts(ctx);
    let legacyAccounts = 0;
    let locationsWithoutZone = 0;
    for (const a of accounts) {
      if (hasLegacy(a)) legacyAccounts++;
      for (const l of await locationsOfAccount(ctx.db, a._id))
        if (!placed(l)) locationsWithoutZone++;
    }
    const l7Ids = new Set(accounts.map((a) => a._id as string));
    let openRuns = 0;
    for (const state of ['running', 'waiting'] as const) {
      const runs = await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_state', (q) => q.eq('state', state as never))
        .collect();
      openRuns += runs.filter((r) => (r.picks ?? []).some((p) => l7Ids.has(p.accountId))).length;
    }
    return { l7Accounts: accounts.length, legacyAccounts, locationsWithoutZone, openRuns };
  },
});

export const unmigrate = internalMutation({
  args: { confirm: v.literal('restore-single-zone-settings') },
  handler: async (ctx) => {
    let restored = 0;
    const skipped: string[] = [];
    const now = Date.now();
    for (const a of await l7Accounts(ctx)) {
      const rows = await locationsOfAccount(ctx.db, a._id);
      if (rows.length === 0) continue;
      if (rows.length > 1) {
        skipped.push(a.name);
        continue;
      }
      const l = rows[0];
      const accountPatch: Partial<Account> = {};
      const locationPatch: Partial<Location> = {
        observed: undefined,
        observedAt: undefined,
        checkError: undefined,
        checkErrorDetail: undefined,
        sharedCertificate: undefined,
      };
      if (!hasLegacy(a) && placed(l)) {
        const p = l.placement as Record<string, unknown>;
        const legacy =
          a.provider === 'cloudflare'
            ? { zoneId: p.zoneId, zoneName: p.zoneName }
            : {
                dnsAccountId: p.dnsAccountId,
                ...(p.tlsConfigurationId ? { tlsConfigurationId: p.tlsConfigurationId } : {}),
              };
        accountPatch.settings = { ...(a.settings as Record<string, unknown>), ...legacy } as never;
        const empty = { type: a.provider };
        locationPatch.placement = empty as never;
        locationPatch.placementHash = placementHashOf(empty);
        restored++;
      }
      // What only this build keeps on the zone goes back where an older build
      // reads it (the account: the zone facts and CAA verdict its credential
      // test recorded, the shared wildcard), and leaves the location, whose
      // older schema has no such fields.
      if (l.observed) {
        accountPatch.observedSettings = l.observed;
        accountPatch.observedAt = l.observedAt ?? now;
      }
      if (l.sharedCertificate) accountPatch.sharedCertificate = l.sharedCertificate;
      if (Object.keys(accountPatch).length > 0)
        await ctx.db.patch(a._id, { ...accountPatch, updatedAt: now });
      await ctx.db.patch(l._id, { ...locationPatch, updatedAt: now });
    }
    // The catalog is this build's alone (an older schema has no such table).
    for (const row of await ctx.db.query('edgeProviderCatalog').collect())
      await ctx.db.delete(row._id);
    return { restored, skipped };
  },
});
