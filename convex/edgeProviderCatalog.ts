/**
 * What one provider account's credentials REACH, as last listed
 * (docs/edges.md § "Provider accounts and locations"): the DNS zones, regions,
 * projects or TLS configurations the location pickers offer when a node is
 * protected, a spare is added or an address replaced. An account is the whole
 * provider account; this is its menu.
 *
 * A hint, never an authority: creating a location asks the provider again
 * (`edgeProviderOps.createLocation`), so a stale entry can never create a
 * place the key cannot use. Refreshed by `edgeProviderOps.refreshCatalog`
 * after a passing credential test or rotation, on an admin's Refresh, and when
 * a picker finds it old. A failed listing keeps the previous items and records
 * why. Rows are operator-scale (one per account and kind).
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { CATALOG_STALE_MS, type CatalogKind } from './lib/edges/catalog';
import { pickableByRegion } from './lib/edges/placementDefaults';

/** Most entries kept per kind (a Cloudflare listing stops at 1,000 zones). */
const MAX_ITEMS = 1000;

export interface CatalogItem {
  id: string;
  label: string;
  facts?: Record<string, string>;
}

export interface CatalogEntry {
  items: CatalogItem[];
  truncated: boolean;
  refreshedAt: number | null;
  error: string | null;
  errorDetail: string | null;
}

function parseItems(json: string): CatalogItem[] {
  try {
    const raw = JSON.parse(json) as unknown;
    if (!Array.isArray(raw)) return [];
    return raw.flatMap((r) => {
      const o = r as Record<string, unknown>;
      if (typeof o?.id !== 'string' || typeof o.label !== 'string') return [];
      const facts =
        o.facts && typeof o.facts === 'object' && !Array.isArray(o.facts)
          ? Object.fromEntries(
              Object.entries(o.facts as Record<string, unknown>).filter(
                ([, v]) => typeof v === 'string',
              ),
            )
          : undefined;
      return [
        {
          id: o.id,
          label: o.label,
          ...(facts && Object.keys(facts).length > 0
            ? { facts: facts as Record<string, string> }
            : {}),
        },
      ];
    });
  } catch {
    return [];
  }
}

function entryOf(row: Doc<'edgeProviderCatalog'> | null): CatalogEntry {
  return {
    items: row ? parseItems(row.items) : [],
    truncated: row?.truncated === true,
    refreshedAt: row?.refreshedAt || null,
    error: row?.error ?? null,
    errorDetail: row?.errorDetail ?? null,
  };
}

async function rowOf(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
  kind: CatalogKind,
): Promise<Doc<'edgeProviderCatalog'> | null> {
  return db
    .query('edgeProviderCatalog')
    .withIndex('by_account_kind', (q) => q.eq('accountId', accountId).eq('kind', kind))
    .unique();
}

/** One kind of an account's catalog (empty when never listed). */
export async function catalogOf(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
  kind: CatalogKind,
): Promise<CatalogEntry> {
  return entryOf(await rowOf(db, accountId, kind));
}

/** A listed zone of an account by id (null when the catalog does not list it). */
export async function listedZone(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
  zoneId: string,
): Promise<CatalogItem | null> {
  return (await catalogOf(db, accountId, 'zones')).items.find((z) => z.id === zoneId) ?? null;
}

/**
 * The regions a load balancer account's key reaches that are not one of its
 * locations yet (`placeKeys`: every location it has, switched on or not): what
 * the protect sheet and a node's "Add a location" offer, the location being
 * created when one is picked. Empty for a CDN account (its place is a zone,
 * added in the location form) and for a catalog never listed.
 */
export async function regionOffersOf(
  db: DatabaseReader,
  account: Pick<Doc<'edgeProviderAccounts'>, '_id' | 'provider'>,
  placeKeys: readonly string[],
): Promise<Array<{ id: string; label: string }>> {
  if (!pickableByRegion(account.provider)) return [];
  const taken = new Set(placeKeys);
  return (await catalogOf(db, account._id, 'regions')).items
    .filter((r) => !taken.has(r.id))
    .map((r) => ({ id: r.id, label: r.label }));
}

/** When the account's catalog was last refreshed (any kind), or null. */
export async function catalogRefreshedAt(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<number | null> {
  const rows = await db
    .query('edgeProviderCatalog')
    .withIndex('by_account_kind', (q) => q.eq('accountId', accountId))
    .collect();
  const at = rows.map((r) => r.refreshedAt).filter((n) => n > 0);
  return at.length > 0 ? Math.max(...at) : null;
}

/** Every kind of an account's catalog that was ever listed (the admin read). */
export const view = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }) => {
    const rows = await ctx.db
      .query('edgeProviderCatalog')
      .withIndex('by_account_kind', (q) => q.eq('accountId', accountId))
      .collect();
    const out: Partial<Record<CatalogKind, CatalogEntry>> = {};
    for (const r of rows) out[r.kind] = entryOf(r);
    return { accountId, kinds: out, staleAfterMs: CATALOG_STALE_MS };
  },
});

/** One listed zone of an account (a location form that sent only the zone id). */
export const zoneOf = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts'), zoneId: v.string() },
  handler: async (ctx, { accountId, zoneId }) => listedZone(ctx.db, accountId, zoneId),
});

/** When the catalog was last refreshed (the refresh action's floor check). */
export const refreshedAt = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }) => catalogRefreshedAt(ctx.db, accountId),
});

const catalogItem = v.object({
  id: v.string(),
  label: v.string(),
  facts: v.optional(v.record(v.string(), v.string())),
});

/**
 * Store one listing: each kind it answered replaces that kind's items; each
 * kind it failed keeps its items and records the code (and the provider's
 * redacted answer). Kinds it did not mention are left alone.
 */
export const record = internalMutation({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    lists: v.array(
      v.object({
        kind: v.union(
          v.literal('zones'),
          v.literal('regions'),
          v.literal('projects'),
          v.literal('tlsConfigurations'),
        ),
        items: v.array(catalogItem),
        truncated: v.optional(v.boolean()),
      }),
    ),
    errors: v.array(
      v.object({
        kind: v.union(
          v.literal('zones'),
          v.literal('regions'),
          v.literal('projects'),
          v.literal('tlsConfigurations'),
        ),
        code: v.string(),
        detail: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, a) => {
    if (!(await ctx.db.get(a.accountId))) return null;
    const now = Date.now();
    for (const l of a.lists) {
      const items = l.items.slice(0, MAX_ITEMS).map((i) => ({
        id: i.id.slice(0, 128),
        label: i.label.replace(/\s+/g, ' ').trim().slice(0, 253),
        ...(i.facts ? { facts: i.facts } : {}),
      }));
      const truncated = l.truncated === true || l.items.length > MAX_ITEMS;
      const row = await rowOf(ctx.db, a.accountId, l.kind);
      const doc = {
        items: JSON.stringify(items),
        truncated: truncated || undefined,
        refreshedAt: now,
        error: undefined,
        errorDetail: undefined,
        errorAt: undefined,
      };
      if (row) await ctx.db.patch(row._id, doc);
      else
        await ctx.db.insert('edgeProviderCatalog', {
          accountId: a.accountId,
          kind: l.kind,
          ...doc,
        });
    }
    for (const e of a.errors) {
      const row = await rowOf(ctx.db, a.accountId, e.kind);
      const failed = {
        error: e.code.slice(0, 64),
        errorDetail: e.detail ? e.detail.slice(0, 700) : undefined,
        errorAt: now,
      };
      if (row) await ctx.db.patch(row._id, failed);
      else
        await ctx.db.insert('edgeProviderCatalog', {
          accountId: a.accountId,
          kind: e.kind,
          items: '[]',
          refreshedAt: 0,
          ...failed,
        });
    }
    return null;
  },
});

/** An account's catalog goes with it (the account delete calls this). */
export async function deleteCatalogOf(
  ctx: { db: import('./_generated/server').MutationCtx['db'] },
  accountId: Id<'edgeProviderAccounts'>,
): Promise<void> {
  const rows = await ctx.db
    .query('edgeProviderCatalog')
    .withIndex('by_account_kind', (q) => q.eq('accountId', accountId))
    .collect();
  for (const r of rows) await ctx.db.delete(r._id);
}
