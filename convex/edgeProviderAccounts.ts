/**
 * Relay provider ACCOUNTS: one cloud account (+ region/zone/network settings)
 * FCP may provision edges in. A sibling of mirrorProviders/backendServers: a
 * variable-length pool of secret-bearing rows.
 *
 * Secret invariant: `credentials` is stored on create/edit, read back ONLY by
 * the "use node" provider actions (`getWithSecret`), and surfaced to the admin
 * as per-field set/not-set booleans (`maskCredentials`). Blank fields on an
 * edit keep the stored value. Nothing here is logged; audits carry name +
 * provider only.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { edgeProviderIdValidator, type EdgeProviderId } from './lib/edgeProviderIds';
import {
  buildCredentials,
  maskCredentials,
  validateSettings,
  type EdgeCredentials,
  type EdgeSettings,
} from './lib/edges/accountSettings';

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

function checkName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new ConvexError({
      code: 'validation',
      message: 'name must be 2-63 chars of lowercase letters, digits and dashes',
    });
  }
}

/** Admin-safe view of one account. */
export function mapAccountAdmin(r: Doc<'edgeProviderAccounts'>) {
  const { type: _t, ...settings } = r.settings as { type: string } & Record<string, unknown>;
  return {
    id: r._id as string,
    provider: r.provider,
    name: r.name,
    settings,
    credentialsSet: maskCredentials(r.credentials as Record<string, unknown>),
    defaultTemplateId: (r.defaultTemplateId as string | undefined) ?? null,
    enabled: r.enabled,
    qualified: r.qualified,
    qualifiedTemplateHash: r.qualifiedTemplateHash ?? null,
    priority: r.priority,
    dailyAllocationBudget: r.dailyAllocationBudget,
    allocationsToday: r.allocationsDayKey === dayKey() ? r.allocationsToday : 0,
    maxLiveEdges: r.maxLiveEdges,
    lastTestOkAt: r.lastTestOkAt ? new Date(r.lastTestOkAt).toISOString() : null,
    lastTestError: r.lastTestError ?? null,
    inventoryAt: r.inventoryAt ? new Date(r.inventoryAt).toISOString() : null,
    createdAt: new Date(r._creationTime).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export function dayKey(now = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** The full config the provider actions need (credentials + settings merged). */
export interface RelayAccountWithSecret {
  id: Id<'edgeProviderAccounts'>;
  provider: EdgeProviderId;
  name: string;
  credentials: EdgeCredentials;
  settings: EdgeSettings;
  enabled: boolean;
  qualified: boolean;
  defaultTemplateId: Id<'edgeTemplates'> | null;
}

function toWithSecret(r: Doc<'edgeProviderAccounts'>): RelayAccountWithSecret {
  return {
    id: r._id,
    provider: r.provider,
    name: r.name,
    credentials: r.credentials as EdgeCredentials,
    settings: r.settings as EdgeSettings,
    enabled: r.enabled,
    qualified: r.qualified,
    defaultTemplateId: r.defaultTemplateId ?? null,
  };
}

// --- reads -------------------------------------------------------------------------

export const getWithSecret = internalQuery({
  args: { id: v.id('edgeProviderAccounts') },
  handler: async (ctx, { id }): Promise<RelayAccountWithSecret | null> => {
    const r = await ctx.db.get(id);
    return r ? toWithSecret(r) : null;
  },
});

/** Every enabled account WITHOUT secrets, for selection (small table). */
export const listEnabledForSelection = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('edgeProviderAccounts').collect();
    return rows
      .filter((r) => r.enabled)
      .map((r) => ({
        id: r._id,
        provider: r.provider,
        name: r.name,
        qualified: r.qualified,
        priority: r.priority,
        dailyAllocationBudget: r.dailyAllocationBudget,
        allocationsToday: r.allocationsDayKey === dayKey() ? r.allocationsToday : 0,
        maxLiveEdges: r.maxLiveEdges,
        defaultTemplateId: r.defaultTemplateId ?? null,
      }));
  },
});

export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('edgeProviderAccounts').collect();
    return rows
      .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name))
      .map(mapAccountAdmin);
  },
});

export const getForAdmin = internalQuery({
  args: { id: v.id('edgeProviderAccounts') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r ? mapAccountAdmin(r) : null;
  },
});

/** The stored inventory snapshot, decoded for the admin contract (addresses are public client-facing data). */
export const getInventory = internalQuery({
  args: { id: v.id('edgeProviderAccounts') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    let inventory: { loadBalancers?: Array<Record<string, unknown>> } | null = null;
    if (r.inventorySnapshot) {
      try {
        inventory = JSON.parse(r.inventorySnapshot);
      } catch {
        inventory = null;
      }
    }
    if (inventory && Array.isArray(inventory.loadBalancers)) {
      // `unowned` = no live edge ledger references the LB: what the relay import
      // picker offers first (an owned one is already an edge).
      const owned = new Set<string>();
      for (const e of await ctx.db
        .query('edges')
        .withIndex('by_account_status', (q) => q.eq('accountId', id))
        .collect()) {
        if (e.status === 'destroyed') continue;
        for (const res of e.resources) owned.add(res.resourceId);
      }
      inventory = {
        ...inventory,
        loadBalancers: inventory.loadBalancers.map((lb) => ({
          ...lb,
          unowned: !owned.has(String(lb.id)),
        })),
      };
    }
    return {
      inventory,
      inventoryAt: r.inventoryAt ? new Date(r.inventoryAt).toISOString() : null,
    };
  },
});

// --- writes ------------------------------------------------------------------------

const upsertArgs = {
  provider: edgeProviderIdValidator,
  name: v.string(),
  settings: v.any(),
  credentials: v.optional(v.any()),
  enabled: v.optional(v.boolean()),
  priority: v.optional(v.number()),
  dailyAllocationBudget: v.optional(v.number()),
  maxLiveEdges: v.optional(v.number()),
  defaultTemplateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
  actorAdminId: v.optional(v.id('adminUsers')),
};

function checkLimits(a: {
  dailyAllocationBudget?: number;
  maxLiveEdges?: number;
  priority?: number;
}) {
  if (
    a.dailyAllocationBudget !== undefined &&
    (a.dailyAllocationBudget < 0 || a.dailyAllocationBudget > 1000)
  ) {
    throw new ConvexError({ code: 'validation', message: 'dailyAllocationBudget must be 0..1000' });
  }
  if (a.maxLiveEdges !== undefined && (a.maxLiveEdges < 1 || a.maxLiveEdges > 200)) {
    throw new ConvexError({ code: 'validation', message: 'maxLiveEdges must be 1..200' });
  }
  if (a.priority !== undefined && !Number.isFinite(a.priority)) {
    throw new ConvexError({ code: 'validation', message: 'priority must be a number' });
  }
}

export const create = internalMutation({
  args: upsertArgs,
  handler: async (ctx, a) => {
    checkName(a.name);
    checkLimits(a);
    const dup = await ctx.db
      .query('edgeProviderAccounts')
      .withIndex('by_name', (q) => q.eq('name', a.name))
      .unique();
    if (dup)
      throw new ConvexError({ code: 'conflict', message: 'An account with this name exists' });
    const settings = validateSettings(a.provider, a.settings);
    if (!settings.ok)
      throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
    const creds = buildCredentials(
      a.provider,
      a.credentials as Record<string, unknown> | undefined,
    );
    if (!creds.ok) {
      throw new ConvexError({
        code: 'validation',
        message: `missing credentials: ${creds.missing.join(', ')}`,
      });
    }
    const now = Date.now();
    const id = await ctx.db.insert('edgeProviderAccounts', {
      provider: a.provider,
      name: a.name,
      credentials: creds.credentials as never,
      settings: settings.settings as never,
      defaultTemplateId: a.defaultTemplateId ?? undefined,
      enabled: a.enabled ?? true,
      qualified: false,
      priority: a.priority ?? 0,
      dailyAllocationBudget: a.dailyAllocationBudget ?? 10,
      allocationsToday: 0,
      maxLiveEdges: a.maxLiveEdges ?? 6,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.provider_account.create',
      targetType: 'edge_provider_account',
      targetId: id,
      payload: { name: a.name, provider: a.provider },
    });
    return { id };
  },
});

export const update = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    settings: v.optional(v.any()),
    credentials: v.optional(v.any()),
    enabled: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    dailyAllocationBudget: v.optional(v.number()),
    maxLiveEdges: v.optional(v.number()),
    defaultTemplateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    checkLimits(a);
    const patch: Partial<Doc<'edgeProviderAccounts'>> = { updatedAt: Date.now() };
    let credentialsChanged = false;
    let settingsChanged = false;
    if (a.settings !== undefined) {
      const settings = validateSettings(row.provider, a.settings);
      if (!settings.ok)
        throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
      settingsChanged = JSON.stringify(settings.settings) !== JSON.stringify(row.settings);
      if (settingsChanged) {
        // Edges store only resource ids; the project/region/zone/network that
        // locate them live here and are reloaded by every describe/destroy. A
        // change while edges exist would make their resources invisible to
        // reconciliation and undeletable (yet still live and billable).
        const live = (
          await ctx.db
            .query('edges')
            .withIndex('by_account_status', (q) => q.eq('accountId', a.id))
            .collect()
        ).filter((e) => e.status !== 'destroyed');
        if (live.length > 0)
          throw new ConvexError({
            code: 'conflict',
            message: `${live.length} edge(s) still reference this account; destroy them before changing its settings`,
          });
      }
      patch.settings = settings.settings as never;
    }
    if (a.credentials !== undefined) {
      const creds = buildCredentials(
        row.provider,
        a.credentials as Record<string, unknown>,
        row.credentials as Record<string, unknown>,
      );
      if (!creds.ok) {
        throw new ConvexError({
          code: 'validation',
          message: `missing credentials: ${creds.missing.join(', ')}`,
        });
      }
      const before = JSON.stringify(row.credentials);
      patch.credentials = creds.credentials as never;
      credentialsChanged = JSON.stringify(creds.credentials) !== before;
    }
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.priority !== undefined) patch.priority = a.priority;
    if (a.dailyAllocationBudget !== undefined)
      patch.dailyAllocationBudget = a.dailyAllocationBudget;
    if (a.maxLiveEdges !== undefined) patch.maxLiveEdges = a.maxLiveEdges;
    let templateChanged = false;
    if (a.defaultTemplateId !== undefined) {
      patch.defaultTemplateId = a.defaultTemplateId ?? undefined;
      templateChanged = (a.defaultTemplateId ?? undefined) !== row.defaultTemplateId;
    }
    // New credentials or settings invalidate the qualification (a different
    // account/network may not carry the protocol the same way); so does a
    // different effective template — its parameters were never qualified.
    if (credentialsChanged || settingsChanged || templateChanged) {
      patch.qualified = false;
      patch.qualifiedTemplateHash = undefined;
    }
    await ctx.db.patch(a.id, patch);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.provider_account.update',
      targetType: 'edge_provider_account',
      targetId: a.id,
      payload: { name: row.name, provider: row.provider },
    });
    return { ok: true as const };
  },
});

export const remove = internalMutation({
  args: { id: v.id('edgeProviderAccounts'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    // Refuse while any edge still references the account (its resources would
    // become undeletable); the caller destroys edges first.
    const live = await ctx.db
      .query('edges')
      .withIndex('by_account_status', (q) => q.eq('accountId', id))
      .filter((q) => q.neq(q.field('status'), 'destroyed'))
      .first();
    if (live) {
      throw new ConvexError({ code: 'conflict', message: 'Edges still reference this account' });
    }
    await ctx.db.delete(id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.provider_account.delete',
      targetType: 'edge_provider_account',
      targetId: id,
      payload: { name: row.name, provider: row.provider },
    });
    return { ok: true as const };
  },
});

export const setQualified = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    qualified: v.boolean(),
    templateHash: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, qualified, templateHash, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    await ctx.db.patch(id, {
      qualified,
      qualifiedTemplateHash: qualified ? templateHash : undefined,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.provider_account.qualified',
      targetType: 'edge_provider_account',
      targetId: id,
      payload: { name: row.name, provider: row.provider, qualified },
    });
    return { ok: true as const };
  },
});

/** Stamp a credential test outcome (code only, never a body). */
export const recordTest = internalMutation({
  args: { id: v.id('edgeProviderAccounts'), ok: v.boolean(), code: v.optional(v.string()) },
  handler: async (ctx, { id, ok, code }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    await ctx.db.patch(id, {
      ...(ok
        ? { lastTestOkAt: Date.now(), lastTestError: undefined }
        : { lastTestError: (code ?? 'error').slice(0, 64) }),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Store the latest provider inventory pull (admin-only JSON). */
export const recordInventory = internalMutation({
  args: { id: v.id('edgeProviderAccounts'), inventory: v.string() },
  handler: async (ctx, { id, inventory }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    await ctx.db.patch(id, {
      inventorySnapshot: inventory.slice(0, 200_000),
      inventoryAt: Date.now(),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * Atomically reserve one allocation against the account's daily budget.
 * Returns false (nothing changed) when the budget is exhausted. Called inside
 * the edge-insert mutation so a reservation and its edge row commit together.
 */
export async function reserveAllocation(
  ctx: {
    db: {
      get: (id: Id<'edgeProviderAccounts'>) => Promise<Doc<'edgeProviderAccounts'> | null>;
      patch: (
        id: Id<'edgeProviderAccounts'>,
        p: Partial<Doc<'edgeProviderAccounts'>>,
      ) => Promise<void>;
    };
  },
  id: Id<'edgeProviderAccounts'>,
): Promise<boolean> {
  const row = await ctx.db.get(id);
  if (!row) return false;
  const today = dayKey();
  const used = row.allocationsDayKey === today ? row.allocationsToday : 0;
  if (row.dailyAllocationBudget > 0 && used >= row.dailyAllocationBudget) return false;
  await ctx.db.patch(id, {
    allocationsDayKey: today,
    allocationsToday: used + 1,
    updatedAt: Date.now(),
  });
  return true;
}
