/**
 * Edge templates: operator-editable provisioning parameters per provider (and
 * optionally per account). `params` is JSON validated by the provider's
 * template schema (convex/lib/relays/providers/templates.ts — SDK-free, so this
 * isolate module can validate directly). A provider always has at least one
 * template: `ensureDefaults` seeds the adapter defaults on first use.
 * `paramsHash` is a stable content hash (FNV-1a over canonical JSON) so a
 * qualified account can tell "the template I was qualified with" from a later
 * edit; it is a change detector, not a security primitive.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import {
  relayProviderIdValidator,
  RELAY_PROVIDER_IDS,
  type RelayProviderId,
} from './lib/relayProviderIds';
import { RELAY_TEMPLATES, validateTemplateParams } from './lib/relays/providers/templates';
import { canonicalJson } from './lib/relays/providers/template';

/** FNV-1a 64-bit as 16 hex chars (isolate-safe, no WebCrypto needed). */
export function fnv1a64Hex(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

export function templateHashOf(params: unknown): string {
  return fnv1a64Hex(canonicalJson(params));
}

export function mapTemplateAdmin(r: Doc<'relayEdgeTemplates'>) {
  let params: unknown = {};
  try {
    params = JSON.parse(r.params);
  } catch {
    params = {};
  }
  return {
    id: r._id as string,
    provider: r.provider,
    accountId: (r.accountId as string | undefined) ?? null,
    name: r.name,
    params,
    paramsHash: r.paramsHash,
    isDefault: r.isDefault,
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/;

export const list = internalQuery({
  args: { provider: v.optional(relayProviderIdValidator) },
  handler: async (ctx, { provider }) => {
    const rows = provider
      ? await ctx.db
          .query('relayEdgeTemplates')
          .withIndex('by_provider', (q) => q.eq('provider', provider))
          .collect()
      : await ctx.db.query('relayEdgeTemplates').collect();
    return rows
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name))
      .map(mapTemplateAdmin);
  },
});

export const get = internalQuery({
  args: { id: v.id('relayEdgeTemplates') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r ? mapTemplateAdmin(r) : null;
  },
});

/** The schema descriptors the CMS renders forms from (pure data). */
export const describeSchemas = internalQuery({
  args: {},
  handler: async () =>
    Object.fromEntries(
      RELAY_PROVIDER_IDS.map((id) => [
        id,
        { fields: RELAY_TEMPLATES[id].fields, defaults: RELAY_TEMPLATES[id].defaults },
      ]),
    ),
});

/**
 * Resolve the template to provision with: an explicit id, else the account's
 * default, else the provider's default row (seeded if missing). Returns the
 * parsed params + hash.
 */
export async function resolveTemplateFor(
  ctx: { db: import('./_generated/server').DatabaseReader },
  provider: RelayProviderId,
  explicitId: Doc<'relayEdgeTemplates'>['_id'] | null | undefined,
  accountDefaultId: Doc<'relayEdgeTemplates'>['_id'] | null | undefined,
): Promise<{
  id: Doc<'relayEdgeTemplates'>['_id'] | null;
  params: Record<string, unknown>;
  hash: string;
}> {
  const candidates = [explicitId, accountDefaultId].filter(
    (x): x is Doc<'relayEdgeTemplates'>['_id'] => !!x,
  );
  for (const id of candidates) {
    const row = await ctx.db.get(id);
    if (row && row.provider === provider) {
      const parsed = validateTemplateParams(provider, JSON.parse(row.params));
      if (parsed.ok) return { id: row._id, params: parsed.params, hash: row.paramsHash };
    }
  }
  const rows = await ctx.db
    .query('relayEdgeTemplates')
    .withIndex('by_provider', (q) => q.eq('provider', provider))
    .collect();
  const dflt = rows.find((r) => r.isDefault) ?? rows[0];
  if (dflt) {
    const parsed = validateTemplateParams(provider, JSON.parse(dflt.params));
    if (parsed.ok) return { id: dflt._id, params: parsed.params, hash: dflt.paramsHash };
  }
  const params = RELAY_TEMPLATES[provider].defaults;
  return { id: null, params, hash: templateHashOf(params) };
}

export const resolveForProvision = internalQuery({
  args: {
    provider: relayProviderIdValidator,
    templateId: v.optional(v.union(v.id('relayEdgeTemplates'), v.null())),
    accountDefaultId: v.optional(v.union(v.id('relayEdgeTemplates'), v.null())),
  },
  handler: (ctx, a) =>
    resolveTemplateFor(ctx, a.provider, a.templateId ?? null, a.accountDefaultId ?? null),
});

/** Seed one default template per provider that has none (idempotent). */
export const ensureDefaults = internalMutation({
  args: {},
  handler: async (ctx) => {
    let created = 0;
    for (const provider of RELAY_PROVIDER_IDS) {
      const existing = await ctx.db
        .query('relayEdgeTemplates')
        .withIndex('by_provider', (q) => q.eq('provider', provider))
        .first();
      if (existing) continue;
      const params = RELAY_TEMPLATES[provider].defaults;
      await ctx.db.insert('relayEdgeTemplates', {
        provider,
        name: 'Default',
        params: JSON.stringify(params),
        paramsHash: templateHashOf(params),
        isDefault: true,
        updatedAt: Date.now(),
      });
      created++;
    }
    return { created };
  },
});

export const create = internalMutation({
  args: {
    provider: relayProviderIdValidator,
    name: v.string(),
    params: v.any(),
    accountId: v.optional(v.union(v.id('relayProviderAccounts'), v.null())),
    isDefault: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    if (!NAME_RE.test(a.name))
      throw new ConvexError({ code: 'validation', message: 'invalid template name' });
    const parsed = validateTemplateParams(a.provider, a.params);
    if (!parsed.ok)
      throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
    if (a.accountId) {
      const acct = await ctx.db.get(a.accountId);
      if (!acct || acct.provider !== a.provider)
        throw new ConvexError({ code: 'validation', message: 'account/provider mismatch' });
    }
    const now = Date.now();
    if (a.isDefault) await clearDefault(ctx, a.provider);
    const id = await ctx.db.insert('relayEdgeTemplates', {
      provider: a.provider,
      accountId: a.accountId ?? undefined,
      name: a.name,
      params: JSON.stringify(parsed.params),
      paramsHash: templateHashOf(parsed.params),
      isDefault: a.isDefault ?? false,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.template.create',
      targetType: 'relay_edge_template',
      targetId: id,
      payload: { provider: a.provider, name: a.name },
    });
    return { id, paramsHash: templateHashOf(parsed.params) };
  },
});

async function clearDefault(
  ctx: { db: import('./_generated/server').DatabaseWriter },
  provider: RelayProviderId,
) {
  const rows = await ctx.db
    .query('relayEdgeTemplates')
    .withIndex('by_provider', (q) => q.eq('provider', provider))
    .collect();
  for (const r of rows) if (r.isDefault) await ctx.db.patch(r._id, { isDefault: false });
}

export const update = internalMutation({
  args: {
    id: v.id('relayEdgeTemplates'),
    name: v.optional(v.string()),
    params: v.optional(v.any()),
    isDefault: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Template not found' });
    const patch: Partial<Doc<'relayEdgeTemplates'>> = { updatedAt: Date.now() };
    if (a.name !== undefined) {
      if (!NAME_RE.test(a.name))
        throw new ConvexError({ code: 'validation', message: 'invalid template name' });
      patch.name = a.name;
    }
    let requalify: Doc<'relayProviderAccounts'>[] = [];
    if (a.params !== undefined) {
      const parsed = validateTemplateParams(row.provider, a.params);
      if (!parsed.ok)
        throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
      patch.params = JSON.stringify(parsed.params);
      patch.paramsHash = templateHashOf(parsed.params);
      if (patch.paramsHash !== row.paramsHash) {
        // The REALITY qualification was run with the OLD parameters: every
        // qualified account that was qualified with them, or that would provision
        // from this template next, must be re-qualified before automation uses it.
        const accounts = await ctx.db.query('relayProviderAccounts').collect();
        requalify = accounts.filter(
          (acct) =>
            acct.provider === row.provider &&
            acct.qualified &&
            (acct.defaultTemplateId === a.id || acct.qualifiedTemplateHash === row.paramsHash),
        );
      }
    }
    if (a.isDefault === true) {
      await clearDefault(ctx, row.provider);
      patch.isDefault = true;
    } else if (a.isDefault === false) {
      patch.isDefault = false;
    }
    await ctx.db.patch(a.id, patch);
    for (const acct of requalify) {
      await ctx.db.patch(acct._id, {
        qualified: false,
        qualifiedTemplateHash: undefined,
        updatedAt: Date.now(),
      });
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: a.actorAdminId ?? undefined,
        action: 'relay.provider_account.qualified',
        targetType: 'relay_provider_account',
        targetId: acct._id,
        payload: { name: acct.name, provider: acct.provider, qualified: false },
      });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.template.update',
      targetType: 'relay_edge_template',
      targetId: a.id,
      payload: { provider: row.provider, name: patch.name ?? row.name },
    });
    return {
      ok: true as const,
      paramsHash: patch.paramsHash ?? row.paramsHash,
      requalify: requalify.length,
    };
  },
});

export const remove = internalMutation({
  args: { id: v.id('relayEdgeTemplates'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    const siblings = await ctx.db
      .query('relayEdgeTemplates')
      .withIndex('by_provider', (q) => q.eq('provider', row.provider))
      .collect();
    if (siblings.length <= 1) {
      throw new ConvexError({
        code: 'conflict',
        message: 'A provider keeps at least one template',
      });
    }
    const referencing = await ctx.db.query('relayProviderAccounts').collect();
    for (const acct of referencing) {
      if (acct.defaultTemplateId === id)
        await ctx.db.patch(acct._id, { defaultTemplateId: undefined, updatedAt: Date.now() });
    }
    await ctx.db.delete(id);
    if (row.isDefault) {
      const next = siblings.find((s) => s._id !== id);
      if (next) await ctx.db.patch(next._id, { isDefault: true, updatedAt: Date.now() });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.template.delete',
      targetType: 'relay_edge_template',
      targetId: id,
      payload: { provider: row.provider, name: row.name },
    });
    return { ok: true as const };
  },
});

/** Pure validation for the CMS "Validate" button (no write). */
export const validate = internalQuery({
  args: { provider: relayProviderIdValidator, params: v.any() },
  handler: async (_ctx, { provider, params }) => {
    const parsed = validateTemplateParams(provider, params);
    return parsed.ok
      ? { ok: true as const, params: parsed.params, paramsHash: templateHashOf(parsed.params) }
      : { ok: false as const, issues: parsed.issues };
  },
});
