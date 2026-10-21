/**
 * Edge templates: operator-editable provisioning parameters per provider (and
 * optionally per account). `params` is JSON validated by the provider's
 * template schema (convex/lib/edges/providers/templates.ts — SDK-free, so this
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
  edgeProviderIdValidator,
  EDGE_PROVIDER_IDS,
  type EdgeProviderId,
} from './lib/edgeProviderIds';
import {
  EDGE_TEMPLATES,
  checkBuiltParams,
  optionFieldsOf,
  validatePickOptions,
  validateTemplateParams,
  validateTemplateWrite,
} from './lib/edges/providers/templates';
import { accountOptionDefaultsOf, certificateValuesFor } from './lib/edges/choices';
import {
  builtTemplateHash,
  deepMerge,
  splitChoices,
  type Values,
} from './lib/edges/providers/options';
import { canonicalJson } from './lib/edges/providers/template';
import { assertAdmission } from './lib/edges/maintenance';
import { parseRegionalParams, withRegionalOverlay } from './lib/edges/locations';

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

export function mapTemplateAdmin(r: Doc<'edgeTemplates'>) {
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
  args: { provider: v.optional(edgeProviderIdValidator) },
  handler: async (ctx, { provider }) => {
    const rows = provider
      ? await ctx.db
          .query('edgeTemplates')
          .withIndex('by_provider', (q) => q.eq('provider', provider))
          .collect()
      : await ctx.db.query('edgeTemplates').collect();
    return rows
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.name.localeCompare(b.name))
      .map(mapTemplateAdmin);
  },
});

/** The schema descriptors the CMS renders forms from (pure data). */
export const describeSchemas = internalQuery({
  args: {},
  handler: async () =>
    Object.fromEntries(
      EDGE_PROVIDER_IDS.map((id) => [
        id,
        {
          // A hidden field is kept only so stored templates parse as before.
          fields: EDGE_TEMPLATES[id].fields.filter((f) => !f.hidden),
          defaults: EDGE_TEMPLATES[id].defaults,
        },
      ]),
    ),
});

/** A template is usable by an account when unscoped or scoped to THAT account. */
function visibleTo(
  row: Pick<Doc<'edgeTemplates'>, 'accountId'>,
  accountId: Doc<'edgeProviderAccounts'>['_id'] | null | undefined,
): boolean {
  return !row.accountId || (!!accountId && row.accountId === accountId);
}

/** What a location adds to the template choice: its own default and its regional values. */
export interface TemplateLocation {
  defaultTemplateId?: Doc<'edgeTemplates'>['_id'] | null;
  regionalParams?: string | null;
}

/**
 * Resolve the template to provision with, for ONE account (and one of its
 * locations): an explicit id, else the location's default, else the
 * account's default, else the account's own scoped default, else the
 * provider-wide (unscoped) default, else the first unscoped row, else the
 * compiled defaults. A template scoped to ANOTHER account is never used — its
 * `isDefault` flag is that account's default, not the provider's. The
 * location's regional values (a flavor offered in its region) are laid over
 * the result; with none the params and hash are the template's own. Returns
 * the parsed params + hash.
 */
export async function resolveTemplateFor(
  ctx: { db: import('./_generated/server').DatabaseReader },
  provider: EdgeProviderId,
  explicitId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountDefaultId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountId?: Doc<'edgeProviderAccounts'>['_id'] | null,
  location?: TemplateLocation | null,
): Promise<{
  id: Doc<'edgeTemplates'>['_id'] | null;
  params: Record<string, unknown>;
  hash: string;
}> {
  const base = await resolveBaseTemplate(
    ctx,
    provider,
    explicitId,
    accountDefaultId,
    accountId,
    location,
  );
  const overlay = parseRegionalParams(provider, location?.regionalParams);
  if (Object.keys(overlay).length === 0) return base;
  const params = withRegionalOverlay(provider, base.params, overlay);
  return { id: base.id, params, hash: templateHashOf(params) };
}

/**
 * What a node's pick BUILDS with at one location: the template the location
 * resolves, with the pick's tuning choices laid over it (lib/edges/providers
 * /options.ts). `hash` is the template's own hash when the pick chose no
 * tuning value, so a pick without choices builds exactly what it did before
 * options existed; `baseHash` is always the location's own. `choices` is the
 * pick's whole choice set as stored (null = a pick from before options).
 * `invalid` lists what breaks a provider rule once laid over the template.
 */
export async function resolveBuildFor(
  ctx: { db: import('./_generated/server').DatabaseReader },
  provider: EdgeProviderId,
  explicitId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountDefaultId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountId: Doc<'edgeProviderAccounts'>['_id'] | null | undefined,
  location: TemplateLocation | null | undefined,
  choices: Values | null,
): Promise<{
  id: Doc<'edgeTemplates'>['_id'] | null;
  params: Record<string, unknown>;
  hash: string;
  baseHash: string;
  choices: Values | null;
  invalid: string[] | null;
}> {
  const base = await resolveTemplateFor(
    ctx,
    provider,
    explicitId,
    accountDefaultId,
    accountId,
    location,
  );
  const { tuning } = splitChoices(optionFieldsOf(provider), choices ?? {});
  if (Object.keys(tuning).length === 0)
    return { ...base, baseHash: base.hash, choices, invalid: null };
  const built = checkBuiltParams(provider, deepMerge(base.params, tuning));
  return {
    id: base.id,
    params: built.ok ? built.params : deepMerge(base.params, tuning),
    hash: builtTemplateHash(base.params, base.hash, tuning),
    baseHash: base.hash,
    choices,
    invalid: built.ok ? null : built.issues,
  };
}

/**
 * One pick's provider options, checked where they will build: validated for
 * the pick's provider, the account's certificate defaults copied in (an
 * account default only ever PREFILLS a node), laid over the template the
 * location resolves and checked as a whole. Returns what the pick stores.
 */
export async function checkPickOptions(
  ctx: { db: import('./_generated/server').DatabaseReader },
  location: Doc<'edgeLocations'>,
  account: Doc<'edgeProviderAccounts'>,
  raw: unknown,
): Promise<{ ok: true; options: Values } | { ok: false; code: string; issues: string[] }> {
  const res = validatePickOptions(account.provider, raw);
  if (!res.ok) return { ok: false, code: res.code, issues: res.issues };
  const options = {
    ...certificateValuesFor(account.provider, accountOptionDefaultsOf(account), res.values),
    ...res.values,
  };
  const built = await resolveBuildFor(
    ctx,
    account.provider,
    null,
    account.defaultTemplateId ?? null,
    account._id,
    location,
    options,
  );
  if (built.invalid) return { ok: false, code: 'edge.option_invalid', issues: built.invalid };
  return { ok: true, options };
}

async function resolveBaseTemplate(
  ctx: { db: import('./_generated/server').DatabaseReader },
  provider: EdgeProviderId,
  explicitId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountDefaultId: Doc<'edgeTemplates'>['_id'] | null | undefined,
  accountId: Doc<'edgeProviderAccounts'>['_id'] | null | undefined,
  location: TemplateLocation | null | undefined,
): Promise<{
  id: Doc<'edgeTemplates'>['_id'] | null;
  params: Record<string, unknown>;
  hash: string;
}> {
  const candidates = [explicitId, location?.defaultTemplateId, accountDefaultId].filter(
    (x): x is Doc<'edgeTemplates'>['_id'] => !!x,
  );
  for (const id of candidates) {
    const row = await ctx.db.get(id);
    if (row && row.provider === provider && visibleTo(row, accountId)) {
      const parsed = validateTemplateParams(provider, JSON.parse(row.params));
      if (parsed.ok) return { id: row._id, params: parsed.params, hash: row.paramsHash };
    }
  }
  const rows = await ctx.db
    .query('edgeTemplates')
    .withIndex('by_provider', (q) => q.eq('provider', provider))
    .collect();
  const scopedDefault = accountId
    ? rows.find((r) => r.isDefault && r.accountId === accountId)
    : undefined;
  const unscoped = rows.filter((r) => !r.accountId);
  const dflt = scopedDefault ?? unscoped.find((r) => r.isDefault) ?? unscoped[0];
  if (dflt) {
    const parsed = validateTemplateParams(provider, JSON.parse(dflt.params));
    if (parsed.ok) return { id: dflt._id, params: parsed.params, hash: dflt.paramsHash };
  }
  const params = EDGE_TEMPLATES[provider].defaults;
  return { id: null, params, hash: templateHashOf(params) };
}

export const resolveForProvision = internalQuery({
  args: {
    provider: edgeProviderIdValidator,
    templateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    accountDefaultId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    /** The provisioning account: scopes which templates may be used (see resolveTemplateFor). */
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    /** The location: its default template and regional values (an edge's own, at a step). */
    locationId: v.optional(v.union(v.id('edgeLocations'), v.null())),
  },
  handler: async (ctx, a) =>
    resolveTemplateFor(
      ctx,
      a.provider,
      a.templateId ?? null,
      a.accountDefaultId ?? null,
      a.accountId ?? null,
      a.locationId ? await ctx.db.get(a.locationId) : null,
    ),
});

/**
 * First-use seeding: while the table is EMPTY, one default template per
 * provider from the adapter defaults. Runs from the templates read route, so a
 * fresh deployment shows editable defaults instead of an empty tab; once an
 * operator has any template (or deleted one on purpose) nothing is re-seeded.
 */
export const ensureDefaults = internalMutation({
  args: {},
  handler: async (ctx) => {
    if (await ctx.db.query('edgeTemplates').first()) return { created: 0 };
    await assertAdmission(ctx.db, 'template.write');
    let created = 0;
    for (const provider of EDGE_PROVIDER_IDS) {
      const existing = await ctx.db
        .query('edgeTemplates')
        .withIndex('by_provider', (q) => q.eq('provider', provider))
        .first();
      if (existing) continue;
      const params = EDGE_TEMPLATES[provider].defaults;
      await ctx.db.insert('edgeTemplates', {
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

/**
 * The effective template hash of every TRUSTED location of a provider's
 * accounts: the template it names (or its account names), else the default it
 * falls back to, with the location's regional values laid over it. Taken
 * before a write that can move a template (create / update / remove) and
 * compared after it: a location whose effective template changed was trusted
 * with parameters it will no longer provision with, so its trust is revoked
 * (audited) until taken again. Selection trusts `qualified` alone.
 */
async function effectiveDefaultHashes(
  ctx: { db: import('./_generated/server').DatabaseReader },
  provider: EdgeProviderId,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const loc of await ctx.db.query('edgeLocations').collect()) {
    if (loc.provider !== provider || !loc.qualified) continue;
    const acct = await ctx.db.get(loc.accountId);
    if (!acct) continue;
    const eff = await resolveTemplateFor(
      ctx,
      provider,
      null,
      acct.defaultTemplateId ?? null,
      acct._id,
      loc,
    );
    out.set(loc._id, eff.hash);
  }
  return out;
}

async function revokeMovedDefaults(
  ctx: import('./_generated/server').MutationCtx,
  provider: EdgeProviderId,
  before: Map<string, string>,
  actorAdminId: Doc<'adminUsers'>['_id'] | undefined,
): Promise<number> {
  let revoked = 0;
  for (const [id, prevHash] of before) {
    const fresh = await ctx.db.get(id as Doc<'edgeLocations'>['_id']);
    if (!fresh || !fresh.qualified) continue; // already revoked by another rule
    const acct = await ctx.db.get(fresh.accountId);
    if (!acct) continue;
    const eff = await resolveTemplateFor(
      ctx,
      provider,
      null,
      acct.defaultTemplateId ?? null,
      acct._id,
      fresh,
    );
    if (eff.hash === prevHash) continue;
    await untrustForTemplate(ctx, acct, fresh, actorAdminId);
    revoked++;
  }
  return revoked;
}

/** Revoke one location's trust because the parameters it was trusted with moved (audited). */
async function untrustForTemplate(
  ctx: import('./_generated/server').MutationCtx,
  acct: Doc<'edgeProviderAccounts'>,
  loc: Doc<'edgeLocations'>,
  actorAdminId: Doc<'adminUsers'>['_id'] | undefined,
): Promise<void> {
  await ctx.db.patch(loc._id, {
    qualified: false,
    qualifiedTemplateHash: undefined,
    qualification: undefined,
    updatedAt: Date.now(),
  });
  await writeAuditLog(ctx, {
    actorType: 'admin',
    actorId: actorAdminId,
    action: 'edge.provider_account.qualified',
    targetType: 'edge_provider_account',
    targetId: acct._id,
    payload: { name: acct.name, provider: acct.provider, qualified: false, placeKey: loc.placeKey },
  });
}

export const create = internalMutation({
  args: {
    provider: edgeProviderIdValidator,
    name: v.string(),
    params: v.any(),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    isDefault: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'template.write');
    if (!NAME_RE.test(a.name))
      throw new ConvexError({ code: 'validation', message: 'invalid template name' });
    const parsed = validateTemplateWrite(a.provider, a.params);
    if (!parsed.ok)
      throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
    if (a.accountId) {
      const acct = await ctx.db.get(a.accountId);
      if (!acct || acct.provider !== a.provider)
        throw new ConvexError({ code: 'validation', message: 'account/provider mismatch' });
    }
    const now = Date.now();
    // A new default changes what qualified accounts provision with next.
    const before = a.isDefault ? await effectiveDefaultHashes(ctx, a.provider) : null;
    if (a.isDefault) await clearDefault(ctx, a.provider, a.accountId ?? undefined);
    const id = await ctx.db.insert('edgeTemplates', {
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
      action: 'edge.template.create',
      targetType: 'edge_template',
      targetId: id,
      payload: { provider: a.provider, name: a.name },
    });
    const requalify = before
      ? await revokeMovedDefaults(ctx, a.provider, before, a.actorAdminId ?? undefined)
      : 0;
    return { id, paramsHash: templateHashOf(parsed.params), requalify };
  },
});

/**
 * One default per SCOPE: the provider-wide default (unscoped rows) and each
 * account's own default (rows scoped to it) are independent.
 */
async function clearDefault(
  ctx: { db: import('./_generated/server').DatabaseWriter },
  provider: EdgeProviderId,
  accountId: Doc<'edgeProviderAccounts'>['_id'] | undefined,
) {
  const rows = await ctx.db
    .query('edgeTemplates')
    .withIndex('by_provider', (q) => q.eq('provider', provider))
    .collect();
  for (const r of rows)
    if (r.isDefault && (r.accountId ?? undefined) === accountId)
      await ctx.db.patch(r._id, { isDefault: false });
}

export const update = internalMutation({
  args: {
    id: v.id('edgeTemplates'),
    name: v.optional(v.string()),
    params: v.optional(v.any()),
    isDefault: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'template.write');
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Template not found' });
    const patch: Partial<Doc<'edgeTemplates'>> = { updatedAt: Date.now() };
    if (a.name !== undefined) {
      if (!NAME_RE.test(a.name))
        throw new ConvexError({ code: 'validation', message: 'invalid template name' });
      patch.name = a.name;
    }
    let requalify: Doc<'edgeLocations'>[] = [];
    const before = await effectiveDefaultHashes(ctx, row.provider);
    if (a.params !== undefined) {
      const parsed = validateTemplateWrite(row.provider, a.params);
      if (!parsed.ok)
        throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
      patch.params = JSON.stringify(parsed.params);
      patch.paramsHash = templateHashOf(parsed.params);
      if (patch.paramsHash !== row.paramsHash) {
        // The trust was taken with the OLD parameters: every trusted location
        // that provisions from this template (named by it or its account, or
        // reached through the default it falls back to) or that was trusted
        // with exactly these parameters must be trusted again before
        // automation uses it.
        for (const loc of await ctx.db.query('edgeLocations').collect()) {
          if (loc.provider !== row.provider || !loc.qualified) continue;
          const acct = await ctx.db.get(loc.accountId);
          if (!acct) continue;
          const eff = await resolveTemplateFor(
            ctx,
            row.provider,
            null,
            acct.defaultTemplateId ?? null,
            acct._id,
            loc,
          );
          if (eff.id === a.id || loc.qualifiedTemplateHash === row.paramsHash) requalify.push(loc);
        }
      }
    }
    if (a.isDefault === true) {
      await clearDefault(ctx, row.provider, row.accountId ?? undefined);
      patch.isDefault = true;
    } else if (a.isDefault === false) {
      patch.isDefault = false;
    }
    await ctx.db.patch(a.id, patch);
    for (const loc of requalify) {
      const acct = await ctx.db.get(loc.accountId);
      if (acct) await untrustForTemplate(ctx, acct, loc, a.actorAdminId ?? undefined);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.template.update',
      targetType: 'edge_template',
      targetId: a.id,
      payload: { provider: row.provider, name: patch.name ?? row.name },
    });
    // Any account whose EFFECTIVE default moved (this template became or
    // stopped being its default, or its default's parameters changed) must
    // re-qualify — `selectionContext` trusts `qualified` alone.
    const moved = await revokeMovedDefaults(ctx, row.provider, before, a.actorAdminId ?? undefined);
    return {
      ok: true as const,
      paramsHash: patch.paramsHash ?? row.paramsHash,
      requalify: requalify.length + moved,
    };
  },
});

export const remove = internalMutation({
  args: { id: v.id('edgeTemplates'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    await assertAdmission(ctx.db, 'template.write');
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    const siblings = await ctx.db
      .query('edgeTemplates')
      .withIndex('by_provider', (q) => q.eq('provider', row.provider))
      .collect();
    if (siblings.length <= 1) {
      throw new ConvexError({
        code: 'edge.template_last_of_provider',
        message: 'A provider keeps at least one template',
      });
    }
    // Accounts naming this template, or falling back to it as a default, will
    // provision from something else next: snapshot before anything moves.
    const before = await effectiveDefaultHashes(ctx, row.provider);
    const referencing = await ctx.db.query('edgeProviderAccounts').collect();
    for (const acct of referencing) {
      if (acct.defaultTemplateId === id)
        await ctx.db.patch(acct._id, { defaultTemplateId: undefined, updatedAt: Date.now() });
    }
    for (const loc of await ctx.db.query('edgeLocations').collect()) {
      if (loc.defaultTemplateId === id)
        await ctx.db.patch(loc._id, { defaultTemplateId: undefined, updatedAt: Date.now() });
    }
    await ctx.db.delete(id);
    if (row.isDefault) {
      // The default hands off within the same scope only.
      const next = siblings.find(
        (s) => s._id !== id && (s.accountId ?? undefined) === (row.accountId ?? undefined),
      );
      if (next) await ctx.db.patch(next._id, { isDefault: true, updatedAt: Date.now() });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.template.delete',
      targetType: 'edge_template',
      targetId: id,
      payload: { provider: row.provider, name: row.name },
    });
    const requalify = await revokeMovedDefaults(
      ctx,
      row.provider,
      before,
      actorAdminId ?? undefined,
    );
    return { ok: true as const, requalify };
  },
});

/** Pure validation for the CMS "Validate" button (no write). */
export const validate = internalQuery({
  args: { provider: edgeProviderIdValidator, params: v.any() },
  handler: async (_ctx, { provider, params }) => {
    const parsed = validateTemplateWrite(provider, params);
    return parsed.ok
      ? { ok: true as const, params: parsed.params, paramsHash: templateHashOf(parsed.params) }
      : { ok: false as const, issues: parsed.issues };
  },
});
