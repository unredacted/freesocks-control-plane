/**
 * Origin provider ACCOUNTS: one cloud or CDN account FCP may provision edges
 * in, a provider plus credentials. WHERE its edges live is a LOCATION
 * (convex/edgeLocations.ts), and trust is taken per location. A sibling of
 * mirrorProviders/backendServers: a variable-length pool of secret-bearing rows.
 *
 * Secret invariant: `credentials` is stored on create/edit, read back ONLY by
 * the "use node" provider actions (`getWithSecret`), and surfaced to the admin
 * as per-field set/not-set booleans (`maskCredentials`). Blank fields on an
 * edit keep the stored value. Nothing here is logged; audits carry name +
 * provider only.
 */
import { ConvexError, v } from 'convex/values';
import { fakeShadowedIds } from './lib/edges/providers/fake';
import { internalMutation, internalQuery } from './_generated/server';
import type { QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { edgeProviderIdValidator, type EdgeProviderId } from './lib/edgeProviderIds';
export { accountOptionDefaultsOf } from './lib/edges/choices';
import {
  buildCredentials,
  legacyOptionDefaults,
  locatingSettingsChanged,
  maskCredentials,
  placementKeysOf,
  settingsEqual,
  validatePlacement,
  validateSettings,
  withoutPlacementKeys,
  type EdgeCredentials,
  type EdgeSettings,
} from './lib/edges/accountSettings';
import { EDGE_PROVIDER_CAPABILITIES, edgeLayerOf } from './lib/edges/providers/capabilities';
import { optionChanges, sameValues, type Values } from './lib/edges/providers/options';
import { accountOptionDefaultsOf } from './lib/edges/choices';
import {
  EDGE_NEW_ACCOUNT_OPTION_DEFAULTS,
  optionFieldsOf,
  validateAccountOptionDefaults,
} from './lib/edges/providers/templates';
import { parseIntent, parseObservedSettings } from './lib/edges/intent';
import { liveEdgesOfAccount } from './relays';
import { assertAdmission } from './lib/edges/maintenance';
import { type AutoQualifyEvidence } from './lib/edges/autoQualify';
import { placementHashOf } from './lib/edges/locations';
import {
  applyLocationQualification,
  defaultLocationOf,
  evaluateAutoQualificationForLocation,
  initialPlacementOf,
  inventoryView,
  locationInUse,
  locationsAdminOf,
  locationsOfAccount,
  untrustAccountLocations,
  untrustLocation,
  upsertLocation,
  type LocationAdmin,
} from './edgeLocations';

// A display label (never a provider resource name or a URL segment): same shape as a
// template name.
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/;

/** Option defaults an admin payload sets, checked (`edge.option_*` refusals). */
function checkedOptionDefaults(provider: EdgeProviderId, raw: Values): Values {
  const res = validateAccountOptionDefaults(provider, raw);
  if (!res.ok) throw new ConvexError({ code: res.code, message: res.issues.join('; ') });
  return res.values;
}

const storedOptions = (v: Values): string | undefined =>
  Object.keys(v).length > 0 ? JSON.stringify(v) : undefined;

function checkName(name: string): void {
  if (!NAME_RE.test(name) || name !== name.trim()) {
    throw new ConvexError({
      code: 'validation',
      message: 'name must be 1-63 chars of letters, digits, spaces, dots, dashes and underscores',
    });
  }
}

/**
 * Admin-safe view of one account. `settings` holds the account's own keys only
 * (never a placement: that is a location's). The trust fields read the
 * DEFAULT location's (`qualified`: any enabled location is trusted), so a
 * single-location account reads as it always did; `locations` has them all.
 */
export function mapAccountAdmin(
  r: Doc<'edgeProviderAccounts'>,
  locations: LocationAdmin[],
  sharedUsers = 0,
) {
  const { type: _t, ...raw } = r.settings as { type: string } & Record<string, unknown>;
  const settings = withoutPlacementKeys(r.provider, raw);
  const dflt = locations.find((l) => l.isDefault) ?? null;
  return {
    id: r._id as string,
    provider: r.provider,
    name: r.name,
    settings,
    // Defaults for the provider's certificate options (copied into a node's pick).
    optionDefaults: accountOptionDefaultsOf(r),
    credentialsSet: maskCredentials(r.credentials as Record<string, unknown>),
    defaultTemplateId: (r.defaultTemplateId as string | undefined) ?? null,
    defaultLocationId: dflt?.id ?? null,
    locations,
    enabled: r.enabled,
    qualified: locations.some((l) => l.enabled && l.qualified),
    qualifiedTemplateHash: dflt?.qualifiedTemplateHash ?? null,
    // How the trust was taken (never the endpoint itself: ids + dates only).
    qualification: dflt?.qualification ?? null,
    autoQualifyHold: dflt?.autoQualifyHold === true,
    priority: r.priority,
    dailyAllocationBudget: r.dailyAllocationBudget,
    allocationsToday: r.allocationsDayKey === dayKey() ? r.allocationsToday : 0,
    maxLiveEdges: r.maxLiveEdges,
    lastTestOkAt: r.lastTestOkAt ? new Date(r.lastTestOkAt).toISOString() : null,
    lastTestError: r.lastTestError ?? null,
    lastTestErrorDetail: r.lastTestErrorDetail ?? null,
    // What the last credential test read at the provider (e.g. the zone's
    // encryption mode). Planning needs it; the operator never types it.
    observedSettings: r.observedSettings ? parseObservedSettings(r.observedSettings) : null,
    observedAt: r.observedAt ? new Date(r.observedAt).toISOString() : null,
    inventoryAt: dflt?.inventoryAt ?? null,
    // The account-wide certificate its fronts share, as last read at the
    // provider, and how many live edges front through it (null: none).
    sharedCertificate: r.sharedCertificate
      ? {
          name: r.sharedCertificate.name,
          state: r.sharedCertificate.state,
          code: r.sharedCertificate.code ?? null,
          notAfter: r.sharedCertificate.notAfter ?? null,
          checkedAt: new Date(r.sharedCertificate.checkedAt).toISOString(),
          edges: sharedUsers,
        }
      : null,
    // Dev only: the adapter behind this account is the in-memory fake, so the
    // CMS can badge it and no screenshot shows a real adapter name for it.
    fake: fakeShadowedIds().includes(r.provider),
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
  /** The certificate option defaults as stored (JSON; `accountOptionDefaultsOf` reads them). */
  optionDefaults?: string;
  enabled: boolean;
  defaultTemplateId: Id<'edgeTemplates'> | null;
  /** Row version for compare-and-set writes (a rotation applies only to the row it tested). */
  updatedAt: number;
  /** Consecutive provider-side API failures (a success resets them). */
  apiFailures: number;
}

function toWithSecret(r: Doc<'edgeProviderAccounts'>): RelayAccountWithSecret {
  return {
    id: r._id,
    provider: r.provider,
    name: r.name,
    credentials: r.credentials as EdgeCredentials,
    settings: r.settings as EdgeSettings,
    ...(r.optionDefaults !== undefined ? { optionDefaults: r.optionDefaults } : {}),
    enabled: r.enabled,
    defaultTemplateId: r.defaultTemplateId ?? null,
    updatedAt: r.updatedAt,
    apiFailures: r.apiFailures ?? 0,
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

export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('edgeProviderAccounts').collect();
    const out = [];
    for (const r of rows.sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name)))
      out.push(
        mapAccountAdmin(
          r,
          await locationsAdminOf(ctx.db, r),
          r.sharedCertificate ? await sharedCertificateUsers(ctx.db, r._id) : 0,
        ),
      );
    return out;
  },
});

export const getForAdmin = internalQuery({
  args: { id: v.id('edgeProviderAccounts') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r
      ? mapAccountAdmin(
          r,
          await locationsAdminOf(ctx.db, r),
          r.sharedCertificate ? await sharedCertificateUsers(ctx.db, r._id) : 0,
        )
      : null;
  },
});

/**
 * The stored inventory snapshot of one of the account's locations (the
 * default one when none is named), decoded for the admin contract (addresses
 * are public client-facing data). Inventory is per region.
 */
export const getInventory = internalQuery({
  args: { id: v.id('edgeProviderAccounts'), locationId: v.optional(v.id('edgeLocations')) },
  handler: async (ctx, { id, locationId }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    const loc = locationId ? await ctx.db.get(locationId) : await defaultLocationOf(ctx.db, r);
    if (!loc || loc.accountId !== r._id)
      return { locationId: null, inventory: null, inventoryAt: null };
    return inventoryView(ctx, loc);
  },
});

// --- writes ------------------------------------------------------------------------

const upsertArgs = {
  provider: edgeProviderIdValidator,
  name: v.string(),
  settings: v.any(),
  /** The region's display name, for a first location given in the old single-location shape. */
  locationLabel: v.optional(v.string()),
  credentials: v.optional(v.any()),
  enabled: v.optional(v.boolean()),
  priority: v.optional(v.number()),
  dailyAllocationBudget: v.optional(v.number()),
  maxLiveEdges: v.optional(v.number()),
  defaultTemplateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
  /** Defaults for the provider's certificate options (lib/edges/providers/options.ts). */
  optionDefaults: v.optional(v.any()),
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
  // 0 = no daily limit on billable allocations: a runaway loop could then spend
  // without bound. Only a development deployment may say so.
  if (a.dailyAllocationBudget === 0 && process.env.ENVIRONMENT !== 'development') {
    throw new ConvexError({
      code: 'validation',
      message: 'dailyAllocationBudget 0 (no daily limit) is allowed only in development',
    });
  }
  if (a.maxLiveEdges !== undefined && (a.maxLiveEdges < 1 || a.maxLiveEdges > 200)) {
    throw new ConvexError({ code: 'validation', message: 'maxLiveEdges must be 1..200' });
  }
  if (a.priority !== undefined && !Number.isFinite(a.priority)) {
    throw new ConvexError({ code: 'validation', message: 'priority must be a number' });
  }
}

/**
 * A default template must belong to the account's provider and be visible to
 * it: unscoped, or scoped to THIS account. A template scoped to another account
 * would be silently skipped by `resolveTemplateFor`, so the operator's pick and
 * what provisions/qualifies would differ.
 */
async function assertTemplateUsable(
  db: import('./_generated/server').DatabaseReader,
  templateId: Id<'edgeTemplates'>,
  provider: EdgeProviderId,
  accountId: Id<'edgeProviderAccounts'> | null,
) {
  const tpl = await db.get(templateId);
  if (!tpl || tpl.provider !== provider)
    throw new ConvexError({ code: 'validation', message: 'unknown template for this provider' });
  if (tpl.accountId && tpl.accountId !== accountId)
    throw new ConvexError({
      code: 'validation',
      message: 'that template is scoped to another account',
    });
}

// --- DNS-account references ------------------------------------------------------------
//
// A Fastly-style account writes its records through ANOTHER account's
// credentials (`settings.dnsAccountId` → a Cloudflare account). That makes the
// referenced account load-bearing for edges that never name it directly: their
// DNS records live in ITS zone, addressed by ITS credentials. So every rule that
// protects an account from being moved or removed under its own edges has to
// see through the reference too.

/** Accounts that name `id` as their DNS account (the small, operator-managed table). */
async function fastlyAccountsUsing(
  db: import('./_generated/server').DatabaseReader,
  id: Id<'edgeProviderAccounts'>,
): Promise<Doc<'edgeProviderAccounts'>[]> {
  const rows = await db.query('edgeProviderAccounts').collect();
  return rows.filter((r) => (r.settings as { dnsAccountId?: string }).dnsAccountId === id);
}

/**
 * Non-destroyed edges that depend on this account for DNS: the ones provisioned
 * from an account that references it, whose FROZEN intent names it as the DNS
 * account or names its zone. The intent is what makes this complete: an edge is
 * covered from `insertPlanned` onward, including one whose DNS create response
 * was lost and has no recorded resource yet.
 */
async function edgesDependingOnDnsAccount(
  db: import('./_generated/server').DatabaseReader,
  account: Doc<'edgeProviderAccounts'>,
): Promise<number> {
  const zoneId = (account.settings as { zoneId?: string }).zoneId;
  let n = 0;
  for (const referencing of await fastlyAccountsUsing(db, account._id)) {
    for (const e of await liveEdgesOfAccount(db, referencing._id)) {
      const intent = parseIntent(e.provisionIntent);
      if (!intent) {
        // No intent yet is not "no dependency": the edge belongs to an account
        // that names this one, so it is counted.
        n++;
        continue;
      }
      if (intent.dnsAccountId === (account._id as string) || (zoneId && intent.zoneId === zoneId))
        n++;
    }
  }
  return n;
}

/**
 * Editing a DNS account's credentials or settings invalidates every Fastly
 * account that writes through it: their qualification was taken with the old
 * token against the old zone, and neither is what would be used now. Every
 * dependent account (qualified or not) is stamped `dependencyChangedAt`, so
 * the auto-trust rule (lib/edges/autoQualify.ts) cannot re-trust it from a
 * proof or a credential test taken through the old dependency.
 */
async function clearQualificationOfReferencing(
  ctx: import('./_generated/server').MutationCtx,
  id: Id<'edgeProviderAccounts'>,
  actorAdminId: Id<'adminUsers'> | undefined,
): Promise<number> {
  let n = 0;
  const now = Date.now();
  for (const r of await fastlyAccountsUsing(ctx.db, id)) {
    await ctx.db.patch(r._id, { dependencyChangedAt: now, updatedAt: now });
    n += await untrustAccountLocations(ctx, r, { actorAdminId });
  }
  return n;
}

/**
 * Validate `settings.dnsAccountId`: it must name an existing account whose
 * provider can host DNS. A dangling or wrong-kind reference would only surface
 * at provision time, with a paid-for edge half-created.
 */
async function assertDnsAccountUsable(
  db: import('./_generated/server').DatabaseReader,
  provider: EdgeProviderId,
  settings: Record<string, unknown>,
) {
  if (!EDGE_PROVIDER_CAPABILITIES[provider].needsDnsAccount) return;
  const ref = settings.dnsAccountId;
  if (typeof ref !== 'string' || ref.length === 0)
    throw new ConvexError({ code: 'validation', message: 'a DNS account is required' });
  const row = await db.get(ref as Id<'edgeProviderAccounts'>);
  if (!row || !EDGE_PROVIDER_CAPABILITIES[row.provider].providesDns)
    throw new ConvexError({
      code: 'validation',
      message: 'dnsAccountId must name an account that can host DNS records',
    });
}

/**
 * A settings payload may still carry placement keys (the old single-location
 * shape). Re-sending the place the account already has is accepted; any other
 * place is a new location, never an edit of this account.
 */
async function assertPlacementUnchanged(
  db: import('./_generated/server').DatabaseReader,
  row: Doc<'edgeProviderAccounts'>,
  raw: Record<string, unknown>,
): Promise<void> {
  const keys = placementKeysOf(row.provider, raw);
  if (!keys) return;
  const parsed = validatePlacement(row.provider, keys);
  if (!parsed.ok) throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
  const hash = placementHashOf(parsed.placement);
  const dflt = await defaultLocationOf(db, row);
  if (dflt && dflt.placementHash === hash) return;
  throw new ConvexError({
    code: 'edge.placement_on_location',
    message: 'A place belongs to a location: add a location instead of moving the account',
  });
}

/**
 * "Tested" = a successful credential test on record AND the latest test did
 * not fail. A failure keeps the older success timestamp (so the history stays
 * readable), which must not keep the account usable: one rule for the guided
 * status, the attention list and the explicit test provision.
 */
export function accountTested(
  a: Pick<Doc<'edgeProviderAccounts'>, 'lastTestOkAt' | 'lastTestError'>,
): boolean {
  return !!a.lastTestOkAt && !a.lastTestError;
}

/**
 * Why no new front can be planned on the account, though it may be tested:
 * its last credential test ended on the CAA preflight (`caa_forbids_ca`), or
 * the wildcard certificate it shares failed (`shared_certificate_failed`).
 * Null when nothing certificate-shaped stands in the way. One rule for the
 * selection, the preflight, the start guards, the setup plan and the run.
 */
export function certificateRefusalOf(
  a: Pick<
    Doc<'edgeProviderAccounts'>,
    'provider' | 'lastTestError' | 'settings' | 'optionDefaults' | 'sharedCertificate'
  >,
): 'caa_forbids_ca' | 'shared_certificate_failed' | null {
  if (a.lastTestError === 'caa_forbids_ca') return 'caa_forbids_ca';
  // The account's default scope (a node may choose its own; its front waits on
  // the certificate step instead).
  const wildcard = accountOptionDefaultsOf(a).certificateScope === 'wildcard';
  if (wildcard && a.sharedCertificate?.state === 'failed') return 'shared_certificate_failed';
  return null;
}

export const create = internalMutation({
  args: upsertArgs,
  handler: async (ctx, a) => {
    checkName(a.name);
    checkLimits(a);
    await assertAdmission(ctx.db, 'provider.write');
    const dup = await ctx.db
      .query('edgeProviderAccounts')
      .withIndex('by_name', (q) => q.eq('name', a.name))
      .unique();
    if (dup)
      throw new ConvexError({ code: 'conflict', message: 'An account with this name exists' });
    // An account is a provider plus credentials. A payload in the old
    // single-location shape (placement keys among the settings) also gets
    // that place as the account's first location, so nothing that created
    // accounts that way breaks; a CDN account always gets its one location.
    const rawSettings = (a.settings ?? {}) as Record<string, unknown>;
    const settings = validateSettings(a.provider, withoutPlacementKeys(a.provider, rawSettings));
    if (!settings.ok)
      throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
    const initialPlacement = initialPlacementOf(a.provider, rawSettings);
    if (initialPlacement) {
      const p = validatePlacement(a.provider, initialPlacement);
      if (!p.ok) throw new ConvexError({ code: 'validation', message: p.issues.join('; ') });
    }
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
    await assertDnsAccountUsable(ctx.db, a.provider, settings.settings as Record<string, unknown>);
    // What a new account starts with where the payload leaves it out (a new
    // Fastly account shares one wildcard certificate); an older client's
    // authority or scope under settings is the same default.
    const optionDefaults = checkedOptionDefaults(a.provider, {
      ...(EDGE_NEW_ACCOUNT_OPTION_DEFAULTS[a.provider] ?? {}),
      ...legacyOptionDefaults(a.provider, rawSettings),
      ...((a.optionDefaults ?? {}) as Values),
    });
    // A template picked at creation can only be unscoped (the account has no id yet).
    if (a.defaultTemplateId)
      await assertTemplateUsable(ctx.db, a.defaultTemplateId, a.provider, null);
    const now = Date.now();
    const id = await ctx.db.insert('edgeProviderAccounts', {
      provider: a.provider,
      name: a.name,
      credentials: creds.credentials as never,
      settings: settings.settings as never,
      optionDefaults: storedOptions(optionDefaults),
      defaultTemplateId: a.defaultTemplateId ?? undefined,
      enabled: a.enabled ?? true,
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
    let locationId: Id<'edgeLocations'> | null = null;
    if (initialPlacement) {
      const row = (await ctx.db.get(id))!;
      locationId = (
        await upsertLocation(
          ctx,
          row,
          initialPlacement,
          { label: typeof a.locationLabel === 'string' ? a.locationLabel : undefined },
          { actorAdminId: a.actorAdminId },
        )
      ).id;
    }
    return { id, locationId };
  },
});

export const update = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    name: v.optional(v.string()),
    settings: v.optional(v.any()),
    credentials: v.optional(v.any()),
    enabled: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    dailyAllocationBudget: v.optional(v.number()),
    maxLiveEdges: v.optional(v.number()),
    defaultTemplateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    /** The account's certificate option defaults, whole (replaces the stored set). */
    optionDefaults: v.optional(v.any()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    checkLimits(a);
    // An account stored with no daily limit (0, allowed before) keeps it only
    // until its next edit: any edit must set a budget too. Switching it off is
    // the one exception, so an operator can always stop it at once.
    const onlySwitchingOff =
      a.enabled === false &&
      [
        a.name,
        a.settings,
        a.credentials,
        a.priority,
        a.maxLiveEdges,
        a.defaultTemplateId,
        a.optionDefaults,
      ].every((x) => x === undefined);
    if (a.dailyAllocationBudget === undefined && !onlySwitchingOff)
      checkLimits({ dailyAllocationBudget: row.dailyAllocationBudget });
    await assertAdmission(ctx.db, 'provider.write');
    const patch: Partial<Doc<'edgeProviderAccounts'>> = { updatedAt: Date.now() };
    let credentialsChanged = false;
    let settingsChanged = false;
    // The name is a label only (edges reference the account by id), so a rename
    // never touches the qualification.
    if (a.name !== undefined && a.name !== row.name) {
      checkName(a.name);
      const dup = await ctx.db
        .query('edgeProviderAccounts')
        .withIndex('by_name', (q) => q.eq('name', a.name!))
        .unique();
      if (dup && dup._id !== row._id)
        throw new ConvexError({ code: 'conflict', message: 'An account with that name exists' });
      patch.name = a.name;
    }
    if (a.settings !== undefined) {
      const raw = a.settings as Record<string, unknown>;
      // A placement is a location's, never the account's: the old
      // single-location shape re-sent unchanged is accepted, a different
      // place is a new location (`POST providers/{id}/locations`).
      await assertPlacementUnchanged(ctx.db, row, raw);
      const settings = validateSettings(row.provider, withoutPlacementKeys(row.provider, raw));
      if (!settings.ok)
        throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
      // Canonical (key-order-insensitive) compare of the account's own keys: a
      // stored row re-sent in a different key order is not a change.
      const ownNow = withoutPlacementKeys(row.provider, row.settings as Record<string, unknown>);
      settingsChanged = !settingsEqual(settings.settings, ownNow);
      if (
        settingsChanged &&
        locatingSettingsChanged(
          row.provider,
          settings.settings as Record<string, unknown>,
          row.settings as Record<string, unknown>,
        )
      ) {
        // Edges store only resource ids; the project/region/zone/network that
        // locate them live here and are reloaded by every describe/destroy. A
        // change while edges exist would make their resources invisible to
        // reconciliation and undeletable (yet still live and billable). The
        // credential identifiers (access/application key) also live in
        // `settings` but locate nothing: they stay editable.
        const live = await liveEdgesOfAccount(ctx.db, a.id);
        // An account that hosts DNS for another provider's edges also locates
        // THEIR records; moving it would strand records this account's own edge
        // list never mentions.
        const transitive = await edgesDependingOnDnsAccount(ctx.db, row);
        const total = live.length + transitive;
        if (total > 0)
          throw new ConvexError({
            code: 'edge.account_in_use',
            message: `${total} edge(s) still reference this account; destroy them before changing its settings`,
          });
      }
      await assertDnsAccountUsable(
        ctx.db,
        row.provider,
        settings.settings as Record<string, unknown>,
      );
      patch.settings = settings.settings as never;
    }
    // The certificate option defaults: a whole set from `optionDefaults`, or an
    // older client's authority under `settings` laid over the stored ones. A
    // row that still keeps a copy under `settings` keeps it through any
    // settings write (the validated settings no longer hold it).
    const before = accountOptionDefaultsOf(row);
    const legacyIncoming =
      a.settings !== undefined
        ? legacyOptionDefaults(row.provider, a.settings as Record<string, unknown>)
        : {};
    let optionsChanged = false;
    let optionChangeList: ReturnType<typeof optionChanges> = [];
    if (a.optionDefaults !== undefined || Object.keys(legacyIncoming).length > 0) {
      const next = checkedOptionDefaults(
        row.provider,
        a.optionDefaults !== undefined
          ? { ...legacyIncoming, ...(a.optionDefaults as Values) }
          : { ...before, ...legacyIncoming },
      );
      optionsChanged = !sameValues(next, before);
      optionChangeList = optionChanges(optionFieldsOf(row.provider), before, next);
      patch.optionDefaults = storedOptions(next);
    } else if (
      patch.settings !== undefined &&
      !row.optionDefaults &&
      Object.keys(before).length > 0
    )
      patch.optionDefaults = storedOptions(before);
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
      patch.credentials = creds.credentials as never;
      credentialsChanged = !settingsEqual(creds.credentials, row.credentials);
    }
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.priority !== undefined) patch.priority = a.priority;
    if (a.dailyAllocationBudget !== undefined)
      patch.dailyAllocationBudget = a.dailyAllocationBudget;
    if (a.maxLiveEdges !== undefined) patch.maxLiveEdges = a.maxLiveEdges;
    let templateChanged = false;
    if (a.defaultTemplateId !== undefined) {
      if (a.defaultTemplateId)
        await assertTemplateUsable(ctx.db, a.defaultTemplateId, row.provider, row._id);
      patch.defaultTemplateId = a.defaultTemplateId ?? undefined;
      templateChanged = (a.defaultTemplateId ?? undefined) !== row.defaultTemplateId;
    }
    // New credentials or settings invalidate the trust of every location (a
    // different account/network may not carry the protocol the same way); so
    // does a different effective template for the locations that fall back
    // to the account's: its parameters were never trusted. A routine secret
    // rotation that must KEEP the trust goes through
    // `edgeProviderOps.rotateCredentials` (tests the new secret first) instead.
    // New credentials or a moved account: the automatic rules may look again
    // once a test AFTER this change passes (lib/edges/autoQualify.ts).
    // The certificate defaults decide what a node protected from now on (and a
    // pick from before options) gets: a change is untrusted like a settings change.
    if (optionsChanged) settingsChanged = true;
    if (credentialsChanged || settingsChanged) patch.credentialsChangedAt = Date.now();
    await ctx.db.patch(a.id, patch);
    const fresh = (await ctx.db.get(a.id))!;
    let requalify = 0;
    if (credentialsChanged || settingsChanged)
      requalify += await untrustAccountLocations(ctx, fresh, {
        actorAdminId: a.actorAdminId,
        releaseHolds: true,
      });
    else if (templateChanged)
      requalify += await untrustAccountLocations(ctx, fresh, {
        actorAdminId: a.actorAdminId,
        onlyFallingBack: true,
      });
    // A DNS account's new token or zone was never trusted by the accounts
    // that write THROUGH it either: clear theirs too, audited per location.
    if (credentialsChanged || settingsChanged)
      requalify += await clearQualificationOfReferencing(ctx, a.id, a.actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.provider_account.update',
      targetType: 'edge_provider_account',
      targetId: a.id,
      payload: { name: patch.name ?? row.name, provider: row.provider },
    });
    if (optionsChanged)
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: a.actorAdminId ?? undefined,
        action: 'edge.provider_account.options_changed',
        targetType: 'edge_provider_account',
        targetId: a.id,
        payload: {
          name: patch.name ?? row.name,
          provider: row.provider,
          changes: optionChangeList,
        },
      });
    return { ok: true as const, requalify };
  },
});

export const remove = internalMutation({
  args: { id: v.id('edgeProviderAccounts'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    await assertAdmission(ctx.db, 'provider.write');
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
      throw new ConvexError({
        code: 'edge.account_in_use',
        message: 'Edges still reference this account',
      });
    }
    // An account other accounts write DNS through cannot go either: their
    // records live in its zone and are addressed with its credentials.
    const referencing = await fastlyAccountsUsing(ctx.db, id);
    if (referencing.length > 0 || (await edgesDependingOnDnsAccount(ctx.db, row)) > 0) {
      throw new ConvexError({
        code: 'edge.account_referenced',
        message: 'Another provider account uses this one for DNS; repoint or remove it first',
      });
    }
    // Its locations go with it, unless a protected node or an open setup run
    // still names one.
    const locations = await locationsOfAccount(ctx.db, id);
    for (const loc of locations) {
      const use = await locationInUse(ctx.db, loc);
      if (use.sets > 0 || use.runs > 0)
        throw new ConvexError({
          code: 'edge.account_in_use',
          message: 'A node still uses or is being protected in a location of this account',
        });
    }
    for (const loc of locations) await ctx.db.delete(loc._id);
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

/**
 * Credential rotation that KEEPS the qualification. Internal: the ONLY caller
 * is `edgeProviderOps.rotateCredentials`, which has just verified the new
 * credentials against the provider with `testCredentials`. The secret fields
 * and the non-secret identifiers (access/application key, kept in `settings`)
 * change together; every LOCATING setting must be untouched, so the account
 * still points at the same resources and the qualification still holds.
 */
// NOT gated by the maintenance switch on purpose: a destroy run that has to
// finish during a drain needs working credentials, so rotating an expired or
// revoked secret is a COMPLETION need, not new work.
export const applyCredentialRotation = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    /** The FULL credential set that passed the provider test (not a partial patch). */
    credentials: v.any(),
    /** The FULL settings that were tested alongside them. */
    settings: v.any(),
    /** What the passing test observed at the provider (refreshes `observedSettings`). */
    observed: v.optional(v.record(v.string(), v.string())),
    /** `updatedAt` of the row the test was built from; a newer row refuses the write. */
    expectedUpdatedAt: v.number(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    // Compare-and-set: the action tested ONE exact credential+settings pair.
    // If the row moved meanwhile (a concurrent rotation or edit), re-merging
    // here could store a pair nobody tested (one request's secret with the
    // other's access key); refuse instead and let the caller retry.
    if (row.updatedAt !== a.expectedUpdatedAt)
      throw new ConvexError({
        code: 'conflict',
        message: 'The account changed while its credentials were being tested; retry',
      });
    const creds = buildCredentials(row.provider, a.credentials as Record<string, unknown>, {});
    if (!creds.ok)
      throw new ConvexError({
        code: 'validation',
        message: `missing credentials: ${creds.missing.join(', ')}`,
      });
    const settings = validateSettings(
      row.provider,
      withoutPlacementKeys(row.provider, a.settings as Record<string, unknown>),
    );
    if (!settings.ok)
      throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
    if (
      locatingSettingsChanged(
        row.provider,
        settings.settings as Record<string, unknown>,
        row.settings as Record<string, unknown>,
      )
    )
      throw new ConvexError({ code: 'validation', message: 'rotation cannot move the account' });
    const credentialsChanged = !settingsEqual(creds.credentials, row.credentials);
    const identifiersChanged = !settingsEqual(
      settings.settings,
      withoutPlacementKeys(row.provider, row.settings as Record<string, unknown>),
    );
    const trusted = (await locationsOfAccount(ctx.db, row._id)).some((l) => l.qualified);
    const now = Date.now();
    await ctx.db.patch(a.id, {
      credentials: creds.credentials as never,
      settings: settings.settings as never,
      lastTestOkAt: now,
      lastTestError: undefined,
      // The passing test observed the provider's live facts; a test that observed
      // nothing leaves the previous observation alone (same rule as recordTest).
      ...(a.observed && Object.keys(a.observed).length > 0
        ? { observedSettings: JSON.stringify(a.observed).slice(0, 4_000), observedAt: now }
        : {}),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.provider_account.credentials_rotated',
      targetType: 'edge_provider_account',
      targetId: a.id,
      // Booleans only: never a key, an identifier or a hash of one.
      payload: {
        name: row.name,
        provider: row.provider,
        credentialsChanged,
        identifiersChanged,
        qualifiedKept: trusted,
      },
    });
    return { ok: true as const, credentialsChanged, identifiersChanged, qualified: trusted };
  },
});

/**
 * The trust override for one of the account's locations (its default one when
 * none is named): trusts the LOCATION, verifies no endpoint. An untrust holds
 * every automatic rule off until an operator trusts again or the credentials
 * change.
 */
export const setQualified = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    qualified: v.boolean(),
    locationId: v.optional(v.id('edgeLocations')),
    /** DEPRECATED and ignored: the effective template's hash is computed server-side. */
    templateHash: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, qualified, locationId, actorAdminId }) => {
    await assertAdmission(ctx.db, 'provider.write');
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    const loc = await locationFor(ctx, row, locationId);
    if (qualified) await applyLocationQualification(ctx, row, loc, { by: 'admin', actorAdminId });
    else await untrustLocation(ctx, row, loc, { hold: true, actorAdminId });
    return { ok: true as const };
  },
});

type QualificationCtx = import('./_generated/server').MutationCtx;

/** A named location of the account, else its default one; refused when it has none. */
async function locationFor(
  ctx: { db: import('./_generated/server').DatabaseReader },
  row: Doc<'edgeProviderAccounts'>,
  locationId: Id<'edgeLocations'> | undefined,
): Promise<Doc<'edgeLocations'>> {
  const loc = locationId ? await ctx.db.get(locationId) : await defaultLocationOf(ctx.db, row);
  if (!loc || loc.accountId !== row._id)
    throw new ConvexError({
      code: 'edge.no_location',
      message: 'This account has no location yet; add one first',
    });
  return loc;
}

/**
 * Trust one of the account's locations (`opts.locationId`, else its default
 * one): the account-level entry point kept for the callers that name an
 * account (lib/edges trust rules live in edgeLocations.ts).
 */
export async function applyQualification(
  ctx: QualificationCtx,
  row: Doc<'edgeProviderAccounts'>,
  opts: {
    by: 'admin' | 'auto';
    actorAdminId?: Id<'adminUsers'>;
    locationId?: Id<'edgeLocations'>;
    evidence?: Omit<AutoQualifyEvidence, 'proofCheckedAt'> & { proofCheckedAt?: number };
  },
): Promise<void> {
  const loc = await locationFor(ctx, row, opts.locationId);
  await applyLocationQualification(ctx, row, loc, opts);
}

/**
 * The L7 auto-trust rule (lib/edges/autoQualify.ts) for ONE account: each of
 * its locations is trusted when an active edge there carries a current
 * authenticated proof for the location's effective template NOW. Only ever
 * sets `qualified: true`; every existing invalidation stays. Called after a
 * passing front proof (frontQualify.record) and by the reconcile sweep below.
 * L4 accounts always answer `not_l7`.
 */
export async function evaluateAutoQualificationFor(
  ctx: QualificationCtx,
  accountId: Id<'edgeProviderAccounts'>,
  now = Date.now(),
): Promise<{ qualified: boolean; code: string | null }> {
  const row = await ctx.db.get(accountId);
  if (!row) return { qualified: false, code: 'account_not_found' };
  const locations = await locationsOfAccount(ctx.db, row._id);
  if (locations.length === 0) return { qualified: false, code: 'no_location' };
  // Every location is judged; the answer is the default location's (an
  // account with one location reads exactly as before locations existed).
  const dflt = await defaultLocationOf(ctx.db, row);
  let answer: { qualified: boolean; code: string | null } | null = null;
  for (const loc of locations) {
    const r = await evaluateAutoQualificationForLocation(ctx, row, loc, now);
    if (!answer || loc._id === dflt?._id) answer = r;
  }
  return answer!;
}

/**
 * The reconcile sweep: every enabled, untrusted, unheld location of an
 * enabled L7 account is evaluated (bounded: the tables are operator-scale).
 * L4 locations are never looked at here; they are trusted only by an operator.
 */
export const reconcileAutoQualification = internalMutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    let evaluated = 0;
    let qualified = 0;
    for (const row of await ctx.db.query('edgeProviderAccounts').collect()) {
      if (!row.enabled || edgeLayerOf(row.provider) !== 'l7') continue;
      for (const loc of await locationsOfAccount(ctx.db, row._id)) {
        if (!loc.enabled || loc.qualified || loc.autoQualifyHold) continue;
        evaluated++;
        if ((await evaluateAutoQualificationForLocation(ctx, row, loc, now)).qualified) qualified++;
      }
    }
    return { evaluated, qualified };
  },
});

/** Stamp a credential test outcome: a code, plus the redacted provider answer on a failure. */
export const recordTest = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    ok: v.boolean(),
    code: v.optional(v.string()),
    detail: v.optional(v.string()),
    /**
     * Facts the test read at the provider that planning needs but the operator
     * never enters (a zone's encryption mode, its WebSocket switch). Stored so a
     * rotation can freeze them into an edge's intent instead of guessing.
     */
    observed: v.optional(v.record(v.string(), v.string())),
  },
  handler: async (ctx, { id, ok, code, detail, observed }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const now = Date.now();
    await ctx.db.patch(id, {
      ...(ok
        ? { lastTestOkAt: now, lastTestError: undefined, lastTestErrorDetail: undefined }
        : {
            lastTestError: (code ?? 'error').slice(0, 64),
            lastTestErrorDetail: detail ? detail.slice(0, 700) : undefined,
          }),
      // A test that observed nothing leaves the previous observation alone: an
      // adapter with no facts to report is not evidence that the zone changed.
      ...(observed && Object.keys(observed).length > 0
        ? { observedSettings: JSON.stringify(observed).slice(0, 4_000), observedAt: now }
        : {}),
      updatedAt: now,
    });
    return null;
  },
});

/**
 * The account's shared certificate as the provider last showed it
 * (edgeProviderOps.refreshSharedCertificate). `null` clears it: the account no
 * longer uses one. Writes only when something but the check time moved.
 */
export const recordSharedCertificate = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    status: v.union(
      v.null(),
      v.object({
        name: v.string(),
        subscriptionId: v.optional(v.string()),
        state: v.string(),
        code: v.optional(v.string()),
        notAfter: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, { id, status }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    if (status === null) {
      if (row.sharedCertificate) await ctx.db.patch(id, { sharedCertificate: undefined });
      return null;
    }
    const { checkedAt: _at, ...was } = row.sharedCertificate ?? { checkedAt: 0 };
    const next = {
      name: status.name.slice(0, 253),
      ...(status.subscriptionId ? { subscriptionId: status.subscriptionId.slice(0, 64) } : {}),
      state: status.state.slice(0, 32),
      ...(status.code ? { code: status.code.slice(0, 64) } : {}),
      ...(status.notAfter ? { notAfter: status.notAfter.slice(0, 40) } : {}),
    };
    // `updatedAt` is left alone: it is the row version a credential rotation compares against.
    if (settingsEqual(was, next) && row.sharedCertificate) {
      await ctx.db.patch(id, {
        sharedCertificate: { ...row.sharedCertificate, checkedAt: Date.now() },
      });
      return null;
    }
    await ctx.db.patch(id, { sharedCertificate: { ...next, checkedAt: Date.now() } });
    return null;
  },
});

/** An issued shared certificate is read again this often; one still waiting, every pass. */
export const SHARED_CERTIFICATE_RECHECK_MS = 30 * 60_000;

/**
 * The accounts whose shared certificate the reconcile cron reads now: an
 * account that uses one (its settings say so) or still records one (so one
 * switched back is cleared), when it has not been read yet, is not issued, or
 * was last read longer ago than the recheck interval.
 */
export const listForSharedCertificates = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const rows = await ctx.db.query('edgeProviderAccounts').collect();
    const usesSharedCertificate = new Set<string>();
    for (const r of rows)
      if (
        EDGE_PROVIDER_CAPABILITIES[r.provider].sharedCertificates &&
        (await sharedCertificateUsers(ctx.db, r._id)) > 0
      )
        usesSharedCertificate.add(r._id as string);
    return rows
      .filter((r) => {
        if (!EDGE_PROVIDER_CAPABILITIES[r.provider].sharedCertificates) return false;
        // The account's default, or a node that chose the wildcard there.
        const uses =
          accountOptionDefaultsOf(r).certificateScope === 'wildcard' ||
          usesSharedCertificate.has(r._id as string);
        const sc = r.sharedCertificate;
        if (!uses && !sc) return false;
        if (!sc) return true;
        const settled = sc.state === 'issued' || sc.state === 'renewing';
        return !settled || !uses || now - sc.checkedAt >= SHARED_CERTIFICATE_RECHECK_MS;
      })
      .map((r) => r._id);
  },
});

/** The live edges of an account that front through its shared wildcard (their intent says so). */
export async function sharedCertificateUsers(
  db: QueryCtx['db'],
  accountId: Id<'edgeProviderAccounts'>,
): Promise<number> {
  const edges = await liveEdgesOfAccount(db, accountId);
  return edges.filter((e) => parseIntent(e.provisionIntent)?.certificateScope === 'wildcard')
    .length;
}

/** A provider failing this many calls in a row is raised as attention `account_api_failing`. */
export const API_FAILING_AFTER = 3;

/**
 * One provider API outcome of an account (edgeProviderOps `tracked`): a
 * provider-side failure counts, a success resets the run. Writes only when the
 * count moves, so a healthy account costs nothing. `updatedAt` is left alone:
 * it is the row version a credential rotation compares against.
 */
export const recordApiOutcome = internalMutation({
  args: { id: v.id('edgeProviderAccounts'), failure: v.union(v.string(), v.null()) },
  handler: async (ctx, { id, failure }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const now = Date.now();
    if (failure === null) {
      if ((row.apiFailures ?? 0) === 0) return null;
      await ctx.db.patch(id, {
        apiFailures: 0,
        apiFailingSince: undefined,
        lastApiError: undefined,
      });
      return null;
    }
    await ctx.db.patch(id, {
      apiFailures: (row.apiFailures ?? 0) + 1,
      apiFailingSince: row.apiFailingSince ?? now,
      lastApiError: failure.slice(0, 64),
    });
    return null;
  },
});

/** Store the latest provider inventory pull of one location (the account's default when none is named). */
export const recordInventory = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    locationId: v.optional(v.id('edgeLocations')),
    inventory: v.string(),
  },
  handler: async (ctx, { id, locationId, inventory }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const loc = locationId ? await ctx.db.get(locationId) : await defaultLocationOf(ctx.db, row);
    if (!loc || loc.accountId !== row._id) return null;
    await ctx.db.patch(loc._id, {
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

/**
 * Deploy step (seedCutover): option defaults an account still keeps under
 * `settings` (the Fastly authority from before provider options) move into
 * `optionDefaults`. The account's effective configuration is unchanged, so its
 * trust, `credentialsChangedAt` and every location stay as they are. Idempotent:
 * a row without such a key is left alone.
 */
export const migrateOptionDefaults = internalMutation({
  args: {},
  handler: async (ctx) => {
    let moved = 0;
    for (const row of await ctx.db.query('edgeProviderAccounts').collect()) {
      const legacy = legacyOptionDefaults(row.provider, row.settings as Record<string, unknown>);
      const keys = Object.keys(legacy);
      if (keys.length === 0) continue;
      const settings = Object.fromEntries(
        Object.entries(row.settings as Record<string, unknown>).filter(([k]) => !keys.includes(k)),
      );
      await ctx.db.patch(row._id, {
        settings: settings as never,
        optionDefaults: storedOptions(accountOptionDefaultsOf(row)),
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.provider_account.options_migrated',
        targetType: 'edge_provider_account',
        targetId: row._id,
        payload: { name: row.name, provider: row.provider, keys },
      });
      moved++;
    }
    return { moved };
  },
});
