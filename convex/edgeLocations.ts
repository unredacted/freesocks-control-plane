/**
 * Edge LOCATIONS (docs/edges.md § "Provider accounts and locations"): one
 * account's place to create edges in. An account is a provider plus
 * credentials; a location is the placement (region / zone / project /
 * network) it provisions in, chosen when a node is protected or an address is
 * added. Every edge freezes its location's placement (`edges.placement`), so
 * a describe or a destroy always acts in the edge's own region.
 *
 * Trust lives here, per location: automatic selection only uses trusted
 * locations, and a new region is trusted by its first tested address (or a
 * passing L7 proof), bound to the effective template it was taken with. An
 * account's credential or settings edit untrusts all of its locations.
 *
 * A CDN account (L7) has one location per DNS zone it fronts in (a Fastly
 * front also names the DNS account writing its records and its TLS
 * configuration); every one keeps the place key `anycast`, since a CDN's zones
 * share its address ranges. A zone location is checked with the provider when
 * it is created and whenever the account is tested (`recordCheck`). Rows are
 * operator-scale.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx, QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { MAX_LIVE_EDGES_CEILING } from '../src/shared/contracts/edgeLimits';
import { ACCOUNT_EDGE_SCAN_LIMIT, EDGE_LIVE_STATUSES } from './lib/edges/pool';
import {
  placementKeysOf,
  validatePlacement,
  type EdgePlacement,
} from './lib/edges/accountSettings';
import {
  ANYCAST_PLACE,
  locationKeyOf,
  parseRegionalParams,
  placeKeyOf,
  placementHashOf,
  regionalParamsOf,
} from './lib/edges/locations';
import { resolveTemplateFor, type TemplateLocation } from './edgeTemplates';
import { EDGE_TEMPLATES } from './lib/edges/providers/templates';
import { SIZE_NOT_MULTICLOUD_WORDS, sizeCheckApplies, sizeProblemOf } from './lib/edges/sizeCheck';
import { assertAdmission } from './lib/edges/maintenance';
import { autoQualifyDecision, type AutoQualifyEvidence } from './lib/edges/autoQualify';
import { verificationEndpoint } from './lib/edges/verification';
import type { EdgeProviderId } from './lib/edgeProviderIds';
import { EDGE_PROVIDER_CAPABILITIES, edgeLayerOf } from './lib/edges/providers/capabilities';
import {
  removableSharedCertificate,
  sharedCertificateOrderedByFcp,
} from './lib/edges/sharedCertificate';
import { parseIntent, parseObservedSettings } from './lib/edges/intent';
import { deletePlansOfLocation, locationCostAdmin, type LocationCostAdmin } from './edgePlans';
import { sizeKeyOf } from './lib/edges/pricing';

export type Location = Doc<'edgeLocations'>;
type Account = Doc<'edgeProviderAccounts'>;

// --- reads (helpers) ---------------------------------------------------------------------

/** Every location of an account, oldest first. */
export async function locationsOfAccount(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<Location[]> {
  const rows = await db
    .query('edgeLocations')
    .withIndex('by_account', (q) => q.eq('accountId', accountId))
    .collect();
  return rows.sort((a, b) => a.createdAt - b.createdAt || a._creationTime - b._creationTime);
}

/**
 * The location pickers preselect and the account-level calls act on: the
 * account's `defaultLocationId` when it still names one of its own rows, else
 * its first enabled location, else its first one, else none.
 */
export async function defaultLocationOf(
  db: DatabaseReader,
  account: Pick<Account, '_id' | 'defaultLocationId'>,
): Promise<Location | null> {
  if (account.defaultLocationId) {
    const row = await db.get(account.defaultLocationId);
    if (row && row.accountId === account._id) return row;
  }
  const rows = await locationsOfAccount(db, account._id);
  return rows.find((r) => r.enabled) ?? rows[0] ?? null;
}

/** The location an edge was created in (null for an adopted edge without an account). */
export async function locationOfEdge(
  db: DatabaseReader,
  edge: Pick<Doc<'edges'>, 'locationId'>,
): Promise<Location | null> {
  return edge.locationId ? db.get(edge.locationId) : null;
}

/** Non-destroyed edges in this location, exact up to the live-edge ceiling. */
export async function liveEdgesOfLocation(
  db: DatabaseReader,
  location: Pick<Location, '_id'>,
): Promise<Doc<'edges'>[]> {
  const out: Doc<'edges'>[] = [];
  for (const status of EDGE_LIVE_STATUSES) {
    out.push(
      ...(await db
        .query('edges')
        .withIndex('by_location_status', (q) =>
          q.eq('locationId', location._id).eq('status', status),
        )
        .take(ACCOUNT_EDGE_SCAN_LIMIT)),
    );
  }
  return out;
}

/** Managed live edges in this location (the `maxLiveEdges` regional cap). */
export async function liveCountForLocation(
  db: DatabaseReader,
  location: Pick<Location, '_id'>,
): Promise<number> {
  return (await liveEdgesOfLocation(db, location)).filter((e) => e.managed).length;
}

/** The template a location provisions with now (its default, else its account's), regional values laid over. */
export async function effectiveTemplateOfLocation(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId'>,
  location: Pick<Location, 'defaultTemplateId' | 'regionalParams'> | null,
  explicitId?: Id<'edgeTemplates'> | null,
) {
  return resolveTemplateFor(
    ctx,
    account.provider,
    explicitId ?? null,
    account.defaultTemplateId ?? null,
    account._id,
    location,
  );
}

/**
 * Why the size this location builds with (its template, its regional values)
 * cannot front an FCP node, or null (`sizeProblemOf`: a Scaleway size that is
 * not multi-cloud). A node's own options are checked with its pick
 * (`checkPickOptions`) and at selection.
 */
export async function sizeProblemOfLocation(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId'>,
  location: Pick<Location, 'defaultTemplateId' | 'regionalParams' | 'inventorySnapshot'>,
): Promise<string | null> {
  if (!sizeCheckApplies(account.provider)) return null;
  const tpl = await effectiveTemplateOfLocation(ctx, account, location);
  return sizeProblemOf(account.provider, tpl.params, location.inventorySnapshot);
}

/**
 * A front location of a provider that writes its records through a DNS
 * account must name one that exists, hosts DNS and is switched on: a dangling
 * or wrong-kind reference would only surface at provision time, with a
 * paid-for front half-created.
 */
export async function assertDnsAccountOfPlacement(
  db: DatabaseReader,
  provider: EdgeProviderId,
  placement: unknown,
): Promise<void> {
  if (!EDGE_PROVIDER_CAPABILITIES[provider].needsDnsAccount) return;
  const ref = (placement as { dnsAccountId?: unknown } | null)?.dnsAccountId;
  const id = typeof ref === 'string' ? db.normalizeId('edgeProviderAccounts', ref) : null;
  const row = id ? await db.get(id) : null;
  if (!row || !EDGE_PROVIDER_CAPABILITIES[row.provider].providesDns)
    throw new ConvexError({
      code: 'edge.dns_account_unusable',
      message: 'Pick a DNS account that can host DNS records',
    });
  if (!row.enabled)
    throw new ConvexError({
      code: 'edge.dns_account_unusable',
      message: 'That DNS account is switched off',
    });
}

// --- writes (helpers) --------------------------------------------------------------------

export interface LocationExtras {
  label?: string;
  regionalParams?: Record<string, string>;
  maxLiveEdges?: number;
  costNote?: string;
  /** What the provider said about the place when it was checked (a zone's encryption mode). */
  observed?: Record<string, string>;
}

/** The name a location gets when nobody gave one: a CDN place's zone, else the region id. */
function defaultLabelOf(placement: EdgePlacement, placeKey: string): string {
  const zoneName = (placement as { zoneName?: string }).zoneName;
  if (zoneName) return zoneName;
  return placeKey === ANYCAST_PLACE ? 'Anycast' : placeKey;
}

function observedJson(observed: Record<string, string> | undefined): string | undefined {
  return observed && Object.keys(observed).length > 0
    ? JSON.stringify(observed).slice(0, 4_000)
    : undefined;
}

function cleanLabel(raw: string | undefined, fallback: string): string {
  const s = (raw ?? '').replace(/\s+/g, ' ').trim().slice(0, 80);
  return s.length > 0 ? s : fallback;
}

function cleanCostNote(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const s = raw.replace(/\s+/g, ' ').trim().slice(0, 120);
  return s.length > 0 ? s : undefined;
}

function checkLocationCap(n: number | undefined): void {
  if (n !== undefined && (!Number.isInteger(n) || n < 1 || n > MAX_LIVE_EDGES_CEILING))
    throw new ConvexError({
      code: 'validation',
      message: `maxLiveEdges must be 1..${MAX_LIVE_EDGES_CEILING}`,
    });
}

/**
 * Create a location for an account, or return the existing one with the same
 * placement (`by_account_placement`). The first location of an account
 * becomes its default. Audited `edge.location.created` (never the placement).
 */
export async function upsertLocation(
  ctx: MutationCtx,
  account: Account,
  rawPlacement: Record<string, unknown> | EdgePlacement,
  extras: LocationExtras = {},
  opts: { actorAdminId?: Id<'adminUsers'>; quiet?: boolean } = {},
): Promise<{ id: Id<'edgeLocations'>; created: boolean }> {
  const parsed = validatePlacement(account.provider, rawPlacement);
  if (!parsed.ok) throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
  const placement = parsed.placement;
  const placementHash = placementHashOf(placement);
  const existing = await ctx.db
    .query('edgeLocations')
    .withIndex('by_account_placement', (q) =>
      q.eq('accountId', account._id).eq('placementHash', placementHash),
    )
    .first();
  if (existing) return { id: existing._id, created: false };
  checkLocationCap(extras.maxLiveEdges);
  const placeKey = placeKeyOf(placement);
  const regional = regionalParamsOf(account.provider, extras.regionalParams ?? {});
  const now = Date.now();
  const id = await ctx.db.insert('edgeLocations', {
    accountId: account._id,
    provider: account.provider,
    placeKey,
    placement: placement as never,
    placementHash,
    label: cleanLabel(extras.label, defaultLabelOf(placement, placeKey)),
    enabled: true,
    qualified: false,
    ...(Object.keys(regional).length > 0 ? { regionalParams: JSON.stringify(regional) } : {}),
    ...(extras.maxLiveEdges !== undefined ? { maxLiveEdges: extras.maxLiveEdges } : {}),
    ...(cleanCostNote(extras.costNote) ? { costNote: cleanCostNote(extras.costNote) } : {}),
    ...(observedJson(extras.observed)
      ? { observed: observedJson(extras.observed), observedAt: now }
      : {}),
    createdAt: now,
    updatedAt: now,
  });
  if (!account.defaultLocationId) await ctx.db.patch(account._id, { defaultLocationId: id });
  if (!opts.quiet)
    await writeAuditLog(ctx, {
      actorType: opts.actorAdminId ? 'admin' : 'system',
      actorId: opts.actorAdminId,
      action: 'edge.location.created',
      targetType: 'edge_provider_account',
      targetId: account._id,
      payload: { name: account.name, provider: account.provider, placeKey },
    });
  return { id, created: true };
}

/**
 * The location an account created with its old single-location shape gets at
 * once: the placement keys its settings carried (a region, or a CDN's zone).
 * Null when the payload names no place (the operator adds one later, or picks
 * one when a node is protected).
 */
export function initialPlacementOf(
  provider: EdgeProviderId,
  rawSettings: Record<string, unknown> | undefined,
): Record<string, unknown> | null {
  const keys = placementKeysOf(provider, rawSettings);
  if (!keys) return null;
  // A CDN place starts at its zone (or a front's DNS account): a leftover zone
  // name or TLS configuration alone names no place.
  if (
    edgeLayerOf(provider) === 'l7' &&
    keys.zoneId === undefined &&
    keys.dnsAccountId === undefined
  )
    return null;
  return { ...keys, type: provider };
}

// --- trust ---------------------------------------------------------------------------------

/**
 * Trust a location: the ONLY writer of `qualified: true`. The hash recorded is
 * the one of the template this location provisions with NOW, never a
 * client-supplied value: the template-edit invalidation keys off it. `by`
 * says who took the trust: an operator (the trust override, or the first
 * confirmed L4 endpoint here, which carries endpoint evidence) or the L7
 * auto-trust rule. Trusting clears a manual hold.
 */
export async function applyLocationQualification(
  ctx: MutationCtx,
  account: Account,
  location: Location,
  opts: {
    by: 'admin' | 'auto';
    actorAdminId?: Id<'adminUsers'>;
    evidence?: Omit<AutoQualifyEvidence, 'proofCheckedAt'> & { proofCheckedAt?: number };
  },
): Promise<void> {
  const effective = await effectiveTemplateOfLocation(ctx, account, location);
  const now = Date.now();
  await ctx.db.patch(location._id, {
    qualified: true,
    qualifiedTemplateHash: effective.hash,
    qualification: {
      by: opts.by,
      at: now,
      ...(opts.evidence
        ? {
            evidence: {
              edgeId: opts.evidence.edgeId as Id<'edges'>,
              endpoint: opts.evidence.endpoint,
              accountTestedAt: opts.evidence.accountTestedAt,
              templateHash: opts.evidence.templateHash,
              listenerId: opts.evidence.listenerId as Id<'relayListeners'>,
              listenerRevision: opts.evidence.listenerRevision,
              ...(opts.evidence.proofCheckedAt !== undefined
                ? { proofCheckedAt: opts.evidence.proofCheckedAt }
                : {}),
            },
          }
        : {}),
    },
    autoQualifyHold: undefined,
    updatedAt: now,
  });
  await writeAuditLog(ctx, {
    actorType: opts.by === 'admin' ? 'admin' : 'system',
    actorId: opts.actorAdminId ?? undefined,
    action:
      opts.by === 'auto'
        ? 'edge.provider_account.auto_qualified'
        : 'edge.provider_account.qualified',
    targetType: 'edge_provider_account',
    targetId: account._id,
    // Ids only: never the endpoint.
    payload: {
      name: account.name,
      provider: account.provider,
      qualified: true,
      placeKey: location.placeKey,
      ...(opts.evidence ? { edgeId: opts.evidence.edgeId, endpointEvidence: true } : {}),
    },
  });
}

/**
 * Untrust one location. `hold` (a manual untrust) keeps the automatic rules
 * off until an operator trusts again or the account's credentials change.
 */
export async function untrustLocation(
  ctx: MutationCtx,
  account: Account,
  location: Location,
  opts: { hold?: boolean; actorAdminId?: Id<'adminUsers'> } = {},
): Promise<void> {
  await ctx.db.patch(location._id, {
    qualified: false,
    qualifiedTemplateHash: undefined,
    qualification: undefined,
    ...(opts.hold ? { autoQualifyHold: true } : {}),
    updatedAt: Date.now(),
  });
  await writeAuditLog(ctx, {
    actorType: 'admin',
    actorId: opts.actorAdminId ?? undefined,
    action: 'edge.provider_account.qualified',
    targetType: 'edge_provider_account',
    targetId: account._id,
    payload: {
      name: account.name,
      provider: account.provider,
      qualified: false,
      placeKey: location.placeKey,
    },
  });
}

/**
 * An account edit (credentials, settings, its default template) changes what
 * every location of it provisions with: each trusted one is untrusted
 * (audited), and `releaseHolds` clears the manual holds so the automatic
 * rules may look again once a test after the change passes. `onlyFallingBack`
 * limits it to the locations that use the account's default template.
 */
export async function untrustAccountLocations(
  ctx: MutationCtx,
  account: Account,
  opts: {
    actorAdminId?: Id<'adminUsers'>;
    releaseHolds?: boolean;
    onlyFallingBack?: boolean;
  } = {},
): Promise<number> {
  let n = 0;
  for (const loc of await locationsOfAccount(ctx.db, account._id)) {
    if (opts.onlyFallingBack && loc.defaultTemplateId) continue;
    if (loc.qualified) {
      await untrustLocation(ctx, account, loc, { actorAdminId: opts.actorAdminId });
      n++;
    }
    if (opts.releaseHolds && loc.autoQualifyHold)
      await ctx.db.patch(loc._id, { autoQualifyHold: undefined, updatedAt: Date.now() });
  }
  return n;
}

/**
 * The L7 auto-trust rule (lib/edges/autoQualify.ts) for ONE location: trusts
 * it when an active edge there carries a current authenticated proof for the
 * location's effective template NOW. Only ever sets `qualified: true`. L4
 * locations always answer `not_l7`.
 */
export async function evaluateAutoQualificationForLocation(
  ctx: MutationCtx,
  account: Account,
  location: Location,
  now = Date.now(),
): Promise<{ qualified: boolean; code: string | null }> {
  if (!account.enabled) return { qualified: location.qualified, code: 'account_disabled' };
  if (!location.enabled) return { qualified: location.qualified, code: 'location_disabled' };
  const effective = await effectiveTemplateOfLocation(ctx, account, location);
  const candidates = [];
  for (const e of await liveEdgesOfLocation(ctx.db, location)) {
    const listener = await ctx.db.get(e.listenerId);
    if (!listener || listener.retired) continue;
    candidates.push({
      id: e._id as string,
      status: e.status,
      layer: e.layer ?? edgeLayerOf(e.provider),
      // The location's own template for an edge built with a node's choices.
      templateHash: e.baseTemplateHash ?? e.templateHash ?? null,
      listenerId: e.listenerId as string,
      listenerRevision: listener.revision,
      endpoint: verificationEndpoint(e),
      frontQualification: e.frontQualification
        ? {
            ok: e.frontQualification.ok,
            checkedAt: e.frontQualification.checkedAt,
            expiresAt: e.frontQualification.expiresAt,
            binding: {
              listenerId: e.frontQualification.binding.listenerId as string,
              listenerRevision: e.frontQualification.binding.listenerRevision,
            },
          }
        : null,
    });
  }
  const decision = autoQualifyDecision(
    {
      layer: edgeLayerOf(account.provider),
      qualified: location.qualified,
      autoQualifyHold: location.autoQualifyHold ?? false,
      lastTestOkAt: account.lastTestOkAt ?? null,
      lastTestError: account.lastTestError ?? null,
      credentialsChangedAt: account.credentialsChangedAt ?? null,
      dependencyChangedAt: account.dependencyChangedAt ?? null,
      effectiveTemplateHash: effective.hash,
    },
    candidates,
    now,
  );
  if (!decision.ok) return { qualified: location.qualified, code: decision.code };
  await applyLocationQualification(ctx, account, location, {
    by: 'auto',
    evidence: decision.evidence,
  });
  return { qualified: true, code: null };
}

// --- admin view ------------------------------------------------------------------------------

/** Admin-safe view of one location (the placement is admin data: region / project / network ids). */
export function mapLocationAdmin(
  r: Location,
  extras: {
    liveEdges: number;
    isDefault: boolean;
    sharedUsers?: number;
    orderedByFcp?: boolean;
    pricing?: LocationCostAdmin;
  },
) {
  const { type: _t, ...placement } = r.placement as { type: string } & Record<string, unknown>;
  return {
    id: r._id as string,
    accountId: r.accountId as string,
    provider: r.provider,
    placeKey: r.placeKey,
    locationKey: locationKeyOf(r.provider, r.placeKey),
    label: r.label,
    placement,
    enabled: r.enabled,
    isDefault: extras.isDefault,
    qualified: r.qualified,
    qualifiedTemplateHash: r.qualifiedTemplateHash ?? null,
    qualification: r.qualification
      ? {
          by: r.qualification.by,
          at: new Date(r.qualification.at).toISOString(),
          edgeId: (r.qualification.evidence?.edgeId as string | undefined) ?? null,
          proofCheckedAt: r.qualification.evidence?.proofCheckedAt
            ? new Date(r.qualification.evidence.proofCheckedAt).toISOString()
            : null,
        }
      : null,
    autoQualifyHold: r.autoQualifyHold === true,
    defaultTemplateId: (r.defaultTemplateId as string | undefined) ?? null,
    regionalParams: parseRegionalParams(r.provider, r.regionalParams),
    maxLiveEdges: r.maxLiveEdges ?? null,
    liveEdges: extras.liveEdges,
    costNote: r.costNote ?? null,
    inventoryAt: r.inventoryAt ? new Date(r.inventoryAt).toISOString() : null,
    observed: r.observed ? parseObservedSettings(r.observed) : null,
    observedAt: r.observedAt ? new Date(r.observedAt).toISOString() : null,
    checkError: r.checkError ?? null,
    checkErrorDetail: r.checkErrorDetail ?? null,
    // The wildcard certificate the fronts in this zone share, as last read at
    // the provider, and how many live edges front through it (null: none).
    sharedCertificate: r.sharedCertificate
      ? {
          name: r.sharedCertificate.name,
          state: r.sharedCertificate.state,
          code: r.sharedCertificate.code ?? null,
          notAfter: r.sharedCertificate.notAfter ?? null,
          checkedAt: new Date(r.sharedCertificate.checkedAt).toISOString(),
          edges: extras.sharedUsers ?? 0,
          // FCP ordered it (only then can it be removed from the account page).
          orderedByFcp: extras.orderedByFcp === true,
        }
      : null,
    // Its plans and prices, and what one edge here costs now (`edgePlans`).
    pricing: extras.pricing ?? null,
    createdAt: new Date(r.createdAt).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export type LocationAdmin = ReturnType<typeof mapLocationAdmin>;

/** Every location of an account in its admin shape (default first, then oldest first). */
export async function locationsAdminOf(
  db: DatabaseReader,
  account: Pick<
    Account,
    | '_id'
    | 'provider'
    | 'defaultTemplateId'
    | 'defaultLocationId'
    | 'orderedSharedResources'
    | 'cost'
  >,
): Promise<LocationAdmin[]> {
  const dflt = await defaultLocationOf(db, account);
  const out: LocationAdmin[] = [];
  for (const r of await locationsOfAccount(db, account._id)) {
    out.push(
      mapLocationAdmin(r, {
        liveEdges: await liveCountForLocation(db, r),
        isDefault: !!dflt && dflt._id === r._id,
        sharedUsers: r.sharedCertificate ? await sharedCertificateUsers(db, r) : 0,
        // An edge of the account created it (lib/edges/sharedCertificate.ts).
        orderedByFcp: sharedCertificateOrderedByFcp(
          account.orderedSharedResources,
          r.sharedCertificate,
        ),
        pricing: await locationCostAdmin({ db }, account, r),
      }),
    );
  }
  return out.sort((a, b) => Number(b.isDefault) - Number(a.isDefault));
}

// --- queries ---------------------------------------------------------------------------------

export const listForAccount = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }) => {
    const account = await ctx.db.get(accountId);
    return account ? locationsAdminOf(ctx.db, account) : [];
  },
});

/** What a provider action needs to act in a location: its account and its placement. */
export const getForOps = internalQuery({
  args: { id: v.id('edgeLocations') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    return {
      id: r._id,
      accountId: r.accountId,
      provider: r.provider,
      placeKey: r.placeKey,
      placement: r.placement as Record<string, unknown>,
      defaultTemplateId: r.defaultTemplateId ?? null,
      regionalParams: r.regionalParams ?? null,
    };
  },
});

/**
 * The placement an EXISTING edge acts in: its own frozen copy (null for an
 * edge without one, which `loadAdapter` refuses for a placed provider).
 */
export const placementOfEdge = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const e = await ctx.db.get(edgeId);
    return e?.placement ? (e.placement as Record<string, unknown>) : null;
  },
});

/** The default location of an account (ops: inventory, adoption without a named location). */
export const defaultOf = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }) => {
    const account = await ctx.db.get(accountId);
    const loc = account ? await defaultLocationOf(ctx.db, account) : null;
    return loc ? loc._id : null;
  },
});

/** The stored inventory snapshot of one location (addresses are public client-facing data). */
export const getInventory = internalQuery({
  args: { id: v.id('edgeLocations') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    return inventoryView(ctx, r);
  },
});

/** A location's inventory with `unowned` marked (no live edge ledger references the LB). */
export async function inventoryView(ctx: { db: QueryCtx['db'] }, r: Location) {
  let inventory: { loadBalancers?: Array<Record<string, unknown>> } | null = null;
  if (r.inventorySnapshot) {
    try {
      inventory = JSON.parse(r.inventorySnapshot);
    } catch {
      inventory = null;
    }
  }
  if (inventory && Array.isArray(inventory.loadBalancers)) {
    // `unowned` = no live edge ledger references the LB: what the origin import
    // picker offers first (an owned one is already an edge).
    const owned = new Set<string>();
    for (const e of await ctx.db
      .query('edges')
      .withIndex('by_account_status', (q) => q.eq('accountId', r.accountId))
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
    locationId: r._id as string,
    inventory,
    inventoryAt: r.inventoryAt ? new Date(r.inventoryAt).toISOString() : null,
  };
}

// --- mutations -------------------------------------------------------------------------------

/**
 * Create a location (the action `edgeProviderOps.createLocation` checked the
 * region is offered to this key and read its label first). Returns the
 * existing row for a placement the account already has.
 */
/**
 * The required per-region template values a location would provision without:
 * empty both in the template it resolves and in its own overlay (an OVH load
 * balancer needs a flavor id, and which ones exist depends on the region).
 * Returns the field labels.
 */
async function missingRegionalValues(
  db: DatabaseReader,
  account: Doc<'edgeProviderAccounts'>,
  location: TemplateLocation,
): Promise<string[]> {
  const required = EDGE_TEMPLATES[account.provider].fields.filter((f) => f.regional && f.required);
  if (required.length === 0) return [];
  const eff = await resolveTemplateFor(
    { db },
    account.provider,
    null,
    account.defaultTemplateId ?? null,
    account._id,
    location,
  );
  return required
    .filter((f) => {
      const value = eff.params[f.key];
      return value === undefined || value === null || String(value).trim() === '';
    })
    .map((f) => f.label);
}

function refuseMissingRegional(missing: string[]): void {
  if (missing.length > 0)
    throw new ConvexError({
      code: 'edge.template_value_required',
      message: `Choose ${missing.join(', ')} for this region: the template leaves it empty`,
    });
}

/**
 * A size chosen for a location that cannot carry an FCP node there (a
 * Scaleway size that takes Scaleway's own servers only) is refused when it is
 * chosen, in the plan picker's words, before any edge would be planned on it.
 */
function refuseSizeOf(
  location: Pick<Location, 'provider' | 'inventorySnapshot'>,
  regionalParams: Record<string, string>,
): void {
  const key = sizeKeyOf(location.provider);
  const size = key ? regionalParams[key] : undefined;
  if (!key || !size) return;
  const problem = sizeProblemOf(location.provider, { [key]: size }, location.inventorySnapshot);
  if (problem)
    throw new ConvexError({ code: `edge.${problem}`, message: SIZE_NOT_MULTICLOUD_WORDS });
}

export const create = internalMutation({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    placement: v.any(),
    label: v.optional(v.string()),
    regionalParams: v.optional(v.any()),
    maxLiveEdges: v.optional(v.number()),
    costNote: v.optional(v.string()),
    observed: v.optional(v.record(v.string(), v.string())),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const account = await ctx.db.get(a.accountId);
    if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    await assertDnsAccountOfPlacement(ctx.db, account.provider, a.placement);
    const regionalParams = regionalParamsOf(account.provider, a.regionalParams);
    refuseSizeOf({ provider: account.provider, inventorySnapshot: undefined }, regionalParams);
    refuseMissingRegional(
      await missingRegionalValues(ctx.db, account, {
        regionalParams:
          Object.keys(regionalParams).length > 0 ? JSON.stringify(regionalParams) : null,
      }),
    );
    const res = await upsertLocation(
      ctx,
      account,
      { ...((a.placement ?? {}) as Record<string, unknown>), type: account.provider },
      {
        label: a.label,
        regionalParams,
        maxLiveEdges: a.maxLiveEdges,
        costNote: a.costNote,
        observed: a.observed,
      },
      { actorAdminId: a.actorAdminId },
    );
    return { id: res.id as string, created: res.created };
  },
});

export const update = internalMutation({
  args: {
    id: v.id('edgeLocations'),
    enabled: v.optional(v.boolean()),
    label: v.optional(v.string()),
    maxLiveEdges: v.optional(v.union(v.number(), v.null())),
    costNote: v.optional(v.union(v.string(), v.null())),
    regionalParams: v.optional(v.any()),
    defaultTemplateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    makeDefault: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Location not found' });
    const account = await ctx.db.get(row.accountId);
    if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    const patch: Partial<Location> = { updatedAt: Date.now() };
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.label !== undefined) patch.label = cleanLabel(a.label, row.label);
    if (a.maxLiveEdges !== undefined) {
      checkLocationCap(a.maxLiveEdges ?? undefined);
      patch.maxLiveEdges = a.maxLiveEdges ?? undefined;
    }
    if (a.costNote !== undefined) patch.costNote = cleanCostNote(a.costNote ?? undefined);
    // What the location provisions with: a change re-opens its trust (the
    // parameters it was trusted with are not the ones it would use next).
    let templateMoved = false;
    if (a.regionalParams !== undefined) {
      const next = regionalParamsOf(row.provider, a.regionalParams);
      const prev = parseRegionalParams(row.provider, row.regionalParams);
      if (JSON.stringify(next) !== JSON.stringify(prev)) refuseSizeOf(row, next);
      patch.regionalParams = Object.keys(next).length > 0 ? JSON.stringify(next) : undefined;
      templateMoved ||= JSON.stringify(next) !== JSON.stringify(prev);
    }
    if (a.defaultTemplateId !== undefined) {
      if (a.defaultTemplateId) {
        const tpl = await ctx.db.get(a.defaultTemplateId);
        if (!tpl || tpl.provider !== row.provider)
          throw new ConvexError({
            code: 'validation',
            message: 'unknown template for this provider',
          });
        if (tpl.accountId && tpl.accountId !== row.accountId)
          throw new ConvexError({
            code: 'validation',
            message: 'that template is scoped to another account',
          });
      }
      patch.defaultTemplateId = a.defaultTemplateId ?? undefined;
      templateMoved ||= (a.defaultTemplateId ?? undefined) !== row.defaultTemplateId;
    }
    if (templateMoved)
      refuseMissingRegional(
        await missingRegionalValues(ctx.db, account, {
          defaultTemplateId:
            'defaultTemplateId' in patch ? patch.defaultTemplateId : row.defaultTemplateId,
          regionalParams: 'regionalParams' in patch ? patch.regionalParams : row.regionalParams,
        }),
      );
    await ctx.db.patch(row._id, patch);
    if (templateMoved && row.qualified)
      await untrustLocation(ctx, account, row, { actorAdminId: a.actorAdminId });
    if (a.makeDefault) await ctx.db.patch(account._id, { defaultLocationId: row._id });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.location.updated',
      targetType: 'edge_provider_account',
      targetId: account._id,
      payload: {
        name: account.name,
        provider: account.provider,
        placeKey: row.placeKey,
        enabled: patch.enabled ?? row.enabled,
      },
    });
    return { ok: true as const };
  },
});

/**
 * Locations still named after their bare region id (the migration had no
 * region name to copy from an account's settings): what `relabelLocations`
 * asks the provider about.
 */
export const unnamed = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out: Array<{
      id: Id<'edgeLocations'>;
      accountId: Id<'edgeProviderAccounts'>;
      placeKey: string;
    }> = [];
    for (const r of await ctx.db.query('edgeLocations').collect())
      if (r.placeKey !== ANYCAST_PLACE && r.label === r.placeKey)
        out.push({ id: r._id, accountId: r.accountId, placeKey: r.placeKey });
    return out;
  },
});

/** A location's readable name, as its provider lists it (quiet: a name only, nothing else moves). */
export const setLabel = internalMutation({
  args: { id: v.id('edgeLocations'), label: v.string() },
  handler: async (ctx, { id, label }) => {
    const row = await ctx.db.get(id);
    if (!row || row.label !== row.placeKey) return null;
    await ctx.db.patch(id, { label: cleanLabel(label, row.label), updatedAt: Date.now() });
    return null;
  },
});

/** Locations named by a node's provider set (operator-scale scan of the relays). */
async function setsReferencing(db: DatabaseReader, id: Id<'edgeLocations'>): Promise<number> {
  let n = 0;
  for (const r of await db.query('relays').collect())
    if ((r.providerSet ?? []).some((p) => p.locationId === id)) n++;
  return n;
}

/**
 * Open setup runs that picked a location: a run chooses its location before it
 * creates its first edge, so neither a live edge nor a provider set shows it yet.
 */
async function runsReferencing(db: DatabaseReader, id: Id<'edgeLocations'>): Promise<number> {
  let n = 0;
  for (const state of ['running', 'waiting', 'needs_you'] as const) {
    const rows = await db
      .query('edgeSetupRuns')
      .withIndex('by_state', (q) => q.eq('state', state))
      .collect();
    for (const r of rows)
      if (
        (r.picks ?? []).some((p) => p.locationId === id) ||
        r.listeners.some((l) => l.locationId === id)
      )
        n++;
  }
  return n;
}

/** Whether anything still depends on a location (a live edge, a node's provider set, an open setup run). */
export async function locationInUse(
  db: DatabaseReader,
  location: Location,
): Promise<{ edges: number; sets: number; runs: number }> {
  const edges = (await liveEdgesOfLocation(db, location)).length;
  return {
    edges,
    sets: await setsReferencing(db, location._id),
    runs: await runsReferencing(db, location._id),
  };
}

export const remove = internalMutation({
  args: { id: v.id('edgeLocations'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    await assertAdmission(ctx.db, 'provider.write');
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    const account = await ctx.db.get(row.accountId);
    const use = await locationInUse(ctx.db, row);
    if (use.edges > 0)
      throw new ConvexError({
        code: 'edge.location_in_use',
        message: 'Edges still live in this location; destroy them first',
      });
    if (use.sets > 0)
      throw new ConvexError({
        code: 'edge.location_in_use',
        message: 'A protected node still uses this location; remove it from the node first',
      });
    if (use.runs > 0)
      throw new ConvexError({
        code: 'edge.location_in_use',
        message: 'A node is being protected in this location; finish or cancel that first',
      });
    // Nor one whose wildcard FCP ordered is still at the provider: this row is
    // the only record of it, and the account's delete guard reads its zones.
    if (removableSharedCertificate(account?.orderedSharedResources, row.sharedCertificate))
      throw new ConvexError({
        code: 'edge.shared_certificate_present',
        message: 'This zone still has a shared certificate; remove it first',
      });
    await deletePlansOfLocation(ctx, id);
    await ctx.db.delete(id);
    if (account && account.defaultLocationId === id) {
      const next = (await locationsOfAccount(ctx.db, account._id))[0];
      await ctx.db.patch(account._id, { defaultLocationId: next?._id });
    }
    if (account)
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'edge.location.removed',
        targetType: 'edge_provider_account',
        targetId: account._id,
        payload: { name: account.name, provider: account.provider, placeKey: row.placeKey },
      });
    return { ok: true as const };
  },
});

/** The trust override for one location (an untrust holds the automatic rules off). */
export const setQualified = internalMutation({
  args: {
    id: v.id('edgeLocations'),
    qualified: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, qualified, actorAdminId }) => {
    await assertAdmission(ctx.db, 'provider.write');
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Location not found' });
    const account = await ctx.db.get(row.accountId);
    if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    if (qualified)
      await applyLocationQualification(ctx, account, row, { by: 'admin', actorAdminId });
    else await untrustLocation(ctx, account, row, { hold: true, actorAdminId });
    return { ok: true as const };
  },
});

/** Store the latest provider inventory pull for one location (admin-only JSON). */
export const recordInventory = internalMutation({
  args: { id: v.id('edgeLocations'), inventory: v.string() },
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
 * What a location check found (`edgeProviderOps.checkLocation`, a credential
 * test or rotation): the facts it observed replace the last ones (a check that
 * observed nothing leaves them alone), a refusal is recorded as `checkError`
 * (no new edge is planned there meanwhile), a pass clears it.
 */
export const recordCheck = internalMutation({
  args: {
    id: v.id('edgeLocations'),
    ok: v.boolean(),
    code: v.optional(v.string()),
    detail: v.optional(v.string()),
    observed: v.optional(v.record(v.string(), v.string())),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) return null;
    const now = Date.now();
    const observed = observedJson(a.observed);
    await ctx.db.patch(a.id, {
      ...(observed ? { observed, observedAt: now } : {}),
      ...(a.ok
        ? { checkError: undefined, checkErrorDetail: undefined }
        : {
            checkError: (a.code ?? 'error').slice(0, 64),
            checkErrorDetail: a.detail ? a.detail.slice(0, 700) : undefined,
          }),
      updatedAt: now,
    });
    return null;
  },
});

/**
 * The zones OTHER accounts write through this DNS account: the zones of the
 * front locations naming it, of live fronts whose intent names it, and the
 * origin-name zones of backend setups. A credential rotation reads each with
 * the new token before it is applied. `inUse`: a location there is switched on
 * or holds edges, a live front names it, or an origin name lives there (the
 * rotation must reach it); otherwise only switched-off fronts with nothing in
 * them name it (`locationIds`: they record a zone the new token cannot read).
 */
export const zonesWrittenThrough = internalQuery({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }) => {
    const zones = new Map<
      string,
      { zoneId: string; zoneName: string; inUse: boolean; locationIds: string[] }
    >();
    const add = (
      zoneId: string | undefined,
      zoneName: string | undefined,
      inUse: boolean,
      locationId?: string,
    ) => {
      if (!zoneId) return;
      const z = zones.get(zoneId) ?? { zoneId, zoneName: zoneName ?? '', inUse, locationIds: [] };
      z.inUse ||= inUse;
      if (locationId && !z.locationIds.includes(locationId)) z.locationIds.push(locationId);
      zones.set(zoneId, z);
    };
    // Every front that writes its records through a DNS account (Fastly, CloudFront).
    const writers = (Object.keys(EDGE_PROVIDER_CAPABILITIES) as EdgeProviderId[]).filter(
      (p) => EDGE_PROVIDER_CAPABILITIES[p].needsDnsAccount,
    );
    for (const provider of writers) {
      const rows = await ctx.db
        .query('edgeLocations')
        .withIndex('by_place', (q) => q.eq('provider', provider))
        .collect();
      for (const r of rows) {
        const p = r.placement as { dnsAccountId?: string; zoneId?: string; zoneName?: string };
        if (p.dnsAccountId !== (accountId as string)) continue;
        const live = await liveEdgesOfLocation(ctx.db, r);
        add(p.zoneId, p.zoneName, r.enabled || live.length > 0, r._id as string);
        for (const e of live) {
          const intent = parseIntent(e.provisionIntent);
          if (intent?.dnsAccountId === (accountId as string))
            add(intent.zoneId, intent.zoneName, true);
        }
      }
    }
    for (const setup of await ctx.db.query('panelSetups').collect())
      if (setup.originDns?.accountId === accountId)
        add(setup.originDns.zoneId, setup.originDns.zoneName, true);
    return [...zones.values()];
  },
});

/** The live edges in this location that front through its shared wildcard (their intent says so). */
export async function sharedCertificateUsers(
  db: DatabaseReader,
  location: Pick<Location, '_id'>,
): Promise<number> {
  return (await liveEdgesOfLocation(db, location)).filter(
    (e) => parseIntent(e.provisionIntent)?.certificateScope === 'wildcard',
  ).length;
}

/**
 * The certificate a live front in this location froze when it shares the
 * zone's wildcard (its intent's authority and scope), or null. A node may
 * choose the wildcard where the account's default is one per front: reading
 * the shared certificate must then follow that front, not the default.
 */
export const sharedCertificateChoice = internalQuery({
  args: { locationId: v.id('edgeLocations') },
  handler: async (ctx, { locationId }) => {
    const location = await ctx.db.get(locationId);
    if (!location) return null;
    for (const e of await liveEdgesOfLocation(ctx.db, location)) {
      const intent = parseIntent(e.provisionIntent);
      if (intent?.certificateScope !== 'wildcard') continue;
      return {
        certificateScope: 'wildcard',
        ...(intent.certificateAuthority
          ? { certificateAuthority: intent.certificateAuthority }
          : {}),
      };
    }
    return null;
  },
});

/**
 * The zone's shared certificate as the provider last showed it
 * (edgeProviderOps.refreshSharedCertificate). `null` clears it: no front here
 * uses one. Writes only when something but the check time moved.
 */
export const recordSharedCertificate = internalMutation({
  args: {
    id: v.id('edgeLocations'),
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
    if (JSON.stringify(was) === JSON.stringify(next) && row.sharedCertificate) {
      await ctx.db.patch(id, {
        sharedCertificate: { ...row.sharedCertificate, checkedAt: Date.now() },
      });
      return null;
    }
    await ctx.db.patch(id, { sharedCertificate: { ...next, checkedAt: Date.now() } });
    return null;
  },
});
