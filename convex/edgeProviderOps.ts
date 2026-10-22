'use node';
/**
 * Origin-edge provider operations — the "use node" half of the origin layer.
 *
 * Everything that talks to a cloud load-balancer provider's API (provisioning
 * steps, discovery, describe/inspect, inventory, destroy) runs here so provider
 * SDKs that assume a Node runtime can be used. This module holds ACTIONS ONLY
 * and each action is one bounded provider round trip: it loads the account
 * (with its credentials) through an internal query, builds the adapter config,
 * performs exactly the requested operation and returns plain data. Every state
 * change goes back through the isolate mutations (edgeRotations / edges),
 * which are the sole writers of origin state.
 *
 * Errors: an adapter throws `EdgeProviderError` (status + short code, never a
 * body/URL/credential), but a plain Error's extra fields do NOT survive
 * `ctx.runAction` — only `ConvexError.data` does. Every action is therefore
 * wrapped by `run()`, which rethrows as `ConvexError<EdgeProviderOpsFailure>`
 * so the callers' `errCode`/`errText` can read `err.data.code` etc. A create
 * step's failure also carries the provider's own refusal (`detail`), with the
 * edge's names scrubbed (`refusalNames`); no other call forwards one.
 *
 * The Node version that executes this file is decided by the self-hosted Convex
 * backend image (its .nvmrc), not by FCP. `runtimeInfo` exposes it so the deploy
 * entrypoint can refuse a backend below the floor the imported packages declare
 * (scripts/node-floor.mjs) and the admin dashboard can show it.
 */
import { ConvexError, v } from 'convex/values';
import { ZodError } from 'zod';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import type { ActionCtx } from './_generated/server';
import { edgeProviderFor, edgeProviderConfigFrom } from './lib/edges/providers/registry';
import { cloudflareDnsClient } from './lib/edges/providers/dns/cloudflareDns';
import { EdgeProviderError, refusalOf, scrubNames } from './lib/edges/providers/http';
import {
  EDGE_PROVIDER_CAPABILITIES,
  edgeLayerOf,
  edgeRoleOf,
  protocolCarriedBy,
  unsupportedTransport,
  zoneModeGovernsOrigin,
} from './lib/edges/providers/capabilities';
import { renderTemplateValue } from './lib/edges/providers/template';
import { jsonSafe } from './lib/edges/jsonSafe';
import { isRelayProviderId, type EdgeProviderId } from './lib/edgeProviderIds';
import { frozenSettingsOf, parseObservedSettings, type ProvisionIntent } from './lib/edges/intent';
import type { ListenerProto } from './lib/edges/protocols';
import { listenerProtoFields } from './lib/edgeProtocolIds';
import {
  buildCredentials,
  legacySettingsOf,
  pickCredentialIdentifiers,
  validatePlacement,
  validateSettings,
  withoutPlacementKeys,
  EDGE_INTENT_FACTS,
  EDGE_OBSERVED_PLACEMENT,
  EDGE_PLACEMENT_SETTINGS,
} from './lib/edges/accountSettings';
import { placeKeyOf } from './lib/edges/locations';
import {
  PROJECT_KEYS,
  completePlacement,
  needsNetwork,
  needsProject,
  pickableByRegion,
  projectDefault,
  projectPlacement,
} from './lib/edges/placementDefaults';
import { accountOptionDefaultsOf, certificateValuesFor } from './lib/edges/choices';
import { EDGE_CERTIFICATE_OPTIONS, certificateKeysOf } from './lib/edges/providers/templates';
import { defaultsOf } from './lib/edges/providers/options';
import { CATALOG_KINDS, CATALOG_REFRESH_FLOOR_MS, type CatalogKind } from './lib/edges/catalog';
import { l7HostAccepted, l7HostHeaderFor, zoneModeCarriesOrigin } from './lib/edges/layers';
import type {
  AdoptionInspection,
  DiscoverResult,
  Discovery,
  EdgeDescription,
  EdgeSpec,
  DestroyOutcome,
  Inventory,
  InspectResult,
  Ledger,
  LocationCheckResult,
  EdgeProvider,
  EdgeProviderConfig,
  ReapplyOutcome,
  ResourceStep,
  SharedCertificateStatus,
  SharedTeardownState,
  StepOutcome,
} from './lib/edges/providers/types';

export const runtimeInfo = internalAction({
  args: {},
  handler: async (): Promise<{ nodeVersion: string }> => {
    return { nodeVersion: process.version };
  },
});

// --- error surfacing -------------------------------------------------------------

/**
 * What a failed provider action carries across `ctx.runAction` as
 * `ConvexError.data`. `code` is a short provider/adapter code (or the HTTP
 * status as text, or `timeout` / `error`); `message` is the adapter's
 * body-free message. Never a URL, header or credential. `detail` is the
 * provider's own words on a refused create step only: its secrets, address
 * literals and every name of the edge already replaced (admin display only,
 * never a log line or an audit row).
 */
export type EdgeProviderOpsFailure = {
  code: string;
  message: string;
  provider?: EdgeProviderId;
  step?: string;
  status?: number;
  detail?: string;
  retryable: boolean;
  timedOut: boolean;
};

const URL_RE = /https?:\/\/[^\s'")]+/gi;

/**
 * Wrap any throw into a ConvexError whose data survives the action boundary.
 * `names` (a create step's: `refusalNames`) lets the provider's redacted answer
 * through with every one of them replaced; without it, the answer stays here.
 */
export function toOpsFailure(err: unknown, names?: string[]): ConvexError<EdgeProviderOpsFailure> {
  if (err instanceof ConvexError) return err as ConvexError<EdgeProviderOpsFailure>;
  if (err instanceof EdgeProviderError) {
    const m = err.meta;
    const detail = names ? scrubNames(refusalOf(err), names) : undefined;
    return new ConvexError<EdgeProviderOpsFailure>({
      code:
        m.code ?? (m.status !== undefined ? String(m.status) : m.timedOut ? 'timeout' : 'error'),
      message: err.message.slice(0, 200),
      provider: m.provider,
      step: m.step,
      status: m.status,
      ...(detail ? { detail } : {}),
      retryable: m.retryable,
      timedOut: m.timedOut,
    });
  }
  if (err instanceof ZodError) {
    // Template/spec validation: paths only, never values.
    const paths = err.issues
      .slice(0, 6)
      .map((i) => i.path.join('.') || '(root)')
      .join(', ');
    return new ConvexError<EdgeProviderOpsFailure>({
      code: 'template_invalid',
      message: `template params invalid [${paths}]`,
      retryable: false,
      timedOut: false,
    });
  }
  const raw = err instanceof Error ? err.message : String(err);
  return new ConvexError<EdgeProviderOpsFailure>({
    code: 'error',
    message: raw.replace(URL_RE, '<url>').slice(0, 200),
    retryable: false,
    timedOut: false,
  });
}

/** Ledger meta keys whose values name something (a hostname, a record, an address). */
const NAME_META_KEYS = ['name', 'hostname', 'fqdn', 'domain', 'address'] as const;

/**
 * Every name a create step's request could carry and a refusal could echo
 * back: the edge's resource names (spec and ledger), its fronted hostname, the
 * origin's addresses and certificate names, the zone, and what the ledger
 * recorded under a naming key. Filled as the call learns them (the intent and
 * the zone only once the adapter is loaded).
 */
function refusalNames(
  into: string[],
  from: {
    spec?: EdgeSpec;
    ledger?: Ledger;
    intent?: ProvisionIntent | null;
    cfg?: EdgeProviderConfig;
  },
): void {
  const add = (v: unknown) => {
    if (typeof v === 'string' && v.length > 0) into.push(v);
  };
  const { spec, ledger, intent, cfg } = from;
  if (spec) {
    add(spec.name);
    add(spec.hostname);
    for (const l of spec.listeners) for (const m of l.members) add(m.address);
    for (const n of spec.originTransport?.certNames ?? []) add(n);
  }
  for (const st of ledger?.steps ?? []) add(st.resourceName);
  for (const r of ledger?.resources ?? [])
    for (const k of NAME_META_KEYS) add((r.meta as Record<string, unknown> | undefined)?.[k]);
  if (intent) {
    add(intent.hostname);
    add(intent.zoneName);
    for (const n of intent.originTransport?.certNames ?? []) add(n);
  }
  if (cfg) {
    const c = cfg as unknown as { zoneName?: unknown; dns?: { zoneName?: unknown } };
    add(c.zoneName);
    add(c.dns?.zoneName);
  }
}

/** A refused create's words (`StepOutcome.detail`), scrubbed of the edge's names on the way out. */
function scrubbedOutcome(out: StepOutcome, names: string[]): StepOutcome {
  if (out.status !== 'partial' || !out.detail) return out;
  const { detail: said, ...rest } = out;
  const detail = scrubNames(said, names);
  return detail ? { ...rest, detail } : rest;
}

/**
 * Run one action body; any throw crosses the action boundary as
 * `ConvexError<EdgeProviderOpsFailure>` (with the refusal, scrubbed of
 * `names`, when given).
 */
async function run<R>(fn: () => Promise<R>, names?: string[]): Promise<R> {
  try {
    return await fn();
  } catch (err) {
    throw toOpsFailure(err, names);
  }
}

/**
 * Whether a throw says the PROVIDER's API is failing (the code to count), as
 * opposed to FCP refusing a request or the provider refusing it for a reason
 * the caller handles (a 404 in discovery, a 409 on create): a timeout or a
 * network error, a 5xx, a refused credential (401 / 403), rate limiting (429),
 * or an answer the adapter could not read. Null = not a provider fault.
 */
export function apiFailureCode(err: unknown): string | null {
  if (!(err instanceof EdgeProviderError)) return null;
  const m = err.meta;
  if (m.timedOut) return 'timeout';
  if (m.code === 'schema_mismatch' || m.code === 'redirect_refused') return m.code;
  if (m.status === undefined) return m.code ? null : 'network';
  if (m.status >= 500 || m.status === 401 || m.status === 403 || m.status === 429)
    return String(m.status);
  return null;
}

/** What `loadAdapter` saw of the account's API health (so a healthy success writes nothing). */
interface ApiSeen {
  failures: number;
  /** The call resolved but reported a provider failure itself (a failed credential test). */
  failed?: boolean;
}

/**
 * A credential test that came back refused: the adapter caught the provider's
 * answer and returned it, so it is counted here (the account cannot be used,
 * whatever the reason) and the resolved call does not reset the run. The
 * recorded code is FCP's own (`test_failed`): the provider's code stays in
 * `lastTestError`, never in what an alert may carry.
 */
async function noteTestFailure(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  seen: ApiSeen,
): Promise<void> {
  seen.failed = true;
  await noteApiOutcome(ctx, accountId, 'test_failed');
}

/**
 * `run` for an account-scoped provider call that counts toward the account's
 * API health (`edgeProviderAccounts.recordApiOutcome`): a provider-side failure
 * adds one, the first success after failures resets the run. Recording never
 * changes what the caller sees.
 */
async function tracked<R>(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  fn: (seen: ApiSeen) => Promise<R>,
  /** A create step's names: its refusal crosses scrubbed of them (`toOpsFailure`). */
  names?: string[],
): Promise<R> {
  const seen: ApiSeen = { failures: 0 };
  let result: R;
  try {
    result = await fn(seen);
  } catch (err) {
    const failure = apiFailureCode(err);
    if (failure !== null) await noteApiOutcome(ctx, accountId, failure);
    throw toOpsFailure(err, names);
  }
  if (seen.failures > 0 && !seen.failed) await noteApiOutcome(ctx, accountId, null);
  return result;
}

async function noteApiOutcome(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  failure: string | null,
): Promise<void> {
  try {
    await ctx.runMutation(internal.edgeProviderAccounts.recordApiOutcome, {
      id: accountId,
      failure,
    });
  } catch {
    // Health bookkeeping is best effort: never turn a provider answer into a failure.
  }
}

// --- shared validators -----------------------------------------------------------

const edgeSpec = v.object({
  name: v.string(),
  listeners: v.array(
    v.object({
      edgePort: v.number(),
      members: v.array(v.object({ address: v.string(), port: v.number() })),
      /** Absent = tcp. `udp` is refused unless the provider capability allows it. */
      transport: v.optional(v.union(v.literal('tcp'), v.literal('udp'))),
    }),
  ),
  /** L7 only: the fronted hostname, minted once and frozen in the edge's intent. */
  hostname: v.optional(v.string()),
  /** L7 only: how the front must dial the origin (the slot's declaration). */
  originTransport: v.optional(
    v.object({
      scheme: v.union(v.literal('http'), v.literal('https')),
      certPublic: v.boolean(),
      certNames: v.array(v.string()),
      acceptsHostHeader: v.union(v.literal('any'), v.literal('names')),
    }),
  ),
});

const resourceStep = v.object({
  id: v.string(),
  kind: v.string(),
  resourceName: v.string(),
  discoverability: v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
});

const ledger = v.object({
  steps: v.array(
    v.object({
      stepId: v.string(),
      kind: v.string(),
      resourceName: v.string(),
      discoverability: v.optional(
        v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
      ),
      state: v.string(),
      opRef: v.optional(v.string()),
      attempt: v.number(),
      discoverAttempts: v.optional(v.number()),
      startedAt: v.optional(v.number()),
      finishedAt: v.optional(v.number()),
    }),
  ),
  resources: v.array(
    v.object({
      stepId: v.string(),
      kind: v.string(),
      resourceId: v.string(),
      ownership: v.union(v.literal('created'), v.literal('adopted')),
      deleteState: v.union(
        v.literal('present'),
        v.literal('delete_requested'),
        v.literal('confirmed_gone'),
      ),
      meta: v.optional(v.string()),
    }),
  ),
});

const ledgerResource = v.object({
  stepId: v.string(),
  kind: v.string(),
  resourceId: v.string(),
  ownership: v.union(v.literal('created'), v.literal('adopted')),
  deleteState: v.union(
    v.literal('present'),
    v.literal('delete_requested'),
    v.literal('confirmed_gone'),
  ),
  meta: v.optional(v.string()),
});

/**
 * The adapter + its config for one account, in one place.
 *
 * WHERE the call acts (region / zone / project / network) is never the
 * account's: an EXISTING edge (`edgeId`) acts in the placement it froze when
 * it was planned, so a describe or a destroy always reaches the edge's own
 * region (a wrong-region 404 would read as "gone" and orphan a billing
 * resource); PLANNING a new edge or an inventory pull acts in the chosen
 * location (`locationId`). An edge of a placed provider without its own
 * placement is refused (`placement_missing`) rather than sent to whatever
 * region the call would default to. An account-level call (a credential test)
 * acts nowhere.
 *
 * A provider whose DNS lives in ANOTHER account (Fastly's records in a
 * Cloudflare zone) needs that account's secret attached. Which DNS account is
 * resolved depends on what we are doing:
 *
 *  - acting on an EXISTING edge (`edgeId`): from the edge's FROZEN intent, so a
 *    later settings edit cannot make a step, a discovery or a destroy look in a
 *    different zone than the one the records were created in;
 *  - PLANNING a new edge (no `edgeId`): from the account's current settings,
 *    which the intent then freezes.
 *
 * The DNS account's secret is read regardless of its `enabled` flag: disabling
 * it must stop NEW allocations, not strand reconciliation and destroy for the
 * edges that already depend on it. This is the only cross-account secret read;
 * it is never returned, logged or audited.
 */
async function loadAdapter(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  edgeId?: Id<'edges'>,
  seen?: ApiSeen,
  locationId?: Id<'edgeLocations'>,
  /** A placement no location holds yet (a location being created is checked with it). */
  rawPlacement?: Record<string, unknown>,
): Promise<{
  provider: EdgeProvider;
  cfg: EdgeProviderConfig;
  providerId: EdgeProviderId;
  intent: ProvisionIntent | null;
}> {
  const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, { id: accountId });
  if (!acct) {
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'account_missing',
      message: 'origin account not found',
      step: 'load',
      retryable: false,
      timedOut: false,
    });
  }
  if (seen) seen.failures = acct.apiFailures;
  const cfg = edgeProviderConfigFrom(
    acct.credentials as Record<string, unknown> & { type: typeof acct.provider },
    acct.settings as Record<string, unknown> & { type: typeof acct.provider },
  );
  // A DNS account set to DNS and fronting: its location checks also check
  // what a front needs of the zone.
  if (edgeRoleOf(acct.provider) === 'dns' && acct.frontsTraffic)
    (cfg as { frontsTraffic?: boolean }).frontsTraffic = true;
  // A CDN account's call about no edge and no named place (an account-level
  // describe, a plan without a location) acts in its default location: its
  // zone is where such a call's records would live.
  const where =
    locationId ??
    (!edgeId && !rawPlacement && edgeLayerOf(acct.provider) === 'l7'
      ? ((await ctx.runQuery(internal.edgeLocations.defaultOf, { accountId })) ?? undefined)
      : undefined);
  const placement = edgeId
    ? await ctx.runQuery(internal.edgeLocations.placementOfEdge, { edgeId })
    : where
      ? await locationPlacement(ctx, accountId, where)
      : (rawPlacement ?? null);
  if (placement) {
    const { type: _t, ...where } = placement;
    Object.assign(cfg as unknown as Record<string, unknown>, where);
  } else if (edgeId && edgeLayerOf(acct.provider) === 'l4') {
    // (An L7 edge needs no placement of its own: its intent holds its zone.)
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'placement_missing',
      message: 'the edge has no placement of its own',
      step: 'load',
      retryable: false,
      timedOut: false,
    });
  }
  // A placement value the location left empty takes the provider's own
  // default as the credential test observed it (Scaleway: the API key's
  // default project), for a new edge and an existing one alike.
  const observed = parseObservedSettings(acct.observedSettings);
  for (const [key, { fact }] of Object.entries(EDGE_OBSERVED_PLACEMENT[acct.provider])) {
    const into = cfg as unknown as Record<string, unknown>;
    if ((into[key] === undefined || into[key] === '') && observed[fact]) into[key] = observed[fact];
  }
  // The account's certificate option defaults (planning a NEW edge reads
  // them; a node's own choices reach a new edge through its intent).
  Object.assign(
    cfg as unknown as Record<string, unknown>,
    certificateValuesFor(acct.provider, accountOptionDefaultsOf(acct), null),
  );
  // Acting on an EXISTING edge: every setting the intent froze wins over the
  // account row and any location: the zone its records live in, the DNS
  // account writing them, and the TLS subscription (the TLS configuration and
  // the certificate options), which decides which certificate a describe or a
  // destroy acts on. An edit after planning must not move a live edge.
  const intent = edgeId ? await ctx.runQuery(internal.edges.intentOf, { edgeId }) : null;
  const mutable = cfg as unknown as Record<string, unknown>;
  if (intent) {
    Object.assign(mutable, frozenSettingsOf(intent));
    // The intent's ABSENCE of a TLS configuration is frozen too: an edge
    // planned on the provider's default keeps it, whatever its location or
    // the account's old settings say now.
    if (!intent.tlsConfigurationId) delete mutable.tlsConfigurationId;
    // The certificate options: what the intent froze, else the value from
    // before the option existed (the declared default: one certificate per
    // front, the default authority), never the account's default now.
    const frozen = intent as unknown as Record<string, unknown>;
    const declared = defaultsOf(EDGE_CERTIFICATE_OPTIONS[acct.provider].fields);
    for (const key of certificateKeysOf(acct.provider)) {
      const v = frozen[key] ?? declared[key];
      if (v !== undefined) mutable[key] = v;
      else delete mutable[key];
    }
  }
  // How the provider is driven: planning gets the account's choice, else
  // today's way; an existing edge the way it was built (an intent from before
  // a fact existed: `legacy`).
  for (const [key, fact] of Object.entries(EDGE_INTENT_FACTS[acct.provider])) {
    const frozen = (intent as unknown as Record<string, unknown> | null)?.[key];
    const chosen = mutable[key];
    mutable[key] = edgeId
      ? typeof frozen === 'string'
        ? frozen
        : fact.legacy
      : typeof chosen === 'string'
        ? chosen
        : fact.planned;
  }
  if (EDGE_PROVIDER_CAPABILITIES[acct.provider].needsDnsAccount) {
    // The DNS account and zone: the intent's for an existing edge, else the
    // location's (merged above), else the account's legacy settings (an
    // account the L7 locations migration has not moved yet). A call about the
    // account alone with no place at all (a credential test, its catalog)
    // needs none: the DNS account is a location's.
    const merged = cfg as unknown as { dnsAccountId?: string; zoneId?: string; zoneName?: string };
    const dnsAccountId = intent?.dnsAccountId ?? merged.dnsAccountId;
    const placed = !!edgeId || !!where || !!rawPlacement;
    if (!dnsAccountId && !placed)
      return { provider: edgeProviderFor(acct.provider), cfg, providerId: acct.provider, intent };
    if (!dnsAccountId) {
      throw new ConvexError<EdgeProviderOpsFailure>({
        code: 'dns_account_missing',
        message: 'this provider needs a DNS account',
        step: 'load',
        retryable: false,
        timedOut: false,
      });
    }
    (cfg as { dns?: unknown }).dns = await dnsConfigFor(ctx, dnsAccountId, {
      zoneId: intent?.zoneId ?? merged.zoneId,
      zoneName: intent?.zoneName ?? merged.zoneName,
    });
  }
  return { provider: edgeProviderFor(acct.provider), cfg, providerId: acct.provider, intent };
}

/**
 * The resolved DNS side of a front: the DNS account's token and the zone its
 * records go into (the given zone, else the DNS account's legacy settings, for
 * an account the L7 locations migration has not moved yet).
 */
async function dnsConfigFor(
  ctx: ActionCtx,
  dnsAccountId: string,
  zone: { zoneId?: string; zoneName?: string },
): Promise<{ apiToken: string; zoneId: string; zoneName: string; accountId: string }> {
  const dns = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
    id: dnsAccountId as Id<'edgeProviderAccounts'>,
  });
  const dnsSettings = dns?.settings as { zoneId?: string; zoneName?: string } | undefined;
  const apiToken = (dns?.credentials as { apiToken?: string } | undefined)?.apiToken;
  const zoneId = zone.zoneId ?? dnsSettings?.zoneId;
  const zoneName = zone.zoneName ?? dnsSettings?.zoneName;
  if (!dns || !EDGE_PROVIDER_CAPABILITIES[dns.provider].providesDns || !apiToken || !zoneId) {
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'dns_account_missing',
      message: 'the referenced DNS account is unusable',
      step: 'load',
      retryable: false,
      timedOut: false,
    });
  }
  return { apiToken, zoneId, zoneName: zoneName ?? '', accountId: dnsAccountId };
}

/** A location's placement, checked to belong to the account the call acts for. */
async function locationPlacement(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  locationId: Id<'edgeLocations'>,
): Promise<Record<string, unknown>> {
  const loc = await ctx.runQuery(internal.edgeLocations.getForOps, { id: locationId });
  if (!loc || loc.accountId !== accountId)
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'location_missing',
      message: 'location not found for this account',
      step: 'load',
      retryable: false,
      timedOut: false,
    });
  return loc.placement;
}

/**
 * Template params are validated by the adapter schema, then placeholders
 * rendered. The zone's encryption mode rides ALONG the params rather than in
 * them: it is not an operator-settable template field (the adapter schema
 * would strip it), but the adapter that proxies the zone reads it as one,
 * because it decides the effective origin port and whether the origin leg is
 * encrypted. It is added after the schema parse for exactly that reason.
 */
function renderedTemplate(
  provider: EdgeProvider,
  params: unknown,
  spec: EdgeSpec,
  zoneSslMode?: string,
): Record<string, unknown> {
  const parsed = provider.templateSchema.parse(params ?? {}) as Record<string, unknown>;
  const rendered = renderTemplateValue(parsed, spec) as Record<string, unknown>;
  return zoneSslMode ? { ...rendered, zoneSslMode } : rendered;
}

function refuse(code: string, message: string, providerId: EdgeProviderId): never {
  throw new ConvexError<EdgeProviderOpsFailure>({
    code,
    message,
    provider: providerId,
    step: 'plan',
    retryable: false,
    timedOut: false,
  });
}

/** Refuse a listener transport the provider cannot carry BEFORE any provider call. */
function checkTransport(providerId: EdgeProviderId, spec: EdgeSpec): void {
  const bad = unsupportedTransport(providerId, spec);
  if (bad)
    refuse(
      'transport_unsupported',
      `${providerId} edges cannot carry ${bad} listeners`,
      providerId,
    );
}

/**
 * Refuse a slot PROTOCOL the provider cannot carry. An L4 forwarder carries any
 * TCP protocol; an L7 front carries only the HTTP transports it declares
 * (Fastly's WebSocket path, for instance, is not a gRPC path). The spec carries
 * no protocol, so the caller passes it.
 */
function checkProtocolCarried(providerId: EdgeProviderId, proto?: ListenerProto): void {
  if (!proto) return;
  if (!protocolCarriedBy(providerId, proto))
    refuse(
      'protocol_not_carried',
      `${providerId} edges cannot carry ${proto.protocol}/${proto.streamTransport}/${proto.security}`,
      providerId,
    );
}

/**
 * Refuse an origin transport the provider cannot realise, before any call. Only
 * the layer-independent rules live here (an L7 front needs the slot to declare
 * how the origin is reached at all); each adapter refuses its own specifics
 * (zone encryption mode, fixed ports, publicly trusted certificates) at plan
 * time with its own codes, because only it knows them.
 */
function checkOriginTransport(
  providerId: EdgeProviderId,
  spec: EdgeSpec,
  tpl?: Record<string, unknown>,
  zoneSslMode?: string,
): void {
  if (EDGE_PROVIDER_CAPABILITIES[providerId].layer !== 'l7') return;
  if (!spec.hostname) refuse('hostname_missing', 'an L7 edge needs its hostname', providerId);
  if (!spec.originTransport)
    refuse(
      'origin_transport_missing',
      'the slot does not declare how its origin is reached',
      providerId,
    );
  // The Host header the front will send the origin: the minted hostname, or the
  // origin's own address when the template passes it through. A node that
  // answers only for its certificate names would reject anything else.
  if (!l7HostAccepted(spec.originTransport, l7HostHeaderFor(spec.hostname, tpl?.overrideHost)))
    refuse(
      'host_header_rejected',
      'the origin does not accept the Host header this front would send',
      providerId,
    );
  // The zone's encryption mode decides whether the front dials the origin over
  // HTTP or HTTPS, and whether it validates the origin certificate, but only
  // for the provider that proxies the zone itself. A front whose records are
  // unproxied CNAMEs in someone else's zone dials the origin by its own
  // service configuration, so that zone's mode never refuses it.
  if (
    zoneSslMode &&
    zoneModeGovernsOrigin(providerId) &&
    !zoneModeCarriesOrigin(zoneSslMode, spec.originTransport)
  )
    refuse(
      'origin_tls_mismatch',
      'the zone encryption mode cannot carry this origin transport',
      providerId,
    );
}

/**
 * Refuse an origin port the provider cannot dial. `fixed` providers follow the
 * origin scheme (443 for https, 80 for http) because the transport honours no
 * port override; a `default-or-override` provider accepts any port but not for
 * gRPC, which needs 443 end to end.
 */
function checkOriginPort(providerId: EdgeProviderId, spec: EdgeSpec, proto?: ListenerProto): void {
  const caps = EDGE_PROVIDER_CAPABILITIES[providerId];
  if (caps.layer !== 'l7') return;
  const port = spec.listeners[0]?.members[0]?.port;
  if (port === undefined) return;
  if (caps.originPortMode === 'fixed') {
    const want = spec.originTransport?.scheme === 'http' ? 80 : 443;
    if (port !== want)
      refuse(
        'origin_port_unsupported',
        `${providerId} dials the origin on ${want} only`,
        providerId,
      );
  }
  // gRPC is carried end to end over HTTP/2 on 443; a destination-port override
  // would break the h2 path the front negotiates.
  if (proto?.streamTransport === 'grpc' && port !== 443)
    refuse('grpc_requires_443', 'a gRPC listener needs origin port 443', providerId);
}

/** Every pre-call refusal in one place, so plan and run apply the same rules. */
function checkSpec(
  providerId: EdgeProviderId,
  spec: EdgeSpec,
  proto?: ListenerProto,
  tpl?: Record<string, unknown>,
  zoneSslMode?: string,
): void {
  checkTransport(providerId, spec);
  // The port rule has its own refusal below (`grpc_requires_443`).
  checkProtocolCarried(providerId, proto);
  checkOriginTransport(providerId, spec, tpl, zoneSslMode);
  checkOriginPort(providerId, spec, proto);
}

/**
 * The EFFECTIVE template params for one spec: the adapter's schema applied
 * (defaults filled, unknown keys dropped) and the placeholders rendered. The
 * rotation freezes exactly this into the edge's intent, so no later step needs
 * the template row again.
 */
export const effectiveTemplate = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    locationId: v.optional(v.id('edgeLocations')),
    spec: edgeSpec,
    templateParams: v.any(),
  },
  handler: (
    ctx,
    { accountId, locationId, spec, templateParams },
  ): Promise<Record<string, unknown>> =>
    run(async () => {
      const { provider } = await loadAdapter(ctx, accountId, undefined, undefined, locationId);
      return renderedTemplate(provider, templateParams, spec);
    }),
});

// --- credentials / discovery of provider metadata ---------------------------------

export const testCredentials = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<{ ok: boolean; code?: string; detail?: string }> =>
    tracked(ctx, accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, seen);
      const res = await provider.testCredentials(cfg);
      // A zone whose CAA records refuse the CA is the zone's answer, not the
      // provider's: the API answered, so it does not count toward its health.
      if (!res.ok && !NOT_API_FAILURES.has(res.code ?? ''))
        await noteTestFailure(ctx, accountId, seen);
      // A passing test's `detail` is adapter prose about the account, not a refusal.
      const detail = res.ok ? undefined : res.detail;
      await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
        id: accountId,
        ok: res.ok,
        code: res.code,
        detail,
        observed: res.observed,
      });
      if (res.ok) {
        // What the key reaches (the pickers' menu), and every place in use
        // checked again: a zone's encryption mode, its CAA records and its
        // shared certificate are the place's own facts.
        await ctx.scheduler.runAfter(0, internal.edgeProviderOps.refreshCatalog, { accountId });
        if (provider.checkLocation) await checkLocationsOf(ctx, accountId);
      }
      return { ok: res.ok, code: res.code, detail };
    }),
});

/**
 * Whether the certificate options a node chose (other than the ones the
 * location's check covered) can be issued: the adapter's preflight with those
 * values laid over the account's, at the pick's zone (its CAA records). A
 * lookup that cannot be read never refuses: issuance then reports what it meets.
 */
export const certificatePreflight = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    locationId: v.id('edgeLocations'),
    certificate: v.any(),
  },
  handler: async (
    ctx,
    { accountId, locationId, certificate },
  ): Promise<{ ok: true } | { ok: false; code: string; detail?: string }> => {
    try {
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, undefined, locationId);
      if (!provider.certificatePreflight) return { ok: true };
      Object.assign(cfg as unknown as Record<string, unknown>, certificate as object);
      return await provider.certificatePreflight(cfg);
    } catch {
      return { ok: true };
    }
  },
});

/** Test refusals that are not the provider failing (they never raise `account_api_failing`). */
const NOT_API_FAILURES: ReadonlySet<string> = new Set(['caa_forbids_ca']);

/** Read and record a zone's shared certificate; a read that fails leaves the last one. */
async function recordSharedCertificate(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  locationId: Id<'edgeLocations'>,
  provider: EdgeProvider,
  cfg: EdgeProviderConfig,
): Promise<SharedCertificateStatus | null> {
  // A node that chose the wildcard where the account defaults to one per front:
  // the certificate this zone's fronts share is read as such a front froze it.
  const mutable = cfg as unknown as Record<string, unknown>;
  if (provider.sharedCertificate && mutable.certificateScope !== 'wildcard') {
    const shared = await ctx.runQuery(internal.edgeLocations.sharedCertificateChoice, {
      locationId,
    });
    if (shared) Object.assign(mutable, shared);
  }
  // What edges of the account ordered: an FCP-ordered wildcard is named (and
  // so removable) even under an authority the account no longer defaults to.
  const ordered = provider.sharedCertificate
    ? await ctx.runQuery(internal.edgeProviderAccounts.orderedSharedResourcesOf, { accountId })
    : [];
  const status = provider.sharedCertificate
    ? await provider.sharedCertificate(cfg, { ordered })
    : null;
  await ctx.runMutation(internal.edgeLocations.recordSharedCertificate, { id: locationId, status });
  return status;
}

/**
 * Remove a zone's shared certificate at the provider, with the ACME record
 * FCP wrote for it: an operator's explicit action for a wildcard no live edge
 * in that zone fronts through any more (an account switched back to one
 * certificate per front, or about to be deleted, which refuses while one is
 * held). Refused while a live edge still uses it.
 */
export const removeSharedCertificate = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    locationId: v.id('edgeLocations'),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: (
    ctx,
    { accountId, locationId, actorAdminId },
  ): Promise<{ ok: true; removed: boolean }> =>
    tracked(ctx, accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, seen, locationId);
      if (!provider.removeSharedCertificate)
        throw new ConvexError({
          code: 'validation',
          message: 'This provider shares no certificate',
        });
      // Under the zone's certificate lock, with the users counted again in the
      // same transaction: a front cannot order or adopt the wildcard while it
      // is being deleted, nor be planned on it unseen.
      const opId = `remove-${Math.random().toString(36).slice(2)}`;
      const begun = await ctx.runMutation(
        internal.edgeProviderAccounts.beginSharedCertificateRemoval,
        { id: accountId, locationId, opId },
      );
      if (!begun.ok)
        throw new ConvexError({
          code: `edge.${begun.code}`,
          message:
            begun.code === 'shared_certificate_in_use'
              ? 'Live edges still front through the shared certificate'
              : 'The shared certificate cannot be removed now',
        });
      try {
        const res = await provider.removeSharedCertificate(cfg, { ordered: begun.ordered });
        if (res.code)
          throw new ConvexError({
            code: `edge.${res.code}`,
            message: 'The shared certificate cannot be removed by FCP',
          });
        await ctx.runMutation(internal.edgeProviderAccounts.noteSharedCertificateRemoved, {
          id: accountId,
          locationId,
          removed: res.removed,
          actorAdminId,
        });
        return { ok: true as const, removed: res.removed };
      } finally {
        await ctx.runMutation(internal.edges.settleExternalLock, { key: begun.key, opId });
      }
    }),
});

/**
 * The certificate the fronts in one zone of an account share, read at the
 * provider and recorded on the zone's location (the reconcile cron, so a
 * renewal or a failure shows on the account page and in attention). Orders
 * nothing.
 */
export const refreshSharedCertificate = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), locationId: v.id('edgeLocations') },
  handler: (ctx, { accountId, locationId }): Promise<SharedCertificateStatus | null> =>
    tracked(ctx, accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, seen, locationId);
      return recordSharedCertificate(ctx, accountId, locationId, provider, cfg);
    }),
});

/**
 * Check every location of an L7 account that is switched on or still holds
 * edges, and record what each check found. Fail-soft per location: a provider
 * that cannot be reached leaves that location's last result alone.
 */
async function checkLocationsOf(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<void> {
  const locations = await ctx.runQuery(internal.edgeLocations.listForAccount, { accountId });
  for (const loc of locations) {
    if (!loc.enabled && loc.liveEdges === 0) continue;
    try {
      const locationId = loc.id as Id<'edgeLocations'>;
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, undefined, locationId);
      if (!provider.checkLocation) return;
      const res = await provider.checkLocation(cfg);
      await ctx.runMutation(internal.edgeLocations.recordCheck, {
        id: locationId,
        ok: res.ok,
        code: res.code,
        detail: res.detail,
        observed: res.observed,
      });
      // The zone's shared certificate as of this test (best effort: the
      // reconcile cron reads it again).
      if (provider.sharedCertificate)
        await recordSharedCertificate(ctx, accountId, locationId, provider, cfg).catch(() => null);
    } catch {
      // Unreachable now says nothing about the place; its last check stands.
    }
  }
}

/**
 * Check ONE location now (the admin's "Check again"): an L7 location through
 * the adapter's `checkLocation`, recorded on the row; an L4 location through
 * its inventory pull.
 */
export const checkLocation = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), locationId: v.id('edgeLocations') },
  handler: (
    ctx,
    a,
  ): Promise<{ ok: boolean; code?: string; detail?: string; observed?: Record<string, string> }> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, undefined, seen, a.locationId);
      if (!provider.checkLocation) {
        await provider.inventory(cfg);
        return { ok: true };
      }
      const res = await provider.checkLocation(cfg);
      await ctx.runMutation(internal.edgeLocations.recordCheck, {
        id: a.locationId,
        ok: res.ok,
        code: res.code,
        detail: res.detail,
        observed: res.observed,
      });
      return {
        ok: res.ok,
        ...(res.code ? { code: res.code } : {}),
        ...(res.detail ? { detail: res.detail } : {}),
        ...(res.observed ? { observed: res.observed } : {}),
      };
    }),
});

/**
 * List what the account's credentials reach (its catalog: zones, regions,
 * projects, TLS configurations) and store it. A provider whose regions depend
 * on the project (Gcore, OVH) lists them in the project a region pick creates
 * in (the one the account's locations all use, else the key's first:
 * `projectDefault`), and each region names it (`facts.project`). A refresh within
 * `CATALOG_REFRESH_FLOOR_MS` of the last one does nothing (`fresh`), so a
 * picker opening on several screens costs one listing.
 */
export const refreshCatalog = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    /** List again even right after a listing (new credentials reach other things). */
    force: v.optional(v.boolean()),
  },
  handler: (ctx, { accountId, force }): Promise<{ refreshed: boolean }> =>
    tracked(ctx, accountId, async (seen) => {
      const last = await ctx.runQuery(internal.edgeProviderCatalog.refreshedAt, { accountId });
      if (!force && last !== null && Date.now() - last < CATALOG_REFRESH_FLOOR_MS)
        return { refreshed: false };
      const { provider, cfg, providerId } = await loadAdapter(ctx, accountId, undefined, seen);
      if (!provider.discoverOptions) return { refreshed: false };
      const projects = PROJECT_KEYS[providerId] !== undefined;
      const own = projects
        ? projectDefault(
            providerId,
            undefined,
            (await ctx.runQuery(internal.edgeLocations.listForAccount, { accountId })).map(
              (l) => l.placement as Record<string, unknown>,
            ),
          )
        : null;
      const found = await provider.discoverOptions({
        ...cfg,
        ...(own ? projectPlacement(providerId, own) : {}),
      } as never);
      // The project the regions were listed in (the adapter's own fallback is the key's first).
      const listedIn = projects ? (own ?? found.projects?.[0]?.id ?? null) : null;
      const lists: Array<{
        kind: CatalogKind;
        items: Array<{ id: string; label: string; facts?: Record<string, string> }>;
        truncated?: boolean;
      }> = [];
      const errors: Array<{ kind: CatalogKind; code: string; detail?: string }> = [];
      for (const kind of CATALOG_KINDS) {
        const err = found.errors?.[kind];
        if (err) {
          errors.push({
            kind,
            code: err,
            ...(found.errorDetails?.[kind] ? { detail: found.errorDetails[kind] } : {}),
          });
          continue;
        }
        const items = found[kind];
        if (!items) continue;
        lists.push({
          kind,
          items: items.map((i) => {
            const facts = {
              ...(i.facts ?? {}),
              ...(kind === 'regions' && listedIn ? { project: listedIn } : {}),
            };
            return {
              id: String(i.id),
              label: i.label,
              ...(Object.keys(facts).length > 0 ? { facts } : {}),
            };
          }),
          ...(found.truncated?.includes(kind) ? { truncated: true } : {}),
        });
      }
      await ctx.runMutation(internal.edgeProviderCatalog.record, { accountId, lists, errors });
      return { refreshed: true };
    }),
});

/**
 * Rotate an account's credentials WITHOUT dropping its qualification: the new
 * secret (+ its non-secret identifier, e.g. an access/application key) is
 * tested against the provider FIRST; only a passing test is applied, by
 * `edgeProviderAccounts.applyCredentialRotation`, which also refuses any
 * locating change. A failing test changes nothing and reports the code.
 * Nothing here is logged; the audit row carries booleans only.
 */
export const rotateCredentials = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    credentials: v.any(),
    identifiers: v.optional(v.any()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: (
    ctx,
    a,
  ): Promise<
    | { ok: true; qualified: boolean; credentialsChanged: boolean; identifiersChanged: boolean }
    | { ok: false; code: string; detail?: string }
  > =>
    run(async () => {
      const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
        id: a.accountId,
      });
      if (!acct)
        throw new ConvexError<EdgeProviderOpsFailure>({
          code: 'account_missing',
          message: 'origin account not found',
          retryable: false,
          timedOut: false,
        });
      const creds = buildCredentials(
        acct.provider,
        a.credentials as Record<string, unknown>,
        acct.credentials as Record<string, unknown>,
      );
      if (!creds.ok)
        throw new ConvexError({
          code: 'validation',
          message: `missing credentials: ${creds.missing.join(', ')}`,
        });
      const settings = validateSettings(acct.provider, {
        ...withoutPlacementKeys(acct.provider, acct.settings as Record<string, unknown>),
        ...pickCredentialIdentifiers(
          acct.provider,
          a.identifiers as Record<string, unknown> | undefined,
        ),
      });
      if (!settings.ok)
        throw new ConvexError({ code: 'validation', message: settings.issues.join('; ') });
      const cfg = edgeProviderConfigFrom(
        creds.credentials as Record<string, unknown> & { type: typeof acct.provider },
        settings.settings as Record<string, unknown> & { type: typeof acct.provider },
      );
      if (edgeRoleOf(acct.provider) === 'dns' && acct.frontsTraffic)
        (cfg as { frontsTraffic?: boolean }).frontsTraffic = true;
      const res = await edgeProviderFor(acct.provider).testCredentials(cfg);
      // The stored (still valid) credentials are untouched on a failed test.
      if (!res.ok) return { ok: false, code: res.code ?? 'error', detail: res.detail };
      // The test above needs no location, so a key scoped to fewer projects,
      // regions or zones can pass it. Every location still in use (switched
      // on, or with edges that describe and destroy must keep reaching) is read
      // with the new key first, and so is every zone other accounts write
      // through this one (a DNS provider's); one it cannot read refuses the
      // rotation, nothing changed.
      const provider = edgeProviderFor(acct.provider);
      const locations = await ctx.runQuery(internal.edgeLocations.listForAccount, {
        accountId: a.accountId,
      });
      const checked: Array<{ id: Id<'edgeLocations'>; res: LocationCheckResult }> = [];
      // An account the L7 locations migration has not moved yet still names
      // its zone (or DNS account) in its settings: the location falls back to it.
      const legacy = legacySettingsOf(acct.provider, acct.settings as Record<string, unknown>);
      for (const loc of locations) {
        // A place in use (switched on, or holding edges) must stay reachable.
        // One switched off with nothing in it is checked too, when it can be:
        // what the new key cannot do there is recorded on it (no new edge is
        // planned there until a check passes), and it never holds the
        // rotation back.
        const inUse = loc.enabled || loc.liveEdges > 0;
        if (!inUse && !provider.checkLocation) continue;
        const where = { ...cfg, ...legacy, ...loc.placement } as EdgeProviderConfig;
        const id = loc.id as Id<'edgeLocations'>;
        try {
          if (provider.checkLocation) {
            const p = where as { dnsAccountId?: string; zoneId?: string; zoneName?: string };
            const needsDns = EDGE_PROVIDER_CAPABILITIES[acct.provider].needsDnsAccount;
            // A place that names no zone yet has nothing to reach.
            if (needsDns ? !p.dnsAccountId : !p.zoneId) continue;
            if (needsDns)
              (where as { dns?: unknown }).dns = await dnsConfigFor(ctx, p.dnsAccountId!, p);
            const res = await provider.checkLocation(where);
            // Only a zone's own state may refuse a place the new key still
            // reaches in full (paused, encryption off, CAA): that is recorded
            // like any check, and the leaked key still goes. Anything the key
            // itself cannot do there (a TLS configuration it does not see) is
            // the key's, and the edges there need it.
            if (!res.ok && !ZONE_STATE_REFUSALS.has(res.code ?? '') && inUse)
              return {
                ok: false,
                code: 'location_unreachable',
                detail: `${loc.label} (${res.code})`,
              };
            checked.push({ id, res });
          } else {
            await provider.inventory(where);
          }
        } catch (err) {
          const code = toOpsFailure(err).data.code;
          if (!inUse) {
            checked.push({ id, res: { ok: false, code: 'location_unreachable', detail: code } });
            continue;
          }
          return {
            ok: false,
            code: 'location_unreachable',
            detail: `${loc.label} (${code})`,
          };
        }
      }
      if (EDGE_PROVIDER_CAPABILITIES[acct.provider].providesDns) {
        const zones = await ctx.runQuery(internal.edgeLocations.zonesWrittenThrough, {
          accountId: a.accountId,
        });
        const apiToken = (creds.credentials as { apiToken?: string }).apiToken ?? '';
        for (const z of zones) {
          try {
            await cloudflareDnsClient({
              apiToken,
              zoneId: z.zoneId,
              zoneName: z.zoneName,
              accountId: a.accountId,
            }).readZone();
          } catch (err) {
            const code = toOpsFailure(err).data.code;
            // A zone only switched-off fronts with nothing in them name: they
            // record it, and the rotation goes on.
            if (!z.inUse) {
              for (const locationId of z.locationIds)
                checked.push({
                  id: locationId as Id<'edgeLocations'>,
                  res: { ok: false, code: 'location_unreachable', detail: code },
                });
              continue;
            }
            return {
              ok: false,
              code: 'location_unreachable',
              detail: `${z.zoneName} (${code})`,
            };
          }
        }
      }
      // Apply EXACTLY what was tested, against the row version it was built from.
      const applied = await ctx.runMutation(internal.edgeProviderAccounts.applyCredentialRotation, {
        id: a.accountId,
        credentials: creds.credentials,
        settings: settings.settings,
        observed: res.observed,
        expectedUpdatedAt: acct.updatedAt,
        actorAdminId: a.actorAdminId,
      });
      // The zone checks just read each place's live facts (encryption mode,
      // WebSockets): recorded like a credential test's, or planning keeps
      // freezing a mode the zone no longer has.
      for (const c of checked)
        await ctx.runMutation(internal.edgeLocations.recordCheck, {
          id: c.id,
          ok: c.res.ok,
          code: c.res.code,
          detail: c.res.detail,
          observed: c.res.observed,
        });
      // What the new key reaches may differ from the old one's.
      await ctx.scheduler.runAfter(0, internal.edgeProviderOps.refreshCatalog, {
        accountId: a.accountId,
        force: true,
      });
      return {
        ok: true,
        qualified: applied.qualified,
        credentialsChanged: applied.credentialsChanged,
        identifiersChanged: applied.identifiersChanged,
      };
    }),
});

/**
 * Choice lists for the account form BEFORE an account exists: the operator's
 * credentials + the settings chosen so far, straight from the (sealed) request.
 * Nothing is stored; the credentials are used for this call only.
 */
export const discoverOptions = internalAction({
  args: {
    provider: v.string(),
    credentials: v.any(),
    settings: v.optional(v.any()),
    /** Reuse a stored account's credentials when editing (blank form fields). */
    accountId: v.optional(v.id('edgeProviderAccounts')),
  },
  handler: (ctx, a): Promise<DiscoverResult> =>
    run(async () => {
      if (!isRelayProviderId(a.provider))
        throw new ConvexError({ code: 'validation', message: 'unknown provider' });
      const provider = edgeProviderFor(a.provider);
      if (!provider.discoverOptions) return {};
      let creds: Record<string, unknown> = {
        ...((a.credentials as Record<string, unknown> | undefined) ?? {}),
      };
      if (a.accountId) {
        const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
          id: a.accountId,
        });
        if (acct && acct.provider === a.provider) {
          // Blank form fields fall back to the stored secret.
          const stored = acct.credentials as Record<string, unknown>;
          for (const [k, v] of Object.entries(stored))
            if (typeof creds[k] !== 'string' || (creds[k] as string).trim() === '') creds[k] = v;
        }
      }
      creds = Object.fromEntries(
        Object.entries(creds).filter(([, v]) => typeof v === 'string' && v.trim() !== ''),
      );
      const partial = {
        ...((a.settings as Record<string, unknown> | undefined) ?? {}),
        ...creds,
        type: a.provider,
      } as Record<string, unknown>;
      return provider.discoverOptions(partial as never);
    }),
});

/**
 * The choices for a NEW location of a stored account (the location form): the
 * account's credentials and settings, plus the placement chosen so far
 * (project, region, network), through the adapter's discovery. Regions come
 * back as the key can use them; networks, subnets and flavors once a region
 * is chosen. Nothing is stored.
 *
 * With `defaults` (a region picked when a node is protected, its options
 * opened before the location exists): the placement is completed the way a
 * pick by region would be (`completeRegionPick`), returned as `defaults`
 * with what could not be chosen (`missing`), and the lists are those of the
 * completed placement.
 */
export const locationOptions = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    placement: v.optional(v.any()),
    defaults: v.optional(v.boolean()),
  },
  handler: (
    ctx,
    a,
  ): Promise<DiscoverResult & { defaults?: Record<string, unknown>; missing?: string[] }> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId, undefined, seen);
      if (!provider.discoverOptions) return {};
      const chosen = Object.fromEntries(
        Object.entries((a.placement as Record<string, unknown> | undefined) ?? {}).filter(
          ([k, v]) => k !== 'type' && v !== undefined && v !== null && v !== '',
        ),
      );
      if (!a.defaults) return provider.discoverOptions({ ...cfg, ...chosen } as never);
      const filled = await completeRegionPick(ctx, a.accountId, providerId, provider, cfg, chosen);
      const lists =
        filled.found ?? (await provider.discoverOptions({ ...cfg, ...filled.placement } as never));
      return { ...lists, defaults: filled.placement, missing: filled.missing };
    }),
});

/**
 * A placement that names its region and maybe little else, completed from
 * what the key reaches (lib/edges/placementDefaults.ts): the project (the
 * account's own when its other locations agree on one, else the first the key
 * lists) and, where the provider needs one, the private network and subnet
 * that serve the region. `found` is the listing asked with the project and
 * the region when one was made (it also says whether the region is offered).
 * A project listing that failed with no project to fall back on is
 * `edge.location_unchecked`.
 */
async function completeRegionPick(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
  providerId: EdgeProviderId,
  provider: EdgeProvider,
  cfg: EdgeProviderConfig,
  chosen: Record<string, unknown>,
): Promise<{
  placement: Record<string, unknown>;
  missing: string[];
  found: DiscoverResult | null;
}> {
  if (!pickableByRegion(providerId) || !provider.discoverOptions)
    return { placement: chosen, missing: [], found: null };
  const discover = async (where: Record<string, unknown>): Promise<DiscoverResult> => {
    try {
      return await provider.discoverOptions!({ ...cfg, ...where } as never);
    } catch {
      return { errors: { projects: 'error', regions: 'error', networks: 'error' } };
    }
  };
  const placements = (await ctx.runQuery(internal.edgeLocations.listForAccount, { accountId })).map(
    (l) => l.placement as Record<string, unknown>,
  );
  let projects: DiscoverResult['projects'];
  let projectsFailed = false;
  if (needsProject(providerId, chosen)) {
    const listed = await discover({});
    projectsFailed = !!listed.errors?.projects || !listed.projects;
    projects = projectsFailed ? undefined : listed.projects;
  }
  let filled = completePlacement(providerId, chosen, { projects }, placements);
  if (projectsFailed && needsProject(providerId, filled.placement))
    throw new ConvexError({
      code: 'edge.location_unchecked',
      message: 'The provider did not list its projects; try again',
    });
  let found: DiscoverResult | null = null;
  // The networks of a region are listed once its project and region are known.
  const networkOnly = filled.missing.every((k) => k === 'networkId' || k === 'subnetId');
  if (needsNetwork(providerId, filled.placement) && networkOnly) {
    found = await discover(filled.placement);
    filled = completePlacement(providerId, filled.placement, { networks: found.networks });
  }
  return { ...filled, found };
}

/**
 * A CDN place's own state, which a check reports while the key still reaches
 * it in full: a credential rotation records these and goes on.
 */
const ZONE_STATE_REFUSALS: ReadonlySet<string> = new Set([
  'zone_ssl_off',
  'zone_paused',
  'zone_not_active',
  'zone_name_mismatch',
  'caa_forbids_ca',
  // What a front needs of a fronting DNS account's zone.
  'edge_certificate_missing',
]);

/** A CDN place the provider reached but refused, in words for the admin (`edge.location_unusable`). */
const LOCATION_REFUSALS: Record<string, string> = {
  zone_ssl_off: "That zone's encryption mode is off: set Flexible, Full or Full (strict) first",
  zone_paused: 'That zone is paused at the provider',
  zone_not_active: 'That zone is not active at the provider yet',
  zone_name_mismatch:
    "That zone's name changed at the provider: refresh the list and pick it again",
  tls_configuration_missing: 'This Fastly key does not see that TLS configuration',
  caa_forbids_ca:
    "That zone's CAA records do not let the account's certificate authority issue: allow it, or pick another authority",
  edge_certificate_missing:
    'That zone has no edge certificate for its first-level names: turn Universal SSL on, or order one',
};

/**
 * Add a location to an account: the provider's own listing must offer the
 * region to this key (`edge.location_not_offered`; a listing that failed is
 * `edge.location_unchecked`, never a guess), and its name becomes the label.
 * Creating a location the account already has returns it. Its inventory is
 * pulled at once (fail-soft).
 *
 * `fill` (a region picked when a node is protected or given another
 * location): a placement naming its region is completed from what the key
 * reaches (`completeRegionPick`); a value no default fills is refused
 * `edge.location_options_needed`, naming it, so the form can ask for it.
 */
export const createLocation = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    placement: v.any(),
    fill: v.optional(v.boolean()),
    regionalParams: v.optional(v.any()),
    maxLiveEdges: v.optional(v.number()),
    costNote: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<{ id: string; created: boolean }> => {
    const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
      id: a.accountId,
    });
    if (!acct) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    let raw = { ...((a.placement as Record<string, unknown> | undefined) ?? {}) };
    const provider = edgeProviderFor(acct.provider);
    let filledLists: DiscoverResult | null = null;
    if (a.fill) {
      const { cfg } = await loadAdapter(ctx, a.accountId);
      const filled = await completeRegionPick(ctx, a.accountId, acct.provider, provider, cfg, raw);
      if (filled.missing.length > 0)
        throw new ConvexError({
          code: 'edge.location_options_needed',
          message: `Choose ${filled.missing.join(', ')} for this location`,
          missing: filled.missing,
        });
      raw = filled.placement;
      filledLists = filled.found;
    }
    /** A CDN place checked with the credentials that will use it (its zone, a front's DNS account, TLS configuration). */
    const checkPlace = async (placement: Record<string, unknown>): Promise<LocationCheckResult> => {
      try {
        const { cfg } = await loadAdapter(
          ctx,
          a.accountId,
          undefined,
          undefined,
          undefined,
          placement,
        );
        return await provider.checkLocation!(cfg);
      } catch (err) {
        if (toOpsFailure(err).data.code === 'dns_account_missing')
          throw new ConvexError({
            code: 'edge.dns_account_unusable',
            message: 'That DNS account cannot be used: it is missing or has no token',
          });
        throw new ConvexError({
          code: 'edge.location_unchecked',
          message: 'The provider could not be asked about that zone; try again',
        });
      }
    };
    let check: LocationCheckResult | undefined;
    // A zone picked by id alone takes its name from the catalog's listing, or
    // (an id typed by hand) from the provider's own answer.
    if (typeof raw.zoneId === 'string' && typeof raw.zoneName !== 'string') {
      const lister =
        typeof raw.dnsAccountId === 'string'
          ? (raw.dnsAccountId as Id<'edgeProviderAccounts'>)
          : a.accountId;
      const listed = await ctx.runQuery(internal.edgeProviderCatalog.zoneOf, {
        accountId: lister,
        zoneId: raw.zoneId,
      });
      if (listed) raw.zoneName = listed.label;
      else if (provider.checkLocation) {
        check = await checkPlace({ ...raw, type: acct.provider });
        if (check.zoneName) raw.zoneName = check.zoneName;
      }
    }
    const parsed = validatePlacement(acct.provider, raw);
    if (!parsed.ok)
      throw new ConvexError({ code: 'validation', message: parsed.issues.join('; ') });
    const placeKey = placeKeyOf(parsed.placement);
    let label: string | undefined;
    let observed: Record<string, string> | undefined;
    if (provider.checkLocation) {
      check ??= await checkPlace(parsed.placement as Record<string, unknown>);
      if (!check.ok) {
        const why = LOCATION_REFUSALS[check.code ?? ''];
        throw new ConvexError({
          code: why ? 'edge.location_unusable' : 'edge.location_not_offered',
          message: why ?? 'This key cannot reach that zone',
          reason: check.code ?? 'error',
        });
      }
      label = check.label;
      observed = check.observed;
    } else if (provider.discoverOptions) {
      const { type: _t, ...where } = parsed.placement as Record<string, unknown>;
      // A filled pick may already hold the listing made with this project and region.
      let found: DiscoverResult;
      if (filledLists?.regions && !filledLists.errors?.regions) found = filledLists;
      else {
        const { cfg } = await loadAdapter(ctx, a.accountId);
        try {
          found = await provider.discoverOptions({ ...cfg, ...where } as never);
        } catch {
          found = { errors: { regions: 'error' } };
        }
      }
      if (found.errors?.regions || !found.regions)
        throw new ConvexError({
          code: 'edge.location_unchecked',
          message: 'The provider did not list its regions; try again',
        });
      const offered = found.regions.find((r) => String(r.id) === placeKey);
      if (!offered)
        throw new ConvexError({
          code: 'edge.location_not_offered',
          message: 'This key cannot create load balancers in that region',
        });
      label = offered.label;
    }
    const res: { id: string; created: boolean } = await ctx.runMutation(
      internal.edgeLocations.create,
      {
        accountId: a.accountId,
        placement: parsed.placement,
        label,
        regionalParams: a.regionalParams,
        maxLiveEdges: a.maxLiveEdges,
        costNote: a.costNote,
        ...(observed ? { observed } : {}),
        actorAdminId: a.actorAdminId,
      },
    );
    if (res.created && !provider.checkLocation)
      await ctx.scheduler.runAfter(0, internal.edgeProviderOps.inventory, {
        accountId: a.accountId,
        locationId: res.id as Id<'edgeLocations'>,
      });
    return res;
  },
});

/**
 * Give the locations named after their bare region id the name their provider
 * lists for that region (an account migrated into locations had no name to
 * copy). Fail-soft per location (a read the provider refuses leaves the id);
 * scheduled by `seedCutover`, and it touches only such rows.
 */
export const relabelLocations = internalAction({
  args: {},
  handler: async (ctx): Promise<{ named: number }> => {
    const rows = await ctx.runQuery(internal.edgeLocations.unnamed, {});
    let named = 0;
    for (const row of rows) {
      try {
        const { provider, cfg } = await loadAdapter(
          ctx,
          row.accountId,
          undefined,
          undefined,
          row.id,
        );
        if (!provider.listRegions) continue;
        const region = (await provider.listRegions(cfg)).find((r) => String(r.id) === row.placeKey);
        if (!region?.label || region.label === row.placeKey) continue;
        await ctx.runMutation(internal.edgeLocations.setLabel, { id: row.id, label: region.label });
        named++;
      } catch {
        // The id stays the label; the next deploy asks again.
      }
    }
    return { named };
  },
});

export const listRegions = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<Array<{ id: string; label: string }>> =>
    tracked(ctx, accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, seen);
      return provider.listRegions ? provider.listRegions(cfg) : [];
    }),
});

/**
 * One location's inventory (its region's load balancers, addresses and
 * flavors), the account's default location when none is named; recorded on
 * the location. An account without a location yet has nothing to list.
 */
export const inventory = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), locationId: v.optional(v.id('edgeLocations')) },
  handler: (ctx, a): Promise<Inventory> =>
    tracked(ctx, a.accountId, async (seen) => {
      const accountId = a.accountId;
      const locationId =
        a.locationId ??
        (await ctx.runQuery(internal.edgeLocations.defaultOf, { accountId })) ??
        undefined;
      if (!locationId) return { loadBalancers: [], ips: [], flavors: [] };
      const { provider, cfg } = await loadAdapter(ctx, accountId, undefined, seen, locationId);
      const inv = await provider.inventory(cfg);
      await ctx.runMutation(internal.edgeProviderAccounts.recordInventory, {
        id: accountId,
        locationId,
        inventory: JSON.stringify(inv),
      });
      // The place's observed facts (a zone's encryption mode) go stale exactly
      // like the inventory does, and planning refuses without them. Check the
      // location again on the same operator action; a failing check never fails
      // the inventory pull, which is the thing that was asked for.
      if (provider.checkLocation) {
        try {
          const res = await provider.checkLocation(cfg);
          await ctx.runMutation(internal.edgeLocations.recordCheck, {
            id: locationId,
            ok: res.ok,
            code: res.code,
            detail: res.detail,
            observed: res.observed,
          });
        } catch {
          // Deliberately silent: the inventory the operator asked for is already in.
        }
      }
      return inv;
    }),
});

// --- provisioning steps ------------------------------------------------------------

export const planProvision = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    /** The location the new edge is created in (its placement is frozen on the edge). */
    locationId: v.optional(v.id('edgeLocations')),
    spec: edgeSpec,
    templateParams: v.any(),
    /** What the listener speaks, so the carriage / port rules can be checked. */
    proto: v.optional(v.object(listenerProtoFields)),
    /** The zone's observed encryption mode (L7), checked against the origin transport. */
    zoneSslMode: v.optional(v.string()),
  },
  handler: (ctx, a): Promise<ResourceStep[]> => {
    const names: string[] = [];
    refusalNames(names, { spec: a.spec });
    return run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(
        ctx,
        a.accountId,
        undefined,
        undefined,
        a.locationId,
      );
      refusalNames(names, { cfg });
      const tpl = renderedTemplate(provider, a.templateParams, a.spec, a.zoneSslMode);
      checkSpec(providerId, a.spec, a.proto, tpl, a.zoneSslMode);
      return provider.planProvision(cfg, a.spec, tpl);
    }, names);
  },
});

export const runStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    templateParams: v.any(),
    step: resourceStep,
    ledger,
    edgeId: v.optional(v.id('edges')),
    proto: v.optional(v.object(listenerProtoFields)),
  },
  handler: (ctx, a): Promise<StepOutcome> => {
    // A create the provider refuses comes back with its reason, scrubbed of these.
    const names: string[] = [a.step.resourceName];
    refusalNames(names, { spec: a.spec, ledger: a.ledger as Ledger });
    return tracked(
      ctx,
      a.accountId,
      async (seen) => {
        const { provider, cfg, providerId, intent } = await loadAdapter(
          ctx,
          a.accountId,
          a.edgeId,
          seen,
        );
        refusalNames(names, { intent, cfg });
        const tpl = renderedTemplate(provider, a.templateParams, a.spec, intent?.zoneSslMode);
        checkSpec(providerId, a.spec, a.proto, tpl, intent?.zoneSslMode);
        return scrubbedOutcome(
          await provider.runStep(cfg, a.step as ResourceStep, a.spec, tpl, a.ledger as Ledger),
          names,
        );
      },
      names,
    );
  },
});

export const pollStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    step: resourceStep,
    opRef: v.string(),
    ledger,
    edgeId: v.optional(v.id('edges')),
  },
  handler: (ctx, a): Promise<StepOutcome> => {
    const names: string[] = [a.step.resourceName];
    refusalNames(names, { ledger: a.ledger as Ledger });
    return tracked(
      ctx,
      a.accountId,
      async (seen) => {
        const { provider, cfg, providerId, intent } = await loadAdapter(
          ctx,
          a.accountId,
          a.edgeId,
          seen,
        );
        refusalNames(names, { intent, cfg });
        // A `requested` step exists only because the adapter asked to be polled.
        // Fabricating `done` here would mark an allocating step complete with an
        // EMPTY ledger: the resource it created would never be recorded, never be
        // destroyed, and stay billable forever. An adapter that plans async steps
        // without a poller is a contract violation, not a success.
        if (!provider.pollStep)
          throw new ConvexError<EdgeProviderOpsFailure>({
            code: 'contract_violation',
            message: `${providerId} has no pollStep but planned an async step`,
            provider: providerId,
            step: a.step.id,
            retryable: false,
            timedOut: false,
          });
        return scrubbedOutcome(
          await provider.pollStep(cfg, a.step as ResourceStep, a.opRef, a.ledger as Ledger),
          names,
        );
      },
      names,
    );
  },
});

export const discover = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    step: resourceStep,
    ledger,
    attempt: v.number(),
    edgeId: v.optional(v.id('edges')),
    /**
     * Fallback reference time for the step (`step.startedAt ?? currentOp.claimedAt
     * ?? edge._creationTime`). An adapter promotes "the listing shows nothing"
     * to `confirmed_absent` only once its settle floor has passed since the step
     * was first requested; with no reference time the floor cannot be proven and
     * the answer must stay `unresolved`. A lost settle can leave `startedAt`
     * unstamped, so the caller supplies what it knows.
     */
    stepStartedAt: v.optional(v.number()),
  },
  handler: (ctx, a): Promise<Discovery> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      const ledgerWithReference =
        a.stepStartedAt === undefined
          ? (a.ledger as Ledger)
          : {
              ...(a.ledger as Ledger),
              steps: (a.ledger as Ledger).steps.map((st) =>
                st.stepId === a.step.id
                  ? { ...st, startedAt: st.startedAt ?? a.stepStartedAt }
                  : st,
              ),
            };
      return provider.discover(cfg, a.step as ResourceStep, a.spec, ledgerWithReference, a.attempt);
    }),
});

/**
 * `describe` and `inspect` answer with what the adapter read, which for an SDK
 * adapter holds class values (`Date`s) Convex cannot return: both go through
 * `jsonSafe` here, once, for every adapter.
 */
export const describe = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a): Promise<EdgeDescription> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      return jsonSafe(await provider.describe(cfg, a.ledger as Ledger)) as EdgeDescription;
    }),
});

/**
 * Save an edge's configuration again, unchanged (`EdgeProvider.reapply`): a
 * guided run's one retry when its outside check finds a new address
 * unreachable. `not_offered` when the adapter has nothing to save again.
 */
export const reapply = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a): Promise<ReapplyOutcome | { status: 'skipped'; code: 'not_offered' }> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      if (!provider.reapply) return { status: 'skipped' as const, code: 'not_offered' as const };
      return provider.reapply(cfg, a.ledger as Ledger);
    }),
});

export const inspect = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a): Promise<InspectResult> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      return jsonSafe(await provider.inspect(cfg, a.ledger as Ledger)) as InspectResult;
    }),
});

/**
 * What an EXISTING provider resource an operator wants to import really is: the
 * ledger children FCP should record (with the provider's own ids and versions,
 * so discovery and destroy never depend on a generated name), every hostname it
 * serves, whether it is SHARED with other hostnames, and what it dials. An
 * adapter that cannot answer refuses `adoption_unsupported`: importing a front
 * FCP cannot describe would produce an edge that can never qualify.
 */
export const inspectForAdoption = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    /** Where the resource lives (the account's default location when absent). */
    locationId: v.optional(v.id('edgeLocations')),
    resourceId: v.string(),
    hostname: v.string(),
  },
  handler: (ctx, a): Promise<AdoptionInspection> =>
    run(async () => {
      const locationId =
        a.locationId ??
        (await ctx.runQuery(internal.edgeLocations.defaultOf, { accountId: a.accountId })) ??
        undefined;
      const { provider, cfg, providerId } = await loadAdapter(
        ctx,
        a.accountId,
        undefined,
        undefined,
        locationId,
      );
      if (!provider.inspectForAdoption)
        refuse(
          'adoption_unsupported',
          `${providerId} edges cannot be imported from a resource`,
          providerId,
        );
      return provider.inspectForAdoption(cfg, a.resourceId, a.hostname);
    }),
});

// --- destroy -------------------------------------------------------------------------

const sharedTeardownState = v.object({
  phase: v.string(),
  serviceId: v.string(),
  fromVersion: v.optional(v.number()),
  workVersion: v.optional(v.number()),
  code: v.optional(v.string()),
  /** The driver's own extra fields (JSON, adapter-shaped). */
  extra: v.optional(v.string()),
});

type SharedStateWire = {
  phase: string;
  serviceId: string;
  fromVersion?: number;
  workVersion?: number;
  code?: string;
  extra?: string;
};

/** Wire shape → the driver's own state object (its extra fields spread back on). */
function fromWire(s: SharedStateWire): SharedTeardownState {
  let extra: Record<string, unknown> = {};
  if (s.extra) {
    try {
      const raw = JSON.parse(s.extra) as unknown;
      if (raw && typeof raw === 'object' && !Array.isArray(raw))
        extra = raw as Record<string, unknown>;
    } catch {
      extra = {};
    }
  }
  const { extra: _drop, ...known } = s;
  return { ...extra, ...known } as SharedTeardownState;
}

/** The driver's state → the wire shape (known columns + the rest as JSON). */
export function toWire(s: SharedTeardownState): SharedStateWire {
  const { phase, serviceId, fromVersion, workVersion, code, ...rest } = s;
  return {
    phase,
    serviceId,
    ...(typeof fromVersion === 'number' ? { fromVersion } : {}),
    ...(typeof workVersion === 'number' ? { workVersion } : {}),
    ...(typeof code === 'string' ? { code } : {}),
    ...(Object.keys(rest).length > 0 ? { extra: JSON.stringify(rest).slice(0, 4_000) } : {}),
  };
}

/**
 * The INITIAL state of a shared-resource teardown, or `null` when the ledger
 * describes a resource FCP owns exclusively (the ordinary destroy walk then
 * applies). Pure at the adapter; an action only because the adapter lives in
 * the Node runtime.
 */
export const planSharedTeardown = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    ledger,
    opId: v.string(),
    edgeId: v.optional(v.id('edges')),
  },
  handler: (ctx, a): Promise<SharedStateWire | null> =>
    run(async () => {
      const { provider } = await loadAdapter(ctx, a.accountId, a.edgeId);
      if (!provider.sharedTeardown) return null;
      const state = provider.sharedTeardown.plan(a.ledger as Ledger, a.opId, Date.now());
      return state ? toWire(state) : null;
    }),
});

/**
 * ONE phase of a shared-resource teardown (Fastly: clone → remove domain →
 * validate → activate → confirm). The caller persists what comes back and calls
 * again next pass, under the per-service external lock; terminal phases are
 * `done` and `needs_operator`.
 */
export const sharedTeardownStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    edgeId: v.optional(v.id('edges')),
    state: sharedTeardownState,
  },
  handler: (ctx, a): Promise<SharedStateWire> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      if (!provider.sharedTeardown)
        refuse(
          'shared_teardown_unsupported',
          `${providerId} edges have no shared-resource teardown`,
          providerId,
        );
      return toWire(await provider.sharedTeardown.step(cfg, fromWire(a.state)));
    }),
});

export const planDestroy = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a) =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
      return provider.planDestroy(cfg, a.ledger as Ledger);
    }),
});

export const runDestroy = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    resource: ledgerResource,
    ledger,
    edgeId: v.optional(v.id('edges')),
  },
  handler: (ctx, a): Promise<DestroyOutcome> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
    }),
});

export const confirmDestroyed = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    resource: ledgerResource,
    ledger,
    edgeId: v.optional(v.id('edges')),
  },
  handler: (ctx, a): Promise<DestroyOutcome> =>
    tracked(ctx, a.accountId, async (seen) => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId, seen);
      // A provider without an async-delete confirmation deletes synchronously, so
      // the delete is idempotent: re-issue it. 404 → gone; still present → deleted
      // now; a throw stays `delete_requested` for the next pass. Never assume gone.
      if (!provider.confirmDestroyed)
        return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
      return provider.confirmDestroyed(cfg, a.resource, a.ledger as Ledger);
    }),
});
