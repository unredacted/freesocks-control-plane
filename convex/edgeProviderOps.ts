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
 * so the callers' `errCode`/`errText` can read `err.data.code` etc.
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
import { EdgeProviderError } from './lib/edges/providers/http';
import {
  EDGE_PROVIDER_CAPABILITIES,
  protocolCarriedBy,
  unsupportedTransport,
  zoneModeGovernsOrigin,
} from './lib/edges/providers/capabilities';
import { renderTemplateValue } from './lib/edges/providers/template';
import { isRelayProviderId, type EdgeProviderId } from './lib/edgeProviderIds';
import { parseIntent, type ProvisionIntent } from './lib/edges/intent';
import type { ListenerProto } from './lib/edges/protocols';
import { listenerProtoFields } from './lib/edgeProtocolIds';
import {
  buildCredentials,
  pickCredentialIdentifiers,
  validateSettings,
  EDGE_INTENT_DEFAULT_SETTINGS,
} from './lib/edges/accountSettings';
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
  EdgeProvider,
  EdgeProviderConfig,
  ResourceStep,
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
 * body-free message. Never a URL, header, response body or credential.
 */
export type EdgeProviderOpsFailure = {
  code: string;
  message: string;
  provider?: EdgeProviderId;
  step?: string;
  status?: number;
  retryable: boolean;
  timedOut: boolean;
};

const URL_RE = /https?:\/\/[^\s'")]+/gi;

/** Wrap any throw into a ConvexError whose data survives the action boundary. */
export function toOpsFailure(err: unknown): ConvexError<EdgeProviderOpsFailure> {
  if (err instanceof ConvexError) return err as ConvexError<EdgeProviderOpsFailure>;
  if (err instanceof EdgeProviderError) {
    const m = err.meta;
    return new ConvexError<EdgeProviderOpsFailure>({
      code:
        m.code ?? (m.status !== undefined ? String(m.status) : m.timedOut ? 'timeout' : 'error'),
      message: err.message.slice(0, 200),
      provider: m.provider,
      step: m.step,
      status: m.status,
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

/** Run one action body; any throw crosses the action boundary as `ConvexError<EdgeProviderOpsFailure>`. */
async function run<R>(fn: () => Promise<R>): Promise<R> {
  try {
    return await fn();
  } catch (err) {
    throw toOpsFailure(err);
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
 * The adapter + its config for one account.
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
  const cfg = edgeProviderConfigFrom(
    acct.credentials as Record<string, unknown> & { type: typeof acct.provider },
    acct.settings as Record<string, unknown> & { type: typeof acct.provider },
  );
  // Acting on an EXISTING edge: every setting the intent froze wins over the
  // account row. The zone/DNS account below is one of them; so is the TLS
  // subscription (`certificateAuthority`, `tlsConfigurationId`), which decides
  // which certificate a describe or a destroy acts on. A settings edit after
  // planning must not move a live edge's certificate to another subscription.
  const intent = edgeId ? await ctx.runQuery(internal.edges.intentOf, { edgeId }) : null;
  if (intent) {
    const frozen = intent as unknown as Record<string, unknown>;
    for (const key of EDGE_INTENT_DEFAULT_SETTINGS[acct.provider]) {
      if (frozen[key] !== undefined) (cfg as unknown as Record<string, unknown>)[key] = frozen[key];
    }
  }
  if (EDGE_PROVIDER_CAPABILITIES[acct.provider].needsDnsAccount) {
    let dnsAccountId = (acct.settings as { dnsAccountId?: string }).dnsAccountId;
    let zoneId: string | undefined;
    let zoneName: string | undefined;
    if (intent) {
      dnsAccountId = intent.dnsAccountId ?? dnsAccountId;
      zoneId = intent.zoneId;
      zoneName = intent.zoneName;
    }
    if (!dnsAccountId) {
      throw new ConvexError<EdgeProviderOpsFailure>({
        code: 'dns_account_missing',
        message: 'this provider needs a DNS account',
        step: 'load',
        retryable: false,
        timedOut: false,
      });
    }
    const dns = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
      id: dnsAccountId as Id<'edgeProviderAccounts'>,
    });
    const dnsSettings = dns?.settings as { zoneId?: string; zoneName?: string } | undefined;
    const apiToken = (dns?.credentials as { apiToken?: string } | undefined)?.apiToken;
    if (!dns || !apiToken || !(zoneId ?? dnsSettings?.zoneId)) {
      throw new ConvexError<EdgeProviderOpsFailure>({
        code: 'dns_account_missing',
        message: 'the referenced DNS account is unusable',
        step: 'load',
        retryable: false,
        timedOut: false,
      });
    }
    (cfg as { dns?: unknown }).dns = {
      apiToken,
      zoneId: zoneId ?? dnsSettings!.zoneId!,
      zoneName: zoneName ?? dnsSettings?.zoneName ?? '',
      accountId: dnsAccountId,
    };
  }
  return { provider: edgeProviderFor(acct.provider), cfg, providerId: acct.provider, intent };
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
  args: { accountId: v.id('edgeProviderAccounts'), spec: edgeSpec, templateParams: v.any() },
  handler: (ctx, { accountId, spec, templateParams }): Promise<Record<string, unknown>> =>
    run(async () => {
      const { provider } = await loadAdapter(ctx, accountId);
      return renderedTemplate(provider, templateParams, spec);
    }),
});

// --- credentials / discovery of provider metadata ---------------------------------

export const testCredentials = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<{ ok: boolean; code?: string; detail?: string }> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, accountId);
      const res = await provider.testCredentials(cfg);
      // A passing test's `detail` is adapter prose about the zone, not a refusal.
      const detail = res.ok ? undefined : res.detail;
      await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
        id: accountId,
        ok: res.ok,
        code: res.code,
        detail,
        observed: res.observed,
      });
      return { ok: res.ok, code: res.code, detail };
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
        ...(acct.settings as Record<string, unknown>),
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
      const res = await edgeProviderFor(acct.provider).testCredentials(cfg);
      // The stored (still valid) credentials are untouched on a failed test.
      if (!res.ok) return { ok: false, code: res.code ?? 'error', detail: res.detail };
      // Apply EXACTLY what was tested, against the row version it was built from.
      const applied = await ctx.runMutation(internal.edgeProviderAccounts.applyCredentialRotation, {
        id: a.accountId,
        credentials: creds.credentials,
        settings: settings.settings,
        // The test just observed the zone's live facts (encryption mode, WebSockets);
        // a rotation must refresh them like a credential test does, or planning
        // keeps freezing a mode the zone no longer has.
        observed: res.observed,
        expectedUpdatedAt: acct.updatedAt,
        actorAdminId: a.actorAdminId,
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

export const listRegions = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<Array<{ id: string; label: string }>> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, accountId);
      return provider.listRegions ? provider.listRegions(cfg) : [];
    }),
});

export const inventory = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<Inventory> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, accountId);
      const inv = await provider.inventory(cfg);
      await ctx.runMutation(internal.edgeProviderAccounts.recordInventory, {
        id: accountId,
        inventory: JSON.stringify(inv),
      });
      // The observed facts (a zone's encryption mode) go stale exactly like the
      // inventory does, and planning refuses without them. Refresh them on the
      // same operator action; a failing test never fails the inventory pull,
      // which is the thing that was asked for.
      try {
        const res = await provider.testCredentials(cfg);
        await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
          id: accountId,
          ok: res.ok,
          code: res.code,
          detail: res.ok ? undefined : res.detail,
          observed: res.observed,
        });
      } catch {
        // Deliberately silent: the inventory the operator asked for is already in.
      }
      return inv;
    }),
});

// --- provisioning steps ------------------------------------------------------------

export const planProvision = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    templateParams: v.any(),
    /** What the listener speaks, so the carriage / port rules can be checked. */
    proto: v.optional(v.object(listenerProtoFields)),
    /** The zone's observed encryption mode (L7), checked against the origin transport. */
    zoneSslMode: v.optional(v.string()),
  },
  handler: (ctx, a): Promise<ResourceStep[]> =>
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId);
      const tpl = renderedTemplate(provider, a.templateParams, a.spec, a.zoneSslMode);
      checkSpec(providerId, a.spec, a.proto, tpl, a.zoneSslMode);
      return provider.planProvision(cfg, a.spec, tpl);
    }),
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
  handler: (ctx, a): Promise<StepOutcome> =>
    run(async () => {
      const { provider, cfg, providerId, intent } = await loadAdapter(ctx, a.accountId, a.edgeId);
      const tpl = renderedTemplate(provider, a.templateParams, a.spec, intent?.zoneSslMode);
      checkSpec(providerId, a.spec, a.proto, tpl, intent?.zoneSslMode);
      return provider.runStep(cfg, a.step as ResourceStep, a.spec, tpl, a.ledger as Ledger);
    }),
});

export const pollStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    step: resourceStep,
    opRef: v.string(),
    ledger,
    edgeId: v.optional(v.id('edges')),
  },
  handler: (ctx, a): Promise<StepOutcome> =>
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId, a.edgeId);
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
      return provider.pollStep(cfg, a.step as ResourceStep, a.opRef, a.ledger as Ledger);
    }),
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
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
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

export const describe = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a): Promise<EdgeDescription> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
      return provider.describe(cfg, a.ledger as Ledger);
    }),
});

export const inspect = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger, edgeId: v.optional(v.id('edges')) },
  handler: (ctx, a): Promise<InspectResult> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
      return provider.inspect(cfg, a.ledger as Ledger);
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
    resourceId: v.string(),
    hostname: v.string(),
  },
  handler: (ctx, a): Promise<AdoptionInspection> =>
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId);
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
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId, a.edgeId);
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
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
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
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId, a.edgeId);
      // A provider without an async-delete confirmation deletes synchronously, so
      // the delete is idempotent: re-issue it. 404 → gone; still present → deleted
      // now; a throw stays `delete_requested` for the next pass. Never assume gone.
      if (!provider.confirmDestroyed)
        return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
      return provider.confirmDestroyed(cfg, a.resource, a.ledger as Ledger);
    }),
});
