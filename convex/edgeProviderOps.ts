'use node';
/**
 * Relay-edge provider operations — the "use node" half of the relay layer.
 *
 * Everything that talks to a cloud load-balancer provider's API (provisioning
 * steps, discovery, describe/inspect, inventory, destroy) runs here so provider
 * SDKs that assume a Node runtime can be used. This module holds ACTIONS ONLY
 * and each action is one bounded provider round trip: it loads the account
 * (with its credentials) through an internal query, builds the adapter config,
 * performs exactly the requested operation and returns plain data. Every state
 * change goes back through the isolate mutations (edgeRotations / edges),
 * which are the sole writers of relay state.
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
import { unsupportedTransport } from './lib/edges/providers/capabilities';
import { renderTemplateValue } from './lib/edges/providers/template';
import { isRelayProviderId, type EdgeProviderId } from './lib/edgeProviderIds';
import {
  buildCredentials,
  pickCredentialIdentifiers,
  validateSettings,
} from './lib/edges/accountSettings';
import type {
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

async function loadAdapter(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<{ provider: EdgeProvider; cfg: EdgeProviderConfig; providerId: EdgeProviderId }> {
  const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, { id: accountId });
  if (!acct) {
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'account_missing',
      message: 'relay account not found',
      step: 'load',
      retryable: false,
      timedOut: false,
    });
  }
  const cfg = edgeProviderConfigFrom(
    acct.credentials as Record<string, unknown> & { type: typeof acct.provider },
    acct.settings as Record<string, unknown> & { type: typeof acct.provider },
  );
  return { provider: edgeProviderFor(acct.provider), cfg, providerId: acct.provider };
}

/** Template params are validated by the adapter schema, then placeholders rendered. */
function renderedTemplate(
  provider: EdgeProvider,
  params: unknown,
  spec: EdgeSpec,
): Record<string, unknown> {
  const parsed = provider.templateSchema.parse(params ?? {}) as Record<string, unknown>;
  return renderTemplateValue(parsed, spec);
}

/** Refuse a transport the provider cannot carry BEFORE any provider call. */
function checkTransport(providerId: EdgeProviderId, spec: EdgeSpec): void {
  const bad = unsupportedTransport(providerId, spec);
  if (bad)
    throw new ConvexError<EdgeProviderOpsFailure>({
      code: 'transport_unsupported',
      message: `${providerId} edges cannot carry ${bad} listeners`,
      provider: providerId,
      step: 'plan',
      retryable: false,
      timedOut: false,
    });
}

// --- credentials / discovery of provider metadata ---------------------------------

export const testCredentials = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: (ctx, { accountId }): Promise<{ ok: boolean; code?: string }> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, accountId);
      const res = await provider.testCredentials(cfg);
      await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
        id: accountId,
        ok: res.ok,
        code: res.code,
      });
      return { ok: res.ok, code: res.code };
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
    | { ok: false; code: string }
  > =>
    run(async () => {
      const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
        id: a.accountId,
      });
      if (!acct)
        throw new ConvexError<EdgeProviderOpsFailure>({
          code: 'account_missing',
          message: 'relay account not found',
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
      if (!res.ok) return { ok: false, code: res.code ?? 'error' };
      const applied = await ctx.runMutation(internal.edgeProviderAccounts.applyCredentialRotation, {
        id: a.accountId,
        credentials: a.credentials,
        identifiers: a.identifiers,
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
      return inv;
    }),
});

// --- provisioning steps ------------------------------------------------------------

export const planProvision = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), spec: edgeSpec, templateParams: v.any() },
  handler: (ctx, { accountId, spec, templateParams }): Promise<ResourceStep[]> =>
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, accountId);
      checkTransport(providerId, spec);
      return provider.planProvision(cfg, spec, renderedTemplate(provider, templateParams, spec));
    }),
});

export const runStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    templateParams: v.any(),
    step: resourceStep,
    ledger,
  },
  handler: (ctx, a): Promise<StepOutcome> =>
    run(async () => {
      const { provider, cfg, providerId } = await loadAdapter(ctx, a.accountId);
      checkTransport(providerId, a.spec);
      return provider.runStep(
        cfg,
        a.step as ResourceStep,
        a.spec,
        renderedTemplate(provider, a.templateParams, a.spec),
        a.ledger as Ledger,
      );
    }),
});

export const pollStep = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), step: resourceStep, opRef: v.string(), ledger },
  handler: (ctx, a): Promise<StepOutcome> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      if (!provider.pollStep) return { status: 'done', resources: [] };
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
  },
  handler: (ctx, a): Promise<Discovery> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      return provider.discover(cfg, a.step as ResourceStep, a.spec, a.ledger as Ledger, a.attempt);
    }),
});

export const describe = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: (ctx, a): Promise<EdgeDescription> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      return provider.describe(cfg, a.ledger as Ledger);
    }),
});

export const inspect = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: (ctx, a): Promise<InspectResult> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      return provider.inspect(cfg, a.ledger as Ledger);
    }),
});

// --- destroy -------------------------------------------------------------------------

export const planDestroy = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: (ctx, a) =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      return provider.planDestroy(cfg, a.ledger as Ledger);
    }),
});

export const runDestroy = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), resource: ledgerResource, ledger },
  handler: (ctx, a): Promise<DestroyOutcome> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
    }),
});

export const confirmDestroyed = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), resource: ledgerResource, ledger },
  handler: (ctx, a): Promise<DestroyOutcome> =>
    run(async () => {
      const { provider, cfg } = await loadAdapter(ctx, a.accountId);
      // A provider without an async-delete confirmation deletes synchronously, so
      // the delete is idempotent: re-issue it. 404 → gone; still present → deleted
      // now; a throw stays `delete_requested` for the next pass. Never assume gone.
      if (!provider.confirmDestroyed)
        return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
      return provider.confirmDestroyed(cfg, a.resource, a.ledger as Ledger);
    }),
});
