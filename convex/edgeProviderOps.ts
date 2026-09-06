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
 * change goes back through the isolate mutations (relayRotations / relayEdges),
 * which are the sole writers of relay state. Errors thrown here are
 * EdgeProviderError (status + short code, never a body/URL/credential); the
 * callers map them to ledger outcomes.
 *
 * The Node version that executes this file is decided by the self-hosted Convex
 * backend image (its .nvmrc), not by FCP. `runtimeInfo` exposes it so the deploy
 * entrypoint can refuse a backend below the floor the imported packages declare
 * (scripts/node-floor.mjs) and the admin dashboard can show it.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import type { ActionCtx } from './_generated/server';
import { edgeProviderFor, relayConfigFrom } from './lib/relays/providers/registry';
import { EdgeProviderError } from './lib/relays/providers/http';
import { renderTemplateValue } from './lib/relays/providers/template';
import type {
  Discovery,
  EdgeDescription,
  EdgeSpec,
  DestroyOutcome,
  Inventory,
  InspectResult,
  Ledger,
  EdgeProvider,
  RelayProviderConfig,
  ResourceStep,
  StepOutcome,
} from './lib/relays/providers/types';

export const runtimeInfo = internalAction({
  args: {},
  handler: async (): Promise<{ nodeVersion: string }> => {
    return { nodeVersion: process.version };
  },
});

// --- shared validators -----------------------------------------------------------

const edgeSpec = v.object({
  name: v.string(),
  listeners: v.array(
    v.object({
      edgePort: v.number(),
      members: v.array(v.object({ address: v.string(), port: v.number() })),
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
): Promise<{ provider: EdgeProvider; cfg: RelayProviderConfig; providerId: string }> {
  const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, { id: accountId });
  if (!acct) {
    throw new EdgeProviderError('relay account not found', {
      provider: 'gcore',
      step: 'load',
      code: 'account_missing',
      retryable: false,
      timedOut: false,
    });
  }
  const cfg = relayConfigFrom(
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

// --- credentials / discovery of provider metadata ---------------------------------

export const testCredentials = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }): Promise<{ ok: boolean; code?: string }> => {
    const { provider, cfg } = await loadAdapter(ctx, accountId);
    const res = await provider.testCredentials(cfg);
    await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
      id: accountId,
      ok: res.ok,
      code: res.code,
    });
    return { ok: res.ok, code: res.code };
  },
});

export const listRegions = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }): Promise<Array<{ id: string; label: string }>> => {
    const { provider, cfg } = await loadAdapter(ctx, accountId);
    return provider.listRegions ? provider.listRegions(cfg) : [];
  },
});

export const inventory = internalAction({
  args: { accountId: v.id('edgeProviderAccounts') },
  handler: async (ctx, { accountId }): Promise<Inventory> => {
    const { provider, cfg } = await loadAdapter(ctx, accountId);
    const inv = await provider.inventory(cfg);
    await ctx.runMutation(internal.edgeProviderAccounts.recordInventory, {
      id: accountId,
      inventory: JSON.stringify(inv),
    });
    return inv;
  },
});

// --- provisioning steps ------------------------------------------------------------

export const planProvision = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), spec: edgeSpec, templateParams: v.any() },
  handler: async (ctx, { accountId, spec, templateParams }): Promise<ResourceStep[]> => {
    const { provider, cfg } = await loadAdapter(ctx, accountId);
    return provider.planProvision(cfg, spec, renderedTemplate(provider, templateParams, spec));
  },
});

export const runStep = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    templateParams: v.any(),
    step: resourceStep,
    ledger,
  },
  handler: async (ctx, a): Promise<StepOutcome> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.runStep(
      cfg,
      a.step as ResourceStep,
      a.spec,
      renderedTemplate(provider, a.templateParams, a.spec),
      a.ledger as Ledger,
    );
  },
});

export const pollStep = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), step: resourceStep, opRef: v.string(), ledger },
  handler: async (ctx, a): Promise<StepOutcome> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    if (!provider.pollStep) return { status: 'done', resources: [] };
    return provider.pollStep(cfg, a.step as ResourceStep, a.opRef, a.ledger as Ledger);
  },
});

export const discover = internalAction({
  args: {
    accountId: v.id('edgeProviderAccounts'),
    spec: edgeSpec,
    step: resourceStep,
    ledger,
    attempt: v.number(),
  },
  handler: async (ctx, a): Promise<Discovery> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.discover(cfg, a.step as ResourceStep, a.spec, a.ledger as Ledger, a.attempt);
  },
});

export const describe = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: async (ctx, a): Promise<EdgeDescription> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.describe(cfg, a.ledger as Ledger);
  },
});

export const inspect = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: async (ctx, a): Promise<InspectResult> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.inspect(cfg, a.ledger as Ledger);
  },
});

// --- destroy -------------------------------------------------------------------------

export const planDestroy = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), ledger },
  handler: async (ctx, a) => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.planDestroy(cfg, a.ledger as Ledger);
  },
});

export const runDestroy = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), resource: ledgerResource, ledger },
  handler: async (ctx, a): Promise<DestroyOutcome> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
  },
});

export const confirmDestroyed = internalAction({
  args: { accountId: v.id('edgeProviderAccounts'), resource: ledgerResource, ledger },
  handler: async (ctx, a): Promise<DestroyOutcome> => {
    const { provider, cfg } = await loadAdapter(ctx, a.accountId);
    // A provider without an async-delete confirmation deletes synchronously, so
    // the delete is idempotent: re-issue it. 404 → gone; still present → deleted
    // now; a throw stays `delete_requested` for the next pass. Never assume gone.
    if (!provider.confirmDestroyed) return provider.runDestroy(cfg, a.resource, a.ledger as Ledger);
    return provider.confirmDestroyed(cfg, a.resource, a.ledger as Ledger);
  },
});
