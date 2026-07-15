/**
 * Proxy-backend operations as Convex actions (external HTTP -> V8 runtime). The
 * dispatch is now GENERIC: it resolves a backend INSTANCE (a `backendServers`
 * row of any type) and calls that type's provider from the registry
 * (convex/lib/backends/registry.ts). There are no per-backend `if` arms and no
 * env-based config: every backend (Remnawave, Outline, ...) is a DB-managed
 * instance, picked from the scored pool at issuance and resolved by key for
 * later reads/updates.
 *
 *  - issueUser dispatches on the tier's backend TYPE, picks an active instance of
 *    that type, and returns the chosen `backendServerId` (persisted on the sub).
 *  - get/update/reset/delete resolve the instance from the subscription row by
 *    `backendUserId`; the passed `backend` is vestigial (the resolved instance is
 *    authoritative) and kept only to avoid churning call sites.
 *  - delete + fetchContent also accept a `backendServerId` hint for the points in
 *    the saga where the subscription row does not exist yet (issuance compensation
 *    + the S3 mirror fetch).
 *
 * The dev mock backend (double-gated, DEV_MOCK_BACKEND + ENVIRONMENT=development)
 * still short-circuits every op so the full flow works without a real instance.
 */
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import type {
  IssueUserSpec,
  IssuedUser,
  SubscriptionContent,
  UpdateUserPatch,
  UsageSeries,
  UserState,
} from './lib/backends/types';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import {
  mockBackendEnabled,
  mockFetchContent,
  mockGetUser,
  mockIssueUser,
} from './lib/backends/mock';
import { isRemnawaveNotFound } from './lib/backends/remnawave';

// Keep in sync with BACKEND_IDS (src/shared/contracts/backends.ts).
const backendId = v.union(v.literal('remnawave'), v.literal('outline'));
const trafficStrategy = v.union(
  v.literal('NO_RESET'),
  v.literal('DAY'),
  v.literal('WEEK'),
  v.literal('MONTH'),
);

const issueSpec = v.object({
  username: v.string(),
  trafficLimitBytes: v.union(v.number(), v.null()),
  expireAt: v.union(v.string(), v.null()),
  tag: v.string(),
  description: v.optional(v.string()),
  hwidDeviceLimit: v.optional(v.union(v.number(), v.null())),
  trafficLimitStrategy: v.optional(trafficStrategy),
  placement: v.optional(v.union(v.string(), v.null())),
});

const updatePatch = v.object({
  trafficLimitBytes: v.optional(v.union(v.number(), v.null())),
  expireAt: v.optional(v.union(v.string(), v.null())),
  tag: v.optional(v.string()),
  description: v.optional(v.string()),
  hwidDeviceLimit: v.optional(v.union(v.number(), v.null())),
  trafficLimitStrategy: v.optional(trafficStrategy),
  placement: v.optional(v.union(v.string(), v.null())),
  status: v.optional(v.union(v.literal('active'), v.literal('disabled'))),
});

/** The instance hosting an existing key (resolved from its subscription row). */
async function resolveInstanceByKey(ctx: ActionCtx, backendUserId: string) {
  return ctx.runQuery(internal.backendServers.resolveKeyServer, { backendUserId });
}

export const issueUser = internalAction({
  args: {
    backend: backendId,
    spec: issueSpec,
    // Pin issuance to ONE instance (Remnawave node placement resolves the
    // placement and its panel TOGETHER — a squad UUID only exists on its own
    // panel, so the paired pick must not be re-rolled here). Unusable pin
    // (gone/inactive/wrong type) → backend.unavailable, never a silent re-pick
    // that would break the (placement, panel) pairing.
    pinServerId: v.optional(v.id('backendServers')),
  },
  handler: async (
    ctx,
    { backend, spec, pinServerId },
  ): Promise<IssuedUser & { backendServerId?: Id<'backendServers'> }> => {
    if (mockBackendEnabled()) return mockIssueUser(spec as IssueUserSpec);
    let server: Doc<'backendServers'> | null;
    if (pinServerId) {
      const pinned = await ctx.runQuery(internal.backendServers.getById, { id: pinServerId });
      server = pinned && pinned.isActive && pinned.backend === backend ? pinned : null;
      if (!server) throw new ConvexError({ code: 'backend.unavailable', backend });
    } else {
      const candidates = await ctx.runQuery(internal.backendServers.pickCandidatesForIssue, {
        backend,
      });
      if (candidates.length === 0)
        // Typed so the HTTP layer maps it to an actionable 503 by CODE, not a brittle
        // message regex (issuanceErrorResponse). (Review P3.)
        throw new ConvexError({ code: 'backend.unavailable', backend });
      // Random pick among the top candidates (CSPRNG, can't live in the query).
      const idx = new Uint32Array(1);
      crypto.getRandomValues(idx);
      server = candidates[idx[0]! % candidates.length]!;
    }
    const issued = await PROVIDERS[server.backend].issue(
      server.config as BackendConfig,
      spec as IssueUserSpec,
    );
    await ctx.runMutation(internal.backendServers.bumpKeyCount, { id: server._id });
    return { ...issued, backendServerId: server._id };
  },
});

export const getUser = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (ctx, { backendUserId }): Promise<UserState> => {
    if (mockBackendEnabled()) return mockGetUser();
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) {
      // READ-path tolerance: an unresolved key (e.g. row mid-write) shouldn't
      // crash /account; return a sentinel "active/unknown" state.
      return {
        trafficLimitBytes: null,
        usedTrafficBytes: 0,
        expireAt: null,
        status: 'active',
        devices: [],
      };
    }
    return PROVIDERS[server.backend].get(server.config as BackendConfig, backendUserId);
  },
});

export const updateUser = internalAction({
  args: { backend: backendId, backendUserId: v.string(), patch: updatePatch },
  handler: async (ctx, { backendUserId, patch }) => {
    if (mockBackendEnabled()) return null;
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) throw new Error('Subscription key not resolvable to a backend instance');
    await PROVIDERS[server.backend].update(
      server.config as BackendConfig,
      backendUserId,
      patch as UpdateUserPatch,
    );
    return null;
  },
});

export const resetUserTraffic = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (ctx, { backendUserId }) => {
    if (mockBackendEnabled()) return null;
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) return null;
    await PROVIDERS[server.backend].resetTraffic(server.config as BackendConfig, backendUserId);
    return null;
  },
});

export const deleteUser = internalAction({
  args: {
    backend: backendId,
    backendUserId: v.string(),
    // Hint for the issuance-compensation path, where no subscription row exists
    // yet to resolve the instance from.
    backendServerId: v.optional(v.id('backendServers')),
  },
  handler: async (ctx, { backendUserId, backendServerId }) => {
    if (mockBackendEnabled()) return null;
    const server = backendServerId
      ? await ctx.runQuery(internal.backendServers.getById, { id: backendServerId })
      : await resolveInstanceByKey(ctx, backendUserId);
    if (!server) return null; // already gone / no instance recorded
    await PROVIDERS[server.backend].remove(server.config as BackendConfig, backendUserId);
    return null;
  },
});

export const revokeDevice = internalAction({
  args: { backend: backendId, backendUserId: v.string(), hwid: v.string() },
  handler: async (ctx, { backendUserId, hwid }): Promise<null> => {
    if (mockBackendEnabled()) return null;
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) throw new Error('Subscription key not resolvable to a backend instance');
    const provider = PROVIDERS[server.backend];
    if (!provider.removeDevice) {
      throw new Error(`${server.backend} does not support device management`);
    }
    await provider.removeDevice(server.config as BackendConfig, backendUserId, hwid);
    return null;
  },
});

// Enable/disable a user via the backend's dedicated status action (Remnawave's
// /actions/{enable|disable}), decoupled from the field-update `updateUser` path.
export const setUserStatus = internalAction({
  args: { backend: backendId, backendUserId: v.string(), active: v.boolean() },
  handler: async (ctx, { backendUserId, active }): Promise<null> => {
    if (mockBackendEnabled()) return null;
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) throw new Error('Subscription key not resolvable to a backend instance');
    const provider = PROVIDERS[server.backend];
    if (!provider.setStatus) {
      throw new Error(`${server.backend} does not support status changes`);
    }
    await provider.setStatus(server.config as BackendConfig, backendUserId, active);
    return null;
  },
});

// Bulk-set trafficLimitBytes on many users of ONE instance in a single call
// (Remnawave bulk/update). Resolves the instance by its id (the caller — the
// donation free-bandwidth apply — already grouped user ids by server). A backend
// with no bulk primitive (Outline) is a silent no-op; the caller can fall back to
// per-user updateUser. Caller chunks ids to the panel's ≤500 limit.
export const bulkUpdateTrafficLimit = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    backendUserIds: v.array(v.string()),
    trafficLimitBytes: v.number(),
  },
  handler: async (ctx, { backendServerId, backendUserIds, trafficLimitBytes }): Promise<null> => {
    if (mockBackendEnabled() || backendUserIds.length === 0) return null;
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) return null;
    const provider = PROVIDERS[server.backend];
    if (!provider.bulkUpdateTrafficLimit) return null; // no bulk primitive (Outline)
    await provider.bulkUpdateTrafficLimit(
      server.config as BackendConfig,
      backendUserIds,
      trafficLimitBytes,
    );
    return null;
  },
});

// Aggregate member usage series (read-only). Best-effort: degrades to null when
// unsupported (Outline / older panel) or unreachable, so the account page never
// breaks on it. Read live, never persisted.
export const getUserUsage = internalAction({
  args: { backend: backendId, backendUserId: v.string(), days: v.optional(v.number()) },
  handler: async (ctx, { backendUserId, days }): Promise<UsageSeries | null> => {
    if (mockBackendEnabled()) return null;
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) return null;
    const provider = PROVIDERS[server.backend];
    if (!provider.getUserUsage) return null;
    try {
      return await provider.getUserUsage(server.config as BackendConfig, backendUserId, days ?? 30);
    } catch {
      return null;
    }
  },
});

export const fetchSubscriptionContent = internalAction({
  args: {
    backend: backendId,
    // The instance is passed explicitly (optional so the dev mock path validates).
    backendServerId: v.optional(v.id('backendServers')),
    backendShortId: v.string(),
    userAgent: v.optional(v.string()),
    // The panel-provided public subscription URL — the actual location of the
    // raw content. Remnawave fetches THIS (the shortUuid is a public capability,
    // no admin token), not the admin API. Callers resolve it from the sub row.
    subscriptionUrl: v.optional(v.string()),
    // HWID identification headers forwarded from the member's proxy app (the
    // FCP-fronted /api/v1/sub/ route), so panel device registration + limits work.
    hwidHeaders: v.optional(v.record(v.string(), v.string())),
  },
  handler: async (
    ctx,
    { backendServerId, backendShortId, userAgent, subscriptionUrl, hwidHeaders },
  ): Promise<SubscriptionContent> => {
    if (mockBackendEnabled()) return mockFetchContent();
    if (!backendServerId) throw new Error('backendServerId required to fetch subscription content');
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new Error('Backend instance not found for subscription content fetch');
    try {
      return await PROVIDERS[server.backend].fetchContent(
        server.config as BackendConfig,
        backendShortId,
        userAgent,
        subscriptionUrl,
        hwidHeaders,
      );
    } catch (err) {
      // A panel 404 on a HWID-gated fetch (no/invalid x-hwid) is AUTHORITATIVE,
      // not an outage — surface it as a typed error so the fronted route passes
      // 404 through instead of serving a stale entry or a generic 502.
      if (isRemnawaveNotFound(err)) {
        throw new ConvexError({ code: 'subscription.device_rejected' });
      }
      throw err;
    }
  },
});
