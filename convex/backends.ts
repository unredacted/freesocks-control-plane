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
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import type {
  IssueUserSpec,
  IssuedUser,
  SubscriptionContent,
  UpdateUserPatch,
  UserState,
} from './lib/backends/types';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import {
  mockBackendEnabled,
  mockFetchContent,
  mockGetUser,
  mockIssueUser,
} from './lib/backends/mock';

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
  remnawaveSquadUuid: v.optional(v.union(v.string(), v.null())),
});

const updatePatch = v.object({
  trafficLimitBytes: v.optional(v.union(v.number(), v.null())),
  expireAt: v.optional(v.union(v.string(), v.null())),
  tag: v.optional(v.string()),
  description: v.optional(v.string()),
  hwidDeviceLimit: v.optional(v.union(v.number(), v.null())),
  trafficLimitStrategy: v.optional(trafficStrategy),
  remnawaveSquadUuid: v.optional(v.union(v.string(), v.null())),
  status: v.optional(v.union(v.literal('active'), v.literal('disabled'))),
});

/** The instance hosting an existing key (resolved from its subscription row). */
async function resolveInstanceByKey(ctx: ActionCtx, backendUserId: string) {
  return ctx.runQuery(internal.backendServers.resolveKeyServer, { backendUserId });
}

export const issueUser = internalAction({
  args: { backend: backendId, spec: issueSpec },
  handler: async (
    ctx,
    { backend, spec },
  ): Promise<IssuedUser & { backendServerId?: Id<'backendServers'> }> => {
    if (mockBackendEnabled()) return mockIssueUser(spec as IssueUserSpec);
    const candidates = await ctx.runQuery(internal.backendServers.pickCandidatesForIssue, {
      backend,
    });
    if (candidates.length === 0)
      throw new Error(`No active ${backend} instances available to issue a key`);
    // Random pick among the top candidates (CSPRNG, can't live in the query).
    const idx = new Uint32Array(1);
    crypto.getRandomValues(idx);
    const server = candidates[idx[0]! % candidates.length]!;
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

export const fetchSubscriptionContent = internalAction({
  args: {
    backend: backendId,
    // The instance is passed explicitly: this is called during issuance (S3
    // mirror), before the subscription row exists to resolve from. Optional so
    // the dev mock path (which needs no instance) still validates.
    backendServerId: v.optional(v.id('backendServers')),
    backendShortId: v.string(),
    userAgent: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { backendServerId, backendShortId, userAgent },
  ): Promise<SubscriptionContent> => {
    if (mockBackendEnabled()) return mockFetchContent();
    if (!backendServerId) throw new Error('backendServerId required to fetch subscription content');
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new Error('Backend instance not found for subscription content fetch');
    return PROVIDERS[server.backend].fetchContent(
      server.config as BackendConfig,
      backendShortId,
      userAgent,
    );
  },
});
