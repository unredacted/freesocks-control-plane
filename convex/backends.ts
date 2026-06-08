/**
 * Proxy-backend operations as Convex actions (external HTTP → V8 runtime).
 * Dispatch by `backend`; `internalAction`s invoked by the issuance saga (P5),
 * grace/disable sweep, and tier propagation.
 *
 * Remnawave is pure HTTP (config from process.env). Outline needs the DB to
 * pick/resolve a server (its `apiUrl` is secret), so its branches call the
 * internal queries/mutation in convex/outlineServers.ts and then do the HTTP
 * in convex/lib/backends/outline.ts: the read → act → write decomposition.
 *
 * Config (Convex env vars): REMNAWAVE_BASE_URL, REMNAWAVE_API_TOKEN.
 */
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import type {
  IssueUserSpec,
  IssuedUser,
  SubscriptionContent,
  UpdateUserPatch,
  UserState,
} from './lib/backends/types';
import {
  remnawaveDeleteUser,
  remnawaveFetchSubscription,
  remnawaveGetUser,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveUpdateUser,
  type RemnawaveConfig,
} from './lib/backends/remnawave';
import {
  outlineDelete,
  outlineFetchContent,
  outlineGetState,
  outlineIssue,
  outlineUpdate,
  type OutlineServerConfig,
} from './lib/backends/outline';

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
  outlineServerId: v.optional(v.id('outlineServers')),
  outlineServerPoolIds: v.optional(v.array(v.id('outlineServers'))),
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

function remnawaveConfig(): RemnawaveConfig {
  const baseUrl = process.env.REMNAWAVE_BASE_URL;
  const apiToken = process.env.REMNAWAVE_API_TOKEN;
  if (!baseUrl || !apiToken) {
    throw new Error(
      'REMNAWAVE_BASE_URL and REMNAWAVE_API_TOKEN must be set (bunx convex env set ...)',
    );
  }
  return { baseUrl, apiToken };
}

function outlineCfg(server: {
  apiUrl: string;
  websocketEnabled: boolean;
  websocketDomain?: string | null;
}): OutlineServerConfig {
  return {
    apiUrl: server.apiUrl,
    websocketEnabled: server.websocketEnabled,
    websocketDomain: server.websocketDomain ?? null,
  };
}

/** Resolve the server hosting an existing Outline key (read/update/delete/fetch). */
async function resolveOutlineServer(ctx: ActionCtx, backendUserId: string) {
  return ctx.runQuery(internal.outlineServers.resolveKeyServer, { backendUserId });
}

export const issueUser = internalAction({
  args: { backend: backendId, spec: issueSpec },
  handler: async (ctx, { backend, spec }): Promise<IssuedUser> => {
    if (backend === 'remnawave')
      return remnawaveIssueUser(remnawaveConfig(), spec as IssueUserSpec);

    // Outline: resolve a server (admin hint, else pick from the scored pool).
    let server;
    if (spec.outlineServerId) {
      server = await ctx.runQuery(internal.outlineServers.getById, { id: spec.outlineServerId });
      if (!server) throw new Error('Outline server not found for the requested id');
    } else {
      const candidates = await ctx.runQuery(internal.outlineServers.pickCandidatesForIssue, {
        poolIds: spec.outlineServerPoolIds,
      });
      if (candidates.length === 0)
        throw new Error('No active Outline servers available to issue a key');
      // Random pick among the top candidates (CSPRNG, can't live in the query).
      const idx = new Uint32Array(1);
      crypto.getRandomValues(idx);
      server = candidates[idx[0]! % candidates.length]!;
    }
    const issued = await outlineIssue(outlineCfg(server), {
      username: spec.username,
      trafficLimitBytes: spec.trafficLimitBytes,
    });
    await ctx.runMutation(internal.outlineServers.bumpAccessKeyCount, { id: server._id });
    return { ...issued, outlineServerId: server._id };
  },
});

export const getUser = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (ctx, { backend, backendUserId }): Promise<UserState> => {
    if (backend === 'remnawave') return remnawaveGetUser(remnawaveConfig(), backendUserId);
    const server = await resolveOutlineServer(ctx, backendUserId);
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
    return outlineGetState(outlineCfg(server), backendUserId);
  },
});

export const updateUser = internalAction({
  args: { backend: backendId, backendUserId: v.string(), patch: updatePatch },
  handler: async (ctx, { backend, backendUserId, patch }) => {
    if (backend === 'remnawave') {
      await remnawaveUpdateUser(remnawaveConfig(), backendUserId, patch as UpdateUserPatch);
      return null;
    }
    const server = await resolveOutlineServer(ctx, backendUserId);
    if (!server) throw new Error('Outline key not resolvable to a server');
    await outlineUpdate(outlineCfg(server), backendUserId, patch as UpdateUserPatch);
    return null;
  },
});

export const resetUserTraffic = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (_ctx, { backend, backendUserId }) => {
    if (backend === 'remnawave') {
      await remnawaveResetTraffic(remnawaveConfig(), backendUserId);
      return null;
    }
    // Outline exposes no per-key traffic reset; metrics roll on the server window. No-op.
    void backendUserId;
    return null;
  },
});

export const deleteUser = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (ctx, { backend, backendUserId }) => {
    if (backend === 'remnawave') {
      await remnawaveDeleteUser(remnawaveConfig(), backendUserId);
      return null;
    }
    const server = await resolveOutlineServer(ctx, backendUserId);
    if (!server) return null; // already gone / no server recorded
    await outlineDelete(outlineCfg(server), backendUserId);
    return null;
  },
});

export const fetchSubscriptionContent = internalAction({
  args: { backend: backendId, backendShortId: v.string(), userAgent: v.optional(v.string()) },
  handler: async (ctx, { backend, backendShortId, userAgent }): Promise<SubscriptionContent> => {
    if (backend === 'remnawave') {
      return remnawaveFetchSubscription(remnawaveConfig(), backendShortId, userAgent);
    }
    const server = await resolveOutlineServer(ctx, backendShortId);
    if (!server) throw new Error('Outline key not resolvable to a server');
    return outlineFetchContent(outlineCfg(server), backendShortId);
  },
});
