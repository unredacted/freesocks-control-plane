/**
 * Proxy-backend operations as Convex actions (external HTTP → V8 runtime).
 * These dispatch by `backend` and are `internalAction`s — the issuance saga
 * (P5), grace/disable sweep, and tier propagation invoke them via
 * `ctx.runAction(internal.backends.*)` (or import the lib functions directly).
 *
 * Config comes from Convex environment variables (set with `npx convex env set`):
 *   REMNAWAVE_BASE_URL, REMNAWAVE_API_TOKEN
 *
 * Outline is wired in P4b (it needs a server-pool query for the apiUrl); its
 * branches throw until then.
 */
import { internalAction } from './_generated/server';
import { v } from 'convex/values';
import type { IssueUserSpec, UpdateUserPatch } from './lib/backends/types';
import {
  remnawaveDeleteUser,
  remnawaveFetchSubscription,
  remnawaveGetUser,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveUpdateUser,
  type RemnawaveConfig,
} from './lib/backends/remnawave';

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
      'REMNAWAVE_BASE_URL and REMNAWAVE_API_TOKEN must be set (npx convex env set ...)',
    );
  }
  return { baseUrl, apiToken };
}

function outlineNotYet(): never {
  throw new Error('Outline backend not yet ported to Convex (migration phase P4b)');
}

export const issueUser = internalAction({
  args: { backend: backendId, spec: issueSpec },
  handler: (_ctx, { backend, spec }) =>
    backend === 'remnawave'
      ? remnawaveIssueUser(remnawaveConfig(), spec as IssueUserSpec)
      : outlineNotYet(),
});

export const getUser = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: (_ctx, { backend, backendUserId }) =>
    backend === 'remnawave'
      ? remnawaveGetUser(remnawaveConfig(), backendUserId)
      : outlineNotYet(),
});

export const updateUser = internalAction({
  args: { backend: backendId, backendUserId: v.string(), patch: updatePatch },
  handler: async (_ctx, { backend, backendUserId, patch }) => {
    if (backend !== 'remnawave') outlineNotYet();
    await remnawaveUpdateUser(remnawaveConfig(), backendUserId, patch as UpdateUserPatch);
    return null;
  },
});

export const resetUserTraffic = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (_ctx, { backend, backendUserId }) => {
    if (backend !== 'remnawave') outlineNotYet();
    await remnawaveResetTraffic(remnawaveConfig(), backendUserId);
    return null;
  },
});

export const deleteUser = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (_ctx, { backend, backendUserId }) => {
    if (backend !== 'remnawave') outlineNotYet();
    await remnawaveDeleteUser(remnawaveConfig(), backendUserId);
    return null;
  },
});

export const fetchSubscriptionContent = internalAction({
  args: { backend: backendId, backendShortId: v.string(), userAgent: v.optional(v.string()) },
  handler: (_ctx, { backend, backendShortId, userAgent }) =>
    backend === 'remnawave'
      ? remnawaveFetchSubscription(remnawaveConfig(), backendShortId, userAgent)
      : outlineNotYet(),
});
