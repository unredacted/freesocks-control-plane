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
 *  - `backendUserId` crosses this layer in two forms: the STORED form (what the
 *    subscription row, audit payloads and every caller hold — globally unique)
 *    and the PROVIDER form (the bare id the backend speaks). A per-instance numeric
 *    id (Remnawave 3.x, Outline) is scoped `<backendServerId>:<id>` on the way in
 *    (right after `issue`) and stripped on the way out (right before every
 *    provider call) — see convex/lib/backendUserId.ts. Nothing outside this file
 *    converts.
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
  BackendHost,
  PanelInbound,
} from './lib/backends/types';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { backendIdValidator } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import { pinSubscriptionToNode } from './lib/nodePinning';
import {
  mockBackendEnabled,
  mockFetchContent,
  mockGetUser,
  mockIssueUser,
} from './lib/backends/mock';
import { isRemnawaveNotFound } from './lib/backends/remnawave';
import { scopedServerId, toProviderUserId, toStoredBackendUserId } from './lib/backendUserId';

const backendId = backendIdValidator;
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
    // placement and its backend TOGETHER — a mode group UUID only exists on its own
    // backend, so the paired pick must not be re-rolled here). Unusable pin
    // (gone/inactive/wrong type) → backend.unavailable, never a silent re-pick
    // that would break the (placement, backend) pairing.
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
    // Anything that throws AFTER the provider create succeeds must not leak the
    // key: the issuance saga only compensates failures after `issueUser`
    // RETURNS (it needs the issued identity), so a post-create throw here is
    // compensated locally before rethrowing.
    let issued: IssuedUser | null = null;
    try {
      issued = await PROVIDERS[server.backend].issue(
        server.config as BackendConfig,
        spec as IssueUserSpec,
      );
      await ctx.runMutation(internal.backendServers.bumpKeyCount, { id: server._id });
    } catch (err) {
      if (issued) {
        try {
          await PROVIDERS[server.backend].remove(
            server.config as BackendConfig,
            issued.backendUserId,
          );
        } catch {
          console.warn(
            `[backends] post-create compensation delete failed for ${server.backend} user — orphan backend account`,
          );
          try {
            await ctx.runMutation(internal.audit.record, {
              actorType: 'system',
              action: 'subscription.compensation_failed',
              targetType: 'subscription',
              payload: { backend: server.backend, backendUserId: issued.backendUserId },
            });
          } catch {
            /* the original error takes precedence */
          }
        }
      }
      throw err;
    }
    // Persist the globally-unique form (a per-backend integer gets scoped to this
    // instance); the provider only ever saw/needs the bare id above.
    return {
      ...issued,
      backendUserId: toStoredBackendUserId(server._id, issued.backendUserId),
      backendServerId: server._id,
    };
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
    return PROVIDERS[server.backend].get(
      server.config as BackendConfig,
      toProviderUserId(backendUserId),
    );
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
      toProviderUserId(backendUserId),
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
    await PROVIDERS[server.backend].resetTraffic(
      server.config as BackendConfig,
      toProviderUserId(backendUserId),
    );
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
    if (backendServerId) {
      // An explicit hint that fails to resolve (the instance row was deleted
      // out from under a live key) must NOT silently succeed — the saga would
      // record a clean teardown and orphan the backend account. Throw so the
      // caller's retry/audit path engages.
      const hinted = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
      if (!hinted) {
        throw new Error(
          `Backend instance ${backendServerId} not found for key teardown (possible orphan)`,
        );
      }
      await PROVIDERS[hinted.backend].remove(
        hinted.config as BackendConfig,
        toProviderUserId(backendUserId),
      );
      return null;
    }
    const server = await resolveInstanceByKey(ctx, backendUserId);
    if (!server) return null; // already gone / no instance recorded
    await PROVIDERS[server.backend].remove(
      server.config as BackendConfig,
      toProviderUserId(backendUserId),
    );
    return null;
  },
});

/**
 * Locate which ACTIVE instance actually hosts a key by probing the fleet — the
 * repair path for a subscription whose stored `backendServerId` is stale (its
 * backend row was re-registered) or absent (legacy). Bounded by the fleet size;
 * a per-instance failure (404 = not this backend; anything else = unreachable)
 * just moves on. Returns the hosting instance's id, or null when no active
 * instance answers for the key.
 */
export const locateKeyInstance = internalAction({
  args: { backend: backendId, backendUserId: v.string() },
  handler: async (ctx, { backend, backendUserId }): Promise<string | null> => {
    if (mockBackendEnabled()) return null;
    // A scoped (per-instance integer) id is only meaningful on the instance it
    // names — the same integer on another backend is a DIFFERENT user, so a fleet
    // probe would "find" a stranger's key and repoint the sub at it. Probe only
    // the named instance; if that row is gone, the key cannot be relocated.
    const scope = scopedServerId(backendUserId);
    const servers = (await ctx.runQuery(internal.backendServers.listActiveWithSecret, {})).filter(
      (s) => s.backend === backend && (scope === null || (s._id as string) === scope),
    );
    for (const server of servers) {
      try {
        await PROVIDERS[server.backend].get(
          server.config as BackendConfig,
          toProviderUserId(backendUserId),
        );
        return server._id as string;
      } catch {
        continue; // not on this backend (404) or unreachable — try the next
      }
    }
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
    await provider.removeDevice(
      server.config as BackendConfig,
      toProviderUserId(backendUserId),
      hwid,
    );
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
    await provider.setStatus(
      server.config as BackendConfig,
      toProviderUserId(backendUserId),
      active,
    );
    return null;
  },
});

// Bulk-set trafficLimitBytes on many users of ONE instance in a single call
// (Remnawave bulk/update). Resolves the instance by its id (the caller — the
// donation free-bandwidth apply — already grouped user ids by server). A backend
// with no bulk primitive (Outline) is a silent no-op; the caller can fall back to
// per-user updateUser. Caller chunks ids to the backend's ≤500 limit.
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
      backendUserIds.map(toProviderUserId),
      trafficLimitBytes,
    );
    return null;
  },
});

// Aggregate member usage series (read-only). Best-effort: degrades to null when
// unsupported (Outline / older backend) or unreachable, so the account page never
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
      return await provider.getUserUsage(
        server.config as BackendConfig,
        toProviderUserId(backendUserId),
        days ?? 30,
      );
    } catch {
      return null;
    }
  },
});

/**
 * Origin-edge Host management (Remnawave Hosts): list the instance's client-facing
 * connection entries, and repoint ONE of them. Both are thin dispatches over the
 * optional provider capability; a backend without it throws a typed error.
 */
/**
 * A read-only backend listing that failed, as a coded error an admin route can
 * show. The Remnawave error class is written to be loggable (path, status and
 * a short slice of the backend's own error text; never the URL or the token), so
 * its message is passed on. Anything else is reduced to its class name:
 * validator and network errors can embed values.
 */
function panelReadFailure(
  what: string,
  err: unknown,
): ConvexError<{ code: string; message: string }> {
  if (err instanceof ConvexError) return err as ConvexError<{ code: string; message: string }>;
  const name = err instanceof Error ? err.name : typeof err;
  const words =
    err instanceof Error && name === 'RemnawaveApiError' ? err.message.slice(0, 400) : name;
  return new ConvexError({
    code: 'backend.panel_read_failed',
    message: `The panel did not answer ${what}: ${words}`,
  });
}

export const listHosts = internalAction({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }): Promise<BackendHost[]> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.listHosts) throw new ConvexError({ code: 'backend.hosts_unsupported' });
    try {
      return await provider.listHosts(server.config as BackendConfig);
    } catch (err) {
      throw panelReadFailure('the Host listing', err);
    }
  },
});

export const createAddress = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    remark: v.string(),
    address: v.string(),
    port: v.number(),
    sni: v.optional(v.union(v.string(), v.null())),
    host: v.optional(v.union(v.string(), v.null())),
    inbound: v.object({ configProfileUuid: v.string(), configProfileInboundUuid: v.string() }),
  },
  handler: async (ctx, { backendServerId, ...h }): Promise<{ uuid: string }> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.createAddress) throw new ConvexError({ code: 'backend.hosts_unsupported' });
    return provider.createAddress(server.config as BackendConfig, h);
  },
});

export const deleteAddress = internalAction({
  args: { backendServerId: v.id('backendServers'), uuid: v.string() },
  handler: async (ctx, { backendServerId, uuid }): Promise<null> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.deleteAddress) throw new ConvexError({ code: 'backend.hosts_unsupported' });
    await provider.deleteAddress(server.config as BackendConfig, uuid);
    return null;
  },
});

export const updateAddress = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    uuid: v.string(),
    address: v.string(),
    port: v.number(),
    /** Three-valued: absent = leave the field, a string = set it, null = clear it. */
    sni: v.optional(v.union(v.string(), v.null())),
    host: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, { backendServerId, uuid, address, port, sni, host }): Promise<null> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.updateAddress) throw new ConvexError({ code: 'backend.hosts_unsupported' });
    await provider.updateAddress(server.config as BackendConfig, {
      uuid,
      address,
      port,
      // `undefined` must stay undefined (leave it): a Convex arg that was not
      // sent is absent here, and only an explicit null means "clear".
      ...(sni !== undefined ? { sni } : {}),
      ...(host !== undefined ? { host } : {}),
    });
    return null;
  },
});

/**
 * Flip ONE Host's disabled bit (the origin hide/restore ledger: FCP hides a
 * node's direct Hosts while its edges serve members, and restores them on
 * cancel/release/delete). The bit alone travels; the caller confirms by
 * re-listing. No dev mock branch: the Host ops above have none either (the
 * fake edge provider stops at the provider layer).
 */
export const setHostDisabled = internalAction({
  args: { backendServerId: v.id('backendServers'), uuid: v.string(), disabled: v.boolean() },
  handler: async (ctx, { backendServerId, uuid, disabled }): Promise<null> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.setHostDisabled) throw new ConvexError({ code: 'backend.hosts_unsupported' });
    await provider.setHostDisabled(server.config as BackendConfig, uuid, disabled);
    return null;
  },
});

/**
 * The transports one backend node serves (origin listener discovery), as the
 * provider's allowlisted projection: never credentials, private keys, short
 * ids or certificate material. A backend without the capability throws
 * `backend.inbounds_unsupported`.
 */
export const listNodeInbounds = internalAction({
  args: { backendServerId: v.id('backendServers'), nodeUuid: v.string() },
  handler: async (ctx, { backendServerId, nodeUuid }): Promise<PanelInbound[]> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.listNodeInbounds) throw new ConvexError({ code: 'backend.inbounds_unsupported' });
    try {
      return await provider.listNodeInbounds(server.config as BackendConfig, nodeUuid);
    } catch (err) {
      throw panelReadFailure("the node's transport listing", err);
    }
  },
});

/**
 * Re-find a user FCP created on ONE instance by its username (the persisted
 * mint operations discover an issued user after a crash between the create
 * and the store). Returns the issued shape with the STORED id form, or null
 * when the backend has no such user. A backend without a name lookup throws
 * `backend.lookup_unsupported`.
 */
export const findUserByUsername = internalAction({
  args: { backendServerId: v.id('backendServers'), username: v.string() },
  handler: async (
    ctx,
    { backendServerId, username },
  ): Promise<(IssuedUser & { backendServerId: Id<'backendServers'> }) | null> => {
    if (mockBackendEnabled()) return null;
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const provider = PROVIDERS[server.backend];
    if (!provider.findUserByUsername) throw new ConvexError({ code: 'backend.lookup_unsupported' });
    const found = await provider.findUserByUsername(server.config as BackendConfig, username);
    if (!found) return null;
    return {
      ...found,
      backendUserId: toStoredBackendUserId(server._id, found.backendUserId),
      backendServerId: server._id,
    };
  },
});

export const fetchSubscriptionContent = internalAction({
  args: {
    backend: backendId,
    // The instance is passed explicitly (optional so the dev mock path validates).
    backendServerId: v.optional(v.id('backendServers')),
    backendShortId: v.string(),
    userAgent: v.optional(v.string()),
    // The backend-provided public subscription URL — the actual location of the
    // raw content. Remnawave fetches THIS (the shortUuid is a public capability,
    // no admin token), not the admin API. Callers resolve it from the sub row.
    subscriptionUrl: v.optional(v.string()),
    // HWID identification headers forwarded from the member's proxy app (the
    // FCP-fronted /api/v1/sub/ route), so backend device registration + limits work.
    hwidHeaders: v.optional(v.record(v.string(), v.string())),
    // The node this key was PREVIOUSLY pinned to (set at issuance from the old
    // subscription's pinnedNode) — excluded from the pin pick when others
    // exist, so a regenerated key lands on a different node.
    excludeNode: v.optional(v.string()),
    // Skip the node pin and return the backend body whole: the origin test link
    // resolves ONE node's entry itself (by Host identity), so a pin that
    // rendezvous-picked another node of the placement would hide it.
    unpinned: v.optional(v.boolean()),
  },
  handler: async (
    ctx,
    {
      backendServerId,
      backendShortId,
      userAgent,
      subscriptionUrl,
      hwidHeaders,
      excludeNode,
      unpinned,
    },
  ): Promise<SubscriptionContent> => {
    if (mockBackendEnabled()) return mockFetchContent();
    if (!backendServerId) throw new Error('backendServerId required to fetch subscription content');
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new Error('Backend instance not found for subscription content fetch');
    try {
      const fetched = await PROVIDERS[server.backend].fetchContent(
        server.config as BackendConfig,
        backendShortId,
        userAgent,
        subscriptionUrl,
        hwidHeaders,
      );
      // Pin each key to ONE node's endpoints: the backend serves every Host of
      // the shared mode group, which would expose the whole fleet in every
      // subscription. Filter down to the pinned node's lines (deterministic
      // rendezvous pick on the backend user id — stable per key, moves only when
      // the pinned node disappears, e.g. rotation/teardown).
      if (
        !unpinned &&
        capabilitiesOf(server.backend).nodePinning &&
        typeof fetched.content === 'string'
      ) {
        // Nodes whose delivery gate is closed (enrolled but not live, under
        // maintenance, retiring; docs/servers.md "Node lifecycle") are never
        // picked while another node exists; a body that can only resolve to one
        // is refused by the delivery policy afterwards.
        const gated = await ctx.runQuery(internal.panelIntents.blockedNodeNames, {
          backendServerId,
        });
        const pinned = pinSubscriptionToNode(fetched.content, backendShortId, [
          ...(excludeNode ? [excludeNode] : []),
          ...gated,
        ]);
        return { ...fetched, content: pinned.content, pinnedNode: pinned.node ?? undefined };
      }
      return fetched;
    } catch (err) {
      // A backend 404 on a HWID-gated fetch (no/invalid x-hwid) is AUTHORITATIVE,
      // not an outage — surface it as a typed error so the fronted route passes
      // 404 through instead of serving a stale entry or a generic 502.
      if (capabilitiesOf(server.backend).fetch404IsDeviceRejection && isRemnawaveNotFound(err)) {
        throw new ConvexError({ code: 'subscription.device_rejected' });
      }
      throw err;
    }
  },
});
