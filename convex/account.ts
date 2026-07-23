/**
 * Member account operations (P7): the multi-step flows behind GET /account,
 * regenerate, switch-backend, and refresh-membership. Ported from
 * routes/api/account.ts. The HTTP layer authenticates the member session and
 * passes the userId; these internalActions own the saga (backend issue + S3 via
 * lib/issuance, tombstone-with-grace, tier switch, audit). The live subscription
 * state is fetched best-effort so a backend outage degrades /account instead of
 * 500-ing it.
 *
 * The switch-backend peer resolution is the documented interim: free-tier users
 * switch via the default-free peer tier; paid users get 409 until the billing
 * portal defines cross-backend tier linkage (CiviCRM linkage is gone).
 */
import { internalAction, internalMutation, type ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { randomHex } from './lib/crypto';
import { issueNewSubscription } from './lib/issuance';
import {
  applyUsageCarryover,
  computeExpireAtIso,
  resolveHwidLimit,
  resolveTrafficLimitBytes,
  type UsageSeries,
} from './lib/backends/types';

type Backend = 'remnawave' | 'outline';

/**
 * WS1 bring-up safety net: when a Remnawave key is issued with a null placement
 * (only possible when NO mode has a pool bound anywhere on the deploy), the key
 * has no inbounds. We still issue it (keys must mint during bring-up) but never
 * SILENTLY — audit it so an admin sees they must bind a placement pool. A no-op
 * for Outline or when a placement resolved. `switchMode` can't reach this (it
 * rejects unbound targets first).
 */
async function auditIfPlacementless(
  ctx: ActionCtx,
  args: {
    backend: Backend;
    placement: string | null;
    userId: Id<'users'>;
    subscriptionId: Id<'subscriptions'>;
    requestedMode: string | null;
    requestId?: string;
  },
): Promise<void> {
  if (args.backend !== 'remnawave' || args.placement !== null) return;
  console.warn('[placement] issued a squad-less key: no Remnawave pool bound on this deploy');
  await ctx.runMutation(internal.audit.record, {
    actorType: 'member',
    actorId: args.userId,
    action: 'subscription.issued_without_placement',
    targetType: 'subscription',
    targetId: args.subscriptionId,
    payload: { requestedMode: args.requestedMode },
    requestId: args.requestId,
  });
}

const TOMBSTONE_GRACE_MS = 24 * 60 * 60 * 1000;

/**
 * Quota carryover (Review D-M3): a re-issue mints a FRESH backend traffic
 * counter while the superseded key keeps routing for the 24h tombstone grace,
 * so every regenerate/switch used to multiply the member's effective quota
 * (scripted churn compounded it by orders of magnitude). Read the old key's
 * live usedTrafficBytes and shrink the new key's limit by it, so the member's
 * period quota is preserved across the re-issue instead of reset.
 *
 * Best-effort: a panel blip (or an already-gone old key) must not block
 * re-issue — there is usually nothing to carry then. A fully-spent quota
 * carries as 1 byte, NOT 0: 0 means UNLIMITED to Remnawave (and 'blocked' to
 * Outline), so 1 byte is the only value that reads as "spent" on both.
 */
async function carriedTrafficLimit(
  ctx: ActionCtx,
  oldSub: { backend: Backend; backendUserId: string } | null,
  limitBytes: number | null,
): Promise<number | null> {
  if (limitBytes === null || !oldSub) return limitBytes;
  try {
    const state = await ctx.runAction(internal.backends.getUser, {
      backend: oldSub.backend,
      backendUserId: oldSub.backendUserId,
    });
    return applyUsageCarryover(limitBytes, state.usedTrafficBytes ?? 0);
  } catch {
    console.warn('[account] usage-carryover read failed; issuing at the full tier limit');
    return limitBytes;
  }
}

/**
 * Tombstone the superseded key (24h grace), with a bounded-retry backstop: a
 * transient failure here must not leave TWO live keys (the just-minted one +
 * this one), and no sweep re-tombstones an active row. On failure the retry
 * action is scheduled (it audits at exhaustion) and the saga continues.
 */
async function tombstoneOldSub(
  ctx: ActionCtx,
  backendUserId: string,
): Promise<{ deletedAt: number } | null> {
  try {
    return await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
      backendUserId,
      graceMs: TOMBSTONE_GRACE_MS,
    });
  } catch (err) {
    console.warn(
      `[subscription] tombstone failed; scheduling retry: ${err instanceof Error ? err.message : String(err)}`,
    );
    await ctx.scheduler.runAfter(0, internal.subscriptions.tombstoneWithGraceAction, {
      backendUserId,
      graceMs: TOMBSTONE_GRACE_MS,
      attempt: 0,
    });
    return null;
  }
}

/**
 * Where a NEW key issues: for Remnawave, the (placement, panel) pair resolved
 * TOGETHER (a squad UUID only exists on its own panel) for the member's mode +
 * preferred location; null-everything for other backends. `serverId` pins
 * issueUser to the squad's panel — without it the instance pick could land on a
 * different panel than the squad (a dead key on any multi-panel deploy).
 */
async function resolveIssueTarget(
  ctx: ActionCtx,
  backend: Backend,
  modeId: string | null,
  location: string | null,
): Promise<{ placement: string | null; serverId: Id<'backendServers'> | null }> {
  if (backend !== 'remnawave') return { placement: null, serverId: null };
  // Mint the anti-herding randomness HERE (actions may use the CSPRNG; queries
  // must stay deterministic) and thread it through the resolution.
  const randBuf = new Uint32Array(1);
  crypto.getRandomValues(randBuf);
  const t = await ctx.runQuery(internal.remnawaveNodes.resolveTarget, {
    modeId,
    location,
    rand: randBuf[0]! / 2 ** 32,
  });
  // Multi-panel + zero attributable squads: an unpinned issue would mint a
  // (squad, wrong-panel) dead key — fail loudly (503, retryable once the stats
  // cron attributes the pool) instead. Single-panel deploys never see this.
  if (t.unattributedMultiPanel) {
    throw new ConvexError({
      code: 'backend.placement_unresolved',
      message:
        'Node placement is still resolving on this deployment. Please try again in a few minutes.',
    });
  }
  return { placement: t.placement, serverId: (t.serverId as Id<'backendServers'> | null) ?? null };
}

// P1-3: a serializable per-user issuance lock. regenerate / switch-backend /
// switch-profile each mint a NEW backend key and tombstone the old one; two
// concurrent runs would mint two keys but tombstone only one, orphaning a live key
// forever. The lock makes only one issuance saga run per user at a time.
//
// Review #7: the TTL must exceed a worst-case saga — a switch chains several
// backend HTTP calls (8s timeout each, see remnawave.ts) plus S3 mirror work, so
// the old 30s could expire mid-saga and let a SECOND saga acquire (the exact
// double-issue this lock prevents). And release is owner-checked via a nonce, so
// even after such a takeover a stale saga's `finally` can't delete the NEW holder's
// lock (a blind delete previously could).
const ISSUE_LOCK_TTL_MS = 120_000;

/** Parse a lock row's value (the JSON `{exp, token}` form; anything else reads
 *  as expired-with-no-owner, so a corrupt row can always be taken over). */
function parseLock(value: string): { exp: number; token: string | null } {
  try {
    const o = JSON.parse(value) as { exp?: number; token?: string };
    if (o && typeof o.exp === 'number') {
      return { exp: o.exp, token: typeof o.token === 'string' ? o.token : null };
    }
  } catch {
    /* fall through */
  }
  return { exp: 0, token: null };
}

export const acquireIssuanceLock = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ acquired: boolean; token?: string }> => {
    const key = `issue-lock:${userId}`;
    const now = Date.now();
    const token = randomHex(16);
    const value = JSON.stringify({ exp: now + ISSUE_LOCK_TTL_MS, token });
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) {
      if (parseLock(row.value).exp > now) return { acquired: false }; // held + unexpired
      await ctx.db.patch(row._id, { value, updatedAt: now }); // take over an expired lock
      return { acquired: true, token };
    }
    await ctx.db.insert('appState', { key, value, updatedAt: now });
    return { acquired: true, token };
  },
});

export const releaseIssuanceLock = internalMutation({
  // The token is REQUIRED (Review D-#9): a tokenless call deleted ANY holder's
  // lock, silently defeating the owner-check (Review #7) for every future call
  // site that forgot to pass it.
  args: { userId: v.id('users'), token: v.string() },
  handler: async (ctx, { userId, token }): Promise<null> => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', `issue-lock:${userId}`))
      .unique();
    if (!row) return null;
    // Owner-checked: delete only when the caller's nonce matches the held one, so a
    // saga whose lock already expired + was re-acquired by another can't delete the
    // NEW holder's lock. (Review #7.)
    const held = parseLock(row.value).token;
    if (held && held !== token) return null;
    await ctx.db.delete(row._id);
    return null;
  },
});

/**
 * Gate a (re-)issue on the member's EFFECTIVE connection mode (see
 * remnawaveNodes.effectivePlacementGate): WS1's cross-mode placement fallback,
 * applied blindly, would silently re-home the key into a DIFFERENT mode's pool
 * — e.g. a 'privacy' member re-issued into the CDN-fronted 'evade' pool while
 * the UI still says privacy, degrading the exact property they selected. When
 * the effective mode's pool is unbound but another mode's is bound, the member
 * must pick a new mode first (the /connection-mode + switchMode guards are the
 * same shape). An all-unbound (bring-up) deploy is NOT blocked: issuance
 * proceeds squad-less + audited.
 */
const MODE_UNAVAILABLE_MESSAGE =
  'Your current connection mode is no longer available. Switch to another connection mode first.';

async function isEffectiveModeBlocked(
  ctx: ActionCtx,
  backend: Backend,
  modeId: string | null,
): Promise<boolean> {
  if (backend !== 'remnawave') return false;
  const gate = await ctx.runQuery(internal.remnawaveNodes.effectivePlacementGate, { modeId });
  return gate.blocked;
}

interface AccountView {
  user: {
    id: Id<'users'>;
    status: 'active' | 'grace' | 'disabled' | 'deleted' | 'inactive';
    supportId: string | null;
    tier: {
      slug: string;
      name: string;
      monthlyTrafficGb: number;
      deviceLimit: number;
      backend: Backend;
      // True when this member's tier enforces a device limit AND enforcement is
      // globally enabled — the SPA gates app compatibility only when true.
      deviceLimited: boolean;
    };
    membership: { expiresAt: string | null; isCurrent: boolean } | null;
    connectionModeId: string;
    /** ISO of the member's first settled donation (null = not a donor). */
    donorSince: string | null;
    /** Lifetime settled donation total (cents) — the member's own impact figure. */
    donatedCentsTotal: number;
    /** Number of settled orders that carried a donation. */
    donationCount: number;
    /** GB equivalent of the member's giving at the current rate, computed
     *  server-side so the raw GB-per-dollar rate never ships to the client. */
    donatedGbTotal: number;
    createdAt: string;
  };
  subscription: {
    url: string;
    // Opaque FCP-fronted-URL token; the SPA builds `<origin>/api/v1/sub/<subToken>`.
    subToken: string | null;
    shortUuid: string;
    mirrors: { provider: string; publicUrl: string }[];
    expiresAt: string | null;
    trafficLimitBytes: number | null;
    trafficUsedBytes: number;
    // Live key state from the backend (undefined/'unknown' when it's unreachable).
    // `status` explains a stopped VPN (limited = over quota, disabled = lapsed);
    // resetStrategy + lastResetAt drive the "resets in N days" hint.
    status?: 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';
    resetStrategy?: 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH';
    lastResetAt?: string;
    backend: Backend;
    // Node location this key is served from (the hosting instance's location
    // code + display label; null when the instance has none set).
    location: { code: string; label: string } | null;
    devices: {
      hwid: string;
      platform?: string;
      deviceModel?: string;
      firstSeenAt?: string;
      lastSeenAt?: string;
    }[];
  } | null;
  /** The member's stored location preference (a location code; null = automatic). */
  preferredLocation: string | null;
}

export const getAccountView = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<AccountView | null> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return null;
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return null;
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const deviceLimited = !!settings['devices.enforcementEnabled'] && tier.hwidEnabled;

    // W3: lazily backfill the support ID for pre-W3 accounts. Non-fatal — the
    // account view still renders if minting transiently fails.
    let supportId = user.supportId ?? null;
    if (!supportId) {
      try {
        supportId = (await ctx.runAction(internal.supportId.ensureForUser, { userId })).supportId;
      } catch {
        /* leave null; next view retries */
      }
    }

    // Member's chosen connection mode (or the catalog default) — surfaced so the
    // client renders the selected transport server-authoritatively.
    const connectionModeId =
      user.connectionModeId ?? (await ctx.runQuery(internal.connectionModes.defaultId, {}));
    // Fold the current shared donation bonus into the free-tier fallback so an
    // outage (backend unreachable) still shows the raised cap, not the base.
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const trafficLimitFromTier = resolveTrafficLimitBytes(tier, bonusGb);
    // The member's own settled donation totals (impact panel). The GB figure is
    // computed server-side at the current rate so the raw rate never ships.
    const donationTotals: {
      donatedCentsTotal: number;
      donationCount: number;
      donatedGbTotal: number;
    } = await ctx.runQuery(internal.donations.donationTotals, { userId });
    let subscription: AccountView['subscription'] = null;
    if (sub) {
      // Best-effort live state; degrade to local data if the backend is down.
      let live = {
        expireAt: null as string | null,
        trafficLimitBytes: trafficLimitFromTier,
        usedTrafficBytes: 0,
        // Degrade default: backend unreachable ⇒ we don't know the key's status,
        // so 'unknown' (the member badge only fires for limited/disabled).
        status: 'unknown' as 'active' | 'disabled' | 'limited' | 'expired' | 'unknown',
        resetStrategy: undefined as 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH' | undefined,
        lastResetAt: undefined as string | undefined,
        devices: [] as {
          hwid: string;
          platform?: string | null;
          deviceModel?: string | null;
          firstSeenAt?: string | null;
          lastSeenAt?: string | null;
        }[],
      };
      try {
        const state = await ctx.runAction(internal.backends.getUser, {
          backend: sub.backend,
          backendUserId: sub.backendUserId,
        });
        live = {
          expireAt: state.expireAt,
          trafficLimitBytes: state.trafficLimitBytes,
          usedTrafficBytes: state.usedTrafficBytes,
          status: state.status,
          resetStrategy: state.trafficLimitStrategy,
          lastResetAt: state.lastTrafficResetAt,
          devices: state.devices,
        };
      } catch {
        /* backend unreachable: serve local data with zeroed live fields */
      }
      // The hosting instance's member-facing location (code + label; no secrets).
      const server = sub.backendServerId
        ? await ctx.runQuery(internal.backendServers.getById, { id: sub.backendServerId })
        : null;
      subscription = {
        // The raw backend URL (fallback) + the opaque token; the SPA builds the
        // FCP-fronted URL from the token + its own origin, so there's no
        // deployment-origin env dependency and every UI surface fronts uniformly.
        url: sub.subscriptionUrl,
        subToken: sub.subToken ?? null,
        shortUuid: sub.backendShortId,
        // Don't advertise a mirror whose last refresh failed (Review #2): it's kept
        // in the DB so the cap holds + the next refresh retries it, but the member
        // shouldn't be handed a URL we couldn't refresh.
        mirrors: sub.subscriptionMirrors
          .filter((m) => m.status !== 'failed')
          .map((m) => ({ provider: m.provider, publicUrl: m.publicUrl })),
        expiresAt: live.expireAt,
        trafficLimitBytes: live.trafficLimitBytes,
        trafficUsedBytes: live.usedTrafficBytes,
        status: live.status,
        resetStrategy: live.resetStrategy,
        lastResetAt: live.lastResetAt,
        backend: sub.backend,
        location: server?.location
          ? { code: server.location, label: server.locationLabel ?? server.location }
          : null,
        devices: live.devices.map((d) => ({
          hwid: d.hwid,
          platform: d.platform ?? undefined,
          deviceModel: d.deviceModel ?? undefined,
          firstSeenAt: d.firstSeenAt ?? undefined,
          lastSeenAt: d.lastSeenAt ?? undefined,
        })),
      };
    }

    return {
      user: {
        id: user._id,
        status: user.status,
        supportId,
        tier: {
          slug: tier.slug,
          name: tier.name,
          monthlyTrafficGb: tier.monthlyTrafficGb,
          deviceLimit: tier.deviceLimit,
          backend: tier.backend,
          deviceLimited,
        },
        membership: user.membershipExpiresAt
          ? {
              expiresAt: new Date(user.membershipExpiresAt).toISOString(),
              isCurrent: user.status === 'active',
            }
          : null,
        connectionModeId,
        donorSince: user.firstDonatedAt ? new Date(user.firstDonatedAt).toISOString() : null,
        donatedCentsTotal: donationTotals.donatedCentsTotal,
        donationCount: donationTotals.donationCount,
        donatedGbTotal: donationTotals.donatedGbTotal,
        createdAt: new Date(user._creationTime).toISOString(),
      },
      subscription,
      preferredLocation: user.preferredLocation ?? null,
    };
  },
});

/**
 * Member usage trend (aggregate, read-live-and-never-stored). Resolves the
 * member's current subscription and asks the backend for the last `days` of
 * usage; null when there's no sub or the backend has no usage history (Outline).
 * Kept OUT of getAccountView so it doesn't add a second live backend call to the
 * main account load — the client fetches it lazily when the member opens the panel.
 */
export const getUsage = internalAction({
  args: { userId: v.id('users'), days: v.optional(v.number()) },
  handler: async (ctx, { userId, days }): Promise<{ usage: UsageSeries | null }> => {
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!sub) return { usage: null };
    const usage = await ctx.runAction(internal.backends.getUserUsage, {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      days: days ?? 30,
    });
    return { usage };
  },
});

interface NodeStatusView {
  /** true/false when we have a signal; null = never observed (unknown). */
  online: boolean | null;
  /** Squad/node display name (Remnawave), when known. */
  label: string | null;
  location: { code: string; label: string } | null;
  /** The location's coarse public load band (quiet/busy/crowded); null when the
   *  key has no located instance. */
  load: 'quiet' | 'busy' | 'crowded' | 'unknown' | null;
  /** When the signal was last observed (ISO), null when never. */
  checkedAt: string | null;
}

const NODE_STATUS_FRESH_MS = 60_000;

/**
 * Live-ish status of the node the member's config is homed to, so a member can
 * tell "the node is up, my network is filtering me" from an actual outage. For
 * a placed Remnawave key this is the squad's node snapshot (refreshed on demand
 * at most once per instance per NODE_STATUS_FRESH_MS via the claimStatsRefresh
 * stampede guard — the SPA polls this endpoint); otherwise it degrades to the
 * instance-level healthcheck signal (10-min cron cadence).
 */
export const getNodeStatus = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ node: NodeStatusView | null }> => {
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!sub) return { node: null };
    const server = sub.backendServerId
      ? await ctx.runQuery(internal.backendServers.getById, { id: sub.backendServerId })
      : null;
    const location = server?.location
      ? { code: server.location, label: server.locationLabel ?? server.location }
      : null;
    const load = location
      ? await ctx.runQuery(internal.statusPage.locationLoad, { code: location.code })
      : null;

    if (sub.backend === 'remnawave' && sub.backendPlacement) {
      let stats = await ctx.runQuery(internal.remnawaveNodes.getPlacementStats, {
        placement: sub.backendPlacement,
      });
      if (server && (!stats || Date.now() - stats.lastStatsAt > NODE_STATUS_FRESH_MS)) {
        const claimed = await ctx.runMutation(internal.remnawaveNodes.claimStatsRefresh, {
          backendServerId: server._id,
          freshMs: NODE_STATUS_FRESH_MS,
        });
        if (claimed) {
          await ctx.runAction(internal.backendServers.refreshNodeStats, { id: server._id });
          stats = await ctx.runQuery(internal.remnawaveNodes.getPlacementStats, {
            placement: sub.backendPlacement,
          });
        }
      }
      if (stats) {
        return {
          node: {
            online: stats.online && stats.nodeCount > 0,
            // Neutral label: the panel's squad/node name (stats.label) often
            // encodes provider/host infra detail — the member sees the curated
            // location label instead ("Kansas City, MO").
            label: location?.label ?? null,
            location,
            load,
            checkedAt: new Date(stats.lastStatsAt).toISOString(),
          },
        };
      }
    }

    // Fallback: instance-level health (Outline, legacy rows, placement-less
    // keys). `online:null` when the instance has never passed a healthcheck.
    if (server) {
      const okAt = server.lastHealthOkAt ?? null;
      return {
        node: {
          online: okAt == null ? null : Date.now() - okAt < 30 * 60_000,
          label: null,
          location,
          load,
          checkedAt: okAt != null ? new Date(okAt).toISOString() : null,
        },
      };
    }
    return { node: null };
  },
});

export const regenerate = internalAction({
  args: {
    userId: v.id('users'),
    requestId: v.optional(v.string()),
    // Member's location pick for THIS issuance (a backendServers.location code,
    // validated at the HTTP layer): a string persists the preference, null
    // clears it back to automatic, absent keeps the stored preference.
    location: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (
    ctx,
    { userId, requestId, location },
  ): Promise<{ subscriptionUrl: string; shortUuid: string }> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) throw new Error('user not found');
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) throw new Error('tier not found');

    // Record the location pick BEFORE issuing so the effective preference and
    // the stored one can't diverge (and a failed issuance keeps the choice).
    if (location !== undefined && location !== (user.preferredLocation ?? null)) {
      await ctx.runMutation(internal.users.setPreferredLocation, { userId, location });
    }
    const effectiveLocation = location !== undefined ? location : (user.preferredLocation ?? null);

    // Capture the OLD subscription BEFORE issuing (issueNewSubscription repoints
    // currentSubscriptionId at the new row).
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    // Refuse a re-issue that would silently downgrade the member's mode (an
    // admin unbound its pool) — they must pick an available mode first.
    if (await isEffectiveModeBlocked(ctx, tier.backend, user.connectionModeId ?? null)) {
      throw new ConvexError({ code: 'mode.unavailable', message: MODE_UNAVAILABLE_MESSAGE });
    }
    // Node placement from the member's chosen mode's pool, narrowed to their
    // preferred location (Remnawave only; fail-soft to any location).
    const target = await resolveIssueTarget(
      ctx,
      tier.backend,
      user.connectionModeId ?? null,
      effectiveLocation,
    );
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: tier.backend,
      spec: {
        username: `freesocks-${tier.slug}-${randomHex(8)}`,
        trafficLimitBytes: await carriedTrafficLimit(
          ctx,
          oldSub,
          resolveTrafficLimitBytes(tier, bonusGb),
        ),
        trafficLimitStrategy: tier.trafficStrategy,
        // Member term, else the far-future sentinel (free keys never expire
        // panel-side; the usage-based idle sweep owns free reclaim).
        expireAt: computeExpireAtIso(user.membershipExpiresAt),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
        tag: tier.slug,
        placement: target.placement,
      },
      pinServerId: target.serverId,
      // The node the OLD key was pinned to — avoided on the new key's first
      // fetch, so regenerate moves the member to a different node when one
      // exists (Remnawave node pinning).
      excludeNode: oldSub?.pinnedNode ?? undefined,
    });

    if (oldSub) {
      await tombstoneOldSub(ctx, oldSub.backendUserId);
    }
    await auditIfPlacementless(ctx, {
      backend: tier.backend,
      placement: target.placement,
      userId,
      subscriptionId: issued.subscriptionId,
      requestedMode: user.connectionModeId ?? null,
      requestId,
    });
    // Free key (re)issued → refresh the idle window (and reactivate if the member
    // was inactive and regenerated from a still-valid session). (WS2.)
    if (tier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
    }
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.regenerate',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      requestId,
    });
    return { subscriptionUrl: issued.subscriptionUrl, shortUuid: issued.backendShortId };
  },
});

type SwitchResult =
  | {
      ok: true;
      subscriptionUrl: string;
      shortUuid: string;
      backend: Backend;
      tier: { slug: string; name: string; monthlyTrafficGb: number; deviceLimit: number };
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

export const switchBackend = internalAction({
  args: {
    userId: v.id('users'),
    target: v.union(v.literal('remnawave'), v.literal('outline')),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, { userId, target, requestId }): Promise<SwitchResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const currentTier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!currentTier)
      return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };

    if (currentTier.backend === target) {
      return {
        ok: false,
        code: 'validation',
        message: 'Already on the requested backend',
        status: 400,
      };
    }
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    if (!settings[`${target}.enabled`]) {
      return {
        ok: false,
        code: 'backend.disabled',
        message: `Backend "${target}" is currently disabled. Try again later or contact support.`,
        status: 503,
      };
    }

    // Resolve the cross-backend peer (D-1): a free tier auto-peers via the
    // per-backend default-free row; a paid tier uses the admin-linked peerTierId
    // (either direction). No peer → an actionable 409 (an admin can now link one).
    const peerTier = await ctx.runQuery(internal.tiers.getPeerTier, {
      tierId: currentTier._id,
      targetBackend: target,
    });
    if (!peerTier) {
      return {
        ok: false,
        code: 'tier.no_peer',
        message: `No peer tier configured on backend "${target}" for this membership. Ask an admin to add one.`,
        status: 409,
      };
    }

    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    // Refuse a switch that would silently land the new key in a DIFFERENT mode's
    // pool than the member's stored mode (its pool was unbound by an admin).
    if (await isEffectiveModeBlocked(ctx, peerTier.backend, user.connectionModeId ?? null)) {
      return {
        ok: false,
        code: 'mode.unavailable',
        message: MODE_UNAVAILABLE_MESSAGE,
        status: 400,
      };
    }
    // Carry the member's chosen mode + preferred location across the backend
    // switch (Remnawave only).
    const issueTarget = await resolveIssueTarget(
      ctx,
      peerTier.backend,
      user.connectionModeId ?? null,
      user.preferredLocation ?? null,
    );
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: peerTier.backend,
      spec: {
        username: `freesocks-${peerTier.slug}-${randomHex(8)}`,
        trafficLimitBytes: await carriedTrafficLimit(
          ctx,
          oldSub,
          resolveTrafficLimitBytes(peerTier, bonusGb),
        ),
        trafficLimitStrategy: peerTier.trafficStrategy,
        // Entitlement unchanged by a backend switch: keep the member's term
        // (free keys carry the no-expiry sentinel).
        expireAt: computeExpireAtIso(user.membershipExpiresAt),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], peerTier),
        tag: peerTier.slug,
        placement: issueTarget.placement,
      },
      pinServerId: issueTarget.serverId,
    });

    // P1-6: tombstone the OLD subscription BEFORE flipping the tier. issueNew
    // already repointed currentSubscriptionId at the new key, so the old key is
    // scheduled for teardown first; if a later step dies, the worst case is the
    // user on the old tier with the new key live and the old key tombstoned —
    // never two indefinitely-live keys.
    let oldDeletedAt: number | null = null;
    if (oldSub) {
      const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId);
      oldDeletedAt = tomb?.deletedAt ?? null;
    }

    await auditIfPlacementless(ctx, {
      backend: peerTier.backend,
      placement: issueTarget.placement,
      userId,
      subscriptionId: issued.subscriptionId,
      requestedMode: user.connectionModeId ?? null,
      requestId,
    });
    if (peerTier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
    }
    await ctx.runMutation(internal.users.setTier, { userId, tierId: peerTier._id });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.switch_backend',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      payload: {
        fromBackend: currentTier.backend,
        toBackend: peerTier.backend,
        fromTier: currentTier.slug,
        toTier: peerTier.slug,
      },
      requestId,
    });
    return {
      ok: true,
      subscriptionUrl: issued.subscriptionUrl,
      shortUuid: issued.backendShortId,
      backend: issued.backend,
      tier: {
        slug: peerTier.slug,
        name: peerTier.name,
        monthlyTrafficGb: peerTier.monthlyTrafficGb,
        deviceLimit: peerTier.deviceLimit,
      },
      oldSubscriptionDeletedAt: oldDeletedAt !== null ? new Date(oldDeletedAt).toISOString() : null,
    };
  },
});

type SwitchModeResult =
  | {
      ok: true;
      subscriptionUrl: string;
      shortUuid: string;
      mode: { id: string; label: string | null };
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

/**
 * Switch the member's connection mode (transport) WITHIN the same backend.
 * PREFERS an IN-PLACE update: a member who already holds a live Remnawave key just
 * has that key's squad re-pointed (PATCH /api/users → activeInternalSquads), so the
 * SAME subscription row/URL/token, traffic counter, and devices survive the switch
 * — no user churn and no 24h "old key" window. Falls back to the re-issue saga
 * (mint new key into the mode's least-loaded node → tombstone the old with 24h
 * grace → audit) only when there's no in-place-updatable key: the first key, a
 * cross-backend / non-Remnawave sub, or a PATCH that failed. A mode's
 * `deliveryStyle` is a client-render concern keyed off the recorded mode, so no
 * re-issue is needed to change how the key is delivered.
 */
export const switchMode = internalAction({
  args: {
    userId: v.id('users'),
    target: v.string(),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, { userId, target, requestId }): Promise<SwitchModeResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };

    // No-op guard: choosing the mode you already have shouldn't churn a new key.
    if ((user.connectionModeId ?? null) === target) {
      return {
        ok: false,
        code: 'validation',
        message: 'Already on the requested mode',
        status: 400,
      };
    }

    // Validate the target against the live catalog (data-driven; not a union).
    const modes = await ctx.runQuery(internal.connectionModes.list, {});
    const chosen = modes.find((m) => m.id === target);
    if (!chosen) {
      return { ok: false, code: 'validation', message: 'Unknown connection mode', status: 400 };
    }
    // Refuse to switch to a mode with no placement pool bound (Remnawave only):
    // issuing into it would mint a squad-less "dead" key AND we'd have tombstoned
    // the working key to do it. The picker also disables unbound modes; this is
    // the server-authoritative guard. (WS1.)
    if (tier.backend === 'remnawave' && !chosen.bound) {
      return {
        ok: false,
        code: 'validation',
        message: 'This connection mode is not available yet.',
        status: 400,
      };
    }

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });

    // Re-issue path (the historical behavior): mint a NEW key into the mode's
    // placement and tombstone the old one with 24h grace. Used only when there is
    // no in-place-updatable current key — the first key, a cross-backend /
    // non-Remnawave sub, or an in-place PATCH that failed (e.g. the panel user was
    // manually deleted).
    const reissue = async (): Promise<SwitchModeResult> => {
      const issueTarget = await resolveIssueTarget(
        ctx,
        tier.backend,
        target,
        user.preferredLocation ?? null,
      );
      const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
      const issued = await issueNewSubscription(ctx, {
        userId,
        backend: tier.backend,
        spec: {
          username: `freesocks-${tier.slug}-${randomHex(8)}`,
          trafficLimitBytes: await carriedTrafficLimit(
            ctx,
            oldSub,
            resolveTrafficLimitBytes(tier, bonusGb),
          ),
          trafficLimitStrategy: tier.trafficStrategy,
          expireAt: computeExpireAtIso(user.membershipExpiresAt),
          hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
          tag: tier.slug,
          placement: issueTarget.placement,
        },
        pinServerId: issueTarget.serverId,
      });
      // Tombstone the OLD key before recording the choice (issueNew already
      // repointed currentSubscriptionId), same 24h grace as regenerate/switch.
      let oldDeletedAt: number | null = null;
      if (oldSub) {
        const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId);
        oldDeletedAt = tomb?.deletedAt ?? null;
      }
      await auditIfPlacementless(ctx, {
        backend: tier.backend,
        placement: issueTarget.placement,
        userId,
        subscriptionId: issued.subscriptionId,
        requestedMode: target,
        requestId,
      });
      await ctx.runMutation(internal.users.setConnectionMode, { userId, modeId: target });
      if (tier.isDefaultFree) {
        await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
      }
      await ctx.runMutation(internal.audit.record, {
        actorType: 'member',
        actorId: userId,
        action: 'subscription.switch_mode',
        targetType: 'subscription',
        targetId: issued.subscriptionId,
        // Never a placement/squad uuid — only which mode.
        payload: { fromMode: user.connectionModeId ?? null, toMode: target, inPlace: false },
        requestId,
      });
      return {
        ok: true,
        subscriptionUrl: issued.subscriptionUrl,
        shortUuid: issued.backendShortId,
        mode: { id: chosen.id, label: chosen.label },
        oldSubscriptionDeletedAt:
          oldDeletedAt !== null ? new Date(oldDeletedAt).toISOString() : null,
      };
    };

    // In-place switch (the common case): a member who already has a live Remnawave
    // key just moves it to the new mode's squad via PATCH /api/users. The SAME
    // subscription row/URL/token, live traffic counter, and registered devices are
    // all preserved — no user churn in the panel and no separate "old key" to keep
    // alive for 24h. Only when the current key AND the tier are Remnawave.
    if (oldSub && tier.backend === 'remnawave' && oldSub.backend === 'remnawave') {
      // The in-place PATCH lands on the key's OWN panel, so the new mode's
      // placement must exist there — a hard `onlyServerId` pin. The stored
      // backendServerId can be stale (its panel row was re-registered) or
      // absent (legacy sub); either used to force the re-issue fallback on
      // EVERY switch. Repair it first: probe the active fleet for the panel
      // that actually hosts this key, and persist the fix so every later
      // key→instance resolution works again too. A failed probe resolves
      // unpinned (the historical single-panel behavior).
      let pinServerId: string | null = oldSub.backendServerId ?? null;
      const activeIds = new Set(
        (await ctx.runQuery(internal.backendServers.listActiveWithSecret, {}))
          .filter((s) => s.backend === 'remnawave')
          .map((s) => s._id as string),
      );
      if (!pinServerId || !activeIds.has(pinServerId)) {
        pinServerId = await ctx.runAction(internal.backends.locateKeyInstance, {
          backend: 'remnawave',
          backendUserId: oldSub.backendUserId,
        });
        if (pinServerId) {
          await ctx.runMutation(internal.subscriptions.setBackendServer, {
            subscriptionId: oldSub._id,
            backendServerId: pinServerId as Id<'backendServers'>,
          });
        }
      }
      const { placement: nodePlacement } = await ctx.runQuery(
        internal.remnawaveNodes.resolveTarget,
        {
          modeId: target,
          onlyServerId: pinServerId as Id<'backendServers'> | null,
        },
      );
      // null when no pool is bound anywhere OR the target mode has no squad on
      // this key's panel; the re-issue path owns both (it may move panels and
      // owns the squad-less-key audit), so fall through to it rather than PATCH
      // a squad clear onto a live key. (The per-mode unbound case was rejected
      // above.)
      if (nodePlacement !== null) {
        // Persist BEFORE the panel PATCH (Review D-#6): a concurrent
        // pushTierToBackend reads the PERSISTED placement — with DB-first, a
        // push landing mid-switch re-sends the NEW placement (exactly what the
        // PATCH is about to do), so panel and DB stay convergent. The old
        // order (PATCH → persist) let such a push silently revert the squad
        // move while the DB recorded it. On PATCH failure we restore the old
        // persisted placement so the DB never claims a move that didn't happen.
        await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
          subscriptionId: oldSub._id,
          placement: nodePlacement,
        });
        try {
          await ctx.runAction(internal.backends.updateUser, {
            backend: 'remnawave',
            backendUserId: oldSub.backendUserId,
            patch: { placement: nodePlacement },
          });
        } catch (e) {
          console.warn('[switchMode] in-place placement update failed; re-issuing', e);
          await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
            subscriptionId: oldSub._id,
            placement: oldSub.backendPlacement ?? null,
          });
          return reissue();
        }
        await ctx.runMutation(internal.users.setConnectionMode, { userId, modeId: target });
        if (tier.isDefaultFree) {
          await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
        }
        await ctx.runMutation(internal.audit.record, {
          actorType: 'member',
          actorId: userId,
          action: 'subscription.switch_mode',
          targetType: 'subscription',
          targetId: oldSub._id,
          // Never a placement/squad uuid — only which mode + that it was in place.
          payload: { fromMode: user.connectionModeId ?? null, toMode: target, inPlace: true },
          requestId,
        });
        return {
          ok: true,
          // Same key: the member's saved fronted URL keeps working, now homed to
          // the new node. No tombstone → nothing is deleted.
          subscriptionUrl: oldSub.subscriptionUrl,
          shortUuid: oldSub.backendShortId,
          mode: { id: chosen.id, label: chosen.label },
          oldSubscriptionDeletedAt: null,
        };
      }
    }
    return reissue();
  },
});

type RevokeDeviceResult =
  | { ok: true }
  | { ok: false; code: string; message: string; status: number };

/**
 * Revoke one of the member's HWID devices, freeing a slot under the tier's
 * device cap without a full key regenerate. The hwid must belong to the
 * member's own current key (verified against the backend's live device list
 * before the delete — a member can never name someone else's device).
 */
export const revokeDevice = internalAction({
  args: { userId: v.id('users'), hwid: v.string(), requestId: v.optional(v.string()) },
  handler: async (ctx, { userId, hwid, requestId }): Promise<RevokeDeviceResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!sub) {
      return {
        ok: false,
        code: 'devices.no_subscription',
        message: 'No active subscription',
        status: 404,
      };
    }
    if (sub.backend !== 'remnawave') {
      return {
        ok: false,
        code: 'devices.unsupported',
        message: 'This backend does not support device management',
        status: 409,
      };
    }

    // Backend failures (a RemnawaveApiError carries a panel-body slice) must be
    // mapped to a generic result HERE — otherwise they escape the route and
    // surface as a runtime 500 with panel text attached (every other member
    // route maps backend errors to a clean 502). (Review D-#5.)
    let state;
    try {
      state = await ctx.runAction(internal.backends.getUser, {
        backend: sub.backend,
        backendUserId: sub.backendUserId,
      });
    } catch {
      return {
        ok: false,
        code: 'devices.unavailable',
        message: 'Device service is unavailable right now. Please try again later.',
        status: 502,
      };
    }
    // Ownership check: the hwid must be on the member's own key right now.
    if (!state.devices.some((d) => d.hwid === hwid)) {
      return {
        ok: false,
        code: 'devices.not_found',
        message: 'Device not found on this account',
        status: 404,
      };
    }

    try {
      await ctx.runAction(internal.backends.revokeDevice, {
        backend: sub.backend,
        backendUserId: sub.backendUserId,
        hwid,
      });
    } catch {
      return {
        ok: false,
        code: 'devices.unavailable',
        message: 'Device service is unavailable right now. Please try again later.',
        status: 502,
      };
    }
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.device_revoke',
      targetType: 'subscription',
      targetId: sub._id,
      // Never the full hwid (it's a device identifier): a short prefix traces it.
      payload: { hwidPrefix: hwid.slice(0, 8) },
      requestId,
    });
    return { ok: true };
  },
});

/** Local entitlement snapshot (CiviCRM live lookup removed). Read-only query. */
export const refreshMembership = internalAction({
  args: { userId: v.id('users') },
  handler: async (
    ctx,
    { userId },
  ): Promise<{
    tierSlug: string;
    tierName: string;
    membershipExpiresAt: string | null;
    isCurrent: boolean;
  }> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    const tier = user ? await ctx.runQuery(internal.tiers.get, { id: user.tierId }) : null;
    const effective = tier ?? (await ctx.runQuery(internal.tiers.getDefaultFree, {}));
    if (!effective) throw new Error('no tier');
    return {
      tierSlug: effective.slug,
      tierName: effective.name,
      membershipExpiresAt: user?.membershipExpiresAt
        ? new Date(user.membershipExpiresAt).toISOString()
        : null,
      isCurrent: (user?.status ?? 'active') === 'active',
    };
  },
});
