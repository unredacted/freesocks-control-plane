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
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
  type QueryCtx,
} from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { randomHex } from './lib/crypto';
import { requiresPrivateDelivery } from '../src/shared/contracts/connectionModes';
import { boundedUsername } from './lib/backends/username';
import { issueNewSubscription } from './lib/issuance';
import { carryPeriodEnd, liveCarryBytes, type CarryFields } from './lib/quotaCarry';
import {
  applyUsageCarryover,
  computeExpireAtIso,
  resolveHwidLimit,
  resolveTrafficLimitBytes,
  type TrafficLimitStrategy,
  type UsageSeries,
  type UserState,
} from './lib/backends/types';
import { backendIdValidator, type BackendId } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import { currentOrActiveSub } from './subscriptions';
import { placementSetOf } from './lib/placementSet';
import { appNoticeShown, type AppNoticeFamily } from './lib/appNotice';
import { mirrorFormatsOf, type MirrorFormat } from '../src/shared/mirrorFormats';
import {
  crossPanelMoveProven,
  groupHasOtherNode,
  inPlaceMoveProven,
  switchServerAvailable as switchServerAvailableIn,
} from './lib/switchServer';
import { resolveAppSettings } from './appSettings';
import { defaultModeIdOf, memberModeOf } from './connectionModes';
import { resolveCatalogWithAvailability } from './lib/placement';
import { currentBonusGbOf, donationTotalsOf } from './donations';
import { deliveryPolicyFor, rawUrlEdgeRequiredOf } from './edgeRender';
import { freedomRawUrlWithheldOf } from './freedomDelivery';
import { extraModeDegradedOf } from './lib/extraModeNodes';
import { readingContextOf, memberViewOf } from './memberCountry';
import { isListedOf, suggestModeOf } from './censoredCountries';
import { suggestionCountry } from './lib/memberCountry';
import { pendingGiftRevealOf } from './billing';
import type { OwnExits } from './lib/ownExits';

/**
 * Whether a key's raw backend URL (and the short id it ends in) is kept from
 * its member, who is handed only the fronted token URL. Under edge-required
 * delivery the raw URL serves the origin's own body (for an Outline key it IS
 * the `ss://` key at the origin address): withheld where a delivery binding
 * covers the key's node, or, for a key not pinned to a node yet, anywhere on
 * its backend (`edgeRender.rawUrlEdgeRequired`). So is a key held to freedom
 * delivery through edges (the backend URL hands out its nodes' own addresses).
 */
async function rawUrlWithheld(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'>,
): Promise<boolean> {
  return (
    (await ctx.runQuery(internal.edgeRender.rawUrlEdgeRequired, { subscriptionId })) ||
    (await ctx.runQuery(internal.freedomDelivery.rawUrlWithheld, { subscriptionId }))
  );
}

/** The raw URL and short id an issue or switch answer carries: both blank when withheld. */
async function memberFacing(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'>,
  key: { subscriptionUrl: string; backendShortId: string },
): Promise<{ subscriptionUrl: string; shortUuid: string }> {
  return (await rawUrlWithheld(ctx, subscriptionId))
    ? { subscriptionUrl: '', shortUuid: '' }
    : { subscriptionUrl: key.subscriptionUrl, shortUuid: key.backendShortId };
}

type Backend = BackendId;

/**
 * WS1 bring-up safety net: when a Remnawave key is issued with a null placement
 * (only possible when NO mode has a pool bound anywhere on the deploy), the key
 * has no transports. We still issue it (keys must mint during bring-up) but never
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
  if (!capabilitiesOf(args.backend).placement || args.placement !== null) return;
  console.warn('[placement] issued a placement-less key: no pool bound on this deploy');
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
 * Quota carryover (Review D-M3, lib/quotaCarry.ts): a re-issue mints a FRESH
 * backend traffic counter, so without a carry every regenerate/switch would
 * reset the member's period quota (scripted churn compounded it by orders of
 * magnitude). The new key's limit is the tier limit less what the member
 * already spent this period: the old key's live usage PLUS what that key had
 * itself carried in from its predecessors, so a chain of re-issues cannot
 * forget earlier keys. Spending on the old key during its 24h grace is charged
 * to the current key by the tombstone sweep (`graceBaseUsedBytes`,
 * lifecycle.settleGraceUsage).
 *
 * Best-effort: a backend blip (or an already-gone old key) must not block
 * re-issue, since the member may be replacing a key on a failing server. A
 * fully-spent quota carries as 1 byte, NOT 0: 0 means UNLIMITED to Remnawave
 * (and 'blocked' to Outline), so 1 byte is the only value that reads as
 * "spent" on both.
 */
type QuotaCarry = {
  trafficLimitBytes: number | null;
  // Spent on earlier keys this period and when it stops counting (new row).
  periodCarryBytes?: number;
  periodCarryUntil?: number;
  // The old key's usage counted above, stored on its tombstone.
  graceBaseUsedBytes?: number;
};

async function carriedTrafficLimit(
  ctx: ActionCtx,
  oldSub: ({ backend: Backend; backendUserId: string } & CarryFields) | null,
  tier: {
    monthlyTrafficGb: number;
    isDefaultFree: boolean;
    trafficStrategy?: TrafficLimitStrategy;
  },
  bonusGb: number,
): Promise<QuotaCarry> {
  const limitBytes = resolveTrafficLimitBytes(tier, bonusGb);
  if (limitBytes === null || !oldSub) return { trafficLimitBytes: limitBytes };
  try {
    const state = await ctx.runAction(internal.backends.getUser, {
      backend: oldSub.backend,
      backendUserId: oldSub.backendUserId,
    });
    const now = Date.now();
    const used = Math.max(0, Math.floor(state.usedTrafficBytes ?? 0));
    const spent = used + liveCarryBytes(oldSub, now);
    return {
      trafficLimitBytes: applyUsageCarryover(limitBytes, spent),
      periodCarryBytes: spent,
      periodCarryUntil: carryPeriodEnd(tier.trafficStrategy, now),
      graceBaseUsedBytes: used,
    };
  } catch {
    console.warn('[account] usage-carryover read failed; issuing at the full tier limit');
    return { trafficLimitBytes: limitBytes };
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
  graceBaseUsedBytes?: number,
): Promise<{ deletedAt: number } | null> {
  try {
    return await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
      backendUserId,
      graceMs: TOMBSTONE_GRACE_MS,
      graceBaseUsedBytes,
    });
  } catch (err) {
    console.warn(
      `[subscription] tombstone failed; scheduling retry: ${err instanceof Error ? err.message : String(err)}`,
    );
    await ctx.scheduler.runAfter(0, internal.subscriptions.tombstoneWithGraceAction, {
      backendUserId,
      graceMs: TOMBSTONE_GRACE_MS,
      attempt: 0,
      graceBaseUsedBytes,
    });
    return null;
  }
}

/**
 * Where a NEW key issues: for Remnawave, the (placement, backend) pair resolved
 * TOGETHER (a mode group UUID only exists on its own backend) for the member's mode +
 * preferred location; null-everything for other backends. `serverId` pins
 * issueUser to the mode group's backend — without it the instance pick could land on a
 * different backend than the mode group (a dead key on any multi-backend deploy).
 * `userId`: with no location pick, the exit locations of the member's own
 * country choice (countryExits.forIssue) narrow it softly, in order.
 */
async function resolveIssueTarget(
  ctx: ActionCtx,
  backend: Backend,
  modeId: string | null,
  location: string | null,
  userId?: Id<'users'>,
  choiceHint?: string,
): Promise<{
  placement: string | null;
  extraPlacements: string[];
  serverId: Id<'backendServers'> | null;
}> {
  if (!capabilitiesOf(backend).placement)
    return { placement: null, extraPlacements: [], serverId: null };
  const exitLocations =
    !location && userId
      ? await ctx.runQuery(internal.countryExits.forIssue, {
          userId,
          backend,
          modeId,
          ...(choiceHint ? { choiceHint } : {}),
        })
      : [];
  // Mint the anti-herding randomness HERE (actions may use the CSPRNG; queries
  // must stay deterministic) and thread it through the resolution.
  const randBuf = new Uint32Array(1);
  crypto.getRandomValues(randBuf);
  const t = await ctx.runQuery(internal.connectionModes.resolveIssueTarget, {
    backend,
    modeId,
    location,
    ...(exitLocations.length > 0 ? { exitLocations } : {}),
    rand: randBuf[0]! / 2 ** 32,
  });
  // Multi-backend + zero attributable mode groups: an unpinned issue would mint a
  // (mode group, wrong-backend) dead key — fail loudly (503, retryable once the stats
  // cron attributes the pool) instead. Single-backend deploys never see this.
  if (t.unattributedMultiPanel) {
    throw new ConvexError({
      code: 'backend.placement_unresolved',
      message:
        'Node placement is still resolving on this deployment. Please try again in a few minutes.',
    });
  }
  // A mode with a backup group (a Hysteria key's REALITY one) never issues
  // without it: the member would hold a key with no fallback entry.
  if (t.fallbackUnresolved) {
    throw new ConvexError({
      code: 'mode.fallback_unbound',
      message: 'This connection mode is not available on this server right now.',
    });
  }
  return {
    placement: t.placement,
    extraPlacements: t.extraPlacements,
    serverId: (t.serverId as Id<'backendServers'> | null) ?? null,
  };
}

/**
 * The backend that actually hosts a live key, for the in-place update paths. The
 * stored `backendServerId` can be stale (its backend row was re-registered) or
 * absent (legacy sub); either used to force the re-issue fallback on EVERY
 * switch. Repair it: probe the active fleet for the backend that really has this
 * key, and persist the fix so later key→instance resolutions work too. A failed
 * probe resolves null = unpinned (the historical single-backend behavior).
 */
async function resolveOwnPanel(
  ctx: ActionCtx,
  sub: { _id: Id<'subscriptions'>; backendUserId: string; backendServerId?: Id<'backendServers'> },
  backend: Backend,
): Promise<string | null> {
  let pinServerId: string | null = sub.backendServerId ?? null;
  const activeIds = new Set(
    (await ctx.runQuery(internal.backendServers.listActiveWithSecret, {}))
      .filter((s) => s.backend === backend)
      .map((s) => s._id as string),
  );
  if (!pinServerId || !activeIds.has(pinServerId)) {
    pinServerId = await ctx.runAction(internal.backends.locateKeyInstance, {
      backend,
      backendUserId: sub.backendUserId,
    });
    if (pinServerId) {
      await ctx.runMutation(internal.subscriptions.setBackendServer, {
        subscriptionId: sub._id,
        backendServerId: pinServerId as Id<'backendServers'>,
      });
    }
  }
  return pinServerId;
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

/** The signup preference may be written only before first-key issuance starts.
 * Reading the same lock as the issuance saga and checking for an active row in
 * this transaction rules out a change between placement selection and issuance. */
export const setInitialMode = internalMutation({
  args: { userId: v.id('users'), modeId: v.string() },
  handler: async (ctx, { userId, modeId }): Promise<'saved' | 'issuing' | 'active'> => {
    const lock = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', `issue-lock:${userId}`))
      .unique();
    if (lock && parseLock(lock.value).exp > Date.now()) return 'issuing';
    const active = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .first();
    if (active) return 'active';
    await ctx.db.patch(userId, { connectionModeId: modeId, updatedAt: Date.now() });
    return 'saved';
  },
});

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
 * proceeds mode group-less + audited.
 */
const MODE_UNAVAILABLE_MESSAGE =
  'Your current connection mode is no longer available. Switch to another connection mode first.';

async function isEffectiveModeBlocked(
  ctx: ActionCtx,
  backend: Backend,
  modeId: string | null,
): Promise<boolean> {
  // Backend-AGNOSTIC: dispatched to the backend's placement resolver (or the
  // catalog-judged trivial gate), so switching to a placement-less backend can
  // no longer bypass a blocked stored mode when that backend has usable modes
  // of its own.
  const gate = await ctx.runQuery(internal.connectionModes.effectiveGate, { backend, modeId });
  return gate.blocked;
}

/** A saved preference can predate the live key, or its catalog default may
 * have changed. A server/location move can preserve public links into a
 * private mode only if the key already belongs to that mode. */
async function canMoveWithExistingUrls(
  ctx: ActionCtx,
  backend: Backend,
  modeId: string | null,
  placement: string | undefined,
): Promise<boolean> {
  const mode = await ctx.runQuery(internal.connectionModes.memberMode, { backend, modeId });
  if (!mode || !requiresPrivateDelivery(mode.deliveryStyle, mode.family?.id)) return true;
  return (
    !!placement &&
    (await ctx.runQuery(internal.subscriptions.placementIsSolelyInMode, {
      placement,
      modeId: mode.id,
    }))
  );
}

const PRIVATE_MOVE_REQUIRES_NEW_KEY = {
  ok: false,
  code: 'mode.unavailable',
  status: 409,
  message: 'Regenerate your subscription before moving this key to a private placement.',
} as const;

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
    // Fully-resolved projection of the member's CURRENT mode — present even
    // when the mode is admin-disabled or gone from the catalog, so the client
    // renders the right delivery UI + label instead of a raw slug.
    currentMode: {
      id: string;
      deliveryStyle: 'url' | 'rawConfig';
      label: string | null;
      description: string | null;
      family: { id: string; label: string | null } | null;
      available: boolean;
    } | null;
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
    /** An origin covers this key's place: only the fronted token URL is handed out. */
    edgeRequired: boolean;
    shortUuid: string;
    mirrors: { provider: string; publicUrl: string; formats: MirrorFormat[] }[];
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
    /** "Switch server" would move this key right now (`switchServerAvailable`). */
    canSwitchServer: boolean;
    /**
     * A key in two groups (a Hysteria key with its REALITY backup) whose mode
     * no node serves for it right now: its config carries the backup only.
     */
    udpUnavailable: boolean;
    /**
     * An app that fetched this key's link got the app notice within the hint
     * window (lib/appNotice.ts `appNoticeShown`): the kind of app and when
     * (ISO). Null otherwise.
     */
    appNotice: { family: AppNoticeFamily; at: string } | null;
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
  /** A paid gift order whose codes the member hasn't seen yet (its order ref,
   *  the same poll token as /account?order=), so the SPA opens the one-time
   *  reveal on the next visit. Null when none. */
  pendingGiftOrderRef: string | null;
}

/** The view's fields that come from the backend's live state, not the database. */
type LiveField =
  | 'expiresAt'
  | 'trafficLimitBytes'
  | 'trafficUsedBytes'
  | 'status'
  | 'resetStrategy'
  | 'lastResetAt'
  | 'devices';

/** Everything the account view reads from the database, read in one transaction. */
export interface AccountViewData {
  /** The view without its key; `user.supportId` is null when it is still to be minted. */
  view: Omit<AccountView, 'subscription'>;
  /** The key the view shows (what the live backend read needs, and its local part). */
  key: {
    id: Id<'subscriptions'>;
    backend: Backend;
    backendUserId: string;
    local: Omit<NonNullable<AccountView['subscription']>, LiveField>;
  } | null;
  /** The cap shown while the backend is unreachable: the tier's, with the shared donation bonus. */
  trafficLimitFromTier: number | null;
  /**
   * The account route's part, present when the caller passed `geoCountry`: the
   * member-country reading context and the verdicts for this request's country.
   * `suggestedModeId` is null when detection will store a reading first (the
   * route asks again after it), since the suggestion reads the stored country.
   */
  route: {
    detect: boolean;
    ownExits: OwnExits;
    suggestedModeId: string | null;
    geoCountryCensored: boolean;
  } | null;
}

async function accountViewDataOf(
  ctx: QueryCtx,
  args: {
    userId: Id<'users'>;
    includeSubscriptionCredentials: boolean;
    geoCountry?: string | null;
  },
): Promise<AccountViewData | null> {
  const { db } = ctx;
  const { userId, includeSubscriptionCredentials, geoCountry } = args;
  const user = await db.get(userId);
  if (!user) return null;
  const tier = await db.get(user.tierId);
  if (!tier) return null;
  const now = Date.now();
  const sub = await currentOrActiveSub(db, user);
  const settings = await resolveAppSettings(db);
  const deviceLimited = !!settings['devices.enforcementEnabled'] && tier.hwidEnabled;

  // Member's chosen connection mode (or the catalog default) — surfaced so the
  // client renders the selected transport server-authoritatively.
  const catalog = await resolveCatalogWithAvailability(db);
  const connectionModeId =
    user.connectionModeId ?? (await defaultModeIdOf(db, tier.backend, catalog));
  const currentMode = await memberModeOf(db, connectionModeId, tier.backend, catalog);
  // Fold the current shared donation bonus into the free-tier fallback so an
  // outage (backend unreachable) still shows the raised cap, not the base.
  const bonusGb = await currentBonusGbOf(db);
  const trafficLimitFromTier = resolveTrafficLimitBytes(tier, bonusGb);
  // The member's own settled donation totals (impact backend). The GB figure is
  // computed server-side at the current rate so the raw rate never ships.
  const donationTotals = await donationTotalsOf(db, user);

  let key: AccountViewData['key'] = null;
  if (sub) {
    // The hosting instance's member-facing location (code + label; no secrets).
    const server = sub.backendServerId ? await db.get(sub.backendServerId) : null;
    // Edge-required delivery (docs/edges.md): when an origin covers this key's
    // place, only the fronted token URL is handed out (`rawUrlWithheld`).
    const delivery = sub.backendServerId
      ? await deliveryPolicyFor(ctx, sub.backendServerId, sub.pinnedNode ?? undefined)
      : null;
    const edgeRequired = delivery?.required === true;
    // An app on this key got the app notice lately (lib/appNotice.ts).
    const notice = appNoticeShown(sub.appNotice, now);
    const withheld =
      !includeSubscriptionCredentials ||
      edgeRequired ||
      (await rawUrlEdgeRequiredOf(db, sub)) ||
      (await freedomRawUrlWithheldOf(db, sub._id));
    key = {
      id: sub._id,
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      local: {
        // The raw backend URL (fallback) + the opaque token; the SPA builds the
        // FCP-fronted URL from the token + its own origin, so there's no
        // deployment-origin env dependency and every UI surface fronts uniformly.
        url: withheld ? '' : sub.subscriptionUrl,
        edgeRequired,
        subToken: includeSubscriptionCredentials ? (sub.subToken ?? null) : null,
        shortUuid: withheld ? '' : sub.backendShortId,
        // Don't advertise a mirror whose last refresh failed (Review #2): it's kept
        // in the DB so the cap holds + the next refresh retries it, but the member
        // shouldn't be handed a URL we couldn't refresh.
        mirrors: (includeSubscriptionCredentials ? sub.subscriptionMirrors : [])
          .filter((m) => m.status !== 'failed')
          .map((m) => ({
            provider: m.provider,
            publicUrl: m.publicUrl,
            // The formats written at this copy: an app is handed its own only once it exists.
            formats: mirrorFormatsOf(m),
          })),
        backend: sub.backend,
        location: server?.location
          ? { code: server.location, label: server.locationLabel ?? server.location }
          : null,
        canSwitchServer: await switchServerAvailableIn(db, user, tier, sub, now),
        udpUnavailable: await extraModeDegradedOf(db, sub),
        appNotice: notice ? { family: notice.family, at: new Date(notice.at).toISOString() } : null,
      },
    };
  }

  let route: AccountViewData['route'] = null;
  if (geoCountry !== undefined) {
    // The account route (http.ts): with detection on and a country on this
    // request, the route stores the reading first and then asks for the
    // suggestion, so it is not computed here. Without a country, a reading from
    // one of FCP's own exits may still be stored: the route compares the client
    // address (never passed in here) and asks again in that case.
    const reading = await readingContextOf(db);
    const suggestedModeId =
      reading.detect && geoCountry
        ? null
        : await suggestModeOf(
            db,
            tier.backend,
            suggestionCountry(await memberViewOf(db, userId), geoCountry),
          );
    route = {
      detect: reading.detect,
      ownExits: reading.ownExits,
      suggestedModeId,
      geoCountryCensored: await isListedOf(db, geoCountry),
    };
  }

  return {
    view: {
      user: {
        id: user._id,
        status: user.status,
        supportId: user.supportId ?? null,
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
        currentMode,
        donorSince: user.firstDonatedAt ? new Date(user.firstDonatedAt).toISOString() : null,
        donatedCentsTotal: donationTotals.donatedCentsTotal,
        donationCount: donationTotals.donationCount,
        donatedGbTotal: donationTotals.donatedGbTotal,
        createdAt: new Date(user._creationTime).toISOString(),
      },
      preferredLocation: user.preferredLocation ?? null,
      pendingGiftOrderRef: await pendingGiftRevealOf(db, userId),
    },
    key,
    trafficLimitFromTier,
    route,
  };
}

/**
 * The database half of the account view in ONE query: one transaction (a
 * consistent snapshot) and one query-cache entry per (member, grant, country),
 * where the view used to be a chain of about fifteen queries, each at its own
 * timestamp. A deterministic function of its args: the clock is read inside.
 */
export const accountViewData = internalQuery({
  args: {
    userId: v.id('users'),
    includeSubscriptionCredentials: v.boolean(),
    geoCountry: v.optional(v.union(v.string(), v.null())),
  },
  handler: (ctx, args) => accountViewDataOf(ctx, args),
});

/** Which key the view will show, for the live backend read started beside the view query. */
export const liveKeyOf = internalQuery({
  args: { userId: v.id('users') },
  handler: async (
    ctx,
    { userId },
  ): Promise<{ id: Id<'subscriptions'>; backend: Backend; backendUserId: string } | null> => {
    const user = await ctx.db.get(userId);
    const sub = user ? await currentOrActiveSub(ctx.db, user) : null;
    return sub ? { id: sub._id, backend: sub.backend, backendUserId: sub.backendUserId } : null;
  },
});

type LiveState = UserState | null;

/** Best-effort live state; null when the backend is down or no instance resolves the key. */
async function readLiveState(
  ctx: ActionCtx,
  key: { backend: Backend; backendUserId: string },
): Promise<LiveState> {
  try {
    return await ctx.runAction(internal.backends.getUser, {
      backend: key.backend,
      backendUserId: key.backendUserId,
    });
  } catch {
    return null;
  }
}

/**
 * Start the account view: the view query and the live backend read run side
 * by side (the live read needs only which key, from a small query of its own).
 * Null for an unknown user or tier. `finish` merges the live state in, and
 * mints a missing support ID; the account route runs its member-country step
 * between the two, beside the live read.
 */
export async function startAccountView(
  ctx: ActionCtx,
  args: {
    userId: Id<'users'>;
    includeSubscriptionCredentials: boolean;
    geoCountry?: string | null;
  },
): Promise<{ data: AccountViewData; finish: () => Promise<AccountView> } | null> {
  const early = ctx
    .runQuery(internal.account.liveKeyOf, { userId: args.userId })
    .then(async (key) => (key ? { id: key.id, state: await readLiveState(ctx, key) } : null));
  // Settle the early read even when the view query throws, so it never rejects unobserved.
  early.catch(() => undefined);
  const data = await ctx.runQuery(internal.account.accountViewData, args);
  if (!data) return null;
  const finish = async (): Promise<AccountView> => {
    // W3: lazily backfill the support ID for pre-W3 accounts. Non-fatal — the
    // account view still renders if minting transiently fails.
    const supportId: Promise<string | null> = data.view.user.supportId
      ? Promise.resolve(data.view.user.supportId)
      : ctx.runAction(internal.supportId.ensureForUser, { userId: args.userId }).then(
          (r) => r.supportId,
          () => null /* leave null; next view retries */,
        );
    const { key } = data;
    let live: LiveState = null;
    if (key) {
      const read = await early.catch(() => null);
      // A key re-issued between the two reads: read the one the view shows.
      live = read?.id === key.id ? read.state : await readLiveState(ctx, key);
    }
    const subscription: AccountView['subscription'] = key
      ? {
          ...key.local,
          expiresAt: live?.expireAt ?? null,
          trafficLimitBytes: live ? live.trafficLimitBytes : data.trafficLimitFromTier,
          trafficUsedBytes: live?.usedTrafficBytes ?? 0,
          // Degrade default: backend unreachable ⇒ we don't know the key's status,
          // so 'unknown' (the member badge only fires for limited/disabled).
          status: live?.status ?? 'unknown',
          resetStrategy: live?.trafficLimitStrategy,
          lastResetAt: live?.lastTrafficResetAt,
          devices: (live?.devices ?? []).map((d) => ({
            hwid: d.hwid,
            platform: d.platform ?? undefined,
            deviceModel: d.deviceModel ?? undefined,
            firstSeenAt: d.firstSeenAt ?? undefined,
            lastSeenAt: d.lastSeenAt ?? undefined,
          })),
        }
      : null;
    return {
      ...data.view,
      user: { ...data.view.user, supportId: await supportId },
      subscription,
    };
  };
  return { data, finish };
}

export const getAccountView = internalAction({
  args: { userId: v.id('users'), includeSubscriptionCredentials: v.optional(v.boolean()) },
  handler: async (
    ctx,
    { userId, includeSubscriptionCredentials = false },
  ): Promise<AccountView | null> => {
    const started = await startAccountView(ctx, { userId, includeSubscriptionCredentials });
    return started ? started.finish() : null;
  },
});

/**
 * Member usage trend (aggregate, read-live-and-never-stored). Resolves the
 * member's current subscription and asks the backend for the last `days` of
 * usage; null when there's no sub or the backend has no usage history (Outline).
 * Kept OUT of getAccountView so it doesn't add a second live backend call to the
 * main account load — the client fetches it lazily when the member opens the backend.
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
  /** Mode group/node display name (Remnawave), when known. */
  label: string | null;
  location: { code: string; label: string } | null;
  /** The location's coarse public load band (quiet/busy/crowded); null when the
   *  key has no located instance. */
  load: 'quiet' | 'busy' | 'crowded' | 'unknown' | null;
  /** When the signal was last observed (ISO), null when never. */
  checkedAt: string | null;
  /** Edges (docs/edges.md): a refresh nudge + the labels of the
   *  connections this key's subscription carries. Null when the key is not
   *  behind a rendered origin origin. Labels only, never addresses. */
  relay: {
    refreshSuggested: boolean;
    /** `name` = a hostname-fronted connection (one entry, no address family). */
    connections: Array<{
      label: string;
      /** The name without its form tag or spare number: one per address. */
      base: string;
      role: 'primary' | 'backup';
      family: 'v4' | 'v6' | 'name';
    }>;
  } | null;
}

const NODE_STATUS_FRESH_MS = 60_000;

/**
 * Live-ish status of the node the member's config is homed to, so a member can
 * tell "the node is up, my network is filtering me" from an actual outage. For
 * a placed Remnawave key this is the mode group's node snapshot (refreshed on demand
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
    const relay = await ctx.runQuery(internal.edgeRender.memberView, { subscriptionId: sub._id });

    if (capabilitiesOf(sub.backend).nodeStats && sub.backendPlacement) {
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
            // Neutral label: the backend's mode group/node name (stats.label) often
            // encodes provider/host infra detail — the member sees the curated
            // location label instead ("Kansas City, MO").
            label: location?.label ?? null,
            location,
            load,
            checkedAt: new Date(stats.lastStatsAt).toISOString(),
            relay,
          },
        };
      }
    }

    // Fallback: instance-level health (Outline, legacy rows, placement-less
    // keys). `online:null` when the instance has never passed a healthcheck.
    if (server) {
      const okAt: number | null = await ctx.runQuery(internal.backendServers.lastHealthOkAt, {
        id: server._id,
      });
      return {
        node: {
          online: okAt == null ? null : Date.now() - okAt < 30 * 60_000,
          label: null,
          location,
          load,
          checkedAt: okAt != null ? new Date(okAt).toISOString() : null,
          relay,
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
    // The member's answer to "Where are you connecting from?" given with this
    // issuance (sign-up's first key; checked by the HTTP layer): a listed
    // country or `ZZ`. Stored on the new key only when its mode is
    // freedom-family; `regionApplied` says whether it was.
    region: v.optional(v.string()),
    // The country the CDN reports for this request (transient, never stored):
    // with no answer, the first key's location preference reads it.
    geoCountry: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { userId, requestId, location, region, geoCountry },
  ): Promise<{ subscriptionUrl: string; shortUuid: string; regionApplied: boolean }> => {
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
    // The first key (none to replace) is placed for the member's country: the
    // answer given with it, else the request's (lib/countryExits.ts).
    const target = await resolveIssueTarget(
      ctx,
      tier.backend,
      user.connectionModeId ?? null,
      effectiveLocation,
      userId,
      oldSub ? undefined : (region ?? geoCountry),
    );
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const carry = await carriedTrafficLimit(ctx, oldSub, tier, bonusGb);
    const issued = await issueNewSubscription(ctx, {
      periodCarryBytes: carry.periodCarryBytes,
      periodCarryUntil: carry.periodCarryUntil,
      userId,
      backend: tier.backend,
      spec: {
        username: boundedUsername('freesocks-', tier.slug, randomHex(8)),
        trafficLimitBytes: carry.trafficLimitBytes,
        trafficLimitStrategy: tier.trafficStrategy,
        // Member term, else the far-future sentinel (free keys never expire
        // backend-side; the usage-based idle sweep owns free reclaim).
        expireAt: computeExpireAtIso(user.membershipExpiresAt),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
        tag: tier.slug,
        placement: target.placement,
        // The groups it also needs (a Hysteria key's REALITY backup).
        extraPlacements: target.extraPlacements,
      },
      pinServerId: target.serverId,
      // The node the OLD key was pinned to — avoided on the new key's first
      // fetch, so regenerate moves the member to a different node when one
      // exists (Remnawave node pinning).
      excludeNode: oldSub?.pinnedNode ?? undefined,
      // NO carrySubTokenFromId: regenerate exists to ROTATE the member's URL
      // (the recover-from-a-leaked-link action) — mode/backend switches carry
      // the token so their URL never changes; this one must not. Their answer
      // to "where are you connecting from?" does follow them (not a guess).
      carryCountryFromId: oldSub?._id,
      region,
    });
    const regionApplied =
      region !== undefined &&
      (await ctx.runQuery(internal.memberCountry.keyChoice, {
        subscriptionId: issued.subscriptionId,
      })) === region.trim().toUpperCase();

    if (oldSub) {
      await tombstoneOldSub(ctx, oldSub.backendUserId, carry.graceBaseUsedBytes);
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
    return {
      ...(await memberFacing(ctx, issued.subscriptionId, issued)),
      regionApplied,
    };
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
    target: backendIdValidator,
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
      userId,
    );
    const destination = await ctx.runQuery(internal.connectionModes.memberMode, {
      backend: peerTier.backend,
      modeId: user.connectionModeId ?? null,
    });
    const privateDestination = requiresPrivateDelivery(
      destination?.deliveryStyle,
      destination?.family?.id,
    );
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const carry = await carriedTrafficLimit(ctx, oldSub, peerTier, bonusGb);
    const issued = await issueNewSubscription(ctx, {
      periodCarryBytes: carry.periodCarryBytes,
      periodCarryUntil: carry.periodCarryUntil,
      userId,
      backend: peerTier.backend,
      spec: {
        username: boundedUsername('freesocks-', peerTier.slug, randomHex(8)),
        trafficLimitBytes: carry.trafficLimitBytes,
        trafficLimitStrategy: peerTier.trafficStrategy,
        // Entitlement unchanged by a backend switch: keep the member's term
        // (free keys carry the no-expiry sentinel).
        expireAt: computeExpireAtIso(user.membershipExpiresAt),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], peerTier),
        tag: peerTier.slug,
        placement: issueTarget.placement,
        // The groups it also needs (a Hysteria key's REALITY backup).
        extraPlacements: issueTarget.extraPlacements,
      },
      pinServerId: issueTarget.serverId,
      carrySubTokenFromId: privateDestination ? undefined : oldSub?._id,
      retireSubTokenFromId: privateDestination ? oldSub?._id : undefined,
    });

    // P1-6: tombstone the OLD subscription BEFORE flipping the tier. issueNew
    // already repointed currentSubscriptionId at the new key, so the old key is
    // scheduled for teardown first; if a later step dies, the worst case is the
    // user on the old tier with the new key live and the old key tombstoned —
    // never two indefinitely-live keys.
    let oldDeletedAt: number | null = null;
    if (oldSub) {
      const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId, carry.graceBaseUsedBytes);
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
      ...(await memberFacing(ctx, issued.subscriptionId, issued)),
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
      previousUrlRetired?: boolean;
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

/**
 * Switch the member's connection mode (transport) WITHIN the same backend.
 * URL-preserving switches prefer an in-place placement update and can fall
 * back to a reissue. By default a private destination gets a separate backend
 * identity so previously disclosed native, fronted and mirror URLs can never
 * serve its configuration. A member may explicitly retain unsealed links.
 */
export const switchMode = internalAction({
  args: {
    userId: v.id('users'),
    target: v.string(),
    keepUnsealedUrls: v.optional(v.boolean()),
    requestId: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { userId, target, keepUnsealedUrls, requestId },
  ): Promise<SwitchModeResult> => {
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
    // Refuse to switch INTO a mode an admin has turned off. publicConfig already
    // omits it from the picker, but that is presentation — this is the
    // server-authoritative guard (and the only one an API caller hits).
    // Deliberately one-way: the member's CURRENT mode is never re-validated here,
    // so someone stranded on a just-disabled mode can always switch AWAY.
    if (!chosen.enabled) {
      return {
        ok: false,
        code: 'validation',
        message: 'This connection mode is not available.',
        status: 400,
      };
    }
    // Refuse to switch to a mode that is not AVAILABLE on the member's backend:
    // not applicable there (backends[]), or unbound on a placement-capable
    // backend (issuing into it would mint a placement-less "dead" key AND we'd
    // have tombstoned the working key to do it). The picker also disables
    // unavailable modes; this is the server-authoritative guard. (WS1.)
    if (!chosen.availableBackends.includes(tier.backend)) {
      return {
        ok: false,
        code: 'validation',
        message: 'This connection mode is not available yet.',
        status: 400,
      };
    }

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });

    const retireUrls =
      !!oldSub &&
      requiresPrivateDelivery(chosen.deliveryStyle, chosen.family) &&
      keepUnsealedUrls !== true;

    // A placement-less backend (no placement capability) has nothing to move:
    // the switch is a PREFERENCE update, not a key operation. Record it and
    // leave the working subscription untouched — the old behavior fell through
    // to the re-issue saga and tombstoned a live key for zero functional
    // change. (A member with no key yet still falls through to the issue path.)
    if (oldSub && !retireUrls && !capabilitiesOf(tier.backend).placement) {
      await ctx.runMutation(internal.users.setConnectionMode, { userId, modeId: target });
      await ctx.runMutation(internal.audit.record, {
        actorType: 'member',
        actorId: userId,
        action: 'subscription.switch_mode',
        targetType: 'subscription',
        targetId: oldSub._id,
        payload: { fromMode: user.connectionModeId ?? null, toMode: target, inPlace: true },
        requestId,
      });
      return {
        ok: true,
        ...(await memberFacing(ctx, oldSub._id, oldSub)),
        mode: { id: chosen.id, label: chosen.label },
        oldSubscriptionDeletedAt: null,
      };
    }

    // Re-issue path (the historical behavior): mint a NEW key into the mode's
    // placement and tombstone the old one with 24h grace. A private switch
    // without URL retention always uses this path, as do first issuance and
    // switches where the current backend key cannot be updated in place.
    const reissue = async (): Promise<SwitchModeResult> => {
      const issueTarget = await resolveIssueTarget(
        ctx,
        tier.backend,
        target,
        user.preferredLocation ?? null,
        userId,
      );
      const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
      const carry = await carriedTrafficLimit(ctx, oldSub, tier, bonusGb);
      const issued = await issueNewSubscription(ctx, {
        periodCarryBytes: carry.periodCarryBytes,
        periodCarryUntil: carry.periodCarryUntil,
        userId,
        backend: tier.backend,
        spec: {
          username: boundedUsername('freesocks-', tier.slug, randomHex(8)),
          trafficLimitBytes: carry.trafficLimitBytes,
          trafficLimitStrategy: tier.trafficStrategy,
          expireAt: computeExpireAtIso(user.membershipExpiresAt),
          hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
          tag: tier.slug,
          placement: issueTarget.placement,
          // The groups it also needs (a Hysteria key's REALITY backup).
          extraPlacements: issueTarget.extraPlacements,
        },
        pinServerId: issueTarget.serverId,
        carrySubTokenFromId: retireUrls ? undefined : oldSub?._id,
        retireSubTokenFromId: retireUrls ? oldSub?._id : undefined,
      });
      // Tombstone the OLD key before recording the choice (issueNew already
      // repointed currentSubscriptionId), same 24h grace as regenerate/switch.
      let oldDeletedAt: number | null = null;
      if (oldSub) {
        const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId, carry.graceBaseUsedBytes);
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
        // Never a placement/mode group uuid — only which mode.
        payload: { fromMode: user.connectionModeId ?? null, toMode: target, inPlace: false },
        requestId,
      });
      return {
        ok: true,
        ...(await memberFacing(ctx, issued.subscriptionId, issued)),
        previousUrlRetired: retireUrls,
        mode: { id: chosen.id, label: chosen.label },
        oldSubscriptionDeletedAt:
          oldDeletedAt !== null ? new Date(oldDeletedAt).toISOString() : null,
      };
    };

    if (retireUrls) return reissue();

    // In-place switch (the common case): a member who already has a live Remnawave
    // key just moves it to the new mode's mode group via PATCH /api/users. The SAME
    // subscription row/URL/token, live traffic counter, and registered devices are
    // all preserved — no user churn in the backend and no separate "old key" to keep
    // alive for 24h. Only when the current key AND the tier are Remnawave.
    if (oldSub && capabilitiesOf(tier.backend).placement && oldSub.backend === tier.backend) {
      // The in-place PATCH lands on the key's OWN backend, so the new mode's
      // placement must exist there — a hard `onlyServerId` pin.
      const pinServerId = await resolveOwnPanel(ctx, oldSub, tier.backend);
      const {
        placement: nodePlacement,
        extraPlacements: nodeExtras,
        fallbackUnresolved,
      } = await ctx.runQuery(internal.connectionModes.resolveIssueTarget, {
        backend: tier.backend,
        modeId: target,
        onlyServerId: pinServerId as Id<'backendServers'> | null,
      });
      // A mode whose backup group is not bound on this backend never moves a
      // key in without it (lib/placementSet.ts); the re-issue path decides.
      if (fallbackUnresolved) return reissue();
      // null when no pool is bound anywhere OR the target mode has no mode group on
      // this key's backend; the re-issue path owns both (it may move backends and
      // owns the mode group-less-key audit), so fall through to it rather than PATCH
      // a mode group clear onto a live key. (The per-mode unbound case was rejected
      // above.)
      if (nodePlacement !== null) {
        // Persist BEFORE the backend PATCH (Review D-#6): a concurrent
        // pushTierToBackend reads the PERSISTED placement — with DB-first, a
        // push landing mid-switch re-sends the NEW placement (exactly what the
        // PATCH is about to do), so backend and DB stay convergent. The old
        // order (PATCH → persist) let such a push silently revert the mode group
        // move while the DB recorded it. On PATCH failure we restore the old
        // persisted placement so the DB never claims a move that didn't happen.
        // The WHOLE set moves: switching to Hysteria brings its REALITY backup
        // group, switching away leaves only the target mode's own groups.
        await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
          subscriptionId: oldSub._id,
          placement: nodePlacement,
          extraPlacements: nodeExtras,
        });
        try {
          await ctx.runAction(internal.backends.updateUser, {
            backend: tier.backend,
            backendUserId: oldSub.backendUserId,
            patch: { placementSet: { primary: nodePlacement, extras: nodeExtras } },
          });
        } catch (e) {
          console.warn('[switchMode] in-place placement update failed; re-issuing', e);
          // Restored as it was, both halves together.
          const was = placementSetOf(oldSub);
          await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
            subscriptionId: oldSub._id,
            placement: was.primary,
            extraPlacements: was.extras,
          });
          return reissue();
        }
        // The backend serves the new mode now: the same token must stop handing
        // out the old one at once (bodies, pin, render snapshot, mirrors),
        // including what a fetch in flight across the PATCH stored meanwhile.
        await ctx.runMutation(internal.subscriptions.placementApplied, {
          subscriptionId: oldSub._id,
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
          targetId: oldSub._id,
          // Never a placement/mode group uuid — only which mode + that it was in place.
          payload: { fromMode: user.connectionModeId ?? null, toMode: target, inPlace: true },
          requestId,
        });
        return {
          ok: true,
          // Same key: the member's saved fronted URL keeps working, now homed to
          // the new node. No tombstone → nothing is deleted.
          ...(await memberFacing(ctx, oldSub._id, oldSub)),
          mode: { id: chosen.id, label: chosen.label },
          oldSubscriptionDeletedAt: null,
        };
      }
    }
    return reissue();
  },
});

type SwitchServerResult =
  | {
      ok: true;
      subscriptionUrl: string;
      shortUuid: string;
      /** True when the key stayed put and only its server moved — the member's
       *  URL, traffic counter and devices all survive. */
      inPlace: boolean;
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

/**
 * Move the member's key to a DIFFERENT server, keeping their connection mode.
 * The escape hatch for a node that is slow or locally blocked: before this, the
 * only way off a node was switching modes (which changes the transport too) or
 * regenerating (which rotates the saved URL).
 *
 * Three levers, cheapest first, because they move different things:
 *  1. a different mode group on the key's OWN backend — an in-place PATCH, nothing else
 *     changes;
 *  2. the node pin — when one mode group spans several nodes, this is the ONLY thing
 *     that decides which node a member gets, so it is always rotated;
 *  3. a re-issue — the only way to reach another backend (the backend owns the user
 *     record), used when (1) is impossible or its PATCH failed. Carries the sub
 *     token, so even here the member's saved URL does not change.
 *
 * `reason` is a bounded enum chosen by the member, recorded so an operator can
 * see WHICH nodes people are leaving and why.
 *
 * The lever conditions live in lib/switchServer.ts, shared with
 * `switchServerAvailable` below, which the account view projects so the SPA
 * only offers the button when one of them can fire.
 */
export const switchServerAvailable = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<boolean> => {
    const user = await ctx.db.get(userId);
    const tier = user ? await ctx.db.get(user.tierId) : null;
    if (!user || !tier) return false;
    const sub = await currentOrActiveSub(ctx.db, user);
    return switchServerAvailableIn(ctx.db, user, tier, sub, Date.now());
  },
});

export const switchServer = internalAction({
  args: {
    userId: v.id('users'),
    reason: v.string(),
    // Consented, member-editable network context + what the CDN edge detected —
    // both pre-sanitized by the HTTP layer (lib/issueTelemetry). Recorded ONLY
    // into the unlinked issueReports table, never the per-user audit trail.
    telemetry: v.optional(
      v.object({
        country: v.union(v.string(), v.null()),
        city: v.union(v.string(), v.null()),
        asn: v.union(v.number(), v.null()),
      }),
    ),
    detected: v.optional(
      v.object({
        country: v.union(v.string(), v.null()),
        city: v.union(v.string(), v.null()),
        asn: v.union(v.number(), v.null()),
      }),
    ),
    requestId: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { userId, reason, telemetry, detected, requestId },
  ): Promise<SwitchServerResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };

    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!oldSub) {
      return {
        ok: false,
        code: 'server.no_subscription',
        message: 'You have no active key to move.',
        status: 409,
      };
    }

    // A backend with neither lever (Outline: no placement, no node pinning) can
    // never move a key. Say so distinctly instead of falling through to
    // `server.no_alternative`, which invites a pointless retry — nothing about
    // this deployment will make it work later. The SPA hides the control on the
    // same capability; this is the server-authoritative half.
    const subCaps = capabilitiesOf(oldSub.backend);
    if (!subCaps.placement && !subCaps.nodePinning) {
      return {
        ok: false,
        code: 'server.unsupported',
        message: 'Switching servers is not available for this key.',
        status: 409,
      };
    }

    const modeId = user.connectionModeId ?? null;
    // Two DIFFERENT backends are in play, and the split matters (see the
    // tier-vs-subscription rule in docs/backends.md): a placement move resolves
    // a pool for the TIER's backend and either PATCHes or re-issues into it, so
    // it is only coherent while the live key is already on that backend. A pin
    // rotation touches nothing but the member's own key, so it follows the
    // SUBSCRIPTION's backend — otherwise flipping a tier to Outline would strand
    // every retained Remnawave key on its node, unable to move at all, even
    // though rotating its pin is entirely safe and local.
    const canPlaceBackend =
      capabilitiesOf(tier.backend).placement && oldSub.backend === tier.backend;
    const canPinBackend = capabilitiesOf(oldSub.backend).nodePinning;
    // Is the member's stored mode still usable here? `resolvePlacementPool` falls
    // back across modes (own pool → default → any bound), which is right at
    // ISSUANCE but wrong here: a placement move would silently re-home the key
    // into ANOTHER mode's mode group while connectionModeId and the whole UI still say
    // the original. On a privacy mode that quietly swaps the transport the member
    // deliberately chose. regenerate and switch-backend already refuse in this
    // state; so does this. The node-pin rotation below stays available — it moves
    // inside the current mode group and cannot change the transport.
    const modeBlocked =
      canPlaceBackend && (await isEffectiveModeBlocked(ctx, tier.backend, modeId));
    const privateMoveBlocked =
      canPlaceBackend &&
      !modeBlocked &&
      !(await canMoveWithExistingUrls(ctx, tier.backend, modeId, oldSub.backendPlacement));
    const canPlace = canPlaceBackend && !modeBlocked && !privateMoveBlocked;
    // The backend this key actually lives on. Resolved once: the in-place lever
    // pins to it, and the cross-backend probe compares against it to tell a real
    // relocation from a same-backend shuffle.
    const ownPanelId = canPlaceBackend ? await resolveOwnPanel(ctx, oldSub, tier.backend) : null;
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});

    // An in-place move can contribute diagnostics because it emits no identified
    // audit. Reissues below have their own operational and recovery audit trail.
    const recordInPlaceDiagnostics = async (fromNode: string | null) => {
      const server = oldSub.backendServerId
        ? await ctx.runQuery(internal.backendServers.getById, { id: oldSub.backendServerId })
        : null;
      await ctx.runMutation(internal.issueReports.record, {
        auditIsolated: true,
        kind: 'switch',
        reason,
        backend: oldSub.backend,
        locationCode: server?.location ?? fromNode,
        nodeLabel: fromNode,
        connectionModeId: modeId,
        country: telemetry?.country ?? null,
        city: telemetry?.city ?? null,
        asn: telemetry?.asn ?? null,
        detectedCountry: detected?.country ?? null,
        detectedCity: detected?.city ?? null,
        detectedAsn: detected?.asn ?? null,
      });
    };

    // Where a re-issue would land: the mode's pool with NO backend pin, so it can
    // cross to another backend/location — the only lever that can, since a backend
    // owns its user records. Separate from `reissue` itself so the caller can ask
    // "is there anywhere else to go?" WITHOUT minting a key to find out.
    const resolveCrossPanelTarget = async () => {
      if (!canPlace)
        return {
          placement: null,
          serverId: null,
          unattributedMultiPanel: false,
          extraPlacements: [] as string[],
          fallbackUnresolved: false,
        };
      const rand = new Uint32Array(1);
      crypto.getRandomValues(rand);
      // A member on Automatic who chose a country: its exit locations first.
      const exitLocations = user.preferredLocation
        ? []
        : await ctx.runQuery(internal.countryExits.forIssue, {
            userId,
            backend: tier.backend,
            modeId,
          });
      return ctx.runQuery(internal.connectionModes.resolveIssueTarget, {
        backend: tier.backend,
        modeId,
        location: user.preferredLocation ?? null,
        ...(exitLocations.length > 0 ? { exitLocations } : {}),
        excludePlacement: oldSub.backendPlacement ?? null,
        rand: rand[0]! / 2 ** 32,
      });
    };

    // (3) Re-issue: a new key in the SAME mode, excluding the placement the
    // member is leaving, unpinned so it may land on another backend/location.
    // `pre` is a target already resolved by the caller (the cross-backend probe);
    // the PATCH-failure path passes nothing and resolves fresh.
    const reissue = async (
      pre?: Awaited<ReturnType<typeof resolveCrossPanelTarget>>,
    ): Promise<SwitchServerResult> => {
      const target = pre ?? (await resolveCrossPanelTarget());
      if (target.unattributedMultiPanel) {
        return {
          ok: false,
          code: 'backend.placement_unresolved',
          message: 'Node placement is still resolving. Please try again in a few minutes.',
          status: 503,
        };
      }
      // The mode's backup group is not bound where the key would land: never a
      // key without it (lib/placementSet.ts).
      if (target.fallbackUnresolved) {
        return {
          ok: false,
          code: 'mode.fallback_unbound',
          message: 'This connection mode is not available on another server right now.',
          status: 409,
        };
      }
      const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
      const carry = await carriedTrafficLimit(ctx, oldSub, tier, bonusGb);
      const issued = await issueNewSubscription(ctx, {
        periodCarryBytes: carry.periodCarryBytes,
        periodCarryUntil: carry.periodCarryUntil,
        userId,
        backend: tier.backend,
        spec: {
          username: boundedUsername('freesocks-', tier.slug, randomHex(8)),
          trafficLimitBytes: carry.trafficLimitBytes,
          trafficLimitStrategy: tier.trafficStrategy,
          expireAt: computeExpireAtIso(user.membershipExpiresAt),
          hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
          tag: tier.slug,
          placement: target.placement,
          // The groups it also needs (a Hysteria key's REALITY backup).
          extraPlacements: target.extraPlacements,
        },
        pinServerId: (target.serverId as Id<'backendServers'> | null) ?? undefined,
        // Land on a different node than the one being left, for the same reason
        // regenerate does — the mode group may span nodes.
        excludeNode: oldSub.pinnedNode ?? undefined,
        // Moving servers is not a rotation: the member keeps their saved link.
        carrySubTokenFromId: oldSub._id,
      });
      const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId, carry.graceBaseUsedBytes);
      await auditIfPlacementless(ctx, {
        backend: tier.backend,
        placement: target.placement,
        userId,
        subscriptionId: issued.subscriptionId,
        requestedMode: modeId,
        requestId,
      });
      if (tier.isDefaultFree) {
        await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
      }
      await ctx.runMutation(internal.audit.record, {
        actorType: 'member',
        actorId: userId,
        action: 'subscription.switch_server',
        targetType: 'subscription',
        targetId: issued.subscriptionId,
        payload: {
          inPlace: false,
          movedPlacement: target.placement !== (oldSub.backendPlacement ?? null),
          movedNodePin: true,
        },
        requestId,
      });
      return {
        ok: true,
        ...(await memberFacing(ctx, issued.subscriptionId, issued)),
        inPlace: false,
        oldSubscriptionDeletedAt: tomb ? new Date(tomb.deletedAt).toISOString() : null,
      };
    };

    // (1) A different mode group on this key's own backend.
    if (canPlace) {
      const pinServerId = ownPanelId;
      const rand = new Uint32Array(1);
      crypto.getRandomValues(rand);
      const { placement, extraPlacements, fallbackUnresolved } = await ctx.runQuery(
        internal.connectionModes.resolveIssueTarget,
        {
          backend: tier.backend,
          modeId,
          onlyServerId: pinServerId as Id<'backendServers'> | null,
          excludePlacement: oldSub.backendPlacement ?? null,
          rand: rand[0]! / 2 ** 32,
        },
      );
      // A legacy row (issued before placements were persisted — a state
      // lifecycle.legacyPushPlacement still supports) has NO source placement to
      // compare against, so "different from null" proves nothing: the key may
      // already sit in the very mode group we resolved, making the PATCH a no-op that
      // we would report as a move. Require a KNOWN source that actually differs.
      // The unknown case still falls through to the pin rotation and the
      // cross-backend re-issue, both of which prove a move on their own terms.
      const sourcePlacement = oldSub.backendPlacement ?? null;
      if (!fallbackUnresolved && inPlaceMoveProven(sourcePlacement, placement)) {
        // DB before backend, as in switchMode: a concurrent pushTierToBackend
        // re-sends the PERSISTED placement, so this ordering keeps the two
        // convergent. Restore on failure so the DB never claims a move that
        // didn't happen. The whole set moves (lib/placementSet.ts).
        await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
          subscriptionId: oldSub._id,
          placement,
          extraPlacements,
        });
        try {
          await ctx.runAction(internal.backends.updateUser, {
            backend: tier.backend,
            backendUserId: oldSub.backendUserId,
            patch: { placementSet: { primary: placement, extras: extraPlacements } },
          });
        } catch (e) {
          console.warn('[switchServer] in-place placement update failed; re-issuing', e);
          const was = placementSetOf(oldSub);
          await ctx.runMutation(internal.subscriptions.setPlacementAndClearCache, {
            subscriptionId: oldSub._id,
            placement: was.primary,
            extraPlacements: was.extras,
          });
          return reissue();
        }
        // (2) also rotate the pin: the new mode group may still serve several
        // nodes. With it goes everything stored from the old group, a fetch in
        // flight across the PATCH included (subscriptions.placementApplied).
        const leftNode = await ctx.runMutation(internal.subscriptions.placementApplied, {
          subscriptionId: oldSub._id,
          rotatePin: true,
        });
        await recordInPlaceDiagnostics(leftNode);
        return {
          ok: true,
          ...(await memberFacing(ctx, oldSub._id, oldSub)),
          inPlace: true,
          oldSubscriptionDeletedAt: null,
        };
      }
    }

    // (2) alone: no other mode group to move to, but the key may be pinned to one node
    // of a MULTI-node mode group, where rotating the pin genuinely changes the server.
    //
    // "Multi-node" is load-bearing, not decoration: pinSubscriptionToNode refuses
    // to pin a single-node list at all, and pickNode DROPS the exclusion rather
    // than empty the pool (lib/nodePinning.ts). So on a one-node mode group the next
    // fetch serves the very same node while we'd have told the member their key
    // moved. Only claim the move when the cached stats prove another node exists;
    // an unknown count (no stats row yet — bring-up, or a placement the
    // healthcheck cron hasn't observed) counts as unproven, which reads as
    // "try again later" and self-heals on the next cron pass.
    // The snapshot must also be FRESH. A mode group that has since shrunk to one node
    // would still read >1 from a stale row, putting us right back to claiming a
    // move that cannot happen — so apply the same staleness bar pickByNodeLoad
    // uses for its own load decisions.
    // Deliberately `canPinBackend`, not `canPlace`: rotating the pin stays
    // available to a member whose mode an admin just unbound, or whose tier was
    // flipped to another backend, because it moves WITHIN their current mode group —
    // it cannot change their transport and needs nothing from the tier.
    const placementStats =
      canPinBackend && oldSub.backendPlacement
        ? await ctx.runQuery(internal.remnawaveNodes.getPlacementStats, {
            placement: oldSub.backendPlacement,
          })
        : null;
    // A key in two groups pins only among its mode's tier (lib/extraModeNodes.ts):
    // the group's count overstates where its pin can go.
    const otherTargets =
      canPinBackend && placementStats
        ? await ctx.runQuery(internal.subscriptions.otherPinTargets, {
            subscriptionId: oldSub._id,
          })
        : null;
    const hasOtherNode = groupHasOtherNode(placementStats, Date.now(), otherTargets);
    const leftNode = hasOtherNode
      ? await ctx.runMutation(internal.subscriptions.rotateNodePin, {
          subscriptionId: oldSub._id,
        })
      : null;
    if (leftNode !== null) {
      await recordInPlaceDiagnostics(leftNode);
      return {
        ok: true,
        ...(await memberFacing(ctx, oldSub._id, oldSub)),
        inPlace: true,
        oldSubscriptionDeletedAt: null,
      };
    }

    // (3) Cross-backend re-issue. Both cheap levers are exhausted, but the mode's
    // pool may still hold a placement on ANOTHER backend — the same-backend lookup
    // above deliberately hides those (`onlyServerId` is a hard pin), so without
    // this probe a member on a one-mode group, one-node backend could never leave it
    // even with a whole other location bound. Probe before committing: reissue
    // mints a key and tombstones the old one, which is far too much to spend
    // landing back where we started.
    const crossPanel = await resolveCrossPanelTarget();
    const knownSource = oldSub.backendPlacement ?? null;
    // With a KNOWN current mode group, a different resolved mode group is proof enough.
    // With an UNKNOWN one (a legacy row) it is not: `excludePlacement` was null,
    // so the pick can be the very mode group the key already sits in, and on a
    // one-mode group/one-node pool the re-issue would then tombstone a working key,
    // re-register the member's devices and land them on the same server — while
    // reporting success. A different PANEL is the one thing that still proves a
    // move without knowing the mode group: a key created on backend B is by definition
    // not on backend A. (Such a row can also recover a recorded placement via
    // regenerate, after which its switches are provable the normal way.)
    if (
      crossPanel.unattributedMultiPanel ||
      crossPanelMoveProven(knownSource, crossPanel, ownPanelId)
    ) {
      return reissue(crossPanel);
    }

    if (privateMoveBlocked) return PRIVATE_MOVE_REQUIRES_NEW_KEY;

    // The pin was the only lever left and it wasn't available: if placement moves
    // were the thing we withheld, say WHY, so the member is pointed at picking an
    // available mode rather than at a retry that will keep failing.
    if (modeBlocked) {
      return {
        ok: false,
        code: 'mode.unavailable',
        message: MODE_UNAVAILABLE_MESSAGE,
        status: 400,
      };
    }

    // Nothing to move: a single-mode group, single-node deployment, a key that has
    // never been served (so there is no pin yet), or a node count we can't prove.
    // Change nothing and say so — tombstoning a working key to land back on the
    // same server helps no one, and neither does claiming a move that didn't
    // happen.
    return {
      ok: false,
      code: 'server.no_alternative',
      message: 'There is no other server available right now. Please try again later.',
      status: 409,
    };
  },
});

/**
 * The account page's one-time move (docs/edges.md "Exit location by country"):
 * a member on Automatic whose own country choice has an exit location, while
 * their key is somewhere else (`countryExits.memberExit`), has the key
 * re-issued there ONCE. The location is not saved as their pick, so they stay
 * on Automatic; like a server switch, their link, their country and their
 * mirrors carry over. Refused, minting nothing, when nothing is offered or the
 * offered location cannot take the key now.
 */
export const moveToCountryExit = internalAction({
  args: { userId: v.id('users'), requestId: v.optional(v.string()) },
  handler: async (ctx, { userId, requestId }): Promise<SwitchServerResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    const nothing: SwitchServerResult = {
      ok: false,
      code: 'exit.none',
      message: 'There is no better location for this key right now.',
      status: 409,
    };
    if (!oldSub || oldSub.backend !== tier.backend || !capabilitiesOf(tier.backend).placement)
      return nothing;
    const modeId = user.connectionModeId ?? null;
    if (!(await canMoveWithExistingUrls(ctx, tier.backend, modeId, oldSub.backendPlacement)))
      return PRIVATE_MOVE_REQUIRES_NEW_KEY;
    const offer = await ctx.runQuery(internal.countryExits.memberExit, { userId });
    if (!offer) return nothing;
    if (await isEffectiveModeBlocked(ctx, tier.backend, modeId)) {
      return {
        ok: false,
        code: 'mode.unavailable',
        message: MODE_UNAVAILABLE_MESSAGE,
        status: 400,
      };
    }
    const rand = new Uint32Array(1);
    crypto.getRandomValues(rand);
    const target = await ctx.runQuery(internal.connectionModes.resolveIssueTarget, {
      backend: tier.backend,
      modeId,
      location: offer.code,
      rand: rand[0]! / 2 ** 32,
    });
    if (target.unattributedMultiPanel) {
      return {
        ok: false,
        code: 'backend.placement_unresolved',
        message: 'Node placement is still resolving. Please try again in a few minutes.',
        status: 503,
      };
    }
    // The narrowing is soft: a key the offered location cannot take now stays put.
    const server = target.serverId
      ? await ctx.runQuery(internal.backendServers.getById, {
          id: target.serverId as Id<'backendServers'>,
        })
      : null;
    if (!target.placement || server?.location !== offer.code) return nothing;
    // A mode whose backup group is not bound there: never a key without it.
    if (target.fallbackUnresolved) return nothing;
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const bonusGb = await ctx.runQuery(internal.donations.currentBonusGb, {});
    const carry = await carriedTrafficLimit(ctx, oldSub, tier, bonusGb);
    const issued = await issueNewSubscription(ctx, {
      periodCarryBytes: carry.periodCarryBytes,
      periodCarryUntil: carry.periodCarryUntil,
      userId,
      backend: tier.backend,
      spec: {
        username: boundedUsername('freesocks-', tier.slug, randomHex(8)),
        trafficLimitBytes: carry.trafficLimitBytes,
        trafficLimitStrategy: tier.trafficStrategy,
        expireAt: computeExpireAtIso(user.membershipExpiresAt),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
        tag: tier.slug,
        placement: target.placement,
        // The groups it also needs (a Hysteria key's REALITY backup).
        extraPlacements: target.extraPlacements,
      },
      pinServerId: target.serverId as Id<'backendServers'>,
      excludeNode: oldSub.pinnedNode ?? undefined,
      // A move, not a rotation: the member keeps their saved link.
      carrySubTokenFromId: oldSub._id,
    });
    const tomb = await tombstoneOldSub(ctx, oldSub.backendUserId, carry.graceBaseUsedBytes);
    if (tier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
    }
    // Neither the country nor the location: the key's own server says where it went.
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.move_location',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      requestId,
    });
    return {
      ok: true,
      ...(await memberFacing(ctx, issued.subscriptionId, issued)),
      inPlace: false,
      oldSubscriptionDeletedAt: tomb ? new Date(tomb.deletedAt).toISOString() : null,
    };
  },
});

type RevokeDeviceResult =
  { ok: true } | { ok: false; code: string; message: string; status: number };

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
    if (!capabilitiesOf(sub.backend).deviceManagement) {
      return {
        ok: false,
        code: 'devices.unsupported',
        message: 'This backend does not support device management',
        status: 409,
      };
    }

    // Backend failures (a RemnawaveApiError carries a backend-body slice) must be
    // mapped to a generic result HERE — otherwise they escape the route and
    // surface as a runtime 500 with backend text attached (every other member
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
