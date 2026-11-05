/**
 * Backend instance pool: the DB-touching half of the backend system, generalized
 * from the former outlineServers.ts so EVERY backend type (Remnawave, Outline,
 * ...) is selected from the same registry. These are INTERNAL functions: the
 * rows carry the secret `config`, so they must never be exposed via a public
 * query. The dispatch action (convex/backends.ts) calls them, does the HTTP via
 * the provider registry (convex/lib/backends/registry.ts), and (issuance) the
 * random pick (CSPRNG can't live in a query).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { runWithCronOutcome } from './cronHeartbeat';
import { ConvexError, v } from 'convex/values';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { writeAuditLog } from './lib/audit';
import { claimKey } from './lib/backend/ops';
import { panelDigestKey } from './lib/backend/key';
import { capabilitiesOf } from './lib/backends/capabilities';
import { resolveServerConfig } from './lib/serverConfig';
import type { Id } from './_generated/dataModel';
import type { BackendConfig, RemnawaveServerConfig } from './lib/backends/registry';
import { PROVIDERS } from './lib/backends/registry';
import { observeInstance } from './backendObserve';
import { inventoryRows } from './backendNodes';
import {
  remnawaveFleetStats,
  remnawaveMajorVersion,
  remnawaveResolveUserIdByShortUuid,
} from './lib/backends/remnawave';
import { isNumericBackendUserId, scopedServerId, toStoredBackendUserId } from './lib/backendUserId';
import { resolveLocations } from './lib/locations';
import { backendIdValidator } from './lib/backendIds';

const backendId = backendIdValidator;

const DEFAULT_LATENCY_WEIGHT = 1;
const DEFAULT_KEY_COUNT_WEIGHT = 100;

/** Scoring weights (admin-tunable via appSettings; JSON-encoded numbers). */
async function scoringWeights(ctx: QueryCtx): Promise<{ latency: number; keyCount: number }> {
  const read = async (key: string, def: number): Promise<number> => {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    const n = row ? Number(row.value) : NaN;
    return Number.isFinite(n) ? n : def;
  };
  return {
    latency: await read('backend.scoring.latency_weight', DEFAULT_LATENCY_WEIGHT),
    keyCount: await read('backend.scoring.key_count_weight', DEFAULT_KEY_COUNT_WEIGHT),
  };
}

/**
 * Top-N scored active instances of a given backend type for new-key issuance
 * (lower score wins). The action picks one at random among them. Score =
 * latency_weight * lastHealthRttMs + key_count_weight * keyCount, then admin
 * `priority` as a tiebreak. An instance we have NEVER successfully probed sorts
 * after every probed one (we have no evidence it works), so it can't win the pool
 * on a phantom rtt of 0 — only relevant in the no-fresh-instances fallback below,
 * since the `fresh` set is already probed-by-definition.
 */
export const pickCandidatesForIssue = internalQuery({
  args: {
    backend: backendId,
    poolIds: v.optional(v.array(v.id('backendServers'))),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { backend, poolIds, limit }) => {
    let candidates = await ctx.db
      .query('backendServers')
      .withIndex('by_backend_active', (q) => q.eq('backend', backend).eq('isActive', true))
      .collect();
    if (poolIds && poolIds.length > 0) {
      const allow = new Set<string>(poolIds);
      candidates = candidates.filter((s) => allow.has(s._id));
    }
    // Hard capacity cap: an at-capacity instance is out of the running entirely
    // (before the fresh/fallback split, so being "the only fresh one" can't
    // resurrect it). All-at-capacity → [] → the caller's backend.unavailable.
    candidates = candidates.filter((s) => s.maxKeys == null || s.keyCount < s.maxKeys);
    if (candidates.length === 0) return [];
    // Prefer instances healthy within ~30 min; fall back to all if none qualify.
    const now = Date.now();
    const fresh = candidates.filter(
      (s) => s.lastHealthOkAt != null && now - s.lastHealthOkAt < 30 * 60_000,
    );
    const usable = fresh.length > 0 ? fresh : candidates;
    const w = await scoringWeights(ctx);
    return usable
      .map((s) => ({
        s,
        // Probed-ness is the PRIMARY sort key: an instance with no successful
        // healthcheck yet (lastHealthRttMs == null) is less trustworthy than any
        // probed one and must sort last, not score as rtt=0 ("fastest"). In the
        // common `fresh` path every instance is probed, so this is a no-op there.
        probed: s.lastHealthRttMs != null,
        score: w.latency * (s.lastHealthRttMs ?? 0) + w.keyCount * s.keyCount,
      }))
      .sort(
        (a, b) =>
          Number(b.probed) - Number(a.probed) || a.score - b.score || a.s.priority - b.s.priority,
      )
      .slice(0, limit ?? 3)
      .map((x) => x.s);
  },
});

export const getById = internalQuery({
  args: { id: v.id('backendServers') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/**
 * Resolve which instance hosts a given key. The instance the caller names wins
 * (a key with no subscription row: the origin's qualification account, a
 * temporary test key, the issuance compensation); then the key's subscription
 * row; then the instance its scoped id names (lib/backendUserId.ts). A named
 * instance that disagrees with the id's own scope resolves to nothing: the
 * bare integer on another instance is a different user. Null = not
 * resolvable; the dispatch refuses rather than guess (backends.ts).
 */
export const resolveKeyServer = internalQuery({
  args: { backendUserId: v.string(), backendServerId: v.optional(v.id('backendServers')) },
  handler: async (ctx, { backendUserId, backendServerId }) => {
    const scope = scopedServerId(backendUserId);
    if (backendServerId) {
      if (scope !== null && scope !== (backendServerId as string)) return null;
      return ctx.db.get(backendServerId);
    }
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique();
    if (sub?.backendServerId) return ctx.db.get(sub.backendServerId);
    const scoped = scope === null ? null : ctx.db.normalizeId('backendServers', scope);
    return scoped ? ctx.db.get(scoped) : null;
  },
});

/** Keep the per-instance key count fresh between healthchecks (pool load-scoring). */
export const bumpKeyCount = internalMutation({
  args: { id: v.id('backendServers'), delta: v.optional(v.number()) },
  handler: async (ctx, { id, delta }) => {
    const s = await ctx.db.get(id);
    if (!s) return null;
    await ctx.db.patch(id, {
      keyCount: Math.max(0, s.keyCount + (delta ?? 1)),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** All active instances WITH their secret config; internal-only (the cron pings them). */
export const listActiveWithSecret = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await ctx.db.query('backendServers').collect()).filter((s) => s.isActive),
});

/**
 * The member-facing node-location catalog (see lib/locations.ts). Non-secret
 * (code + display label + online bit only) — projected via publicConfig and
 * used to validate a member's location pick at the HTTP boundary.
 */
export const listLocations = internalQuery({
  args: {},
  handler: (ctx) => resolveLocations(ctx.db),
});

/**
 * On-demand node-stats pull for ONE instance (the member node-status endpoint's
 * freshness refresh — the same pull the healthcheck cron does every 10 min).
 * Best-effort: false on any failure, keeping the last snapshot. Callers gate it
 * behind `remnawaveNodes.claimStatsRefresh` so a burst of members polling can't
 * stampede the backend.
 */
export const refreshNodeStats = internalAction({
  args: { id: v.id('backendServers') },
  handler: async (ctx, { id }): Promise<boolean> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id });
    if (!server || !server.isActive) return false;
    const provider = PROVIDERS[server.backend];
    if (!provider.getNodeStats) return false;
    try {
      const nodes = await provider.getNodeStats(server.config as BackendConfig);
      if (nodes.length > 0) {
        await ctx.runMutation(internal.remnawaveNodes.markNodeStats, {
          backendServerId: id,
          nodes,
        });
      }
      return true;
    } catch {
      return false; // backend unreachable: the cached snapshot stays authoritative
    }
  },
});

/**
 * Stamp an instance healthy: refresh lastHealthOkAt + rtt, and (when the backend
 * reports an authoritative count, i.e. Outline) the key count. A null keyCount
 * (Remnawave) leaves the bumped estimate alone.
 */
export const markHealthy = internalMutation({
  args: {
    id: v.id('backendServers'),
    keyCount: v.union(v.number(), v.null()),
    rttMs: v.number(),
  },
  handler: async (ctx, { id, keyCount, rttMs }) => {
    const fields: {
      lastHealthOkAt: number;
      lastHealthRttMs: number;
      updatedAt: number;
      keyCount?: number;
    } = {
      lastHealthOkAt: Date.now(),
      lastHealthRttMs: rttMs,
      updatedAt: Date.now(),
    };
    if (keyCount != null) fields.keyCount = keyCount;
    await ctx.db.patch(id, fields);
    return null;
  },
});

/** Cache the latest read-only fleet stats on the instance row (for the admin
 *  dashboard). Stamped by the healthcheck cron; best-effort, so it's only called
 *  when a fetch succeeded — a failed fetch leaves the last values in place. */
export const markFleetStats = internalMutation({
  args: {
    id: v.id('backendServers'),
    fleetStats: v.object({
      onlineNow: v.number(),
      nodesOnline: v.number(),
      nodesTotal: v.number(),
      distinctCountries: v.number(),
      monthTrafficBytes: v.number(),
      lifetimeTrafficBytes: v.number(),
      panelVersion: v.string(),
    }),
  },
  handler: async (ctx, { id, fleetStats }) => {
    await ctx.db.patch(id, { fleetStats, fleetStatsAt: Date.now(), updatedAt: Date.now() });
    return null;
  },
});

// Node-load telemetry (feeds issuance-time node placement) lives in the
// Remnawave-namespaced module convex/remnawaveNodes.ts (markNodeStats /
// listNodeStats). The healthcheck cron below stamps it via provider.getNodeStats.

/**
 * Cron: ping each active instance through its provider's health probe. On
 * success, stamp lastHealthOkAt (which keeps it in pickCandidatesForIssue's
 * 30-min "fresh" set) + rtt (+ key count for backends that report one). A failing
 * instance is NOT deactivated; it ages out of the fresh window and is
 * deprioritized, with all-instances fallback preserved, so a transient blip
 * can't take a backend's whole pool offline. Never logs the secret config.
 */
export const healthcheck = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; healthy: number }> =>
    runWithCronOutcome(ctx, 'backend-healthcheck', async () => {
      const servers = await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
      const observe = await ctx.runQuery(internal.serverAdmin.observeEnabled, {});
      let healthy = 0;
      for (const s of servers) {
        try {
          const provider = PROVIDERS[s.backend];
          const { keyCount, rttMs } = await provider.health(s.config as BackendConfig);
          await ctx.runMutation(internal.backendServers.markHealthy, {
            id: s._id,
            keyCount,
            rttMs,
          });
          healthy++;
          // Best-effort fleet observability (read-only) — a failure here must NOT
          // mark the instance unhealthy, so it's caught on its own and just skips.
          if (provider.getFleetStats) {
            try {
              const fleetStats = await provider.getFleetStats(s.config as BackendConfig);
              await ctx.runMutation(internal.backendServers.markFleetStats, {
                id: s._id,
                fleetStats,
              });
            } catch {
              /* fleet stats unavailable this cycle; last stamped values are kept */
            }
          }
          // Best-effort per-node load for issuance-time node placement — same
          // isolation as fleet stats: a failure keeps the last snapshot and
          // must NOT mark the instance unhealthy.
          if (provider.getNodeStats) {
            try {
              const nodes = await provider.getNodeStats(s.config as BackendConfig);
              if (nodes.length > 0) {
                await ctx.runMutation(internal.remnawaveNodes.markNodeStats, {
                  backendServerId: s._id,
                  nodes,
                });
              }
            } catch {
              /* node stats unavailable this cycle; picker falls back gracefully */
            }
          }
          // Best-effort per-NODE inventory for the origin block detector + the
          // origin picker (same isolation: never marks the instance unhealthy).
          if (provider.getNodeInventory) {
            try {
              const nodes = await provider.getNodeInventory(s.config as BackendConfig);
              await ctx.runMutation(internal.backendNodes.markNodeInventory, {
                backendServerId: s._id,
                nodes: inventoryRows(nodes),
              });
            } catch {
              /* inventory unavailable this cycle; the detector reads stale/unknown */
            }
          }
          // Best-effort backend observation for server management (read-only, and
          // only when an operator turned it on): the same isolation again.
          if (observe && provider.observePanel) await observeInstance(ctx, s);
        } catch {
          /* unhealthy: ages out of the fresh window; secret config never logged */
        }
      }
      return { checked: servers.length, healthy };
    }),
});

// --- Node logging privacy (docs/privacy.md §5) ------------------------------------------------

/** One instance's row of a logging-privacy run (the `RemnawaveLoggingReport` contract). */
interface LoggingInstanceReport {
  serverId: string;
  name: string;
  ok: boolean;
  error?: string;
  profiles: Array<{
    uuid: string;
    name: string;
    hardened: boolean;
    changed: boolean;
    error?: string;
  }>;
}

/** An instance's row plus how the run treated it. `wrote`: the run was allowed
 *  to write there (false for a dry run, and for an instance the automatic run
 *  only read because a server change holds it, `busy`). */
interface LoggingRunRow {
  instance: LoggingInstanceReport;
  wrote: boolean;
  busy: boolean;
}

/**
 * Whether a server change (an op of the backend-write ledger, convex/backendLedger.ts)
 * holds a config profile or a node on this backend right now. A profile write
 * replaces the config wholesale and restarts the profile's nodes, so the ledger's
 * own profile writes claim `profile:<uuid>` AND every `node:<uuid>` under it; the
 * automatic logging run respects the same claims and leaves such a backend alone
 * until the next run. Two indexed range reads, one row each at most. A backend
 * FCP does not manage never has claims, so this is always false there.
 */
export const serverChangeRunning = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }): Promise<boolean> => {
    for (const prefix of [claimKey.profile(''), claimKey.node('')]) {
      // Every key starting with `<kind>:` sorts in [`<kind>:`, `<kind>;`).
      const upper = `${prefix.slice(0, -1)};`;
      const held = await ctx.db
        .query('panelClaims')
        .withIndex('by_server_key', (q) =>
          q.eq('backendServerId', backendServerId).gte('key', prefix).lt('key', upper),
        )
        .first();
      if (held) return true;
    }
    return false;
  },
});

/**
 * Whether a backend's logging write goes through the backend-write ledger:
 * server changes are on and FCP has set the backend up (`assertWritable`'s
 * gates), so typed edits, rollouts and node changes can be writing its profiles.
 * There the write is a ledger op under a claim (`requestLoggingPatch`). Anywhere
 * else no ledger op can be admitted, so nothing can interleave with a direct write.
 */
export const loggingThroughLedger = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }): Promise<boolean> => {
    const server = await ctx.db.get(backendServerId);
    if (!server || !capabilitiesOf(server.backend).backendWrites) return false;
    if (!(await resolveServerConfig(ctx.db)).manage.enabled) return false;
    const setup = await ctx.db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .unique();
    return !!setup;
  },
});

type ServerWithSecret = {
  _id: Id<'backendServers'>;
  name: string;
  backend: keyof typeof PROVIDERS;
  config: unknown;
};
type LoggingProfile = LoggingInstanceReport['profiles'][number];
/** Who a logging write is attributed to: the admin who pressed Apply, else the run. */
type LoggingActor = { actorAdminId?: Id<'adminUsers'>; actorRun?: string };

/** A ledger refusal that means "another change holds it": left for the next run. */
const HELD_CODES = new Set(['servers.op_running', 'servers.op_uncertain']);
const codeOf = (err: unknown): string | null =>
  err instanceof ConvexError ? ((err.data as { code?: string })?.code ?? null) : null;

/**
 * One backend through the ledger: list the profiles (a read), and turn logging
 * off on each one that logs as its own ledger op: preview the tokens, claim the
 * profile and its nodes, then the ledger's `run` re-reads, refuses a profile that
 * moved since the preview, records the token and sends once. A profile another
 * change holds, or one that moved under the preview, is left for the next run.
 */
async function hardenThroughLedger(
  ctx: ActionCtx,
  s: ServerWithSecret,
  writes: NonNullable<(typeof PROVIDERS)[keyof typeof PROVIDERS]['backendWrites']>,
  actor: LoggingActor,
): Promise<LoggingRunRow> {
  const provider = PROVIDERS[s.backend];
  const config = s.config as BackendConfig;
  const listed = await provider.hardenLogging!(config, { dryRun: true });
  const digestKey = (await panelDigestKey()).key;
  const profiles: LoggingProfile[] = [];
  let wrote = false;
  let busy = false;
  const leftAlone = (p: LoggingProfile) => {
    busy = true;
    profiles.push({ uuid: p.uuid, name: p.name, hardened: false, changed: true });
  };
  for (const p of listed.profiles) {
    if (p.error || !p.changed) {
      profiles.push(p);
      continue;
    }
    try {
      const preview = await writes.previewLoggingPatch(config, p.uuid, digestKey);
      if (!preview.changed) {
        profiles.push({ uuid: p.uuid, name: p.name, hardened: true, changed: false });
        continue;
      }
      const claim = {
        backendServerId: s._id,
        profileUuid: p.uuid,
        baseToken: preview.baseToken,
        expectedToken: preview.expectedToken,
        inboundUuids: preview.inboundUuids,
        ...actor,
      };
      let opId: Id<'panelOps'>;
      try {
        ({ opId } = await ctx.runMutation(internal.backendWrites.requestLoggingPatch, claim));
      } catch (err) {
        if (HELD_CODES.has(codeOf(err) ?? '')) {
          leftAlone(p);
          continue;
        }
        // A profile FCP has not read yet: read the backend once, then claim again.
        if (codeOf(err) !== 'not_found') throw err;
        await ctx.runAction(internal.backendObserve.refresh, { backendServerId: s._id });
        ({ opId } = await ctx.runMutation(internal.backendWrites.requestLoggingPatch, claim));
      }
      await ctx.runAction(internal.backendWrites.run, { opId });
      const op = await ctx.runQuery(internal.backendLedger.getForRun, { opId });
      // Hardened only once the ledger SAW the expected profile (its token): a
      // write whose answer was lost, or whose read-back failed or still shows
      // the old config, is not reported as done. Its op stays open and holds
      // the profile; a later look settles it and the next run reads it again.
      if (op?.request === 'acknowledged' && op.panelState === 'observed') {
        wrote = true;
        profiles.push({ uuid: p.uuid, name: p.name, hardened: true, changed: true });
      } else if (
        (op?.attemptId && op.request !== 'rejected_pre_mutation') ||
        op?.errorCode === 'servers.profile_changed'
      )
        leftAlone(p);
      else
        profiles.push({
          uuid: p.uuid,
          name: p.name,
          hardened: false,
          changed: true,
          error: 'The write was not admitted',
        });
    } catch (err) {
      if (HELD_CODES.has(codeOf(err) ?? '')) {
        leftAlone(p);
        continue;
      }
      profiles.push({
        uuid: p.uuid,
        name: p.name,
        hardened: false,
        changed: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return {
    instance: { serverId: s._id as string, name: s.name, ok: true, profiles },
    wrote,
    busy,
  };
}

/**
 * The shared run behind the Check / Apply routes and the hourly cron: every
 * active backend with a `hardenLogging` provider (Outline has no config-profile
 * concept and is skipped). A per-instance failure is isolated + reported, never
 * thrown, so one unreachable backend can't block the rest.
 *
 * A write goes through the ledger where ledger ops can run (`loggingThroughLedger`);
 * elsewhere it is direct, and the token each profile will have is recorded
 * BEFORE the write (`backendObserve.noteOwnProfileTokens`) so a later observation
 * attributes the change to FCP even when the immediate re-read fails. A
 * direct-path backend an older server change still holds (`serverChangeRunning`),
 * and any backend whose ledger eligibility cannot be read, is only READ and left
 * for the next run.
 */
async function hardenEveryBackend(
  ctx: ActionCtx,
  opts: { dryRun: boolean; actor: LoggingActor },
): Promise<LoggingRunRow[]> {
  const servers = await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
  const rows: LoggingRunRow[] = [];
  for (const s of servers) {
    const provider = PROVIDERS[s.backend];
    if (!provider.hardenLogging) continue; // no config-profile concept (Outline)
    // Fail closed: an eligibility read that fails (null) is never permission to
    // bypass the ledger; that backend is only read this time.
    const ledger: boolean | null =
      !opts.dryRun && !!provider.backendWrites
        ? await ctx
            .runQuery(internal.backendServers.loggingThroughLedger, { backendServerId: s._id })
            .catch(() => null)
        : false;
    // Off the ledger, an older op may still hold a profile or a node: left alone
    // (a guard that cannot be read counts as held). Admin Apply and cron alike.
    const busy =
      ledger === null ||
      (!opts.dryRun &&
        ledger === false &&
        (await ctx
          .runQuery(internal.backendServers.serverChangeRunning, { backendServerId: s._id })
          .catch(() => true)));
    const dryRun = opts.dryRun || busy;
    try {
      if (ledger === true && provider.backendWrites) {
        rows.push(await hardenThroughLedger(ctx, s, provider.backendWrites, opts.actor));
        continue;
      }
      // Without the key (a deployment missing ACCOUNT_ID_PEPPER) nothing is
      // recorded first; the immediate re-read below still re-baselines.
      const digestKey = dryRun
        ? undefined
        : await panelDigestKey()
            .then((k) => k.key)
            .catch(() => undefined);
      const report = await provider.hardenLogging(s.config as BackendConfig, {
        dryRun,
        digestKey,
        // Recorded before the write: the observer counts it as FCP's own.
        beforeWrite: async (profileUuid, token) => {
          try {
            await ctx.runMutation(internal.backendObserve.noteOwnProfileTokens, {
              backendServerId: s._id,
              tokens: [{ profileUuid, token }],
            });
            return true;
          } catch {
            return false;
          }
        },
      });
      // A new baseline at once (the recorded token covers a failed re-read).
      if (!dryRun && report.profiles.some((p) => p.changed) && provider.observePanel)
        await ctx
          .runAction(internal.backendObserve.refresh, { backendServerId: s._id, ownEdit: true })
          .catch(() => undefined);
      rows.push({
        instance: { serverId: s._id as string, name: s.name, ok: true, profiles: report.profiles },
        wrote: !dryRun,
        busy,
      });
    } catch (err) {
      rows.push({
        instance: {
          serverId: s._id as string,
          name: s.name,
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          profiles: [],
        },
        wrote: false,
        busy,
      });
    }
  }
  return rows;
}

/**
 * The `appState` key holding the NEWEST logging-privacy check, whoever ran it
 * (the hourly cron, or an admin's Check / Apply). Counts and a time only: no
 * profile name or content, no backend name, address or secret.
 */
export const LOGGING_CHECK_STATE_KEY = 'logging:lastCheck';

const loggingCheckFields = {
  /** `automatic` = the `logging-privacy` cron; `manual` = an admin's Check / Apply. */
  source: v.union(v.literal('automatic'), v.literal('manual')),
  /** A dry run (the admin's Check) wrote nothing. */
  dryRun: v.boolean(),
  /** Backends with config profiles that were looked at. */
  panels: v.number(),
  /** Backends whose profiles could not be listed. */
  panelsUnreadable: v.number(),
  /** Backends the automatic run only read because a server change held them. */
  panelsBusy: v.number(),
  /** Profiles read. */
  profiles: v.number(),
  /** Profiles found logging (before this run turned any off). */
  profilesLogging: v.number(),
  /** Profiles this run turned logging off on. */
  profilesTurnedOff: v.number(),
  /** Profiles that could not be checked or written (malformed, refused). */
  profilesSkipped: v.number(),
};

export interface LoggingCheckCounts {
  source: 'automatic' | 'manual';
  dryRun: boolean;
  panels: number;
  panelsUnreadable: number;
  panelsBusy: number;
  profiles: number;
  profilesLogging: number;
  profilesTurnedOff: number;
  profilesSkipped: number;
}

export interface LoggingCheckRecord extends LoggingCheckCounts {
  /** When the check finished (epoch ms). */
  at: number;
}

/** A run reduced to the counts the card shows (pure). */
export function summarizeLoggingRun(
  rows: readonly LoggingRunRow[],
  source: 'automatic' | 'manual',
  dryRun: boolean,
): LoggingCheckCounts {
  const c: LoggingCheckCounts = {
    source,
    dryRun,
    panels: rows.length,
    panelsUnreadable: 0,
    panelsBusy: 0,
    profiles: 0,
    profilesLogging: 0,
    profilesTurnedOff: 0,
    profilesSkipped: 0,
  };
  for (const { instance, wrote, busy } of rows) {
    if (busy) c.panelsBusy += 1;
    if (!instance.ok) {
      c.panelsUnreadable += 1;
      continue;
    }
    for (const p of instance.profiles) {
      c.profiles += 1;
      if (p.error) c.profilesSkipped += 1;
      else if (p.changed) {
        c.profilesLogging += 1;
        // Written: the direct path (every profile it read) or a ledger op that sent.
        if (wrote && p.hardened) c.profilesTurnedOff += 1;
      }
    }
  }
  return c;
}

/** A stored record read back defensively (an unreadable row reads as never run). */
function parseLoggingCheck(raw: unknown): LoggingCheckRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.at !== 'number' || !Number.isFinite(r.at)) return null;
  const n = (k: keyof LoggingCheckCounts): number => {
    const x = r[k];
    return typeof x === 'number' && Number.isFinite(x) && x >= 0 ? Math.floor(x) : 0;
  };
  return {
    at: r.at,
    source: r.source === 'manual' ? 'manual' : 'automatic',
    dryRun: r.dryRun === true,
    panels: n('panels'),
    panelsUnreadable: n('panelsUnreadable'),
    panelsBusy: n('panelsBusy'),
    profiles: n('profiles'),
    profilesLogging: n('profilesLogging'),
    profilesTurnedOff: n('profilesTurnedOff'),
    profilesSkipped: n('profilesSkipped'),
  };
}

/**
 * Store a finished check as the newest one (`at` = now, so whoever finished last
 * is what the card shows). An AUTOMATIC run that turned logging off anywhere
 * also writes a system audit row, counts only; the admin's Apply is audited by
 * its route (`admin.remnawave.logging_hardened`).
 */
export const recordLoggingCheck = internalMutation({
  args: loggingCheckFields,
  handler: async (ctx, c): Promise<LoggingCheckRecord> => {
    const record: LoggingCheckRecord = {
      at: Date.now(),
      source: c.source,
      dryRun: c.dryRun,
      panels: c.panels,
      panelsUnreadable: c.panelsUnreadable,
      panelsBusy: c.panelsBusy,
      profiles: c.profiles,
      profilesLogging: c.profilesLogging,
      profilesTurnedOff: c.profilesTurnedOff,
      profilesSkipped: c.profilesSkipped,
    };
    await writeStateJson(ctx.db, LOGGING_CHECK_STATE_KEY, record);
    if (c.source === 'automatic' && c.profilesTurnedOff > 0)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'remnawave.logging_hardened',
        targetType: 'backend',
        payload: {
          instances: c.panels,
          profilesChanged: c.profilesTurnedOff,
          profilesTotal: c.profiles,
          panelsUnreadable: c.panelsUnreadable,
          panelsBusy: c.panelsBusy,
        },
      });
    return record;
  },
});

/** The newest logging-privacy check, or null when none ever ran. */
export const getLoggingLastCheck = internalQuery({
  args: {},
  handler: async (ctx): Promise<LoggingCheckRecord | null> =>
    parseLoggingCheck(await readStateJson<unknown>(ctx.db, LOGGING_CHECK_STATE_KEY)),
});

/**
 * Enforce the no-client-IP-logging posture on every active Remnawave instance's
 * config profiles (docs/privacy.md §5), via each provider's `hardenLogging` — a
 * SAFE read-modify-write that touches only the Xray `log`/`policy`, preserving
 * transports/Reality/routing. `dryRun` reports what WOULD change without writing.
 * Writing restarts the affected nodes (Remnawave auto-push). This is the admin's
 * entry point (the Check / Apply routes): the run is stored as the newest check
 * (`source: 'manual'`); a failure to store it never fails the admin's request.
 */
export const hardenRemnawaveLogging = internalAction({
  args: {
    dryRun: v.boolean(),
    /** The admin who pressed Apply: its ledger ops are theirs (absent: an API token). */
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (
    ctx,
    { dryRun, actorAdminId },
  ): Promise<{ instances: LoggingInstanceReport[] }> => {
    const rows = await hardenEveryBackend(ctx, {
      dryRun,
      actor: actorAdminId ? { actorAdminId } : { actorRun: 'admin:logging-apply' },
    });
    try {
      await ctx.runMutation(
        internal.backendServers.recordLoggingCheck,
        summarizeLoggingRun(rows, 'manual', dryRun),
      );
    } catch {
      /* the report is still the admin's answer; the next run records again */
    }
    return { instances: rows.map((r) => r.instance) };
  },
});

/**
 * The `logging-privacy` cron (hourly): check every config profile and turn
 * logging off on any profile found logging, with the same safe read-modify-write
 * as the admin's Apply. In the steady state every profile is already hardened,
 * so nothing is written and no node restarts. A backend a server change holds is
 * only read and left for the next run (`serverChangeRunning`).
 */
export const autoHardenLogging = internalAction({
  args: {},
  handler: async (ctx): Promise<LoggingCheckRecord> =>
    runWithCronOutcome(ctx, 'logging-privacy', async (): Promise<LoggingCheckRecord> => {
      const rows = await hardenEveryBackend(ctx, {
        dryRun: false,
        actor: { actorRun: 'cron:logging-privacy' },
      });
      return ctx.runMutation(
        internal.backendServers.recordLoggingCheck,
        summarizeLoggingRun(rows, 'automatic', false),
      );
    }),
});

/**
 * OPERATOR-RUN, one backend upgrade at a time: re-key every subscription on a
 * Remnawave backend that has been upgraded to 3.x from its 2.x `uuid` to the
 * instance-scoped numeric id (`<backendServerId>:<id>`). Remnawave 3.0 dropped
 * the user uuid, so every per-user call on a 2.x-era key 400s on the upgraded
 * backend until it is remapped; the key's `shortUuid` survives the upgrade and is
 * the join (`GET /api/users/by-short-uuid`). Runbook: docs/backends.md
 * "Upgrading a backend to Remnawave 3.x".
 *
 * Safe to rerun: already-scoped rows are skipped, the remap is compare-and-set,
 * and `dryRun` reports without writing. A backend that still reports a 2.x
 * version is skipped outright (its keys are correct as they are). A key the
 * backend no longer knows is counted as `missing` and left alone for the operator
 * (its tombstone/regenerate path will surface it). Bounded per run by
 * `maxPages` × `pageSize` rows (50 × 100 by default, to stay inside one
 * action's time budget); an incomplete run reports `continueCursor`, which the
 * next run takes as `cursor` (+ `serverId`) to RESUME — a run without a cursor
 * starts from the backend's first row again (cheap for already-scoped rows, but
 * it never gets past `maxPages` on a large fleet, which is how prod stalled on
 * 2026-09-03 before this arg existed).
 */
/** Per-instance report row of `migrateRemnawaveUserIds`. */
interface UserIdMigrationRow {
  serverId: string;
  name: string;
  panelVersion: string | null;
  skipped?: string;
  scanned: number;
  legacy: number;
  remapped: number;
  missing: number;
  failed: number;
  conflicts: number;
  complete: boolean;
  // Where this run stopped when `complete` is false: pass it back as `cursor`
  // (with the same `serverId`) so the next run RESUMES instead of re-walking
  // the rows already done. Null once the backend's rows are exhausted.
  continueCursor: string | null;
}

export const migrateRemnawaveUserIds = internalAction({
  args: {
    dryRun: v.optional(v.boolean()),
    serverId: v.optional(v.id('backendServers')),
    maxPages: v.optional(v.number()),
    pageSize: v.optional(v.number()),
    // Resume point from a previous run's `continueCursor` (requires `serverId`:
    // a cursor is only meaningful within one backend's row sequence).
    cursor: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { dryRun = false, serverId, maxPages = 50, pageSize = 100, cursor: startCursor },
  ): Promise<{ dryRun: boolean; servers: UserIdMigrationRow[] }> => {
    if (startCursor !== undefined && !serverId)
      throw new Error('cursor requires serverId (a cursor belongs to one backend)');
    const all = serverId
      ? [await ctx.runQuery(internal.backendServers.getById, { id: serverId })]
      : await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
    const servers = all.filter((s) => s != null && s.backend === 'remnawave');
    const out: UserIdMigrationRow[] = [];
    for (const s of servers) {
      const cfg = s!.config as RemnawaveServerConfig;
      const row: UserIdMigrationRow = {
        serverId: s!._id as string,
        name: s!.name,
        panelVersion: null as string | null,
        scanned: 0,
        legacy: 0,
        remapped: 0,
        missing: 0,
        failed: 0,
        conflicts: 0,
        complete: true,
        continueCursor: null,
      };
      let major: number | null = null;
      try {
        row.panelVersion = (await remnawaveFleetStats(cfg)).panelVersion;
        major = remnawaveMajorVersion(row.panelVersion);
      } catch {
        out.push({ ...row, skipped: 'backend unreachable (version unknown) — nothing changed' });
        continue;
      }
      if (major === null || major < 3) {
        out.push({ ...row, skipped: 'backend is not 3.x — its 2.x uuids are still correct' });
        continue;
      }
      let cursor: string | null = startCursor ?? null;
      let pages = 0;
      do {
        const page: {
          page: Array<{
            _id: Id<'subscriptions'>;
            backendUserId: string;
            backendShortId: string;
            state: string;
          }>;
          isDone: boolean;
          continueCursor: string;
        } = await ctx.runQuery(internal.subscriptions.listByServerPage, {
          backendServerId: s!._id,
          cursor,
          numItems: pageSize,
        });
        for (const sub of page.page) {
          row.scanned++;
          // Already scoped (issued on / migrated to 3.x) → nothing to do.
          if (scopedServerId(sub.backendUserId) !== null) continue;
          if (sub.state === 'deleted') continue; // hard-deleted rows never hit the backend again
          row.legacy++;
          let resolved: string | null;
          try {
            resolved = await remnawaveResolveUserIdByShortUuid(cfg, sub.backendShortId);
          } catch {
            row.failed++;
            continue;
          }
          if (resolved === null) {
            row.missing++;
            continue;
          }
          if (!isNumericBackendUserId(resolved)) {
            // A 3.x backend answering with a uuid would contradict its version;
            // never write a guess.
            row.failed++;
            continue;
          }
          if (dryRun) {
            row.remapped++;
            continue;
          }
          const res: 'remapped' | 'stale' | 'conflict' = await ctx.runMutation(
            internal.subscriptions.remapBackendUserId,
            {
              id: sub._id,
              expect: sub.backendUserId,
              next: toStoredBackendUserId(s!._id as string, resolved),
            },
          );
          if (res === 'remapped') row.remapped++;
          else if (res === 'conflict') row.conflicts++;
          // 'stale': the row moved on concurrently (re-issued) — nothing to count.
        }
        cursor = page.isDone ? null : page.continueCursor;
        pages++;
      } while (cursor !== null && pages < maxPages);
      row.complete = cursor === null;
      row.continueCursor = cursor;
      if (!dryRun && row.remapped > 0) {
        await ctx.runMutation(internal.audit.record, {
          actorType: 'system',
          action: 'admin.remnawave.user_ids_migrated',
          targetType: 'backendServer',
          targetId: s!._id as string,
          payload: {
            panelVersion: row.panelVersion,
            remapped: row.remapped,
            missing: row.missing,
            failed: row.failed,
            conflicts: row.conflicts,
          },
        });
      }
      out.push(row);
    }
    return { dryRun, servers: out };
  },
});
