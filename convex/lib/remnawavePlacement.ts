/**
 * Remnawave node-load placement (pure fns). At issuance FCP homes a new key to
 * the LEAST-LOADED node of the chosen mode's placement pool, using the per-
 * placement node-load snapshot the healthcheck cron caches in `remnawaveNodeStats`.
 *
 * "Placement" is the opaque handle the generic layer carries (a Remnawave
 * internal-squad UUID); a placement maps to one or more nodes, and its load is
 * the aggregate `usersOnline` (+ optional realtime bandwidth) of those nodes.
 * This module is Remnawave-local by design — the generic backend layer never
 * sees a squad or a node.
 */
import type { DatabaseReader } from '../_generated/server';
import {
  CONNECTION_MODES,
  CONNECTION_MODE_KEYS,
  DEFAULT_CONNECTION_MODE,
  isConnectionModeId,
} from './connectionModes';

// The per-mode squad pool a mode's keys are placed across. Remnawave-specific
// (squad UUIDs), so it lives in the Remnawave-namespaced appSettings prefix
// (`remnawave.modePlacement.<id>.squads`), edited via /admin/remnawave/*, NOT
// under the generic connectionMode.* catalog.
const POOL_PREFIX = 'remnawave.modePlacement.';
const POOL_KEY_SUFFIX = '.squads';
const MODE_POOL_KEY = (id: string) => `${POOL_PREFIX}${id}${POOL_KEY_SUFFIX}`;

/** Fail-safe parse of a stored squad pool: a JSON array of non-empty strings,
 *  de-duplicated in declaration order; anything else resolves to []. */
function sanitizePool(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string' && entry.trim() && !out.includes(entry)) out.push(entry);
  }
  return out;
}

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

/** The squad pool a mode issues into. When the member has made no explicit
 *  choice (id null/invalid), resolves the DEFAULT mode's pool — a new member
 *  follows the catalog default. Returns [] when the resolved mode has no pool
 *  bound; callers that must never issue a squad-less key use `resolvePlacementPool`
 *  (which then falls back across modes). `resolveBoundModeIds` intentionally reads
 *  THIS (raw, no fallback) so the public `available` flag stays truthful. */
export async function resolveModeSquadPool(
  db: DatabaseReader,
  modeId: string | null | undefined,
): Promise<string[]> {
  const id = isConnectionModeId(modeId)
    ? modeId
    : isConnectionModeId(await readSetting(db, CONNECTION_MODE_KEYS.defaultId))
      ? ((await readSetting(db, CONNECTION_MODE_KEYS.defaultId)) as string)
      : DEFAULT_CONNECTION_MODE;
  return sanitizePool(await readSetting(db, MODE_POOL_KEY(id)));
}

/**
 * The pool a key is ACTUALLY issued into — the anti-squad-less invariant.
 * Falls back so a bound-somewhere deploy never mints a key with no inbounds:
 *   the mode's own pool → the DEFAULT mode's pool → ANY bound pool (catalog
 *   order) → [].
 * Only returns [] when NO mode has a pool bound anywhere (a fresh/misconfigured
 * deploy — the caller issues squad-less + audits). All three issuance sites and
 * the tier-push preserve path resolve through this; `resolveModeSquadPool` and
 * `resolveBoundModeIds` stay raw so per-mode availability is reported honestly.
 */
export async function resolvePlacementPool(
  db: DatabaseReader,
  modeId: string | null | undefined,
): Promise<string[]> {
  const own = await resolveModeSquadPool(db, modeId);
  if (own.length) return own;
  const viaDefault = await resolveModeSquadPool(db, null);
  if (viaDefault.length) return viaDefault;
  const bound = await resolveBoundModeIds(db);
  for (const def of CONNECTION_MODES) {
    if (bound.has(def.id)) return resolveModeSquadPool(db, def.id);
  }
  return [];
}

/** Deterministic first-of-pool (declaration order) — the tier-push preserve
 *  fallback for rows with no persisted placement. Routes through
 *  `resolvePlacementPool` so a renewal never CLEARS the squad of a key whose mode
 *  lost its pool (which would strand a live key). */
export async function resolveModePlacementStable(
  db: DatabaseReader,
  modeId: string | null | undefined,
): Promise<string | null> {
  return (await resolvePlacementPool(db, modeId))[0] ?? null;
}

/** Per-mode bound-squad COUNTS (non-secret — pool sizes only, never the UUIDs).
 *  Feeds the admin placement editor's "N squads bound" feedback so a typo'd or
 *  half-pasted pool is visible immediately, not as a silently dead node. Raw
 *  per-mode reads (no cross-mode fallback), like `resolveBoundModeIds`. */
export async function resolveBoundModeCounts(db: DatabaseReader): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const def of CONNECTION_MODES) {
    counts[def.id] = sanitizePool(await readSetting(db, MODE_POOL_KEY(def.id))).length;
  }
  return counts;
}

/** The set of mode ids that have ≥1 squad bound — drives the public `available`
 *  flag. One range scan over the Remnawave placement namespace. */
export async function resolveBoundModeIds(db: DatabaseReader): Promise<Set<string>> {
  const rows = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.gte('key', POOL_PREFIX).lt('key', POOL_PREFIX.slice(0, -1) + '/'))
    .collect();
  const bound = new Set<string>();
  for (const r of rows) {
    if (!r.key.endsWith(POOL_KEY_SUFFIX)) continue;
    const id = r.key.slice(POOL_PREFIX.length, -POOL_KEY_SUFFIX.length);
    try {
      if (sanitizePool(JSON.parse(r.value)).length > 0) bound.add(id);
    } catch {
      /* malformed → not bound */
    }
  }
  return bound;
}

// Same UUID shape the admin placement editor enforces client-side
// (AdminRemnawave.svelte UUID_RE) — the server-side guard covers headless
// callers (the Ansible role) that have no UI validation.
const SQUAD_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function requireStringList(raw: unknown, field: string): string[] {
  if (!Array.isArray(raw) || raw.some((s) => typeof s !== 'string' || !s.trim())) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
  return (raw as string[]).map((s) => s.trim());
}

function requireUuidList(raw: unknown, field: string): string[] {
  const list = requireStringList(raw, field);
  const bad = list.filter((s) => !SQUAD_UUID_RE.test(s));
  if (bad.length) throw new Error(`not a squad UUID: ${bad.join(', ')}`);
  return list;
}

/**
 * Admin PATCH → the per-mode squad-pool appSettings writes (Remnawave-specific).
 * Per mode, three composable ops (applied replace → add → remove):
 *   - `squadUuids`       full replace; `[]` clears the pool
 *   - `addSquadUuids`    union into the stored pool (deduped)
 *   - `removeSquadUuids` drop from the stored pool
 * add/remove exist so a headless node deploy can append/detach ITSELF without
 * knowing the rest of the pool (the UUIDs are write-only — there is no GET).
 * Replace/add entries must be squad UUIDs (server-side guard for UI-less
 * callers); remove accepts any non-empty string so a garbage entry that predates
 * the validation can still be purged. Throws on a malformed patch. Returns the
 * key/value pairs the mutation persists.
 */
export async function modePlacementWrites(
  db: DatabaseReader,
  patch: unknown,
): Promise<Array<{ key: string; value: string }>> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('mode-placement patch must be an object');
  }
  const modes = ((patch as Record<string, unknown>).modes ?? {}) as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  for (const id of Object.keys(modes)) {
    if (!isConnectionModeId(id)) continue;
    const entry = modes[id];
    if (!entry || typeof entry !== 'object') continue;
    const { squadUuids, addSquadUuids, removeSquadUuids } = entry as Record<string, unknown>;
    if (squadUuids === undefined && addSquadUuids === undefined && removeSquadUuids === undefined) {
      continue;
    }
    let pool =
      squadUuids !== undefined
        ? requireUuidList(squadUuids, 'squadUuids')
        : sanitizePool(await readSetting(db, MODE_POOL_KEY(id)));
    if (addSquadUuids !== undefined) {
      pool = pool.concat(requireUuidList(addSquadUuids, 'addSquadUuids'));
    }
    if (removeSquadUuids !== undefined) {
      const drop = new Set(requireStringList(removeSquadUuids, 'removeSquadUuids'));
      pool = pool.filter((s) => !drop.has(s));
    }
    writes.push({ key: MODE_POOL_KEY(id), value: JSON.stringify(sanitizePool(pool)) });
  }
  return writes;
}

// A node-load snapshot older than this is treated as unknown load (the
// healthcheck cron refreshes every 10 min; 30 min matches the instance pool's
// "fresh" window).
const NODE_STATS_STALE_MS = 30 * 60_000;

const DEFAULT_USERS_ONLINE_WEIGHT = 1;
const DEFAULT_BANDWIDTH_WEIGHT = 0; // usersOnline-only until the realtime shape is pinned

/** Scoring weights (admin-tunable via appSettings; JSON-encoded numbers). */
async function placementWeights(
  db: DatabaseReader,
): Promise<{ usersOnline: number; bandwidth: number }> {
  const read = async (key: string, def: number): Promise<number> => {
    const row = await db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    const n = row ? Number(JSON.parse(row.value)) : NaN;
    return Number.isFinite(n) ? n : def;
  };
  return {
    usersOnline: await read(
      'remnawave.nodePlacement.usersOnline_weight',
      DEFAULT_USERS_ONLINE_WEIGHT,
    ),
    bandwidth: await read('remnawave.nodePlacement.bandwidth_weight', DEFAULT_BANDWIDTH_WEIGHT),
  };
}

/**
 * The (placement, server) pair a NEW Remnawave key issues into — the multi-panel
 * generalization of `pickByNodeLoad`. A mode's squad pool may span several
 * panels (one panel per location); the squad UUID sent at issuance MUST exist on
 * the panel the user is created on, so the two are resolved TOGETHER: each pool
 * squad is attributed to its panel via its `remnawaveNodeStats` row (stamped by
 * the healthcheck cron), the pool is narrowed to squads on eligible panels, and
 * the least-loaded survivor wins. `serverId` pins issuance to that panel.
 *
 * Eligibility filters, all FAIL-SOFT except `onlyServerId`:
 *  - `location`: keep panels whose `location` code matches (the member's picked
 *    location). No active panel matches / none of its squads are in the pool →
 *    the filter is dropped (issue anywhere) rather than blocking issuance.
 *  - capacity/health: at-capacity panels (maxKeys) are dropped the same way
 *    `pickCandidatesForIssue` drops them; if that empties the pool the filter
 *    is dropped (a degraded pool still issues — same posture as pickByNodeLoad).
 *  - `onlyServerId` (the in-place mode-switch path): HARD — the key already
 *    lives on that panel, so a placement on another panel is unusable. Returns
 *    `{placement:null}` when the target mode has no squad there; the caller
 *    falls back to a re-issue (which may move panels).
 *
 * A squad with no stats row yet (bring-up: the cron hasn't observed it) can't be
 * attributed to a panel; when the constrained pool is empty we fall back to the
 * whole pool with `serverId:null`, which reproduces the historical single-panel
 * behavior (issueUser picks the instance independently).
 */
export async function resolvePlacementTarget(
  db: DatabaseReader,
  modeId: string | null | undefined,
  opts: {
    location?: string | null;
    onlyServerId?: string | null;
  } = {},
): Promise<{
  placement: string | null;
  serverId: string | null;
  unattributedMultiPanel?: boolean;
}> {
  const pool = await resolvePlacementPool(db, modeId);
  if (pool.length === 0) return { placement: null, serverId: null };

  // Attribute each pool squad to its panel via the node-stats cache.
  const statsByPlacement = new Map<string, { serverId: string }>();
  for (const placement of pool) {
    const row = await db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', placement))
      .unique();
    if (row) statsByPlacement.set(placement, { serverId: row.backendServerId as string });
  }

  const servers = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();

  if (opts.onlyServerId) {
    // HARD pin: the in-place switch can only use squads on the key's own panel.
    // Capacity (maxKeys) deliberately does NOT apply — no new key is minted, the
    // existing one just moves squads on the same panel. A squad with NO stats
    // row can't be proven foreign, so it stays eligible (single-panel deploys
    // and bring-up have no attribution yet); if it does turn out to be another
    // panel's squad, the PATCH fails and the caller falls back to a re-issue.
    const ids = new Set(servers.map((s) => s._id as string));
    if (!ids.has(opts.onlyServerId)) return { placement: null, serverId: null };
    const constrained = pool.filter((p) => {
      const attributed = statsByPlacement.get(p);
      return !attributed || attributed.serverId === opts.onlyServerId;
    });
    if (constrained.length === 0) return { placement: null, serverId: null };
    const placement = await pickByNodeLoad(db, constrained);
    return { placement, serverId: placement ? opts.onlyServerId : null };
  }

  // Eligible panels for a NEW key: active instances, minus at-capacity ones.
  let eligible = servers.filter((s) => s.maxKeys == null || s.keyCount < s.maxKeys);
  if (eligible.length === 0) eligible = servers; // fail-soft: degraded > blocked

  // Soft location narrowing: prefer the member's picked location, drop the
  // filter whenever honoring it would block issuance.
  let allowed = eligible;
  if (opts.location) {
    const atLocation = eligible.filter((s) => s.location === opts.location);
    if (atLocation.length > 0) allowed = atLocation;
  }
  const allowedIds = new Set(allowed.map((s) => s._id as string));
  let constrained = pool.filter((p) => {
    const attributed = statsByPlacement.get(p);
    return attributed != null && allowedIds.has(attributed.serverId);
  });
  if (constrained.length === 0 && allowed !== eligible) {
    // The picked location has no bound squads — fall back to any eligible panel.
    const eligibleIds = new Set(eligible.map((s) => s._id as string));
    constrained = pool.filter((p) => {
      const attributed = statsByPlacement.get(p);
      return attributed != null && eligibleIds.has(attributed.serverId);
    });
  }
  if (constrained.length === 0) {
    // No squad is attributable yet (the stats cron hasn't observed a node behind
    // any pool squad — bring-up or a freshly-added panel). On a MULTI-panel
    // deploy the historical fail-soft is a dead-key factory: an unpinned pick
    // lets issueUser choose the instance independently, and the squad UUID only
    // exists on ITS panel — a (squad, wrong-panel) pair mints a key that can't
    // route. Signal the caller to FAIL LOUDLY instead (503, retryable); a
    // single-panel deploy keeps the fail-soft (the pair can't mismatch).
    if (servers.length > 1)
      return { placement: null, serverId: null, unattributedMultiPanel: true };
    return { placement: await pickByNodeLoad(db, pool), serverId: null };
  }
  const placement = await pickByNodeLoad(db, constrained);
  return {
    placement,
    serverId: placement ? (statsByPlacement.get(placement)?.serverId ?? null) : null,
  };
}

/**
 * A least-loaded placement of a pool, by cached node load. Fresh+online
 * placements win over stale/offline/unroutable ones; among all-unknown the
 * pool's declaration order decides, deterministically. A single-element (or
 * empty) pool short-circuits. Between cron refreshes the load can drift by a
 * few issuances — bounded + self-correcting.
 *
 * Load score = usersOnline_weight * usersOnline + bandwidth_weight * (realtime bytes).
 * A placement that is offline or maps to zero nodes is treated as unusable-load
 * (sorted after every usable one) but still selectable as a last resort, so a
 * bound-but-degraded pool still issues a key rather than falling through to null.
 *
 * Anti-herding (L5): with ≥2 usable candidates the pick is UNIFORM AT RANDOM
 * over the top 3 by score — a deterministic top-1 makes every concurrent
 * issuance between 10-minute stat refreshes pile onto the same node. Degraded
 * pools stay deterministic (declaration order) for reproducibility.
 */
export async function pickByNodeLoad(db: DatabaseReader, pool: string[]): Promise<string | null> {
  if (pool.length <= 1) return pool[0] ?? null;
  const now = Date.now();
  const w = await placementWeights(db);
  const scored: { placement: string; order: number; usable: boolean; score: number }[] = [];
  for (let order = 0; order < pool.length; order++) {
    const placement = pool[order]!;
    const row = await db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', placement))
      .unique();
    const fresh = row != null && now - row.lastStatsAt < NODE_STATS_STALE_MS;
    // Usable = a fresh snapshot with ≥1 online node. Everything else (stale,
    // offline, never-observed, unroutable) sorts last but stays selectable.
    const usable = fresh && row.online && row.nodeCount > 0;
    const score = usable
      ? w.usersOnline * row.usersOnline + w.bandwidth * (row.trafficBytesRealtime ?? 0)
      : Number.POSITIVE_INFINITY;
    scored.push({ placement, order, usable, score });
  }
  scored.sort(
    (a, b) => Number(b.usable) - Number(a.usable) || a.score - b.score || a.order - b.order,
  );
  const usable = scored.filter((s) => s.usable);
  if (usable.length >= 2) {
    const top = usable.slice(0, 3);
    return top[Math.floor(Math.random() * top.length)]!.placement;
  }
  return scored[0]!.placement;
}
