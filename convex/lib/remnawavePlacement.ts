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

/**
 * Admin PATCH → the per-mode squad-pool appSettings writes (Remnawave-specific).
 * Validates each mode id + that the pool is an array of non-empty strings; an
 * empty array clears the pool. Throws on a malformed patch. Returns the key/value
 * pairs the mutation persists.
 */
export function modePlacementWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('mode-placement patch must be an object');
  }
  const modes = ((patch as Record<string, unknown>).modes ?? {}) as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  for (const id of Object.keys(modes)) {
    if (!isConnectionModeId(id)) continue;
    const entry = modes[id];
    if (!entry || typeof entry !== 'object') continue;
    const squads = (entry as Record<string, unknown>).squadUuids;
    if (squads === undefined) continue;
    if (!Array.isArray(squads) || squads.some((s) => typeof s !== 'string' || !s.trim())) {
      throw new Error('squadUuids must be an array of non-empty strings');
    }
    writes.push({ key: MODE_POOL_KEY(id), value: JSON.stringify(sanitizePool(squads)) });
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
 * The least-loaded placement of a pool, by cached node load. Fresh+online
 * placements win over stale/offline/unroutable ones (lowest weighted load
 * first); among all-unknown the pool's declaration order decides,
 * deterministically. A single-element (or empty) pool short-circuits. Between
 * cron refreshes the load can drift by a few issuances — bounded + self-correcting.
 *
 * Load score = usersOnline_weight * usersOnline + bandwidth_weight * (realtime bytes).
 * A placement that is offline or maps to zero nodes is treated as unusable-load
 * (sorted after every usable one) but still selectable as a last resort, so a
 * bound-but-degraded pool still issues a key rather than falling through to null.
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
  return scored[0]!.placement;
}
