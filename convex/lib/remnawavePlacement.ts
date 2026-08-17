/**
 * Remnawave node-load placement (pure fns). At issuance FCP homes a new key to
 * the LEAST-LOADED node of the chosen mode's placement pool, using the per-
 * placement node-load snapshot the healthcheck cron caches in `remnawaveNodeStats`.
 *
 * "Placement" is the opaque handle the generic layer carries (a Remnawave
 * internal-squad UUID); a placement maps to one or more nodes, and its load is
 * the aggregate `usersOnline` (+ optional realtime bandwidth) of those nodes.
 * This module is Remnawave-local by design — the generic backend layer never
 * sees a squad or a node; it reaches this code only through the placement-
 * resolver registry in lib/placement.ts.
 *
 * The per-mode squad pool lives in the `modePlacements` table, one row per
 * (modeSlug, 'remnawave'), config = {"squadUuids":[...]}.
 */
import type { DatabaseReader } from '../_generated/server';
import { resolveDefaultModeId, resolveModeCatalog } from './connectionModes';

/** Fail-safe parse of a stored squad pool: a JSON array of non-empty strings,
 *  de-duplicated in declaration order; anything else resolves to []. */
export function sanitizePool(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string' && entry.trim() && !out.includes(entry)) out.push(entry);
  }
  return out;
}

/** Fail-safe parse of a modePlacements row's config JSON → the squad pool. */
export function poolFromConfig(configJson: string | null | undefined): string[] {
  if (!configJson) return [];
  try {
    const parsed: unknown = JSON.parse(configJson);
    if (!parsed || typeof parsed !== 'object') return [];
    return sanitizePool((parsed as { squadUuids?: unknown }).squadUuids);
  } catch {
    return [];
  }
}

/** The stored pool for ONE slug: its modePlacements row (missing row = unbound). */
async function readStoredPool(db: DatabaseReader, slug: string): Promise<string[]> {
  const row = await db
    .query('modePlacements')
    .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', 'remnawave'))
    .unique();
  return row ? poolFromConfig(row.config) : [];
}

/** The squad pool a mode issues into. When the member has made no explicit
 *  choice (id null/unknown), resolves the DEFAULT mode's pool — a new member
 *  follows the catalog default. Returns [] when the resolved mode has no pool
 *  bound; callers that must never issue a squad-less key use `resolvePlacementPool`
 *  (which then falls back across modes). `resolveBoundModeIds` intentionally reads
 *  raw per-slug pools so the public availability stays truthful. */
export async function resolveModeSquadPool(
  db: DatabaseReader,
  modeId: string | null | undefined,
): Promise<string[]> {
  const { modes } = await resolveModeCatalog(db);
  const known = new Set(modes.map((m) => m.id));
  const slug = modeId && known.has(modeId) ? modeId : await resolveDefaultModeId(db);
  return readStoredPool(db, slug);
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
  // Last resort: any bound pool — but never one belonging to an admin-DISABLED
  // mode. An operator who turns a mode off must not have keys land on its nodes
  // by way of the fallback ladder.
  const { modes } = await resolveModeCatalog(db);
  for (const m of modes) {
    if (!m.enabled) continue;
    const pool = await readStoredPool(db, m.id);
    if (pool.length) return pool;
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
  const { modes } = await resolveModeCatalog(db);
  const counts: Record<string, number> = {};
  for (const m of modes) {
    counts[m.id] = (await readStoredPool(db, m.id)).length;
  }
  return counts;
}

/** The set of mode slugs with ≥1 squad bound on Remnawave — feeds per-backend
 *  availability. One index scan over `modePlacements`. */
export async function resolveBoundModeIds(db: DatabaseReader): Promise<Set<string>> {
  const bound = new Set<string>();
  const rows = await db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', 'remnawave'))
    .collect();
  for (const r of rows) {
    if (poolFromConfig(r.config).length > 0) bound.add(r.modeSlug);
  }
  return bound;
}

/**
 * Re-issue gate for the member's EFFECTIVE mode (regenerate / switch-backend).
 * The cross-mode placement fallback keeps a key from going squad-less, but
 * applied blindly it silently DOWNGRADES a member whose stored mode's pool was
 * unbound by an admin (e.g. a 'privacy-reality' key re-issued into the
 * CDN-fronted 'freedom-ws' pool while the UI still says Privacy Mode). `blocked`
 * is true exactly when the effective mode is unusable AND some other mode is
 * usable — the caller then refuses with an actionable error. When NO mode is
 * usable anywhere (bring-up), blocked is false and issuance proceeds squad-less
 * + audited. "Unusable" covers admin-DISABLED as well as unbound.
 */
export async function remnawaveEffectiveGate(
  db: DatabaseReader,
  modeId: string | null,
): Promise<{ blocked: boolean }> {
  const { modes } = await resolveModeCatalog(db);
  const enabled = new Set(modes.filter((m) => m.enabled).map((m) => m.id));

  const own = await resolveModeSquadPool(db, modeId);
  if (own.length > 0 && (modeId === null || enabled.has(modeId))) {
    return { blocked: false };
  }
  // Some OTHER mode is both enabled and bound → refuse rather than downgrade.
  const bound = await resolveBoundModeIds(db);
  const alternativeExists = [...enabled].some((id) => id !== modeId && bound.has(id));
  return { blocked: alternativeExists };
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
 * One mode's placement-config patch → the JSON string to store. Three
 * composable ops (applied replace → add → remove):
 *   - `squadUuids`       full replace; `[]` clears the pool
 *   - `addSquadUuids`    union into the stored pool (deduped)
 *   - `removeSquadUuids` drop from the stored pool
 * add/remove exist so a headless node deploy can append/detach ITSELF without
 * knowing the rest of the pool (the UUIDs are write-only — there is no GET).
 * Replace/add entries must be squad UUIDs (server-side guard for UI-less
 * callers); remove accepts any non-empty string so a garbage entry that
 * predates the validation can still be purged. Returns null when the entry
 * carries none of the three ops (nothing to write). Throws on malformed input.
 */
export function applyRemnawaveConfigPatch(
  existingConfigJson: string | null,
  entry: unknown,
): string | null {
  if (!entry || typeof entry !== 'object') return null;
  const { squadUuids, addSquadUuids, removeSquadUuids } = entry as Record<string, unknown>;
  if (squadUuids === undefined && addSquadUuids === undefined && removeSquadUuids === undefined) {
    return null;
  }
  let pool =
    squadUuids !== undefined
      ? requireUuidList(squadUuids, 'squadUuids')
      : poolFromConfig(existingConfigJson);
  if (addSquadUuids !== undefined) {
    pool = pool.concat(requireUuidList(addSquadUuids, 'addSquadUuids'));
  }
  if (removeSquadUuids !== undefined) {
    const drop = new Set(requireStringList(removeSquadUuids, 'removeSquadUuids'));
    pool = pool.filter((s) => !drop.has(s));
  }
  return JSON.stringify({ squadUuids: sanitizePool(pool) });
}

/** Public-safe summary of one stored config (never the UUIDs). */
export function summarizeRemnawaveConfig(configJson: string | null): {
  bound: boolean;
  count: number;
} {
  const n = poolFromConfig(configJson).length;
  return { bound: n > 0, count: n };
}

// A node-load snapshot older than this is treated as unknown load (the
// healthcheck cron refreshes every 10 min; 30 min matches the instance pool's
// "fresh" window). Exported because the same bar decides whether a snapshot's
// `nodeCount` is trustworthy enough to promise a member a different server
// (account.switchServer) — one staleness rule, not two.
export const NODE_STATS_STALE_MS = 30 * 60_000;

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
 *  - `excludePlacement` (the member's "switch server" action): skip the squad the
 *    key is already on, so the pick must actually MOVE it. Fail-soft: dropped when
 *    it would empty the pool, and the caller compares the result against the
 *    current placement to tell "moved" from "nowhere else to go".
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
    excludePlacement?: string | null;
    // Injected PRNG for the anti-herding pick (queries must stay deterministic —
    // callers on the issuance path mint this in the ACTION and thread it down).
    rand?: () => number;
  } = {},
): Promise<{
  placement: string | null;
  serverId: string | null;
  unattributedMultiPanel?: boolean;
}> {
  const fullPool = await resolvePlacementPool(db, modeId);
  // Fail-soft exclusion: a one-squad pool still issues (onto the same squad), and
  // the caller decides what "didn't move" means.
  const pool =
    opts.excludePlacement && fullPool.some((p) => p !== opts.excludePlacement)
      ? fullPool.filter((p) => p !== opts.excludePlacement)
      : fullPool;
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
    const placement = await pickByNodeLoad(db, constrained, opts.rand);
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
    return { placement: await pickByNodeLoad(db, pool, opts.rand), serverId: null };
  }
  const placement = await pickByNodeLoad(db, constrained, opts.rand);
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
 * issuance between 10-minute stat refreshes pile onto the same node. The
 * randomness is INJECTED (`rand`): Convex queries/mutations must be
 * deterministic (the runtime may pin the PRNG, which would degenerate the
 * top-3 pick to a constant), so callers on the issuance path pass a float
 * minted in the ACTION. No rand → deterministic top-1 (tier pushes, tests).
 */
export async function pickByNodeLoad(
  db: DatabaseReader,
  pool: string[],
  rand?: () => number,
): Promise<string | null> {
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
  if (usable.length >= 2 && rand) {
    const top = usable.slice(0, 3);
    return top[Math.floor(rand() * top.length)]!.placement;
  }
  return scored[0]!.placement;
}
