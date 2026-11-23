/**
 * The moving parts of a backend server, kept off its `backendServers` row.
 *
 * Convex caches a query's result until something writes a document it read.
 * The server row is read by many cached queries for its name, location and
 * config alone (publicConfig.get, the status page, the subscription route's
 * entry naming), so a field on it that changes at every key issuance evicted
 * all of them, and two issuances on one server conflicted on it. The moving
 * fields live in two side tables instead, one row per server:
 *
 *  - `backendServerLoad`: the key count, bumped at every issuance and
 *    teardown. Read by the issuance pickers and the admin views only.
 *  - `backendServerHealth`: the healthcheck's stamps (last success, rtt) and
 *    the fleet stats, written every 10 min. Read wherever the online bit is
 *    needed (the location catalog, the status page, alerts, the pickers).
 *
 * They are apart from each other so a public reader that needs the online bit
 * never sees a per-issuance write.
 *
 * Until `seed:migrateServerLoad` has run (seedCutover, on deploy) a server may
 * have no side row yet and still carry the legacy fields on its own row; every
 * read here falls back to those, so the moment between pushing the code and
 * the migration reads the same numbers as before.
 */
import type { DatabaseReader, MutationCtx } from '../_generated/server';
import type { Doc, Id } from '../_generated/dataModel';

type Server = Doc<'backendServers'>;

export interface ServerHealth {
  lastHealthOkAt: number | undefined;
  lastHealthRttMs: number | undefined;
  fleetStats: Doc<'backendServerHealth'>['fleetStats'];
  fleetStatsAt: number | undefined;
}

async function loadRow(db: DatabaseReader, id: Id<'backendServers'>) {
  return db
    .query('backendServerLoad')
    .withIndex('by_server', (q) => q.eq('backendServerId', id))
    .unique();
}

async function healthRow(db: DatabaseReader, id: Id<'backendServers'>) {
  return db
    .query('backendServerHealth')
    .withIndex('by_server', (q) => q.eq('backendServerId', id))
    .unique();
}

/** One server's key count (0 when nothing has counted one yet). */
export async function readKeyCount(db: DatabaseReader, server: Server): Promise<number> {
  const row = await loadRow(db, server._id);
  return row ? row.keyCount : (server.keyCount ?? 0);
}

/** One server's health stamps. */
export async function readHealth(db: DatabaseReader, server: Server): Promise<ServerHealth> {
  const row = await healthRow(db, server._id);
  const src = row ?? server;
  return {
    lastHealthOkAt: src.lastHealthOkAt,
    lastHealthRttMs: src.lastHealthRttMs,
    fleetStats: src.fleetStats,
    fleetStatsAt: src.fleetStatsAt,
  };
}

/** Key counts for several servers, by id. */
export async function keyCountsOf(
  db: DatabaseReader,
  servers: readonly Server[],
): Promise<Map<Id<'backendServers'>, number>> {
  const counts = await Promise.all(servers.map((s) => readKeyCount(db, s)));
  return new Map(servers.map((s, i) => [s._id, counts[i]!]));
}

/** Health stamps for several servers, by id. */
export async function healthOf(
  db: DatabaseReader,
  servers: readonly Server[],
): Promise<Map<Id<'backendServers'>, ServerHealth>> {
  const rows = await Promise.all(servers.map((s) => readHealth(db, s)));
  return new Map(servers.map((s, i) => [s._id, rows[i]!]));
}

/** Whether a health record passed a check within `windowMs` of `now`. */
export function healthFresh(
  h: Pick<ServerHealth, 'lastHealthOkAt'> | undefined,
  now: number,
  windowMs: number,
): boolean {
  return h?.lastHealthOkAt != null && now - h.lastHealthOkAt < windowMs;
}

/** Add `delta` to a server's key count (clamped at 0). */
export async function bumpServerKeyCount(
  ctx: MutationCtx,
  id: Id<'backendServers'>,
  delta: number,
): Promise<void> {
  const now = Date.now();
  const row = await loadRow(ctx.db, id);
  if (row) {
    await ctx.db.patch(row._id, { keyCount: Math.max(0, row.keyCount + delta), updatedAt: now });
    return;
  }
  // First count since the split: start from the legacy figure on the server row.
  const server = await ctx.db.get(id);
  if (!server) return;
  await ctx.db.insert('backendServerLoad', {
    backendServerId: id,
    keyCount: Math.max(0, (server.keyCount ?? 0) + delta),
    updatedAt: now,
  });
}

/** Overwrite a server's key count (a backend that reports an exact one). */
export async function setServerKeyCount(
  ctx: MutationCtx,
  id: Id<'backendServers'>,
  keyCount: number,
): Promise<void> {
  const now = Date.now();
  const row = await loadRow(ctx.db, id);
  if (row) {
    if (row.keyCount !== keyCount) await ctx.db.patch(row._id, { keyCount, updatedAt: now });
    return;
  }
  await ctx.db.insert('backendServerLoad', { backendServerId: id, keyCount, updatedAt: now });
}

/** Merge fields into a server's health row (creating it, seeded from any legacy stamps). */
export async function patchServerHealth(
  ctx: MutationCtx,
  id: Id<'backendServers'>,
  fields: Partial<Omit<Doc<'backendServerHealth'>, '_id' | '_creationTime' | 'backendServerId'>>,
): Promise<void> {
  const now = Date.now();
  const row = await healthRow(ctx.db, id);
  if (row) {
    await ctx.db.patch(row._id, { ...fields, updatedAt: now });
    return;
  }
  const server = await ctx.db.get(id);
  if (!server) return;
  await ctx.db.insert('backendServerHealth', {
    backendServerId: id,
    lastHealthOkAt: server.lastHealthOkAt,
    lastHealthRttMs: server.lastHealthRttMs,
    fleetStats: server.fleetStats,
    fleetStatsAt: server.fleetStatsAt,
    ...fields,
    updatedAt: now,
  });
}

/** Drop a removed server's side rows. */
export async function deleteServerLoad(ctx: MutationCtx, id: Id<'backendServers'>): Promise<void> {
  const [load, health] = await Promise.all([loadRow(ctx.db, id), healthRow(ctx.db, id)]);
  if (load) await ctx.db.delete(load._id);
  if (health) await ctx.db.delete(health._id);
}

/**
 * Move one server's legacy fields into its side rows and clear them from the
 * server row. A side row that already exists is newer than the legacy field
 * (something wrote it since the split), so it is kept. Returns whether the
 * server row changed.
 */
export async function migrateServerLoadRow(ctx: MutationCtx, server: Server): Promise<boolean> {
  const legacy =
    server.keyCount !== undefined ||
    server.lastHealthOkAt !== undefined ||
    server.lastHealthRttMs !== undefined ||
    server.fleetStats !== undefined ||
    server.fleetStatsAt !== undefined;
  if (!legacy) return false;
  const now = Date.now();
  if (!(await loadRow(ctx.db, server._id)))
    await ctx.db.insert('backendServerLoad', {
      backendServerId: server._id,
      keyCount: server.keyCount ?? 0,
      updatedAt: now,
    });
  if (!(await healthRow(ctx.db, server._id)))
    await ctx.db.insert('backendServerHealth', {
      backendServerId: server._id,
      lastHealthOkAt: server.lastHealthOkAt,
      lastHealthRttMs: server.lastHealthRttMs,
      fleetStats: server.fleetStats,
      fleetStatsAt: server.fleetStatsAt,
      updatedAt: now,
    });
  await ctx.db.patch(server._id, {
    keyCount: undefined,
    lastHealthOkAt: undefined,
    lastHealthRttMs: undefined,
    fleetStats: undefined,
    fleetStatsAt: undefined,
  });
  return true;
}
