/**
 * Names for load balancer addresses: the DB half (lib/edges/addressNames.ts is
 * the pure half, edgeNameOps.ts the DNS calls). docs/edges.md "Names for load
 * balancer addresses".
 *
 * A name row moves through `creating -> live -> (moving -> live)* -> removing
 * -> gone`; `parked` is where automation stops and the operator takes over.
 * Every DNS call runs under the row's one op claim (`begin` / `settle`), and
 * every pass reads the name back from the zone before it writes, so an answer
 * lost mid-call is settled by discovery (the marker proves which records are
 * FCP's), never by a second blind write.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { randomHex } from './lib/crypto';
import { writeAuditLog } from './lib/audit';
import { upsertSettingRow } from './appSettings';
import { EDGE_PLUMBING, sanitizeBool, sanitizeInt, sanitizeNameZones } from './lib/edgeConfig';
import { EDGE_PROVIDER_CAPABILITIES } from './lib/edges/providers/capabilities';
import { edgeLaneOf } from './lib/edges/lanes';
import {
  ADDRESS_NAME_HISTORY,
  ADDRESS_NAME_MAX_ATTEMPTS,
  ADDRESS_NAME_MAX_GENERATION,
  NAME_SERVES,
  addressNameMarker,
  desiredNameRecords,
  mayMoveName,
  mintAddressName,
  nameTargetOf,
  pickNameZone,
  type AddressNameState,
  type MoveVerdict,
} from './lib/edges/addressNames';
import { bumpEpochAndRefresh } from './lib/edges/relayGuards';

type Name = Doc<'edgeNames'>;
type Edge = Doc<'edges'>;

const ENDED: readonly AddressNameState[] = ['gone', 'parked'];
const OPEN: readonly AddressNameState[] = ['creating', 'live', 'moving', 'removing'];

// --- settings ---------------------------------------------------------------------------------

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

export interface NamesSettings {
  enabled: boolean;
  zones: string[];
  moveQuietDays: number;
}

/** `edge.names.*`, read on its own (three rows; the render reads only the switch). */
export async function namesSettingsOf(db: DatabaseReader): Promise<NamesSettings> {
  const [enabled, zones, quiet] = await Promise.all([
    readSetting(db, 'edge.names.enabled'),
    readSetting(db, 'edge.names.zones'),
    readSetting(db, 'edge.names.moveQuietDays'),
  ]);
  return {
    enabled: sanitizeBool(enabled, false),
    zones: sanitizeNameZones(zones),
    moveQuietDays: sanitizeInt(quiet, 0, 365, 30),
  };
}

export async function namesEnabledOf(db: DatabaseReader): Promise<boolean> {
  return sanitizeBool(await readSetting(db, 'edge.names.enabled'), false);
}

// --- reads ------------------------------------------------------------------------------------

/** The name a member body may carry for this address (`live` or `moving` to it), if any. */
export async function servingNameOf(db: DatabaseReader, edgeId: Id<'edges'>): Promise<Name | null> {
  for (const state of NAME_SERVES) {
    const row = await db
      .query('edgeNames')
      .withIndex('by_edge', (q) => q.eq('edgeId', edgeId).eq('state', state))
      .first();
    if (row) return row;
  }
  return null;
}

/** Every row of an address, newest first (bounded: an address has a handful at most). */
async function namesOfEdge(db: DatabaseReader, edgeId: Id<'edges'>): Promise<Name[]> {
  const rows = await db
    .query('edgeNames')
    .withIndex('by_edge', (q) => q.eq('edgeId', edgeId))
    .take(50);
  return rows.sort((a, b) => b.createdAt - a.createdAt);
}

/** The open (not yet ended) row that serves or is being made for this address. */
async function openNameOf(db: DatabaseReader, edgeId: Id<'edges'>): Promise<Name | null> {
  for (const state of ['creating', 'live', 'moving'] as const) {
    const row = await db
      .query('edgeNames')
      .withIndex('by_edge', (q) => q.eq('edgeId', edgeId).eq('state', state))
      .first();
    if (row) return row;
  }
  return null;
}

/** What the admin views say about an address's name (never shown to members). */
export async function nameViewOf(
  db: DatabaseReader,
  edgeId: Id<'edges'>,
): Promise<{
  fqdn: string;
  state: AddressNameState;
  zoneLocationId: Id<'edgeLocations'>;
  moves: number;
  movedAt?: number;
  movedHere: boolean;
  failure?: { code: string; at: number };
  /** A name of this address FCP gave up on is still open (the drawer offers Dismiss). */
  stuck: boolean;
} | null> {
  const rows = await namesOfEdge(db, edgeId);
  const row = rows.find((r) => !ENDED.includes(r.state)) ?? rows.find((r) => r.state === 'parked');
  if (!row) return null;
  const first = row.served[0];
  return {
    stuck: rows.some((r) => r.state === 'parked'),
    fqdn: row.fqdn,
    state: row.state,
    zoneLocationId: row.zoneLocationId,
    moves: row.moves,
    ...(row.movedAt !== undefined ? { movedAt: row.movedAt } : {}),
    movedHere: !!first && first.edgeId !== edgeId,
    ...(row.failure ? { failure: row.failure } : {}),
  };
}

export interface NameZone {
  locationId: Id<'edgeLocations'>;
  dnsAccountId: Id<'edgeProviderAccounts'>;
  zoneId: string;
  zoneName: string;
}

/**
 * The eligible zones that can take new work now: a location of a DNS account
 * with a zone, both switched on. A switched-off one gets no new name and no
 * move; a name already there keeps its frozen zone, so it can still be removed.
 */
export async function nameZonesOf(db: DatabaseReader, ids: readonly string[]): Promise<NameZone[]> {
  const out: NameZone[] = [];
  for (const id of ids) {
    const locationId = db.normalizeId('edgeLocations', id);
    if (!locationId) continue;
    const loc = await db.get(locationId);
    if (!loc || !loc.enabled) continue;
    const acct = await db.get(loc.accountId);
    if (!acct || !acct.enabled || !EDGE_PROVIDER_CAPABILITIES[acct.provider].providesDns) continue;
    const p = loc.placement as { zoneId?: unknown; zoneName?: unknown };
    if (typeof p.zoneId !== 'string' || typeof p.zoneName !== 'string' || !p.zoneName) continue;
    out.push({ locationId, dnsAccountId: acct._id, zoneId: p.zoneId, zoneName: p.zoneName });
  }
  return out;
}

/** Names that still hold (or may hold) records in a zone: a zone or account delete waits for them. */
export async function namesInZone(
  db: DatabaseReader,
  locationId: Id<'edgeLocations'>,
): Promise<number> {
  let n = 0;
  for (const state of [...OPEN, 'parked'] as const)
    n += (
      await db
        .query('edgeNames')
        .withIndex('by_zone', (q) => q.eq('zoneLocationId', locationId).eq('state', state))
        .take(1)
    ).length;
  return n;
}

// --- the pass: claim, then settle ---------------------------------------------------------------

export type NameOrder =
  | { kind: 'none' }
  | { kind: 'busy' }
  | {
      kind: 'order';
      nameId: Id<'edgeNames'>;
      opId: string;
      fqdn: string;
      marker: string;
      state: AddressNameState;
      zone: { dnsAccountId: Id<'edgeProviderAccounts'>; zoneId: string; zoneName: string };
      /** Exactly what should be at the name afterwards (empty = remove FCP's records). */
      desired: Array<{ type: 'A' | 'AAAA'; name: string; content: string }>;
    };

/**
 * Claim ONE pass over a name: by its id, or for an address that wants one
 * (`edgeId`: the row is made here, its zone and name chosen). The order says
 * what the zone should hold afterwards; a claim still running answers `busy`,
 * and an expired one is taken over (the pass reads the name back first).
 */
export const begin = internalMutation({
  args: { nameId: v.optional(v.id('edgeNames')), edgeId: v.optional(v.id('edges')) },
  handler: async (ctx, a): Promise<NameOrder> => {
    const now = Date.now();
    let row: Name | null = a.nameId ? await ctx.db.get(a.nameId) : null;
    if (!row && a.edgeId) {
      row = await openNameOf(ctx.db, a.edgeId);
      if (!row) row = await createFor(ctx, a.edgeId, now);
    }
    if (!row || ENDED.includes(row.state)) return { kind: 'none' };
    if (row.currentOp && row.currentOp.expiresAt > now) return { kind: 'busy' };
    // What the zone should hold: the address the name serves now, or nothing.
    let state = row.state;
    let desired: Array<{ type: 'A' | 'AAAA'; name: string; content: string }> = [];
    if (state !== 'removing') {
      const target = nameTargetOf(await ctx.db.get(row.edgeId));
      if (target.kind === 'hold') return { kind: 'none' };
      if (target.kind === 'remove') {
        state = 'removing';
        await retarget(ctx, row, { state, served: closeServed(row.served, now, 'destroyed') }, now);
        await scheduleEpochIfServing(ctx, row);
      } else desired = desiredNameRecords(row.fqdn, target);
    }
    const opId = randomHex(8);
    await ctx.db.patch(row._id, {
      currentOp: { opId, startedAt: now, expiresAt: now + EDGE_PLUMBING.opClaimMs },
      updatedAt: now,
    });
    return {
      kind: 'order',
      nameId: row._id,
      opId,
      fqdn: row.fqdn,
      marker: addressNameMarker(row._id),
      state,
      zone: { dnsAccountId: row.dnsAccountId, zoneId: row.zoneId, zoneName: row.zoneName },
      desired,
    };
  },
});

/** The row for an address that wants a name and has none: zone and name chosen now. */
async function createFor(ctx: MutationCtx, edgeId: Id<'edges'>, now: number): Promise<Name | null> {
  const edge = await ctx.db.get(edgeId);
  if (!wantsName(edge)) return null;
  const settings = await namesSettingsOf(ctx.db);
  if (!settings.enabled) return null;
  const zones = await nameZonesOf(ctx.db, settings.zones);
  if (zones.length === 0) return null;
  // A renewed name's zone is avoided (it may be blocked there); the next
  // name of the address is a new word pair.
  const previous = await namesOfEdge(ctx.db, edgeId);
  const renewed = previous.find((r) => r.served.at(-1)?.why === 'renewed');
  const uses = [];
  for (const z of zones) {
    const inZone = await liveNamesInZone(ctx.db, z.locationId);
    uses.push({
      locationId: z.locationId as string,
      onOrigin: inZone.filter((r) => r.relayId === edge.relayId).length,
      inFleet: inZone.length,
    });
  }
  const pick = pickNameZone(uses, edge.name, renewed?.zoneLocationId);
  const zone = zones.find((z) => z.locationId === pick);
  if (!zone) return null;
  const free = await freeName(
    ctx.db,
    edge.name,
    zone.zoneName,
    previous.reduce((m, r) => Math.max(m, r.generation + 1), 0),
  );
  if (!free) return null;
  const { fqdn, generation } = free;
  const id = await ctx.db.insert('edgeNames', {
    relayId: edge.relayId,
    edgeId,
    fqdn,
    generation,
    zoneLocationId: zone.locationId,
    dnsAccountId: zone.dnsAccountId,
    zoneId: zone.zoneId,
    zoneName: zone.zoneName,
    state: 'creating',
    records: [],
    moves: 0,
    served: [{ edgeId, from: now }],
    attempts: 0,
    createdAt: now,
    updatedAt: now,
  });
  return await ctx.db.get(id);
}

/** The first name from `generation` on that no row holds (a collision is all but impossible). */
async function freeName(
  db: DatabaseReader,
  seed: string,
  zoneName: string,
  generation: number,
): Promise<{ fqdn: string; generation: number } | null> {
  for (let g = generation; g <= ADDRESS_NAME_MAX_GENERATION; g++) {
    const fqdn = mintAddressName(seed, zoneName, g);
    const taken = await db
      .query('edgeNames')
      .withIndex('by_fqdn', (q) => q.eq('fqdn', fqdn))
      .first();
    if (!taken) return { fqdn, generation: g };
  }
  return null;
}

async function liveNamesInZone(
  db: DatabaseReader,
  locationId: Id<'edgeLocations'>,
): Promise<Name[]> {
  const out: Name[] = [];
  for (const state of ['creating', 'live', 'moving'] as const)
    out.push(
      ...(await db
        .query('edgeNames')
        .withIndex('by_zone', (q) => q.eq('zoneLocationId', locationId).eq('state', state))
        .take(500)),
    );
  return out;
}

/** An address that should get a name now (planned with the switch on, addressed, in use or a spare). */
function wantsName(edge: Edge | null): edge is Edge {
  return (
    !!edge &&
    edge.nameWanted === true &&
    edge.managed &&
    (edge.layer ?? 'l4') === 'l4' &&
    edge.status === 'active' &&
    !!edge.addresses.v4
  );
}

const recordV = v.object({
  type: v.union(v.literal('A'), v.literal('AAAA')),
  recordId: v.string(),
  content: v.string(),
});

/**
 * Settle a pass. `done`: the zone holds exactly `records` (FCP's own); a
 * `conflict` (something at the name FCP did not write) moves a name being
 * made to the next word pair and parks any other; a failure counts, and past
 * its cap (or at once when `final`) the name is parked, or, for a name
 * moving to a new address, removed (that address then gets a name of its own).
 */
export const settle = internalMutation({
  args: {
    nameId: v.id('edgeNames'),
    opId: v.string(),
    outcome: v.union(
      v.object({ kind: v.literal('done'), records: v.array(recordV) }),
      v.object({ kind: v.literal('conflict'), reason: v.string() }),
      v.object({ kind: v.literal('failed'), code: v.string(), final: v.boolean() }),
    ),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.nameId);
    if (!row) return { ok: false as const };
    if (row.currentOp?.opId !== a.opId) {
      // A pass whose claim was revoked (the name was pointed elsewhere) or lapsed:
      // whatever it wrote landed before this call, so one more pass reads the
      // zone back after it and puts right what it left.
      if (!ENDED.includes(row.state))
        await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: row._id });
      return { ok: false as const };
    }
    const now = Date.now();
    const base = { currentOp: undefined, updatedAt: now };
    const o = a.outcome;
    if (o.kind === 'done') {
      if (row.state === 'removing') {
        if (o.records.length > 0) {
          await ctx.db.patch(row._id, { ...base, records: o.records });
          return { ok: true as const, state: row.state };
        }
        await ctx.db.patch(row._id, {
          ...base,
          state: 'gone',
          records: [],
          goneAt: now,
          attempts: 0,
          failure: undefined,
        });
        await auditName(ctx, row, 'edge.name.removed', { why: row.served.at(-1)?.why });
        return { ok: true as const, state: 'gone' as const };
      }
      const wasCreating = row.state === 'creating';
      await ctx.db.patch(row._id, {
        ...base,
        state: 'live',
        records: o.records,
        leavingEdgeId: undefined,
        attempts: 0,
        failure: undefined,
        ...(wasCreating ? { liveAt: now } : {}),
      });
      if (wasCreating) {
        await auditName(ctx, row, 'edge.name.live', { zoneLocationId: row.zoneLocationId });
        // Members of a published address move to the name at their next fetch.
        await scheduleEpochIfServing(ctx, row);
      }
      return { ok: true as const, state: 'live' as const };
    }
    if (o.kind === 'conflict') {
      if (row.state === 'creating' && row.records.length === 0) {
        const edge = await ctx.db.get(row.edgeId);
        const free = edge
          ? await freeName(ctx.db, edge.name, row.zoneName, row.generation + 1)
          : null;
        if (free) {
          await ctx.db.patch(row._id, { ...base, ...free });
          return { ok: true as const, state: row.state };
        }
      }
      if (row.state === 'removing') {
        // Nothing of ours is left at the name (only somebody else's): done.
        await ctx.db.patch(row._id, { ...base, state: 'gone', records: [], goneAt: now });
        return { ok: true as const, state: 'gone' as const };
      }
      return await park(ctx, row, 'name_taken', now);
    }
    const attempts = row.attempts + 1;
    if (!o.final && attempts < ADDRESS_NAME_MAX_ATTEMPTS) {
      await ctx.db.patch(row._id, { ...base, attempts, failure: { code: o.code, at: now } });
      return { ok: true as const, state: row.state };
    }
    if (row.state === 'moving' && !o.final) {
      // The move cannot land: the name is taken back from members (removed), and
      // the new address gets a name of its own.
      await ctx.db.patch(row._id, {
        ...base,
        state: 'removing',
        attempts: 0,
        failure: { code: o.code, at: now },
        served: closeServed(row.served, now, 'move_failed'),
      });
      await ctx.db.patch(row.edgeId, { nameWanted: true, updatedAt: now });
      await scheduleEpochIfServing(ctx, row);
      return { ok: true as const, state: 'removing' as const };
    }
    return await park(ctx, { ...row, attempts }, o.code, now);
  },
});

/**
 * Point a name somewhere else (another address, or nowhere: `removing`). A
 * pass in flight is revoked: its settle no longer matches and asks for a fresh
 * pass that reads the zone back after it. Removing starts its own count of
 * tries, so failures while the name was made never cut its removal short.
 */
async function retarget(
  ctx: MutationCtx,
  row: Name,
  patch: Partial<Omit<Name, '_id' | '_creationTime'>>,
  now: number,
) {
  await ctx.db.patch(row._id, {
    ...patch,
    currentOp: undefined,
    ...(patch.state === 'removing' && row.state !== 'removing' ? { attempts: 0 } : {}),
    updatedAt: now,
  });
}

async function park(ctx: MutationCtx, row: Name, code: string, now: number) {
  await ctx.db.patch(row._id, {
    currentOp: undefined,
    state: 'parked',
    attempts: row.attempts,
    failure: { code, at: now },
    updatedAt: now,
  });
  await auditName(ctx, row, 'edge.name.parked', { code });
  if (NAME_SERVES.includes(row.state)) await scheduleEpochIfServing(ctx, row);
  return { ok: true as const, state: 'parked' as const };
}

/** A change to what a published address's members are handed: its origin's epoch moves. */
async function scheduleEpochIfServing(ctx: MutationCtx, row: Pick<Name, 'edgeId' | 'relayId'>) {
  const edge = await ctx.db.get(row.edgeId);
  if (!edge || edge.publication !== 'published') return;
  const origin = await ctx.db.get(row.relayId);
  if (origin) await bumpEpochAndRefresh(ctx, origin);
}

function closeServed(served: Name['served'], now: number, why: string): Name['served'] {
  if (served.length === 0) return served;
  const last = served[served.length - 1]!;
  if (last.until !== undefined) return served;
  return [...served.slice(0, -1), { ...last, until: now, why }];
}

function openServed(served: Name['served'], edgeId: Id<'edges'>, now: number): Name['served'] {
  return [...served, { edgeId, from: now }].slice(-ADDRESS_NAME_HISTORY);
}

async function auditName(
  ctx: MutationCtx,
  row: Name,
  action: string,
  extra: Record<string, unknown> = {},
) {
  const origin = await ctx.db.get(row.relayId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action,
    targetType: 'edge',
    targetId: row.edgeId,
    payload: { relaySlug: origin?.slug, edgeId: row.edgeId, nameId: row._id, ...extra },
  });
}

// --- a replacement takes the replaced address's name ------------------------------------------

/**
 * Called by the publish flip of a replace, in its transaction (`to` already
 * published in `from`'s place). When `mayMoveName` allows it, `from`'s name
 * now serves `to`: members who hold it reach the new address at their next
 * lookup, no refresh needed. The records follow in the next pass, and until
 * then they still point at `from`, which drains and stays up. Any name `to`
 * already had (made while it was a spare) is removed. Otherwise nothing
 * moves: `from`'s name goes with `from`, and `to` keeps (or gets) its own.
 */
export async function moveNameOnReplace(
  ctx: MutationCtx,
  a: {
    from: Edge;
    to: Edge;
    toLane: 'open' | 'trusted';
    now: number;
    rotationId?: Id<'edgeRotations'>;
  },
): Promise<MoveVerdict> {
  const settings = await namesSettingsOf(ctx.db);
  const name = await servingNameOf(ctx.db, a.from._id);
  const eligible = settings.enabled ? await nameZonesOf(ctx.db, settings.zones) : [];
  const verdict = mayMoveName({
    enabled: settings.enabled,
    moveQuietDays: settings.moveQuietDays,
    eligibleZones: eligible.map((z) => z.locationId as string),
    now: a.now,
    name,
    from: { listenerId: a.from.listenerId, lane: edgeLaneOf(a.from) },
    to: {
      listenerId: a.to.listenerId,
      lane: a.toLane,
      layer: a.to.layer ?? 'l4',
      v4: a.to.addresses.v4 ?? null,
    },
  });
  if (!verdict.move || !name) return verdict;
  for (const own of await namesOfEdge(ctx.db, a.to._id)) {
    if (!['creating', 'live'].includes(own.state)) continue;
    await retarget(
      ctx,
      own,
      { state: 'removing', served: closeServed(own.served, a.now, 'replaced') },
      a.now,
    );
    await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: own._id });
  }
  await retarget(
    ctx,
    name,
    {
      edgeId: a.to._id,
      leavingEdgeId: a.from._id,
      state: 'moving',
      moves: name.moves + 1,
      movedAt: a.now,
      served: openServed(closeServed(name.served, a.now, 'moved'), a.to._id, a.now),
    },
    a.now,
  );
  await auditName(ctx, { ...name, edgeId: a.to._id }, 'edge.name.moved', {
    fromEdgeId: a.from._id,
    rotationId: a.rotationId,
  });
  await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: name._id });
  return verdict;
}

/**
 * A replace rolled back (`previous` published again in `current`'s place): a
 * name that moved to `current` in that replace moves back. It still counts as
 * moved, so it does not move again within the quiet window.
 */
export async function moveNameBack(
  ctx: MutationCtx,
  a: { current: Id<'edges'>; previous: Id<'edges'>; now: number },
): Promise<boolean> {
  for (const row of await namesOfEdge(ctx.db, a.current)) {
    if (!NAME_SERVES.includes(row.state)) continue;
    const prior = row.served.at(-2);
    if (!prior || prior.edgeId !== a.previous || prior.why !== 'moved') continue;
    await retarget(
      ctx,
      row,
      {
        edgeId: a.previous,
        leavingEdgeId: a.current,
        state: 'moving',
        served: openServed(closeServed(row.served, a.now, 'rolled_back'), a.previous, a.now),
      },
      a.now,
    );
    await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: row._id });
    return true;
  }
  return false;
}

// --- an address going away: its names first ----------------------------------------------------

/**
 * Before any provider resource of a destroying address is touched, its names
 * go: the address is released back to the provider, and a record still
 * pointing at it could send members to whoever gets it next. Marks the names
 * that serve it `removing` and returns every row that still points at it
 * (removing, or moving away from it); the destroy walk waits while any is
 * left. A parked name never holds the walk (attention says to remove it by
 * hand).
 */
export const retireForDestroy = internalMutation({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }): Promise<Id<'edgeNames'>[]> => {
    const now = Date.now();
    const pending: Id<'edgeNames'>[] = [];
    for (const row of await namesOfEdge(ctx.db, edgeId)) {
      if (ENDED.includes(row.state)) continue;
      if (row.state === 'creating' || row.state === 'live') {
        await retarget(
          ctx,
          row,
          { state: 'removing', served: closeServed(row.served, now, 'destroyed') },
          now,
        );
      } else if (row.state === 'moving') {
        // Moving TO this address while it is destroyed (a rollback kept the old
        // one): take the name back to where it came from instead.
        if (row.leavingEdgeId) {
          const back = await ctx.db.get(row.leavingEdgeId);
          if (back && nameTargetOf(back).kind === 'serve') {
            await retarget(
              ctx,
              row,
              {
                edgeId: row.leavingEdgeId,
                // Its records may still point here: the walk waits for them.
                leavingEdgeId: edgeId,
                served: openServed(closeServed(row.served, now, 'destroyed'), back._id, now),
              },
              now,
            );
            pending.push(row._id);
            continue;
          }
        }
        await retarget(
          ctx,
          row,
          { state: 'removing', served: closeServed(row.served, now, 'destroyed') },
          now,
        );
      }
      pending.push(row._id);
    }
    const leaving = await ctx.db
      .query('edgeNames')
      .withIndex('by_leaving', (q) => q.eq('leavingEdgeId', edgeId))
      .take(20);
    for (const row of leaving)
      if (row.state === 'moving' && !pending.includes(row._id)) pending.push(row._id);
    return pending;
  },
});

/** The rows that still hold a destroying address's walk (see `retireForDestroy`). */
export const pendingForDestroy = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }): Promise<number> => {
    let n = 0;
    for (const row of await namesOfEdge(ctx.db, edgeId))
      if (!ENDED.includes(row.state) && row.state !== 'moving') n++;
    const leaving = await ctx.db
      .query('edgeNames')
      .withIndex('by_leaving', (q) => q.eq('leavingEdgeId', edgeId))
      .take(20);
    return n + leaving.filter((r) => r.state === 'moving').length;
  },
});

// --- the operator's own calls ------------------------------------------------------------------

/**
 * A new name for an address (its name is blocked by DNS somewhere, say): the
 * current one is removed from its zone, members get the IP until the new one
 * is made, then the new one, in another eligible zone when there is one.
 */
export const renew = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if ((edge.layer ?? 'l4') !== 'l4' || !edge.managed)
      throw new ConvexError({
        code: 'edge.name_not_offered',
        message: 'This address takes no name',
      });
    const settings = await namesSettingsOf(ctx.db);
    if (!settings.enabled || (await nameZonesOf(ctx.db, settings.zones)).length === 0)
      throw new ConvexError({ code: 'edge.names_off', message: 'Names for addresses are off' });
    const now = Date.now();
    // The name in use, else the one FCP gave up on: either is removed again
    // (a parked one gets a fresh count of tries) before the new one is made.
    const row =
      (await openNameOf(ctx.db, edgeId)) ??
      (await namesOfEdge(ctx.db, edgeId)).find((r) => r.state === 'parked') ??
      null;
    if (row) {
      await retarget(
        ctx,
        row,
        { state: 'removing', served: closeServed(row.served, now, 'renewed') },
        now,
      );
      await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: row._id });
    }
    await ctx.db.patch(edgeId, { nameWanted: true, updatedAt: now });
    await scheduleEpochIfServing(ctx, { edgeId, relayId: edge.relayId });
    await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { edgeId });
    const origin = await ctx.db.get(edge.relayId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.edge.name.renew',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin?.slug, edgeId, nameId: row?._id },
    });
    return { ok: true as const };
  },
});

// --- upkeep ------------------------------------------------------------------------------------

/**
 * What the reconcile pass works on (`edgeReconcile`): every name being made,
 * moved or removed; a live name whose records no longer match its address
 * (re-addressed, or the address ended); and, of `candidates` (addresses that
 * want a name), those that have none yet.
 */
export const upkeepPlan = internalQuery({
  args: { candidates: v.array(v.id('edges')), limit: v.number() },
  handler: async (ctx, { candidates, limit }) => {
    const nameIds: Id<'edgeNames'>[] = [];
    const now = Date.now();
    for (const state of ['creating', 'moving', 'removing'] as const) {
      const rows = await ctx.db
        .query('edgeNames')
        .withIndex('by_state', (q) => q.eq('state', state))
        .take(limit);
      for (const r of rows) if (!r.currentOp || r.currentOp.expiresAt <= now) nameIds.push(r._id);
    }
    const edgeIds: Id<'edges'>[] = [];
    if (candidates.length > 0 && (await namesEnabledOf(ctx.db))) {
      for (const id of candidates) {
        if (edgeIds.length >= limit) break;
        const edge = await ctx.db.get(id);
        if (!wantsName(edge)) continue;
        if (await openNameOf(ctx.db, id)) continue;
        // A name that gave up while it was being made for it waits for the
        // operator's renew (a parked removal of an older name does not).
        const rows = await namesOfEdge(ctx.db, id);
        if (rows.some((r) => r.state === 'parked' && r.served.at(-1)?.until === undefined))
          continue;
        edgeIds.push(id);
      }
    }
    return { nameIds: nameIds.slice(0, limit), edgeIds };
  },
});

/**
 * One page of live names whose records no longer match their address
 * (re-addressed, or the address ended); the reconcile pass walks every page,
 * so a deployment with many names never leaves one unlooked at.
 */
export const liveDrift = internalQuery({
  args: { cursor: v.union(v.string(), v.null()) },
  handler: async (ctx, { cursor }) => {
    const page = await ctx.db
      .query('edgeNames')
      .withIndex('by_state', (q) => q.eq('state', 'live'))
      .paginate({ cursor, numItems: 200 });
    const nameIds: Id<'edgeNames'>[] = [];
    for (const r of page.page) {
      const target = nameTargetOf(await ctx.db.get(r.edgeId));
      if (target.kind === 'hold') continue;
      const want =
        target.kind === 'remove' ? [] : desiredNameRecords(r.fqdn, target).map((d) => d.content);
      const have = r.records.map((x) => x.content);
      if (want.length !== have.length || want.some((c) => !have.includes(c))) nameIds.push(r._id);
    }
    return { nameIds, cursor: page.isDone ? null : page.continueCursor };
  },
});

/** Whether an address has a name being made or in use (its end must remove it). */
export async function hasOpenName(db: DatabaseReader, edgeId: Id<'edges'>): Promise<boolean> {
  return (await openNameOf(db, edgeId)) !== null;
}

/** Parked names (attention): the operator removes their records by hand or renews them. */
export async function parkedNamesOf(db: DatabaseReader, relayId: Id<'relays'>): Promise<Name[]> {
  return await db
    .query('edgeNames')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId).eq('state', 'parked'))
    .take(20);
}

/** An operator removed a parked name's records by hand: it is closed. */
export const dismissParked = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    const row = (await namesOfEdge(ctx.db, edgeId)).find((r) => r.state === 'parked');
    if (!row) throw new ConvexError({ code: 'not_found', message: 'No name to dismiss' });
    const nameId = row._id;
    const now = Date.now();
    await ctx.db.patch(nameId, { state: 'gone', goneAt: now, records: [], updatedAt: now });
    const origin = await ctx.db.get(row.relayId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.edge.name.dismiss',
      targetType: 'edge',
      targetId: row.edgeId,
      payload: { relaySlug: origin?.slug, edgeId: row.edgeId, nameId },
    });
    return { ok: true as const };
  },
});

/**
 * Before deploying a build without names (docs/edges.md "Deploy notes"): run it
 * with no arguments, again until it answers `done`. Each run first turns the
 * switch off (members get IPs again) and sends every name that still holds
 * records to `removing` (the next passes delete them from their zones); once
 * none is left, it deletes the rows and clears `edges.nameWanted`, a page at a
 * time. A parked name holds it until the operator removes its records by hand
 * and dismisses it.
 */
export const clearForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    const now = Date.now();
    if (await namesEnabledOf(ctx.db)) {
      await upsertSettingRow(ctx, 'edge.names.enabled', 'false');
      for (const r of await ctx.db
        .query('relays')
        .withIndex('by_enabled', (q) => q.eq('enabled', true))
        .collect())
        await ctx.db.patch(r._id, { publicationEpoch: r.publicationEpoch + 1, updatedAt: now });
    }
    // Removing first: a row this run sends to removing is not counted twice.
    let open = 0;
    for (const state of ['removing', 'creating', 'live', 'moving'] as const) {
      const rows = await ctx.db
        .query('edgeNames')
        .withIndex('by_state', (q) => q.eq('state', state))
        .take(100);
      for (const row of rows) {
        open++;
        if (state !== 'removing')
          await retarget(
            ctx,
            row,
            { state: 'removing', served: closeServed(row.served, now, 'rollback') },
            now,
          );
        await ctx.scheduler.runAfter(0, internal.edgeNameOps.work, { nameId: row._id });
      }
    }
    const parked = (
      await ctx.db
        .query('edgeNames')
        .withIndex('by_state', (q) => q.eq('state', 'parked'))
        .take(100)
    ).length;
    if (open > 0 || parked > 0) return { done: false, removing: open, parked };
    for (const row of await ctx.db
      .query('edgeNames')
      .withIndex('by_state', (q) => q.eq('state', 'gone'))
      .take(500))
      await ctx.db.delete(row._id);
    const page = await ctx.db.query('edges').paginate({ cursor: cursor ?? null, numItems: 200 });
    for (const e of page.page)
      if (e.nameWanted !== undefined) await ctx.db.patch(e._id, { nameWanted: undefined });
    // The rest of the edges in pages of their own (this run answers for the first).
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgeNames.clearForRollback, {
        cursor: page.continueCursor,
      });
    return { done: page.isDone, removing: 0, parked: 0 };
  },
});
