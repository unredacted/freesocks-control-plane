/**
 * Country lists (docs/edges.md "Country lists"): community lists of names and
 * ranges that work in one country (allowlists) or are blocked there
 * (blocklists). FCP fetches or takes a pasted copy, keeps each change as a
 * version, and holds a version that looks wrong until a person ticks it.
 * Lists are evidence only: nothing here changes what members get.
 *
 *  - A version is STAGED under its own id (its names and range chunks are
 *    written over several mutations) and PUBLISHED by moving the list's one
 *    `activeVersionId` pointer in a single mutation. Readers only ever follow
 *    that pointer (lib/edges/lists/facts.ts), so they see one version whole.
 *  - An old version's rows are deleted after a grace, so an action that
 *    pinned it while paging can finish.
 *  - Freshness is `confirmedAt`: when the source last said what the active
 *    version says, whether that made a new version or not.
 *
 * The fetch itself (pinned to the addresses it checked) is in
 * countryListOps.ts. No list, source or address is named anywhere: lists are
 * data.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalMutation,
  internalQuery,
  type DatabaseReader,
  type MutationCtx,
} from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat } from './cronHeartbeat';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { addressFamily, isPublicIpLiteral } from './lib/edges/ip';
import { normalizeAsn } from './lib/edges/networks';
import { siteOf } from './lib/edges/sni/hunt/sources';
import { holdReasons, type ListMeasure } from './lib/edges/lists/guards';
import { isFresh, lookupEntries, MAX_LISTS } from './lib/edges/lists/facts';
import { bumpFactsGen } from './countryListFacts';
import { feedViews, startFeedRuns, sweepFeeds } from './countryListFeeds';
import {
  MAX_LIST_NETWORKS,
  UPLOAD_MAX_BYTES,
  UPLOAD_PART_BYTES,
} from '../src/shared/contracts/countryLists';

type List = Doc<'countryLists'>;
type Version = Doc<'countryListVersions'>;
type ListId = Id<'countryLists'>;
type VersionId = Id<'countryListVersions'>;

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Parts a paste may have (a full one is about a hundred). */
const MAX_UPLOAD_PARTS = 200;
const UPLOAD_TTL_MS = HOUR;
/** How early a list counts as due for the hourly pass. */
const DUE_SLACK_MS = 10 * MIN;
/** An ingest marker older than this is a crashed run, not a running one. */
const INGEST_STALE_MS = 15 * MIN;
/** A staging version older than this is a crashed run. */
const STAGING_STALE_MS = HOUR;
/** How long an ended version's rows stay for a reader that pinned it. */
export const CLEANUP_GRACE_MS = 10 * MIN;
const VERSION_RETENTION_MS = 180 * DAY;
/** Version rows kept per list (the newest), whatever their age. */
const MAX_VERSION_ROWS = 50;
const HISTORY_RETENTION_MS = 180 * DAY;
const MAX_URL_CHARS = 2048;
const MEMBERS_PAGE = 500;
/** Chunks are up to 512 KiB each: a page stays well inside one execution's read limit. */
const CHUNKS_PAGE = 8;
const SWEEP_PAGE = 50;

const actor = { actorAdminId: v.optional(v.id('adminUsers')) };
const regimeV = v.union(v.literal('allowlist'), v.literal('blocklist'));
const sourceV = v.union(
  v.object({ kind: v.literal('url'), url: v.string() }),
  v.object({ kind: v.literal('paste') }),
);
const countsV = v.object({
  entries: v.number(),
  names: v.number(),
  wildcards: v.number(),
  v4Ranges: v.number(),
  v6Ranges: v.number(),
  v4: v.number(),
  v6: v.number(),
  invalid: v.number(),
  nonPublic: v.number(),
  tooBroad: v.number(),
  capped: v.number(),
});
const diffPartV = v.object({ added: v.number(), removed: v.number(), common: v.number() });
const diffV = v.object({ names: diffPartV, v4: diffPartV, v6: diffPartV });

function refuse(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

// --- validation ------------------------------------------------------------------------------------

function cleanLabel(raw: string): string {
  const label = raw.trim().replace(/\s+/g, ' ').slice(0, 80);
  if (!label) refuse('validation', 'A list needs a name');
  return label;
}

function cleanCountry(raw: string): string {
  const c = raw.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) refuse('validation', 'A country is a two-letter code, like RU');
  return c;
}

function cleanNetworks(raw: ReadonlyArray<number | string>): number[] {
  const out = [...new Set(raw.map(normalizeAsn))];
  if (out.some((n) => n === null)) refuse('edge.list.bad_asn', 'Each network is an ASN number');
  if (out.length > MAX_LIST_NETWORKS)
    refuse('edge.list.bad_asn', `A list covers at most ${MAX_LIST_NETWORKS} networks`);
  return (out as number[]).sort((a, b) => a - b);
}

/**
 * A source address FCP may fetch: https on the standard port, no user name or
 * password, and no private address written out. Names are checked again at
 * fetch time, against every address they resolve to.
 */
export function cleanSourceUrl(raw: string): string {
  const t = raw.trim();
  if (t.length > MAX_URL_CHARS) refuse('edge.list.bad_url', 'That address is too long');
  let u: URL;
  try {
    u = new URL(t);
  } catch {
    refuse('edge.list.bad_url', 'That is not a web address');
  }
  if (u.protocol !== 'https:') refuse('edge.list.bad_url', 'A list address starts with https://');
  if (u.username || u.password)
    refuse('edge.list.bad_url', 'A list address carries no user name or password');
  if (u.port !== '' && u.port !== '443')
    refuse('edge.list.bad_url', 'A list address uses the standard https port');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) refuse('edge.list.bad_url', 'That is not a web address');
  if (addressFamily(host) && !isPublicIpLiteral(host))
    refuse('edge.list.bad_url', 'A list address cannot be a private address');
  u.hash = '';
  return u.toString();
}

function cleanHours(raw: number | undefined, dflt: number): number {
  const n = raw ?? dflt;
  if (!Number.isInteger(n) || n < 1 || n > 168) refuse('validation', 'Fetch every 1 to 168 hours');
  return n;
}

async function listOf(db: DatabaseReader, listId: ListId): Promise<List> {
  const list = await db.get(listId);
  if (!list) refuse('not_found', 'No such list');
  return list;
}

async function audit(
  ctx: MutationCtx,
  action: string,
  actorAdminId: Id<'adminUsers'> | undefined,
  payload: Record<string, unknown>,
) {
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'country_list',
    payload,
  });
}

// --- views ------------------------------------------------------------------------------------------

const iso = (t: number | undefined) => (t ? new Date(t).toISOString() : null);

function versionView(ver: Version) {
  return {
    id: ver._id as string,
    at: new Date(ver.at).toISOString(),
    source: ver.source,
    status: ver.status,
    heldReasons: ver.heldReasons,
    counts: ver.counts,
    diff: ver.diff ?? null,
    samples: ver.samples,
    failure: ver.failure ?? null,
    decidedAt: iso(ver.decidedAt),
    byPerson: !!ver.decidedBy,
  };
}

async function listView(db: DatabaseReader, list: List, staleDays: number, now: number) {
  const active = list.activeVersionId ? await db.get(list.activeVersionId) : null;
  const held = list.heldVersionId ? await db.get(list.heldVersionId) : null;
  const busy = !!list.ingest && now - list.ingest.at < INGEST_STALE_MS;
  return {
    id: list._id as string,
    label: list.label,
    country: list.country,
    regime: list.regime,
    networks: list.networks,
    source: list.source,
    fetchEveryHours: list.fetchEveryHours,
    enabled: list.enabled,
    active: active ? versionView(active) : null,
    held: held ? versionView(held) : null,
    busy: busy ? (list.ingest?.kind ?? null) : null,
    lastFetch: list.lastFetch
      ? { at: new Date(list.lastFetch.at).toISOString(), outcome: list.lastFetch.outcome }
      : null,
    confirmedAt: iso(list.confirmedAt),
    fresh: isFresh(list, staleDays, now),
    feeds: await feedViews(db, list),
  };
}

export const list = internalQuery({
  args: { country: v.optional(v.string()) },
  handler: async (ctx, a) => {
    const now = Date.now();
    const cfg = await resolveEdgeConfig(ctx.db);
    const rows = a.country
      ? await ctx.db
          .query('countryLists')
          .withIndex('by_country', (q) => q.eq('country', a.country!.toUpperCase()))
          .take(MAX_LISTS)
      : await ctx.db.query('countryLists').take(MAX_LISTS);
    const lists = [];
    for (const l of rows) lists.push(await listView(ctx.db, l, cfg.lists.staleDays, now));
    lists.sort((x, y) => x.country.localeCompare(y.country) || x.label.localeCompare(y.label));
    return {
      enabled: cfg.lists.enabled,
      staleDays: cfg.lists.staleDays,
      defaultFetchHours: cfg.lists.defaultFetchHours,
      lists,
    };
  },
});

export const detail = internalQuery({
  args: { listId: v.id('countryLists') },
  handler: async (ctx, a) => {
    const now = Date.now();
    const cfg = await resolveEdgeConfig(ctx.db);
    const list = await listOf(ctx.db, a.listId);
    const versions = await ctx.db
      .query('countryListVersions')
      .withIndex('by_list_at', (q) => q.eq('listId', list._id))
      .order('desc')
      .take(20);
    return {
      enabled: cfg.lists.enabled,
      staleDays: cfg.lists.staleDays,
      list: await listView(ctx.db, list, cfg.lists.staleDays, now),
      versions: versions.map(versionView),
    };
  },
});

/**
 * Entries one lookup takes. An address costs one index read per list (up to
 * 50), and one query may read at most 4,096 index ranges: 50 x 50 stays well
 * inside, with room for the config and the lists.
 */
export const MAX_LOOKUP_ENTRIES = 50;

/** The lookup box: which lists hold each name or address. */
export const lookup = internalQuery({
  args: { entries: v.array(v.string()) },
  handler: async (ctx, a) => {
    if (a.entries.length > MAX_LOOKUP_ENTRIES)
      refuse('validation', `Look up at most ${MAX_LOOKUP_ENTRIES} entries at once`);
    const results = await lookupEntries(ctx.db, a.entries, Date.now());
    return {
      results: results.map((r) => ({
        entry: r.entry,
        kind: r.kind,
        lists: r.facts.map((f) => ({
          id: f.listId as string,
          label: f.label,
          country: f.country,
          regime: f.regime,
          how: f.how,
          enabled: f.enabled,
          fresh: f.fresh,
        })),
      })),
    };
  },
});

// --- writes -------------------------------------------------------------------------------------------

export const create = internalMutation({
  args: {
    label: v.string(),
    country: v.string(),
    regime: regimeV,
    networks: v.optional(v.array(v.union(v.number(), v.string()))),
    source: sourceV,
    fetchEveryHours: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    if ((await ctx.db.query('countryLists').take(MAX_LISTS)).length >= MAX_LISTS)
      refuse('edge.list.cap', `A deployment follows at most ${MAX_LISTS} lists`);
    const cfg = await resolveEdgeConfig(ctx.db);
    const source =
      a.source.kind === 'url'
        ? { kind: 'url' as const, url: cleanSourceUrl(a.source.url) }
        : { kind: 'paste' as const };
    const country = cleanCountry(a.country);
    const id = await ctx.db.insert('countryLists', {
      label: cleanLabel(a.label),
      country,
      regime: a.regime,
      networks: cleanNetworks(a.networks ?? []),
      source,
      fetchEveryHours: cleanHours(a.fetchEveryHours, cfg.lists.defaultFetchHours),
      enabled: a.enabled ?? true,
      updatedAt: Date.now(),
    });
    await audit(ctx, 'admin.edge.list.create', a.actorAdminId, {
      listId: id,
      country,
      regime: a.regime,
      source: source.kind,
    });
    return { id: id as string };
  },
});

export const update = internalMutation({
  args: {
    listId: v.id('countryLists'),
    label: v.optional(v.string()),
    country: v.optional(v.string()),
    regime: v.optional(regimeV),
    networks: v.optional(v.array(v.union(v.number(), v.string()))),
    url: v.optional(v.string()),
    fetchEveryHours: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const list = await listOf(ctx.db, a.listId);
    const patch: Partial<List> = { updatedAt: Date.now() };
    const changed: string[] = [];
    if (a.label !== undefined) {
      patch.label = cleanLabel(a.label);
      changed.push('label');
    }
    if (a.country !== undefined) {
      patch.country = cleanCountry(a.country);
      changed.push('country');
    }
    if (a.regime !== undefined) {
      patch.regime = a.regime;
      changed.push('regime');
    }
    if (a.networks !== undefined) {
      patch.networks = cleanNetworks(a.networks);
      changed.push('networks');
    }
    if (a.url !== undefined) {
      if (list.source.kind !== 'url')
        refuse('edge.list.not_url', 'A pasted list has no address to change');
      const url = cleanSourceUrl(a.url);
      if (url !== list.source.url) {
        patch.source = { kind: 'url', url };
        // A new source: nothing it said is known yet. It is due at once, the
        // version in use is unconfirmed (stale) until it says the same, and a
        // read of the old address still running is dropped by its generation.
        patch.sourceGen = (list.sourceGen ?? 0) + 1;
        patch.lastFetch = undefined;
        patch.confirmedAt = undefined;
        patch.ingest = undefined;
        changed.push('url');
      }
    }
    if (a.fetchEveryHours !== undefined) {
      patch.fetchEveryHours = cleanHours(a.fetchEveryHours, list.fetchEveryHours);
      changed.push('fetchEveryHours');
    }
    if (a.enabled !== undefined) {
      patch.enabled = a.enabled;
      changed.push('enabled');
    }
    await ctx.db.patch(list._id, patch);
    // What evidence reads moves with these: every stored fact is looked at again.
    if (changed.some((c) => ['country', 'regime', 'enabled', 'url'].includes(c)))
      await bumpFactsGen(ctx);
    await audit(ctx, 'admin.edge.list.update', a.actorAdminId, {
      listId: list._id,
      country: patch.country ?? list.country,
      regime: patch.regime ?? list.regime,
      changed,
    });
    return { ok: true as const };
  },
});

/**
 * Remove a list. The row goes at once, so nothing can read it any more; its
 * versions, uploads and history follow in pages.
 */
export const remove = internalMutation({
  args: { listId: v.id('countryLists'), ...actor },
  handler: async (ctx, a) => {
    const list = await listOf(ctx.db, a.listId);
    await ctx.db.delete(list._id);
    await ctx.scheduler.runAfter(0, internal.countryLists.purgeList, { listId: list._id });
    if (list.activeVersionId) await bumpFactsGen(ctx);
    await audit(ctx, 'admin.edge.list.delete', a.actorAdminId, {
      listId: list._id,
      country: list.country,
    });
    return { ok: true as const };
  },
});

/** A removed list's rows, a page at a time: versions (each dropped in its own chain), uploads, history. */
export const purgeList = internalMutation({
  args: { listId: v.id('countryLists') },
  handler: async (ctx, { listId }) => {
    if (await ctx.db.get(listId)) return;
    const now = Date.now();
    const versions = await ctx.db
      .query('countryListVersions')
      .withIndex('by_list_at', (q) => q.eq('listId', listId))
      .take(SWEEP_PAGE);
    for (const ver of versions) {
      if (ver.cleanedAt) await ctx.db.delete(ver._id);
      else {
        if (!['superseded', 'rejected', 'failed'].includes(ver.status))
          await ctx.db.patch(ver._id, { status: 'failed', failure: 'list_removed', endedAt: now });
        await ctx.scheduler.runAfter(0, internal.countryLists.dropVersion, { versionId: ver._id });
      }
    }
    const uploads = await ctx.db
      .query('countryListUploads')
      .withIndex('by_list', (q) => q.eq('listId', listId))
      .take(SWEEP_PAGE);
    for (const u of uploads)
      await ctx.scheduler.runAfter(0, internal.countryLists.purgeUpload, { uploadId: u._id });
    const history = await ctx.db
      .query('countryListNameHistory')
      .withIndex('by_list_name', (q) => q.eq('listId', listId))
      .take(MEMBERS_PAGE);
    for (const h of history) await ctx.db.delete(h._id);
    const runs = await ctx.db
      .query('countryListFeedRuns')
      .withIndex('by_list_feed', (q) => q.eq('listId', listId))
      .take(MEMBERS_PAGE);
    for (const r of runs) await ctx.db.delete(r._id);
    const uncleaned = versions.some((ver) => !ver.cleanedAt);
    if (
      versions.length === SWEEP_PAGE ||
      history.length === MEMBERS_PAGE ||
      runs.length === MEMBERS_PAGE ||
      uncleaned
    )
      // Dropped versions stamp `cleanedAt` after the grace; come back for their rows then.
      await ctx.scheduler.runAfter(
        uncleaned ? CLEANUP_GRACE_MS + MIN : 0,
        internal.countryLists.purgeList,
        {
          listId,
        },
      );
  },
});

// --- uploads (a paste in parts) -----------------------------------------------------------------------

const utf8Bytes = (s: string) => new TextEncoder().encode(s).length;

/** A paste starts: any upload still open for the list is replaced. */
export const startUpload = internalMutation({
  args: { listId: v.id('countryLists'), ...actor },
  handler: async (ctx, a) => {
    const list = await listOf(ctx.db, a.listId);
    if (list.source.kind !== 'paste')
      refuse('edge.list.not_paste', 'This list is fetched from its address; it takes no paste');
    for (const old of await ctx.db
      .query('countryListUploads')
      .withIndex('by_list', (q) => q.eq('listId', list._id))
      .take(SWEEP_PAGE))
      if (!old.finished) {
        await ctx.db.patch(old._id, { finished: true });
        await ctx.scheduler.runAfter(0, internal.countryLists.purgeUpload, { uploadId: old._id });
      }
    const id = await ctx.db.insert('countryListUploads', {
      listId: list._id,
      at: Date.now(),
      parts: 0,
      bytes: 0,
      finished: false,
    });
    return { uploadId: id as string, partBytes: UPLOAD_PART_BYTES, maxBytes: UPLOAD_MAX_BYTES };
  },
});

async function openUpload(ctx: MutationCtx, listId: ListId, uploadId: Id<'countryListUploads'>) {
  const u = await ctx.db.get(uploadId);
  if (!u || u.listId !== listId) refuse('not_found', 'No such upload');
  if (u.finished) refuse('edge.list.upload_closed', 'That upload is finished');
  if (Date.now() - u.at > UPLOAD_TTL_MS)
    refuse('edge.list.upload_closed', 'That upload ran out of time; start again');
  return u;
}

/** One part, in order. Sending the same part again is a no-op, so a retried request is harmless. */
export const addUploadPart = internalMutation({
  args: {
    listId: v.id('countryLists'),
    uploadId: v.id('countryListUploads'),
    index: v.number(),
    text: v.string(),
  },
  handler: async (ctx, a) => {
    const u = await openUpload(ctx, a.listId, a.uploadId);
    if (utf8Bytes(JSON.stringify(a.text)) > UPLOAD_PART_BYTES)
      refuse('edge.list.part_too_large', 'That part is too large');
    if (a.index < u.parts) {
      const same = await ctx.db
        .query('countryListUploadParts')
        .withIndex('by_upload_index', (q) => q.eq('uploadId', u._id).eq('index', a.index))
        .unique();
      if (same?.text === a.text) return { parts: u.parts, bytes: u.bytes };
      refuse('edge.list.part_order', 'That part was already sent with other text');
    }
    if (a.index !== u.parts) refuse('edge.list.part_order', 'Parts go in order');
    if (u.parts >= MAX_UPLOAD_PARTS)
      refuse('edge.list.upload_too_large', 'Too many parts; send larger ones');
    const bytes = u.bytes + utf8Bytes(a.text);
    if (bytes > UPLOAD_MAX_BYTES)
      refuse(
        'edge.list.upload_too_large',
        'A paste holds at most 4 MB; give the list an address instead',
      );
    await ctx.db.insert('countryListUploadParts', {
      uploadId: u._id,
      index: a.index,
      text: a.text,
    });
    await ctx.db.patch(u._id, { parts: u.parts + 1, bytes });
    return { parts: u.parts + 1, bytes };
  },
});

/** The paste is complete: read it into a version. */
export const finishUpload = internalMutation({
  args: { listId: v.id('countryLists'), uploadId: v.id('countryListUploads'), ...actor },
  handler: async (ctx, a) => {
    const u = await openUpload(ctx, a.listId, a.uploadId);
    if (u.parts === 0) refuse('edge.list.upload_empty', 'Nothing was pasted');
    const list = await listOf(ctx.db, a.listId);
    await claimIngest(ctx, list, 'upload');
    await ctx.db.patch(u._id, { finished: true });
    await ctx.scheduler.runAfter(0, internal.countryListOps.ingest, {
      listId: list._id,
      uploadId: u._id,
    });
    await audit(ctx, 'admin.edge.list.upload', a.actorAdminId, {
      listId: list._id,
      parts: u.parts,
      bytes: u.bytes,
    });
    return { ok: true as const };
  },
});

export const uploadText = internalQuery({
  args: { uploadId: v.id('countryListUploads') },
  handler: async (ctx, { uploadId }) => {
    const parts = await ctx.db
      .query('countryListUploadParts')
      .withIndex('by_upload_index', (q) => q.eq('uploadId', uploadId))
      .take(MAX_UPLOAD_PARTS);
    return parts.map((p) => p.text).join('');
  },
});

export const purgeUpload = internalMutation({
  args: { uploadId: v.id('countryListUploads') },
  handler: async (ctx, { uploadId }) => {
    const parts = await ctx.db
      .query('countryListUploadParts')
      .withIndex('by_upload_index', (q) => q.eq('uploadId', uploadId))
      .take(SWEEP_PAGE);
    for (const p of parts) await ctx.db.delete(p._id);
    if (parts.length === SWEEP_PAGE)
      await ctx.scheduler.runAfter(0, internal.countryLists.purgeUpload, { uploadId });
    else if (await ctx.db.get(uploadId)) await ctx.db.delete(uploadId);
  },
});

// --- ingest bookkeeping (the action is countryListOps.ingest) ---------------------------------------

/** One ingest at a time per list: a marker newer than 15 minutes means one is running. */
async function claimIngest(ctx: MutationCtx, list: List, kind: 'fetch' | 'upload') {
  const now = Date.now();
  if (list.ingest && now - list.ingest.at < INGEST_STALE_MS)
    refuse('edge.list.busy', 'This list is being read now; try again in a minute');
  await ctx.db.patch(list._id, { ingest: { at: now, kind } });
}

/** Fetch now (an operator, or the cron for a list that is due). */
export const requestFetch = internalMutation({
  args: { listId: v.id('countryLists'), ...actor },
  handler: async (ctx, a) => {
    const list = await listOf(ctx.db, a.listId);
    if (list.source.kind !== 'url')
      refuse('edge.list.not_url', 'A pasted list has no address to fetch; paste it again');
    await claimIngest(ctx, list, 'fetch');
    await ctx.scheduler.runAfter(0, internal.countryListOps.ingest, { listId: list._id });
    if (a.actorAdminId)
      await audit(ctx, 'admin.edge.list.fetch', a.actorAdminId, { listId: list._id });
    return { ok: true as const };
  },
});

/** The lists whose source is due (cron `country-lists`), oldest fetch first. */
export const dueForFetch = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    if (!cfg.lists.enabled) return [];
    return (await ctx.db.query('countryLists').take(MAX_LISTS))
      .filter(
        (l) =>
          l.enabled &&
          l.source.kind === 'url' &&
          !(l.ingest && now - l.ingest.at < INGEST_STALE_MS) &&
          // A little early is due: a read that ended just after the last pass
          // would otherwise wait a whole extra pass.
          (!l.lastFetch || now - l.lastFetch.at >= l.fetchEveryHours * HOUR - DUE_SLACK_MS),
      )
      .sort((x, y) => (x.lastFetch?.at ?? 0) - (y.lastFetch?.at ?? 0))
      .slice(0, limit)
      .map((l) => l._id);
  },
});

/** What an ingest needs to know before it reads anything. */
export const ingestContext = internalQuery({
  args: { listId: v.id('countryLists') },
  handler: async (ctx, { listId }) => {
    const list = await ctx.db.get(listId);
    if (!list) return null;
    const active = list.activeVersionId ? await ctx.db.get(list.activeVersionId) : null;
    const held = list.heldVersionId ? await ctx.db.get(list.heldVersionId) : null;
    // A waiting version whose base is no longer the one in use cannot be
    // used: the same content again is read and staged anew, against today's.
    const heldLive =
      held && (held.basedOn ?? null) === (list.activeVersionId ?? null) ? held : null;
    // Validators are sent only while the version they describe is in use or can still be.
    const of = list.lastFetch?.validatorsOf;
    const describes =
      of && of === active?._id ? 'active' : of && of === heldLive?._id ? 'held' : null;
    return {
      source: list.source,
      sourceGen: list.sourceGen ?? 0,
      etag: describes ? (list.lastFetch?.etag ?? null) : null,
      lastModified: describes ? (list.lastFetch?.lastModified ?? null) : null,
      describes,
      activeSha: active?.sha256 ?? null,
      heldSha: heldLive?.sha256 ?? null,
    };
  },
});

/**
 * An ingest that made no version: the source said what the active version
 * says (`unchanged`, or `not_modified` for a 304 on its validators: it is
 * confirmed), it repeats the version already waiting (`held_same`), another
 * run is writing (`busy`), or it failed (a short code). `validators` says
 * which version this answer's validators describe; `keep` leaves them.
 */
export const recordIngest = internalMutation({
  args: {
    listId: v.id('countryLists'),
    outcome: v.string(),
    confirmed: v.boolean(),
    validators: v.union(v.literal('active'), v.literal('held'), v.literal('keep')),
    etag: v.optional(v.string()),
    lastModified: v.optional(v.string()),
    failedVersionId: v.optional(v.id('countryListVersions')),
    sourceGen: v.number(),
  },
  handler: async (ctx, a) => {
    const list = await ctx.db.get(a.listId);
    if (!list) return;
    const now = Date.now();
    if ((list.sourceGen ?? 0) !== a.sourceGen) {
      // The address changed while this ran: its answer is the old source's.
      if (a.failedVersionId) await failStaging(ctx, list, a.failedVersionId, 'source_changed');
      return;
    }
    const patch: Partial<List> = { ingest: undefined, updatedAt: now };
    const kind = list.ingest?.kind ?? (list.source.kind === 'url' ? 'fetch' : 'upload');
    if (kind === 'fetch') {
      const of =
        a.validators === 'active'
          ? list.activeVersionId
          : a.validators === 'held'
            ? list.heldVersionId
            : list.lastFetch?.validatorsOf;
      const etag = a.validators === 'keep' ? list.lastFetch?.etag : a.etag;
      const lastModified = a.validators === 'keep' ? list.lastFetch?.lastModified : a.lastModified;
      patch.lastFetch = {
        at: now,
        outcome: a.outcome,
        ...(of && (etag || lastModified)
          ? {
              ...(etag ? { etag } : {}),
              ...(lastModified ? { lastModified } : {}),
              validatorsOf: of,
            }
          : {}),
      };
    }
    if (a.confirmed && list.activeVersionId) patch.confirmedAt = now;
    await ctx.db.patch(list._id, patch);
    if (a.failedVersionId) await failStaging(ctx, list, a.failedVersionId, a.outcome);
    const quiet = ['unchanged', 'not_modified', 'held_same', 'busy'];
    if (!quiet.includes(a.outcome))
      await audit(ctx, 'edge.list.failed', undefined, { listId: list._id, outcome: a.outcome });
  },
});

/** Fail a version still being written, and free the list's staging pointer if it is that one. */
async function failStaging(ctx: MutationCtx, list: List, versionId: VersionId, failure: string) {
  const ver = await ctx.db.get(versionId);
  if (ver?.status === 'staging') {
    await ctx.db.patch(ver._id, { status: 'failed', failure, endedAt: Date.now() });
    await scheduleDrop(ctx, ver._id);
  }
  if (list.stagingVersionId === versionId)
    await ctx.db.patch(list._id, { stagingVersionId: undefined });
}

/**
 * Start writing a version. Null when another version is being written (and is
 * not stale), or the source changed since the read began; a stale staging is
 * failed here so this one can go on.
 */
export const stageBegin = internalMutation({
  args: {
    listId: v.id('countryLists'),
    sha256: v.string(),
    source: v.union(v.literal('fetch'), v.literal('upload')),
    counts: countsV,
    samples: v.array(v.string()),
    sourceGen: v.number(),
  },
  handler: async (ctx, a) => {
    const list = await ctx.db.get(a.listId);
    if (!list || (list.sourceGen ?? 0) !== a.sourceGen) return null;
    const now = Date.now();
    if (list.stagingVersionId) {
      const cur = await ctx.db.get(list.stagingVersionId);
      if (cur?.status === 'staging' && now - cur.at < STAGING_STALE_MS) return null;
      if (cur?.status === 'staging') {
        await ctx.db.patch(cur._id, { status: 'failed', failure: 'stale', endedAt: now });
        await scheduleDrop(ctx, cur._id);
      }
    }
    const versionId = await ctx.db.insert('countryListVersions', {
      listId: list._id,
      at: now,
      sha256: a.sha256,
      ...(list.activeVersionId ? { basedOn: list.activeVersionId } : {}),
      source: a.source,
      status: 'staging',
      heldReasons: [],
      counts: a.counts,
      samples: a.samples.slice(0, 5).map((s) => s.slice(0, 80)),
    });
    await ctx.db.patch(list._id, { stagingVersionId: versionId });
    return { versionId, basedOn: list.activeVersionId ?? null };
  },
});

async function staging(ctx: MutationCtx, versionId: VersionId): Promise<Version> {
  const ver = await ctx.db.get(versionId);
  if (!ver || ver.status !== 'staging')
    refuse('edge.list.not_staging', 'That version is not being written');
  return ver;
}

export const stageChunk = internalMutation({
  args: {
    versionId: v.id('countryListVersions'),
    family: v.union(v.literal('v4'), v.literal('v6')),
    index: v.number(),
    firstLo: v.string(),
    text: v.string(),
  },
  handler: async (ctx, a) => {
    await staging(ctx, a.versionId);
    await ctx.db.insert('countryListChunks', {
      versionId: a.versionId,
      family: a.family,
      index: a.index,
      firstLo: a.firstLo,
      text: a.text,
    });
  },
});

/** A batch of names; returns how many the version it is based on holds too (the name diff). */
export const stageNames = internalMutation({
  args: {
    versionId: v.id('countryListVersions'),
    names: v.array(v.object({ name: v.string(), wildcard: v.boolean() })),
  },
  handler: async (ctx, a) => {
    const ver = await staging(ctx, a.versionId);
    let common = 0;
    for (const n of a.names) {
      await ctx.db.insert('countryListMembers', {
        versionId: ver._id,
        name: n.name,
        site: siteOf(n.name),
        wildcard: n.wildcard,
      });
      if (!ver.basedOn) continue;
      const before = await ctx.db
        .query('countryListMembers')
        .withIndex('by_version_name', (q) => q.eq('versionId', ver.basedOn!).eq('name', n.name))
        .take(2);
      if (before.some((b) => b.wildcard === n.wildcard)) common++;
    }
    return { common };
  },
});

/** A version's range chunks in order, a page at a time (for the next version's diff). */
export const versionChunks = internalQuery({
  args: {
    versionId: v.id('countryListVersions'),
    family: v.union(v.literal('v4'), v.literal('v6')),
    after: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const ver = await ctx.db.get(a.versionId);
    // Gone, or cleaned: the caller pinned a version that has ended past its grace.
    if (!ver || ver.cleanedAt) return null;
    const page = await ctx.db
      .query('countryListChunks')
      .withIndex('by_version_family_lo', (q) =>
        a.after === undefined
          ? q.eq('versionId', a.versionId).eq('family', a.family)
          : q.eq('versionId', a.versionId).eq('family', a.family).gt('firstLo', a.after),
      )
      .take(4);
    return {
      texts: page.map((c) => c.text),
      last: page.at(-1)?.firstLo ?? null,
      done: page.length < 4,
    };
  },
});

/** A version's counts (the base a new version's diff is worked out against). */
export const versionCounts = internalQuery({
  args: { versionId: v.id('countryListVersions') },
  handler: async (ctx, { versionId }) => (await ctx.db.get(versionId))?.counts ?? null,
});

const measureOf = (c: Version['counts']): ListMeasure => ({
  names: c.names + c.wildcards,
  v4: c.v4,
  v6: c.v6,
});

async function scheduleDrop(ctx: MutationCtx, versionId: VersionId) {
  await ctx.scheduler.runAfter(CLEANUP_GRACE_MS, internal.countryLists.dropVersion, { versionId });
}

/**
 * Make a version the list's one active version: a single pointer move. The
 * one it replaces ends; its rows go after the grace.
 */
async function publish(
  ctx: MutationCtx,
  list: List,
  ver: Version,
  actorAdminId: Id<'adminUsers'> | undefined,
) {
  const now = Date.now();
  await ctx.db.patch(ver._id, {
    status: 'active',
    ...(actorAdminId ? { decidedBy: actorAdminId, decidedAt: now } : {}),
  });
  if (list.activeVersionId && list.activeVersionId !== ver._id) {
    await ctx.db.patch(list.activeVersionId, { status: 'superseded', endedAt: now });
    await scheduleDrop(ctx, list.activeVersionId);
  }
  await ctx.db.patch(list._id, {
    activeVersionId: ver._id,
    // The source said this when the version was read (a held one may be ticked days later).
    confirmedAt: Math.max(ver.at, list.confirmedAt ?? 0),
    ...(list.heldVersionId === ver._id ? { heldVersionId: undefined } : {}),
    ...(list.stagingVersionId === ver._id ? { stagingVersionId: undefined } : {}),
    updatedAt: now,
  });
  await ctx.scheduler.runAfter(0, internal.countryLists.afterPublish, { versionId: ver._id });
  await audit(ctx, 'edge.list.published', undefined, {
    listId: list._id,
    versionId: ver._id,
    country: list.country,
    regime: list.regime,
    names: ver.counts.names + ver.counts.wildcards,
    v4: ver.counts.v4Ranges,
    v6: ver.counts.v6Ranges,
    by: actorAdminId ? 'person' : 'auto',
  });
}

/**
 * Every row of a version is written: publish it, or hold it for a person when
 * it looks like a broken or replaced source. A version whose base is no longer
 * the active one fails; the next ingest starts again from the new base.
 */
export const stageFinish = internalMutation({
  args: {
    versionId: v.id('countryListVersions'),
    diff: diffV,
    etag: v.optional(v.string()),
    lastModified: v.optional(v.string()),
    sourceGen: v.number(),
  },
  handler: async (ctx, a) => {
    const ver = await staging(ctx, a.versionId);
    const list = await ctx.db.get(ver.listId);
    if (!list) return { outcome: 'gone' as const };
    if ((list.sourceGen ?? 0) !== a.sourceGen) {
      // Read from the address before it changed: never published or held.
      await failStaging(ctx, list, ver._id, 'source_changed');
      return { outcome: 'source_changed' as const };
    }
    const now = Date.now();
    const fetchPart =
      ver.source === 'fetch'
        ? (outcome: string) => ({
            lastFetch: {
              at: now,
              outcome,
              ...(a.etag ? { etag: a.etag } : {}),
              ...(a.lastModified ? { lastModified: a.lastModified } : {}),
              ...(a.etag || a.lastModified ? { validatorsOf: ver._id } : {}),
            },
          })
        : () => ({});
    if (
      list.stagingVersionId !== ver._id ||
      (list.activeVersionId ?? null) !== (ver.basedOn ?? null)
    ) {
      await ctx.db.patch(ver._id, { status: 'failed', failure: 'stale_base', endedAt: now });
      await scheduleDrop(ctx, ver._id);
      await ctx.db.patch(list._id, {
        ...(list.stagingVersionId === ver._id ? { stagingVersionId: undefined } : {}),
        ingest: undefined,
        ...fetchPart('stale_base'),
      });
      return { outcome: 'stale' as const };
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    const base = ver.basedOn ? await ctx.db.get(ver.basedOn) : null;
    const reasons = holdReasons({
      previous: base ? measureOf(base.counts) : null,
      next: measureOf(ver.counts),
      common: { names: a.diff.names.common, v4: a.diff.v4.common, v6: a.diff.v6.common },
      entries: ver.counts.entries,
      invalid: ver.counts.invalid,
      tooBroad: ver.counts.tooBroad,
      capped: ver.counts.capped,
      jumpFactor: cfg.lists.jumpFactor,
      minOverlap: cfg.lists.minOverlap,
    });
    await ctx.db.patch(ver._id, { diff: a.diff, heldReasons: reasons });
    await ctx.db.patch(list._id, {
      ingest: undefined,
      ...fetchPart(reasons.length ? 'held' : 'published'),
    });
    if (reasons.length === 0) {
      await publish(ctx, (await ctx.db.get(list._id))!, (await ctx.db.get(ver._id))!, undefined);
      return { outcome: 'published' as const };
    }
    // Hold it; a version already waiting is replaced by this newer one.
    if (list.heldVersionId) {
      const old = await ctx.db.get(list.heldVersionId);
      if (old?.status === 'held') {
        await ctx.db.patch(old._id, { status: 'rejected', failure: 'replaced', endedAt: now });
        await scheduleDrop(ctx, old._id);
      }
    }
    await ctx.db.patch(ver._id, { status: 'held' });
    await ctx.db.patch(list._id, {
      heldVersionId: ver._id,
      stagingVersionId: undefined,
      updatedAt: now,
    });
    await audit(ctx, 'edge.list.held', undefined, {
      listId: list._id,
      versionId: ver._id,
      country: list.country,
      reasons,
    });
    return { outcome: 'held' as const, reasons };
  },
});

async function heldVersion(db: DatabaseReader, listId: ListId, versionId: VersionId) {
  const list = await listOf(db, listId);
  const ver = await db.get(versionId);
  if (!ver || ver.listId !== list._id || ver.status !== 'held' || list.heldVersionId !== ver._id)
    refuse('edge.list.not_held', 'That version is not waiting for a decision');
  return { list, ver };
}

/** "Use it": publish a held version, unless the list moved on since it was read. */
export const approve = internalMutation({
  args: { listId: v.id('countryLists'), versionId: v.id('countryListVersions'), ...actor },
  handler: async (ctx, a) => {
    const { list, ver } = await heldVersion(ctx.db, a.listId, a.versionId);
    if ((list.activeVersionId ?? null) !== (ver.basedOn ?? null))
      refuse(
        'edge.list.version_stale',
        'The list changed since this version was read. Fetch or paste it again',
      );
    await publish(ctx, list, ver, a.actorAdminId);
    await audit(ctx, 'admin.edge.list.approve', a.actorAdminId, {
      listId: list._id,
      versionId: ver._id,
    });
    return { ok: true as const };
  },
});

/** "Throw it away". */
export const reject = internalMutation({
  args: { listId: v.id('countryLists'), versionId: v.id('countryListVersions'), ...actor },
  handler: async (ctx, a) => {
    const { list, ver } = await heldVersion(ctx.db, a.listId, a.versionId);
    const now = Date.now();
    await ctx.db.patch(ver._id, {
      status: 'rejected',
      endedAt: now,
      ...(a.actorAdminId ? { decidedBy: a.actorAdminId, decidedAt: now } : {}),
    });
    await ctx.db.patch(list._id, { heldVersionId: undefined, updatedAt: now });
    await scheduleDrop(ctx, ver._id);
    await audit(ctx, 'admin.edge.list.reject', a.actorAdminId, {
      listId: list._id,
      versionId: ver._id,
    });
    return { ok: true as const };
  },
});

// --- after publication, cleanup, sweep ---------------------------------------------------------------

/**
 * A version went active: stamp each of its names in the list's history, a
 * page at a time (display only). Stops when another version took over.
 */
export const afterPublish = internalMutation({
  args: { versionId: v.id('countryListVersions'), cursor: v.optional(v.string()) },
  handler: async (ctx, a) => {
    const ver = await ctx.db.get(a.versionId);
    if (!ver || ver.status !== 'active') return;
    const list = await ctx.db.get(ver.listId);
    if (!list || list.activeVersionId !== ver._id) return;
    const now = Date.now();
    if (a.cursor === undefined) {
      // Once per publication: what the lists say moved, and the feeds take the new names.
      await bumpFactsGen(ctx);
      await startFeedRuns(ctx, list);
    }
    const page = await ctx.db
      .query('countryListMembers')
      .withIndex('by_version_name', (q) => q.eq('versionId', ver._id))
      .paginate({ numItems: MEMBERS_PAGE, cursor: a.cursor ?? null });
    for (const m of page.page) {
      const h = await ctx.db
        .query('countryListNameHistory')
        .withIndex('by_list_name', (q) =>
          q.eq('listId', list._id).eq('name', m.name).eq('wildcard', m.wildcard),
        )
        .unique();
      if (h) await ctx.db.patch(h._id, { lastListedAt: now });
      else
        await ctx.db.insert('countryListNameHistory', {
          listId: list._id,
          name: m.name,
          wildcard: m.wildcard,
          firstListedAt: now,
          lastListedAt: now,
        });
    }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.countryLists.afterPublish, {
        versionId: ver._id,
        cursor: page.continueCursor,
      });
  },
});

/** Delete an ended version's names and chunks, a page at a time, once its grace is over. */
export const dropVersion = internalMutation({
  args: { versionId: v.id('countryListVersions') },
  handler: async (ctx, { versionId }) => {
    const ver = await ctx.db.get(versionId);
    if (!ver || ver.cleanedAt) return;
    if (!['superseded', 'rejected', 'failed'].includes(ver.status)) return;
    const now = Date.now();
    const wait = (ver.endedAt ?? 0) + CLEANUP_GRACE_MS - now;
    if (wait > 0) {
      await ctx.scheduler.runAfter(wait, internal.countryLists.dropVersion, { versionId });
      return;
    }
    const members = await ctx.db
      .query('countryListMembers')
      .withIndex('by_version_name', (q) => q.eq('versionId', versionId))
      .take(MEMBERS_PAGE);
    for (const m of members) await ctx.db.delete(m._id);
    if (members.length === MEMBERS_PAGE) {
      await ctx.scheduler.runAfter(0, internal.countryLists.dropVersion, { versionId });
      return;
    }
    const chunks = await ctx.db
      .query('countryListChunks')
      .withIndex('by_version_family_lo', (q) => q.eq('versionId', versionId))
      .take(CHUNKS_PAGE);
    for (const c of chunks) await ctx.db.delete(c._id);
    if (chunks.length === CHUNKS_PAGE) {
      await ctx.scheduler.runAfter(0, internal.countryLists.dropVersion, { versionId });
      return;
    }
    await ctx.db.patch(versionId, { cleanedAt: now });
  },
});

/** Whether a list's pointers still name a version (retention never deletes those). */
function referenced(list: List | null, id: VersionId): boolean {
  return (
    !!list &&
    (list.activeVersionId === id || list.heldVersionId === id || list.stagingVersionId === id)
  );
}

/**
 * Daily (cron `country-lists-sweep`): fail staging that crashed, throw away
 * versions nobody decided on, finish cleanups, and keep version rows, uploads
 * and history bounded. Never touches a version a list still points at.
 */
export const sweep = internalMutation({
  args: {},
  handler: async (ctx) => {
    await recordHeartbeat(ctx, 'country-lists-sweep');
    const now = Date.now();
    const cfg = await resolveEdgeConfig(ctx.db);
    const listCache = new Map<string, List | null>();
    const listOfVersion = async (ver: Version) => {
      if (!listCache.has(ver.listId)) listCache.set(ver.listId, await ctx.db.get(ver.listId));
      return listCache.get(ver.listId)!;
    };
    const counts = { failed: 0, expired: 0, dropping: 0, deleted: 0 };

    for (const ver of await ctx.db
      .query('countryListVersions')
      .withIndex('by_status_at', (q) => q.eq('status', 'staging').lt('at', now - STAGING_STALE_MS))
      .take(SWEEP_PAGE)) {
      await ctx.db.patch(ver._id, { status: 'failed', failure: 'stale', endedAt: now });
      await scheduleDrop(ctx, ver._id);
      const list = await listOfVersion(ver);
      if (list?.stagingVersionId === ver._id) {
        await ctx.db.patch(list._id, { stagingVersionId: undefined });
        listCache.delete(ver.listId);
      }
      counts.failed++;
    }

    for (const ver of await ctx.db
      .query('countryListVersions')
      .withIndex('by_status_at', (q) =>
        q.eq('status', 'held').lt('at', now - cfg.lists.heldDays * DAY),
      )
      .take(SWEEP_PAGE)) {
      await ctx.db.patch(ver._id, { status: 'rejected', failure: 'expired', endedAt: now });
      await scheduleDrop(ctx, ver._id);
      const list = await listOfVersion(ver);
      if (list?.heldVersionId === ver._id) {
        await ctx.db.patch(list._id, { heldVersionId: undefined });
        listCache.delete(ver.listId);
      }
      counts.expired++;
    }

    for (const status of ['superseded', 'rejected', 'failed'] as const) {
      for (const ver of await ctx.db
        .query('countryListVersions')
        .withIndex('by_status_at', (q) => q.eq('status', status))
        .take(SWEEP_PAGE * 4)) {
        if (referenced(await listOfVersion(ver), ver._id)) continue;
        if (!ver.cleanedAt) {
          // A cleanup that should have finished by now: start it again.
          if ((ver.endedAt ?? ver.at) < now - CLEANUP_GRACE_MS - HOUR) {
            await ctx.scheduler.runAfter(0, internal.countryLists.dropVersion, {
              versionId: ver._id,
            });
            counts.dropping++;
          }
        } else if (ver.at < now - VERSION_RETENTION_MS) {
          await ctx.db.delete(ver._id);
          counts.deleted++;
        }
      }
    }

    // Freshness passes with time alone: a list that turned stale (or fresh)
    // since the last look moves what evidence reads.
    let freshnessMoved = false;
    for (const list of await ctx.db.query('countryLists').take(MAX_LISTS)) {
      const fresh = isFresh(list, cfg.lists.staleDays, now);
      if ((list.factsFresh ?? false) === fresh) continue;
      await ctx.db.patch(list._id, { factsFresh: fresh });
      if (list.activeVersionId) freshnessMoved = true;
    }
    if (freshnessMoved) await bumpFactsGen(ctx);
    const feeds = await sweepFeeds(ctx, now);

    // The newest rows per list stay, whatever their age; past that, cleaned ones go.
    for (const list of await ctx.db.query('countryLists').take(MAX_LISTS)) {
      const older = await ctx.db
        .query('countryListVersions')
        .withIndex('by_list_at', (q) => q.eq('listId', list._id))
        .order('desc')
        .take(MAX_VERSION_ROWS + SWEEP_PAGE);
      for (const ver of older.slice(MAX_VERSION_ROWS))
        if (ver.cleanedAt && !referenced(list, ver._id)) {
          await ctx.db.delete(ver._id);
          counts.deleted++;
        }
      if (list.ingest && now - list.ingest.at >= INGEST_STALE_MS)
        await ctx.db.patch(list._id, { ingest: undefined });
    }

    for (const u of await ctx.db
      .query('countryListUploads')
      .withIndex('by_at', (q) => q.lt('at', now - UPLOAD_TTL_MS))
      .take(SWEEP_PAGE))
      await ctx.scheduler.runAfter(0, internal.countryLists.purgeUpload, { uploadId: u._id });

    for (const h of await ctx.db
      .query('countryListNameHistory')
      .withIndex('by_last', (q) => q.lt('lastListedAt', now - HISTORY_RETENTION_MS))
      .take(MEMBERS_PAGE))
      await ctx.db.delete(h._id);

    return { ...counts, feeds };
  },
});
