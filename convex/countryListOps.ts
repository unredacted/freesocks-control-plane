'use node';
/**
 * Reading a country list into a version (docs/edges.md "Country lists"). One
 * path for both sources: a fetch (pinned to the addresses it checked,
 * lib/edges/lists/pinnedFetch.ts) or a finished paste. The text is parsed,
 * hashed in its canonical form, compared with what the list already holds,
 * and only then staged and finished in countryLists.ts, which publishes it or
 * holds it for a person.
 */
import { createHash } from 'node:crypto';
import { v } from 'convex/values';
import { internalAction, type ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { runWithCronOutcome } from './cronHeartbeat';
import { MAX_LISTS } from './lib/edges/lists/facts';
import { canonicalText, parseList, type ParsedList } from './lib/edges/lists/parse';
import {
  commonSize,
  decodeChunk,
  encodeChunks,
  joinSpans,
  sizeOf,
  type ListFamily,
  type Spans,
} from './lib/edges/lists/intervals';
import { DEFAULT_DEPS, pinnedFetch, type PinnedFetchDeps } from './lib/edges/lists/pinnedFetch';

const FETCH_MAX_BYTES = 16 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 20_000;
/** Names written per staging mutation (each is a short row; a batch stays small). */
const NAMES_PER_STAGE = 1_000;
/**
 * Lists started per cron pass: every one that is due (a pass only schedules
 * them; each read is its own action), so an hourly list is read every hour.
 */
const FETCH_PER_PASS = MAX_LISTS;

type Fetcher = (
  url: string,
  opts: Parameters<typeof pinnedFetch>[1],
) => ReturnType<typeof pinnedFetch>;
const realFetch: Fetcher = (url, opts) => pinnedFetch(url, opts, DEFAULT_DEPS);
let fetcher: Fetcher = realFetch;
/** Test seam: the source fetch (pinnedFetch.test.ts covers the real one against a TLS server). */
export function __setListFetchForTests(f: Fetcher | null): void {
  fetcher = f ?? realFetch;
}

type VersionId = Id<'countryListVersions'>;

/** A version's spans of one family, read back from its chunks (null: it was cleaned meanwhile). */
async function spansOf(
  ctx: ActionCtx,
  versionId: VersionId,
  family: ListFamily,
): Promise<Spans<number> | Spans<bigint> | null> {
  const parts: Array<Spans<number> | Spans<bigint>> = [];
  let after: string | undefined;
  for (;;) {
    const page = await ctx.runQuery(internal.countryLists.versionChunks, {
      versionId,
      family,
      ...(after !== undefined ? { after } : {}),
    });
    if (!page) return null;
    for (const t of page.texts)
      parts.push(family === 'v4' ? decodeChunk(t, 'v4') : decodeChunk(t, 'v6'));
    if (page.done || page.last === null) break;
    after = page.last;
  }
  return family === 'v4'
    ? joinSpans(parts as Array<Spans<number>>)
    : joinSpans(parts as Array<Spans<bigint>>);
}

function countsOf(p: ParsedList) {
  return {
    entries: p.entries,
    names: p.names.length,
    wildcards: p.wildcards.length,
    v4Ranges: p.ranges.v4.lo.length,
    v6Ranges: p.ranges.v6.lo.length,
    v4: sizeOf('v4', p.ranges.v4),
    v6: sizeOf('v6', p.ranges.v6),
    ...p.dropped,
  };
}

/**
 * Write a parsed list as a new version and finish it. The diff is worked out
 * against the version it is based on while writing: names by the staging
 * mutations, ranges here from that version's chunks.
 */
async function stage(
  ctx: ActionCtx,
  listId: Id<'countryLists'>,
  parsed: ParsedList,
  sha256: string,
  source: 'fetch' | 'upload',
  validators: { etag?: string; lastModified?: string },
  sourceGen: number,
): Promise<string> {
  const counts = countsOf(parsed);
  const begun = await ctx.runMutation(internal.countryLists.stageBegin, {
    listId,
    sha256,
    source,
    counts,
    samples: parsed.samples,
    sourceGen,
  });
  if (!begun) {
    await ctx.runMutation(internal.countryLists.recordIngest, {
      listId,
      outcome: 'busy',
      confirmed: false,
      validators: 'keep',
      sourceGen,
    });
    return 'busy';
  }
  const { versionId, basedOn } = begun;
  try {
    for (const c of encodeChunks(parsed.ranges))
      await ctx.runMutation(internal.countryLists.stageChunk, { versionId, ...c });
    const all = [
      ...parsed.names.map((name) => ({ name, wildcard: false })),
      ...parsed.wildcards.map((name) => ({ name, wildcard: true })),
    ];
    let namesCommon = 0;
    for (let i = 0; i < all.length; i += NAMES_PER_STAGE) {
      const r = await ctx.runMutation(internal.countryLists.stageNames, {
        versionId,
        names: all.slice(i, i + NAMES_PER_STAGE),
      });
      namesCommon += r.common;
    }
    const before = basedOn
      ? await ctx.runQuery(internal.countryLists.versionCounts, { versionId: basedOn })
      : null;
    let v4Common = 0;
    let v6Common = 0;
    if (basedOn) {
      const old4 = (await spansOf(ctx, basedOn, 'v4')) as Spans<number> | null;
      const old6 = (await spansOf(ctx, basedOn, 'v6')) as Spans<bigint> | null;
      // The base ended and was cleaned while this was written: finishing fails it anyway.
      if (old4 && old6) {
        v4Common = commonSize('v4', old4, parsed.ranges.v4);
        v6Common = commonSize('v6', old6, parsed.ranges.v6);
      }
    }
    const names = counts.names + counts.wildcards;
    const prevNames = before ? before.names + before.wildcards : 0;
    const part = (next: number, prev: number, common: number) => ({
      added: next - common,
      removed: prev - common,
      common,
    });
    const r = await ctx.runMutation(internal.countryLists.stageFinish, {
      versionId,
      diff: {
        names: part(names, prevNames, namesCommon),
        v4: part(counts.v4, before?.v4 ?? 0, v4Common),
        v6: part(counts.v6, before?.v6 ?? 0, v6Common),
      },
      ...(validators.etag ? { etag: validators.etag } : {}),
      ...(validators.lastModified ? { lastModified: validators.lastModified } : {}),
      sourceGen,
    });
    return r.outcome;
  } catch (e) {
    await ctx.runMutation(internal.countryLists.recordIngest, {
      listId,
      outcome: 'stage_failed',
      confirmed: false,
      validators: 'keep',
      failedVersionId: versionId,
      sourceGen,
    });
    throw e;
  }
}

/** Read one list: its source (or the finished paste) into a version, or confirm the one it has. */
export const ingest = internalAction({
  args: { listId: v.id('countryLists'), uploadId: v.optional(v.id('countryListUploads')) },
  handler: async (ctx, a): Promise<string> => {
    const c = await ctx.runQuery(internal.countryLists.ingestContext, { listId: a.listId });
    if (!c) return 'gone';
    const record = (
      outcome: string,
      confirmed: boolean,
      validators: 'active' | 'held' | 'keep',
      extra = {},
    ) =>
      ctx.runMutation(internal.countryLists.recordIngest, {
        listId: a.listId,
        outcome,
        confirmed,
        validators,
        sourceGen: c.sourceGen,
        ...extra,
      });
    let text: string;
    let validators: { etag?: string; lastModified?: string } = {};
    const source = a.uploadId ? 'upload' : 'fetch';
    // Once staging starts, a failure records itself (and fails the version).
    let staging = false;
    try {
      if (a.uploadId) {
        text = await ctx.runQuery(internal.countryLists.uploadText, { uploadId: a.uploadId });
      } else {
        if (c.source.kind !== 'url') {
          await record('not_url', false, 'keep');
          return 'not_url';
        }
        const r = await fetcher(c.source.url, {
          etag: c.etag,
          lastModified: c.lastModified,
          maxBytes: FETCH_MAX_BYTES,
          timeoutMs: FETCH_TIMEOUT_MS,
        });
        if (!r.ok) {
          await record(r.error, false, 'keep');
          return r.error;
        }
        if (r.status === 304) {
          // The validators describe the active version, or the one waiting.
          const confirmed = c.describes === 'active';
          await record(confirmed ? 'not_modified' : 'held_same', confirmed, 'keep');
          return confirmed ? 'not_modified' : 'held_same';
        }
        text = r.text;
        validators = {
          ...(r.etag ? { etag: r.etag } : {}),
          ...(r.lastModified ? { lastModified: r.lastModified } : {}),
        };
      }
      const parsed = parseList(text);
      const sha256 = createHash('sha256').update(canonicalText(parsed)).digest('hex');
      if (sha256 === c.activeSha) {
        await record('unchanged', true, 'active', validators);
        return 'unchanged';
      }
      if (sha256 === c.heldSha) {
        await record('held_same', false, 'held', validators);
        return 'held_same';
      }
      staging = true;
      return await stage(ctx, a.listId, parsed, sha256, source, validators, c.sourceGen);
    } catch (e) {
      if (!staging) await record('error', false, 'keep');
      throw e;
    } finally {
      if (a.uploadId)
        await ctx.runMutation(internal.countryLists.purgeUpload, { uploadId: a.uploadId });
    }
  },
});

/** Cron `country-lists` (hourly): fetch the lists whose source is due. */
export const tick = internalAction({
  args: {},
  handler: async (ctx): Promise<void> =>
    runWithCronOutcome(ctx, 'country-lists', async () => {
      const due = await ctx.runQuery(internal.countryLists.dueForFetch, {
        now: Date.now(),
        limit: FETCH_PER_PASS,
      });
      for (const listId of due) {
        try {
          await ctx.runMutation(internal.countryLists.requestFetch, { listId });
        } catch {
          // Busy (an operator's fetch got there first): the next pass takes it.
        }
      }
    }),
});
