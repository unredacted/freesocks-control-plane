/**
 * The app notice at the subscription route (lib/appNotice.ts; docs/edges.md
 * "Apps that get no connection"): the words the notice says for this key, the
 * notice body in the app's own format, and the key's record that an app got
 * one, which the account page reads for its hint. The record holds the kind of
 * app and a time only (docs/privacy.md), and is written at most every few
 * hours however often the app polls.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery, type ActionCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { SETTINGS_DEFAULTS } from './appSettings';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { resolveClients } from './lib/clientCatalog';
import { resolveSubscriptionSiteName } from './lib/subscriptionTitle';
import { isXhttpMode } from '../src/shared/xhttpModes';
import type { DatabaseReader } from './_generated/server';
import {
  appNoticeBody,
  appNoticeDue,
  appNoticeFamilyValidator,
  appNoticeWhyValidator,
  noticeApps,
  noticeLines,
  type AppNotice,
} from './lib/appNotice';

/**
 * Set by the rollback step (`clearForRollback`) before it clears anything: no
 * record is written while it is set, so none can come back behind the scan.
 * `resumeRecords` removes it when the rollback is called off.
 */
const RECORDS_OFF_KEY = 'appNotice:recordsOff';
const recordsOff = async (db: DatabaseReader) =>
  (await readStateJson<boolean>(db, RECORDS_OFF_KEY)) === true;

/** The device-limit master toggle, fail-safe to its default (as lifecycle.ts reads it). */
async function deviceEnforcementOn(db: DatabaseReader): Promise<boolean> {
  const fallback = SETTINGS_DEFAULTS['devices.enforcementEnabled'] as boolean;
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'devices.enforcementEnabled'))
    .unique();
  if (!row) return fallback;
  try {
    return JSON.parse(row.value) === true;
  } catch {
    return fallback;
  }
}

/**
 * What the notice says for this key: the service name, and the apps the
 * catalog offers on the key's backend for the member's mode and, on a
 * device-limited plan (the account view's `deviceLimited`), the apps that
 * honour the limit first. Whether the record may be written at all. A handful
 * of point reads and the (small, CMS-managed) catalog.
 */
export const words = internalQuery({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: appNoticeFamilyValidator,
    why: appNoticeWhyValidator,
  },
  handler: async (ctx, a): Promise<{ siteName: string; lines: string[]; recordsOff: boolean }> => {
    const sub = await ctx.db.get(a.subscriptionId);
    const user = sub ? await ctx.db.get(sub.userId) : null;
    const tier = user ? await ctx.db.get(user.tierId) : null;
    const [siteName, clients, enforcement, off] = await Promise.all([
      resolveSubscriptionSiteName(ctx.db),
      resolveClients(ctx.db),
      deviceEnforcementOn(ctx.db),
      recordsOff(ctx.db),
    ]);
    const notice: AppNotice = { family: a.family, why: a.why };
    const apps = noticeApps(clients, {
      backend: sub?.backend ?? 'remnawave',
      xhttpMode: isXhttpMode(user?.connectionModeId),
      deviceLimited: enforcement && tier?.hwidEnabled === true,
      notice,
    });
    return { siteName, lines: noticeLines(notice, apps, siteName), recordsOff: off };
  },
});

/**
 * Record that an app on this key got the notice. Only on a live key that has
 * not moved in place since the request read it (a mode switch clears the
 * record, and an answer from before it must not bring it back), and only when
 * due (`appNoticeDue`): the route asks only then, and this asks again. Never
 * while the rollback step has records off.
 */
export const record = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: appNoticeFamilyValidator,
    /** The row's `deliveryRev` the request read. */
    deliveryRev: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || sub.state !== 'active') return null;
    if ((sub.deliveryRev ?? 0) !== (a.deliveryRev ?? 0)) return null;
    if (await recordsOff(ctx.db)) return null;
    const now = Date.now();
    if (!appNoticeDue(sub.appNotice, a.family, now)) return null;
    await ctx.db.patch(sub._id, { appNotice: { family: a.family, at: now } });
    return null;
  },
});

/**
 * The notice body for this key's app, in the format of the body it replaces,
 * and the key's record scheduled when due (never awaited by the answer, like
 * the refusal counter). Never cached: the caller answers it `private, no-store`.
 */
export async function appNoticeContent(
  ctx: Pick<ActionCtx, 'runQuery' | 'scheduler'>,
  a: {
    sub: Pick<Doc<'subscriptions'>, 'appNotice' | 'deliveryRev'> & { _id: Id<'subscriptions'> };
    notice: AppNotice;
    replaced: string;
    now: number;
  },
): Promise<string> {
  const said = await ctx.runQuery(internal.appNotices.words, {
    subscriptionId: a.sub._id,
    family: a.notice.family,
    why: a.notice.why,
  });
  if (!said.recordsOff && appNoticeDue(a.sub.appNotice, a.notice.family, a.now)) {
    try {
      await ctx.scheduler.runAfter(0, internal.appNotices.record, {
        subscriptionId: a.sub._id,
        family: a.notice.family,
        deliveryRev: a.sub.deliveryRev ?? 0,
      });
    } catch {
      /* the hint is best effort */
    }
  }
  return appNoticeBody(a.notice, said.lines, said.siteName, a.replaced);
}

/**
 * The step before rolling back to a build without the app notice (docs/edges.md
 * "Deploy notes"): turns record writes off first, in the same transaction as
 * the first page, so no record (one scheduled before it included) can land
 * behind the scan; then drops `subscriptions.appNotice` page by page,
 * scheduling itself until done, so the older schema accepts every row. Members
 * still get the notice in their apps; they only lose the account page's hint.
 */
export const clearForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    if (!cursor) await writeStateJson(ctx.db, RECORDS_OFF_KEY, true);
    const page = await ctx.db
      .query('subscriptions')
      .paginate({ cursor: cursor ?? null, numItems: 200 });
    let cleared = 0;
    for (const s of page.page)
      if (s.appNotice !== undefined) {
        await ctx.db.patch(s._id, { appNotice: undefined });
        cleared++;
      }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.appNotices.clearForRollback, {
        cursor: page.continueCursor,
      });
    return { cleared, done: page.isDone };
  },
});

/** Calls the rollback off: records are written again from the next notice. */
export const resumeRecords = internalMutation({
  args: {},
  handler: async (ctx) => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', RECORDS_OFF_KEY))
      .unique();
    if (row) await ctx.db.delete(row._id);
    return { resumed: !!row };
  },
});
