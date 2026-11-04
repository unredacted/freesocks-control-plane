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
import { resolveClients } from './lib/clientCatalog';
import { resolveSubscriptionSiteName } from './lib/subscriptionTitle';
import { isXhttpMode } from '../src/shared/xhttpModes';
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
 * What the notice says for this key: the service name, and the apps the
 * catalog offers on the key's backend for the member's mode. A handful of
 * point reads and the (small, CMS-managed) catalog.
 */
export const words = internalQuery({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: appNoticeFamilyValidator,
    why: appNoticeWhyValidator,
  },
  handler: async (ctx, a): Promise<{ siteName: string; lines: string[] }> => {
    const sub = await ctx.db.get(a.subscriptionId);
    const user = sub ? await ctx.db.get(sub.userId) : null;
    const [siteName, clients] = await Promise.all([
      resolveSubscriptionSiteName(ctx.db),
      resolveClients(ctx.db),
    ]);
    const notice: AppNotice = { family: a.family, why: a.why };
    const apps = noticeApps(clients, {
      backend: sub?.backend ?? 'remnawave',
      xhttpMode: isXhttpMode(user?.connectionModeId),
      notice,
    });
    return { siteName, lines: noticeLines(notice, apps, siteName) };
  },
});

/**
 * Record that an app on this key got the notice. Only on a live key that has
 * not moved in place since the request read it (a mode switch clears the
 * record, and an answer from before it must not bring it back), and only when
 * due (`appNoticeDue`): the route asks only then, and this asks again.
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
  if (appNoticeDue(a.sub.appNotice, a.notice.family, a.now)) {
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
