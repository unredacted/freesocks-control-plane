/**
 * Everything the fronted subscription route (GET /api/v1/sub/<token>) reads
 * before it can answer from the cache, as ONE query: one transaction (one
 * consistent snapshot) and one query-cache entry per token and User-Agent,
 * instead of a separate function call for each piece. A cache hit then costs
 * the two rate-limit mutations and this read; the delivery stamp is called
 * only when something is due (lib/deliveryStamp.ts).
 *
 * Every piece is the plain read behind the query the route used to call on
 * its own, so their rules stay in one place:
 *  - the row: `subscriptions.bySubToken` (a deleted row is not found);
 *  - the answer's title and refresh hint: `subscriptions.responseHints`;
 *  - the HWID switch: `appSettings.resolved['devices.enforcementEnabled']`;
 *  - this UA's cached body: `subscriptionBodies` (lib/subscriptionBodies.ts `entriesForUa`);
 *  - the country context: `memberCountry.contextFor` (once: a guess the route
 *    writes changes the row's country fields, never what this reads);
 *  - the place's render context: `edgeRender.renderContextFor`;
 *  - the address lane: `edgeLanes.laneOf`;
 *  - the member-facing names: `subscriptions.entryNamingFor`;
 *  - the Hysteria pins: `subscriptions.hysteriaPinsFor`, read only when the
 *    cached body holds a Hysteria entry (lib/hysteriaGuard.ts).
 */
import { v } from 'convex/values';
import { internalQuery } from './_generated/server';
import { SETTINGS_DEFAULTS } from './appSettings';
import { renderContextOf, type PlaceRenderContext } from './edgeRender';
import { memberLaneOfUser } from './edgeLanes';
import { countryContextOf } from './memberCountry';
import { entryNamingOf, hysteriaPinsOf, responseHintsOf } from './subscriptions';
import { entriesForUa } from './lib/subscriptionBodies';
import { guardHysteria } from './lib/hysteriaGuard';

const HWID_KEY = 'devices.enforcementEnabled';

const NO_PLACE: PlaceRenderContext = {
  token: null,
  curated: [],
  sensitive: false,
  covered: false,
};

export const forToken = internalQuery({
  args: {
    subToken: v.string(),
    /** The UA the cache is keyed by (already truncated by the route). */
    ua: v.string(),
    /** The request carries an `x-hwid` the route would forward (length-capped). */
    hwidHeader: v.boolean(),
  },
  handler: async (ctx, { subToken, ua, hwidHeader }) => {
    const row = await ctx.db
      .query('subscriptions')
      .withIndex('by_sub_token', (q) => q.eq('subToken', subToken))
      .unique();
    if (!row || row.state === 'deleted') return null;
    // The old blob never leaves this query (lib/subscriptionBodies.ts reads it
    // for this UA until it is moved).
    const { subCache: _legacy, ...sub } = row;
    void _legacy;
    const hwidSetting = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', HWID_KEY))
      .unique();
    let hwidEnabled: unknown = SETTINGS_DEFAULTS[HWID_KEY];
    if (hwidSetting) {
      try {
        hwidEnabled = JSON.parse(hwidSetting.value);
      } catch {
        /* keep the default */
      }
    }
    // A device-bound request is never answered from the cache: no body read.
    const hasHwid = hwidEnabled === true && hwidHeader;
    const node = sub.pinnedNode ?? undefined;
    const [hints, entries, country, place, lane, naming] = await Promise.all([
      responseHintsOf(ctx.db, row),
      hasHwid ? Promise.resolve([] as string[]) : entriesForUa(ctx.db, row._id, ua, row),
      countryContextOf(ctx.db, row, node),
      row.backendServerId
        ? renderContextOf(ctx, row.backendServerId, node)
        : Promise.resolve(NO_PLACE),
      memberLaneOfUser(ctx.db, row.userId, Date.now()),
      entryNamingOf(ctx.db, row.backendServerId ?? undefined),
    ]);
    // The pins only when a cached body needs them (the guard's own first look).
    const needsPins = entries.some((raw) => {
      let content: unknown;
      try {
        content = (JSON.parse(raw) as { content?: unknown }).content;
      } catch {
        return false;
      }
      if (typeof content !== 'string') return false;
      const first = guardHysteria(content, { pinHex: [], spkiB64: [] });
      return !(first.kind === 'kept' && first.dropped === 0);
    });
    const pins = needsPins ? await hysteriaPinsOf(ctx.db, row.backendServerId ?? undefined) : null;
    return {
      sub,
      hints,
      hwidEnabled: hwidEnabled === true,
      entries,
      country,
      place,
      lane,
      naming,
      pins,
    };
  },
});
