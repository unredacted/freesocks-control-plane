/**
 * What a member may be handed from a fetched backend body, decided ONE way for
 * every route that hands a configuration out: the fronted subscription
 * (`GET /api/v1/sub/<token>`), the sealed raw-config view
 * (`GET /api/v1/subscription/content`) and, later, the app's config endpoint.
 * A copy path that skipped this would hand out what the delivery gate, the
 * edge render or the leak check exist to withhold (docs/edges.md "Rendering").
 *
 * Every input that shapes the answer is explicit, so no caller keeps a piece of
 * it to itself:
 *  - `sub`: the delivery projection (the row id, its backend server, the STORED
 *    pin, the stored country answer);
 *  - `fetched`: the backend body; the node it names wins over the stored pin, a
 *    body that names none is judged against the stored pin, and a changed pin
 *    is recorded here;
 *  - `ua`: the client family the render rule follows (`classifyClient`; the raw
 *    view passes an empty one and gets the panel's default link format);
 *  - `where`: the member's country, from `locateMember` over the caller's own
 *    request.
 */
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import type { Id } from '../_generated/dataModel';
import type { CountryContext } from './edges/assignment';
import { classifyClient } from './edges/clientFamilies';
import { applyEdgeRender } from './edges/renderPipeline';
import { resolveWhere, type ResolvedWhere } from './edges/sni/country';
import { resolveCountry } from './http';
import { relabelMemberEntries } from './memberEntryNames';
import { subscriptionNow, withinValidity } from './subscriptionEtag';

/** The delivery projection of a subscription: what the decision reads from the row. */
export interface DeliverySubscription {
  subscriptionId: Id<'subscriptions'>;
  backendServerId: Id<'backendServers'> | null;
  /** The node the row is pinned to (the decision's place when the body names none). */
  pinnedNode: string | null;
  /** The member's own stored country answer, if any. */
  sniRegion?: string | null;
}

export interface MemberLocation {
  /** The cache token of the member's place (`edgeRender.epochFor`), null when none applies. */
  edgeToken: string | null;
  /** Names are judged per country at this place (an inferred country then shapes the body). */
  sensitive: boolean;
  located: ResolvedWhere;
}

/**
 * Where the member is, for server-name selection, and the cache token of their
 * place, from THIS request: their own stored answer, else the country the CDN
 * reports (only when fronted), and only a curated one. One function for every
 * route, so the raw view and the subscription pick the same names.
 */
export async function locateMember(
  ctx: ActionCtx,
  sub: DeliverySubscription,
  req: Request,
): Promise<MemberLocation> {
  const { token, curated, sensitive } = sub.backendServerId
    ? await ctx.runQuery(internal.edgeRender.renderContextFor, {
        backendServerId: sub.backendServerId,
        nodeName: sub.pinnedNode ?? undefined,
      })
    : { token: null as string | null, curated: [] as string[], sensitive: false };
  const located = resolveWhere({
    override: sub.sniRegion,
    inferred: resolveCountry(req),
    curated,
  });
  return { edgeToken: token, sensitive, located };
}

export interface RenderSnapshot {
  epoch: number;
  family: string;
  listenerKeys: string[];
  primaryEdgeId?: Id<'edges'>;
  backupEdgeId?: Id<'edges'>;
}

export type DeliveryOutcome =
  | {
      kind: 'serve';
      /** The body to hand out: rendered when an origin covers the place, relabelled always. */
      content: string;
      /** The node the body was judged for (the fetched pin, else the stored one). */
      node: string | null;
      /** A body that names no node while the key has no pin either: never cached. */
      placeholder: boolean;
      /** The cache token it was rendered under (null: no origin covers the place). */
      relay: string | null;
      renderedEpoch: number | null;
      /** The earliest proof expiry among the fronts it hands out, null when none. */
      validUntil: number | null;
      render: RenderSnapshot | null;
    }
  | { kind: 'refuse'; reason: string };

/**
 * Decide, render and relabel one fetched body. A place an origin covers gets a
 * rendered body that passed every check, or a refusal (a `DELIVERY_UNAVAILABLE_CODES`
 * reason, counted per reason here); a place none covers passes through. The
 * policy token is read before the decision and again after the render: one
 * re-render is allowed when it moved (or a front's proof lapsed meanwhile), a
 * second move refuses `policy_moved`.
 */
export async function deliverBody(
  ctx: ActionCtx,
  input: {
    sub: DeliverySubscription;
    fetched: { content: string; pinnedNode?: string | null; nodeless?: boolean };
    ua: string;
    where: CountryContext;
    now: number;
  },
): Promise<DeliveryOutcome> {
  const { sub, fetched, now } = input;
  // Every edge-required refusal is counted per reason (deliveryRefusals.ts):
  // dark members must be visible to the operator. Counting never changes the answer.
  const refuse = async (reason: string): Promise<DeliveryOutcome> => {
    try {
      await ctx.runMutation(internal.deliveryRefusals.record, { reason });
    } catch {
      /* the counter is best effort */
    }
    return { kind: 'refuse', reason };
  };
  // ONE node value drives everything below: the pin recorded on the row, the
  // render context, and the token the caller stores with the body. The pinner
  // reports a node for every known body shape, so the stored pin only covers
  // unknown shapes.
  const node = fetched.pinnedNode ?? sub.pinnedNode;
  const placeholder = fetched.nodeless === true && !node;
  if (fetched.pinnedNode && fetched.pinnedNode !== sub.pinnedNode) {
    await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
      subscriptionId: sub.subscriptionId,
      node: fetched.pinnedNode,
    });
  }
  let content = fetched.content;
  let relay: string | null = null;
  let renderedEpoch: number | null = null;
  let validUntil: number | null = null;
  let render: RenderSnapshot | null = null;
  if (sub.backendServerId) {
    const family = classifyClient(input.ua).family;
    let renderedUnder: string | null = null;
    for (let pass = 0; pass < 2; pass++) {
      const before = await ctx.runQuery(internal.edgeRender.epochFor, {
        backendServerId: sub.backendServerId,
        nodeName: node ?? undefined,
      });
      const decision = await ctx.runQuery(internal.edgeRender.decideForSubscription, {
        subscriptionId: sub.subscriptionId,
        family,
        nodeName: node ?? undefined,
      });
      if (decision.kind === 'unavailable') return refuse(decision.reason);
      let body = fetched.content;
      let epoch: number | null = null;
      let passValidUntil: number | null = null;
      let snapshot: RenderSnapshot | null = null;
      if (decision.kind === 'render') {
        const rctx = decision.context;
        const renderKey =
          rctx.renderKey ??
          (await ctx.runMutation(internal.subscriptions.ensureRenderKey, {
            subscriptionId: sub.subscriptionId,
          }));
        if (!renderKey) return refuse('no_render_key');
        const out = applyEdgeRender(rctx, body, renderKey, { now, where: input.where });
        if (out.delivery.kind !== 'serve') return refuse(out.delivery.reason);
        body = out.body;
        epoch = rctx.epoch;
        passValidUntil = out.validUntil;
        snapshot = {
          epoch: rctx.epoch,
          family,
          listenerKeys: out.snapshot.listenerKeys,
          primaryEdgeId: (out.snapshot.primaryEdgeId as Id<'edges'> | null) ?? undefined,
          backupEdgeId: (out.snapshot.backupEdgeId as Id<'edges'> | null) ?? undefined,
        };
      }
      const after = await ctx.runQuery(internal.edgeRender.epochFor, {
        backendServerId: sub.backendServerId,
        nodeName: node ?? undefined,
      });
      // A front whose proof lapsed while this body was rendered must not go
      // out: render again (that front is now ineligible), as for a moved token.
      if (after !== before || !withinValidity(passValidUntil, subscriptionNow())) continue;
      content = body;
      renderedEpoch = epoch;
      validUntil = passValidUntil;
      render = snapshot;
      renderedUnder = after;
      break;
    }
    if (
      renderedUnder === null &&
      (await ctx.runQuery(internal.edgeRender.epochFor, {
        backendServerId: sub.backendServerId,
        nodeName: node ?? undefined,
      })) !== null
    )
      return refuse('policy_moved');
    relay = renderedUnder;
  }
  // Member-facing names (docs/privacy.md): an entry the backend named after its
  // node and server name gets a neutral label. Last, because pinning and the
  // edge render both read those names.
  const naming = await ctx.runQuery(internal.subscriptions.entryNamingFor, {
    backendServerId: sub.backendServerId ?? undefined,
  });
  content = relabelMemberEntries(content, naming).content;
  // Judged once more before the body is kept or stamped: a proof that lapsed
  // after the render answers like a policy that moved.
  if (!withinValidity(validUntil, subscriptionNow())) return refuse('policy_moved');
  return { kind: 'serve', content, node, placeholder, relay, renderedEpoch, validUntil, render };
}
