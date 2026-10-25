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
 *    pin, the member's country: their answer, the stored guess and its revision);
 *  - `fetched`: the backend body; the node it names wins over the stored pin, a
 *    body that names none is judged against the stored pin, and a changed pin
 *    is recorded here;
 *  - `ua`: the client family the render rule follows (`classifyClient`; the raw
 *    view passes an empty one and gets the panel's default link format);
 *  - `location`: where the member is, from `locateMember` over the caller's own
 *    request (located at the STORED pin, for the caller's cache lookups; it may
 *    set or refresh the stored guess first, lib/memberCountry.ts). When the body
 *    resolves to another node (no pin yet, or a moved one), the country rules of
 *    THAT node's place (and the key's family there) are read again from the same
 *    request inputs before anything is rendered, and the outcome carries the
 *    location it rendered with. The guess is written once, at `locateMember`.
 */
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import type { Id } from '../_generated/dataModel';
import type { CountryContext } from './edges/assignment';
import { classifyClient } from './edges/clientFamilies';
import { applyEdgeRender } from './edges/renderPipeline';
import { withheldNoteDue } from './edges/withheld';
import type { ResolvedWhere } from './edges/sni/country';
import { resolveClientIp, resolveCountry } from './http';
import { memberWhere, nextGuess, steeringCountry, type CountryFields } from './memberCountry';
import { relabelMemberEntries } from './memberEntryNames';
import { placeholderBody } from './nodePinning';
import { isOwnExit } from './ownExits';
import { subscriptionNow, withinValidity } from './subscriptionEtag';

/** The delivery projection of a subscription: what the decision reads from the row. */
export interface DeliverySubscription extends CountryFields {
  subscriptionId: Id<'subscriptions'>;
  backendServerId: Id<'backendServers'> | null;
  /** The node the row is pinned to (the decision's place when the body names none). */
  pinnedNode: string | null;
  /**
   * The revision of the stored country this request read (convex/memberCountry.ts):
   * a guess this request writes is applied only while it is still current.
   */
  countryRev?: number | null;
  /**
   * The row's `deliveryRev` this request read: a pin it records (and the
   * caller's cache write and delivery stamp) only land while the key has not
   * moved in place since (subscriptions.ts `invalidateDelivery`).
   */
  deliveryRev?: number;
}

export interface MemberLocation {
  /** The node this location was judged at (the place whose country rules apply). */
  node: string | null;
  /** The cache token of the member's place (`edgeRender.epochFor`), null when none applies. */
  edgeToken: string | null;
  /** Names are judged per country at this place (an inferred country then shapes the body). */
  sensitive: boolean;
  located: ResolvedWhere;
  /** The country the CDN reported for this request (null unless fronted): kept to re-locate. */
  inferred: string | null;
  /** The member's country fields this request located with (after any guess it wrote). */
  fields: CountryFields;
  /**
   * The country the member's EDGES are ordered by (delivery by country):
   * their STORED country while `delivery.country.steer` is on, else null.
   */
  edgeCountry: string | null;
}

/**
 * The member's location at one node of a backend (lib/memberCountry.ts
 * `memberWhere`): nothing for a key that is not freedom-family THERE; else
 * their own answer; else, with detection on, the stored guess; else, with
 * detection off, the CDN-reported country for this one response. Only a
 * country on the list counts, and only where an origin covers the place (the
 * place's curated countries, `edgeRender.renderContextFor`: none elsewhere, as
 * nothing is rendered there). A stored country is `source: 'override'` and keys
 * the cache; an inferred one is never cached (lib/edges/sni/country.ts).
 */
export async function locateAt(
  ctx: ActionCtx,
  a: {
    subscriptionId: Id<'subscriptions'>;
    backendServerId: Id<'backendServers'> | null;
    node: string | null;
    fields: CountryFields;
    inferred: string | null;
  },
): Promise<MemberLocation> {
  const [place, country] = await Promise.all([
    a.backendServerId
      ? ctx.runQuery(internal.edgeRender.renderContextFor, {
          backendServerId: a.backendServerId,
          nodeName: a.node ?? undefined,
        })
      : { token: null as string | null, curated: [] as string[], sensitive: false },
    ctx.runQuery(internal.memberCountry.contextFor, {
      subscriptionId: a.subscriptionId,
      nodeName: a.node ?? undefined,
    }),
  ]);
  const located = memberWhere({
    family: country.family,
    sub: a.fields,
    cfg: country.cfg,
    listed: place.curated,
    now: Date.now(),
    reading: a.inferred,
  });
  return {
    node: a.node,
    edgeToken: place.token,
    sensitive: place.sensitive,
    located,
    inferred: a.inferred,
    fields: a.fields,
    edgeCountry: steeringCountry(country.cfg, located),
  };
}

/**
 * Where the member is, for server-name selection, and the cache token of their
 * place, from THIS request. One function for every route, so the raw view and
 * the subscription pick the same names. First the request's CDN country may set
 * or refresh the stored guess (lib/memberCountry.ts `nextGuess`; a reading from
 * one of FCP's own exits only keeps a guess alive): the client address is
 * compared HERE and only a yes/no goes on, and the write applies only at the
 * revision this request read (a transition in between wins).
 */
export async function locateMember(
  ctx: ActionCtx,
  sub: DeliverySubscription,
  req: Request,
): Promise<MemberLocation> {
  const reading = resolveCountry(req);
  let fields: CountryFields = {
    sniRegion: sub.sniRegion ?? null,
    regionSeenCountry: sub.regionSeenCountry ?? null,
    regionSeenFirstAt: sub.regionSeenFirstAt ?? null,
    regionSeenAt: sub.regionSeenAt ?? null,
  };
  const country = await ctx.runQuery(internal.memberCountry.contextFor, {
    subscriptionId: sub.subscriptionId,
    nodeName: sub.pinnedNode ?? undefined,
  });
  const ownExit = isOwnExit(resolveClientIp(req), country.ownExits);
  if (nextGuess({ ...country, sub: fields, now: Date.now(), reading, ownExit }).kind !== 'none') {
    const after = await ctx.runMutation(internal.memberCountry.noteSeenCountry, {
      subscriptionId: sub.subscriptionId,
      countryRev: sub.countryRev ?? 0,
      country: reading,
      ownExit,
    });
    if (after) fields = after;
  }
  return locateAt(ctx, {
    subscriptionId: sub.subscriptionId,
    backendServerId: sub.backendServerId,
    node: sub.pinnedNode,
    fields,
    inferred: reading,
  });
}

export interface RenderSnapshot {
  epoch: number;
  family: string;
  listenerKeys: string[];
  primaryEdgeId?: Id<'edges'>;
  backupEdgeId?: Id<'edges'>;
  /**
   * The member's STORED country the body was shaped for (names, and edges when
   * steered); never a transient reading (docs/privacy.md).
   */
  country?: string;
  /** Delivery by country: the tier each endpoint came from in `country`. */
  primaryTier?: number;
  backupTier?: number;
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
      /** Where the member was located for this body (at `node`): what cacheability follows. */
      location: MemberLocation;
    }
  | { kind: 'refuse'; reason: string };

/** One served render's entries left out, and the origin to note them on. */
export interface WithheldNote {
  rctx: { relayId: Id<'relays'>; withheldNotedAt: number | null };
  names: Array<string | null>;
}

/**
 * Tell the operator a render left entries out (`PipelineResult.withheld`):
 * scheduled, never awaited, at most once a minute per origin (the decision
 * carries when it was last noted), and best effort like the refusal counter.
 */
export async function noteWithheldEntries(
  ctx: Pick<ActionCtx, 'scheduler'>,
  rctx: { relayId: Id<'relays'>; withheldNotedAt: number | null },
  withheld: ReadonlyArray<string | null> | undefined,
  now: number,
): Promise<void> {
  if (!withheld || withheld.length === 0 || !withheldNoteDue(rctx.withheldNotedAt, now)) return;
  try {
    await ctx.scheduler.runAfter(0, internal.edgeHostHides.noteWithheld, {
      relayId: rctx.relayId,
      count: withheld.length,
      remarks: withheld.filter((r): r is string => r !== null),
    });
  } catch {
    /* the note is best effort */
  }
}

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
    /** From `locateMember` (at the stored pin); re-read here when the body resolves elsewhere. */
    location: MemberLocation;
    now: number;
  },
): Promise<DeliveryOutcome> {
  const { sub, fetched, now } = input;
  // Every edge-required refusal is counted per reason (deliveryRefusals.ts):
  // dark members must be visible to the operator. Counting never changes the
  // answer, nor delays it: the write is scheduled, not awaited, so a burst of
  // refusals never waits on writes conflicting over the shared counter rows.
  const refuse = async (reason: string): Promise<DeliveryOutcome> => {
    try {
      await ctx.scheduler.runAfter(0, internal.deliveryRefusals.record, { reason });
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
  // A backend placeholder (an expired or disabled key: every entry at a
  // placeholder host, no node named) carries nothing an origin serves and no
  // node address, so it passes through unrendered whatever the stored pin
  // says: the member keeps reading the backend's own "expired" entries
  // instead of a refusal once that node is bound. An EMPTY body is not one: it
  // is still judged (and refused), since an empty 200 would wipe the client.
  const passthrough = fetched.nodeless === true && placeholderBody(fetched.content);
  if (fetched.pinnedNode && fetched.pinnedNode !== sub.pinnedNode) {
    await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
      subscriptionId: sub.subscriptionId,
      node: fetched.pinnedNode,
      deliveryRev: sub.deliveryRev,
    });
  }
  // The country rules are the place's: a body that resolved to another node
  // than the one the caller located at (a first fetch with no pin, a moved pin)
  // is located again there, from the same request inputs, before any render.
  // Otherwise a node-scoped origin would see an empty curated list and judge no
  // country at all (names blocked in the member's country could be picked).
  const location =
    input.location.node === node
      ? input.location
      : await locateAt(ctx, {
          subscriptionId: sub.subscriptionId,
          backendServerId: sub.backendServerId,
          node,
          fields: input.location.fields,
          inferred: input.location.inferred,
        });
  const where: CountryContext = location.located.where;
  let content = fetched.content;
  let relay: string | null = null;
  let renderedEpoch: number | null = null;
  let validUntil: number | null = null;
  let render: RenderSnapshot | null = null;
  // What the served pass left out, noted only once that pass is the one served.
  let withheld: WithheldNote | null = null;
  if (sub.backendServerId && !passthrough) {
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
      let passWithheld: WithheldNote | null = null;
      if (decision.kind === 'render') {
        const rctx = decision.context;
        const renderKey =
          rctx.renderKey ??
          (await ctx.runMutation(internal.subscriptions.ensureRenderKey, {
            subscriptionId: sub.subscriptionId,
          }));
        if (!renderKey) return refuse('no_render_key');
        const out = applyEdgeRender(rctx, body, renderKey, {
          now,
          where,
          edgeCountry: location.edgeCountry,
        });
        if (out.delivery.kind !== 'serve') return refuse(out.delivery.reason);
        if (out.withheld?.length) passWithheld = { rctx, names: out.withheld };
        body = out.body;
        epoch = rctx.epoch;
        passValidUntil = out.validUntil;
        // The country goes on the snapshot only when it is STORED (the
        // member's choice or the stored guess): a transient reading is
        // written nowhere, the snapshot included.
        const stored =
          location.located.source === 'override' ? location.located.where.country : null;
        snapshot = {
          epoch: rctx.epoch,
          family,
          listenerKeys: out.snapshot.listenerKeys,
          primaryEdgeId: (out.snapshot.primaryEdgeId as Id<'edges'> | null) ?? undefined,
          backupEdgeId: (out.snapshot.backupEdgeId as Id<'edges'> | null) ?? undefined,
          ...(stored ? { country: stored } : {}),
          ...(stored && out.snapshot.primaryTier !== undefined
            ? { primaryTier: out.snapshot.primaryTier }
            : {}),
          ...(stored && out.snapshot.backupTier !== undefined
            ? { backupTier: out.snapshot.backupTier }
            : {}),
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
      withheld = passWithheld;
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
  if (withheld) await noteWithheldEntries(ctx, withheld.rctx, withheld.names, now);
  return {
    kind: 'serve',
    content,
    node,
    placeholder,
    relay,
    renderedEpoch,
    validUntil,
    render,
    location,
  };
}
