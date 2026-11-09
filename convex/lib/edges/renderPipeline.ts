/**
 * The pure half of origin rendering: given the render context FCP resolved for
 * one subscription (published edges of its origin, the listener matchers, the
 * effective client rule) and the backend body, resolve which listeners the body
 * actually carries, assign this subscriber's endpoints over the edges whose
 * listener resolved, and rewrite the body. Used by the fronted /sub route, the
 * mirror refresh and the admin preview so all three emit identical output for
 * the same (renderKey, epoch, family).
 *
 * Listener-aware assignment: an edge whose listener has no matching, agreeing
 * template entry in THIS body (or no codec for its format) is marked
 * ineligible BEFORE the PRF pick, keeping its pool index so the walk stays
 * stable for everyone else.
 */
import {
  assignEndpoints,
  type CountryContext,
  type EdgePickVersion,
  type EdgeTier,
  type PublishedEdge,
} from './assignment';
import type { MemberPlace } from '../../../src/shared/entryNames';
import { RENDER_FORMAT_OF, detectBodyFormat } from './clientFamilies';
import { pathFigure, type LatencyBand, type LatencyInputs, type PathFigure } from './latency';
import { formatSupported } from './protocols';
import {
  edgeAddressesOf,
  formatHasAutoGroup,
  matchListeners,
  namesInBody,
  renderEdgeEndpoints,
  ruleCanEmitV6,
  ruleForDelivery,
  type DeliveryStyle,
  type EffectiveRule,
  type RenderMatcher,
  type RenderResult,
} from './render';

export interface EdgeRenderContext {
  /** Publication epoch of the origin: part of the cache key. */
  epoch: number;
  /** One matcher per renderable listener of the origin. */
  matchers: RenderMatcher[];
  published: PublishedEdge[];
  rule: EffectiveRule;
  preferDistinctProviders: boolean;
  /** How the origin walks its pool (`relays.edgePick`); absent = the legacy walk. */
  edgePick?: EdgePickVersion;
  /**
   * The member's lane on a node with lanes on (lib/edges/lanes.ts); absent =
   * no lanes. An open member with no open address left is refused
   * `open_lane_empty`, never handed a trusted one.
   */
  memberLane?: 'open' | 'trusted';
  /**
   * The countries cut over to their own addresses on this node
   * (`relays.ownPools`, docs/edges.md "A country on its own addresses"): a
   * member steered by one is handed its own addresses first. Absent = none.
   */
  ownCountries?: string[];
  originAddress: string;
  /**
   * Other addresses the node is known by (an enrolled node's other public
   * addresses and names, a name among its Hosts that resolves to it): an
   * entry at any of them is the node too (`leak_detected`).
   */
  nodeAddresses?: string[];
  deliveryStyle?: DeliveryStyle;
  /**
   * The node's own place (where the traffic leaves), leading every entry's name
   * (src/shared/entryNames.ts): the place its direct entries read
   * (`subscriptions.entryNamingOf`). Absent/null = not shown.
   */
  exit?: MemberPlace | null;
  /** Delivery by country: proven edges needed before they are handed out alone (default 1). */
  minProvenForExclusive?: number;
  /**
   * Latency ordering is on (docs/edges.md "Latency over the whole path"): what
   * a steered member's paths are judged from. Absent = no bands.
   */
  latency?: LatencyInputs;
}

export interface RenderSnapshot {
  family?: string;
  listenerKeys: string[];
  primaryEdgeId: string | null;
  backupEdgeId: string | null;
  /**
   * Whether the body got an auto group: it then holds the further server names
   * and the auto-group order (render.ts `namesInBody`). The body decides, not
   * the family, so a replay reads this, never the family's usual format.
   */
  autoGroup: boolean;
  /** With an `edgeCountry`: the tier each endpoint came from there (0 proven, 1 not known, 2 blocked). */
  primaryTier?: EdgeTier;
  backupTier?: EdgeTier;
}

export interface PipelineResult extends RenderResult {
  snapshot: RenderSnapshot;
  /**
   * With an `edgeCountry`: whether each endpoint's location is meant for that
   * country (docs/edges.md "Locations meant for a country"). For the preview
   * only: never part of the snapshot a subscription keeps.
   */
  meantFor?: { primary: boolean; backup: boolean };
  /**
   * With an `edgeCountry` and latency ordering: each endpoint's band and the
   * whole path it was judged by (null: no figure). For the preview only.
   */
  latency?: {
    primary: { band: LatencyBand; path: PathFigure | null } | null;
    backup: { band: LatencyBand; path: PathFigure | null } | null;
  };
  /**
   * When this body stops being servable: the earliest proof expiry among the
   * L7 fronts it hands out (primary and backup), null when it holds none. A
   * cached copy is never served past it (docs/edges.md "Asking whether a
   * configuration changed").
   */
  validUntil: number | null;
}

/** The earliest proof expiry among the assigned edges, null when none is an L7 front. */
export function renderValidUntil(
  edges: ReadonlyArray<PublishedEdge | null | undefined>,
): number | null {
  let earliest: number | null = null;
  for (const e of edges) {
    if (!e || e.layer !== 'l7' || e.proofExpiresAt === undefined) continue;
    earliest = earliest === null ? e.proofExpiresAt : Math.min(earliest, e.proofExpiresAt);
  }
  return earliest;
}

export function applyEdgeRender(
  rctx: EdgeRenderContext,
  body: string,
  renderKey: string,
  opts: {
    now: number;
    where?: CountryContext;
    /**
     * Delivery by country: the member's STORED country when steering applies
     * (lib/memberCountry.ts `steeringCountry`); absent/null = no tiers at all.
     */
    edgeCountry?: string | null;
    /** Without an `edgeCountry`: edges blocked in any of these go last (a mirror). */
    avoidBlockedIn?: readonly string[];
  },
): PipelineResult {
  const format = detectBodyFormat(body);
  const renderFormat =
    format === 'links' || format === 'singbox-json' || format === 'clash-yaml'
      ? RENDER_FORMAT_OF[format]
      : null;
  // (1)+(2): which listeners this body carries, verified against what they speak.
  const { matches } = matchListeners(body, rctx.matchers);
  const resolved = new Set((matches ?? []).filter((m) => m.matched).map((m) => m.listenerKey));
  // (3): eligibility = the edge's listener resolved AND a codec exists for the format.
  const published: PublishedEdge[] = rctx.published.map((e) =>
    e.eligible === false ||
    (renderFormat !== null && resolved.has(e.listenerKey) && formatSupported(e.proto, renderFormat))
      ? e
      : { ...e, eligible: false },
  );
  const rule = ruleForDelivery(rctx.rule, rctx.deliveryStyle ?? 'subscription');
  const hasAutoGroup = formatHasAutoGroup(rule, format);
  const canEmitV6 = ruleCanEmitV6(rule, hasAutoGroup);
  // Latency ordering: each address's whole path for a steered member's country.
  const country = opts.edgeCountry ?? null;
  const figures =
    country && rctx.latency
      ? new Map(published.map((e) => [e.edgeId, pathFigure(e, country, rctx.latency!)] as const))
      : null;
  const pathMs = figures
    ? new Map(
        [...figures]
          .filter((f): f is [string, PathFigure] => f[1] !== null)
          .map(([id, f]) => [id, f.ms]),
      )
    : undefined;
  // (4): the PRF pick over the FULL pool order, walking past ineligible positions.
  const assigned = assignEndpoints(renderKey, published, {
    now: opts.now,
    preferDistinctProviders: rctx.preferDistinctProviders,
    ...(rctx.edgePick ? { edgePick: rctx.edgePick } : {}),
    ...(rctx.memberLane ? { memberLane: rctx.memberLane } : {}),
    includeBackup: rule.includeBackup,
    canEmitV6,
    // Further server names only where an auto group hides them.
    ...namesInBody(rule, hasAutoGroup),
    where: opts.where,
    edgeCountry: opts.edgeCountry ?? null,
    ...(opts.edgeCountry && rctx.ownCountries?.includes(opts.edgeCountry) ? { ownPool: true } : {}),
    ...(opts.avoidBlockedIn ? { avoidBlockedIn: opts.avoidBlockedIn } : {}),
    minProvenForExclusive: rctx.minProvenForExclusive,
    ...(pathMs ? { pathMs } : {}),
  });
  // (5): render + the edge-required verdict. A retained entry on a covered
  // transport that is no edge of the origin is left out (`withheld`).
  const out = renderEdgeEndpoints({
    body,
    matchers: rctx.matchers,
    assigned,
    rule: rctx.rule,
    originAddress: rctx.originAddress,
    nodeAddresses: rctx.nodeAddresses,
    edgeAddresses: edgeAddressesOf(rctx.published),
    deliveryStyle: rctx.deliveryStyle,
    exit: rctx.exit ?? null,
  });
  // An open member left with nothing because only trusted addresses remain:
  // its own reason (fail closed), so the refusal counter tells it apart.
  const delivery =
    rctx.memberLane === 'open' &&
    out.delivery.kind === 'unavailable' &&
    out.delivery.reason === 'empty_pool' &&
    published.some((e) => e.lane === 'trusted' && e.eligible !== false)
      ? { kind: 'unavailable' as const, reason: 'open_lane_empty' as const }
      : out.delivery;
  // (6): the eligibility snapshot the DB half persists on the subscription.
  return {
    ...out,
    delivery,
    snapshot: {
      listenerKeys: [...resolved].sort(),
      primaryEdgeId: assigned.primary?.edge.edgeId ?? null,
      backupEdgeId: assigned.backup?.edge.edgeId ?? null,
      autoGroup: hasAutoGroup,
      ...(assigned.primaryTier !== undefined ? { primaryTier: assigned.primaryTier } : {}),
      ...(assigned.backupTier !== undefined ? { backupTier: assigned.backupTier } : {}),
    },
    ...(opts.edgeCountry
      ? {
          meantFor: {
            primary: assigned.primaryMeantFor === true,
            backup: assigned.backupMeantFor === true,
          },
        }
      : {}),
    ...(figures
      ? {
          latency: {
            primary: assigned.primary
              ? {
                  band: assigned.primaryBand ?? 0,
                  path: figures.get(assigned.primary.edge.edgeId) ?? null,
                }
              : null,
            backup: assigned.backup
              ? {
                  band: assigned.backupBand ?? 0,
                  path: figures.get(assigned.backup.edge.edgeId) ?? null,
                }
              : null,
          },
        }
      : {}),
    validUntil: renderValidUntil([assigned.primary?.edge, assigned.backup?.edge]),
  };
}
