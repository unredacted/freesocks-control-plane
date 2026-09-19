/**
 * The pure half of relay rendering: given the render context FCP resolved for
 * one subscription (published edges of its origin, the listener matchers, the
 * effective client rule) and the panel body, resolve which listeners the body
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
import { assignEndpoints, type PublishedEdge } from './assignment';
import { detectBodyFormat } from './clientFamilies';
import { formatSupported } from './protocols';
import {
  formatHasAutoGroup,
  matchListeners,
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
  originAddress: string;
  deliveryStyle?: DeliveryStyle;
}

export interface RenderSnapshot {
  family?: string;
  listenerKeys: string[];
  primaryEdgeId: string | null;
  backupEdgeId: string | null;
}

export interface PipelineResult extends RenderResult {
  snapshot: RenderSnapshot;
}

const RENDER_FORMAT_OF = {
  links: 'links',
  'singbox-json': 'singbox',
  'clash-yaml': 'clash',
} as const;

export function applyEdgeRender(
  rctx: EdgeRenderContext,
  body: string,
  renderKey: string,
  opts: { now: number },
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
  const canEmitV6 = ruleCanEmitV6(rule, formatHasAutoGroup(rule, format));
  // (4): the PRF pick over the FULL pool order, walking past ineligible positions.
  const assigned = assignEndpoints(renderKey, published, {
    now: opts.now,
    preferDistinctProviders: rctx.preferDistinctProviders,
    includeBackup: rule.includeBackup,
    canEmitV6,
    namesPerEndpoint: rule.namesPerEndpoint,
    backupNames: rule.backupNames,
  });
  // (5): render + the edge-required verdict.
  const out = renderEdgeEndpoints({
    body,
    matchers: rctx.matchers,
    assigned,
    rule: rctx.rule,
    originAddress: rctx.originAddress,
    deliveryStyle: rctx.deliveryStyle,
  });
  // (6): the eligibility snapshot the DB half persists on the subscription.
  return {
    ...out,
    snapshot: {
      listenerKeys: [...resolved].sort(),
      primaryEdgeId: assigned.primary?.edge.edgeId ?? null,
      backupEdgeId: assigned.backup?.edge.edgeId ?? null,
    },
  };
}
