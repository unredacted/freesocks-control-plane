/**
 * The pure half of relay rendering: given the render context FCP resolved for
 * one subscription (published edges of its pinned node, the slot template
 * remarks, the effective client rule) and the panel body, assign this
 * subscriber's endpoints and rewrite the body. Used by the fronted /sub route,
 * the mirror refresh and the admin preview so all three emit identical output
 * for the same (renderKey, epoch, family).
 */
import { assignEndpoints, type PublishedEdge } from './assignment';
import { renderRelayEndpoints, type EffectiveRule, type RenderOutput } from './render';

export interface RelayRenderContext {
  /** Publication epoch of the origin: part of the cache key. */
  epoch: number;
  /** Every slot remark of the origin (template entries to replace / drop). */
  templateRemarks: string[];
  published: PublishedEdge[];
  rule: EffectiveRule;
  preferDistinctProviders: boolean;
}

export function applyRelayRender(
  rctx: RelayRenderContext,
  body: string,
  renderKey: string,
  opts: { now: number; lastContentAt?: number | null },
): RenderOutput {
  const assigned = assignEndpoints(renderKey, rctx.published, {
    now: opts.now,
    preferDistinctProviders: rctx.preferDistinctProviders,
    includeBackup: rctx.rule.includeBackup,
    subscriberLastContentAt: opts.lastContentAt ?? null,
  });
  return renderRelayEndpoints({
    body,
    templateRemarks: rctx.templateRemarks,
    assigned,
    rule: rctx.rule,
  });
}
