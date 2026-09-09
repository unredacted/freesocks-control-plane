/**
 * The pure half of relay rendering: given the render context FCP resolved for
 * one subscription (published edges of its pinned node, the slot template
 * remarks, the effective client rule) and the panel body, assign this
 * subscriber's endpoints and rewrite the body. Used by the fronted /sub route,
 * the mirror refresh and the admin preview so all three emit identical output
 * for the same (renderKey, epoch, family).
 */
import { assignEndpoints, type PublishedEdge } from './assignment';
import { detectBodyFormat } from './clientFamilies';
import {
  formatHasAutoGroup,
  renderEdgeEndpoints,
  ruleCanEmitV6,
  type EffectiveRule,
  type RenderOutput,
} from './render';

export interface EdgeRenderContext {
  /** Publication epoch of the origin: part of the cache key. */
  epoch: number;
  /** Every slot remark of the origin (template entries to replace / drop). */
  templateRemarks: string[];
  published: PublishedEdge[];
  rule: EffectiveRule;
  preferDistinctProviders: boolean;
}

export function applyEdgeRender(
  rctx: EdgeRenderContext,
  body: string,
  renderKey: string,
  opts: { now: number },
): RenderOutput {
  // The body's format decides whether an IPv6-only edge can be emitted at all
  // (auto-group-only mode needs an auto-capable format), so it is resolved
  // BEFORE assignment: an edge the render cannot emit is not assignable.
  const format = detectBodyFormat(body);
  const canEmitV6 = ruleCanEmitV6(rctx.rule, formatHasAutoGroup(rctx.rule, format));
  const assigned = assignEndpoints(renderKey, rctx.published, {
    now: opts.now,
    preferDistinctProviders: rctx.preferDistinctProviders,
    includeBackup: rctx.rule.includeBackup,
    canEmitV6,
  });
  return renderEdgeEndpoints({
    body,
    templateRemarks: rctx.templateRemarks,
    assigned,
    rule: rctx.rule,
  });
}
