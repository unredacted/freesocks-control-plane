/**
 * Relay endpoint rendering: turn the panel's subscription body (already pinned
 * to ONE node) into the subscriber's primary/backup connections for that
 * node's relay slots. Pure: the caller resolves assignment + rules + labels
 * and hands them in; this module only transforms text.
 */
import type { ClientRenderRule, EdgeConfig } from '../edgeConfig';
import type { AssignedEndpoint } from './assignment';
import { detectBodyFormat, type SubscriptionFormat } from './clientFamilies';
import { renderClash } from './render/clash';
import { renderLinks } from './render/links';
import { renderSingbox } from './render/singbox';
import type { RenderEndpoint, RenderOutput, RenderRuleInput } from './render/types';

export type { RenderEndpoint, RenderOutput } from './render/types';

export interface EffectiveRule extends RenderRuleInput {
  enabled: boolean;
  includeBackup: boolean;
  ipv6Mode: 'off' | 'auto-group-only' | 'both';
  primaryLabel: string;
  backupLabel: string;
  ipv6Label: string;
}

/** Merge the global render config with one family's rule ('' / inherit = global). */
export function effectiveRule(cfg: EdgeConfig['render'], rule: ClientRenderRule): EffectiveRule {
  return {
    enabled: cfg.enabled && rule.enabled,
    autoGroup: rule.autoGroup,
    autoGroupName: rule.autoGroupName || cfg.autoGroupName,
    dropTemplateEntries: rule.dropTemplateEntries,
    maxEntries: rule.maxEntries,
    order: rule.order,
    includeBackup: rule.includeBackup,
    ipv6Mode: rule.ipv6Mode === 'inherit' ? cfg.ipv6Mode : rule.ipv6Mode,
    primaryLabel: rule.primaryLabel || cfg.primaryLabel,
    backupLabel: rule.backupLabel || cfg.backupLabel,
    ipv6Label: cfg.ipv6Label,
  };
}

/** Whether a body of this format gets an auto group under the rule. */
export function formatHasAutoGroup(
  rule: Pick<EffectiveRule, 'autoGroup'>,
  format: SubscriptionFormat | 'html' | 'unknown',
): boolean {
  return rule.autoGroup && (format === 'singbox-json' || format === 'clash-yaml');
}

/** Whether the rule lets this render emit an IPv6 entry at all (decides if an IPv6-only edge is assignable). */
export function ruleCanEmitV6(
  rule: Pick<EffectiveRule, 'ipv6Mode'>,
  hasAutoGroup: boolean,
): boolean {
  return rule.ipv6Mode === 'both' || (rule.ipv6Mode === 'auto-group-only' && hasAutoGroup);
}

/**
 * Expand assigned endpoints into render entries: the IPv4 entry per endpoint
 * plus an IPv6 entry when the edge has one and the mode allows it. In
 * `auto-group-only` mode the v6 entries are emitted only for formats with an
 * auto group (the caller passes `hasAutoGroup`).
 */
export function renderEntries(
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null },
  rule: EffectiveRule,
  hasAutoGroup: boolean,
): RenderEndpoint[] {
  const out: RenderEndpoint[] = [];
  const wantV6 = ruleCanEmitV6(rule, hasAutoGroup);
  const push = (ep: AssignedEndpoint | null) => {
    if (!ep) return;
    const label = ep.role === 'primary' ? rule.primaryLabel : rule.backupLabel;
    const base = {
      role: ep.role,
      edgeId: ep.edge.edgeId,
      slotRemark: ep.edge.slotRemark,
      port: ep.edge.edgePort,
      sni: ep.sni,
    };
    if (ep.edge.addresses.v4)
      out.push({ ...base, label, address: ep.edge.addresses.v4, family: 'v4' });
    if (ep.edge.addresses.v6 && wantV6) {
      out.push({
        ...base,
        label: ep.edge.addresses.v4 ? `${label} (${rule.ipv6Label})` : label,
        address: ep.edge.addresses.v6,
        family: 'v6',
      });
    }
  };
  push(assigned.primary);
  if (rule.includeBackup) push(assigned.backup);
  return out;
}

/**
 * Render one body; picks the renderer from the body's shape.
 *
 * Empty pool rule: when the subscriber has NO assignable edge (every edge
 * unpublished / draining / ineligible, or the profile has no active name) the
 * template entries still point at whatever the panel Host carries (typically
 * the former index-0 edge) and must be DROPPED — regardless of the family
 * rule's `dropTemplateEntries` or `enabled` flags, which only govern how a
 * NON-empty pool renders. Unknown body shapes still pass through (fail-open).
 */
export function renderEdgeEndpoints(args: {
  body: string;
  templateRemarks: string[];
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null };
  rule: EffectiveRule;
}): RenderOutput {
  const emptyPool = !args.assigned.primary;
  if (!args.rule.enabled && !emptyPool)
    return { body: args.body, applied: false, reason: 'disabled', emitted: 0 };
  const format = detectBodyFormat(args.body);
  const rule: EffectiveRule = emptyPool ? { ...args.rule, dropTemplateEntries: true } : args.rule;
  const endpoints = emptyPool
    ? []
    : renderEntries(args.assigned, rule, formatHasAutoGroup(rule, format));
  const input = {
    body: args.body,
    templateRemarks: args.templateRemarks,
    endpoints,
    rule,
  };
  switch (format) {
    case 'links':
      return renderLinks(input);
    case 'singbox-json':
      return renderSingbox(input);
    case 'clash-yaml':
      return renderClash(input);
    default:
      return {
        body: args.body,
        applied: false,
        reason: `unsupported_format:${format}`,
        emitted: 0,
      };
  }
}
