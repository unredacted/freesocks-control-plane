/**
 * Relay endpoint rendering: turn the panel's subscription body (already pinned
 * to ONE node) into the subscriber's primary/backup connections for that
 * node's relay slots. Pure: the caller resolves assignment + rules + labels
 * and hands them in; this module only transforms text.
 */
import type { ClientRenderRule, RelayConfig } from '../relayConfig';
import type { AssignedEndpoint } from './assignment';
import { detectBodyFormat } from './clientFamilies';
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
export function effectiveRule(cfg: RelayConfig['render'], rule: ClientRenderRule): EffectiveRule {
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
    const wantV6 =
      rule.ipv6Mode === 'both' || (rule.ipv6Mode === 'auto-group-only' && hasAutoGroup);
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

/** Render one body; picks the renderer from the body's shape. */
export function renderRelayEndpoints(args: {
  body: string;
  templateRemarks: string[];
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null };
  rule: EffectiveRule;
}): RenderOutput {
  if (!args.rule.enabled)
    return { body: args.body, applied: false, reason: 'disabled', emitted: 0 };
  if (!args.assigned.primary)
    return { body: args.body, applied: false, reason: 'no_assignment', emitted: 0 };
  const format = detectBodyFormat(args.body);
  const hasAutoGroup =
    args.rule.autoGroup && (format === 'singbox-json' || format === 'clash-yaml');
  const endpoints = renderEntries(args.assigned, args.rule, hasAutoGroup);
  const input = {
    body: args.body,
    templateRemarks: args.templateRemarks,
    endpoints,
    rule: args.rule,
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
