/**
 * Relay endpoint rendering: turn the panel's subscription body (already pinned
 * to ONE node) into the subscriber's primary/backup connections for that
 * node's relay listeners. Pure: the caller resolves assignment + rules + labels
 * and hands them in; this module only transforms text and checks the result.
 *
 * Edge-required delivery (docs/edges.md): a body that comes back from here
 * with `applied:false`, with no emitted endpoint, or with ANY outgoing entry
 * still at the origin address is not a body a member may receive. The verdict
 * is returned as `delivery`; the DB half (edgeRender.ts) turns anything but
 * `serve` into an unavailable response.
 */
import type { ClientRenderRule, EdgeConfig } from '../edgeConfig';
import { edgeHostname, type AssignedEndpoint } from './assignment';
import { detectBodyFormat, type SubscriptionFormat } from './clientFamilies';
import { sameAddress } from './hosts';
import { clashAddresses, matchClash, renderClash } from './render/clash';
import { linkAddresses, matchLinks, renderLinks } from './render/links';
import { matchSingbox, renderSingbox, singboxAddresses } from './render/singbox';
import type {
  ListenerMatch,
  RenderEndpoint,
  RenderMatcher,
  RenderOutput,
  RenderRuleInput,
} from './render/types';

export type { ListenerMatch, RenderEndpoint, RenderMatcher, RenderOutput } from './render/types';

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

/**
 * Delivery style: a subscription body (many entries, groups) or a single
 * access key (Outline: the body IS one key). Single-key delivery renders
 * exactly one entry, no backup, no auto group, and keeps the template's label.
 */
export type DeliveryStyle = 'subscription' | 'single-key';

export function ruleForDelivery(rule: EffectiveRule, style: DeliveryStyle): EffectiveRule {
  if (style === 'subscription') return rule;
  return {
    ...rule,
    includeBackup: false,
    maxEntries: 1,
    autoGroup: false,
    dropTemplateEntries: true,
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
 * plus an IPv6 entry when the edge has one and the mode allows it. An L7
 * (CDN-fronted) edge is ONE entry carrying its hostname.
 *
 * Leak guard: an endpoint whose address is the origin itself is never emitted,
 * whatever the pool says; `leaked` counts them so the caller can refuse.
 */
export function renderEntries(
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null },
  rule: EffectiveRule,
  hasAutoGroup: boolean,
  originAddress?: string,
): RenderEndpoint[] {
  return renderEntriesChecked(assigned, rule, hasAutoGroup, originAddress).entries;
}

export function renderEntriesChecked(
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null },
  rule: EffectiveRule,
  hasAutoGroup: boolean,
  originAddress?: string,
): { entries: RenderEndpoint[]; leaked: number } {
  const out: RenderEndpoint[] = [];
  let leaked = 0;
  const wantV6 = ruleCanEmitV6(rule, hasAutoGroup);
  const leaks = (addr: string) => originAddress !== undefined && sameAddress(addr, originAddress);
  const push = (ep: AssignedEndpoint | null) => {
    if (!ep) return;
    const label = ep.role === 'primary' ? rule.primaryLabel : rule.backupLabel;
    const base = {
      role: ep.role,
      edgeId: ep.edge.edgeId,
      listenerKey: ep.edge.listenerKey,
      port: ep.edge.edgePort,
      sni: ep.sni,
      hostHeader: ep.hostHeader,
    };
    const hostname = edgeHostname(ep.edge);
    if (hostname) {
      if (leaks(hostname)) leaked++;
      else out.push({ ...base, label, address: hostname, family: 'name' });
      return;
    }
    if (ep.edge.addresses.v4) {
      if (leaks(ep.edge.addresses.v4)) leaked++;
      else out.push({ ...base, label, address: ep.edge.addresses.v4, family: 'v4' });
    }
    if (ep.edge.addresses.v6 && wantV6) {
      if (leaks(ep.edge.addresses.v6)) leaked++;
      else
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
  return { entries: out, leaked };
}

/** Which listeners resolve in a body, per format (the eligibility pass). */
export function matchListeners(
  body: string,
  matchers: readonly RenderMatcher[],
): { format: ReturnType<typeof detectBodyFormat>; matches: ListenerMatch[] | null } {
  const format = detectBodyFormat(body);
  const r =
    format === 'links'
      ? matchLinks(body, matchers)
      : format === 'singbox-json'
        ? matchSingbox(body, matchers)
        : format === 'clash-yaml'
          ? matchClash(body, matchers)
          : null;
  return { format, matches: r?.matches ?? null };
}

/** Every proxy entry address:port in a body, per format (the outgoing leak check). */
export function outgoingAddresses(
  body: string,
  format: ReturnType<typeof detectBodyFormat>,
): Array<{ address: string; port: number }> {
  switch (format) {
    case 'links':
      return linkAddresses(body);
    case 'singbox-json':
      return singboxAddresses(body);
    case 'clash-yaml':
      return clashAddresses(body);
    default:
      return [];
  }
}

export type DeliveryVerdict =
  | { kind: 'serve' }
  | {
      kind: 'unavailable';
      reason:
        | 'unsupported_format'
        | 'no_match'
        | 'ambiguous_match'
        | 'entry_mismatch'
        | 'empty_pool'
        | 'leak_detected'
        | 'render_failed';
    };

export interface RenderResult extends RenderOutput {
  /** Endpoints dropped because they pointed at the origin. */
  leaked: number;
  /** Retained or emitted entries still at the origin address after rendering. */
  originEntries: number;
  delivery: DeliveryVerdict;
}

/**
 * Render one body; picks the renderer from the body's shape and judges the
 * result under the edge-required policy.
 *
 * Empty pool rule: when the subscriber has NO assignable edge the template
 * entries still point at whatever the panel Host carries and must be DROPPED
 * regardless of the family rule's flags. Under edge-required delivery an empty
 * pool is `unavailable` (never an empty body: an empty 200 would wipe the
 * client's configuration, a 503 keeps its last one).
 */
export function renderEdgeEndpoints(args: {
  body: string;
  matchers: RenderMatcher[];
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null };
  rule: EffectiveRule;
  originAddress: string;
  deliveryStyle?: DeliveryStyle;
}): RenderResult {
  const rule0 = ruleForDelivery(args.rule, args.deliveryStyle ?? 'subscription');
  const emptyPool = !args.assigned.primary;
  const format = detectBodyFormat(args.body);
  const unavailable = (
    reason: Extract<DeliveryVerdict, { kind: 'unavailable' }>['reason'],
    out?: RenderOutput,
  ): RenderResult => ({
    body: out?.body ?? args.body,
    applied: out?.applied ?? false,
    reason: out?.reason ?? reason,
    emitted: out?.emitted ?? 0,
    listeners: out?.listeners,
    leaked: 0,
    originEntries: 0,
    delivery: { kind: 'unavailable', reason },
  });
  if (format !== 'links' && format !== 'singbox-json' && format !== 'clash-yaml')
    return unavailable('unsupported_format');
  if (emptyPool) return unavailable('empty_pool');
  const rule: EffectiveRule = rule0;
  const { entries, leaked } = renderEntriesChecked(
    args.assigned,
    rule,
    formatHasAutoGroup(rule, format),
    args.originAddress,
  );
  if (entries.length === 0) return unavailable(leaked > 0 ? 'leak_detected' : 'empty_pool');
  const input = { body: args.body, matchers: args.matchers, endpoints: entries, rule };
  const out =
    format === 'links'
      ? renderLinks(input)
      : format === 'singbox-json'
        ? renderSingbox(input)
        : renderClash(input);
  if (!out.applied) {
    const failed = out.listeners?.find((l) => !l.matched);
    const reason =
      failed?.reason === 'ambiguous_match'
        ? 'ambiguous_match'
        : failed?.reason === 'entry_mismatch' || failed?.reason === 'entry_unsupported'
          ? 'entry_mismatch'
          : failed?.reason === 'no_match'
            ? 'no_match'
            : 'render_failed';
    return unavailable(reason, out);
  }
  if (out.emitted === 0) return unavailable('empty_pool', out);
  // Every entry that leaves (emitted AND retained) must not be the origin.
  const originEntries = outgoingAddresses(out.body, format).filter((e) =>
    sameAddress(e.address, args.originAddress),
  ).length;
  if (originEntries > 0)
    return {
      ...out,
      leaked,
      originEntries,
      delivery: { kind: 'unavailable', reason: 'leak_detected' },
    };
  return { ...out, leaked, originEntries: 0, delivery: { kind: 'serve' } };
}
