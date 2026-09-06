/**
 * Shared renderer input/output. A renderer takes the panel body for ONE pinned
 * node, the template entries' identities (slot remarks) and the subscriber's
 * assigned endpoints, and emits the same format with the templates replaced by
 * complete, labelled connections. Renderers are pure and fail OPEN: any shape
 * they do not understand comes back unchanged with `applied:false`.
 */

export interface RenderEndpoint {
  role: 'primary' | 'backup';
  /** Member-facing label (e.g. "FreeSocks Primary", "FreeSocks Backup (IPv6)"). */
  label: string;
  edgeId: string;
  /** The template entry to clone (the slot's stable Host remark). */
  slotRemark: string;
  address: string;
  family: 'v4' | 'v6';
  port: number;
  sni: string;
}

export interface RenderRuleInput {
  autoGroup: boolean;
  autoGroupName: string;
  dropTemplateEntries: boolean;
  /** 0 = unlimited. */
  maxEntries: number;
  order: 'primary-first' | 'backup-first';
}

export interface RenderInput {
  body: string;
  /** Every slot remark that identifies a template entry for this node. */
  templateRemarks: string[];
  endpoints: RenderEndpoint[];
  rule: RenderRuleInput;
}

export interface RenderOutput {
  body: string;
  applied: boolean;
  /** Why nothing was applied (fail-open reason), for counters/logs only. */
  reason?: string;
  emitted: number;
}

export const AUTO_GROUP_TEST_URL = 'https://www.gstatic.com/generate_204';

/** Order + cap the endpoints per the rule. */
export function orderEndpoints(
  endpoints: RenderEndpoint[],
  rule: RenderRuleInput,
): RenderEndpoint[] {
  const rank = (e: RenderEndpoint) => {
    const roleRank =
      rule.order === 'backup-first' ? (e.role === 'backup' ? 0 : 1) : e.role === 'primary' ? 0 : 1;
    return roleRank * 2 + (e.family === 'v4' ? 0 : 1);
  };
  const sorted = [...endpoints].sort((a, b) => rank(a) - rank(b));
  return rule.maxEntries > 0 ? sorted.slice(0, rule.maxEntries) : sorted;
}
