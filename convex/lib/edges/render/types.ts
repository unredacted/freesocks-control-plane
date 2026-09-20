/**
 * Shared renderer input/output. A renderer takes the backend body for ONE pinned
 * node, the LISTENER MATCHERS (how each listener's template entry is found in
 * the body and what it must speak) and the subscriber's assigned endpoints, and
 * emits the same format with the templates replaced by complete, labelled
 * connections. Renderers are pure and fail OPEN only for a body shape they do
 * not understand (`applied:false`); the DB half turns that into an unavailable
 * response for an edge-required subscription (edgeRender.ts).
 */
import type { ListenerProto } from '../protocols';
import type { MatchRule } from '../registration';

export interface RenderMatcher {
  listenerKey: string;
  rule: MatchRule;
  /** Legacy Hosts adopted from a manual deployment also identify the listener. */
  legacyRemarks?: readonly string[];
  /** What the listener speaks: the matched entry must agree (codec verification). */
  proto: ListenerProto;
  originAddress: string;
  originPort: number;
}

export interface RenderEndpoint {
  role: 'primary' | 'backup';
  /** Member-facing label (e.g. "FreeSocks Primary", "FreeSocks Backup (IPv6)"). */
  label: string;
  edgeId: string;
  /** The listener whose template entry to clone. */
  listenerKey: string;
  address: string;
  /** `name` = an L7 front's hostname (one entry, never a v6 sibling). */
  family: 'v4' | 'v6' | 'name';
  port: number;
  /** Selected server name; null when the listener presents none (address/port swap only). */
  sni: string | null;
  /**
   * The HTTP Host header to write for the HTTP transports (`ws`,
   * `httpupgrade`); null = the listener carries none, so the template's own
   * transport parameters are left alone.
   */
  hostHeader: string | null;
  /**
   * 0 / absent = the endpoint's first server name; 1, 2, ... = a further name
   * for the same endpoint (another entry, another SNI). Variants are the first
   * thing `maxEntries` drops: a rule that caps entries keeps primary + backup.
   */
  variant?: number;
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
  matchers: RenderMatcher[];
  endpoints: RenderEndpoint[];
  rule: RenderRuleInput;
}

/** Why a listener's template entry could not be used. */
export type MatchFailure = 'no_match' | 'ambiguous_match' | 'entry_mismatch' | 'entry_unsupported';

export interface ListenerMatch {
  listenerKey: string;
  matched: boolean;
  reason?: MatchFailure;
}

export interface RenderOutput {
  body: string;
  applied: boolean;
  /** Why nothing was applied (fail-open reason), for counters/logs only. */
  reason?: string;
  emitted: number;
  /** Per listener, whether its template entry resolved in this body. */
  listeners?: ListenerMatch[];
}

export const AUTO_GROUP_TEST_URL = 'https://www.gstatic.com/generate_204';

/** Order + cap the endpoints per the rule. A `name` entry ranks like a v4 one: it is the endpoint. */
export function orderEndpoints(
  endpoints: RenderEndpoint[],
  rule: RenderRuleInput,
): RenderEndpoint[] {
  const rank = (e: RenderEndpoint) => {
    const roleRank =
      rule.order === 'backup-first' ? (e.role === 'backup' ? 0 : 1) : e.role === 'primary' ? 0 : 1;
    const variant = e.variant ?? 0;
    // Every first-name entry (both roles, both families) outranks every
    // further-name entry, so a cap cuts the extra names first.
    return (variant > 0 ? 1000 : 0) + roleRank * 100 + variant * 2 + (e.family === 'v6' ? 1 : 0);
  };
  const sorted = [...endpoints].sort((a, b) => rank(a) - rank(b));
  return rule.maxEntries > 0 ? sorted.slice(0, rule.maxEntries) : sorted;
}

/**
 * Resolve every matcher against the body's proxy entries. `entries` is the
 * codec's view of each proxy entry: its identity (remark / tag / name), its
 * address:port, and a verifier that says whether the entry speaks what the
 * listener says it does. Returns the matched entry per listener key and the
 * failures for the rest. Shared by the three codecs so the rules cannot drift.
 */
export interface MatchableEntry<T> {
  entry: T;
  identity: string | null;
  address: string | null;
  port: number | null;
  /** Whether the entry's scheme / type is one this listener's codec can rewrite at all. */
  supported: (proto: ListenerProto) => boolean;
  /** Whether the entry's transport / security agree with the listener. */
  agrees: (proto: ListenerProto) => boolean;
}

export function resolveMatchers<T>(
  entries: readonly MatchableEntry<T>[],
  matchers: readonly RenderMatcher[],
  sameAddress: (a: string, b: string) => boolean,
): { templates: Map<string, T>; matches: ListenerMatch[] } {
  const templates = new Map<string, T>();
  const matches: ListenerMatch[] = [];
  const proxyEntries = entries.filter((e) => e.identity !== null || e.address !== null);
  for (const m of matchers) {
    let candidates: MatchableEntry<T>[];
    switch (m.rule.kind) {
      case 'remark': {
        const names = new Set([m.rule.remark, ...(m.legacyRemarks ?? [])]);
        candidates = proxyEntries.filter((e) => e.identity !== null && names.has(e.identity));
        // Several legacy Hosts of one listener are all that listener; the first is the template.
        if (candidates.length > 1) candidates = [candidates[0]];
        break;
      }
      case 'address':
        candidates = proxyEntries.filter(
          (e) =>
            e.address !== null &&
            e.port === m.originPort &&
            sameAddress(e.address, m.originAddress),
        );
        break;
      case 'whole-body':
        candidates = proxyEntries.length === 1 ? [proxyEntries[0]] : [];
        if (proxyEntries.length > 1) {
          matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'ambiguous_match' });
          continue;
        }
        break;
    }
    if (candidates.length === 0) {
      matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'no_match' });
      continue;
    }
    if (candidates.length > 1) {
      matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'ambiguous_match' });
      continue;
    }
    const c = candidates[0];
    if (!c.supported(m.proto)) {
      matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'entry_unsupported' });
      continue;
    }
    if (!c.agrees(m.proto)) {
      matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'entry_mismatch' });
      continue;
    }
    templates.set(m.listenerKey, c.entry);
    matches.push({ listenerKey: m.listenerKey, matched: true });
  }
  return { templates, matches };
}

/** Every identity the matched templates carry (what the codecs drop / swap in groups). */
export function templateIdentities<T>(
  entries: readonly MatchableEntry<T>[],
  templates: Map<string, T>,
): Set<string> {
  const ids = new Set<string>();
  const chosen = new Set(templates.values());
  for (const e of entries) if (chosen.has(e.entry) && e.identity !== null) ids.add(e.identity);
  return ids;
}
