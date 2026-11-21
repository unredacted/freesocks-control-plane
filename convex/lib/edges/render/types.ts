/**
 * Shared renderer input/output. A renderer takes the backend body for ONE pinned
 * node, the LISTENER MATCHERS (how each listener's template entry is found in
 * the body and what it must speak) and the subscriber's assigned endpoints, and
 * emits the same format with the templates replaced by complete, labelled
 * connections. Renderers are pure and fail OPEN only for a body shape they do
 * not understand (`applied:false`); the DB half turns that into an unavailable
 * response for an edge-required subscription (edgeRender.ts).
 */
import type { EncryptionRule } from '../../../../src/shared/encryptionRule';
import { encryptedName } from '../../../../src/shared/entryNames';
import type { ListenerProto } from '../protocols';
import type { MatchRule } from '../registration';

export interface RenderMatcher {
  listenerKey: string;
  rule: MatchRule;
  /** Legacy Hosts adopted from a manual deployment also identify the listener. */
  legacyRemarks?: readonly string[];
  /**
   * The listener's ENCRYPTED TWIN: a second transport of the same node behind
   * the same addresses that runs VLESS Encryption (docs/backends.md), found in
   * the body by its own Host remark (and the remarks that Host had before its
   * node was renamed). A body may carry the plain entry, the twin, or both;
   * `RenderRuleInput.encryption` says which of them an app gets.
   */
  encrypted?: {
    remarks: readonly string[];
    /**
     * The fronts the twin was checked through (convex/nodeTwins.ts): it is
     * handed out through these and no other, so a front published since gets
     * the plain entry alone. Absent = no limit.
     */
    edgeIds?: readonly string[];
  };
  /** What the listener speaks: the matched entry must agree (codec verification). */
  proto: ListenerProto;
  originAddress: string;
  originPort: number;
}

export interface RenderEndpoint {
  role: 'primary' | 'backup';
  /**
   * The member-facing name (src/shared/entryNames.ts, e.g. "🇧🇷 via Example Town ·
   * IPv6", "🌐 via CDN 1"), given by the renderer once the body's entries are
   * known (lib/edges/render.ts `nameEntries`).
   */
  label: string;
  /** The name without its form tag or spare number: one per address ("🇧🇷 via Example Town"). */
  base?: string;
  edgeId: string;
  /** The listener whose template entry to clone. */
  listenerKey: string;
  address: string;
  /**
   * `name` = an L7 front's hostname (one entry, never a v6 sibling), or an L4
   * address's name (lib/edges/addressNames.ts).
   */
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
  /**
   * A raw IP of an address members are handed by NAME, for when the name is
   * blocked or answered falsely: the IPv4 in a body with an auto group (the
   * app switches to it by itself), both IPs in a link list (the member picks
   * one by hand). Ranked after every first-name entry and before further names.
   */
  fallback?: boolean;
}

export interface RenderRuleInput {
  /** Add the url-test group (`AUTO_GROUP_NAME`, src/shared/entryNames.ts) where the format has one. */
  autoGroup: boolean;
  /**
   * Which of a listener's two entries the app gets where the body carries its
   * encrypted twin (src/shared/encryptionRule.ts). Absent = `prefer`.
   */
  encryption?: EncryptionRule;
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
  /**
   * Edge-required delivery: whether a RETAINED entry's address is one FCP
   * cannot vouch for (not an edge of the origin; the node by an address FCP
   * knows is the leak check's to refuse). Such an entry on a covered transport
   * (it speaks what one of the listeners speaks) is left out of the body and
   * reported in `withheld`. Absent: every other entry passes, as before.
   */
  withholds?: (address: string) => boolean;
}

/** Why a listener's template entry could not be used. */
export type MatchFailure = 'no_match' | 'ambiguous_match' | 'entry_mismatch' | 'entry_unsupported';

export interface ListenerMatch {
  listenerKey: string;
  matched: boolean;
  reason?: MatchFailure;
  /** The listener's encrypted twin resolved in this body. */
  encrypted?: boolean;
  /**
   * The body carries the twin and NOT the plain entry: the listener can only
   * be served encrypted, so an app that must get the plain entry has nothing
   * to use from it (`listenerServable`).
   */
  twinOnly?: boolean;
}

/**
 * Whether a resolved listener has an entry to give under the rule. The
 * pipeline asks BEFORE it assigns edges: an edge of a listener with nothing to
 * give would otherwise be picked and leave the body empty, while another
 * listener of the same body could have served the member.
 */
export function listenerServable(
  m: ListenerMatch,
  rule: Pick<RenderRuleInput, 'encryption'>,
): boolean {
  return m.matched && !(m.twinOnly === true && rule.encryption === 'plain');
}

export interface RenderOutput {
  body: string;
  applied: boolean;
  /** Why nothing was applied (fail-open reason), for counters/logs only. */
  reason?: string;
  emitted: number;
  /** Per listener, whether its template entry resolved in this body. */
  listeners?: ListenerMatch[];
  /** The entries left out (`RenderInput.withholds`): their names, never their addresses. */
  withheld?: Array<string | null>;
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
    // further-name entry, so a cap cuts the extra names first; a named
    // address's raw IPs sit between them (a blocked name takes its further
    // names with it, never its IPs), IPv4 before IPv6.
    return (
      (variant > 0 ? 1000 : e.fallback ? 500 : 0) +
      roleRank * 100 +
      variant * 2 +
      (e.family === 'v6' ? 1 : 0)
    );
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
  /**
   * The entry runs VLESS Encryption: it carries a client string Xray would
   * take (`parseClientEncryption`), not merely something other than `none`.
   * Absent = plain.
   */
  encrypted?: boolean;
}

export interface ResolvedMatchers<T> {
  /** Each listener's plain template entry. */
  templates: Map<string, T>;
  /** Each listener's encrypted twin, where the body carries a usable one. */
  encrypted: Map<string, T>;
  /**
   * Every entry named as some listener's twin, usable or not. They are
   * templates like the plain ones (they point at whatever the backend Host
   * carries), so a codec never passes one through.
   */
  twinEntries: Set<T>;
  /** Per listener whose twin is limited to some fronts (`RenderMatcher.encrypted.edgeIds`): those fronts. */
  twinEdges: Map<string, ReadonlySet<string>>;
  matches: ListenerMatch[];
}

export function resolveMatchers<T>(
  entries: readonly MatchableEntry<T>[],
  matchers: readonly RenderMatcher[],
  sameAddress: (a: string, b: string) => boolean,
): ResolvedMatchers<T> {
  const templates = new Map<string, T>();
  const encrypted = new Map<string, T>();
  const twinEdges = new Map<string, ReadonlySet<string>>();
  const matches: ListenerMatch[] = [];
  // Twins first: a twin sits at its listener's own address, so it must never
  // be read as the plain entry (an address or whole-body rule would).
  const twinRemarks = new Set(matchers.flatMap((m) => m.encrypted?.remarks ?? []));
  const isTwin = (e: MatchableEntry<T>) => e.identity !== null && twinRemarks.has(e.identity);
  const twinEntries = new Set(entries.filter(isTwin).map((e) => e.entry));
  for (const m of matchers) {
    if (!m.encrypted) continue;
    const own = new Set(m.encrypted.remarks);
    // Under several of its remarks (a rename in flight) the first is the twin.
    const c = entries.find((e) => e.identity !== null && own.has(e.identity));
    // Usable only when it is what it is named as: this listener's transport,
    // and really encrypted (a twin entry without a client string would hand
    // out the plain transport under the encrypted name).
    // And only where some front was checked on it: a twin no front carries
    // yet is nobody's to use (its entry is still a template, never passed on).
    const limit = m.encrypted.edgeIds;
    if (limit) twinEdges.set(m.listenerKey, new Set(limit));
    if (
      c &&
      c.encrypted === true &&
      c.supported(m.proto) &&
      c.agrees(m.proto) &&
      (!limit || limit.length > 0)
    )
      encrypted.set(m.listenerKey, c.entry);
  }
  const proxyEntries = entries.filter(
    (e) => (e.identity !== null || e.address !== null) && !isTwin(e),
  );
  const matched = (m: RenderMatcher): ListenerMatch => ({
    listenerKey: m.listenerKey,
    matched: true,
    ...(encrypted.has(m.listenerKey) ? { encrypted: true } : {}),
  });
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
      // A body that carries only the twin (the plain Host kept out of this
      // format on the backend) still resolves the listener.
      if (encrypted.has(m.listenerKey)) matches.push({ ...matched(m), twinOnly: true });
      else matches.push({ listenerKey: m.listenerKey, matched: false, reason: 'no_match' });
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
    matches.push(matched(m));
  }
  // A listener whose plain entry FAILED (ambiguous, another transport) is not
  // rescued by its twin: something about it is not what FCP registered.
  for (const r of matches) if (!r.matched) encrypted.delete(r.listenerKey);
  return { templates, encrypted, twinEntries, twinEdges, matches };
}

/** Every template entry of a resolution: the plain ones and every twin. */
export function templateEntries<T>(r: ResolvedMatchers<T>): Set<T> {
  return new Set<T>([...r.templates.values(), ...r.twinEntries]);
}

/**
 * The template entries that stay in a body beside the rendered ones when the
 * rule keeps templates (`dropTemplateEntries` off). Only the kind the
 * encryption rule hands out: a kept template is one more entry the app can
 * use, so `plain` keeps no twin and `only` keeps no plain entry of a listener
 * that has a twin. A twin that is not usable is never kept, and a format that
 * cannot speak the layer (`twins: false`) keeps none at all.
 */
export function retainedTemplates<T>(
  r: ResolvedMatchers<T>,
  rule: Pick<RenderRuleInput, 'dropTemplateEntries' | 'encryption'>,
  opts: { twins: boolean } = { twins: true },
): Set<T> {
  const kept = new Set<T>();
  if (rule.dropTemplateEntries) return kept;
  const mode = rule.encryption ?? 'prefer';
  const twins = opts.twins && mode !== 'plain';
  for (const [key, plain] of r.templates)
    if (!(mode === 'only' && twins && r.encrypted.has(key))) kept.add(plain);
  // A twin limited to some fronts is never kept as it came: its own address
  // is whatever front the backend address names, checked on the twin or not.
  if (twins) for (const [key, twin] of r.encrypted) if (!r.twinEdges.has(key)) kept.add(twin);
  return kept;
}

/** One entry a codec writes: an endpoint, the template it is a copy of, and its name. */
export interface PlannedEntry<T> {
  endpoint: RenderEndpoint;
  template: T;
  label: string;
}

/**
 * The entries a body gets, in order, for endpoints already ordered and capped
 * (`orderEndpoints`): each endpoint's first choice under the rule, then (rule
 * `prefer`) the plain fallbacks in the same order, named as such. `mixed` says
 * the body holds a fallback: an auto group must then try entries IN ORDER, not
 * pick the fastest (the two are equally fast, so the fastest would be either).
 *
 * A cap (`maxEntries`) counts endpoints: a fallback rides with its endpoint,
 * so capping never leaves an app with entries it cannot use.
 */
export function planEntries<T>(
  endpoints: readonly RenderEndpoint[],
  r: Pick<ResolvedMatchers<T>, 'templates' | 'encrypted'> &
    Partial<Pick<ResolvedMatchers<T>, 'twinEdges'>>,
  rule: Pick<RenderRuleInput, 'encryption'>,
): { entries: PlannedEntry<T>[]; mixed: boolean } {
  const mode = rule.encryption ?? 'prefer';
  const first: PlannedEntry<T>[] = [];
  const fallback: PlannedEntry<T>[] = [];
  for (const endpoint of endpoints) {
    const plain = r.templates.get(endpoint.listenerKey);
    // Through a front the twin was not checked on, the endpoint has no twin:
    // it gets the plain entry, whatever the rule.
    const limit = r.twinEdges?.get(endpoint.listenerKey);
    const twin =
      !limit || limit.has(endpoint.edgeId) ? r.encrypted.get(endpoint.listenerKey) : undefined;
    const label = endpoint.label;
    if (mode === 'plain') {
      if (plain) first.push({ endpoint, template: plain, label });
    } else if (twin) {
      // Beside a plain entry the encrypted one is named as such and the plain
      // one keeps the name an app may already hold (lib/entryNames.ts
      // `encryptedName`). Alone (`only`), it takes the name: a server picked
      // by hand moves onto it.
      const both = mode === 'prefer' && !!plain;
      first.push({ endpoint, template: twin, label: both ? encryptedName(label) : label });
      if (both) fallback.push({ endpoint, template: plain, label });
    } else if (plain) first.push({ endpoint, template: plain, label });
  }
  return { entries: [...first, ...fallback], mixed: fallback.length > 0 };
}

/**
 * How ONE endpoint is handed out where its listener has an encrypted twin, by
 * the rule `planEntries` applies: `fallback` = the encrypted entry first with
 * the plain one behind it, `only` = the encrypted entry alone, `plain` = the
 * plain entry alone (the app's rule, a format that carries no twin, or a front
 * the twin was not checked through). Undefined = the listener has no twin, so
 * there is nothing to tell apart. For the render snapshot (what a member's
 * report is read by), from the listener's match and matcher rather than the
 * codec's own entries.
 *
 * `plain` is said, never left out: a snapshot written before this fact existed
 * has no value either, and on a listener with a twin that must read as "not
 * known", not as "plain" (convex/edgeAttribution.ts).
 */
export function twinDelivery(a: {
  match: ListenerMatch | undefined;
  matcher: Pick<RenderMatcher, 'encrypted'> | undefined;
  edgeId: string;
  rule: Pick<RenderRuleInput, 'encryption'>;
  /** Whether the body's format carries a twin at all (a sing-box body never does). */
  twinsInFormat: boolean;
}): 'fallback' | 'only' | 'plain' | undefined {
  if (!a.matcher?.encrypted) return undefined;
  const mode = a.rule.encryption ?? 'prefer';
  if (!a.twinsInFormat || mode === 'plain') return 'plain';
  if (!a.match?.matched || a.match.encrypted !== true) return 'plain';
  const limit = a.matcher.encrypted.edgeIds;
  if (limit && !limit.includes(a.edgeId)) return 'plain';
  return mode === 'prefer' && a.match.twinOnly !== true ? 'fallback' : 'only';
}

/**
 * The retained entries edge-required delivery leaves out (`RenderInput.withholds`):
 * not a template, on a transport one of the listeners speaks, at an address the
 * caller cannot vouch for. Entries on a transport no listener covers pass.
 */
export function withheldEntries<T>(
  entries: readonly MatchableEntry<T>[],
  matchers: readonly RenderMatcher[],
  isTemplate: (entry: T) => boolean,
  withholds: RenderInput['withholds'],
): MatchableEntry<T>[] {
  if (!withholds) return [];
  return entries.filter(
    (e) =>
      e.address !== null &&
      !isTemplate(e.entry) &&
      matchers.some((m) => e.supported(m.proto) && e.agrees(m.proto)) &&
      withholds(e.address),
  );
}

/** Every identity the matched templates carry (what the codecs drop / swap in groups). */
export function templateIdentities<T>(
  entries: readonly MatchableEntry<T>[],
  chosen: ReadonlySet<T>,
): Set<string> {
  const ids = new Set<string>();
  for (const e of entries) if (chosen.has(e.entry) && e.identity !== null) ids.add(e.identity);
  return ids;
}
