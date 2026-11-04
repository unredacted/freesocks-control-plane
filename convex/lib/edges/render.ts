/**
 * Origin endpoint rendering: turn the backend's subscription body (already pinned
 * to ONE node) into the subscriber's primary/backup connections for that
 * node's origin listeners. Pure: the caller resolves assignment + rules and
 * hands them in; this module names the entries (src/shared/entryNames.ts),
 * transforms text and checks the result.
 *
 * Edge-required delivery (docs/edges.md): a body that comes back from here
 * with `applied:false`, with no emitted endpoint, or with ANY outgoing entry
 * still at the origin address is not a body a member may receive. The verdict
 * is returned as `delivery`; the DB half (edgeRender.ts) turns anything but
 * `serve` into an unavailable response. An entry FCP cannot place (on a covered
 * transport, at neither an edge nor an address the node is known by) is left
 * out of the body instead (`withheld`), and the operator is told.
 */
import YAML from 'yaml';
import {
  entryBase,
  entryName,
  memberPlaceOf,
  placeLetter,
  type EntryForm,
  type EntryRoute,
} from '../../../src/shared/entryNames';
import {
  RENDER_CLIENT_FAMILIES,
  isRenderClientFamily,
  type ClientRenderRule,
  type EdgeConfig,
  type RenderClientFamily,
} from '../edgeConfig';
import { edgeHostname, type AssignedEndpoint, type DeliveryPath } from './assignment';
import { CLIENT_FAMILY_FORMATS, detectBodyFormat, type SubscriptionFormat } from './clientFamilies';
import { sameAddress } from './hosts';
import { clashAddresses, matchClash, renderClash } from './render/clash';
import { decodeLinkList, linkAddresses, matchLinks, renderLinks } from './render/links';
import { matchSingbox, renderSingbox, singboxAddresses } from './render/singbox';
import {
  orderEndpoints,
  type ListenerMatch,
  type RenderEndpoint,
  type RenderMatcher,
  type RenderOutput,
  type RenderRuleInput,
} from './render/types';

export type { ListenerMatch, RenderEndpoint, RenderMatcher, RenderOutput } from './render/types';

export interface EffectiveRule extends RenderRuleInput {
  enabled: boolean;
  includeBackup: boolean;
  ipv6Mode: 'off' | 'auto-group-only' | 'both';
  /**
   * Every entry gets this name instead of its member name (an operator's test
   * link, convex/edgeTestLinks.ts: never a member body). Absent for members.
   */
  fixedLabel?: string;
  /** Server names per endpoint for a listener on the `hrw1` PRF (1 = one name, as ever). */
  namesPerEndpoint: number;
  backupNames: number;
}

/** Merge the global render config with one family's rule ('' / inherit = global). */
export function effectiveRule(cfg: EdgeConfig['render'], rule: ClientRenderRule): EffectiveRule {
  return {
    enabled: cfg.enabled && rule.enabled,
    autoGroup: rule.autoGroup,
    dropTemplateEntries: rule.dropTemplateEntries,
    maxEntries: rule.maxEntries,
    order: rule.order,
    includeBackup: rule.includeBackup,
    ipv6Mode: rule.ipv6Mode === 'inherit' ? cfg.ipv6Mode : rule.ipv6Mode,
    namesPerEndpoint: cfg.namesPerEndpoint,
    backupNames: cfg.backupNames,
  };
}

/**
 * Delivery style: a subscription body (many entries, groups) or a single
 * access key (Outline: the body IS one key). Single-key delivery renders
 * exactly one entry, no backup, no auto group, named like any other entry.
 */
export type DeliveryStyle = 'subscription' | 'single-key';

export function ruleForDelivery(rule: EffectiveRule, style: DeliveryStyle): EffectiveRule {
  if (style === 'subscription') return rule;
  return {
    ...rule,
    includeBackup: false,
    namesPerEndpoint: 1,
    backupNames: 1,
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

/**
 * Server names per endpoint a body carries. Further names only where an auto
 * group hides them and moves past a blocked one by itself; a link list would
 * show each as one more entry the member cannot tell from the first (same
 * address and key, only the unseen server name differs), so it carries the
 * first name only.
 */
export function namesInBody(
  rule: Pick<EffectiveRule, 'namesPerEndpoint' | 'backupNames'>,
  hasAutoGroup: boolean,
): { namesPerEndpoint: number; backupNames: number } {
  return hasAutoGroup
    ? { namesPerEndpoint: rule.namesPerEndpoint, backupNames: rule.backupNames }
    : { namesPerEndpoint: 1, backupNames: 1 };
}

/**
 * The rule a stored render snapshot was made under, for a replay without the
 * body (member labels, report attribution): the snapshot family's own rule,
 * and whether the body had an auto group as the snapshot recorded it (the
 * body decides, not the family). A snapshot from before that was recorded
 * falls back to the family's base format (`CLIENT_FAMILY_FORMATS`). An
 * unknown family reads as `other` (a link list).
 */
export function snapshotRuleOf(
  render: EdgeConfig['render'],
  snap: { family?: string; autoGroup?: boolean },
): { rule: EffectiveRule; hasAutoGroup: boolean } {
  const fam: RenderClientFamily = isRenderClientFamily(snap.family) ? snap.family : 'other';
  const rule = effectiveRule(render, render.clients[fam]);
  return {
    rule,
    hasAutoGroup: snap.autoGroup ?? formatHasAutoGroup(rule, CLIENT_FAMILY_FORMATS[fam]),
  };
}

/**
 * Every delivery path a member body can take on this deployment (the format
 * of the body x whether its rule may emit IPv6), over the client families
 * whose rule is on: what the detector's steering veto must cover
 * (lib/edges/assignment.ts `steeringAvoids`).
 */
export function deliveryPathsOf(
  render: EdgeConfig['render'],
  style: DeliveryStyle,
): DeliveryPath[] {
  const out = new Map<string, DeliveryPath>();
  for (const family of RENDER_CLIENT_FAMILIES) {
    const rule = ruleForDelivery(effectiveRule(render, render.clients[family]), style);
    if (!rule.enabled) continue;
    for (const [format, body] of [
      ['links', 'links'],
      ['singbox', 'singbox-json'],
      ['clash', 'clash-yaml'],
    ] as const) {
      const path: DeliveryPath = {
        format,
        canEmitV6: ruleCanEmitV6(rule, formatHasAutoGroup(rule, body)),
        // The backup leads (and, under a cap, may be all that is handed out).
        backupFirst: rule.includeBackup && rule.order === 'backup-first',
      };
      out.set(`${path.format}|${path.canEmitV6}|${path.backupFirst}`, path);
    }
  }
  return [...out.values()];
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
 * (CDN-fronted) edge is ONE entry carrying its hostname. An L4 address with a
 * name (`addressName`, subscription delivery only) is dialled by the name in
 * place of its IPv4 entry (the name carries both families), and its raw IPs
 * stay in the body beside it, so a member whose lookup of the name is blocked
 * or answered falsely still has a way in. In a body with an auto group the
 * IPv6 entry is unchanged and the IPv4 follows as a fallback the app switches
 * to by itself; in a link list the member picks by hand, so both raw IPs are
 * alternatives after every first entry, the IPv4 first (it is the one an
 * IPv4-only network can use). A single key (Outline) keeps the IP: it has no
 * room for an alternative. Further server names (`alternates`) become entries
 * only in a body with an auto group (`namesInBody`).
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

/** The name an L4 endpoint is dialled by in this render, or null for its IPs. */
function addressNameOf(ep: AssignedEndpoint, names: boolean): string | null {
  return names && (ep.edge.layer ?? 'l4') === 'l4' && ep.edge.addresses.v4
    ? (ep.edge.addressName ?? null)
    : null;
}

/** Whether an address is the node itself: its origin or another address it is known by. */
export function isNodeAddress(
  addr: string,
  originAddress: string | undefined,
  nodeAddresses: readonly string[] = [],
): boolean {
  return (
    (originAddress !== undefined && sameAddress(addr, originAddress)) ||
    nodeAddresses.some((a) => sameAddress(addr, a))
  );
}

export function renderEntriesChecked(
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null },
  rule: EffectiveRule,
  hasAutoGroup: boolean,
  originAddress?: string,
  nodeAddresses: readonly string[] = [],
  opts: { names?: boolean } = {},
): { entries: RenderEndpoint[]; leaked: number } {
  const out: RenderEndpoint[] = [];
  let leaked = 0;
  const wantV6 = ruleCanEmitV6(rule, hasAutoGroup);
  const names = opts.names ?? true;
  const leaks = (addr: string) => isNodeAddress(addr, originAddress, nodeAddresses);
  // Every entry is named once the body's entries are known (`nameEntries`).
  const label = '';
  const push = (ep: AssignedEndpoint | null) => {
    if (!ep) return;
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
    const named = addressNameOf(ep, names);
    if (named) {
      // The name resolves to the address's own IPs: refused with any of them.
      const v4 = ep.edge.addresses.v4!;
      const v6 = ep.edge.addresses.v6;
      if (leaks(named) || leaks(v4) || (!!v6 && leaks(v6))) {
        leaked++;
        return;
      }
      // The name takes the IPv4 entry's place. The IPv6 entry stays: where
      // IPv4 is blocked and IPv6 works, a client that dials the name over
      // IPv4 first (its TCP connects, REALITY is then cut) never tries the
      // other family, so the member (or the auto group) needs the IPv6 entry
      // of its own. The raw IPv4 stays too, for a name that is blocked or
      // answered falsely.
      out.push({ ...base, label, address: named, family: 'name' });
      const ipv4: RenderEndpoint = {
        ...base,
        label,
        address: v4,
        family: 'v4',
        fallback: true,
      };
      const ipv6: RenderEndpoint | null =
        v6 && wantV6 ? { ...base, label, address: v6, family: 'v6' } : null;
      if (hasAutoGroup) {
        // The IPv6 entry ranks as without a name; the IPv4 is the fallback.
        if (ipv6) out.push(ipv6);
        out.push(ipv4);
      } else {
        // A link list never switches by itself: both raw IPs are alternatives
        // the member picks by hand, IPv4 before IPv6, after every first entry.
        out.push(ipv4);
        if (ipv6) out.push({ ...ipv6, fallback: true });
      }
      return;
    }
    if (ep.edge.addresses.v4) {
      if (leaks(ep.edge.addresses.v4)) leaked++;
      else out.push({ ...base, label, address: ep.edge.addresses.v4, family: 'v4' });
    }
    if (ep.edge.addresses.v6 && wantV6) {
      if (leaks(ep.edge.addresses.v6)) leaked++;
      else out.push({ ...base, label, address: ep.edge.addresses.v6, family: 'v6' });
    }
  };
  // A further server name is one more IPv4 entry for the same endpoint (the
  // IPv6 sibling belongs to the first name only: entries multiply otherwise),
  // and only in a body with an auto group (`namesInBody`): a link list would
  // show it as a look-alike of the first.
  const pushAlternates = (ep: AssignedEndpoint | null) => {
    if (!hasAutoGroup) return;
    if (!ep?.alternates || !ep.edge.addresses.v4 || leaks(ep.edge.addresses.v4)) return;
    // A named address's further names dial the name too.
    // (the name also resolves to the IPv6: refused with it, as the first entry is)
    const named = addressNameOf(ep, names);
    const v6 = ep.edge.addresses.v6;
    if (named && (leaks(named) || (!!v6 && leaks(v6)))) return;
    ep.alternates.forEach((alt, i) =>
      out.push({
        role: ep.role,
        edgeId: ep.edge.edgeId,
        listenerKey: ep.edge.listenerKey,
        port: ep.edge.edgePort,
        sni: alt.sni,
        hostHeader: alt.hostHeader,
        label,
        address: named ?? ep.edge.addresses.v4!,
        family: named ? 'name' : 'v4',
        variant: i + 1,
      }),
    );
  };
  push(assigned.primary);
  if (rule.includeBackup) push(assigned.backup);
  pushAlternates(assigned.primary);
  if (rule.includeBackup) pushAlternates(assigned.backup);
  return { entries: nameEntries(out, assigned, rule), leaked };
}

/** The form an entry takes of its address: the name (`Domain`) or a raw IP; none for a CDN front. */
function formOf(e: RenderEndpoint, route: EntryRoute): EntryForm | null {
  if (route.kind === 'cdn') return null;
  return e.family === 'v4' ? 'ipv4' : e.family === 'v6' ? 'ipv6' : 'domain';
}

/**
 * Name every entry (src/shared/entryNames.ts), judged on what the body will
 * hold: the entries in the order and under the cap the codecs apply
 * (`orderEndpoints`). In that order, CDN fronts are numbered (`🌐 via CDN 1`,
 * `2`), and two addresses of one place get letters (`via Example Town A`, `B`), as
 * every address of a location with no member-facing name does (`via relay A`).
 * An address the body holds in more than one form (its name, its raw IPv4, its
 * raw IPv6) tags every form (`· Domain`, `· IPv4`, `· IPv6`); with one form it
 * carries no tag. A further server name ends in `#2`, `#3`. The replays
 * (`memberView`, report attribution) expand the same endpoints the same way,
 * so they read the same names.
 */
function nameEntries(
  entries: RenderEndpoint[],
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null },
  rule: EffectiveRule,
): RenderEndpoint[] {
  const fixed = rule.fixedLabel;
  if (fixed) return entries.map((e) => ({ ...e, label: fixed, base: fixed }));
  const kept = orderEndpoints(entries, rule);
  // Endpoints in body order; one the cap cut entirely comes last (never emitted).
  const roles = [...new Set([...kept, ...entries].map((e) => e.role))];
  const edgeOf = (role: RenderEndpoint['role']) =>
    (role === 'primary' ? assigned.primary : assigned.backup)?.edge ?? null;
  const placeKey = (name: string | null, country: string | null) =>
    name ? `${name}|${country ?? ''}` : '';
  // How many addresses of each place the body holds (a role the cap cut counts for none).
  const places = new Map<string, number>();
  for (const role of new Set(kept.map((e) => e.role))) {
    const edge = edgeOf(role);
    if (!edge || edgeHostname(edge)) continue;
    const p = memberPlaceOf(edge.memberPlace?.name, edge.memberPlace?.country);
    const key = placeKey(p.name, p.country);
    places.set(key, (places.get(key) ?? 0) + 1);
  }
  const routes = new Map<RenderEndpoint['role'], EntryRoute>();
  const letters = new Map<string, number>();
  let cdn = 0;
  for (const role of roles) {
    const edge = edgeOf(role);
    if (!edge) continue;
    if (edgeHostname(edge)) {
      routes.set(role, { kind: 'cdn', n: ++cdn });
      continue;
    }
    const place = memberPlaceOf(edge.memberPlace?.name, edge.memberPlace?.country);
    const key = placeKey(place.name, place.country);
    let letter: string | null = null;
    if (!place.name || (places.get(key) ?? 0) > 1) {
      const i = letters.get(key) ?? 0;
      letters.set(key, i + 1);
      letter = placeLetter(i);
    }
    routes.set(role, { kind: 'relay', place, letter });
  }
  const forms = new Map<RenderEndpoint['role'], Set<EntryForm>>();
  for (const e of kept) {
    const route = routes.get(e.role);
    const form = route ? formOf(e, route) : null;
    if (form) forms.set(e.role, (forms.get(e.role) ?? new Set()).add(form));
  }
  return entries.map((e) => {
    const route = routes.get(e.role) ?? {
      kind: 'relay' as const,
      place: { name: null, country: null },
      letter: null,
    };
    const tagged = (forms.get(e.role)?.size ?? 0) > 1;
    return {
      ...e,
      base: entryBase(route),
      label: entryName(route, {
        form: tagged ? formOf(e, route) : null,
        ...(e.variant ? { spare: e.variant + 1 } : {}),
      }),
    };
  });
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

/** sing-box outbound types that route rather than connect: not an entry. */
const SINGBOX_ROUTING_TYPES = new Set(['direct', 'block', 'dns', 'selector', 'urltest']);
/** A share link of any scheme: an entry, whether or not FCP parses it. */
const SHARE_LINK_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Whether the backend served this body no connection at all: it reads as its
 * format and its own entry list is empty (a Clash `proxies` list, the sing-box
 * outbounds that are not routing helpers, the share-link lines). That is the
 * backend's template for an app that cannot speak the node's protocol (a
 * legacy Clash core has no VLESS, so its body holds no proxy), not a fault of
 * the fleet: `no_entries`, never `empty_pool`. An entry that is there but
 * malformed (no address, a link that does not parse) is still an entry, left
 * to the renderer's own verdicts. The app notice reads it too (lib/appNotice.ts).
 */
export function carriesNoEntry(body: string, format: SubscriptionFormat): boolean {
  try {
    if (format === 'clash-yaml') {
      const doc: unknown = YAML.parse(body);
      if (typeof doc !== 'object' || doc === null) return false;
      const proxies = (doc as { proxies?: unknown }).proxies;
      return proxies == null || (Array.isArray(proxies) && proxies.length === 0);
    }
    if (format === 'singbox-json') {
      const outbounds = (JSON.parse(body) as { outbounds?: unknown } | null)?.outbounds;
      return (
        Array.isArray(outbounds) &&
        outbounds.every(
          (o: unknown) =>
            typeof o === 'object' &&
            o !== null &&
            SINGBOX_ROUTING_TYPES.has(String((o as { type?: unknown }).type)),
        )
      );
    }
    const list = decodeLinkList(body);
    return list !== null && !list.lines.some((l) => SHARE_LINK_RE.test(l));
  } catch {
    return false;
  }
}

export type DeliveryVerdict =
  | { kind: 'serve' }
  | {
      kind: 'unavailable';
      reason:
        | 'unsupported_format'
        | 'no_entries'
        | 'no_match'
        | 'ambiguous_match'
        | 'entry_mismatch'
        | 'empty_pool'
        | 'open_lane_empty'
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

/** Every address an origin's edges answer on (IPv4, IPv6, an L7 front's hostname, an address's name). */
export function edgeAddressesOf(
  edges: ReadonlyArray<{
    addresses: { v4?: string; v6?: string; hostname?: string };
    addressName?: string;
  }>,
): string[] {
  return edges.flatMap((e) =>
    [e.addresses.v4, e.addresses.v6, e.addresses.hostname, e.addressName].filter(
      (a): a is string => !!a,
    ),
  );
}

/**
 * Render one body; picks the renderer from the body's shape and judges the
 * result under the edge-required policy.
 *
 * Empty pool rule: when the subscriber has NO assignable edge the template
 * entries still point at whatever the backend Host carries and must be DROPPED
 * regardless of the family rule's flags. Under edge-required delivery an empty
 * pool is `unavailable` (never an empty body: an empty 200 would wipe the
 * client's configuration, a 503 keeps its last one). A body with no entry at
 * all is judged first (`no_entries`): no edge could be placed in it, so it says
 * nothing about the pool.
 */
export function renderEdgeEndpoints(args: {
  body: string;
  matchers: RenderMatcher[];
  assigned: { primary: AssignedEndpoint | null; backup: AssignedEndpoint | null };
  rule: EffectiveRule;
  originAddress: string;
  /** Other addresses the node is known by (its other family, a name): never served either. */
  nodeAddresses?: readonly string[];
  /**
   * Every address of the origin's edges (`edgeAddressesOf`). Given, a retained
   * entry on a covered transport at none of them (and not the node by an
   * address FCP knows, which the leak check refuses) is left out of the body
   * (`withheld`): FCP cannot tell it from the node by a name it never saw.
   */
  edgeAddresses?: readonly string[];
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
  if (carriesNoEntry(args.body, format)) return unavailable('no_entries');
  if (emptyPool) return unavailable('empty_pool');
  const rule: EffectiveRule = rule0;
  const { entries, leaked } = renderEntriesChecked(
    args.assigned,
    rule,
    formatHasAutoGroup(rule, format),
    args.originAddress,
    args.nodeAddresses,
    { names: (args.deliveryStyle ?? 'subscription') === 'subscription' },
  );
  if (entries.length === 0) return unavailable(leaked > 0 ? 'leak_detected' : 'empty_pool');
  const edgeAddresses = args.edgeAddresses;
  const input = {
    body: args.body,
    matchers: args.matchers,
    endpoints: entries,
    rule,
    ...(edgeAddresses
      ? {
          withholds: (address: string) =>
            !isNodeAddress(address, args.originAddress, args.nodeAddresses) &&
            !edgeAddresses.some((a) => sameAddress(address, a)),
        }
      : {}),
  };
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
  // Every entry that leaves (emitted AND retained) must not be the node, by
  // any of its addresses.
  const originEntries = outgoingAddresses(out.body, format).filter((e) =>
    isNodeAddress(e.address, args.originAddress, args.nodeAddresses),
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
