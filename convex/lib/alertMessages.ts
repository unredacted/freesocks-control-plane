/**
 * Operator alert messages and the send plan (pure; docs/edges.md § "Operator
 * alerts"). convex/alerts.ts gathers the sources (the edges attention list and
 * a few system signals), labels them, and posts what `planAlerts` returns.
 *
 * One alert = one ntfy notification: a title naming what happened and where,
 * about three lines (what, since when, the next step), a priority by severity,
 * tags, and a click link to the admin page that fixes it.
 *
 * WHAT LEAVES: operator-facing labels only (a node's label, a backend's slug,
 * a provider account's or location's label, a transport tag, a country code)
 * and counts. Never a member, an address, a hostname, a token, a credential,
 * a provider's free-text error, or an internal id.
 *
 * Dedupe and repeat rules (`planAlerts`):
 *  - an item alerts once while it stays on the list, at any severity;
 *  - noisy kinds alert only after they stay for a while (`HOLD_DOWN_MS`);
 *  - a critical item still open after `REMIND_MS` is sent again, once per
 *    `REMIND_MS`, in one "Still open" message for all such items;
 *  - an alerted item that stays off the list for `RESOLVE_AFTER_MS` is
 *    reported resolved (one message for all of them) and forgotten; back
 *    before then, it stays open and nothing is sent;
 *  - several new items of one kind share a message; at most
 *    `MAX_FRESH_MESSAGES` new messages go out per tick, most urgent first, and
 *    the rest wait (pending) for the next ticks, so each still arrives in full.
 */
import { ROTATION_PHASE_LABELS, codeFix, codeLabel } from '../../src/client/lib/edgeCodes';

const MIN = 60_000;
const HOUR = 60 * MIN;

/** A critical item still open is sent again this often. */
export const REMIND_MS = 12 * HOUR;
/** An alerted item must stay off the list this long before "Resolved" goes out. */
export const RESOLVE_AFTER_MS = 10 * MIN;
/** New messages per tick; the rest wait for the next tick. */
export const MAX_FRESH_MESSAGES = 4;
/** Lines of a grouped message that name their subjects. */
const GROUP_NAMED = 3;

/**
 * Kinds that alert only once they stay on the list this long. A blocked
 * address is usually replaced by FCP within minutes; a probe source or a node
 * blinks; the alert is for the one that stays.
 */
export const HOLD_DOWN_MS: Record<string, number> = {
  edge_unreachable: 30 * MIN,
  probe_source_failing: HOUR,
  node_offline: 15 * MIN,
};

/** The prompts that alert though they are not critical: FCP never acts on them alone. */
export const PROMPT_KINDS: ReadonlySet<string> = new Set([
  'node_ready_to_protect',
  'node_awaiting_approval',
  // Freedom members are not handed a node until an edge covers it.
  'freedom_node_withheld',
  // A provider refused to create a node's address (a quota): only the operator can raise it.
  'location_refused',
]);

/**
 * Warnings that alert: FCP stops doing something on its own until the
 * operator acts (a cap), or members lose an address and nothing replaced it.
 */
export const WARNING_KINDS: ReadonlySet<string> = new Set([
  'account_spend_cap',
  'fleet_rotation_cap',
  'edge_unreachable',
  'probe_source_failing',
]);

/** Signals FCP reads outside the edges attention list (convex/alerts.ts `systemSignals`). */
export const SYSTEM_KINDS = [
  'node_offline',
  'backend_unhealthy',
  'cron_stale',
  'cron_failing',
  'spend_near_cap',
] as const;
const SYSTEM: ReadonlySet<string> = new Set(SYSTEM_KINDS);

/**
 * Alert-worthy: a critical item, a prompt, an alerting warning, a system
 * signal, or a suspected block (`block_suspected`, a warning) that FCP is
 * holding back: the detector judged that it would replace the address but
 * for a hold, on the whole decision (lib/edges/scoring.ts
 * `replacementHeldBack`), never on its veto alone.
 */
export function alertWorthy(item: {
  kind: string;
  severity: string;
  facts?: Record<string, unknown>;
}): boolean {
  if (item.severity === 'critical') return true;
  if (PROMPT_KINDS.has(item.kind) || WARNING_KINDS.has(item.kind) || SYSTEM.has(item.kind))
    return true;
  return item.kind === 'block_suspected' && item.facts?.heldBack === true;
}

// --- sources --------------------------------------------------------------------------------------

/** Labels the dispatcher looked up for an item (operator-facing only). */
export interface AlertLabels {
  /** The node: the origin's label, else its backend node, else its slug. */
  node?: string | null;
  /** The provider account's label. */
  account?: string | null;
  /** The provider location's label. */
  location?: string | null;
}

/** An attention item (or a system signal shaped like one), with its labels. */
export interface AlertSource {
  id: string;
  kind: string;
  severity: string;
  code: string | null;
  facts: Record<string, unknown>;
  since: string | null;
  /** The attention action (where its row's button goes); null for a system signal. */
  action: string | null;
  relaySlug: string | null;
  edgeId: string | null;
  listenerKey: string | null;
  accountId: string | null;
  rotationId: string | null;
  labels: AlertLabels;
  /** A system signal's admin page (an attention item's comes from its action). */
  path?: string;
  /** This item's own hold-down, over its kind's (`HOLD_DOWN_MS`). */
  holdDownMs?: number;
}

// --- links ----------------------------------------------------------------------------------------

type Params = Record<string, string | null | undefined>;
function withSearch(path: string, params?: Params): string {
  if (!params) return path;
  const qs = new URLSearchParams();
  for (const [k, val] of Object.entries(params)) if (val) qs.set(k, val);
  const s = qs.toString();
  return s ? `${path}?${s}` : path;
}
const enc = encodeURIComponent;

/**
 * Admin paths, spelled as the SPA routes them (src/client/routes/admin/edges/lib/routes.ts
 * `edgesPaths` and src/client/routes/admin/servers/lib/routes.ts `serversPaths`): every
 * page is under Servers. An old address still works there (servers/lib/legacyRoutes.ts),
 * so a link in an alert sent before the move still opens the right page.
 */
const S = '/admin/servers';
export const adminPaths = {
  /** The Servers Overview (`protect`, `server`, `node` open the protect sheet; `run` a run). */
  edges: (params?: Params) => withSearch(S, params),
  /** An origin's page (`test` opens the test card for that address). */
  node: (slug: string, params?: Params) => withSearch(`${S}/origins/${enc(slug)}`, params),
  /** An origin's technical details. */
  relay: (slug: string, params?: Params) => withSearch(`${S}/origins/${enc(slug)}/details`, params),
  providers: () => `${S}/providers`,
  provider: (id: string) => `${S}/providers/${enc(id)}`,
  /** Settings; `group` opens one group. */
  settings: (params?: Params) => withSearch(`${S}/settings`, params),
  probes: () => `${S}/probes`,
  family: (slug: string) => `${S}/snis/lists/${enc(slug)}`,
  findNames: () => `${S}/snis/find`,
  country: (code: string) => `${S}/countries/${enc(code.toUpperCase())}`,
  modes: () => '/admin/connection-modes',
  /** The Nodes tab; `backend` keeps one backend server. */
  servers: (backend?: string | null) => withSearch(`${S}/nodes`, { backend }),
  serverNode: (uuid: string, backend?: string | null) =>
    withSearch(`${S}/nodes/${enc(uuid)}`, { backend }),
  backends: () => `${S}/settings/backends`,
  dashboard: () => '/admin/dashboard',
};

function fact(s: Pick<AlertSource, 'facts'>, key: string): string | null {
  const val = s.facts[key];
  return typeof val === 'string' && val !== '' ? val : null;
}
function num(s: Pick<AlertSource, 'facts'>, key: string): number | null {
  const val = s.facts[key];
  return typeof val === 'number' && Number.isFinite(val) ? val : null;
}

/**
 * The admin page an alert opens: the page the attention row's button goes to
 * (src/client/routes/admin/edges/lib/attention.ts `attentionTarget`, which a
 * test keeps this in step with), or a system signal's own page.
 */
export function alertPath(s: AlertSource): string {
  if (s.path) return s.path;
  const slug = s.relaySlug;
  const relay = (params?: Params) => (slug ? adminPaths.relay(slug, params) : adminPaths.edges());
  switch (s.action) {
    case 'resolve_quarantine':
      // The resolver card is on the origin's Overview tab, not Rotations.
      return relay({ tab: 'overview' });
    case 'resolve_operator':
    case 'open_edge':
    case 'publish':
    case 'qualify_front':
    case 'rotate':
      return relay({ tab: 'edges', edge: s.edgeId });
    case 'verify_endpoint':
      return slug ? adminPaths.node(slug, { test: s.edgeId }) : adminPaths.edges();
    case 'require_edges':
      return slug ? adminPaths.node(slug) : adminPaths.edges();
    case 'look_at_host':
      return relay({ tab: 'listeners', listener: s.listenerKey });
    case 'provision':
    case 'rebalance':
      return relay({ tab: 'edges' });
    case 'open_relay':
      return relay(s.rotationId ? { tab: 'rotations', rotation: s.rotationId } : undefined);
    case 'open_setup':
      return relay();
    case 'open_account':
    case 'test_credentials':
      return s.accountId ? adminPaths.provider(s.accountId) : adminPaths.providers();
    case 'open_settings':
      return adminPaths.settings();
    case 'thaw':
      return adminPaths.settings({ group: 'maintenance' });
    case 'protect_node':
      if (slug) return adminPaths.node(slug);
      return adminPaths.edges({
        protect: '1',
        server: fact(s, 'serverSlug'),
        node: fact(s, 'nodeUuid'),
      });
    case 'open_node': {
      const uuid = fact(s, 'nodeUuid');
      const instance = fact(s, 'serverSlug');
      return uuid ? adminPaths.serverNode(uuid, instance) : adminPaths.servers(instance);
    }
    case 'open_modes':
      return adminPaths.modes();
    case 'open_probes':
      return adminPaths.probes();
    case 'open_run': {
      const run = fact(s, 'runId');
      if (run) return adminPaths.edges({ run });
      return slug ? adminPaths.node(slug) : adminPaths.edges();
    }
    case 'find_names': {
      const family = fact(s, 'family');
      return family ? adminPaths.family(family) : adminPaths.findNames();
    }
    default:
      return adminPaths.edges();
  }
}

/**
 * The deployment's admin origin: the first origin in WEBAUTHN_ORIGIN (the
 * page admins sign in on). https only (http for a local development origin);
 * anything else is null and alerts go out without a click link.
 */
export function adminOrigin(raw: string | undefined): string | null {
  const first = (raw ?? '').split(',')[0]?.trim();
  if (!first) return null;
  try {
    const u = new URL(first);
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) return null;
    return u.origin;
  } catch {
    return null;
  }
}

// --- words ----------------------------------------------------------------------------------------

/** A code that is safe to show: a short identifier, never free text. */
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,48}$/;
/** A label FCP shows the operator: printable, one line, bounded. */
const SAFE_LABEL = /^[^\u0000-\u001f\u007f]{1,64}$/u;
/** Looks like an IPv4 or IPv6 address: never sent, whatever field it sits in. */
const IPV4 = /(?:^|[^\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/;
/**
 * Looks like an IP address, in any form: never sent, whatever field it sits
 * in. IPv4 dotted quads, and any run of hex digits, dots and colons with two
 * or more colons (`::1`, `fe80::`, `2001:db8::1`, `::ffff:192.0.2.1`). A
 * label that merely has `::` in it is dropped too, which costs only its words.
 */
export function addressLike(s: string): boolean {
  if (IPV4.test(s)) return true;
  for (const run of s.match(/[0-9a-f:.%]+/gi) ?? [])
    if ((run.match(/:/g)?.length ?? 0) >= 2) return true;
  return false;
}
/** A country code as probes and lists keep them. */
const COUNTRY = /^[A-Z]{2}$/;

function label(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || !SAFE_LABEL.test(s) || addressLike(s)) return null;
  return s;
}

/** A code in words (the admin UI's own label for it), or null. */
function reason(code: unknown): string | null {
  if (typeof code !== 'string' || !SAFE_CODE.test(code)) return null;
  const words = codeLabel(code);
  return words ? words.charAt(0).toLowerCase() + words.slice(1) : null;
}
/** " (reason)" or "". */
function because(code: unknown): string {
  const r = reason(code);
  return r ? ` (${r})` : '';
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function countries(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return [...new Set(v.filter((c): c is string => typeof c === 'string' && COUNTRY.test(c)))];
}
function inCountries(list: string[]): string {
  if (list.length === 0) return '';
  if (list.length <= 4) return ` in ${list.join(', ')}`;
  return ` in ${list.slice(0, 4).join(', ')} and ${list.length - 4} more`;
}

/** A short duration: "45 min", "3 h 10 min", "2 d 4 h". */
export function durationWords(ms: number): string {
  const m = Math.max(0, Math.round(ms / MIN));
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d} d ${h % 24} h` : `${d} d`;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "Since 14:05 UTC (35 min)." or "Since 6 Nov 14:05 UTC (2 d 3 h)." */
export function sinceLine(at: number, now: number, word = 'Since'): string {
  const d = new Date(at);
  const hm = `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`;
  const sameDay = new Date(now).toISOString().slice(0, 10) === d.toISOString().slice(0, 10);
  const day = sameDay ? '' : `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} `;
  return `${word} ${day}${hm} UTC (${durationWords(now - at)}).`;
}

function money(n: number, currency: string): string {
  const c = SAFE_CODE.test(currency) ? `${currency} ` : '';
  return `${c}${Number.isInteger(n) ? n : n.toFixed(2)}`;
}

// --- one alert ------------------------------------------------------------------------------------

export type Severity = 'critical' | 'warning' | 'info';

export interface AlertText {
  /** What happened, without its subject ("Node paused for safety"). */
  headline: string;
  /** Where: the node, account, country or job ("" for the whole fleet). */
  subject: string;
  /** One line: what happened, with the numbers that matter. */
  what: string;
  /** One line: the next step. */
  next: string;
  priority: number;
  tags: string[];
  path: string;
}

const EMOJI: Record<Severity, string> = {
  critical: 'rotating_light',
  warning: 'warning',
  info: 'information_source',
};

function severityOf(s: AlertSource): Severity {
  return s.severity === 'critical' || s.severity === 'warning' ? s.severity : 'info';
}

/** ntfy priority: 5 urgent (critical), 4 high, 3 default (a prompt that waits on you). */
function priorityOf(s: AlertSource): number {
  if (s.severity === 'critical') return 5;
  if (s.kind === 'node_ready_to_protect' || s.kind === 'node_awaiting_approval') return 3;
  return 4;
}

type Words = { headline: string; subject?: string; what: string; next: string };

/** What each kind says. Unknown kinds fall back to the code's own words (`describe`). */
function wordsFor(s: AlertSource, now: number): Words | null {
  const node = label(s.labels.node) ?? label(s.relaySlug) ?? label(fact(s, 'node')) ?? 'a node';
  const account = label(s.labels.account) ?? label(fact(s, 'name')) ?? 'a provider account';
  const location = label(s.labels.location) ?? label(fact(s, 'location'));
  const where = [label(s.labels.account), location].filter(Boolean).join(', ');
  const at = where ? ` at ${where}` : '';
  const transport = label(s.listenerKey);
  const on = transport ? ` ${transport}` : '';
  const server = label(fact(s, 'serverSlug'));
  const onServer = server ? ` on backend ${server}` : '';
  switch (s.kind) {
    case 'quarantine':
      return {
        headline: 'Node paused for safety',
        subject: node,
        what: `A replacement could not finish${because(s.code)}, so FCP froze edge work on this node. Members keep the addresses they had.`,
        next: 'Open the paused replacement and resolve it.',
      };
    case 'fleet_brake': {
      const suspected = num(s, 'suspected') ?? 0;
      const evaluated = num(s, 'evaluated') ?? 0;
      const threshold = num(s, 'threshold');
      return {
        headline: 'Automatic replacement braked',
        what: `${suspected} of ${evaluated} nodes look blocked at once${threshold !== null ? ` (brake above ${threshold}%)` : ''}, so FCP stopped replacing addresses on every node.`,
        next: 'Check probes for an outage, then release the brake in Edges settings.',
      };
    }
    case 'auto_replace_held':
      return {
        headline: 'Automatic replacement stopped',
        subject: node,
        what: `A new${on} address was blocked again soon after it went into use${because(s.code)}. FCP stopped replacing it.`,
        next: 'Add a location or provider that is not blocked, then replace it by hand.',
      };
    case 'needs_operator':
      return {
        headline: 'Address needs you',
        subject: node,
        what: `An address${at} failed${because(s.code)} and FCP gave up on it.`,
        next: 'Open the address on the node page; retry or delete it.',
      };
    case 'account_api_failing':
      return {
        headline: 'Provider account failing',
        subject: account,
        what: `Its API failed ${plural(num(s, 'failures') ?? 0, 'time', 'times')} in a row${because(s.code)}. Replacements, health checks and deletes there stall.`,
        next: 'Check the account credentials and the provider status page.',
      };
    case 'rotation_stuck': {
      const phase = fact(s, 'phase');
      const step = phase ? (ROTATION_PHASE_LABELS[phase] ?? reason(phase)) : null;
      const what = fact(s, 'kind') === 'replace' ? 'A replacement' : 'An address change';
      return {
        headline: 'Replacement stuck',
        subject: node,
        what: `${what} has run ${durationWords((num(s, 'minutes') ?? 0) * MIN)}${step ? `, at step "${step}"` : ''}.`,
        next: 'Open it; cancel it if the provider stopped answering.',
      };
    }
    case 'host_unresolved':
      return {
        headline: 'Backend Host unclear',
        subject: node,
        what: `FCP cannot tell which backend Host carries${on || ' a transport'}${because(s.code)}.`,
        next: 'Open the transport on the node page and pick its Host.',
      };
    case 'members_dark': {
      const why: Record<string, [string, string]> = {
        empty_pool: ['no address is in use', 'Put a tested address in use on the node page.'],
        relay_disabled: ['its edges are turned off', 'Turn the node back on in Edges.'],
        render_disabled: ['rendering is off', 'Turn rendering on in Edges settings.'],
        relay_missing: [
          'the origin it was bound to was deleted',
          'Release the old binding in Edges settings.',
        ],
      };
      const [w, next] = (s.code && why[s.code]) || ['no usable entry', 'Open the node page.'];
      return {
        headline: 'Members get nothing',
        subject: node,
        what: `Members on this node get no working entry: ${w}.`,
        next,
      };
    }
    case 'delivery_refusals': {
      const total = num(s, 'total') ?? 0;
      const windowMin = num(s, 'windowMinutes');
      const top = reason(s.code);
      const by = s.facts.byReason;
      const topCount =
        s.code && by && typeof by === 'object' ? (by as Record<string, unknown>)[s.code] : null;
      return {
        headline: 'Subscriptions refused',
        what: `${plural(total, 'refusal', 'refusals')}${windowMin ? ` in the last ${durationWords(windowMin * MIN)}` : ''}${top ? `, most for "${top}"${typeof topCount === 'number' ? ` (${topCount})` : ''}` : ''}.`,
        next: codeFix(s.code) ?? 'Open Edges settings and fix the top reason.',
      };
    }
    case 'freedom_node_withheld':
      return {
        headline: 'Node withheld from members',
        subject: node,
        what: `Freedom members are not handed this node${onServer}${because(s.code)}.`,
        next: codeFix(s.code) ?? 'Protect the node or put an address in use.',
      };
    case 'direct_host_reappeared':
      return {
        headline: 'Direct Host came back',
        subject: node,
        what: `${plural(num(s, 'count') ?? 1, 'direct Host', 'direct Hosts')} reappeared in the backend and FCP could not hide them. The node's subscriptions stay closed until they are hidden.`,
        next: 'Disable or delete the Host in the backend.',
      };
    case 'node_awaiting_approval':
      return {
        headline: 'Node waits for approval',
        subject: node,
        what: `It passed its tests${onServer} and waits for you${because(s.code)}.`,
        next: 'Approve it on the node page.',
      };
    case 'node_ready_to_protect':
      return {
        headline: 'Node ready to protect',
        subject: node,
        what: `Its machine is ready${onServer} and nothing fronts it yet.`,
        next: 'Protect it from Edges.',
      };
    case 'needs_test': {
      const spares = num(s, 'untestedSpares') ?? 0;
      return {
        headline: 'Blocked node has no tested spare',
        subject: node,
        what: `It looks blocked and FCP cannot replace it${because(s.code)}. ${plural(spares, 'spare was', 'spares were')} never tested.`,
        next: spares > 0 ? 'Test a spare from the node page.' : 'Add a spare and test it.',
      };
    }
    case 'certificate_waiting': {
      if (s.relaySlug)
        return {
          headline: 'Certificate waiting',
          subject: node,
          what: `A new front's certificate waits on something FCP cannot fix${because(s.code)}.`,
          next: codeFix(s.code) ?? 'Check the DNS records the certificate needs.',
        };
      const notAfter = fact(s, 'notAfter');
      const days = notAfter ? Math.floor((Date.parse(notAfter) - now) / (24 * HOUR)) : null;
      const state = fact(s, 'state') === 'failed' ? 'has failed' : 'is waiting';
      return {
        headline: 'Shared certificate failing',
        subject: account,
        what: `A shared certificate ${state}${because(s.code)}${days !== null && Number.isFinite(days) ? (days < 0 ? '; it has expired' : `; it expires in ${plural(days, 'day', 'days')}`) : ''}.`,
        next: codeFix(s.code) ?? 'Check the CAA and validation records at the DNS provider.',
      };
    }
    case 'address_name_stuck': {
      const removing = s.facts.removing === true;
      return {
        headline: 'DNS record stuck',
        subject: node,
        what: `A DNS record for an address could not be ${removing ? 'removed' : 'set'} after ${plural(num(s, 'attempts') ?? 0, 'try', 'tries')}${because(s.code)}.${removing ? ' It may point at an address the provider took back.' : ''}`,
        next: 'Fix or delete the record at the DNS provider.',
      };
    }
    case 'audience_only_left':
      return {
        headline: 'Only country-limited addresses left',
        subject: node,
        what: `Every address in use${on ? ` on${on}` : ''} serves some countries only (${num(s, 'count') ?? 0}). Other members get none.`,
        next: 'Put an address for everyone in use.',
      };
    case 'client_check_unavailable':
      return {
        headline: 'Client check is down',
        what: `FCP's client-check service failed its last health check${because(s.code)}. No address can be tested until it answers.`,
        next: 'Check the client-check container and its logs.',
      };
    case 'location_refused': {
      const left = num(s, 'minutesLeft');
      return {
        headline: 'Provider refused a location',
        subject: [account, location].filter(Boolean).join(', '),
        what: `It refused an address for ${node}${because(s.code)}. FCP uses other locations${left !== null ? ` for ${durationWords(left * MIN)}` : ''}.`,
        next: 'Raise the quota at the provider, or drop the location from the node.',
      };
    }
    case 'block_suspected': {
      const score = num(s, 'score');
      const hold = reason(s.code);
      return {
        headline: 'Looks blocked, not replaced',
        subject: node,
        what: `It looks blocked${inCountries(countries(s.facts.countries))}${score !== null ? ` (score ${score.toFixed(2)})` : ''}. FCP would replace it, but ${hold ? `"${hold}" holds it` : 'a hold stops it'}.`,
        next: codeFix(s.code) ?? 'Replace the address from the node page, or lift the hold.',
      };
    }
    case 'account_spend_cap': {
      const cur = fact(s, 'currency') ?? '';
      return {
        headline: 'Spend cap reached',
        subject: account,
        what: `${money(num(s, 'monthly') ?? 0, cur)} of ${money(num(s, 'cap') ?? 0, cur)} a month. FCP buys no new address there until the cap rises or addresses go.`,
        next: 'Raise the cap, or delete addresses nobody uses.',
      };
    }
    case 'spend_near_cap': {
      const cur = fact(s, 'currency') ?? '';
      const monthly = num(s, 'monthly') ?? 0;
      const cap = num(s, 'cap') ?? 0;
      return {
        headline: 'Spend near cap',
        subject: account,
        what: `${money(monthly, cur)} of ${money(cap, cur)} a month (${cap > 0 ? Math.floor((monthly / cap) * 100) : 0}%). At the cap FCP buys no new address there.`,
        next: 'Raise the cap before replacements need it.',
      };
    }
    case 'fleet_rotation_cap':
      return {
        headline: 'Daily replacement cap reached',
        what: `FCP made ${num(s, 'used') ?? 0} of ${num(s, 'cap') ?? 0} automatic replacements today (UTC). New blocks wait until tomorrow.`,
        next: 'Raise the daily cap in Edges settings if more blocks are coming.',
      };
    case 'edge_unreachable': {
      const probes = Array.isArray(s.facts.probes) ? s.facts.probes : [];
      const counts = probes
        .map((p) => p as { country?: unknown; ok?: unknown; failed?: unknown })
        .filter(
          (p) =>
            typeof p.country === 'string' &&
            COUNTRY.test(p.country) &&
            typeof p.ok === 'number' &&
            typeof p.failed === 'number',
        )
        .slice(0, 3)
        .map((p) => `${p.ok} of ${(p.ok as number) + (p.failed as number)} probes in ${p.country}`);
      return {
        headline: 'Address unreachable',
        subject: node,
        what: counts.length
          ? `An address in use${at} is reachable from ${counts.join(', ')}.`
          : `An address in use${at} fails probes${inCountries(countries(s.facts.countries))}.`,
        next: 'Check the country view; replace the address if FCP has not.',
      };
    }
    case 'probe_source_failing': {
      const source = label(fact(s, 'source')) ?? 'A probe source';
      const lastOk = fact(s, 'lastOkAt');
      const lastOkMs = lastOk ? Date.parse(lastOk) : NaN;
      return {
        headline: 'Probe source failing',
        subject: source,
        what: `${plural(num(s, 'streak') ?? 0, 'run', 'runs')} in a row brought nothing back${because(s.code)}${Number.isFinite(lastOkMs) ? `; last good ${durationWords(now - lastOkMs)} ago` : ''}. Countries only it covers read "not known".`,
        next: 'Check its credential and allowance in Edges settings.',
      };
    }
    case 'node_offline': {
      const users = num(s, 'usersOnline');
      return {
        headline: 'Node offline',
        subject: node,
        what: `The backend${server ? ` ${server}` : ''} reports it offline${users ? `; it had ${plural(users, 'user', 'users')} online` : ''}.`,
        next: 'Check the machine and its node container.',
      };
    }
    case 'backend_unhealthy':
      return {
        headline: 'Backend not answering',
        subject: server ?? 'a backend',
        what: 'Its health check has failed for 30 min or more. Keys there cannot be issued or changed.',
        next: 'Check the backend panel and its API token.',
      };
    case 'cron_stale': {
      const every = num(s, 'everyMs');
      const does = label(fact(s, 'description'));
      return {
        headline: 'Scheduled job stopped',
        subject: label(fact(s, 'job')) ?? 'a job',
        what: `${s.facts.never === true ? 'It has never run' : 'It has stopped running'}${every ? `; it should run every ${durationWords(every)}` : ''}.${does ? ` It does: ${does}.` : ''}`,
        next: 'Check the backend logs; restart the backend if jobs stopped.',
      };
    }
    case 'cron_failing': {
      const every = num(s, 'everyMs');
      return {
        headline: 'Scheduled job failing',
        subject: label(fact(s, 'job')) ?? 'a job',
        what: `It runs${every ? ` every ${durationWords(every)}` : ''} but every run fails.`,
        next: 'Read its error on the dashboard and in the backend logs.',
      };
    }
    default:
      return null;
  }
}

/** One source as an alert. */
export function describeAlert(s: AlertSource, now = Date.now()): AlertText {
  const sev = severityOf(s);
  const words = wordsFor(s, now) ?? {
    headline: reason(s.kind)
      ? reason(s.kind)!.charAt(0).toUpperCase() + reason(s.kind)!.slice(1)
      : 'Edges alert',
    subject: label(s.labels.node) ?? label(s.relaySlug) ?? '',
    what: reason(s.code) ? `Reason: ${reason(s.code)}.` : 'FCP needs you to look at this.',
    next: codeFix(s.code) ?? 'Open the page to see what to do.',
  };
  return {
    headline: words.headline,
    subject: words.subject ?? '',
    what: words.what,
    next: words.next.startsWith('Next') ? words.next : `Next: ${words.next}`,
    priority: priorityOf(s),
    tags: [EMOJI[sev], s.kind],
    path: alertPath(s),
  };
}

export function alertTitle(t: Pick<AlertText, 'headline' | 'subject'>): string {
  return t.subject ? `${t.headline}: ${t.subject}` : t.headline;
}

// --- ntfy -----------------------------------------------------------------------------------------

export interface NtfyMessage {
  topic?: string;
  title: string;
  message: string;
  priority: number;
  tags: string[];
  click?: string;
}

interface Envelope {
  origin: string | null;
  topic: string;
}

function ntfy(
  env: Envelope,
  m: { title: string; lines: string[]; priority: number; tags: string[]; path: string | null },
): NtfyMessage {
  return {
    ...(env.topic ? { topic: env.topic } : {}),
    title: m.title,
    message: m.lines.filter(Boolean).join('\n'),
    priority: m.priority,
    tags: m.tags,
    ...(env.origin && m.path ? { click: `${env.origin}${m.path}` } : {}),
  };
}

// --- the plan -------------------------------------------------------------------------------------

export interface SentEntry {
  /** When it was first sent. */
  at: number;
  /** Its title then: what "Resolved" names. */
  title: string;
  /** Last "Still open" reminder. */
  remindedAt?: number;
  /** When it left the list (it resolves once gone for RESOLVE_AFTER_MS). */
  goneAt?: number;
}

export interface AlertState {
  /** Alerted item id -> its entry. */
  sent: Record<string, SentEntry>;
  /** Alert-worthy item id not sent yet (holding down) -> when first seen. */
  pending: Record<string, number>;
  lastSentAt: number | null;
  lastAttemptAt: number | null;
  /** A short code (`network`, `timeout`, an HTTP status), never a body. */
  lastError: string | null;
}

export const EMPTY_STATE: AlertState = {
  sent: {},
  pending: {},
  lastSentAt: null,
  lastAttemptAt: null,
  lastError: null,
};

/** Read a stored state; an older one (`sent` id -> time) keeps its ids with no title. */
export function parseAlertState(v: unknown): AlertState {
  if (!v || typeof v !== 'object') return EMPTY_STATE;
  const o = v as Record<string, unknown>;
  const sent: Record<string, SentEntry> = {};
  if (o.sent && typeof o.sent === 'object')
    for (const [id, e] of Object.entries(o.sent as Record<string, unknown>)) {
      if (typeof e === 'number') sent[id] = { at: e, title: '' };
      else if (e && typeof e === 'object' && typeof (e as SentEntry).at === 'number') {
        const x = e as SentEntry;
        sent[id] = {
          at: x.at,
          title: typeof x.title === 'string' ? x.title : '',
          ...(typeof x.remindedAt === 'number' ? { remindedAt: x.remindedAt } : {}),
          ...(typeof x.goneAt === 'number' ? { goneAt: x.goneAt } : {}),
        };
      }
    }
  const pending: Record<string, number> = {};
  if (o.pending && typeof o.pending === 'object')
    for (const [id, at] of Object.entries(o.pending as Record<string, unknown>))
      if (typeof at === 'number') pending[id] = at;
  return {
    sent,
    pending,
    lastSentAt: typeof o.lastSentAt === 'number' ? o.lastSentAt : null,
    lastAttemptAt: typeof o.lastAttemptAt === 'number' ? o.lastAttemptAt : null,
    lastError: typeof o.lastError === 'string' ? o.lastError : null,
  };
}

export type AlertEffect =
  | { type: 'sent'; id: string; title: string }
  | { type: 'reminded'; id: string }
  | { type: 'resolved'; id: string };

export interface PlannedMessage {
  body: NtfyMessage;
  /** Applied to the state only once the post succeeds. */
  effects: AlertEffect[];
}

export interface AlertPlan {
  /** The state with this tick's bookkeeping (holds, gone marks), before any post. */
  base: AlertState;
  messages: PlannedMessage[];
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, warning: 1, info: 2 };

/**
 * What this tick sends (pure). `current` is every item on the list now, at
 * any severity, with the system signals; an id stays remembered while it is
 * on the list at any severity, so an item that flaps between warning and
 * critical alerts once.
 */
export function planAlerts(input: {
  now: number;
  state: AlertState;
  current: AlertSource[];
  origin: string | null;
  topic: string;
}): AlertPlan {
  const { now, state } = input;
  const env: Envelope = { origin: input.origin, topic: input.topic };
  const byId = new Map(input.current.map((s) => [s.id, s]));
  const base: AlertState = { ...state, sent: {}, pending: {} };
  const messages: PlannedMessage[] = [];

  // Already alerted: still there (maybe a reminder), or gone (maybe resolved).
  const reminders: AlertSource[] = [];
  const resolved: Array<{ id: string; title: string }> = [];
  for (const [id, e] of Object.entries(state.sent)) {
    const cur = byId.get(id);
    if (cur) {
      base.sent[id] = {
        at: e.at,
        title: e.title,
        ...(e.remindedAt ? { remindedAt: e.remindedAt } : {}),
      };
      if (cur.severity === 'critical' && now - (e.remindedAt ?? e.at) >= REMIND_MS)
        reminders.push(cur);
      continue;
    }
    const goneAt = e.goneAt ?? now;
    // An entry from before titles were kept is forgotten without a message.
    if (now - goneAt >= RESOLVE_AFTER_MS && !e.title) continue;
    base.sent[id] = { ...e, goneAt };
    if (now - goneAt >= RESOLVE_AFTER_MS) resolved.push({ id, title: e.title });
  }

  // New: alert-worthy, not sent, and past its hold-down.
  const due: AlertSource[] = [];
  for (const s of input.current) {
    if (!alertWorthy(s) || base.sent[s.id] || state.sent[s.id]) continue;
    // Kept until it is sent: a failed post does not restart its hold-down.
    const first = state.pending[s.id] ?? now;
    base.pending[s.id] = first;
    if (now - first >= (s.holdDownMs ?? HOLD_DOWN_MS[s.kind] ?? 0)) due.push(s);
  }

  // Group the new ones by kind, most urgent first.
  const groups = new Map<string, AlertSource[]>();
  for (const s of due) groups.set(s.kind, [...(groups.get(s.kind) ?? []), s]);
  const ordered = [...groups.values()].sort((a, b) => {
    const pa = Math.max(...a.map(priorityOf));
    const pb = Math.max(...b.map(priorityOf));
    return pb - pa || (SEVERITY_ORDER[a[0]!.severity] ?? 3) - (SEVERITY_ORDER[b[0]!.severity] ?? 3);
  });
  // The rest stay pending and go out in full on the next ticks, most urgent first.
  const firstSeen = (id: string) => base.pending[id] ?? now;
  for (const group of ordered.slice(0, MAX_FRESH_MESSAGES))
    messages.push(freshMessage(env, group, now, firstSeen));

  if (reminders.length > 0) messages.push(reminderMessage(env, reminders, base, now));
  if (resolved.length > 0) messages.push(resolvedMessage(env, resolved));
  return { base, messages };
}

function sinceOf(s: AlertSource, firstSeen: number): number {
  const t = s.since ? Date.parse(s.since) : NaN;
  return Number.isFinite(t) ? t : firstSeen;
}

function freshMessage(
  env: Envelope,
  group: AlertSource[],
  now: number,
  firstSeen: (id: string) => number,
): PlannedMessage {
  const texts = group.map((s) => describeAlert(s, now));
  const effects: AlertEffect[] = group.map((s, i) => ({
    type: 'sent',
    id: s.id,
    title: alertTitle(texts[i]!),
  }));
  const first = texts[0]!;
  const priority = Math.max(...texts.map((t) => t.priority));
  const tags = [texts.find((t) => t.priority === priority)!.tags[0]!, group[0]!.kind];
  if (group.length === 1) {
    const s = group[0]!;
    return {
      body: ntfy(env, {
        title: alertTitle(first),
        lines: [first.what, sinceLine(sinceOf(s, firstSeen(s.id)), now), first.next],
        priority,
        tags,
        path: first.path,
      }),
      effects,
    };
  }
  // Several of one kind: one message naming the first few.
  const subjects = [...new Set(texts.map((t) => t.subject).filter(Boolean))];
  const named =
    subjects.length > GROUP_NAMED
      ? `${subjects.slice(0, GROUP_NAMED).join(', ')} and ${subjects.length - GROUP_NAMED} more`
      : subjects.join(', ');
  const paths = new Set(texts.map((t) => t.path));
  const oldest = Math.min(...group.map((s) => sinceOf(s, firstSeen(s.id))));
  return {
    body: ntfy(env, {
      title: `${first.headline}: ${group.length} at once`,
      lines: [
        named ? `${named}. First: ${first.what}` : first.what,
        sinceLine(oldest, now, 'Oldest since'),
        first.next,
      ],
      priority,
      tags,
      path: paths.size === 1 ? first.path : adminPaths.edges(),
    }),
    effects,
  };
}

function reminderMessage(
  env: Envelope,
  items: AlertSource[],
  base: AlertState,
  now: number,
): PlannedMessage {
  const texts = items.map((s) => describeAlert(s, now));
  const effects: AlertEffect[] = items.map((s) => ({ type: 'reminded', id: s.id }));
  if (items.length === 1) {
    const t = texts[0]!;
    const at = sinceOf(items[0]!, base.sent[items[0]!.id]?.at ?? now);
    return {
      body: ntfy(env, {
        title: `Still open: ${alertTitle(t)}`,
        lines: [t.what, sinceLine(at, now), t.next],
        priority: 4,
        tags: [EMOJI.critical, items[0]!.kind],
        path: t.path,
      }),
      effects,
    };
  }
  const titles = texts.map(alertTitle);
  return {
    body: ntfy(env, {
      title: `Still open: ${items.length} critical alerts`,
      lines: [
        titles.slice(0, GROUP_NAMED).join('; ') +
          (titles.length > GROUP_NAMED ? `; and ${titles.length - GROUP_NAMED} more` : ''),
        `Open for ${durationWords(REMIND_MS)} or more.`,
        'Next: open Edges and work down the list.',
      ],
      priority: 4,
      tags: [EMOJI.critical],
      path: adminPaths.edges(),
    }),
    effects,
  };
}

function resolvedMessage(
  env: Envelope,
  items: Array<{ id: string; title: string }>,
): PlannedMessage {
  const effects: AlertEffect[] = items.map((r) => ({ type: 'resolved', id: r.id }));
  if (items.length === 1)
    return {
      body: ntfy(env, {
        title: `Resolved: ${items[0]!.title}`,
        lines: ['It cleared on its own or after a fix. Nothing to do.'],
        priority: 2,
        tags: ['white_check_mark'],
        path: null,
      }),
      effects,
    };
  const titles = items.map((r) => r.title);
  return {
    body: ntfy(env, {
      title: `Resolved: ${items.length} alerts`,
      lines: [
        titles.slice(0, GROUP_NAMED).join('; ') +
          (titles.length > GROUP_NAMED ? `; and ${titles.length - GROUP_NAMED} more` : ''),
        'Nothing to do.',
      ],
      priority: 2,
      tags: ['white_check_mark'],
      path: null,
    }),
    effects,
  };
}

/** The state after a successful post of `effects` (pure). */
export function applyEffects(state: AlertState, effects: AlertEffect[], now: number): AlertState {
  const sent = { ...state.sent };
  const pending = { ...state.pending };
  for (const e of effects) {
    if (e.type === 'sent') {
      sent[e.id] = { at: now, title: e.title };
      delete pending[e.id];
    } else if (e.type === 'reminded') {
      if (sent[e.id]) sent[e.id] = { ...sent[e.id]!, remindedAt: now };
    } else delete sent[e.id];
  }
  return { ...state, sent, pending };
}

/** The one test notification (Admin -> Settings -> Operator alerts). */
export function testMessage(origin: string | null, topic: string): NtfyMessage {
  return ntfy(
    { origin, topic },
    {
      title: 'Test alert from FCP',
      lines: [
        'Alerts reach this channel.',
        origin
          ? 'Tap to open the alert settings.'
          : 'Set WEBAUTHN_ORIGIN to get links to admin pages.',
      ],
      priority: 3,
      tags: ['white_check_mark'],
      path: '/admin/settings',
    },
  );
}
