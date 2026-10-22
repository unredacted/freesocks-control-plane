/**
 * Operator alerts (docs/edges.md § "Operator alerts"): every few minutes the
 * `alerts-dispatch` cron reads the edges attention list and posts the NEW
 * alert-worthy items, once, to the operator's webhook as ntfy-compatible JSON
 * (an ntfy server, or anything that takes the same body).
 *
 * Alert-worthy: every `critical` item (quarantine, a fleet brake, a provider
 * whose API keeps failing, a stuck rotation, dark members, ...) plus the two
 * prompts FCP never acts on by itself: a fronted node ready to protect and a
 * node waiting for approval. An item is sent once while it stays on the list,
 * at any severity (`alerts:state` holds the ids already sent; an id that
 * leaves the list is forgotten, so a recurrence alerts again). A failed post keeps nothing, and
 * the next tick tries again.
 *
 * WHAT LEAVES: kinds, short codes and counts only. Never a member, a token, an
 * address, a node or origin name, a provider or a region. The webhook URL,
 * topic and token stay server-side (lib/alertsConfig.ts).
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { upsertSettingRow } from './appSettings';
import { runWithCronOutcome } from './cronHeartbeat';
import {
  ALERTS_KEYS,
  resolveAlertsConfig,
  sanitizeAlertsToken,
  sanitizeAlertsTopic,
  sanitizeAlertsUrl,
  urlOrigin,
  type AlertsConfig,
} from './lib/alertsConfig';

const STATE_KEY = 'alerts:state';
const POST_TIMEOUT_MS = 10_000;

/** The prompts that alert though they are not critical: FCP never acts on them alone. */
const PROMPT_KINDS: ReadonlySet<string> = new Set([
  'node_ready_to_protect',
  'node_awaiting_approval',
  // Freedom members are not handed a node until an edge covers it.
  'freedom_node_withheld',
]);

export interface AlertItem {
  id: string;
  kind: string;
  severity: string;
  code: string | null;
}

export function alertWorthy(item: { kind: string; severity: string }): boolean {
  return item.severity === 'critical' || PROMPT_KINDS.has(item.kind);
}

interface AlertState {
  /** Item id -> when it was sent. */
  sent: Record<string, number>;
  lastSentAt: number | null;
  lastAttemptAt: number | null;
  /** A short code (`network`, `timeout`, an HTTP status), never a body. */
  lastError: string | null;
}

const EMPTY_STATE: AlertState = {
  sent: {},
  lastSentAt: null,
  lastAttemptAt: null,
  lastError: null,
};

function parseState(v: Partial<AlertState> | null): AlertState {
  if (!v) return EMPTY_STATE;
  const sent: Record<string, number> = {};
  if (v.sent && typeof v.sent === 'object')
    for (const [id, at] of Object.entries(v.sent)) if (typeof at === 'number') sent[id] = at;
  return {
    sent,
    lastSentAt: typeof v.lastSentAt === 'number' ? v.lastSentAt : null,
    lastAttemptAt: typeof v.lastAttemptAt === 'number' ? v.lastAttemptAt : null,
    lastError: typeof v.lastError === 'string' ? v.lastError : null,
  };
}

/** A code that is safe to send: a short identifier, never free text. */
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,48}$/;

export interface NtfyMessage {
  topic?: string;
  title: string;
  message: string;
  priority: number;
  tags: string[];
}

/**
 * The notification for a batch of new items (pure): one line per kind and
 * code with its count, most urgent first. Kinds and codes are the shared
 * vocabulary (src/shared/contracts/edgeCodes.ts); nothing else is included.
 */
export function alertMessage(items: AlertItem[], topic: string): NtfyMessage {
  const counts = new Map<string, number>();
  for (const i of items) {
    const code = i.code && SAFE_CODE.test(i.code) ? i.code : null;
    const key = code ? `${i.kind} (${code})` : i.kind;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const critical = items.some((i) => i.severity === 'critical');
  const lines = [...counts.entries()].map(([k, n]) => `${k}: ${n}`);
  return {
    ...(topic ? { topic } : {}),
    title: `Edges: ${items.length} new ${items.length === 1 ? 'alert' : 'alerts'}`,
    message: `${lines.join('\n')}\n\nOpen Admin, Edges for the details.`,
    priority: critical ? 5 : 4,
    tags: [critical ? 'rotating_light' : 'warning'],
  };
}

// --- config ---------------------------------------------------------------------------------------

/** The admin view: whether each secret is set, the webhook's origin, the last send. Never a secret. */
export const view = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveAlertsConfig(ctx.db);
    const st = parseState(await readStateJson<Partial<AlertState>>(ctx.db, STATE_KEY));
    const iso = (n: number | null) => (n ? new Date(n).toISOString() : null);
    return {
      enabled: cfg.enabled,
      urlSet: cfg.url !== '',
      urlOrigin: urlOrigin(cfg.url),
      topicSet: cfg.topic !== '',
      tokenSet: cfg.token !== '',
      lastSentAt: iso(st.lastSentAt),
      lastAttemptAt: iso(st.lastAttemptAt),
      lastError: st.lastError,
      openAlerts: Object.keys(st.sent).length,
    };
  },
});

/** The full config, secrets included: the dispatcher's read only. */
export const configWithSecret = internalQuery({
  args: {},
  handler: (ctx): Promise<AlertsConfig> => resolveAlertsConfig(ctx.db),
});

/**
 * Write the config. A field left out keeps its stored value; an empty string
 * clears it. A URL, topic or token that does not pass its sanitizer is refused
 * (never stored as something else). Enabling needs a URL. Audited by booleans.
 */
export const setConfig = internalMutation({
  args: {
    enabled: v.optional(v.boolean()),
    url: v.optional(v.string()),
    topic: v.optional(v.string()),
    token: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const cur = await resolveAlertsConfig(ctx.db);
    const pick = (raw: string | undefined, clean: (x: unknown) => string, field: string) => {
      if (raw === undefined) return undefined;
      if (raw.trim() === '') return '';
      const s = clean(raw);
      if (!s) throw new ConvexError({ code: 'validation', message: `${field} is not valid` });
      return s;
    };
    const url = pick(a.url, sanitizeAlertsUrl, 'url');
    const topic = pick(a.topic, sanitizeAlertsTopic, 'topic');
    const token = pick(a.token, sanitizeAlertsToken, 'token');
    const next: AlertsConfig = {
      enabled: a.enabled ?? cur.enabled,
      url: url ?? cur.url,
      topic: topic ?? cur.topic,
      token: token ?? cur.token,
    };
    if (next.enabled && !next.url)
      throw new ConvexError({
        code: 'validation',
        message: 'An enabled alert needs a webhook URL',
      });
    // Nothing is dispatched (or reconciled) while alerts are off, so what was
    // sent before says nothing about what is open now: turning them on starts
    // afresh and sends everything alert-worthy once.
    if (!cur.enabled && next.enabled) {
      const st = parseState(await readStateJson<Partial<AlertState>>(ctx.db, STATE_KEY));
      await writeStateJson(ctx.db, STATE_KEY, { ...st, sent: {} });
    }
    await upsertSettingRow(ctx, ALERTS_KEYS.enabled, JSON.stringify(next.enabled), a.actorAdminId);
    if (url !== undefined)
      await upsertSettingRow(ctx, ALERTS_KEYS.url, JSON.stringify(next.url), a.actorAdminId);
    if (topic !== undefined)
      await upsertSettingRow(ctx, ALERTS_KEYS.topic, JSON.stringify(next.topic), a.actorAdminId);
    if (token !== undefined)
      await upsertSettingRow(ctx, ALERTS_KEYS.token, JSON.stringify(next.token), a.actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.alerts.change',
      targetType: 'alerts',
      payload: {
        enabled: next.enabled,
        urlChanged: url !== undefined && url !== cur.url,
        topicSet: next.topic !== '',
        tokenSet: next.token !== '',
      },
    });
    return null;
  },
});

// --- dispatch -------------------------------------------------------------------------------------

export const readState = internalQuery({
  args: {},
  handler: async (ctx) => parseState(await readStateJson<Partial<AlertState>>(ctx.db, STATE_KEY)),
});

/**
 * Record one dispatch attempt. `sentIds` (after a successful post) join the
 * remembered set; ids no longer on the attention list (`currentIds`) are
 * forgotten either way, so an item that clears and comes back alerts again.
 */
export const recordDispatch = internalMutation({
  args: {
    currentIds: v.array(v.string()),
    sentIds: v.array(v.string()),
    error: v.union(v.string(), v.null()),
    attempted: v.boolean(),
  },
  handler: async (ctx, a) => {
    const st = parseState(await readStateJson<Partial<AlertState>>(ctx.db, STATE_KEY));
    const now = Date.now();
    // Only ids still on the attention list are kept, and every one of them is:
    // the set is bounded by the list (operator-scale), never evicted while open.
    const current = new Set(a.currentIds);
    const sent: Record<string, number> = {};
    for (const [id, at] of Object.entries(st.sent)) if (current.has(id)) sent[id] = at;
    for (const id of a.sentIds) if (current.has(id)) sent[id] = now;
    const next: AlertState = {
      sent,
      lastSentAt: a.attempted && !a.error ? now : st.lastSentAt,
      lastAttemptAt: a.attempted ? now : st.lastAttemptAt,
      lastError: a.attempted ? a.error : st.lastError,
    };
    const unchanged =
      !a.attempted &&
      Object.keys(sent).length === Object.keys(st.sent).length &&
      Object.keys(sent).every((id) => st.sent[id] === sent[id]);
    if (!unchanged) await writeStateJson(ctx.db, STATE_KEY, next);
    return null;
  },
});

/** Post one notification. Never follows a redirect (the SSRF check ran on the stored URL). */
async function post(cfg: AlertsConfig, body: NtfyMessage): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), POST_TIMEOUT_MS);
  try {
    const res = await fetch(cfg.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cfg.token ? { authorization: `Bearer ${cfg.token}` } : {}),
      },
      body: JSON.stringify(body),
      redirect: 'manual',
      signal: controller.signal,
    });
    // The receiver's answer is never read beyond its status.
    return res.status >= 200 && res.status < 300 ? null : String(res.status || 'redirect');
  } catch (err) {
    return err instanceof Error && err.name === 'AbortError' ? 'timeout' : 'network';
  } finally {
    clearTimeout(timer);
  }
}

export interface DispatchReport {
  enabled: boolean;
  alertable: number;
  sent: number;
  error: string | null;
}

async function dispatchOnce(ctx: ActionCtx): Promise<DispatchReport> {
  const cfg: AlertsConfig = await ctx.runQuery(internal.alerts.configWithSecret, {});
  if (!cfg.enabled || !cfg.url) return { enabled: false, alertable: 0, sent: 0, error: null };
  const { items } = await ctx.runQuery(internal.edgeOperator.attention, {});
  const alertable: AlertItem[] = items
    .filter(alertWorthy)
    .map((i) => ({ id: i.id, kind: i.kind, severity: i.severity, code: i.code }));
  const st: AlertState = await ctx.runQuery(internal.alerts.readState, {});
  const fresh = alertable.filter((i) => st.sent[i.id] === undefined);
  // An id is remembered while its item is on the list at ANY severity, so an
  // item that flaps between warning and critical alerts once, not per crossing.
  const currentIds = items.map((i) => i.id);
  if (fresh.length === 0) {
    await ctx.runMutation(internal.alerts.recordDispatch, {
      currentIds,
      sentIds: [],
      error: null,
      attempted: false,
    });
    return { enabled: true, alertable: alertable.length, sent: 0, error: null };
  }
  const error = await post(cfg, alertMessage(fresh, cfg.topic));
  await ctx.runMutation(internal.alerts.recordDispatch, {
    currentIds,
    sentIds: error ? [] : fresh.map((i) => i.id),
    error,
    attempted: true,
  });
  return { enabled: true, alertable: alertable.length, sent: error ? 0 : fresh.length, error };
}

/** The `alerts-dispatch` cron: send what is new on the attention list, once. */
export const dispatch = internalAction({
  args: {},
  handler: async (ctx): Promise<DispatchReport> =>
    runWithCronOutcome(ctx, 'alerts-dispatch', () => dispatchOnce(ctx)),
});

/** `POST /api/v1/admin/alerts/test`: one test notification to the stored webhook. */
export const sendTest = internalAction({
  args: {},
  handler: async (ctx): Promise<{ ok: boolean; error: string | null }> => {
    const cfg: AlertsConfig = await ctx.runQuery(internal.alerts.configWithSecret, {});
    if (!cfg.url) return { ok: false, error: 'no_url' };
    const error = await post(cfg, {
      ...(cfg.topic ? { topic: cfg.topic } : {}),
      title: 'Edges: test alert',
      message: 'Alerts reach this channel. Nothing needs you.',
      priority: 3,
      tags: ['white_check_mark'],
    });
    return { ok: error === null, error };
  },
});
