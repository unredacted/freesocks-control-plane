/**
 * Operator alerts (docs/edges.md § "Operator alerts"): every few minutes the
 * `alerts-dispatch` cron reads the edges attention list and a few system
 * signals (`systemSignals`: a node offline, a backend not answering, a
 * scheduled job stopped or failing, spend near an account's cap), and posts
 * what `planAlerts` (lib/alertMessages.ts) says is due to the operator's
 * webhook as ntfy JSON: one notification per new alert, naming the node,
 * account or job, with a click link to the admin page that fixes it; a
 * "Still open" reminder for a critical alert after 12 h; "Resolved" once an
 * alerted item stays gone. A failed post keeps nothing, and the next tick
 * tries again.
 *
 * WHAT LEAVES: operator-facing labels and counts (lib/alertMessages.ts).
 * Never a member, a token, an address, a hostname or a credential. The
 * webhook URL, topic and token stay server-side (lib/alertsConfig.ts).
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { upsertSettingRow } from './appSettings';
import { CRON_META, cronStaleAfterMs, runWithCronOutcome } from './cronHeartbeat';
import { spendOf } from './edgePlans';
import { atCap } from './lib/edges/pricing';
import {
  ALERTS_KEYS,
  resolveAlertsConfig,
  sanitizeAlertsToken,
  sanitizeAlertsTopic,
  sanitizeAlertsUrl,
  urlOrigin,
  type AlertsConfig,
} from './lib/alertsConfig';
import {
  adminOrigin,
  adminPaths,
  alertWorthy,
  applyEffects,
  parseAlertState,
  planAlerts,
  testMessage,
  type AlertSource,
  type AlertState,
  type NtfyMessage,
} from './lib/alertMessages';

export { alertWorthy };

const STATE_KEY = 'alerts:state';
const POST_TIMEOUT_MS = 10_000;
/** A backend whose last good health check is older than this is not answering. */
const BACKEND_FRESH_MS = 30 * 60_000;
/** Spend at or above this share of the cap is near it. */
const NEAR_CAP = 0.9;

async function readAlertState(db: Parameters<typeof readStateJson>[0]): Promise<AlertState> {
  return parseAlertState(await readStateJson<unknown>(db, STATE_KEY));
}

const iso = (n: number | null | undefined) =>
  typeof n === 'number' ? new Date(n).toISOString() : null;

// --- config ---------------------------------------------------------------------------------------

/** The admin view: whether each secret is set, the webhook's origin, the last send. Never a secret. */
export const view = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveAlertsConfig(ctx.db);
    const st = await readAlertState(ctx.db);
    return {
      enabled: cfg.enabled,
      urlSet: cfg.url !== '',
      urlOrigin: urlOrigin(cfg.url),
      topicSet: cfg.topic !== '',
      tokenSet: cfg.token !== '',
      lastSentAt: iso(st.lastSentAt),
      lastAttemptAt: iso(st.lastAttemptAt),
      lastError: st.lastError,
      openAlerts: Object.values(st.sent).filter((e) => e.goneAt === undefined).length,
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
      const st = await readAlertState(ctx.db);
      await writeStateJson(ctx.db, STATE_KEY, { ...st, sent: {}, pending: {} });
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
  handler: async (ctx): Promise<AlertState> => readAlertState(ctx.db),
});

/**
 * Store the state one dispatch ended with (`stateJson`, from planAlerts and
 * the posts that went through), with the attempt's outcome. Nothing is written
 * while alerts are off (a turn-on starts afresh) or when nothing changed.
 */
export const recordDispatch = internalMutation({
  args: {
    stateJson: v.string(),
    error: v.union(v.string(), v.null()),
    attempted: v.boolean(),
  },
  handler: async (ctx, a) => {
    if (!(await resolveAlertsConfig(ctx.db)).enabled) return null;
    const cur = await readAlertState(ctx.db);
    const planned = parseAlertState(JSON.parse(a.stateJson));
    const now = Date.now();
    const next: AlertState = {
      sent: planned.sent,
      pending: planned.pending,
      lastSentAt: a.attempted && !a.error ? now : cur.lastSentAt,
      lastAttemptAt: a.attempted ? now : cur.lastAttemptAt,
      lastError: a.attempted ? a.error : cur.lastError,
    };
    if (JSON.stringify(next) !== JSON.stringify(cur)) await writeStateJson(ctx.db, STATE_KEY, next);
    return null;
  },
});

/**
 * The labels alerts name things by, for the items about to be described: an
 * origin's label (else its backend node, else its slug), a provider
 * account's label, and an address's account and location. Never an address.
 */
export const labels = internalQuery({
  args: {
    relayIds: v.array(v.string()),
    relaySlugs: v.array(v.string()),
    accountIds: v.array(v.string()),
    edgeIds: v.array(v.string()),
  },
  handler: async (ctx, a) => {
    const relays: Record<string, string> = {};
    const nodeLabel = (r: {
      label?: string;
      slug: string;
      origin: { kind: string; nodeName?: string };
    }) =>
      r.label ?? (r.origin.kind === 'panel-node' && r.origin.nodeName ? r.origin.nodeName : r.slug);
    for (const id of new Set(a.relayIds)) {
      const rid = ctx.db.normalizeId('relays', id);
      const r = rid ? await ctx.db.get(rid) : null;
      if (r) relays[id] = nodeLabel(r);
    }
    for (const slug of new Set(a.relaySlugs)) {
      const r = await ctx.db
        .query('relays')
        .withIndex('by_slug', (q) => q.eq('slug', slug))
        .unique();
      if (r) relays[slug] = nodeLabel(r);
    }
    const accounts: Record<string, string> = {};
    const accountName = async (id: string) => {
      if (accounts[id] !== undefined) return accounts[id];
      const aid = ctx.db.normalizeId('edgeProviderAccounts', id);
      const acct = aid ? await ctx.db.get(aid) : null;
      accounts[id] = acct?.name ?? '';
      return accounts[id];
    };
    for (const id of new Set(a.accountIds)) await accountName(id);
    const edges: Record<string, { account: string | null; location: string | null }> = {};
    for (const id of new Set(a.edgeIds)) {
      const eid = ctx.db.normalizeId('edges', id);
      const e = eid ? await ctx.db.get(eid) : null;
      if (!e) continue;
      const loc = e.locationId ? await ctx.db.get(e.locationId) : null;
      edges[id] = {
        account: e.accountId ? (await accountName(e.accountId as string)) || null : null,
        location: loc?.label ?? null,
      };
    }
    return { relays, accounts, edges };
  },
});

/**
 * What alerts beyond the edges attention list: an active backend whose health
 * check has not passed for 30 min; a node its backend reports offline (not one
 * the backend disables, nor one being retired); a scheduled job that stopped
 * firing or fails every run (the dashboard's own rule, cronHeartbeat.ts); an
 * edge provider account at 90% of its monthly cap (the cap itself is the
 * `account_spend_cap` attention item). Operator-scale reads.
 */
export const systemSignals = internalQuery({
  args: {},
  handler: async (ctx): Promise<AlertSource[]> => {
    const now = Date.now();
    const out: AlertSource[] = [];
    const blank = {
      code: null,
      action: null,
      relaySlug: null,
      edgeId: null,
      listenerKey: null,
      accountId: null,
      rotationId: null,
      labels: {},
    };
    for (const s of await ctx.db.query('backendServers').collect()) {
      if (!s.isActive) continue;
      const ok = s.lastHealthOkAt ?? null;
      if (ok === null ? now - s._creationTime > BACKEND_FRESH_MS : now - ok >= BACKEND_FRESH_MS) {
        out.push({
          ...blank,
          id: `backend_unhealthy:${s._id}`,
          kind: 'backend_unhealthy',
          severity: 'critical',
          facts: { serverSlug: s.slug },
          since: iso(ok),
          path: adminPaths.backends(),
        });
        // Its node list is as old as its last good check: nothing to judge nodes on.
        continue;
      }
      const nodes = await ctx.db
        .query('backendNodeInventory')
        .withIndex('by_server', (q) => q.eq('backendServerId', s._id))
        .collect();
      for (const n of nodes) {
        if (n.online || now - n.lastStatsAt > BACKEND_FRESH_MS) continue;
        const panel = await ctx.db
          .query('panelNodes')
          .withIndex('by_server_uuid', (q) =>
            q.eq('backendServerId', s._id).eq('nodeUuid', n.nodeUuid),
          )
          .first();
        if (panel?.isDisabled) continue;
        const intent = await ctx.db
          .query('panelNodeIntents')
          .withIndex('by_server_name', (q) => q.eq('backendServerId', s._id).eq('name', n.name))
          .first();
        if (intent && (intent.state === 'retiring' || intent.state === 'retired')) continue;
        out.push({
          ...blank,
          id: `node_offline:${s._id}:${n.nodeUuid}`,
          kind: 'node_offline',
          severity: 'critical',
          facts: { serverSlug: s.slug, nodeUuid: n.nodeUuid },
          since: null,
          labels: { node: n.name },
          path: adminPaths.serverNode(n.nodeUuid, s.slug),
        });
      }
    }
    const beats = new Map((await ctx.db.query('cronHeartbeats').collect()).map((h) => [h.name, h]));
    for (const c of CRON_META) {
      // This job cannot report its own death: an outside monitor has to.
      if (c.name === 'alerts-dispatch') continue;
      const hb = beats.get(c.name);
      if (!hb) continue;
      const staleAfter = cronStaleAfterMs(c.everyMs);
      const facts = { job: c.name, description: c.description, everyMs: c.everyMs };
      if (now - hb.lastRunAt > staleAfter)
        out.push({
          ...blank,
          id: `cron_stale:${c.name}`,
          kind: 'cron_stale',
          severity: 'warning',
          facts,
          since: iso(hb.lastRunAt),
          path: adminPaths.dashboard(),
        });
      else if (hb.lastError != null && (hb.lastOkAt == null || now - hb.lastOkAt > staleAfter))
        out.push({
          ...blank,
          id: `cron_failing:${c.name}`,
          kind: 'cron_failing',
          severity: 'warning',
          facts,
          since: iso(hb.lastOkAt),
          path: adminPaths.dashboard(),
        });
    }
    for (const a of await ctx.db.query('edgeProviderAccounts').collect()) {
      if (!a.enabled || typeof a.cost?.monthlyCap !== 'number' || a.cost.monthlyCap <= 0) continue;
      const spend = await spendOf(ctx, a);
      if (spend.cap === null || atCap(spend) || spend.monthly < spend.cap * NEAR_CAP) continue;
      out.push({
        ...blank,
        id: `spend_near_cap:${a._id}`,
        kind: 'spend_near_cap',
        severity: 'warning',
        accountId: a._id as string,
        facts: {
          monthly: spend.monthly,
          cap: spend.cap,
          currency: spend.currency ?? '',
        },
        since: null,
        labels: { account: a.name },
        path: adminPaths.provider(a._id as string),
      });
    }
    return out;
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
  /** Alert-worthy items on the list now. */
  alertable: number;
  /** Items alerted for the first time by this tick. */
  sent: number;
  /** Notifications posted (new, reminders, resolved). */
  messages: number;
  error: string | null;
}

async function dispatchOnce(ctx: ActionCtx): Promise<DispatchReport> {
  const cfg: AlertsConfig = await ctx.runQuery(internal.alerts.configWithSecret, {});
  if (!cfg.enabled || !cfg.url)
    return { enabled: false, alertable: 0, sent: 0, messages: 0, error: null };
  const { items } = await ctx.runQuery(internal.edgeOperator.attention, {});
  const system: AlertSource[] = await ctx.runQuery(internal.alerts.systemSignals, {});
  const worthy = items.filter(alertWorthy);
  const lab = await ctx.runQuery(internal.alerts.labels, {
    relayIds: worthy.flatMap((i) => (i.relayId ? [i.relayId] : [])),
    relaySlugs: worthy.flatMap((i) => (!i.relayId && i.relaySlug ? [i.relaySlug] : [])),
    accountIds: worthy.flatMap((i) => (i.accountId ? [i.accountId] : [])),
    edgeIds: worthy.flatMap((i) => (i.edgeId ? [i.edgeId] : [])),
  });
  const current: AlertSource[] = [
    ...items.map((i) => ({
      id: i.id,
      kind: i.kind,
      severity: i.severity,
      code: i.code,
      facts: i.facts,
      since: i.since,
      action: i.action,
      relaySlug: i.relaySlug,
      edgeId: i.edgeId,
      listenerKey: i.listenerKey,
      accountId: i.accountId,
      rotationId: i.rotationId,
      labels: {
        node:
          (i.relayId ? lab.relays[i.relayId] : undefined) ??
          (i.relaySlug ? lab.relays[i.relaySlug] : undefined) ??
          null,
        account:
          (i.accountId ? lab.accounts[i.accountId] || null : null) ??
          (i.edgeId ? (lab.edges[i.edgeId]?.account ?? null) : null),
        location: i.edgeId ? (lab.edges[i.edgeId]?.location ?? null) : null,
      },
    })),
    ...system,
  ];
  const now = Date.now();
  const st: AlertState = await ctx.runQuery(internal.alerts.readState, {});
  const plan = planAlerts({
    now,
    state: st,
    current,
    origin: adminOrigin(process.env.WEBAUTHN_ORIGIN),
    topic: cfg.topic,
  });
  let state = plan.base;
  let error: string | null = null;
  let sent = 0;
  let messages = 0;
  for (const m of plan.messages) {
    error = await post(cfg, m.body);
    // The receiver is down or refusing: the rest waits for the next tick.
    if (error) break;
    messages++;
    sent += m.effects.filter((e) => e.type === 'sent').length;
    state = applyEffects(state, m.effects, now);
  }
  await ctx.runMutation(internal.alerts.recordDispatch, {
    stateJson: JSON.stringify(state),
    error,
    attempted: plan.messages.length > 0,
  });
  return {
    enabled: true,
    alertable: current.filter(alertWorthy).length,
    sent,
    messages,
    error,
  };
}

/** The `alerts-dispatch` cron: send what is due (new, still open, resolved). */
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
    const error = await post(cfg, testMessage(adminOrigin(process.env.WEBAUTHN_ORIGIN), cfg.topic));
    return { ok: error === null, error };
  },
});
