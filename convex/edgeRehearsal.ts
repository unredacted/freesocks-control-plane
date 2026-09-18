/**
 * Delivery rehearsal (docs/edges.md § "Rendering", the setup's stage 7): prove
 * delivery with the REAL renderer before the binding is claimed, over cohorts
 * derived from authoritative membership (lib/edges/cohorts.ts), never from
 * render snapshots.
 *
 *  - One representative subscription per cohort (distinct placement among the
 *    subscriptions pinned to the node), fetched FRESH from the panel per
 *    supported format (links, sing-box JSON, Clash YAML through catalogued
 *    client user agents), run through `applyEdgeRender` in dry-run: no
 *    persistence, no snapshot write. Every non-dark cohort must yield `serve`
 *    in every format. An approved dark cohort (`darkCohortKeys`) is excluded.
 *  - An EMPTY panel node has no cohort: the rehearsal credential (the relay's
 *    qualification user, minted on demand) is the single representative body.
 *    An empty Outline server has no credential path (`use_manual_setup`); an
 *    Outline server with members is rehearsed from its real single-key subs.
 *  - Every catalogued client family's render rule must be enabled
 *    (`familiesDisabled`); every published L7 proof must be current
 *    (`proofsExpired`).
 *  - The OBSERVATION BOUNDARY: the panel Hosts are listed BEFORE and AFTER
 *    (`edgeHostHides.observe`), and the result is accepted only when the two
 *    listings are identical; otherwise the rehearsal repeats (bounded). The
 *    returned observation is the FINAL listing, so the go-live clock does not
 *    include the rehearsal itself.
 *  - The VECTOR (`listenerRevisions`, `renderConfigHash`, `publicationEpoch`,
 *    `qualificationEvidenceIds`) is what the go-live mutation compares against
 *    `vectorNow` before it binds.
 */
import { v } from 'convex/values';
import type { FunctionReturnType } from 'convex/server';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import { RENDER_CLIENT_FAMILIES, resolveEdgeConfig, type EdgeConfig } from './lib/edgeConfig';
import { classifyClient } from './lib/edges/clientFamilies';
import { cohortsForRelay, type Cohort } from './lib/edges/cohorts';
import { formatSupported, type RenderFormat } from './lib/edges/protocols';
import { fnv1a64Hex } from './lib/edges/registration';
import { effectiveRule, type DeliveryStyle } from './lib/edges/render';
import { applyEdgeRender, type EdgeRenderContext } from './lib/edges/renderPipeline';
import { verificationCurrent } from './lib/edges/verification';
import { deliveryStyleOf, l7QualificationCurrent, publishedEdgesOf } from './edgeRender';
import type { HostObservation } from './edgeHostHides';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { listenersOf } from './relayListeners';

export const REHEARSAL_MAX_ATTEMPTS = 3;

/**
 * The catalogued client of each subscription format (tests/compat/manifest.ts
 * keeps the same shells): what the panel's format selection keys on.
 */
export const REHEARSAL_USER_AGENTS: Record<RenderFormat, string> = {
  links: 'v2rayNG/1.8.29',
  singbox: 'SFA/1.10.0 (sing-box 1.10.0)',
  clash: 'mihomo/1.19.30',
};
const FORMATS: RenderFormat[] = ['links', 'singbox', 'clash'];

export interface RehearsalVector {
  listenerRevisions: Record<string, number>;
  renderConfigHash: string;
  publicationEpoch: number;
  qualificationEvidenceIds: string[];
}

export interface RehearsalFailure {
  cohortKey: string;
  format: RenderFormat;
  reason: string;
}

export interface RehearsalResult {
  ok: boolean;
  failures: RehearsalFailure[];
  familiesDisabled: string[];
  proofsExpired: Id<'edges'>[];
  vector: RehearsalVector;
  hostsObservation: { listingHash: string; observedAt: number; version: number };
  /** The listings never agreed within the attempt budget (the operator reviews the panel). */
  listingChanged: boolean;
  attempts: number;
  /** Cohorts rehearsed (dark ones excluded) and the source of the representative bodies. */
  cohorts: number;
  source: 'members' | 'credential';
  /** Every format each cohort was rehearsed in (a dark cohort must fail in ALL of them). */
  formats: RenderFormat[];
}

function canonicalJson(x: unknown): string {
  if (Array.isArray(x)) return `[${x.map(canonicalJson).join(',')}]`;
  if (x && typeof x === 'object') {
    const o = x as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(x);
}

export function renderConfigHashOf(render: EdgeConfig['render']): string {
  return fnv1a64Hex(canonicalJson(render));
}

async function vectorOf(
  ctx: { db: Parameters<typeof listenersOf>[0]['db'] },
  relay: Doc<'relays'>,
  cfg: EdgeConfig,
  now: number,
): Promise<{ vector: RehearsalVector; proofsExpired: Id<'edges'>[] }> {
  const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired);
  const edges = (await liveEdgesOfRelay(ctx.db, relay._id)).filter(
    (e) => e.publication === 'published' && e.status === 'active',
  );
  const evidence: string[] = [];
  const proofsExpired: Id<'edges'>[] = [];
  for (const e of edges) {
    const l = listeners.find((x) => x._id === e.listenerId) ?? null;
    if ((e.layer ?? 'l4') === 'l7') {
      if (await l7QualificationCurrent(e, l, now)) evidence.push(e._id as string);
      else proofsExpired.push(e._id);
    } else if (l && verificationCurrent(e, l)) evidence.push(e._id as string);
  }
  return {
    vector: {
      listenerRevisions: Object.fromEntries(listeners.map((l) => [l.listenerKey, l.revision])),
      renderConfigHash: renderConfigHashOf(cfg.render),
      publicationEpoch: relay.publicationEpoch,
      qualificationEvidenceIds: evidence.sort(),
    },
    proofsExpired,
  };
}

/** The vector the go-live mutation compares with the rehearsal's. */
export const vectorNow = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<RehearsalVector | null> => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    return (await vectorOf(ctx, relay, cfg, Date.now())).vector;
  },
});

export function sameVector(a: RehearsalVector, b: RehearsalVector): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

/** Everything one rehearsal attempt reads, in one transaction. */
export const context = internalQuery({
  args: { relayId: v.id('relays'), darkCohortKeys: v.array(v.string()) },
  handler: async (ctx, { relayId, darkCohortKeys }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay || !relay.backendServerId) return null;
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    const now = Date.now();
    const cfg = await resolveEdgeConfig(ctx.db);
    const { vector, proofsExpired } = await vectorOf(ctx, relay, cfg, now);
    const listeners = (await listenersOf(ctx, relayId)).filter(
      (l) => !l.retired && l.deployed && l.enabled,
    );
    const protos = listeners.map((l) => ({
      protocol: l.protocol,
      streamTransport: l.streamTransport,
      security: l.security,
    }));
    const deliveryStyle: DeliveryStyle = await deliveryStyleOf(ctx, relay.backendServerId);
    const formats = FORMATS.filter(
      (f) =>
        (deliveryStyle === 'subscription' || f === 'links') &&
        protos.some((p) => formatSupported(p, f)),
    );
    const { published, matchers } = await publishedEdgesOf(ctx, relay, { includeIneligible: true });
    const dark = new Set(darkCohortKeys);
    const all = await cohortsForRelay(ctx, relay);
    const cohorts = all
      .filter((c) => !dark.has(c.key))
      .map((c) => ({ ...c, subscriptionId: c.subscriptionId as Id<'subscriptions'> }));
    const subs: Record<
      string,
      {
        backendShortId: string;
        subscriptionUrl: string;
        renderKey: string | null;
        excludeNode: string | null;
      }
    > = {};
    for (const c of cohorts) {
      const sub = await ctx.db.get(c.subscriptionId);
      if (!sub) continue;
      subs[c.key] = {
        backendShortId: sub.backendShortId,
        subscriptionUrl: sub.subscriptionUrl,
        renderKey: sub.renderKey ?? null,
        excludeNode: sub.excludeNode ?? null,
      };
    }
    return {
      relayId: relay._id,
      backend: server.backend,
      backendServerId: relay.backendServerId,
      nodeName: relay.origin.kind === 'panel-node' ? (relay.nodeName ?? null) : null,
      panelNode: relay.origin.kind === 'panel-node' && capabilitiesOf(server.backend).placement,
      originAddress: relay.originAddress,
      epoch: relay.publicationEpoch,
      formats,
      deliveryStyle,
      published,
      matchers,
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      rules: Object.fromEntries(
        RENDER_CLIENT_FAMILIES.map((f) => [f, effectiveRule(cfg.render, cfg.render.clients[f])]),
      ),
      familiesDisabled: RENDER_CLIENT_FAMILIES.filter((f) => !cfg.render.clients[f].enabled),
      proofsExpired,
      vector,
      cohorts: cohorts as Cohort[],
      totalCohorts: all.length,
      subs,
    };
  },
});

type Observer = (ctx: ActionCtx, relayId: Id<'relays'>) => Promise<HostObservation>;
let observer: Observer = (ctx, relayId) =>
  ctx.runAction(internal.edgeHostHides.observe, { relayId });
/** Test seam: the Host listing the rehearsal brackets itself with (agent H's `observe`). */
export function __setHostObserverForTests(f: Observer | null): void {
  observer = f ?? ((ctx, relayId) => ctx.runAction(internal.edgeHostHides.observe, { relayId }));
}

type RehearsalContext = NonNullable<FunctionReturnType<typeof internal.edgeRehearsal.context>>;

async function rehearseBody(
  ctx: ActionCtx,
  c: RehearsalContext,
  cohortKey: string,
  format: RenderFormat,
  ref: { backendShortId: string; subscriptionUrl: string; excludeNode: string | null },
  renderKey: string,
): Promise<RehearsalFailure | null> {
  const ua = REHEARSAL_USER_AGENTS[format];
  let content: string;
  let pinnedNode: string | undefined;
  try {
    const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
      backend: c.backend,
      backendServerId: c.backendServerId,
      backendShortId: ref.backendShortId,
      subscriptionUrl: ref.subscriptionUrl,
      userAgent: ua,
      ...(ref.excludeNode ? { excludeNode: ref.excludeNode } : {}),
    });
    content = fetched.content;
    pinnedNode = fetched.pinnedNode;
  } catch {
    return { cohortKey, format, reason: 'fetch_failed' };
  }
  if (!content.trim()) return { cohortKey, format, reason: 'empty_body' };
  // The representative must resolve to THIS node, or it says nothing about it.
  if (c.nodeName && pinnedNode && pinnedNode !== c.nodeName)
    return { cohortKey, format, reason: 'pinned_elsewhere' };
  const family = classifyClient(ua).family;
  const rctx: EdgeRenderContext = {
    epoch: c.epoch,
    matchers: c.matchers,
    published: c.published,
    rule: { ...c.rules[family], enabled: true },
    preferDistinctProviders: c.preferDistinctProviders,
    originAddress: c.originAddress,
    deliveryStyle: c.deliveryStyle,
  };
  const out = applyEdgeRender(rctx, content, renderKey, { now: Date.now() });
  if (out.delivery.kind !== 'serve') return { cohortKey, format, reason: out.delivery.reason };
  return null;
}

export const run = internalAction({
  args: { relayId: v.id('relays'), darkCohortKeys: v.array(v.string()) },
  handler: async (ctx, { relayId, darkCohortKeys }): Promise<RehearsalResult> => {
    let attempts = 0;
    let last: RehearsalResult | null = null;
    while (attempts < REHEARSAL_MAX_ATTEMPTS) {
      attempts++;
      const before = await observer(ctx, relayId);
      const c = await ctx.runQuery(internal.edgeRehearsal.context, { relayId, darkCohortKeys });
      if (!c) throw new Error('rehearsal: the relay has no panel origin');
      const failures: RehearsalFailure[] = [];
      let source: RehearsalResult['source'] = 'members';
      if (c.cohorts.length > 0) {
        for (const cohort of c.cohorts) {
          const sub = c.subs[cohort.key];
          if (!sub) {
            for (const f of c.formats)
              failures.push({ cohortKey: cohort.key, format: f, reason: 'subscription_missing' });
            continue;
          }
          for (const format of c.formats) {
            const fail = await rehearseBody(
              ctx,
              c,
              cohort.key,
              format,
              sub,
              sub.renderKey ?? `rehearsal:${cohort.key}`,
            );
            if (fail) failures.push(fail);
          }
        }
      } else {
        // An empty node: the rehearsal credential is the single representative.
        source = 'credential';
        const cred = await ctx.runAction(internal.edgeTestCredentials.ensure, {
          relayId,
          purpose: 'rehearsal',
        });
        if (!cred.ok) {
          for (const f of c.formats.length ? c.formats : (['links'] as RenderFormat[]))
            failures.push({ cohortKey: 'credential', format: f, reason: cred.code });
        } else {
          for (const format of c.formats) {
            const fail = await rehearseBody(
              ctx,
              c,
              'credential',
              format,
              { ...cred.fetchRef, excludeNode: null },
              'rehearsal:credential',
            );
            if (fail) failures.push(fail);
          }
        }
      }
      const after = await observer(ctx, relayId);
      const listingChanged = before.listingHash !== after.listingHash;
      last = {
        ok:
          !listingChanged &&
          failures.length === 0 &&
          c.familiesDisabled.length === 0 &&
          c.proofsExpired.length === 0,
        failures,
        familiesDisabled: c.familiesDisabled,
        proofsExpired: c.proofsExpired,
        vector: c.vector,
        hostsObservation: {
          listingHash: after.listingHash,
          observedAt: after.observedAt,
          version: after.observedAt,
        },
        listingChanged,
        attempts,
        cohorts: c.cohorts.length,
        source,
        formats: c.formats,
      };
      if (!listingChanged) return last;
    }
    return last!;
  },
});
