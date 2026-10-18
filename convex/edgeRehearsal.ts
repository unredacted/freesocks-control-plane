/**
 * Delivery rehearsal (docs/edges.md § "Rendering", the setup's stage 7): prove
 * delivery with the REAL renderer before the binding is claimed, over cohorts
 * derived from authoritative membership (lib/edges/cohorts.ts), never from
 * render snapshots.
 *
 *  - One representative subscription per cohort (distinct placement among the
 *    subscriptions pinned to the node), fetched FRESH from the backend per
 *    supported format (links, sing-box JSON, Clash YAML through catalogued
 *    client user agents), run through `applyEdgeRender` in dry-run: no
 *    persistence, no snapshot write. Every non-dark cohort must yield `serve`
 *    in every format. An approved dark cohort (`darkCohortKeys`) is excluded.
 *  - An EMPTY backend node has no cohort: the rehearsal credential (the origin's
 *    qualification user, minted on demand) is the single representative body.
 *    An empty Outline server has no credential path (`use_manual_setup`); an
 *    Outline server with members is rehearsed from its real single-key subs.
 *  - Every catalogued client family's render rule must be enabled
 *    (`familiesDisabled`); every published L7 proof must be current
 *    (`proofsExpired`).
 *  - The OBSERVATION BOUNDARY: the backend Hosts are listed BEFORE and AFTER
 *    (`edgeHostHides.observe`), and the result is accepted only when the two
 *    listings are identical; otherwise the rehearsal repeats (bounded). The
 *    returned observation is the FINAL listing, so the go-live clock does not
 *    include the rehearsal itself.
 *  - The VECTOR (`listenerRevisions`, `renderConfigHash`, `publicationEpoch`,
 *    `qualificationEvidenceIds`) is what the go-live mutation compares against
 *    `vectorNow` before it binds.
 */
import { verificationListenersOf } from './lib/edges/verificationContext';
import { v } from 'convex/values';
import type { FunctionReturnType } from 'convex/server';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import { RENDER_CLIENT_FAMILIES, resolveEdgeConfig, type EdgeConfig } from './lib/edgeConfig';
import { classifyClient } from './lib/edges/clientFamilies';
import type { Cohort } from './lib/edges/cohorts';
import { cohortValidator, walkRelayCohorts } from './edgeCohorts';
import { formatSupported, type RenderFormat } from './lib/edges/protocols';
import { fnv1a64Hex } from './lib/edges/registration';
import { effectiveRule, ruleForDelivery, type DeliveryStyle } from './lib/edges/render';
import { bodyGroups, resilienceExpectation, type ReducedReason } from './lib/edges/providerSet';
import { applyEdgeRender, type EdgeRenderContext } from './lib/edges/renderPipeline';
import { verificationCurrent } from './lib/edges/verification';
import { deliveryStyleOf, l7QualificationCurrent, publishedEdgesOf } from './edgeRender';
import type { HostObservation } from './edgeHostHides';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import type { VectorActivation } from './lib/edges/setupRuns';
import { listenersOf } from './relayListeners';
import { activationVectorFor } from './nodeActivation';

export const REHEARSAL_MAX_ATTEMPTS = 3;

/**
 * The catalogued client of each subscription format (tests/compat/manifest.ts
 * keeps the same shells): what the backend's format selection keys on.
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
  /** The activation candidate rendered (an enrolled node's running activation), else null. */
  activation?: VectorActivation | null;
}

export interface RehearsalFailure {
  cohortKey: string;
  format: RenderFormat;
  reason: string;
}

/** A body that gets no backup in another failure domain, and why (reported, not failed). */
export interface RehearsalReduced {
  cohortKey: string;
  format: RenderFormat;
  reason: ReducedReason;
}

export interface RehearsalResult {
  ok: boolean;
  failures: RehearsalFailure[];
  familiesDisabled: string[];
  proofsExpired: Id<'edges'>[];
  vector: RehearsalVector;
  hostsObservation: { listingHash: string; observedAt: number; version: number };
  /** The listings never agreed within the attempt budget (the operator reviews the backend). */
  listingChanged: boolean;
  attempts: number;
  /** Cohorts rehearsed (dark ones excluded) and the source of the representative bodies. */
  cohorts: number;
  source: 'members' | 'credential';
  /** Every format each cohort was rehearsed in (a dark cohort must fail in ALL of them). */
  formats: RenderFormat[];
  /** Bodies with no backup in another failure domain, and why. */
  reduced?: RehearsalReduced[];
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
  // With the enrolled node's auth revision: an L4 tick binds to it.
  const listeners = (
    await verificationListenersOf(ctx.db, relay, await listenersOf(ctx, relay._id))
  ).filter((l) => !l.retired);
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
      activation: await activationVectorFor(ctx, relay),
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

/**
 * Everything one rehearsal attempt reads, in one transaction. With
 * `activationRunId` (an enrolled node's setup run) the bodies are rendered
 * from exactly that activation's candidates (`publishedEdgesOf`'s internal
 * activation context): a live node's replacement is proven on the edges the
 * commit will promote, not on what members hold now.
 */
export const context = internalQuery({
  args: {
    relayId: v.id('relays'),
    darkCohortKeys: v.array(v.string()),
    activationRunId: v.optional(v.id('panelActivationRuns')),
    /** Every cohort of the origin, walked by the action beforehand (edgeCohorts.ts). */
    cohorts: v.array(cohortValidator),
  },
  handler: async (ctx, { relayId, darkCohortKeys, activationRunId, cohorts: all }) => {
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
    const { published, matchers } = await publishedEdgesOf(
      ctx,
      relay,
      activationRunId ? { kind: 'activation', activationRunId } : { kind: 'member' },
      { includeIneligible: true },
    );
    // The activation the rehearsal was asked for must still be the node's
    // current, running one, or there is nothing it could prove.
    const activationCurrent =
      !activationRunId || vector.activation?.runId === (activationRunId as string);
    const dark = new Set(darkCohortKeys);
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
      activationCurrent,
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
  onReduced?: (r: RehearsalReduced) => void,
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
  // Resilience: under the EFFECTIVE delivery rule, a body that can have a
  // backup in another failure domain must get one (`resilience_short`); one
  // that cannot is reported with why, never failed.
  const effective = ruleForDelivery(rctx.rule, c.deliveryStyle);
  const usable = c.published.filter((e) => formatSupported(e.proto, format));
  const groups = bodyGroups(usable, out.snapshot.listenerKeys);
  const expectation = resilienceExpectation({
    style: c.deliveryStyle,
    includeBackup: effective.includeBackup,
    maxEntries: effective.maxEntries,
    preferDistinct: c.preferDistinctProviders,
    groupsOffered: groups.count,
  });
  if (expectation.on) {
    const primary = c.published.find((e) => e.edgeId === out.snapshot.primaryEdgeId);
    const backup = c.published.find((e) => e.edgeId === out.snapshot.backupEdgeId);
    if (!primary || !backup || groups.groupOf(primary) === groups.groupOf(backup))
      return { cohortKey, format, reason: 'resilience_short' };
  } else onReduced?.({ cohortKey, format, reason: expectation.reason });
  return null;
}

export const run = internalAction({
  args: {
    relayId: v.id('relays'),
    darkCohortKeys: v.array(v.string()),
    activationRunId: v.optional(v.id('panelActivationRuns')),
  },
  handler: async (ctx, { relayId, darkCohortKeys, activationRunId }): Promise<RehearsalResult> => {
    let attempts = 0;
    let last: RehearsalResult | null = null;
    while (attempts < REHEARSAL_MAX_ATTEMPTS) {
      attempts++;
      const before = await observer(ctx, relayId);
      const c = await ctx.runQuery(internal.edgeRehearsal.context, {
        relayId,
        darkCohortKeys,
        ...(activationRunId ? { activationRunId } : {}),
        cohorts: await walkRelayCohorts(ctx, relayId),
      });
      if (!c) throw new Error('rehearsal: the origin has no backend origin');
      const failures: RehearsalFailure[] = [];
      const reduced: RehearsalReduced[] = [];
      const noteReduced = (r: RehearsalReduced) => reduced.push(r);
      let source: RehearsalResult['source'] = 'members';
      if (!c.activationCurrent) {
        // A newer approval (or none) owns the node now: this run proves nothing.
        for (const f of c.formats.length ? c.formats : (['links'] as RenderFormat[]))
          failures.push({ cohortKey: 'activation', format: f, reason: 'activation_superseded' });
      } else if (c.cohorts.length > 0) {
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
              noteReduced,
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
              noteReduced,
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
        reduced,
      };
      if (!listingChanged) return last;
    }
    return last!;
  },
});
