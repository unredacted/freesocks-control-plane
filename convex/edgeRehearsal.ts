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
 *    A cohort's first key is not always one: its body may be the backend's
 *    placeholder for an expired or disabled key, or resolve to another node (a
 *    stale pin). The next candidates of the cohort (`edgeCohorts.candidates`,
 *    active accounts first, up to REHEARSAL_CANDIDATES) are tried; a cohort
 *    with none that can stand for it is reported `unrepresented`, never failed
 *    (delivery hands a placeholder out as it is, and another node's binding
 *    judges a moved body). When EVERY cohort is unrepresented the credential
 *    stands in, as for an empty node.
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
import { cohortValidator, walkRelayCohorts, type CohortCandidate } from './edgeCohorts';
import { placeholderBody } from './lib/nodePinning';
import { bodyMentionsAny } from './lib/subscriptionDelivery';
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
import { nodeAddressesOf } from './nodeIntents';

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
/**
 * Candidate members one cohort tries before it counts as unrepresented: the
 * first key of a placement may be an expired or disabled one (the backend
 * serves it a placeholder) or one whose pin moved to another node.
 */
export const REHEARSAL_CANDIDATES = 10;
/**
 * A cohort none of whose candidates could prove anything about this node
 * (reported, not failed): `placeholder` = every body was the backend's
 * placeholder for an expired or disabled key, which delivery hands out as it
 * is; `moved` = every body resolved to another node, whose own binding judges
 * it; `mixed` = both.
 */
export interface RehearsalUnrepresented {
  cohortKey: string;
  reason: 'placeholder' | 'moved' | 'mixed';
  tried: number;
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
  /** Cohorts with no candidate whose body proves anything about this node. */
  unrepresented?: RehearsalUnrepresented[];
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
      nodeAddresses: await nodeAddressesOf(ctx, relay),
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

type BodyRef = { backendShortId: string; subscriptionUrl: string; excludeNode: string | null };
type FetchedBody =
  | { kind: 'body'; content: string; pinnedNode?: string; nodeless: boolean }
  | { kind: 'failed' };

/** One representative body, fetched FRESH from the backend in `format`. */
async function fetchBody(
  ctx: ActionCtx,
  c: RehearsalContext,
  format: RenderFormat,
  ref: BodyRef,
): Promise<FetchedBody> {
  try {
    const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
      backend: c.backend,
      backendServerId: c.backendServerId,
      backendShortId: ref.backendShortId,
      subscriptionUrl: ref.subscriptionUrl,
      userAgent: REHEARSAL_USER_AGENTS[format],
      ...(ref.excludeNode ? { excludeNode: ref.excludeNode } : {}),
      nodeCheck: true,
    });
    return {
      kind: 'body',
      content: fetched.content,
      pinnedNode: fetched.pinnedNode,
      nodeless: fetched.nodeless === true,
    };
  } catch {
    return { kind: 'failed' };
  }
}

/**
 * Whether a candidate's body can stand for its cohort on THIS node: not the
 * backend's placeholder for an expired or disabled key (delivery hands that
 * out as it is), and not resolved to another node. An empty body still counts
 * (and fails as `empty_body`): it is a hidden-out cohort's signature.
 */
function candidateVerdict(
  c: RehearsalContext,
  f: FetchedBody,
): 'use' | 'placeholder' | 'leak' | 'moved' | 'failed' {
  if (f.kind === 'failed') return 'failed';
  if (f.nodeless && placeholderBody(f.content))
    // As delivery: a placeholder is handed out as it is unless it names the node.
    return bodyMentionsAny(f.content, [c.originAddress, ...(c.nodeAddresses ?? [])])
      ? 'leak'
      : 'placeholder';
  if (c.nodeName && f.pinnedNode && f.pinnedNode !== c.nodeName) return 'moved';
  return 'use';
}

type Representative = (
  | {
      kind: 'use';
      ref: BodyRef & { renderKey: string | null };
      fetched: Map<RenderFormat, FetchedBody>;
    }
  | { kind: 'unrepresented'; reason: RehearsalUnrepresented['reason']; tried: number }
  | { kind: 'failed' }
) & {
  /** Formats in which some tried candidate's placeholder names the node (delivery refuses it). */
  leaks: RenderFormat[];
};

/**
 * The cohort's representative: its own first key, else the next candidates
 * (`edgeCohorts.candidates`, active accounts first) up to
 * REHEARSAL_CANDIDATES. A candidate stands for the cohort when ANY supported
 * format's body does (the backend picks each format's body from the user
 * agent, so one format may be a placeholder while another is real); every
 * format it was fetched in is then rehearsed from those bodies. No candidate
 * standing for it while any candidate's body could not be fetched is `failed`:
 * an outage is never read as an unrepresented cohort.
 */
async function pickRepresentative(
  ctx: ActionCtx,
  c: RehearsalContext,
  cohort: RehearsalContext['cohorts'][number],
  first: BodyRef & { renderKey: string | null },
): Promise<Representative> {
  const seen = new Set<string>([cohort.subscriptionId as string]);
  let rest: CohortCandidate[] | null = null;
  let next: (BodyRef & { renderKey: string | null }) | undefined = first;
  let placeholders = 0;
  let moved = 0;
  let unfetched = 0;
  let tried = 0;
  const leaks = new Set<RenderFormat>();
  while (next && tried < REHEARSAL_CANDIDATES) {
    tried++;
    const fetched = new Map<RenderFormat, FetchedBody>();
    const verdicts = new Set<ReturnType<typeof candidateVerdict>>();
    for (const format of c.formats) {
      const body = await fetchBody(ctx, c, format, next);
      fetched.set(format, body);
      const verdict = candidateVerdict(c, body);
      // A placeholder is judged while candidates are classified: one that names
      // the node fails the cohort whichever candidate ends up standing for it.
      if (verdict === 'leak') leaks.add(format);
      verdicts.add(verdict);
    }
    if (verdicts.has('use')) return { kind: 'use', ref: next, fetched, leaks: [...leaks] };
    if (verdicts.has('failed')) unfetched++;
    if (verdicts.has('placeholder') || verdicts.has('leak')) placeholders++;
    if (verdicts.has('moved')) moved++;
    rest ??= await ctx.runQuery(internal.edgeCohorts.candidates, {
      backendServerId: cohort.backendServerId,
      ...(cohort.nodeName ? { nodeName: cohort.nodeName } : {}),
      placement: cohort.placement,
      limit: REHEARSAL_CANDIDATES + 1,
    });
    const candidate = rest.find((x) => !seen.has(x.subscriptionId as string));
    if (candidate) seen.add(candidate.subscriptionId as string);
    next = candidate;
  }
  if (unfetched > 0 || (placeholders === 0 && moved === 0))
    return { kind: 'failed', leaks: [...leaks] };
  return {
    kind: 'unrepresented',
    reason: placeholders > 0 && moved > 0 ? 'mixed' : placeholders > 0 ? 'placeholder' : 'moved',
    tried,
    leaks: [...leaks],
  };
}

async function rehearseBody(
  ctx: ActionCtx,
  c: RehearsalContext,
  cohortKey: string,
  format: RenderFormat,
  ref: BodyRef,
  renderKey: string,
  onReduced?: (r: RehearsalReduced) => void,
  prefetched?: FetchedBody,
  /**
   * A member representative's placeholder body in THIS format passes:
   * delivery hands it out as it is. Never for the rehearsal credential, whose
   * placeholder means FCP's own check key cannot be served.
   */
  placeholderPasses = false,
): Promise<RehearsalFailure | null> {
  const ua = REHEARSAL_USER_AGENTS[format];
  const fetched = prefetched ?? (await fetchBody(ctx, c, format, ref));
  if (fetched.kind === 'failed') return { cohortKey, format, reason: 'fetch_failed' };
  if (placeholderPasses) {
    // As delivery: a placeholder is handed out as it is unless it names the node.
    const verdict = candidateVerdict(c, fetched);
    if (verdict === 'placeholder') return null;
    if (verdict === 'leak') return { cohortKey, format, reason: 'leak_detected' };
  }
  const { content, pinnedNode } = fetched;
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
    nodeAddresses: c.nodeAddresses,
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
      const unrepresented: RehearsalUnrepresented[] = [];
      const noteReduced = (r: RehearsalReduced) => reduced.push(r);
      let source: RehearsalResult['source'] = 'members';
      if (!c.activationCurrent) {
        // A newer approval (or none) owns the node now: this run proves nothing.
        for (const f of c.formats.length ? c.formats : (['links'] as RenderFormat[]))
          failures.push({ cohortKey: 'activation', format: f, reason: 'activation_superseded' });
      } else if (c.cohorts.length > 0 && c.formats.length > 0) {
        for (const cohort of c.cohorts) {
          const sub = c.subs[cohort.key];
          if (!sub) {
            for (const f of c.formats)
              failures.push({ cohortKey: cohort.key, format: f, reason: 'subscription_missing' });
            continue;
          }
          const rep = await pickRepresentative(ctx, c, cohort, sub);
          // A placeholder that names the node fails its format, once, whichever
          // candidate it came from (delivery refuses it `leak_detected`).
          const leaked = new Set(rep.leaks);
          for (const f of leaked)
            failures.push({ cohortKey: cohort.key, format: f, reason: 'leak_detected' });
          if (rep.kind === 'failed') {
            for (const f of c.formats)
              if (!leaked.has(f))
                failures.push({ cohortKey: cohort.key, format: f, reason: 'fetch_failed' });
            continue;
          }
          if (rep.kind === 'unrepresented') {
            if (leaked.size === 0)
              unrepresented.push({ cohortKey: cohort.key, reason: rep.reason, tried: rep.tried });
            continue;
          }
          for (const format of c.formats) {
            if (leaked.has(format)) continue;
            const fail = await rehearseBody(
              ctx,
              c,
              cohort.key,
              format,
              rep.ref,
              rep.ref.renderKey ?? `rehearsal:${cohort.key}`,
              noteReduced,
              rep.fetched.get(format),
              true,
            );
            if (fail) failures.push(fail);
          }
        }
      }
      // An empty node, or one whose every cohort had no candidate to prove
      // anything with: the rehearsal credential is the single representative,
      // so a binding is never claimed on no rendered body at all.
      const noMembers =
        c.activationCurrent &&
        (c.cohorts.length === 0 ||
          (failures.length === 0 && unrepresented.length === c.cohorts.length));
      if (noMembers) {
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
        unrepresented,
      };
      if (!listingChanged) return last;
    }
    return last!;
  },
});
