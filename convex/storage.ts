'use node';
/**
 * S3 subscription-content mirrors as a Node action (ported from
 * src/server/providers/storage/*). `@aws-sdk/client-s3` needs the Node runtime,
 * so this whole file is `"use node"`; it can't define queries/mutations.
 *
 * Mirrors are the censorship-resistance hedge: the proxy subscription content is
 * uploaded to S3-compatible providers so a client can fetch it even if the
 * control plane is blocked. They are OPT-IN + LAZY: a member calls
 * `provisionMirror` only when they can't reach the normal subscription URL — so
 * the non-opted-in majority's configs never touch third-party storage. Each
 * mirror is country-tiered (the DB picks the host least likely to be blocked
 * where they are) and capped per user.
 *
 * Config is fully DB-driven (the `mirrorProviders` table, CMS-managed via
 * Admin → Storage; replaced the old S3_PROVIDER_* and S3_MIRRORS_ENABLED env vars).
 * Because this file is `"use node"` it can't define queries, so each action
 * pulls the provider list from `internal.mirrorProviders.*`.
 */
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { runWithCronOutcome } from './cronHeartbeat';
import { v } from 'convex/values';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { randomHex, sha256Hex } from './lib/crypto';
import type { MirrorContext } from './subscriptions';
import type { ActiveMirrorPage } from './subscriptions';
import { applyEdgeRender } from './lib/edges/renderPipeline';
import { relabelMemberEntries } from './lib/memberEntryNames';
import type { Id } from './_generated/dataModel';

/** The body a mirror holds when its place is edge-required and nothing can render. */
export const MIRROR_UNAVAILABLE_STUB =
  '# FreeSocks: this mirror is temporarily unavailable. Refresh later.\n';

export interface MirrorValidation {
  policyVersion: number;
  epoch: number;
  edgeIds: string[];
  at: number;
  stub?: boolean;
}

/**
 * The mirror barrier's token for one upload (convex/mirrorUploads.ts): the
 * delivery token of the place the body resolved to (`edgeRender.epochFor`)
 * and the key's own `deliveryRev`, so an in-place mode or server switch that
 * lands while the object is written leaves the obligation open like any
 * policy move (subscriptions.ts `invalidateDelivery`).
 */
async function mirrorToken(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'>,
  backendServerId: Id<'backendServers'> | null | undefined,
  node: string | undefined,
): Promise<string> {
  const [place, rev] = await Promise.all([
    backendServerId
      ? ctx.runQuery(internal.edgeRender.epochFor, { backendServerId, nodeName: node })
      : Promise.resolve(null),
    ctx.runQuery(internal.subscriptions.deliveryRevOf, { subscriptionId }),
  ]);
  return `r${rev ?? '-'}|${place ?? ''}`;
}

/**
 * Origin rendering for a mirror body under the EDGE-REQUIRED policy
 * (docs/edges.md): a mirror serves the same rendered endpoints as the fronted
 * route (link-list family: no User-Agent here). Returns the body to upload, the
 * origin's publication epoch it was rendered against, and the validation record
 * for the mirror row. A place no origin covers passes the body through
 * (`validated: null`). A covered place whose render is refused gets the
 * UNAVAILABLE STUB, never the origin body: the mirror URL is already
 * distributed, so the object itself must stop serving the origin.
 */
async function renderMirrorBody(
  ctx: ActionCtx,
  sub: { id: Id<'subscriptions'>; backendServerId: Id<'backendServers'> | null | undefined },
  node: string | undefined,
  content: string,
): Promise<{ content: string; renderedEpoch: number | null; validated: MirrorValidation | null }> {
  const out = await renderMirrorEndpoints(ctx, sub, node, content);
  if (out.validated?.stub) return out;
  // The same member-facing names as the fronted route (docs/privacy.md), after
  // the render for the same reason.
  const naming = await ctx.runQuery(internal.subscriptions.entryNamingFor, {
    backendServerId: sub.backendServerId ?? undefined,
  });
  return { ...out, content: relabelMemberEntries(out.content, naming).content };
}

/** The edge-render half of `renderMirrorBody`. */
async function renderMirrorEndpoints(
  ctx: ActionCtx,
  sub: { id: Id<'subscriptions'>; backendServerId: Id<'backendServers'> | null | undefined },
  node: string | undefined,
  content: string,
): Promise<{ content: string; renderedEpoch: number | null; validated: MirrorValidation | null }> {
  if (!sub.backendServerId) return { content, renderedEpoch: null, validated: null };
  const decision = await ctx.runQuery(internal.edgeRender.decideForSubscription, {
    subscriptionId: sub.id,
    family: 'other',
    nodeName: node,
  });
  if (decision.kind === 'raw') return { content, renderedEpoch: null, validated: null };
  const policy = await ctx.runQuery(internal.edgeRender.deliveryPolicy, {
    backendServerId: sub.backendServerId,
    nodeName: node,
  });
  const stub = (
    epoch: number,
  ): { content: string; renderedEpoch: number | null; validated: MirrorValidation } => ({
    content: MIRROR_UNAVAILABLE_STUB,
    renderedEpoch: null,
    validated: {
      policyVersion: policy.bindingVersion ?? 0,
      epoch,
      edgeIds: [],
      at: Date.now(),
      stub: true,
    },
  });
  if (decision.kind === 'unavailable') return stub(-1);
  const rctx = decision.context;
  const renderKey =
    rctx.renderKey ??
    (await ctx.runMutation(internal.subscriptions.ensureRenderKey, { subscriptionId: sub.id }));
  if (!renderKey) return stub(rctx.epoch);
  // A mirror is fetched with no request FCP can see: never a name known
  // blocked in a curated country, unless the member said where they are.
  const out = applyEdgeRender(rctx, content, renderKey, {
    now: Date.now(),
    where: rctx.storedWhere,
    // Edges by country only on the member's own choice (never a guess);
    // without one, edges blocked in any listed country go last.
    edgeCountry: rctx.storedEdgeCountry,
    avoidBlockedIn: rctx.storedAvoidBlockedIn,
  });
  if (out.delivery.kind !== 'serve') return stub(rctx.epoch);
  return {
    content: out.body,
    renderedEpoch: rctx.epoch,
    validated: {
      policyVersion: policy.bindingVersion ?? 0,
      epoch: rctx.epoch,
      edgeIds: [out.snapshot.primaryEdgeId, out.snapshot.backupEdgeId].filter(
        (x): x is string => !!x,
      ),
      at: Date.now(),
    },
  };
}

export interface S3Provider {
  name: string;
  endpoint: string;
  bucket: string;
  publicUrl: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface SubscriptionMirror {
  provider: string;
  publicUrl: string;
  objectPath: string;
  status: 'ok';
  validated?: MirrorValidation;
}

function clientFor(p: S3Provider): S3Client {
  return new S3Client({
    region: p.region,
    endpoint: p.endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: p.accessKeyId, secretAccessKey: p.secretAccessKey },
  });
}

/**
 * One S3 operation against one provider. Injected (default = the real SDK call)
 * so the parallel/aggregate logic in uploadToProviders / deleteFromProviders is
 * unit-testable with a plain stub, without the AWS SDK or the Convex runtime.
 */
export type S3Op =
  | { kind: 'put'; key: string; body: string; contentType: string }
  | { kind: 'delete'; key: string };
export type S3Send = (provider: S3Provider, op: S3Op) => Promise<void>;

let sendImpl: S3Send | null = null;
/** Test seam: replace the S3 call for every upload/delete this module makes (null = the SDK). */
export function __setS3SendForTests(send: S3Send | null): void {
  sendImpl = send;
}
const s3Send: S3Send = (p, op) => (sendImpl ?? realSend)(p, op);

const realSend: S3Send = async (p, op) => {
  const client = clientFor(p);
  if (op.kind === 'put') {
    await client.send(
      new PutObjectCommand({
        Bucket: p.bucket,
        Key: op.key,
        Body: op.body,
        ContentType: op.contentType,
      }),
    );
  } else {
    await client.send(new DeleteObjectCommand({ Bucket: p.bucket, Key: op.key }));
  }
};

/**
 * Upload `content` to every given provider in parallel. Returns the successful
 * mirrors in the subscription-mirror shape. No providers → []. All uploads
 * failed → throws (so the saga knows mirroring is broken). The provider list +
 * send fn are injected so this is unit-testable without the Convex runtime.
 */
export async function uploadToProviders(
  providers: S3Provider[],
  {
    objectPath,
    content,
    contentType,
  }: { objectPath: string; content: string; contentType?: string },
  send: S3Send = realSend,
): Promise<SubscriptionMirror[]> {
  if (providers.length === 0) return [];
  const results = await Promise.allSettled(
    providers.map(async (p): Promise<SubscriptionMirror> => {
      await send(p, {
        kind: 'put',
        key: objectPath,
        body: content,
        contentType: contentType ?? 'text/plain',
      });
      return {
        provider: p.name,
        publicUrl: `${p.publicUrl.replace(/\/$/, '')}/${objectPath}`,
        objectPath,
        status: 'ok',
      };
    }),
  );
  const successes = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
  if (successes.length === 0) throw new Error('All S3 mirror uploads failed');
  return successes;
}

/**
 * Best-effort delete of mirror objects across providers (injected list + send).
 * Never throws; returns the providers whose delete did not go through (an
 * unknown provider is nothing to delete), for a caller that must retry them.
 */
export async function deleteFromProviders(
  providers: S3Provider[],
  items: { provider: string; objectPath: string }[],
  send: S3Send = realSend,
): Promise<{ failed: string[] }> {
  const results = await Promise.allSettled(
    items.map(async (it) => {
      const p = providers.find((x) => x.name === it.provider);
      if (!p) return;
      await send(p, { kind: 'delete', key: it.objectPath });
    }),
  );
  return {
    failed: items.filter((_, i) => results[i]!.status === 'rejected').map((it) => it.provider),
  };
}

export interface ProvisionResult {
  status: 'ok' | 'capped' | 'exhausted' | 'no_subscription' | 'error';
  publicUrl?: string;
  provider?: string;
  remaining: number;
}

/**
 * Opt-in lazy mirror: provision ONE more S3 mirror for the member's active sub,
 * picking the next country-tiered provider they haven't tried. Bounded by the
 * `mirror.maxPerUser` setting. Reuses the sub's capability object path across
 * providers (one unguessable token per sub; content identical, only the host
 * differs). `countryCode` is used transiently to pick a nearby host — never stored.
 */
export const provisionMirror = internalAction({
  args: { userId: v.id('users'), countryCode: v.union(v.string(), v.null()) },
  handler: async (ctx, { userId, countryCode }): Promise<ProvisionResult> => {
    const context: MirrorContext | null = await ctx.runQuery(
      internal.subscriptions.mirrorContextForUser,
      { userId },
    );
    if (!context) return { status: 'no_subscription', remaining: 0 };

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const cap = Math.max(0, Number(settings['mirror.maxPerUser'] ?? 3));
    const used = context.triedProviders.length;
    if (used >= cap) return { status: 'capped', remaining: 0 };

    const next = await ctx.runQuery(internal.mirrorProviders.selectNextProvider, {
      countryCode,
      tried: context.triedProviders,
    });
    if (!next) return { status: 'exhausted', remaining: Math.max(0, cap - used) };

    // Re-resolve the secret-bearing provider by name (active only).
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    const provider = providers.find((p) => p.name === next.name);
    if (!provider) return { status: 'exhausted', remaining: Math.max(0, cap - used) };

    let fetched: { content: string; contentType?: string; pinnedNode?: string };
    try {
      fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: context.backend,
        backendServerId: context.backendServerId ?? undefined,
        backendShortId: context.backendShortId,
        subscriptionUrl: context.subscriptionUrl,
        // The same exclusion the live /sub route and the refresh apply. Node
        // pinning is deterministic, so provisioning a FIRST mirror without it
        // uploads the very node the member just switched away from.
        excludeNode: context.excludeNode ?? undefined,
      });
    } catch {
      return { status: 'error', remaining: Math.max(0, cap - used) };
    }
    // The delivery token the body is rendered under: re-read after the upload
    // (the mirror barrier below).
    const tokenOf = () =>
      mirrorToken(ctx, context.subscriptionId, context.backendServerId, fetched.pinnedNode);
    const tokenBefore = await tokenOf();
    // The first upload is rendered like every later refresh: a mirror must
    // never hold the template entries (the origin / index-0 address) until the
    // sweep comes round.
    const rendered = await renderMirrorBody(
      ctx,
      { id: context.subscriptionId, backendServerId: context.backendServerId },
      fetched.pinnedNode,
      fetched.content,
    );
    const contentAt = Date.now();
    const hash = await sha256Hex(rendered.content);
    // One capability token per sub, reused across providers (stable + unguessable).
    const objectPath = context.objectPath ?? `mirrors/${randomHex(16)}`;

    // The obligation exists BEFORE the object does: an upload that races a
    // policy move is repaired or withdrawn later, never trusted.
    const obligation = await ctx.runMutation(internal.mirrorUploads.open, {
      subscriptionId: context.subscriptionId,
      objectPath,
      providers: [provider.name],
      tokenBefore,
      kind: 'initial',
    });
    const obligationId = obligation.id;
    let entry: SubscriptionMirror | undefined;
    try {
      const mirrors = await uploadToProviders(
        [provider],
        {
          objectPath,
          content: rendered.content,
          contentType: fetched.contentType,
        },
        s3Send,
      );
      entry = mirrors[0];
      if (entry && rendered.validated) entry = { ...entry, validated: rendered.validated };
    } catch {
      // Nothing was written: nothing to repair (unless it replaced an open record of the object).
      if (obligation.superseded === 0)
        await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
      return { status: 'error', remaining: Math.max(0, cap - used) };
    }
    if (!entry) return { status: 'error', remaining: Math.max(0, cap - used) };

    const appended = await ctx.runMutation(internal.subscriptions.appendMirror, {
      subscriptionId: context.subscriptionId,
      mirror: entry,
      rawContentHash: hash,
      cap,
    });
    // The object was uploaded but the row didn't change. Two causes, and they
    // need different answers: a lost cap race (Review D-#8) really is capped,
    // but a SUPERSEDED row means a re-issue overtook us — the member is not
    // capped at all and a retry will provision against their live key, so report
    // it as a retryable error. Either way the uploaded object is residue.
    if (!appended.appended) {
      return appended.reason === 'superseded'
        ? { status: 'error', remaining: Math.max(0, cap - used) }
        : { status: 'capped', remaining: 0 };
    }
    // Record the node only now: the object is uploaded AND the row references
    // it, so this is the first moment the pin describes what the member is
    // actually served. For someone who only ever uses the mirror, this is also
    // the only place it gets written — without it their next switch-server finds
    // no pin to rotate and refuses with `no_alternative`.
    if (fetched.pinnedNode) {
      await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
        subscriptionId: context.subscriptionId,
        node: fetched.pinnedNode,
        deliveryRev: context.deliveryRev,
      });
    }
    await ctx.runMutation(internal.subscriptions.markMirrorRefreshed, {
      subscriptionId: context.subscriptionId,
      contentAt,
      renderedEpoch: rendered.renderedEpoch,
      deliveryRev: context.deliveryRev,
    });
    // Settled only if nothing moved while the object was written; otherwise
    // the repair pass re-renders it under the policy that holds now.
    if ((await tokenOf()) === tokenBefore)
      await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
    return {
      status: 'ok',
      publicUrl: entry.publicUrl,
      provider: provider.name,
      remaining: Math.max(0, cap - used - 1),
    };
  },
});

/** Remove all of the member's mirrors (reset): clear the list + delete the objects. */
export const clearMirrorsForUser = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ removed: number }> => {
    const context: MirrorContext | null = await ctx.runQuery(
      internal.subscriptions.mirrorContextForUser,
      { userId },
    );
    if (!context) return { removed: 0 };
    const { items } = await ctx.runMutation(internal.subscriptions.clearMirrors, {
      subscriptionId: context.subscriptionId,
    });
    if (items.length > 0) {
      const providers = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
      await deleteFromProviders(providers, items, s3Send);
    }
    return { removed: items.length };
  },
});

/** Best-effort delete of mirror objects (tombstone sweep / teardown). Uses ALL
 *  providers (incl. since-deactivated ones) so stale objects get cleaned. */
export const deleteMirrors = internalAction({
  args: { items: v.array(v.object({ provider: v.string(), objectPath: v.string() })) },
  handler: async (ctx, { items }) => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
    await deleteFromProviders(providers, items, s3Send);
    return null;
  },
});

/**
 * Admin test: confirm a provider's connection details work BEFORE saving, by
 * writing a tiny health object to the bucket (also validates write perms, which
 * is what mirroring needs). The secret is never echoed back or put in the error
 * (the SDK error name/message carries no credential).
 */
export const testProviderConnection = internalAction({
  args: {
    endpoint: v.string(),
    bucket: v.string(),
    region: v.optional(v.string()),
    accessKeyId: v.string(),
    secretAccessKey: v.string(),
  },
  handler: async (_ctx, a): Promise<{ ok: true } | { ok: false; error: string }> => {
    if (!a.endpoint || !a.bucket || !a.accessKeyId || !a.secretAccessKey) {
      return { ok: false, error: 'endpoint, bucket, access key ID and secret are all required' };
    }
    const provider: S3Provider = {
      name: '__test__',
      endpoint: a.endpoint,
      bucket: a.bucket,
      publicUrl: '',
      region: a.region?.trim() || 'us-east-1',
      accessKeyId: a.accessKeyId,
      secretAccessKey: a.secretAccessKey,
    };
    try {
      await clientFor(provider).send(
        new PutObjectCommand({
          Bucket: provider.bucket,
          Key: '__fcp_healthcheck',
          Body: 'ok',
          ContentType: 'text/plain',
        }),
      );
      return { ok: true };
    } catch (err) {
      const msg = err instanceof Error ? `${err.name}: ${err.message}` : 'connection failed';
      return { ok: false, error: msg.slice(0, 200) };
    }
  },
});

// Bounded per run: drain up to MAX_PAGES × PAGE active subs, continuing from the
// cursor persisted at the END of the last run so the window rotates through the
// whole fleet over successive ticks (a per-run cold start re-scans the same
// oldest window forever and starves every mirrored sub beyond it — M3).
const REFRESH_MAX_PAGES = 50;
const REFRESH_PAGE = 50;

/** One page item of the mirror sweep. */
type MirrorRefreshItem = ActiveMirrorPage['items'][number];

/**
 * Re-upload ONE subscription's mirrors to its own providers, in place. Shared by
 * the periodic sweep and the targeted refresh a re-issue schedules, so both apply
 * the same node exclusion, the same "record the pin only once the mirror serves
 * it" rule, and the same partial-round hold. Returns whether anything was
 * re-uploaded; never throws (a backend/S3 hiccup must not stall the caller).
 */
async function refreshOneSubMirrors(
  ctx: ActionCtx,
  byName: Map<string, S3Provider>,
  sub: MirrorRefreshItem,
  // Skip the unchanged-content short-circuit. Used by the self-heal below: after
  // a stale writer overwrites the shared object, the OWNER's stored hash still
  // describes the content it uploaded, so an ordinary refresh would match and
  // decline to repair the object.
  force = false,
  kind: 'refresh' | 'repair' = 'refresh',
): Promise<boolean> {
  try {
    // Re-upload only to THIS sub's providers that are still active.
    const targets = sub.providers.map((n) => byName.get(n)).filter((p): p is S3Provider => !!p);
    if (targets.length === 0 || !sub.objectPath) return false;
    const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
      backend: sub.backend,
      backendServerId: sub.backendServerId ?? undefined,
      backendShortId: sub.backendShortId,
      subscriptionUrl: sub.subscriptionUrl,
      // Same exclusion the live /sub route applies, or the deterministic
      // pin regenerates the node the member switched AWAY from — and the
      // unchanged hash below would then skip the re-upload, leaving the
      // mirror pointed at it indefinitely.
      excludeNode: sub.excludeNode ?? undefined,
    });
    // Record the node this landed on, exactly as the live /sub routes do.
    // For a member who only ever uses the mirror URL this is the ONLY
    // place the pin gets written, and without it their next switch-server
    // finds no pin to rotate and refuses with `no_alternative` even
    // though the mode group has other nodes.
    //
    // The pin must describe the node the member's mirror ACTUALLY serves,
    // so it is written at exactly the two points where that is true:
    // unchanged content (the mirror already holds this node's config), or
    // a successful upload. Writing it before a failed upload would record
    // a node the member is not on, and their next switch would then
    // exclude the wrong one.
    const recordPin = async () => {
      if (!fetched.pinnedNode) return;
      await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
        subscriptionId: sub.id,
        node: fetched.pinnedNode,
        deliveryRev: sub.deliveryRev,
      });
    };
    // The delivery token is read before the render and again before the upload:
    // a policy that moved meanwhile (a node gate, a rotation, the key's own
    // mode or server switch) means this body was rendered under an older
    // policy, and it never reaches the object; the next refresh renders under
    // the new one (docs/servers.md "Node lifecycle").
    const tokenOf = () =>
      mirrorToken(ctx, sub.id, sub.backendServerId, fetched.pinnedNode ?? undefined);
    const tokenBefore = await tokenOf();
    // Origin rendering (docs/edges.md): a mirror serves the same rendered
    // endpoints as the fronted route (link-list family: no User-Agent here).
    const rendered = await renderMirrorBody(
      ctx,
      sub,
      fetched.pinnedNode ?? undefined,
      fetched.content,
    );
    const content = rendered.content;
    const contentAt = Date.now();
    // The mirror now provably holds content generated at `contentAt` (and
    // rendered against the current epoch): stamp it exactly where the pin is
    // recorded, so a mirror-only member is not "never refreshed" forever to
    // the origin heuristics.
    const stampContent = () =>
      ctx.runMutation(internal.subscriptions.markMirrorRefreshed, {
        subscriptionId: sub.id,
        contentAt,
        renderedEpoch: rendered.renderedEpoch,
        deliveryRev: sub.deliveryRev,
      });
    if ((await tokenOf()) !== tokenBefore) return false;
    const hash = await sha256Hex(content);
    if (hash === sub.rawContentHash && !force) {
      // Nothing to re-upload: the pin can move while the bytes stay identical,
      // and the mirror is already correct, so record it.
      await recordPin();
      await stampContent();
      return false;
    }
    // The mirror barrier: the obligation is open before the object is
    // written, and settles below only if the token did not move meanwhile.
    const obligation = await ctx.runMutation(internal.mirrorUploads.open, {
      subscriptionId: sub.id,
      objectPath: sub.objectPath,
      providers: targets.map((t) => t.name),
      tokenBefore,
      kind,
    });
    const obligationId = obligation.id;
    // Throws only if EVERY provider failed (caught below → sub skipped,
    // pin deliberately unrecorded: the mirror still serves the old node).
    let uploaded: SubscriptionMirror[];
    try {
      uploaded = await uploadToProviders(
        targets,
        {
          objectPath: sub.objectPath,
          content,
          contentType: fetched.contentType,
        },
        s3Send,
      );
    } catch (err) {
      // Nothing was written by THIS upload: its obligation is settled, unless
      // it replaced an open one of the object (which then still stands for it).
      if (obligation.superseded === 0)
        await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
      throw err;
    }
    const mirrors = uploaded.map((m) =>
      rendered.validated ? { ...m, validated: rendered.validated } : m,
    );
    // Providers we attempted but that didn't come back a success this round →
    // updateMirrors keeps their existing entry marked failed (Review #2),
    // rather than dropping it. (uploadToProviders throws only if ALL fail,
    // caught above → the sub is skipped, entries untouched.)
    const succeeded = new Set(mirrors.map((m) => m.provider));
    const failedProviders = targets.map((t) => t.name).filter((n) => !succeeded.has(n));
    // A PARTIAL round leaves at least one provider serving the previous
    // content, so neither the hash nor the pin may advance yet:
    //  - the hash is subscription-wide, and advancing it would make the
    //    next run take the unchanged-content short-circuit and never
    //    retry the stale provider — stranding it permanently;
    //  - the pin would then describe a node some mirror URL does not
    //    serve, so a later switch-server would exclude the wrong node.
    // Holding both means the next run retries (one extra re-upload to
    // the healthy providers every 6h until the broken one recovers) and
    // both advance together on the first clean round.
    const allSucceeded = failedProviders.length === 0;
    // The token moved while the object was written: the body may describe a
    // policy that no longer holds. Nothing is stamped; the obligation stays
    // open and the repair pass re-renders under the current one.
    const moved = (await tokenOf()) !== tokenBefore;
    await ctx.runMutation(internal.subscriptions.updateMirrors, {
      subscriptionId: sub.id,
      successes: mirrors,
      failedProviders,
      ...(allSucceeded && !moved ? { rawContentHash: hash } : {}),
    });
    if (moved) return true;
    if (allSucceeded)
      // Nothing moved and every copy was rewritten: the obligation is met (and
      // every earlier one of these copies with it).
      await ctx.runMutation(internal.mirrorUploads.settle, {
        id: obligationId,
        subscriptionId: sub.id,
      });
    // A provider that failed still serves a body rendered under an older policy:
    // the obligation stays open for exactly those copies, so the repair pass
    // retries them within minutes rather than at the next sweep.
    else
      await ctx.runMutation(internal.mirrorUploads.narrow, {
        id: obligationId,
        providers: failedProviders,
      });
    if (allSucceeded) {
      await recordPin();
      await stampContent();
    }
    return true;
  } catch {
    /* best-effort per sub: one backend/S3 hiccup must not stall the sweep */
    return false;
  }
}

/**
 * Targeted mirror refresh for ONE subscription, scheduled when a re-issue carries
 * mirrors onto a replacement row. The carry moves the metadata but not the S3
 * object, so until something rewrites it the mirror still serves the OLD key —
 * which stops routing when the tombstone sweep deletes that key 24h later.
 * Waiting for the 6h sweep is not sufficient at scale: it scans a bounded number
 * of active rows per run, so on a large fleet a given row's turn can fall outside
 * that 24h window. This closes the gap in seconds instead.
 */
export const refreshMirrorsForSubscription = internalAction({
  args: { subscriptionId: v.id('subscriptions'), force: v.optional(v.boolean()) },
  handler: async (ctx, { subscriptionId, force }): Promise<null> => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    if (providers.length === 0) return null;
    const target = await ctx.runQuery(internal.subscriptions.mirrorRefreshTarget, {
      subscriptionId,
    });
    if (!target) return null;
    await refreshOneSubMirrors(
      ctx,
      new Map(providers.map((p) => [p.name, p])),
      target,
      force === true,
    );
    return null;
  },
});

/**
 * Cron: the repair pass of the mirror barrier (convex/mirrorUploads.ts). An
 * open obligation past its in-flight grace is an upload whose policy moved
 * under it: a mirror a subscription still references is re-rendered and
 * re-uploaded under the CURRENT policy (forced; the unavailable stub when its
 * place is gated or edge-required with nothing to render), which settles the
 * obligation only under a stable token; an object nothing references any more
 * (a lost first upload, a re-issued key) is withdrawn. Bounded per run.
 */
export const repairMirrorUploads = internalAction({
  args: {},
  handler: async (ctx): Promise<{ repaired: number; withdrawn: number }> =>
    runWithCronOutcome(ctx, 'mirror-barrier-repair', async () => {
      const due = await ctx.runQuery(internal.mirrorUploads.listDue, { now: Date.now() });
      let repaired = 0;
      let withdrawn = 0;
      if (due.length === 0) return { repaired, withdrawn };
      const active = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
      const byName = new Map(active.map((p) => [p.name, p]));
      for (const o of due) {
        await ctx.runMutation(internal.mirrorUploads.markAttempt, { id: o.id });
        if (o.residueProviders.length > 0) {
          // Residue: a copy no subscription references (deactivated providers
          // included). Withdrawn only once every delete went through; a failed
          // one keeps the obligation, so the next pass tries again.
          const all = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
          const { failed } = await deleteFromProviders(
            all,
            o.residueProviders.map((provider) => ({ provider, objectPath: o.objectPath })),
            s3Send,
          );
          if (failed.length > 0) continue;
          withdrawn++;
          // What is left of the obligation is the copies the subscription still serves.
          if (o.referenced)
            await ctx.runMutation(internal.mirrorUploads.narrow, {
              id: o.id,
              providers: o.providers.filter((p) => !o.residueProviders.includes(p)),
            });
        }
        if (!o.referenced) {
          await ctx.runMutation(internal.mirrorUploads.settle, { id: o.id });
          continue;
        }
        const target = await ctx.runQuery(internal.subscriptions.mirrorRefreshTarget, {
          subscriptionId: o.subscriptionId,
        });
        if (target && (await refreshOneSubMirrors(ctx, byName, target, true, 'repair'))) repaired++;
      }
      return { repaired, withdrawn };
    }),
});

/**
 * One full pass over every mirrored key, started NOW and continued until it
 * reached the last one: for a change that must not wait for the six-hourly
 * sweep's window (freedom modes only through edges: a held key's mirror is
 * replaced by the unavailable stub, a released one gets its body back). The
 * same per-key refresh as the sweep, `REFRESH_MAX_PAGES` pages per run, then
 * it schedules itself with its own cursor; the sweep's cursor is untouched.
 */
export const drainMirrors = internalAction({
  args: { cursor: v.union(v.string(), v.null()) },
  handler: async (
    ctx,
    { cursor: start },
  ): Promise<{ refreshed: number; scanned: number; done: boolean }> => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    if (providers.length === 0) return { refreshed: 0, scanned: 0, done: true };
    const byName = new Map(providers.map((p) => [p.name, p]));
    let cursor = start;
    let refreshed = 0;
    let scanned = 0;
    for (let page = 0; page < REFRESH_MAX_PAGES; page++) {
      // Annotated (not inferred) to break the internal-API self-reference cycle.
      const res: ActiveMirrorPage = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
        cursor,
        numItems: REFRESH_PAGE,
      });
      for (const sub of res.items) {
        scanned++;
        if (await refreshOneSubMirrors(ctx, byName, sub)) refreshed++;
      }
      if (res.isDone) return { refreshed, scanned, done: true };
      cursor = res.continueCursor;
    }
    await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, { cursor });
    return { refreshed, scanned, done: false };
  },
});

/**
 * Cron: keep EXISTING (opt-in) mirrors fresh. Pages only subs that already have a
 * mirror (never creates one) and re-uploads each sub's current content to ITS OWN
 * providers at the SAME object path — so the mirror URL the member already holds
 * stays valid with up-to-date content. Skips a sub whose content is unchanged
 * (hash match), so steady state is cheap. No-op when no provider is enabled.
 */
export const refreshActiveMirrors = internalAction({
  args: {},
  handler: async (ctx): Promise<{ refreshed: number; scanned: number }> =>
    runWithCronOutcome(ctx, 'mirror-refresh', async () => {
      const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
      if (providers.length === 0) {
        return { refreshed: 0, scanned: 0 };
      }
      const byName = new Map(providers.map((p) => [p.name, p]));
      let cursor: string | null = await ctx.runQuery(internal.mirrorProviders.getRefreshCursor, {});
      let refreshed = 0;
      let scanned = 0;
      for (let page = 0; page < REFRESH_MAX_PAGES; page++) {
        // Annotated (not inferred) to break the internal-API self-reference cycle.
        let res: ActiveMirrorPage;
        try {
          res = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
            cursor,
            numItems: REFRESH_PAGE,
          });
        } catch (err) {
          // A stale/invalid cursor (e.g. after an index change) must not wedge the
          // sweep: reset to the start and continue from there next run.
          if (cursor === null) throw err;
          console.warn('[mirror-refresh] cursor rejected; restarting from the beginning');
          cursor = null;
          res = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
            cursor,
            numItems: REFRESH_PAGE,
          });
        }
        for (const sub of res.items) {
          scanned++;
          if (await refreshOneSubMirrors(ctx, byName, sub)) refreshed++;
        }
        if (res.isDone) {
          // Full pass complete: restart from the beginning next tick.
          await ctx.runMutation(internal.mirrorProviders.setRefreshCursor, { cursor: null });
          return { refreshed, scanned };
        }
        cursor = res.continueCursor;
      }
      // Hit the per-run page cap: persist where we stopped so the NEXT tick
      // continues forward instead of re-scanning the same window (M3).
      await ctx.runMutation(internal.mirrorProviders.setRefreshCursor, { cursor });
      return { refreshed, scanned };
    }),
});
