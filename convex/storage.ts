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
import type { MirrorItem, MirrorPage } from './mirrorCopies';
import { needsUpload, type CopyOutcome, type VerifyOutcome } from './lib/mirrorSync';
import { applyEdgeRender } from './lib/edges/renderPipeline';
import {
  finishMemberBody,
  noteWithheldEntries,
  type WithheldNote,
} from './lib/subscriptionDelivery';
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
 * delivery token of the place the body resolved to (`edgeRender.epochFor`),
 * the key's own `deliveryRev`, so an in-place mode or server switch that
 * lands while the body is fetched or the object written counts as a policy
 * move (subscriptions.ts `invalidateDelivery`), its `countryRev`, so a change
 * of the member's country (the render depends on it) that lands meanwhile
 * keeps the upload open too (an older body can land after the refresh the
 * change scheduled), and the account's address lane (convex/edgeLanes.ts), so
 * an upload that straddles a lane change stays open and the repair pass
 * renders it again under the lane the account has now. `read`: the revisions
 * the caller read BEFORE it fetched the body; the baseline is taken with them,
 * so a move that lands during the fetch is already a move. Absent, the live ones.
 */
async function mirrorToken(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'>,
  backendServerId: Id<'backendServers'> | null | undefined,
  node: string | undefined,
  read?: { deliveryRev: number; countryRev: number },
): Promise<string> {
  const [place, revs, lane] = await Promise.all([
    backendServerId
      ? ctx.runQuery(internal.edgeRender.epochFor, { backendServerId, nodeName: node })
      : Promise.resolve(null),
    read ?? ctx.runQuery(internal.subscriptions.mirrorRevsOf, { subscriptionId }),
    ctx.runQuery(internal.edgeLanes.laneOf, { subscriptionId }),
  ]);
  return `r${revs?.deliveryRev ?? '-'}|c${revs?.countryRev ?? '-'}|${place ?? ''}|l${lane ?? '-'}`;
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
): Promise<MirrorRender> {
  const out = await renderMirrorEndpoints(ctx, sub, node, content);
  if (out.validated?.stub) return out;
  // Finished like the fronted route's (member-facing names, docs/privacy.md),
  // after the render for the same reason.
  const naming = await ctx.runQuery(internal.subscriptions.entryNamingFor, {
    backendServerId: sub.backendServerId ?? undefined,
  });
  return { ...out, content: finishMemberBody(out.content, naming) };
}

/**
 * A mirror body as rendered, what it left out and the addresses it hands out
 * (both noted once an upload of it is accepted).
 */
interface MirrorRender {
  content: string;
  renderedEpoch: number | null;
  validated: MirrorValidation | null;
  withheld?: WithheldNote;
  handed?: { subscriptionId: Id<'subscriptions'>; edgeIds: Id<'edges'>[] };
}

/**
 * The body now serves from the mirror (an upload accepted under the mirror
 * barrier, or the identical body already there): if the render left entries
 * out, tell the operator, as the fronted route does; and the account was
 * handed its addresses (their first exposure, convex/edgeTrust.ts). Never for
 * a body that was not uploaded or that a moved policy overtook: an account is
 * never held to an address its mirror did not serve.
 */
async function noteMirrorAccepted(ctx: ActionCtx, rendered: MirrorRender): Promise<void> {
  if (rendered.withheld)
    await noteWithheldEntries(ctx, rendered.withheld.rctx, rendered.withheld.names, Date.now());
  if (rendered.handed && rendered.handed.edgeIds.length > 0)
    await ctx.runMutation(internal.edgeTrust.noteExposure, rendered.handed);
}

/** The edge-render half of `renderMirrorBody`. */
async function renderMirrorEndpoints(
  ctx: ActionCtx,
  sub: { id: Id<'subscriptions'>; backendServerId: Id<'backendServers'> | null | undefined },
  node: string | undefined,
  content: string,
): Promise<MirrorRender> {
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
  const stub = (epoch: number): MirrorRender => ({
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
  const handed = [out.snapshot.primaryEdgeId, out.snapshot.backupEdgeId].filter(
    (x): x is string => !!x,
  ) as Id<'edges'>[];
  return {
    content: out.body,
    renderedEpoch: rctx.epoch,
    // Both noted only once an upload of this body is accepted (`noteMirrorAccepted`).
    ...(out.withheld?.length ? { withheld: { rctx, names: out.withheld } } : {}),
    handed: { subscriptionId: sub.id, edgeIds: handed },
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
  | { kind: 'put'; key: string; body: string; contentType: string; cacheControl?: string }
  | { kind: 'delete'; key: string };

/**
 * Every mirror object is written with this: a cache in front of a bucket (or a
 * client) revalidates instead of serving an old body for its default lifetime.
 * A mirror's body must change when FCP changes it: a withdrawn address, the
 * unavailable stub and a re-issued key all ride on that.
 */
export const MIRROR_CACHE_CONTROL = 'no-cache';
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
        ...(op.cacheControl ? { CacheControl: op.cacheControl } : {}),
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
        cacheControl: MIRROR_CACHE_CONTROL,
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

/**
 * Delete copies nothing should serve any more, and record the ones whose delete
 * did not go through as residue (`mirrorUploads.openWithdrawal`): the repair
 * pass deletes them until they are gone, so a member's config never stays in a
 * third-party bucket because one delete failed. Uses every provider row (a
 * deactivated one included); a copy whose provider row is gone cannot be
 * reached by FCP at all.
 */
async function deleteWithResidue(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'> | undefined,
  items: { provider: string; objectPath: string }[],
): Promise<{ failed: number }> {
  if (items.length === 0) return { failed: 0 };
  const providers = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
  const results = await Promise.all(
    items.map(async (it) => ({
      it,
      failed: (await deleteFromProviders(providers, [it], s3Send)).failed.length > 0,
    })),
  );
  const failed = results.filter((r) => r.failed).map((r) => r.it);
  if (subscriptionId) {
    const byPath = new Map<string, string[]>();
    for (const it of failed)
      byPath.set(it.objectPath, [...(byPath.get(it.objectPath) ?? []), it.provider]);
    for (const [objectPath, names] of byPath)
      await ctx.runMutation(internal.mirrorUploads.openWithdrawal, {
        subscriptionId,
        objectPath,
        providers: names,
      });
  }
  return { failed: failed.length };
}

// --- reading a copy back through its member-facing URL -------------------------------------------

/** A GET of a mirror's public URL: the status and, on 200, the body. */
export type MirrorFetch = (
  url: string,
) => Promise<{ status: number; body: string | null; oversize?: boolean }>;

const VERIFY_TIMEOUT_MS = 8_000;
/** A mirror body is a few KB; anything far larger is not one. */
const VERIFY_MAX_BYTES = 4 * 1024 * 1024;

/**
 * The real read (a plain GET, no credentials); exported for the store
 * integration test. The size bound holds while reading: a declared length past
 * it is refused before any byte is read, and the stream is cut at the bound, so
 * a URL that answers with something huge never fills memory.
 */
export const realFetch: MirrorFetch = async (url) => {
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'cache-control': 'no-cache' },
    // A bucket answers directly; a redirect is not the object.
    redirect: 'manual',
    signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
  });
  const declared = Number(res.headers.get('content-length') ?? NaN);
  if (res.status !== 200 || !res.body) {
    await res.body?.cancel().catch(() => {});
    return { status: res.status, body: null };
  }
  if (Number.isFinite(declared) && declared > VERIFY_MAX_BYTES) {
    await res.body.cancel().catch(() => {});
    return { status: 200, body: null, oversize: true };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > VERIFY_MAX_BYTES) {
      await reader.cancel().catch(() => {});
      return { status: 200, body: null, oversize: true };
    }
    chunks.push(value);
  }
  return { status: 200, body: Buffer.concat(chunks).toString('utf8') };
};

let fetchImpl: MirrorFetch | null = null;
/** Test seam: replace the public-URL read (null = a real fetch). */
export function __setMirrorFetchForTests(f: MirrorFetch | null): void {
  fetchImpl = f;
}
const mirrorFetch: MirrorFetch = (url) => (fetchImpl ?? realFetch)(url);

/**
 * Read one copy through the URL the member holds and compare it with what FCP
 * wrote: not found or forbidden is `missing` (the member gets nothing), a body
 * with another hash (or one past the size bound) is `mismatch`, anything else
 * (a timeout, a 5xx) is `unreachable` and decides nothing.
 */
export async function verifyCopy(
  fetchFn: MirrorFetch,
  url: string,
  objectHash: string | null,
): Promise<VerifyOutcome> {
  try {
    const res = await fetchFn(url);
    if (res.status === 404 || res.status === 403) return { kind: 'missing' };
    // Far larger than any mirror body: not the object FCP wrote.
    if (res.oversize) return { kind: 'mismatch', observedHash: 'oversize' };
    if (res.status !== 200 || res.body === null) return { kind: 'unreachable' };
    const observed = await sha256Hex(res.body);
    return observed === objectHash
      ? { kind: 'match' }
      : { kind: 'mismatch', observedHash: observed };
  } catch {
    return { kind: 'unreachable' };
  }
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
    const tokenBefore = await mirrorToken(
      ctx,
      context.subscriptionId,
      context.backendServerId,
      fetched.pinnedNode,
      { deliveryRev: context.deliveryRev, countryRev: context.countryRev },
    );
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
    // The key moved in place while its body was fetched (a mode or server
    // switch): the body is the placement it left, and a new mirror URL must
    // never start out serving it. The member asks again.
    if (
      (await ctx.runQuery(internal.subscriptions.deliveryRevOf, {
        subscriptionId: context.subscriptionId,
      })) !== context.deliveryRev
    )
      return { status: 'error', remaining: Math.max(0, cap - used) };
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
      renderedEpoch: rendered.renderedEpoch,
      stub: rendered.validated?.stub === true,
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
    // the repair pass re-renders it under the policy that holds now (and the
    // ledger says the copy is stale until it does).
    if ((await tokenOf()) === tokenBefore) {
      await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
      await noteMirrorAccepted(ctx, rendered);
    } else {
      await ctx.runMutation(internal.mirrorCopies.recordCheck, {
        subscriptionId: context.subscriptionId,
        deliveryRev: context.deliveryRev,
        countryRev: context.countryRev,
        at: Date.now(),
        served: null,
        outcomes: [{ provider: provider.name, outcome: { kind: 'uploaded', moved: true } }],
      });
    }
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
    // The member asked for these to go: a delete that fails is retried until
    // it goes through (the object holds their LIVE key).
    await deleteWithResidue(ctx, context.subscriptionId, items);
    return { removed: items.length };
  },
});

/** Delete mirror objects (tombstone sweep / teardown). Uses ALL providers
 *  (incl. since-deactivated ones) so stale objects get cleaned; with the
 *  subscription, a delete that fails is recorded and retried (`deleteWithResidue`). */
export const deleteMirrors = internalAction({
  args: {
    items: v.array(v.object({ provider: v.string(), objectPath: v.string() })),
    subscriptionId: v.optional(v.id('subscriptions')),
  },
  handler: async (ctx, { items, subscriptionId }) => {
    await deleteWithResidue(ctx, subscriptionId, items);
    return null;
  },
});

/**
 * Admin test: confirm a provider's connection details work BEFORE saving, by
 * writing a tiny health object to the bucket (also validates write perms, which
 * is what mirroring needs) and, given the public URL, reading it back through
 * that URL the way a member's app would (a bucket that is not publicly
 * readable, or a wrong public URL, would hand every member a dead link). The
 * object is deleted again. The secret is never echoed back or put in the error
 * (the SDK error name/message carries no credential).
 */
export const testProviderConnection = internalAction({
  args: {
    endpoint: v.string(),
    bucket: v.string(),
    region: v.optional(v.string()),
    accessKeyId: v.string(),
    secretAccessKey: v.string(),
    publicUrl: v.optional(v.string()),
  },
  handler: async (
    _ctx,
    a,
  ): Promise<
    | {
        ok: true;
        publicRead: 'ok' | 'unreadable' | 'mismatch' | null;
        publicList: 'listable' | 'private' | null;
      }
    | { ok: false; error: string }
  > => {
    if (!a.endpoint || !a.bucket || !a.accessKeyId || !a.secretAccessKey) {
      return { ok: false, error: 'endpoint, bucket, access key ID and secret are all required' };
    }
    const provider: S3Provider = {
      name: '__test__',
      endpoint: a.endpoint,
      bucket: a.bucket,
      publicUrl: a.publicUrl ?? '',
      region: a.region?.trim() || 'us-east-1',
      accessKeyId: a.accessKeyId,
      secretAccessKey: a.secretAccessKey,
    };
    const key = `__fcp_healthcheck_${randomHex(8)}`;
    const body = `fcp-healthcheck ${randomHex(8)}\n`;
    try {
      await s3Send(provider, { kind: 'put', key, body, contentType: 'text/plain' });
    } catch (err) {
      const msg = err instanceof Error ? `${err.name}: ${err.message}` : 'connection failed';
      return { ok: false, error: msg.slice(0, 200) };
    }
    let publicRead: 'ok' | 'unreadable' | 'mismatch' | null = null;
    // A mirror URL is a capability: a bucket that lists its objects to anyone
    // hands out every member's mirror path.
    let publicList: 'listable' | 'private' | null = null;
    const base = a.publicUrl?.trim().replace(/\/$/, '');
    if (base) {
      const verdict = await verifyCopy(mirrorFetch, `${base}/${key}`, await sha256Hex(body));
      publicRead =
        verdict.kind === 'match' ? 'ok' : verdict.kind === 'mismatch' ? 'mismatch' : 'unreadable';
      try {
        const listing = await mirrorFetch(`${base}/?list-type=2&max-keys=1`);
        publicList =
          listing.status === 200 && (listing.body ?? '').includes('ListBucketResult')
            ? 'listable'
            : 'private';
      } catch {
        publicList = 'private';
      }
    }
    await s3Send(provider, { kind: 'delete', key }).catch(() => {});
    return { ok: true, publicRead, publicList };
  },
});

/** The providers a refresh may write to, and the names being removed (their copies are left to the withdrawal). */
interface RefreshSet {
  byName: Map<string, S3Provider>;
  removing: Set<string>;
}

async function refreshSet(ctx: ActionCtx): Promise<RefreshSet> {
  const { targets, removing } = await ctx.runQuery(internal.mirrorProviders.refreshSet, {});
  return { byName: new Map(targets.map((p) => [p.name, p])), removing: new Set(removing) };
}

interface RefreshOpts {
  /** Rewrite these copies whatever the hashes say (`all`: every copy). */
  force?: 'all' | readonly string[];
  kind?: 'refresh' | 'repair';
}

/**
 * Re-upload ONE subscription's mirrors to its own providers, in place. Shared by
 * the passes, the targeted refresh a re-issue schedules and the repair, so all
 * apply the same node exclusion, the same "record the pin only once the mirror
 * serves it" rule and the same partial-round hold.
 *
 * Per copy: the body is rendered once; a copy whose object already holds it is
 * confirmed, the others are written (the skip-if-unchanged is per copy, from
 * the sync ledger, so a copy that missed a round is never masked by another
 * that took it). Every outcome is recorded (`mirrorCopies.recordCheck`).
 * Returns the providers whose copy was written (empty: nothing was); never
 * throws (a backend/S3 hiccup must not stall the caller).
 */
async function refreshOneSubMirrors(
  ctx: ActionCtx,
  set: RefreshSet,
  sub: MirrorItem,
  opts: RefreshOpts = {},
): Promise<string[]> {
  const kind = opts.kind ?? 'refresh';
  const forced = (name: string) =>
    opts.force === 'all' || (Array.isArray(opts.force) && opts.force.includes(name));
  const record = (
    served: { hash: string; epoch: number | null; stub: boolean } | null,
    outcomes: { provider: string; outcome: CopyOutcome }[],
  ) =>
    outcomes.length === 0
      ? Promise.resolve()
      : ctx
          .runMutation(internal.mirrorCopies.recordCheck, {
            subscriptionId: sub.id,
            deliveryRev: sub.deliveryRev,
            countryRev: sub.countryRev,
            at: Date.now(),
            served,
            outcomes,
          })
          .then(() => {});
  try {
    if (!sub.objectPath) return [];
    // Re-upload only to THIS sub's providers (active or not); a provider being
    // removed is left to its withdrawal, and one whose row is gone cannot be
    // reached at all.
    const targets = sub.providers.map((n) => set.byName.get(n)).filter((p): p is S3Provider => !!p);
    const gone = sub.providers.filter((n) => !set.byName.has(n) && !set.removing.has(n));
    await record(
      null,
      gone.map((provider) => ({ provider, outcome: { kind: 'provider_missing' } })),
    );
    if (targets.length === 0) return [];
    let fetched: { content: string; contentType?: string; pinnedNode?: string };
    try {
      fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
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
    } catch {
      await record(
        null,
        targets.map((t) => ({ provider: t.name, outcome: { kind: 'fetch_failed' } })),
      );
      return [];
    }
    // Record the node this landed on, exactly as the live /sub routes do.
    // For a member who only ever uses the mirror URL this is the ONLY
    // place the pin gets written, and without it their next switch-server
    // finds no pin to rotate and refuses with `no_alternative` even
    // though the mode group has other nodes.
    //
    // The pin must describe the node the member's mirror ACTUALLY serves,
    // so it is written at exactly the two points where that is true:
    // every copy already holds this body, or every copy was rewritten.
    // Writing it before a failed upload would record a node the member is
    // not on, and their next switch would then exclude the wrong one.
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
    // Baseline at the revision read before the fetch: a switch that landed
    // while the body was fetched never reaches the object (it scheduled its
    // own refresh).
    const tokenBefore = await mirrorToken(
      ctx,
      sub.id,
      sub.backendServerId,
      fetched.pinnedNode ?? undefined,
      { deliveryRev: sub.deliveryRev, countryRev: sub.countryRev },
    );
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
    if ((await tokenOf()) !== tokenBefore) return [];
    const hash = await sha256Hex(content);
    const served = {
      hash,
      epoch: rendered.renderedEpoch,
      stub: rendered.validated?.stub === true,
    };
    const heldOf = (name: string) => sub.copies.find((c) => c.provider === name)?.objectHash;
    const needing = targets.filter((t) => needsUpload(heldOf(t.name), hash, forced(t.name)));
    const holding = targets.filter((t) => !needing.includes(t));
    const confirmed = holding.map((t) => ({
      provider: t.name,
      outcome: { kind: 'confirmed' } as CopyOutcome,
    }));
    if (needing.length === 0) {
      // Nothing to re-upload: the pin can move while the bytes stay identical,
      // and every copy is already correct, so record it.
      await recordPin();
      await stampContent();
      await noteMirrorAccepted(ctx, rendered);
      if (sub.rawContentHash !== hash)
        await ctx.runMutation(internal.subscriptions.updateMirrors, {
          subscriptionId: sub.id,
          successes: [],
          failedProviders: [],
          rawContentHash: hash,
        });
      await record(served, confirmed);
      return [];
    }
    // The mirror barrier: the obligation is open before the object is
    // written, and settles below only if the token did not move meanwhile.
    const obligation = await ctx.runMutation(internal.mirrorUploads.open, {
      subscriptionId: sub.id,
      objectPath: sub.objectPath,
      providers: needing.map((t) => t.name),
      tokenBefore,
      kind,
    });
    const obligationId = obligation.id;
    // Throws only if EVERY provider failed (pin deliberately unrecorded: the
    // mirror still serves the old node).
    let uploaded: SubscriptionMirror[];
    try {
      uploaded = await uploadToProviders(
        needing,
        {
          objectPath: sub.objectPath,
          content,
          contentType: fetched.contentType,
        },
        s3Send,
      );
    } catch {
      // Nothing was written by THIS upload: its obligation is settled, unless
      // it replaced an open one of the object (which then still stands for it).
      if (obligation.superseded === 0)
        await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
      await record(served, [
        ...confirmed,
        ...needing.map((t) => ({
          provider: t.name,
          outcome: { kind: 'upload_failed' } as CopyOutcome,
        })),
      ]);
      return [];
    }
    const mirrors = uploaded.map((m) =>
      rendered.validated ? { ...m, validated: rendered.validated } : m,
    );
    // Providers we attempted but that didn't come back a success this round →
    // updateMirrors keeps their existing entry marked failed (Review #2),
    // rather than dropping it.
    const succeeded = new Set(mirrors.map((m) => m.provider));
    const failedProviders = needing.map((t) => t.name).filter((n) => !succeeded.has(n));
    // A PARTIAL round leaves at least one copy serving the previous content,
    // so neither the subscription-wide hash nor the pin may advance yet (the
    // pin would describe a node some mirror URL does not serve). Both
    // advance together on the first clean round.
    const allSucceeded = failedProviders.length === 0;
    // The token moved while the object was written: the body may describe a
    // policy that no longer holds. Nothing is stamped; the obligation stays
    // open and the repair pass re-renders under the current one.
    const moved = (await tokenOf()) !== tokenBefore;
    const merged = await ctx.runMutation(internal.subscriptions.updateMirrors, {
      subscriptionId: sub.id,
      successes: mirrors,
      failedProviders,
      ...(allSucceeded && !moved ? { rawContentHash: hash } : {}),
    });
    if (merged.staleWriter) {
      // This row no longer holds the object (a re-issue carried it while the
      // upload was in flight), and S3 has no fence: the upload just overwrote
      // the copies the live row serves with THIS row's body. The live row's
      // record says so, its open obligation is this one, and its refresh runs
      // now. A superseded key that still lists the copies (a regenerate's
      // grace) keeps serving them until they are deleted with it: settled.
      // With neither, the copies are residue the open record withdraws.
      if (!merged.currentOwner && merged.listedHere)
        await ctx.runMutation(internal.mirrorUploads.settle, { id: obligationId });
      if (merged.currentOwner) {
        await ctx.runMutation(internal.mirrorCopies.noteOverwritten, {
          subscriptionId: merged.currentOwner,
          objectPath: sub.objectPath,
          providers: [...succeeded],
          writtenHash: hash,
        });
        await ctx.runMutation(internal.mirrorUploads.rehome, {
          id: obligationId,
          subscriptionId: merged.currentOwner,
        });
        await ctx.scheduler.runAfter(0, internal.storage.refreshMirrorsForSubscription, {
          subscriptionId: merged.currentOwner,
        });
      }
      return [...succeeded];
    }
    const failedOutcomes = failedProviders.map((provider) => ({
      provider,
      outcome: { kind: 'upload_failed' } as CopyOutcome,
    }));
    if (moved) {
      await record(served, [
        ...[...succeeded].map((provider) => ({
          provider,
          outcome: { kind: 'uploaded', moved: true } as CopyOutcome,
        })),
        ...failedOutcomes,
      ]);
      return [...succeeded];
    }
    await noteMirrorAccepted(ctx, rendered);
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
    await record(served, [
      ...confirmed,
      ...[...succeeded].map((provider) => ({
        provider,
        outcome: { kind: 'uploaded', moved: false } as CopyOutcome,
      })),
      ...failedOutcomes,
    ]);
    return [...succeeded];
  } catch {
    /* best-effort per sub: one backend/S3 hiccup must not stall the pass */
    return [];
  }
}

/**
 * Targeted mirror refresh for ONE subscription: scheduled when a re-issue
 * carries mirrors onto a replacement row (the carry moves the metadata but not
 * the S3 object, which still serves the OLD key until something rewrites it),
 * when the key moves in place, when the member's country changes, when a read
 * of a copy found it wrong, and by the admin re-check. `force` rewrites every
 * copy; `forceProviders` only those.
 */
export const refreshMirrorsForSubscription = internalAction({
  args: {
    subscriptionId: v.id('subscriptions'),
    force: v.optional(v.boolean()),
    forceProviders: v.optional(v.array(v.string())),
    /** Read the forced copies back once rewritten (a rewrite a read asked for). */
    verifyAfter: v.optional(v.boolean()),
  },
  handler: async (ctx, { subscriptionId, force, forceProviders, verifyAfter }): Promise<null> => {
    const set = await refreshSet(ctx);
    if (set.byName.size === 0) return null;
    const target = await ctx.runQuery(internal.subscriptions.mirrorRefreshTarget, {
      subscriptionId,
    });
    if (!target) return null;
    const rewrote = await refreshOneSubMirrors(ctx, set, target, {
      force: force === true ? 'all' : forceProviders,
    });
    if (verifyAfter && forceProviders?.length)
      await readBack(ctx, subscriptionId, forceProviders, rewrote);
    return null;
  },
});

/**
 * Read copies back right after a rewrite that a read asked for, so the copy
 * ends in a definite state now: the rewrite fixed it (a match), or the URL
 * itself is the problem (`afterVerify`'s repeat). No further rewrite is
 * scheduled from here.
 */
async function readBack(
  ctx: ActionCtx,
  subscriptionId: Id<'subscriptions'>,
  providers: string[],
  /** The providers whose copy the refresh before this read actually wrote. */
  rewrote: readonly string[],
): Promise<void> {
  const targets = await ctx.runQuery(internal.mirrorCopies.verifyTargetsOf, {
    subscriptionId,
    providers,
  });
  for (const c of targets) {
    const outcome = await verifyCopy(mirrorFetch, c.publicUrl, c.objectHash);
    await ctx.runMutation(internal.mirrorCopies.recordVerify, {
      id: c.id,
      objectHash: c.objectHash,
      at: Date.now(),
      outcome,
      justRewritten: rewrote.includes(c.provider),
    });
  }
}

/**
 * Cron: the repair pass of the mirror barrier (convex/mirrorUploads.ts). A due
 * open obligation is an upload whose policy moved under it (or a copy that
 * failed, or a withdrawal whose delete failed): a copy a live row of the key
 * still serves is re-rendered and re-uploaded under the CURRENT policy, under
 * the row that holds it now (forced; the unavailable stub when its place is
 * gated or edge-required with nothing to render), which settles the obligation
 * only under a stable token; a copy nothing references any more (a lost first
 * upload, a re-issued key, a cleared or withdrawn mirror) is deleted. Bounded
 * per run, with a backoff per obligation (`mirrorUploads.repairBackoffMs`).
 */
export const repairMirrorUploads = internalAction({
  args: {},
  handler: async (ctx): Promise<{ repaired: number; withdrawn: number }> =>
    runWithCronOutcome(ctx, 'mirror-barrier-repair', async () => {
      const due = await ctx.runQuery(internal.mirrorUploads.listDue, { now: Date.now() });
      let repaired = 0;
      let withdrawn = 0;
      if (due.length === 0) return { repaired, withdrawn };
      const set = await refreshSet(ctx);
      for (const o of due) {
        await ctx.runMutation(internal.mirrorUploads.markAttempt, { id: o.id });
        if (o.residueProviders.length > 0) {
          // Residue: a copy no subscription references (deactivated providers
          // included). Withdrawn only once every delete went through; a failed
          // one keeps the obligation, so a later pass tries again.
          const all = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
          const { failed } = await deleteFromProviders(
            all,
            o.residueProviders.map((provider) => ({ provider, objectPath: o.objectPath })),
            s3Send,
          );
          if (failed.length > 0) continue;
          withdrawn++;
          // What is left of the obligation is the copies a live row still serves.
          if (o.referenced)
            await ctx.runMutation(internal.mirrorUploads.narrow, {
              id: o.id,
              providers: o.providers.filter((p) => !o.residueProviders.includes(p)),
            });
        }
        if (!o.referenced || !o.ownerId) {
          await ctx.runMutation(internal.mirrorUploads.settle, { id: o.id });
          continue;
        }
        // The copies follow the row that holds them now (a re-issue carried them).
        if (o.ownerId !== o.subscriptionId)
          await ctx.runMutation(internal.mirrorUploads.rehome, {
            id: o.id,
            subscriptionId: o.ownerId,
          });
        const target = await ctx.runQuery(internal.subscriptions.mirrorRefreshTarget, {
          subscriptionId: o.ownerId,
        });
        const live = o.providers.filter((p) => !o.residueProviders.includes(p));
        if (
          target &&
          (await refreshOneSubMirrors(ctx, set, target, { force: live, kind: 'repair' })).length > 0
        )
          repaired++;
      }
      return { repaired, withdrawn };
    }),
});

// A mirror pass visits every mirrored key in pages, for at most this long per
// action run, then continues in a new run from its cursor (so a large number
// of mirrors never runs one action into its time limit).
const PASS_PAGE = 50;
const SEED_PAGE = 100;
const PASS_RUN_BUDGET_MS = 4 * 60_000;

interface PassArgs {
  cursor: string | null;
  pass?: 'start' | 'continue';
  /** Paging the active keys (the one pass that gives legacy mirrors their ledger rows). */
  seed?: boolean;
  /** The key the previous page ended on (refreshed whole: skip the rest of its copies). */
  after?: Id<'subscriptions'>;
}

/**
 * One full pass over every mirrored key: the six-hourly sweep, and every change
 * that must not wait for it (an edge left the pool, a node closed, a freedom
 * key held or released, lanes moved). Pages the sync ledger (only mirrored
 * keys; the first pass after the ledger shipped pages the active keys once to
 * give legacy mirrors their rows), refreshes each key, and continues in a new
 * run from its cursor until it reached the last one. `pass: 'start'` claims
 * THE pass first: while one runs, a new request only makes it go round once
 * more at its end (`mirrorProviders.claimMirrorPass` / `noteMirrorPass`).
 */
async function runMirrorPass(
  ctx: ActionCtx,
  a: PassArgs,
): Promise<{ refreshed: number; scanned: number; done: boolean }> {
  const set = await refreshSet(ctx);
  if (set.byName.size === 0) {
    // No mirror to keep: a running pass ends here (a request it absorbed
    // goes round once more and ends the same way), a new one never starts.
    if (
      a.pass === 'continue' &&
      (await ctx.runMutation(internal.mirrorProviders.noteMirrorPass, { done: true }))
    )
      await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, {
        cursor: null,
        pass: 'continue',
      });
    return { refreshed: 0, scanned: 0, done: true };
  }
  if (a.pass === 'start' && !(await ctx.runMutation(internal.mirrorProviders.claimMirrorPass, {})))
    return { refreshed: 0, scanned: 0, done: true };
  const next = a.pass ? ('continue' as const) : undefined;
  const seed = a.seed ?? !(await ctx.runQuery(internal.mirrorCopies.isSeeded, {}));
  const deadline = Date.now() + PASS_RUN_BUDGET_MS;
  let cursor = a.cursor;
  let after = a.after;
  let refreshed = 0;
  let scanned = 0;
  for (;;) {
    // Annotated (not inferred) to break the internal-API self-reference cycle.
    const res: MirrorPage = seed
      ? await ctx.runMutation(internal.mirrorCopies.seedPage, { cursor, numItems: SEED_PAGE })
      : await ctx.runQuery(internal.mirrorCopies.pageMirrored, {
          cursor,
          numItems: PASS_PAGE,
          ...(after ? { after } : {}),
        });
    for (const item of res.items) {
      scanned++;
      if ((await refreshOneSubMirrors(ctx, set, item)).length > 0) refreshed++;
    }
    after = res.items.at(-1)?.id ?? after;
    if (res.isDone) {
      if (seed) await ctx.runMutation(internal.mirrorCopies.markSeeded, {});
      // A request that came in meanwhile: once more from the first key.
      if (
        a.pass &&
        (await ctx.runMutation(internal.mirrorProviders.noteMirrorPass, { done: true }))
      )
        await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, {
          cursor: null,
          pass: next,
        });
      return { refreshed, scanned, done: true };
    }
    cursor = res.continueCursor;
    if (Date.now() >= deadline) break;
  }
  if (a.pass) await ctx.runMutation(internal.mirrorProviders.noteMirrorPass, { done: false });
  await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, {
    cursor,
    seed,
    ...(after ? { after } : {}),
    ...(next ? { pass: next } : {}),
  });
  return { refreshed, scanned, done: false };
}

/** A mirror pass, started now (`scheduleMirrorRefresh`) or continued from its cursor (`runMirrorPass`). */
export const drainMirrors = internalAction({
  args: {
    cursor: v.union(v.string(), v.null()),
    pass: v.optional(v.union(v.literal('start'), v.literal('continue'))),
    seed: v.optional(v.boolean()),
    after: v.optional(v.id('subscriptions')),
  },
  handler: async (ctx, a): Promise<{ refreshed: number; scanned: number; done: boolean }> =>
    runMirrorPass(ctx, a),
});

/**
 * Cron: keep EXISTING (opt-in) mirrors fresh. Starts the full pass (or, while
 * one runs, makes it go round once more): every mirrored key is re-rendered and
 * each copy re-uploaded to ITS OWN provider at the SAME object path when its
 * object does not hold that body, so the mirror URL the member already holds
 * stays valid with up-to-date content. It never creates a mirror, and a copy
 * whose object already holds the body is only confirmed. No-op when no
 * provider exists. Returns the first run's figures.
 */
export const refreshActiveMirrors = internalAction({
  args: {},
  handler: async (ctx): Promise<{ refreshed: number; scanned: number }> =>
    runWithCronOutcome(ctx, 'mirror-refresh', async () => {
      const { refreshed, scanned } = await runMirrorPass(ctx, { cursor: null, pass: 'start' });
      return { refreshed, scanned };
    }),
});

const VERIFY_BATCH = 100;
/** Reads in flight at once, and how long one run may spend reading. */
const VERIFY_CONCURRENCY = 10;
const VERIFY_RUN_BUDGET_MS = 3 * 60_000;

/**
 * Cron: read copies back through the URL each member holds and compare what it
 * serves with what FCP wrote (`verifyCopy`). A copy is read about every six
 * hours (`MIRROR_VERIFY_EVERY_MS`), a new one at the next run, and one that
 * found a problem again soon after the rewrite it caused. A copy the URL
 * serves wrong or not at all is rewritten once (`afterVerify`); if the next
 * read still finds it, the URL is the problem and the copy is failing. The
 * requests carry nothing but the object path the member's app fetches too.
 */
export const verifyMirrorCopies = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    read: number;
    match: number;
    mismatch: number;
    missing: number;
    unreachable: number;
  }> =>
    runWithCronOutcome(ctx, 'mirror-verify', async () => {
      const out = { read: 0, match: 0, mismatch: 0, missing: 0, unreachable: 0 };
      const due = await ctx.runQuery(internal.mirrorCopies.dueForVerify, {
        now: Date.now(),
        limit: VERIFY_BATCH,
      });
      const rewrite = new Map<Id<'subscriptions'>, string[]>();
      // A few reads at a time, within a budget: slow or dead URLs (each up to
      // the read timeout) never run the action past its limit; what is left is
      // still due at the next run.
      const deadline = Date.now() + VERIFY_RUN_BUDGET_MS;
      for (let i = 0; i < due.rows.length && Date.now() < deadline; i += VERIFY_CONCURRENCY) {
        const chunk = due.rows.slice(i, i + VERIFY_CONCURRENCY);
        const outcomes = await Promise.all(
          chunk.map((c) => verifyCopy(mirrorFetch, c.publicUrl, c.objectHash)),
        );
        for (const [j, c] of chunk.entries()) {
          const outcome = outcomes[j]!;
          out.read++;
          out[outcome.kind]++;
          const { needsUpload: reupload } = await ctx.runMutation(
            internal.mirrorCopies.recordVerify,
            {
              id: c.id,
              objectHash: c.objectHash,
              at: Date.now(),
              outcome,
            },
          );
          if (reupload)
            rewrite.set(c.subscriptionId, [...(rewrite.get(c.subscriptionId) ?? []), c.provider]);
        }
      }
      for (const [subscriptionId, forceProviders] of rewrite)
        await ctx.scheduler.runAfter(0, internal.storage.refreshMirrorsForSubscription, {
          subscriptionId,
          forceProviders,
          verifyAfter: true,
        });
      return out;
    }),
});

/**
 * Admin re-check of one copy: render it now, rewrite this copy whatever the
 * ledger says (one write), and read it back through the member's URL. A read
 * that matches clears any failure; one that still finds nothing, or another
 * body, right after the rewrite means the URL itself is the problem. This is
 * also the way out once the operator has fixed a bucket.
 */
export const recheckCopy = internalAction({
  args: { id: v.id('mirrorCopies') },
  handler: async (ctx, { id }): Promise<{ ok: boolean }> => {
    const ref = await ctx.runQuery(internal.mirrorCopies.copyRef, { id });
    if (!ref) return { ok: false };
    const set = await refreshSet(ctx);
    const target = await ctx.runQuery(internal.subscriptions.mirrorRefreshTarget, {
      subscriptionId: ref.subscriptionId,
    });
    if (!target) return { ok: false };
    const rewrote = await refreshOneSubMirrors(ctx, set, target, { force: [ref.provider] });
    await readBack(ctx, ref.subscriptionId, [ref.provider], rewrote);
    return { ok: true };
  },
});

/**
 * Give every mirror that has no ledger row its rows: pages the active keys from
 * `cursor` and records each listed copy (stale, unchecked; the next pass checks
 * it), until the last key or the deadline. Nothing is uploaded; idempotent.
 * Marks the ledger seeded when it reaches the last key; otherwise returns the
 * cursor to resume from (the caller schedules its own continuation).
 */
async function seedPages(
  ctx: ActionCtx,
  cursor: string | null,
  deadline: number,
): Promise<{ keys: number; done: boolean; cursor: string | null }> {
  let keys = 0;
  for (;;) {
    const res: MirrorPage = await ctx.runMutation(internal.mirrorCopies.seedPage, {
      cursor,
      numItems: SEED_PAGE,
    });
    keys += res.items.length;
    if (res.isDone) {
      await ctx.runMutation(internal.mirrorCopies.markSeeded, {});
      return { keys, done: true, cursor: null };
    }
    cursor = res.continueCursor;
    if (Date.now() >= deadline) return { keys, done: false, cursor };
  }
}

/**
 * Post-deploy (docker/deploy-entrypoint.sh): make sure the sync ledger knows
 * every mirror, so the passes (which page the ledger) reach them all. Runs on
 * every deploy, even when the ledger says it was seeded (a rollback to code
 * without the ledger can have added mirrors since); past its time budget it
 * continues in a new run from its cursor.
 */
export const seedMirrorLedger = internalAction({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }): Promise<{ keys: number; done: boolean }> => {
    const res = await seedPages(ctx, cursor ?? null, Date.now() + PASS_RUN_BUDGET_MS);
    if (!res.done)
      await ctx.scheduler.runAfter(0, internal.storage.seedMirrorLedger, { cursor: res.cursor });
    return { keys: res.keys, done: res.done };
  },
});

const WITHDRAW_PAGE = 50;
const WITHDRAW_RETRY_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000];

/**
 * A provider is being removed (`mirrorProviders.remove`): withdraw every copy on
 * it (delete the object, then drop the member's entry, so they may ask for
 * another mirror), then drop the provider row. A delete that fails keeps that
 * copy (and the provider) until a later run gets it through, and so does any
 * open upload or withdrawal record that names the provider (the repair pass
 * deletes those with its credentials): the provider row holds the only
 * credential that can reach its objects. Runs in pages and in new runs (when
 * the time budget ends, or with a backoff when nothing could be deleted),
 * carrying its count; the ledger is seeded first, resumably, so it knows every
 * copy on the provider.
 */
export const withdrawProviderMirrors = internalAction({
  args: {
    providerId: v.id('mirrorProviders'),
    attempt: v.optional(v.number()),
    /** Copies withdrawn by the earlier runs of this removal (for its audit). */
    withdrawn: v.optional(v.number()),
    /** Where the ledger seed this removal runs first resumes. */
    seedCursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (
    ctx,
    { providerId, attempt, withdrawn: before, seedCursor },
  ): Promise<{ withdrawn: number; done: boolean }> => {
    const provider = await ctx.runQuery(internal.mirrorProviders.removalTarget, { providerId });
    if (!provider) return { withdrawn: before ?? 0, done: true };
    const deadline = Date.now() + PASS_RUN_BUDGET_MS;
    let withdrawn = before ?? 0;
    const again = (delayMs: number, extra: { attempt?: number; seedCursor?: string | null } = {}) =>
      ctx.scheduler.runAfter(delayMs, internal.storage.withdrawProviderMirrors, {
        providerId,
        withdrawn,
        ...extra,
      });
    if (seedCursor !== undefined || !(await ctx.runQuery(internal.mirrorCopies.isSeeded, {}))) {
      const seeded = await seedPages(ctx, seedCursor ?? null, deadline);
      if (!seeded.done) {
        await again(0, { seedCursor: seeded.cursor });
        return { withdrawn, done: false };
      }
    }
    const backoff = async () => {
      const n = attempt ?? 0;
      await again(WITHDRAW_RETRY_MS[Math.min(n, WITHDRAW_RETRY_MS.length - 1)]!, {
        attempt: n + 1,
      });
      return { withdrawn, done: false };
    };
    while (Date.now() < deadline) {
      const page = await ctx.runQuery(internal.mirrorCopies.pageOnProvider, {
        provider: provider.name,
        numItems: WITHDRAW_PAGE,
      });
      if (page.length === 0) {
        const { removed } = await ctx.runMutation(internal.mirrorProviders.finishRemoval, {
          providerId,
          withdrawn,
        });
        // An open record still names the provider: wait for the repair pass.
        if (!removed) return backoff();
        return { withdrawn, done: true };
      }
      let progress = 0;
      for (const c of page) {
        const { failed } = await deleteFromProviders(
          [provider],
          [{ provider: c.provider, objectPath: c.objectPath }],
          s3Send,
        );
        if (failed.length > 0) continue;
        await ctx.runMutation(internal.subscriptions.stripMirror, {
          subscriptionId: c.subscriptionId,
          provider: c.provider,
        });
        withdrawn++;
        progress++;
      }
      if (progress === 0) return backoff();
    }
    await again(0);
    return { withdrawn, done: false };
  },
});
