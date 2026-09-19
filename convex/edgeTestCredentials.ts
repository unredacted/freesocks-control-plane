/**
 * Temporary test credentials (docs/edges.md § "Publication"): the backend user
 * whose OWN subscription body the test link and the empty-node rehearsal are
 * built from.
 *
 *  - Remnawave: the relay's qualification credential, through
 *    `relayQualification.ensure` (a persisted, idempotent mint on the relay's
 *    placement; never a second user). No row is written here: that credential
 *    lives with the relay and goes when the relay goes.
 *  - Outline: a temporary access key through the provider's `issueUser`. The
 *    `edgeTestCredentials` row is written BEFORE the create (`backendUserId`
 *    absent until issuance is observed) and is a DURABLE OBLIGATION: the
 *    reconcile sweep removes expired or released keys through `deleteUser`
 *    with bounded retries, independently of any setup run. Closing the sheet,
 *    cancelling the run and a failed panel delete all leave a row the sweep
 *    finishes; a delete that keeps failing is `failed` and surfaces as
 *    attention `test_key_cleanup`. A rehearsal on an EMPTY Outline server has
 *    no credential path (`use_manual_setup`); an Outline server with members
 *    is rehearsed from its real single-key subscriptions.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import type { BackendId } from './lib/backendIds';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { QUALIFICATION_TRAFFIC_LIMIT_BYTES } from './relayQualification';

/** How long a temporary key lives before the sweep removes it. */
export const TEST_CREDENTIAL_TTL_MS = 24 * 60 * 60_000;
/** Delete attempts before a row is `failed` (attention `test_key_cleanup`). */
export const TEST_CREDENTIAL_MAX_ATTEMPTS = 5;
/** `done` rows are kept this long as a record, then dropped. */
const DONE_RETENTION_MS = 7 * 24 * 60 * 60_000;
const SWEEP_BATCH = 50;
/** Index pages one sweep walks past rows still in backoff before giving up for the tick. */
const SWEEP_PAGES = 10;
export const TEST_CREDENTIAL_TAG = 'fcp-test';

const purposeValidator = v.union(v.literal('rehearsal'), v.literal('test_link'));
type Purpose = 'rehearsal' | 'test_link';

export function testCredentialUsername(relaySlug: string, purpose: Purpose, nonce: string): string {
  const slug = relaySlug
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .slice(0, 20);
  return `fcp-test-${purpose === 'test_link' ? 'link' : 'rehearse'}-${slug}-${nonce}`;
}

/** Where the credential's body is fetched from (the sub route's fetch arguments). */
export interface CredentialFetchRef {
  backend: BackendId;
  backendServerId: Id<'backendServers'>;
  backendShortId: string;
  subscriptionUrl: string;
}

export type EnsureCredentialResult =
  | {
      ok: true;
      /** The temporary row (Outline); null when the relay's qualification credential is used. */
      credentialId: Id<'edgeTestCredentials'> | null;
      source: 'qualification' | 'temporary';
      fetchRef: CredentialFetchRef;
      /** The subscription identifier the body is fetched by (the backend short id). */
      subscriptionToken: string;
      reused: boolean;
    }
  | { ok: false; code: string; credentialId: null };

export const context = internalQuery({
  args: { relayId: v.id('relays'), purpose: purposeValidator },
  handler: async (ctx, { relayId, purpose }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay || !relay.backendServerId) return null;
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    const now = Date.now();
    // A live temporary row for this purpose with an observed issuance is reused.
    const rows = await ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    const reusable =
      rows.find(
        (r) =>
          r.purpose === purpose &&
          r.removal === 'pending' &&
          r.expiresAt > now + 60_000 &&
          !!r.backendUserId &&
          !!r.backendShortId &&
          !!r.subscriptionUrl,
      ) ?? null;
    return {
      slug: relay.slug,
      backend: server.backend,
      backendServerId: server._id,
      caps: capabilitiesOf(server.backend),
      qualification: relay.qualificationUserId
        ? {
            subscription: relay.qualificationSubscription ?? null,
          }
        : null,
      reusable: reusable
        ? {
            id: reusable._id,
            backendShortId: reusable.backendShortId!,
            subscriptionUrl: reusable.subscriptionUrl!,
          }
        : null,
    };
  },
});

/**
 * Who a credential row belongs to, for the audit trail: the relay's slug or
 * the enrolled node's name (a direct node's isolated test link,
 * docs/servers.md "Node lifecycle").
 */
async function ownerOf(
  ctx: { db: { get: (id: Id<'relays'> | Id<'panelNodeIntents'>) => Promise<unknown> } },
  row: Pick<Doc<'edgeTestCredentials'>, 'relayId' | 'nodeIntentId'>,
): Promise<{ targetType: 'relay' | 'panel_node_intent'; targetId: string; label: string }> {
  if (row.relayId) {
    const relay = (await ctx.db.get(row.relayId)) as Doc<'relays'> | null;
    return { targetType: 'relay', targetId: row.relayId, label: relay?.slug ?? '' };
  }
  const intent = row.nodeIntentId
    ? ((await ctx.db.get(row.nodeIntentId)) as Doc<'panelNodeIntents'> | null)
    : null;
  return {
    targetType: 'panel_node_intent',
    targetId: row.nodeIntentId ?? '',
    label: intent?.name ?? '',
  };
}

/** The obligation lands before the create. Exactly one owner is set. */
export const insertPending = internalMutation({
  args: {
    relayId: v.optional(v.id('relays')),
    nodeIntentId: v.optional(v.id('panelNodeIntents')),
    backendServerId: v.id('backendServers'),
    username: v.string(),
    purpose: purposeValidator,
  },
  handler: async (ctx, a) => {
    const server = await ctx.db.get(a.backendServerId);
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    if (!!a.relayId === !!a.nodeIntentId)
      throw new ConvexError({ code: 'validation', message: 'One owner: a relay or a node' });
    const now = Date.now();
    return ctx.db.insert('edgeTestCredentials', {
      relayId: a.relayId,
      nodeIntentId: a.nodeIntentId,
      backendServerId: a.backendServerId,
      backend: server.backend,
      username: a.username,
      purpose: a.purpose,
      expiresAt: now + TEST_CREDENTIAL_TTL_MS,
      removal: 'pending',
      attempts: 0,
      updatedAt: now,
    });
  },
});

export const markIssued = internalMutation({
  args: {
    id: v.id('edgeTestCredentials'),
    backendUserId: v.string(),
    backendShortId: v.string(),
    subscriptionUrl: v.string(),
  },
  handler: async (ctx, { id, ...issued }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    await ctx.db.patch(id, { ...issued, updatedAt: Date.now() });
    const owner = await ownerOf(ctx, row);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.test_credential',
      targetType: owner.targetType,
      targetId: owner.targetId,
      payload: { relaySlug: owner.label, purpose: row.purpose, issued: true },
    });
    return null;
  },
});

/** A definitive create failure: nothing was created, so no obligation remains. */
export const dropUnissued = internalMutation({
  args: { id: v.id('edgeTestCredentials') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (row && !row.backendUserId) await ctx.db.delete(id);
    return null;
  },
});

/**
 * Release a credential early (the sheet closed, the run was cancelled): the
 * row expires now and the next sweep removes the key. Idempotent.
 */
export const release = internalMutation({
  args: { id: v.id('edgeTestCredentials') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (!row || row.removal !== 'pending') return null;
    await ctx.db.patch(id, {
      expiresAt: Math.min(row.expiresAt, Date.now()),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * The operator closed or finished a test card: the temporary credential behind
 * its link expires now (the sweep removes it). Scoped to the edge's relay so a
 * caller cannot expire another relay's credential by id.
 */
export const releaseForEdge = internalMutation({
  args: { edgeId: v.id('edges'), credentialId: v.id('edgeTestCredentials') },
  handler: async (ctx, { edgeId, credentialId }) => {
    const edge = await ctx.db.get(edgeId);
    const row = await ctx.db.get(credentialId);
    if (!edge || !row || row.relayId !== edge.relayId)
      throw new ConvexError({ code: 'not_found', message: 'Test credential not found' });
    if (row.removal !== 'pending') return { ok: true as const, released: false };
    const now = Date.now();
    if (row.expiresAt <= now) return { ok: true as const, released: false };
    await ctx.db.patch(credentialId, { expiresAt: now, updatedAt: now });
    return { ok: true as const, released: true };
  },
});

/** Every pending credential of a relay expires now (a cancelled run, a deleted relay). */
export const releaseForRelay = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const now = Date.now();
    const rows = await ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    let released = 0;
    for (const r of rows) {
      if (r.removal !== 'pending' || r.expiresAt <= now) continue;
      await ctx.db.patch(r._id, { expiresAt: now, updatedAt: now });
      released++;
    }
    return { released };
  },
});

/**
 * Ensure a credential whose body the caller can fetch. Remnawave reuses the
 * relay's qualification credential (minted on demand, idempotent); Outline
 * gets a temporary key for a test link and no rehearsal credential at all.
 */
export const ensure = internalAction({
  args: { relayId: v.id('relays'), purpose: purposeValidator },
  handler: async (ctx, { relayId, purpose }): Promise<EnsureCredentialResult> => {
    const c = await ctx.runQuery(internal.edgeTestCredentials.context, { relayId, purpose });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay has no panel' });

    if (c.caps.userLookupByUsername) {
      // A stored credential from before the subscription locator was kept is
      // re-minted once (force) so its body can be fetched.
      const force = !!c.qualification && !c.qualification.subscription;
      const r = await ctx.runAction(internal.relayQualification.ensure, {
        relayId,
        purpose: 'rehearsal',
        ...(force ? { force: true } : {}),
      });
      if (!r.ok) return { ok: false, code: r.code ?? 'credential_unavailable', credentialId: null };
      const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
      const sub = relay?.qualificationSubscription;
      if (!sub) return { ok: false, code: 'credential_unavailable', credentialId: null };
      return {
        ok: true,
        credentialId: null,
        source: 'qualification',
        fetchRef: {
          backend: c.backend,
          backendServerId: c.backendServerId,
          backendShortId: sub.backendShortId,
          subscriptionUrl: sub.subscriptionUrl,
        },
        subscriptionToken: sub.backendShortId,
        reused: r.reused,
      };
    }

    // No name lookup (Outline): a rehearsal has no credential path.
    if (purpose === 'rehearsal') return { ok: false, code: 'use_manual_setup', credentialId: null };

    if (c.reusable) {
      return {
        ok: true,
        credentialId: c.reusable.id,
        source: 'temporary',
        fetchRef: {
          backend: c.backend,
          backendServerId: c.backendServerId,
          backendShortId: c.reusable.backendShortId,
          subscriptionUrl: c.reusable.subscriptionUrl,
        },
        subscriptionToken: c.reusable.backendShortId,
        reused: true,
      };
    }

    const username = testCredentialUsername(c.slug, purpose, randomHex(4));
    const id = await ctx.runMutation(internal.edgeTestCredentials.insertPending, {
      relayId,
      backendServerId: c.backendServerId,
      username,
      purpose,
    });
    let issued;
    try {
      issued = await ctx.runAction(internal.backends.issueUser, {
        backend: c.backend,
        pinServerId: c.backendServerId,
        spec: {
          username,
          trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
          expireAt: null,
          tag: TEST_CREDENTIAL_TAG,
          description: 'FCP test link (automated, temporary)',
        },
      });
    } catch (err) {
      // A typed refusal proves nothing was created; anything else may have
      // landed on the server, so the obligation stays for the sweep.
      if (err instanceof ConvexError)
        await ctx.runMutation(internal.edgeTestCredentials.dropUnissued, { id });
      throw err;
    }
    await ctx.runMutation(internal.edgeTestCredentials.markIssued, {
      id,
      backendUserId: issued.backendUserId,
      backendShortId: issued.backendShortId,
      subscriptionUrl: issued.subscriptionUrl,
    });
    return {
      ok: true,
      credentialId: id,
      source: 'temporary',
      fetchRef: {
        backend: c.backend,
        backendServerId: c.backendServerId,
        backendShortId: issued.backendShortId,
        subscriptionUrl: issued.subscriptionUrl,
      },
      subscriptionToken: issued.backendShortId,
      reused: false,
    };
  },
});

// --- the sweep ------------------------------------------------------------------------------

export const due = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    // Rows in backoff sit at the head of the index (they expired first), so one
    // `take` could return the same not-yet-due rows forever and starve every
    // later expired key. Walk pages until a batch of DUE rows is collected
    // (bounded: SWEEP_PAGES pages per tick).
    const pending: Doc<'edgeTestCredentials'>[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < SWEEP_PAGES && pending.length < SWEEP_BATCH; page++) {
      const res = await ctx.db
        .query('edgeTestCredentials')
        .withIndex('by_removal_expires', (q) => q.eq('removal', 'pending').lte('expiresAt', now))
        .paginate({ cursor, numItems: SWEEP_BATCH });
      for (const r of res.page) {
        if ((r.retryAfter ?? 0) <= now) pending.push(r);
        if (pending.length >= SWEEP_BATCH) break;
      }
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    const done = await ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_removal_expires', (q) =>
        q.eq('removal', 'done').lte('expiresAt', now - DONE_RETENTION_MS),
      )
      .take(SWEEP_BATCH);
    return { pending, doneIds: done.map((r) => r._id) };
  },
});

function backoffMs(attempts: number): number {
  return Math.min(5 * 60_000 * 2 ** Math.max(0, attempts - 1), 6 * 60 * 60_000);
}

export const settleRemoval = internalMutation({
  args: { id: v.id('edgeTestCredentials'), removed: v.boolean() },
  handler: async (ctx, { id, removed }) => {
    const row = await ctx.db.get(id);
    if (!row || row.removal !== 'pending') return null;
    const now = Date.now();
    const owner = await ownerOf(ctx, row);
    const relaySlug = owner.label;
    if (removed) {
      await ctx.db.patch(id, { removal: 'done', retryAfter: undefined, updatedAt: now });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.test_credential',
        targetType: owner.targetType,
        targetId: owner.targetId,
        payload: { relaySlug, purpose: row.purpose, removed: true, attempts: row.attempts + 1 },
      });
      return null;
    }
    const attempts = row.attempts + 1;
    if (attempts >= TEST_CREDENTIAL_MAX_ATTEMPTS) {
      await ctx.db.patch(id, {
        removal: 'failed',
        attempts,
        retryAfter: undefined,
        updatedAt: now,
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.test_credential',
        targetType: owner.targetType,
        targetId: owner.targetId,
        payload: { relaySlug, purpose: row.purpose, failed: true, attempts },
      });
      return null;
    }
    await ctx.db.patch(id, { attempts, retryAfter: now + backoffMs(attempts), updatedAt: now });
    return null;
  },
});

/** Operator retry after a `failed` row (the attention item's action). */
export const retryCleanup = internalMutation({
  args: { id: v.id('edgeTestCredentials') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (!row || row.removal !== 'failed') return null;
    await ctx.db.patch(id, {
      removal: 'pending',
      attempts: 0,
      retryAfter: undefined,
      updatedAt: Date.now(),
    });
    return null;
  },
});

export const dropRows = internalMutation({
  args: { ids: v.array(v.id('edgeTestCredentials')) },
  handler: async (ctx, { ids }) => {
    for (const id of ids) if (await ctx.db.get(id)) await ctx.db.delete(id);
    return null;
  },
});

/** `failed` rows (the attention query reads these). */
export const listFailed = internalQuery({
  args: {},
  handler: (ctx) =>
    ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_removal_expires', (q) => q.eq('removal', 'failed'))
      .take(SWEEP_BATCH),
});

export type TestCredentialRow = Doc<'edgeTestCredentials'>;

export interface SweepReport {
  removed: number;
  retried: number;
  failed: number;
  dropped: number;
}

/**
 * Reconcile-driven: remove every expired or released temporary key. A row
 * whose issuance was never observed (no `backendUserId`) cannot be settled
 * without a name lookup: it counts as a failed attempt each sweep and ends
 * `failed` (the operator checks the server), never silently `done`.
 */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<SweepReport> => {
    const report: SweepReport = { removed: 0, retried: 0, failed: 0, dropped: 0 };
    const now = Date.now();
    const { pending, doneIds } = await ctx.runQuery(internal.edgeTestCredentials.due, { now });
    for (const row of pending) {
      let removed = false;
      if (row.backendUserId) {
        try {
          await ctx.runAction(internal.backends.deleteUser, {
            backend: row.backend,
            backendUserId: row.backendUserId,
            backendServerId: row.backendServerId,
          });
          removed = true;
        } catch {
          console.warn('[edgeTestCredentials] could not remove a temporary test key');
        }
      }
      await ctx.runMutation(internal.edgeTestCredentials.settleRemoval, { id: row._id, removed });
      if (removed) report.removed++;
      else if (row.attempts + 1 >= TEST_CREDENTIAL_MAX_ATTEMPTS) report.failed++;
      else report.retried++;
    }
    if (doneIds.length > 0) {
      await ctx.runMutation(internal.edgeTestCredentials.dropRows, { ids: doneIds });
      report.dropped = doneIds.length;
    }
    return report;
  },
});
