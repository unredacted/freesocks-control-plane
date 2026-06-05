/**
 * Issues, mirrors, refreshes, and tombstones subscriptions. The proxy backend
 * (Remnawave, Outline, …) is selected per-request via the BackendRegistry,
 * keyed off the `backend` discriminator column on `tiers` / `subscriptions`.
 *
 * Callers pass a generic `IssueSubscriptionInput` with the desired backend and
 * a backend-agnostic `IssueUserSpec`; the underlying provider translates that
 * into its native shape.
 *
 * The DB columns `backend_user_id` / `backend_short_id` hold whatever id the
 * underlying provider returned — they were renamed from `remnawave_*` in
 * migration 0004 to reflect their backend-agnostic role.
 */
import { and, eq, isNotNull, lte } from 'drizzle-orm';
import type { Db } from '../db/client';
import { subscriptions } from '../db/schema';
import type { Logger } from '../lib/logger';
import { sha256Hex } from '../lib/crypto';
import { parseMirrors } from '../lib/mirrors';
import type { PlatformConfig } from '../platform/interface';
import type {
  BackendId,
  IssueUserSpec,
  ProxyBackendProvider,
  UpdateUserPatch,
} from '../providers/backend';
import type { StorageProvider, UploadResult } from '../providers/storage/interface';
import type { AuditService } from './audit';
import type { BackendRegistry } from './backend-registry';

interface Deps {
  backends: BackendRegistry;
  storage: StorageProvider;
  /**
   * Audit service for surfacing partial S3-mirror outcomes as durable
   * rows in `audit_log`. A warn-level log alone wasn't enough — the
   * "we have N mirrors" UX contract becomes false silently when uploads
   * fail to a subset of configured providers; landing a row in audit_log
   * makes the partial state queryable by admins from the CMS.
   */
  audit: AuditService;
  db: Db;
  logger: Logger;
  config: PlatformConfig;
}

export interface IssueSubscriptionInput {
  userId: number;
  backend: BackendId;
  spec: IssueUserSpec;
}

export interface SubscriptionRecord {
  id: number;
  userId: number;
  backend: BackendId;
  /** Provider's primary id (Remnawave uuid, Outline access-key id). */
  backendUserId: string;
  /** Provider's short id used for subscription content lookup. */
  backendShortId: string;
  subscriptionUrl: string;
  mirrors: { provider: string; publicUrl: string; objectPath: string }[];
}

export class SubscriptionDeliveryService {
  constructor(private readonly deps: Deps) {}

  async issueNew(input: IssueSubscriptionInput): Promise<SubscriptionRecord> {
    const provider = this.deps.backends.get(input.backend);
    const issued = await provider.issueUser(input.spec);
    try {
      const mirrors = await this.mirrorSubscription(provider, issued.backendShortId);
      const inserted = await this.deps.db
        .insert(subscriptions)
        .values({
          userId: input.userId,
          backend: input.backend,
          backendUserId: issued.backendUserId,
          backendShortId: issued.backendShortId,
          outlineServerId: issued.outlineServerId ?? null,
          subscriptionUrl: issued.subscriptionUrl,
          subscriptionMirrors: JSON.stringify(mirrors),
          rawContentHash: mirrors[0]?.contentHash ?? null,
          state: 'active',
        })
        .returning();
      const row = inserted[0];
      if (!row) throw new Error('subscription insert returned no row');
      return {
        id: row.id,
        userId: row.userId,
        backend: input.backend,
        backendUserId: row.backendUserId,
        backendShortId: row.backendShortId,
        subscriptionUrl: row.subscriptionUrl,
        mirrors: mirrors.map(({ provider: p, publicUrl, objectPath }) => ({
          provider: p,
          publicUrl,
          objectPath,
        })),
      };
    } catch (err) {
      this.deps.logger.warn('subscription_post_create_cleanup', {
        backend: input.backend,
        backendUserId: issued.backendUserId,
        error: String(err),
      });
      try {
        await provider.deleteUser(issued.backendUserId);
      } catch (cleanupErr) {
        this.deps.logger.error('subscription_cleanup_failed', {
          backend: input.backend,
          backendUserId: issued.backendUserId,
          error: String(cleanupErr),
        });
      }
      throw err;
    }
  }

  async refreshMirrors(backend: BackendId, backendShortId: string): Promise<UploadResult[]> {
    const provider = this.deps.backends.get(backend);
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.backendShortId, backendShortId))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub) throw new Error('subscription not found');
    const mirrors = await this.mirrorSubscription(provider, sub.backendShortId);
    await this.deps.db
      .update(subscriptions)
      .set({
        subscriptionMirrors: JSON.stringify(mirrors),
        rawContentHash: mirrors[0]?.contentHash ?? null,
        updatedAt: Date.now(),
      })
      .where(eq(subscriptions.id, sub.id));
    return mirrors.map((m) => ({
      provider: m.provider,
      publicUrl: m.publicUrl,
      objectPath: m.objectPath,
    }));
  }

  async patchUser(
    backend: BackendId,
    backendUserId: string,
    patch: UpdateUserPatch,
  ): Promise<void> {
    await this.deps.backends.get(backend).updateUser(backendUserId, patch);
  }

  async deleteSubscription(backend: BackendId, backendUserId: string): Promise<void> {
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.backendUserId, backendUserId))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (sub) {
      const mirrors = parseMirrors(sub.subscriptionMirrors, this.deps.logger, {
        subscriptionId: sub.id,
      })
        // Only delete entries that actually have an objectPath (writers
        // always set it, but parseMirrors makes it optional for forward
        // compat). Without an objectPath there's nothing to address on
        // the storage provider — silently skip rather than throw.
        .filter((m): m is typeof m & { objectPath: string } => typeof m.objectPath === 'string');
      await this.deps.storage.deleteFromAll(mirrors);
      await this.deps.db
        .update(subscriptions)
        .set({ state: 'deleted', deletedAt: Date.now(), updatedAt: Date.now() })
        .where(eq(subscriptions.id, sub.id));
    }
    try {
      await this.deps.backends.get(backend).deleteUser(backendUserId);
    } catch (err) {
      this.deps.logger.warn('backend_delete_user_failed', {
        backend,
        backendUserId,
        error: String(err),
      });
    }
  }

  /**
   * Soft-delete a subscription with a grace window. The DB row is moved to
   * `state='disabled'` with `deletedAt = now + graceMs` (the wall-clock time
   * at which it should be hard-deleted), and the **backend user is left
   * alive** so the existing URL keeps working through the grace window.
   *
   * The `sweepGracePeriodTombstones` method walks tombstoned rows whose
   * deletion timestamp has passed and calls `deleteUser` on each, removing
   * them from the backend and flipping the row to `state='deleted'`. That
   * sweep runs from cron alongside `cleanup-expired-free`.
   *
   * Used by:
   *   - `/api/v1/account/regenerate` — old subscription tombstoned, new one
   *     issued; the user's existing devices keep working for 24h while they
   *     re-import.
   *   - `/api/v1/account/switch-backend` — same shape but the new
   *     subscription is on a different backend.
   */
  async tombstoneWithGrace(
    backend: BackendId,
    backendUserId: string,
    graceMs: number,
  ): Promise<{ deletedAt: number } | null> {
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.backendUserId, backendUserId))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub) {
      // Caller is asking us to tombstone something we have no record of.
      // Surface as a debug log — not throwing because the caller is usually
      // a regenerate/switch flow that doesn't strictly need this to succeed
      // (the new subscription is already issued and that's the load-bearing
      // success). A future reconcile will catch any backend-side orphan.
      this.deps.logger.debug('tombstone_no_row', { backend, backendUserId });
      return null;
    }
    // Only tombstone an active sub. If the row is already in `disabled` (an
    // earlier tombstone is mid-grace) or `deleted` (sweep already ran),
    // re-tombstoning would reset the grace clock to "now + 24h", which is
    // how a second regenerate call could end up extending the wrong row's
    // life. Return the existing deletedAt so the caller still has a
    // meaningful timestamp to show the user.
    if (sub.state !== 'active') {
      this.deps.logger.debug('tombstone_already_tombstoned', {
        backend,
        backendUserId,
        state: sub.state,
      });
      return sub.deletedAt !== null ? { deletedAt: sub.deletedAt } : null;
    }
    const deletedAt = Date.now() + graceMs;
    await this.deps.db
      .update(subscriptions)
      .set({ state: 'disabled', deletedAt, updatedAt: Date.now() })
      .where(eq(subscriptions.id, sub.id));
    return { deletedAt };
  }

  /**
   * Run from cron. For each tombstoned subscription whose `deletedAt` has
   * passed, hard-delete the backend user, drop the S3 mirrors, and flip the
   * row to `state='deleted'`. Bounded to `limit` rows per call so a backlog
   * doesn't run away with a single cron invocation.
   */
  async sweepGracePeriodTombstones(limit = 100): Promise<{ swept: number; failed: number }> {
    const now = Date.now();
    // Push the whole predicate into SQL (state + deletedAt set + due) so we
    // fetch exactly the ripe rows instead of over-fetching and filtering in JS.
    const ripe = await this.deps.db
      .select()
      .from(subscriptions)
      .where(
        and(
          eq(subscriptions.state, 'disabled'),
          isNotNull(subscriptions.deletedAt),
          lte(subscriptions.deletedAt, now),
        ),
      )
      .limit(limit)
      .all();
    let swept = 0;
    let failed = 0;
    for (const sub of ripe) {
      try {
        const mirrors = parseMirrors(sub.subscriptionMirrors, this.deps.logger, {
          subscriptionId: sub.id,
        }).filter((m): m is typeof m & { objectPath: string } => typeof m.objectPath === 'string');
        await this.deps.storage.deleteFromAll(mirrors);
        try {
          await this.deps.backends.get(sub.backend).deleteUser(sub.backendUserId);
        } catch (err) {
          // Backend may already have deleted the user (admin, prior partial
          // sweep, etc.). Log + continue so we still mark the row deleted.
          this.deps.logger.warn('grace_sweep_backend_delete_failed', {
            subId: sub.id,
            backend: sub.backend,
            error: String(err),
          });
        }
        await this.deps.db
          .update(subscriptions)
          .set({ state: 'deleted', updatedAt: Date.now() })
          .where(eq(subscriptions.id, sub.id));
        swept++;
      } catch (err) {
        failed++;
        this.deps.logger.error('grace_sweep_failed', { subId: sub.id, error: String(err) });
      }
    }
    return { swept, failed };
  }

  private async mirrorSubscription(
    provider: ProxyBackendProvider,
    backendShortId: string,
  ): Promise<(UploadResult & { contentHash: string; status: 'ok' })[]> {
    if (!this.deps.config.S3_MIRRORS_ENABLED || this.deps.storage.providers.length === 0) {
      return [];
    }
    const fetched = await provider.fetchSubscriptionContent(backendShortId);
    const contentHash = await sha256Hex(fetched.content);
    const objectPath = `subs/${backendShortId}/${contentHash.slice(0, 12)}`;
    const configured = this.deps.storage.providers.length;
    const uploaded = await this.deps.storage.uploadToAll(
      objectPath,
      fetched.content,
      fetched.contentType,
    );
    // Partial-upload surfacing. The user-facing claim is "N mirrors for
    // censorship resistance" — when uploads fail to a subset, that
    // promise is silently broken. The storage layer already logs a
    // `s3_partial_upload_failures` warn for ops; we additionally write
    // a durable audit row so admins can see partial mirrors from the CMS
    // and the support team can correlate user reports.
    if (uploaded.length < configured) {
      const uploadedProviders = new Set(uploaded.map((u) => u.provider));
      const missing = this.deps.storage.providers
        .map((p) => p.name)
        .filter((name) => !uploadedProviders.has(name));
      await this.deps.audit.record({
        actorType: 'system',
        action: 'subscription.mirror.partial',
        targetType: 'subscription',
        targetId: backendShortId,
        payload: {
          configured,
          uploaded: uploaded.length,
          missingProviders: missing,
        },
      });
    }
    // Tag each persisted mirror with `status: 'ok'` so future readers can
    // distinguish entries known-good from entries-with-no-status (older
    // rows). The schema in `lib/mirrors.ts` accepts the field as optional.
    return uploaded.map((u) => ({ ...u, contentHash, status: 'ok' as const }));
  }
}
