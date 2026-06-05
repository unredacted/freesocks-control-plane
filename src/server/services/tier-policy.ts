import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { appState, tiers } from '../db/schema';
import type { KvStore } from '../kv/interface';
import type { Logger } from '../lib/logger';

export type Tier = typeof tiers.$inferSelect;

const CACHE_KEY_ALL = 'tiers:all';
const CACHE_TTL_SEC = 300;
const PROPAGATION_PREFIX = 'tier_propagation_pending:';

export class TierPolicyService {
  constructor(
    private readonly db: Db,
    private readonly cache: KvStore,
    private readonly logger: Logger,
  ) {}

  async listAll(): Promise<Tier[]> {
    const cached = await this.cache.getJson<Tier[]>(CACHE_KEY_ALL);
    if (cached) return cached;
    const rows = await this.db.select().from(tiers).all();
    await this.cache.putJson(CACHE_KEY_ALL, rows, { expirationTtl: CACHE_TTL_SEC });
    return rows;
  }

  async invalidate(): Promise<void> {
    await this.cache.delete(CACHE_KEY_ALL);
  }

  /**
   * Returns the active default-free tier. When the dual-backend mode is in
   * play, callers can pass a `backend` filter so a free user requesting an
   * Outline key gets the Outline-backed default-free tier rather than the
   * Remnawave one. With no filter, the first active default-free tier wins
   * (callers that don't care about backend get backwards-compatible behavior).
   */
  async getDefaultFreeTier(backend?: 'remnawave' | 'outline'): Promise<Tier> {
    const all = await this.listAll();
    const free = all.find(
      (t) => t.isDefaultFree && t.isActive && (backend === undefined || t.backend === backend),
    );
    if (!free) {
      this.logger.error('no_default_free_tier', { backend: backend ?? 'any' });
      throw new Error(
        backend
          ? `No default free tier configured for backend "${backend}"`
          : 'No default free tier configured',
      );
    }
    return free;
  }

  async getById(id: number): Promise<Tier | null> {
    const all = await this.listAll();
    return all.find((t) => t.id === id) ?? null;
  }

  async getBySlug(slug: string): Promise<Tier | null> {
    const all = await this.listAll();
    return all.find((t) => t.slug === slug) ?? null;
  }

  async upsert(
    input: Omit<Tier, 'id' | 'createdAt' | 'updatedAt'> & { id?: number },
  ): Promise<Tier> {
    const now = Date.now();
    // Defense-in-depth: explicit allowlist of mutable columns. The caller
    // already passes Zod-validated data (so unknown keys are stripped at
    // parse time), but spreading the result directly into `.set(...)` would
    // happily write any field name that exists on the table — `createdAt`,
    // `id`, anything a future schema migration adds. Pinning the field list
    // here means future additions are opt-in, not opt-out.
    const mutable = {
      slug: input.slug,
      name: input.name,
      description: input.description,
      backend: input.backend,
      monthlyTrafficGb: input.monthlyTrafficGb,
      deviceLimit: input.deviceLimit,
      hwidLimit: input.hwidLimit,
      hwidEnabled: input.hwidEnabled,
      trafficStrategy: input.trafficStrategy,
      remnawaveSquadUuid: input.remnawaveSquadUuid,
      isDefaultFree: input.isDefaultFree,
      isActive: input.isActive,
      priority: input.priority,
      expirationDaysAfterMembershipLapse: input.expirationDaysAfterMembershipLapse,
    };
    if (input.id) {
      // Capture the BEFORE state so the propagation job knows what changed.
      // We're particularly interested in fields that affect Remnawave state:
      // monthlyTrafficGb, deviceLimit, hwidLimit, hwidEnabled, trafficStrategy,
      // remnawaveSquadUuid. Other fields (display name, description) don't
      // require propagation to existing users.
      const beforeRow = (
        await this.db.select().from(tiers).where(eq(tiers.id, input.id)).limit(1).all()
      )[0];

      await this.db
        .update(tiers)
        .set({ ...mutable, updatedAt: now })
        .where(eq(tiers.id, input.id));
      const row = await this.db.select().from(tiers).where(eq(tiers.id, input.id)).limit(1).all();
      await this.invalidate();
      if (!row[0]) throw new Error('Tier not found after update');

      // Queue tier propagation if a propagation-relevant field changed.
      if (beforeRow && this.affectsExistingUsers(beforeRow, row[0])) {
        await this.queuePropagation(input.id);
      }
      return row[0];
    }
    const inserted = await this.db
      .insert(tiers)
      .values({ ...mutable, createdAt: now, updatedAt: now })
      .returning();
    await this.invalidate();
    if (!inserted[0]) throw new Error('Tier insert returned no rows');
    return inserted[0];
  }

  /**
   * Returns true if the diff between two tier states should bulk-update
   * existing users on the backend. Used by `upsert` to decide whether to
   * queue a propagation job.
   *
   * `backend` is NOT propagated: changing a tier's backend mid-flight would
   * require migrating every user's subscription, which is a separate
   * admin-initiated workflow. Existing users keep their current backend
   * until they regenerate or switch explicitly.
   */
  private affectsExistingUsers(before: Tier, after: Tier): boolean {
    return (
      before.monthlyTrafficGb !== after.monthlyTrafficGb ||
      before.deviceLimit !== after.deviceLimit ||
      before.hwidLimit !== after.hwidLimit ||
      before.hwidEnabled !== after.hwidEnabled ||
      before.trafficStrategy !== after.trafficStrategy ||
      before.remnawaveSquadUuid !== after.remnawaveSquadUuid
    );
  }

  async queuePropagation(tierId: number): Promise<void> {
    const key = `${PROPAGATION_PREFIX}${tierId}`;
    const value = JSON.stringify({ tierId, queuedAt: Date.now(), startedAt: null, lastUserId: 0 });
    await this.db
      .insert(appState)
      .values({ key, value, updatedAt: Date.now() })
      .onConflictDoUpdate({ target: appState.key, set: { value, updatedAt: Date.now() } });
  }

  async listPendingPropagations(): Promise<
    { tierId: number; queuedAt: number; lastUserId: number }[]
  > {
    const rows = await this.db.select().from(appState).all();
    return rows
      .filter((r) => r.key.startsWith(PROPAGATION_PREFIX))
      .map((r) => {
        const v = JSON.parse(r.value) as {
          tierId: number;
          queuedAt: number;
          startedAt: number | null;
          lastUserId: number;
        };
        return { tierId: v.tierId, queuedAt: v.queuedAt, lastUserId: v.lastUserId };
      });
  }

  async setPropagationCursor(tierId: number, lastUserId: number): Promise<void> {
    const key = `${PROPAGATION_PREFIX}${tierId}`;
    const existing = (
      await this.db.select().from(appState).where(eq(appState.key, key)).limit(1).all()
    )[0];
    if (!existing) return;
    const v = JSON.parse(existing.value) as {
      tierId: number;
      queuedAt: number;
      startedAt: number | null;
      lastUserId: number;
    };
    v.lastUserId = lastUserId;
    if (!v.startedAt) v.startedAt = Date.now();
    await this.db
      .update(appState)
      .set({ value: JSON.stringify(v), updatedAt: Date.now() })
      .where(eq(appState.key, key));
  }

  async clearPropagation(tierId: number): Promise<void> {
    await this.db.delete(appState).where(eq(appState.key, `${PROPAGATION_PREFIX}${tierId}`));
  }

  async setActive(id: number, isActive: boolean): Promise<void> {
    await this.db.update(tiers).set({ isActive, updatedAt: Date.now() }).where(eq(tiers.id, id));
    await this.invalidate();
  }

  async byActiveOnly(): Promise<Tier[]> {
    const all = await this.listAll();
    return all.filter((t) => t.isActive);
  }
}
