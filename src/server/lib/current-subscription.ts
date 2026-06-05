import { and, desc, eq } from 'drizzle-orm';
import { subscriptions } from '../db/schema';
import type { Db } from '../db/client';

type SubscriptionRow = typeof subscriptions.$inferSelect;

/**
 * Resolve a user's current ACTIVE subscription, consistently across endpoints.
 *
 * Prefers the canonical `users.currentSubscriptionId` pointer (kept current by
 * regenerate / switch-backend / tier propagation); falls back to the newest
 * active row (deterministic `ORDER BY id DESC`) for legacy rows / corruption
 * recovery. Tombstoned (`state !== 'active'`) rows are never returned, so
 * callers never render a stale URL during the 24h grace window after a
 * regenerate/switch-backend. `/api/v1/account` and `/api/v1/subscription` both
 * use this so they can't diverge.
 */
export async function resolveActiveSubscription(
  db: Db,
  user: { id: number; currentSubscriptionId: number | null },
): Promise<SubscriptionRow | undefined> {
  if (user.currentSubscriptionId) {
    const rows = await db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.id, user.currentSubscriptionId))
      .limit(1)
      .all();
    if (rows[0]?.state === 'active') return rows[0];
  }
  const rows = await db
    .select()
    .from(subscriptions)
    .where(and(eq(subscriptions.userId, user.id), eq(subscriptions.state, 'active')))
    .orderBy(desc(subscriptions.id))
    .limit(1)
    .all();
  return rows[0];
}
