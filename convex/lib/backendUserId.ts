/**
 * The stored form of a backend user id vs. the form the provider speaks.
 *
 * `subscriptions.backendUserId` is resolved through the `by_backend_user_id`
 * index with `.unique()` (key → instance, tombstones, admin ops), so it MUST be
 * globally unique across every instance of every backend type. Remnawave 2.x
 * handed out UUIDs (unique by construction); Remnawave 3.x dropped the user
 * uuid and addresses users by a per-panel numeric `id` — and Outline's key ids
 * are per-server small integers too. Two panels both mint user `2`.
 *
 * So a NUMERIC provider id is stored scoped to its instance:
 * `<backendServerId>:<id>` (a Convex document id never contains `:`). Anything
 * else (a UUID, `mock-…`) is stored verbatim. The dispatch in convex/backends.ts
 * is the ONLY place that converts: `toStoredBackendUserId` right after a
 * provider `issue`, `toProviderUserId` right before every provider call. Every
 * other consumer (subscription rows, audit payloads, the admin UI, the tombstone
 * sweep) only ever sees the stored form and never needs to know.
 *
 * The provider itself infers the panel contract from the RAW id's shape (UUID →
 * 2.x body/param names, integer → 3.x), so a mixed fleet keeps working while
 * panels are upgraded one at a time (see convex/lib/backends/remnawave.ts).
 */

const NUMERIC_ID = /^\d+$/;
const SCOPED_ID = /^[^:]+:(\d+)$/;

/** True for a bare provider id that is a per-instance integer (needs scoping). */
export function isNumericBackendUserId(rawId: string): boolean {
  return NUMERIC_ID.test(rawId);
}

/** Provider id → the globally-unique stored form. */
export function toStoredBackendUserId(backendServerId: string, rawId: string): string {
  return isNumericBackendUserId(rawId) ? `${backendServerId}:${rawId}` : rawId;
}

/** Stored form → the id the provider speaks (strips the instance scope). */
export function toProviderUserId(storedId: string): string {
  const m = SCOPED_ID.exec(storedId);
  return m ? m[1]! : storedId;
}

/**
 * The instance a scoped id belongs to, or null for an unscoped (globally
 * unique) id. A scoped id is only meaningful on ITS instance: probing another
 * panel with the bare integer would "find" an unrelated user, so the fleet
 * locate/repair path must never try.
 */
export function scopedServerId(storedId: string): string | null {
  const m = /^([^:]+):\d+$/.exec(storedId);
  return m ? m[1]! : null;
}
