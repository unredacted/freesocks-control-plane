/**
 * Pure helpers for an origin's PUBLISHED pool (`relays.publishedEdgeIds`,
 * ordered by pool index, nulls are gaps). Generic over the id type so the
 * `Id<'edges'>` brand survives a round trip.
 */

export function nextFreePoolIndex(
  published: readonly (string | null)[],
  desired: number,
): number | null {
  for (let i = 0; i < Math.max(desired, published.length); i++) {
    if (i < desired && (published[i] === null || published[i] === undefined)) return i;
  }
  return null;
}

export function withEdgeAt<T extends string>(
  published: readonly (T | null)[],
  index: number,
  edgeId: T,
): (T | null)[] {
  const out: (T | null)[] = [...published];
  while (out.length <= index) out.push(null);
  out[index] = edgeId;
  return out;
}

export function withoutEdge<T extends string>(
  published: readonly (T | null)[],
  edgeId: T,
): (T | null)[] {
  const out = published.map((e) => (e === edgeId ? null : e));
  // Trim trailing gaps so `publishedCount` and indexes stay tidy.
  while (out.length > 0 && out[out.length - 1] === null) out.pop();
  return out;
}

export function publishedCount(published: readonly (string | null)[]): number {
  return published.filter((e) => e !== null).length;
}

export function poolIndexOf(published: readonly (string | null)[], edgeId: string): number | null {
  const i = published.indexOf(edgeId);
  return i >= 0 ? i : null;
}
