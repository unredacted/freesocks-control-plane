/**
 * Convex-side derivations of the backend-type id set. Every schema field and
 * function arg that names a backend type uses `backendIdValidator` instead of a
 * hand-copied `v.union(v.literal(...))` — adding a backend id in
 * src/shared/contracts/backendIds.ts updates them all at once.
 */
import { v } from 'convex/values';
import { BACKEND_IDS, isBackendId } from '../../src/shared/contracts/backendIds';
import type { BackendId } from '../../src/shared/contracts/backendIds';

export { BACKEND_IDS, isBackendId };
export type { BackendId };

// Spreading the mapped tuple keeps the inferred VALUE type at the literal
// union ('remnawave' | 'outline' | ...), not string — only the tuple precision
// of the member LIST degrades, which nothing relies on.
export const backendIdValidator = v.union(...BACKEND_IDS.map((id) => v.literal(id)));
