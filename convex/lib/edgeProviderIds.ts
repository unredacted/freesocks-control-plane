/**
 * Convex-side derivations of the relay-provider id set (the backendIds.ts
 * pattern): every schema field and function arg that names a relay provider
 * uses `edgeProviderIdValidator` instead of a hand-copied union.
 */
import { v } from 'convex/values';
import { EDGE_PROVIDER_IDS, isRelayProviderId } from '../../src/shared/contracts/edgeProviderIds';
import type { EdgeProviderId } from '../../src/shared/contracts/edgeProviderIds';

export { EDGE_PROVIDER_IDS, isRelayProviderId };
export type { EdgeProviderId };

export const edgeProviderIdValidator = v.union(...EDGE_PROVIDER_IDS.map((id) => v.literal(id)));
