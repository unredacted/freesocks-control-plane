/**
 * Convex-side derivations of the relay-provider id set (the backendIds.ts
 * pattern): every schema field and function arg that names a relay provider
 * uses `relayProviderIdValidator` instead of a hand-copied union.
 */
import { v } from 'convex/values';
import { RELAY_PROVIDER_IDS, isRelayProviderId } from '../../src/shared/contracts/relayProviderIds';
import type { RelayProviderId } from '../../src/shared/contracts/relayProviderIds';

export { RELAY_PROVIDER_IDS, isRelayProviderId };
export type { RelayProviderId };

export const relayProviderIdValidator = v.union(...RELAY_PROVIDER_IDS.map((id) => v.literal(id)));
