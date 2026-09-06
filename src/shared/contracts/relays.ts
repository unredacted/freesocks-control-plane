/**
 * Relay-edge contracts (admin surface): the zod shapes the SPA parses. The
 * provider id enum derives from RELAY_PROVIDER_IDS so it can never drift from
 * the Convex validator. Route/response shapes are added alongside the routes.
 */
import { z } from 'zod';
import { RELAY_PROVIDER_IDS } from './relayProviderIds';

export { RELAY_PROVIDER_IDS, isRelayProviderId } from './relayProviderIds';
export type RelayProviderId = import('./relayProviderIds').RelayProviderId;
export const RelayProviderId = z.enum(RELAY_PROVIDER_IDS);
