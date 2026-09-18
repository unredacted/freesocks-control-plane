/**
 * Convex-side derivations of the listener catalogue (the edgeProviderIds.ts
 * pattern): every schema field and function arg that names a listener
 * protocol / stream transport / security uses these validators instead of a
 * hand-copied union.
 */
import { v } from 'convex/values';
import {
  LISTENER_PROTOCOL_IDS,
  LISTENER_SECURITY_IDS,
  LISTENER_STREAM_TRANSPORT_IDS,
} from '../../src/shared/contracts/edgeProtocolIds';

export const listenerProtocolValidator = v.union(
  ...LISTENER_PROTOCOL_IDS.map((id) => v.literal(id)),
);
export const listenerStreamTransportValidator = v.union(
  ...LISTENER_STREAM_TRANSPORT_IDS.map((id) => v.literal(id)),
);
export const listenerSecurityValidator = v.union(
  ...LISTENER_SECURITY_IDS.map((id) => v.literal(id)),
);

/** The three-field listener identity, for args and nested objects. */
export const listenerProtoFields = {
  protocol: listenerProtocolValidator,
  streamTransport: listenerStreamTransportValidator,
  security: listenerSecurityValidator,
};
