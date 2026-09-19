/**
 * The qualification BINDING as the front check sees it.
 *
 * A qualification is only evidence for the configuration it ran against, so the
 * publishing mutation re-derives the binding from the live rows and refuses when
 * it no longer matches. The derivation itself lives in `lib/edges/intent.ts`
 * (the rotation machine freezes the intent there and re-derives the binding
 * inside `applyPublish`); this module adds only the transport-parameter shape
 * the checker actually sends on the wire, and re-exports the rest so a reader
 * of the front check never has to guess which hash rule is in force.
 *
 * Deliberately free of any Node import: the isolate mutations import it too.
 */
import {
  qualificationBinding as buildQualificationBinding,
  type BindingArgs,
  type QualificationBinding,
} from '../intent';

export type { QualificationBinding } from '../intent';
export {
  qualificationVerdict,
  qualificationCurrent,
  qualificationRefusal,
  type QualificationVerdict,
  type StoredQualification,
} from '../intent';

/**
 * How the inbound behind the slot is addressed over its HTTP transport, as the
 * node role declares it (`relayListeners.transportParams`). Each transport uses a
 * different subset: `ws` and `httpupgrade` need the path (and the upgrade
 * token), `grpc` needs the service name, `xhttp` the path and its mode. Absent
 * is distinct from empty.
 */
export interface TransportParams {
  path?: string | null;
  host?: string | null;
  serviceName?: string | null;
  upgradeToken?: string | null;
  mode?: string | null;
}

/**
 * Normalize to `string | null` before the binding hashes them: JSON.stringify
 * drops `undefined` keys, which would make "absent path" and "absent host"
 * hash alike.
 */
export function canonicalTransportParams(p: TransportParams): Record<string, string | null> {
  return {
    path: p.path ?? null,
    host: p.host ?? null,
    serviceName: p.serviceName ?? null,
    upgradeToken: p.upgradeToken ?? null,
    // Only when set: every binding hashed before XHTTP existed stays valid.
    ...(p.mode ? { mode: p.mode } : {}),
  };
}

/**
 * The binding for a front-qualification session. One entry point so the action,
 * the recording mutation and the publishing mutation cannot drift apart.
 */
export function qualificationBinding(
  args: Omit<BindingArgs, 'transportParams'> & { params: TransportParams },
): QualificationBinding {
  return buildQualificationBinding({
    listener: args.listener,
    intent: args.intent,
    transportParams: canonicalTransportParams(args.params),
  });
}

/**
 * Field-by-field equality. Never compare two bindings by their JSON: one side
 * has crossed a Convex validator, which does not promise key order.
 */
export function bindingsMatch(a: QualificationBinding, b: QualificationBinding): boolean {
  return (
    a.hostname === b.hostname &&
    a.listenerId === b.listenerId &&
    a.listenerRevision === b.listenerRevision &&
    a.protocol === b.protocol &&
    a.streamTransport === b.streamTransport &&
    a.security === b.security &&
    a.transportParamsHash === b.transportParamsHash &&
    a.intentHash === b.intentHash
  );
}
