/**
 * The one way to hand a listener to the endpoint-verification functions
 * (lib/edges/verification.ts): with the REALITY authentication revision of the
 * enrolled node behind its origin (`panelNodeIntents.authRevision`), or null
 * for any other origin (an unmanaged backend node, a whole backend server, a
 * manual or Outline origin) and for an enrolled node with none derived yet.
 *
 * Every place that builds a binding or judges a record goes through here, so
 * a confirmation, the publication gate, the setup run and the approval all
 * fold in the same value.
 */
import type { DatabaseReader } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import type { VerificationListenerLike } from './verification';

type Listener = Doc<'relayListeners'>;
export type VerifiableListener = Listener & Pick<VerificationListenerLike, 'authRevision'>;

/** Per-call memo: origin id -> auth revision (one intent read per origin). */
export type AuthRevisionCache = Map<string, string | null>;

/** The auth revision of the enrolled node behind an origin, or null. */
export async function originAuthRevision(
  db: DatabaseReader,
  relay: Pick<Doc<'relays'>, '_id' | 'origin' | 'backendServerId'> | null,
  cache?: AuthRevisionCache,
): Promise<string | null> {
  if (!relay) return null;
  const key = relay._id as string;
  const hit = cache?.get(key);
  if (hit !== undefined) return hit;
  let auth: string | null = null;
  if (relay.origin.kind === 'panel-node' && relay.backendServerId) {
    const sid = relay.backendServerId;
    const nodeName = relay.origin.nodeName;
    const intent = await db
      .query('panelNodeIntents')
      .withIndex('by_server_name', (q) => q.eq('backendServerId', sid).eq('name', nodeName))
      .unique();
    auth = intent?.authRevision ?? null;
  }
  cache?.set(key, auth);
  return auth;
}

/** A listener ready for the verification functions (its origin's auth revision attached). */
export async function verificationListenerOf(
  db: DatabaseReader,
  listener: Listener,
  cache?: AuthRevisionCache,
): Promise<VerifiableListener> {
  const relay = await db.get(listener.relayId as Id<'relays'>);
  return { ...listener, authRevision: await originAuthRevision(db, relay, cache) };
}

/** The same, for every listener of one origin (one intent read). */
export async function verificationListenersOf(
  db: DatabaseReader,
  relay: Pick<Doc<'relays'>, '_id' | 'origin' | 'backendServerId'>,
  listeners: readonly Listener[],
): Promise<VerifiableListener[]> {
  const authRevision = await originAuthRevision(db, relay);
  return listeners.map((l) => ({ ...l, authRevision }));
}
