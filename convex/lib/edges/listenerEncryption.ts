/**
 * Whether a listener's transport runs VLESS Encryption, from what FCP last
 * observed of its backend (docs/backends.md "VLESS Encryption"). The
 * observation holds only what is public: the client string members' entries
 * carry, how the handshake looks and what the node is verified by.
 *
 * A listener is judged by the backend transport it is bound to
 * (`panelBinding`). A listener without one (a manual origin, an Outline
 * server), a backend never observed, and a transport the observation shows as
 * plain all answer null: plain as far as FCP can tell.
 */
import type { Doc } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';

/**
 * The Host remarks of a listener's encrypted twin (`relayListeners.encryptedTwin`):
 * the listener's own remarks with the twin's key in place of its own, so the
 * twin's Host is named like any Host of the node (`<node>-relay-<key>`: it pins
 * with the node, hides with it and is renamed with it) and follows the same
 * renames. The current one first. None for a listener without a twin, or one
 * not found by such a remark (an adopted or manual origin has no twin).
 */
export function twinRemarksOf(
  l: Pick<Doc<'relayListeners'>, 'listenerKey' | 'matchRule' | 'formerRemarks' | 'encryptedTwin'>,
): string[] {
  const twin = l.encryptedTwin;
  if (!twin || l.matchRule.kind !== 'remark') return [];
  const suffix = `-relay-${l.listenerKey}`;
  const out: string[] = [];
  for (const remark of [l.matchRule.remark, ...(l.formerRemarks ?? [])])
    if (remark.endsWith(suffix))
      out.push(`${remark.slice(0, remark.length - l.listenerKey.length)}${twin.key}`);
  return out;
}

export type ObservedVlessEncryption = NonNullable<
  Doc<'panelProfiles'>['inbounds'][number]['vlessEncryption']
>;

export async function listenerVlessEncryption(
  db: DatabaseReader,
  relay: Pick<Doc<'relays'>, 'backendServerId'>,
  listener: Pick<Doc<'relayListeners'>, 'panelBinding'>,
): Promise<ObservedVlessEncryption | null> {
  const bound = listener.panelBinding;
  if (!relay.backendServerId || !bound) return null;
  const profile = await db
    .query('panelProfiles')
    .withIndex('by_server_uuid', (q) =>
      q.eq('backendServerId', relay.backendServerId!).eq('profileUuid', bound.configProfileUuid),
    )
    .first();
  // The uuid is what the binding holds onto; the tag is the fallback for a row
  // observed before the backend had given the transport one.
  const inbound =
    profile?.inbounds.find((i) => i.inboundUuid === bound.configProfileInboundUuid) ??
    profile?.inbounds.find((i) => i.tag === bound.inboundTag);
  return inbound?.vlessEncryption ?? null;
}
