/**
 * A first name for an L4 address that has none (pure; unit-tested).
 *
 * An address planned before "Names for load balancer addresses" was on keeps
 * its IPs (docs/edges.md "Names for load balancer addresses"). Its drawer
 * offers **Give it a name**, the same call as New name. The server makes a
 * name only for an active address FCP owns that has an IPv4, and refuses
 * (`edge.names_off`) while the switch is off or no chosen zone can take one.
 *
 * Exports:
 *   firstNameOffer(edge, name, config)   what the drawer says of an address with no name, or null
 *   FIRST_NAME_WORDS                     the line for each outcome but `offer`
 */
import type {
  EdgeAddressName,
  EdgeAdmin,
  EdgeConfigView,
} from '../../../../../shared/contracts/edges';

/**
 * `offer`: the button. `names_off` / `no_zone`: why there is none. `refused`:
 * the server said no although the settings looked on (a chosen zone's
 * location or DNS account is switched off).
 */
export type FirstNameOffer = 'offer' | 'names_off' | 'no_zone' | 'refused';

/**
 * Null: no section (the address has a name, or takes none). `config` null: the
 * settings could not be read, so the button shows and the server decides.
 */
export function firstNameOffer(
  edge: Pick<EdgeAdmin, 'layer' | 'managed' | 'status' | 'addresses'>,
  name: EdgeAddressName | null,
  config: Pick<EdgeConfigView, 'config' | 'nameZones'> | null,
): Exclude<FirstNameOffer, 'refused'> | null {
  if (name) return null;
  if (edge.layer !== 'l4' || !edge.managed || edge.status !== 'active' || !edge.addresses.v4)
    return null;
  if (!config) return 'offer';
  const names = config.config.names;
  if (!names.enabled) return 'names_off';
  // A chosen zone that is no longer a DNS account's zone takes nothing.
  const zones = new Set(config.nameZones.map((z) => z.id));
  return names.zones.some((id) => zones.has(id)) ? 'offer' : 'no_zone';
}

export const FIRST_NAME_WORDS: Record<Exclude<FirstNameOffer, 'offer'>, string> = {
  names_off: 'Names for load balancer addresses are off. Turn them on in Settings to give it one.',
  no_zone: 'No zone is chosen for names. Pick one in Settings to give it one.',
  refused:
    'No chosen zone can take a name now. Check that its location and DNS account are switched on.',
};
