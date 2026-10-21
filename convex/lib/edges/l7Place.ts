/**
 * Where an L7 edge planned in a location lives, and whether a new one can be
 * planned there (docs/edges.md § "Provider accounts and locations"): the
 * location's zone, the DNS account its records go through and its TLS
 * configuration, with the zone facts its last check observed. Shared by the
 * setup plan, selection and the provider-set reads, so all three judge a
 * zone the same way. Reads the database, no provider call.
 */
import type { Doc, Id } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';
import { intentPlaceOf, parseObservedSettings, type IntentPlace } from './intent';
import {
  EDGE_PROVIDER_CAPABILITIES,
  edgeLayerOf,
  zoneModeGovernsOrigin,
} from './providers/capabilities';

type Account = Doc<'edgeProviderAccounts'>;
type Location = Doc<'edgeLocations'>;

/**
 * Where an L7 edge planned in this location lives: the location's zone, DNS
 * account and TLS configuration, with the zone facts its last check observed.
 * An account the L7 locations migration has not moved yet still names its zone
 * (or its DNS account, whose settings name the zone) in its own settings: that
 * legacy shape is read as the fallback until the cleanup removes it.
 */
export async function l7PlaceOf(
  db: DatabaseReader,
  account: Pick<Account, 'settings' | 'observedSettings'>,
  location: Pick<Location, 'placement' | 'observed'> | null,
): Promise<IntentPlace> {
  const place = location ? intentPlaceOf(location.placement, location.observed) : {};
  if (place.zoneId) return place;
  const legacy = account.settings as {
    zoneId?: string;
    zoneName?: string;
    dnsAccountId?: string;
    tlsConfigurationId?: string;
  };
  if (legacy.zoneId)
    return {
      zoneId: legacy.zoneId,
      zoneName: legacy.zoneName,
      observed: parseObservedSettings(account.observedSettings),
    };
  if (legacy.dnsAccountId) {
    const dns = await db.get(legacy.dnsAccountId as Id<'edgeProviderAccounts'>);
    const zone = dns?.settings as { zoneId?: string; zoneName?: string } | undefined;
    return {
      dnsAccountId: legacy.dnsAccountId,
      ...(zone?.zoneId ? { zoneId: zone.zoneId, zoneName: zone.zoneName } : {}),
      ...(legacy.tlsConfigurationId ? { tlsConfigurationId: legacy.tlsConfigurationId } : {}),
      // What the DNS account's own test read of that zone (its plan).
      observed: parseObservedSettings(dns?.observedSettings),
    };
  }
  return place;
}

/**
 * Why no new L7 edge can be planned in this location, or null: it names no
 * zone (`dns_zone_missing`), its last check refused the zone
 * (`location_check_failed`), the DNS account its records go through is gone or
 * switched off, or the zone's encryption mode was never observed for a front
 * that is the zone's own proxy (`zone_mode_unknown`). An L4 location has none.
 */
export async function l7PlaceProblemOf(
  db: DatabaseReader,
  account: Pick<Account, 'provider' | 'settings' | 'observedSettings'>,
  location: Pick<Location, 'placement' | 'observed' | 'checkError'>,
): Promise<string | null> {
  if (edgeLayerOf(account.provider) !== 'l7') return null;
  const place = await l7PlaceOf(db, account, location);
  if (!place.zoneId || !place.zoneName) return 'dns_zone_missing';
  if (location.checkError) return 'location_check_failed';
  if (EDGE_PROVIDER_CAPABILITIES[account.provider].needsDnsAccount) {
    const dns = place.dnsAccountId
      ? await db.get(place.dnsAccountId as Id<'edgeProviderAccounts'>)
      : null;
    if (!dns) return 'dns_account_missing';
    if (!dns.enabled) return 'dns_account_disabled';
  }
  if (zoneModeGovernsOrigin(account.provider) && !place.observed?.zoneSslMode)
    return 'zone_mode_unknown';
  return null;
}
