/**
 * Pure helpers for edge LOCATIONS (docs/edges.md § "Provider accounts and
 * locations"). A location is one account's place to create edges in: a frozen
 * placement (region / zone / project / network) plus its `placeKey`, the
 * provider's own id for the region. Isolate-safe.
 *
 *  - `placeKeyOf`: the provider's region / zone id (`anycast` for a CDN, which
 *    has no place). Two accounts in the same region share address ranges, so
 *    the place is account-agnostic.
 *  - `locationKeyOf`: `<provider>:<placeKey>`, the identity per-country grades
 *    and the renderer's backup diversity are keyed on. Admin-only: never in a
 *    member body, an alert or an audit row's free text.
 *  - `placementHashOf`: the canonical identity of a placement, so creating the
 *    same location twice returns the existing row.
 *  - the regional overlay: a template field that differs per region (a load
 *    balancer flavor) is set on the location and laid over the template.
 */
import type { EdgeProviderId } from '../edgeProviderIds';
import { canonicalJson } from './providers/template';
import { EDGE_TEMPLATE_REGIONAL_FIELDS } from './providers/templates';
import type { EdgePlacement } from './accountSettings';

/** The place key of a provider that is not geographic (one location per account). */
export const ANYCAST_PLACE = 'anycast';

/** FNV-1a 64-bit as 16 hex chars (the same change detector `templateHashOf` uses). */
function fnv1a64Hex(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/** The provider's own id for where a placement puts its resources. */
export function placeKeyOf(placement: EdgePlacement): string {
  switch (placement.type) {
    case 'gcore':
      return String(placement.regionId);
    case 'upcloud':
    case 'scaleway':
      return placement.zone;
    case 'ovh':
      return placement.regionName;
    case 'cloudflare':
    case 'fastly':
    case 'cloudfront':
      return ANYCAST_PLACE;
  }
}

/** `<provider>:<placeKey>`: the account-agnostic identity of a place. */
export function locationKeyOf(provider: EdgeProviderId | string, placeKey: string): string {
  return `${provider}:${placeKey}`;
}

/** Canonical identity of a placement (key order never matters). */
export function placementHashOf(placement: EdgePlacement | Record<string, unknown>): string {
  return fnv1a64Hex(canonicalJson(placement));
}

/** Whether a provider has places at all (a CDN has exactly one, `anycast`). */
export function providerHasPlaces(placement: EdgePlacement): boolean {
  return placeKeyOf(placement) !== ANYCAST_PLACE;
}

/**
 * The regional template values a location sets: only the provider's regional
 * keys survive (anything else is dropped), and only non-empty strings.
 */
export function regionalParamsOf(provider: EdgeProviderId, raw: unknown): Record<string, string> {
  const keys = EDGE_TEMPLATE_REGIONAL_FIELDS[provider];
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const k of keys) {
    const v = (raw as Record<string, unknown>)[k];
    if (typeof v === 'string' && v.trim().length > 0) out[k] = v.trim().slice(0, 64);
  }
  return out;
}

/** Parse the stored JSON of a location's regional values (bad JSON = none). */
export function parseRegionalParams(
  provider: EdgeProviderId,
  stored: string | undefined | null,
): Record<string, string> {
  if (!stored) return {};
  try {
    return regionalParamsOf(provider, JSON.parse(stored));
  } catch {
    return {};
  }
}

/**
 * A template's params with the location's regional values laid over them. An
 * empty overlay returns the params untouched, so the effective hash of a
 * location that sets nothing is exactly the template's own hash.
 */
export function withRegionalOverlay(
  provider: EdgeProviderId,
  params: Record<string, unknown>,
  overlay: Record<string, string>,
): Record<string, unknown> {
  const keys = EDGE_TEMPLATE_REGIONAL_FIELDS[provider].filter((k) => overlay[k] !== undefined);
  if (keys.length === 0) return params;
  const out = { ...params };
  for (const k of keys) out[k] = overlay[k];
  return out;
}
