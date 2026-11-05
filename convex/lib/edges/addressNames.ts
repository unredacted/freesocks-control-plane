/**
 * Names for load balancer addresses (pure). An L4 edge publishes IP literals;
 * with `edge.names.enabled` an address made while the switch is on also gets
 * a NAME: one word label (`lib/edges/frontWords.ts`, the style of a CDN
 * front's name) in a zone the operator made eligible, holding an A record
 * (and an AAAA where the address has IPv6) that FCP writes through the zone's
 * DNS account. Members then dial the name; the server name a REALITY or TLS
 * listener presents is unchanged.
 *
 * A name is its own row (`edgeNames`), not a resource of the edge, because it
 * can MOVE: when an address is replaced, its name is pointed at the new one
 * (members keep working without a refresh) unless it moved within the last
 * `moveQuietDays` (a name whose new address was blocked that soon is
 * probably known to the censor, so the next address gets a new name). See
 * docs/edges.md "Names for load balancer addresses".
 */
import { planRecord, type DesiredRecord, type DnsRecordLike } from '../backend/originDns';
import { edgeHostnameFor } from './hostname';

/** Seconds: short, so a moved name is followed within a minute. */
export const ADDRESS_NAME_TTL_S = 60;
/** Consecutive failed passes before a name stops being retried by itself. */
export const ADDRESS_NAME_MAX_ATTEMPTS = 12;
/** Names FCP tries for one address before it gives up (each taken one moves to the next). */
export const ADDRESS_NAME_MAX_GENERATION = 8;
/** How many addresses a name remembers it served (newest last). */
export const ADDRESS_NAME_HISTORY = 8;

export type AddressNameState = 'creating' | 'live' | 'moving' | 'removing' | 'gone' | 'parked';

/** States whose records point at an address (the name may be handed out from `live` and `moving`). */
export const NAME_HOLDS_RECORDS: readonly AddressNameState[] = [
  'creating',
  'live',
  'moving',
  'removing',
];
/** States a member body may carry the name in. */
export const NAME_SERVES: readonly AddressNameState[] = ['live', 'moving'];

/** The ownership marker every record of a name carries (its row id: stable across moves). */
export function addressNameMarker(nameId: string): string {
  return `fcp-name:${nameId}`;
}

/**
 * `<word>-<word>.<zone>`: deterministic for (the edge's provider-side name,
 * the zone, the generation). A taken name moves to the next generation.
 */
export function mintAddressName(seed: string, zoneName: string, generation: number): string {
  return edgeHostnameFor(generation > 0 ? `${seed}#n${generation}` : seed, zoneName, {
    labelLength: 12,
    labelStyle: 'words',
    labelWords: 2,
  });
}

export interface ZoneUse {
  locationId: string;
  /** Names of this origin that hold records in the zone. */
  onOrigin: number;
  /** Names of the whole deployment that hold records in the zone. */
  inFleet: number;
}

/**
 * The zone a new name goes in: the one this origin uses least (so its
 * addresses, and a member's main and backup, sit in different zones and one
 * blocked zone takes out only part), then the one the deployment uses least,
 * then a stable pick by the seed. `avoid` (the zone a renewed name leaves) is
 * used only when it is the only one.
 */
export function pickNameZone(
  zones: readonly ZoneUse[],
  seed: string,
  avoid?: string,
): string | null {
  const pool = zones.length > 1 && avoid ? zones.filter((z) => z.locationId !== avoid) : zones;
  if (pool.length === 0) return null;
  const tie = (id: string) => fnv1a32(`${seed}/${id}`);
  const best = [...pool].sort(
    (a, b) =>
      a.onOrigin - b.onOrigin ||
      a.inFleet - b.inFleet ||
      tie(a.locationId) - tie(b.locationId) ||
      a.locationId.localeCompare(b.locationId),
  )[0]!;
  return best.locationId;
}

function fnv1a32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** The records a name should hold for an address: A for IPv4, AAAA for IPv6. */
export function desiredNameRecords(
  fqdn: string,
  addresses: { v4?: string | null; v6?: string | null },
): DesiredRecord[] {
  const out: DesiredRecord[] = [];
  if (addresses.v4) out.push({ type: 'A', name: fqdn, content: addresses.v4 });
  if (addresses.v6) out.push({ type: 'AAAA', name: fqdn, content: addresses.v6 });
  return out;
}

export type NameRecordStep =
  | { action: 'create'; record: DesiredRecord }
  /** FCP's own record at the name with other content: changed in place (no gap a resolver could cache). */
  | { action: 'update'; id: string; record: DesiredRecord }
  | { action: 'delete'; id: string };

export type NamePlan =
  | {
      kind: 'steps';
      steps: NameRecordStep[];
      kept: Array<{ type: 'A' | 'AAAA'; id: string; content: string }>;
    }
  /** Something at the name FCP did not write (a CNAME, a foreign record, a proxied one): never touched. */
  | { kind: 'conflict'; reason: 'cname' | 'foreign' | 'proxied' };

/**
 * What to do so that exactly `desired` is at the name, given everything the
 * zone holds there now. Every record FCP wrote carries `marker`; anything else
 * at the name is a conflict, never replaced or deleted. Records of ours that
 * are not desired (a family the address lost, a duplicate a lost answer left)
 * are deleted.
 */
export function planNameRecords(
  existing: readonly DnsRecordLike[],
  desired: readonly DesiredRecord[],
  marker: string,
  fqdn: string,
): NamePlan {
  const name = fqdn.toLowerCase();
  const atName = existing.filter((r) => r.name.toLowerCase() === name);
  if (atName.some((r) => r.type === 'CNAME')) return { kind: 'conflict', reason: 'cname' };
  if (atName.some((r) => r.comment !== marker)) return { kind: 'conflict', reason: 'foreign' };
  if (atName.some((r) => r.proxied)) return { kind: 'conflict', reason: 'proxied' };
  const steps: NameRecordStep[] = [];
  const kept: Array<{ type: 'A' | 'AAAA'; id: string; content: string }> = [];
  const used = new Set<string>();
  for (const d of desired) {
    const sameType = atName.filter((r) => r.type === d.type);
    // planRecord decides keep / replace for the first one; the rest are duplicates.
    const plan = planRecord(sameType.slice(0, 1), d, marker);
    if (plan.action === 'keep') {
      kept.push({ type: d.type, id: plan.id, content: d.content });
      used.add(plan.id);
    } else if (plan.action === 'replace') {
      steps.push({ action: 'update', id: plan.deleteId, record: d });
      used.add(plan.deleteId);
    } else if (plan.action === 'create') {
      steps.push({ action: 'create', record: d });
    } else {
      return { kind: 'conflict', reason: plan.reason === 'cname' ? 'cname' : 'foreign' };
    }
  }
  for (const r of atName) if (!used.has(r.id)) steps.push({ action: 'delete', id: r.id });
  return { kind: 'steps', steps, kept };
}

// --- moving a name to the address that replaces its own -------------------------------------

export interface MoveFacts {
  /** `edge.names.enabled`. */
  enabled: boolean;
  /** `edge.names.moveQuietDays`: 0 = a name never moves. */
  moveQuietDays: number;
  /** The zones new names may go in now. */
  eligibleZones: readonly string[];
  now: number;
  name: { state: AddressNameState; zoneLocationId: string; movedAt?: number } | null;
  /** `audience`: the countries a contained address is handed to (absent = everyone). */
  from: { listenerId: string; lane: 'open' | 'trusted'; audience?: readonly string[] };
  to: {
    listenerId: string;
    lane: 'open' | 'trusted';
    layer: 'l4' | 'l7';
    v4: string | null;
    audience?: readonly string[];
  };
}

/** Two audiences hand an address to the same members (absent and empty are everyone). */
function sameAudience(a: readonly string[] = [], b: readonly string[] = []): boolean {
  return a.length === b.length && a.every((c) => b.includes(c));
}

export type MoveVerdict =
  | { move: true }
  | {
      move: false;
      reason:
        | 'names_off'
        | 'no_name'
        | 'not_l4'
        | 'no_address'
        | 'other_listener'
        | 'other_lane'
        | 'other_audience'
        | 'zone_not_eligible'
        | 'moved_recently';
    };

/**
 * Whether a replacement takes over the replaced address's name. Moving keeps
 * every member who holds the name working without a refresh; it also hands the
 * new address to anyone who holds the name, the censor included. So a name
 * moves only to an address members of the same lane would get anyway, and at
 * most once per quiet window: a name whose new address is blocked within the
 * window is treated as known, and the next address gets a new name.
 */
export function mayMoveName(f: MoveFacts): MoveVerdict {
  if (!f.enabled || f.moveQuietDays <= 0) return { move: false, reason: 'names_off' };
  if (!f.name || !NAME_SERVES.includes(f.name.state)) return { move: false, reason: 'no_name' };
  if (f.to.layer !== 'l4') return { move: false, reason: 'not_l4' };
  if (!f.to.v4) return { move: false, reason: 'no_address' };
  if (f.to.listenerId !== f.from.listenerId) return { move: false, reason: 'other_listener' };
  if (f.to.lane !== f.from.lane) return { move: false, reason: 'other_lane' };
  // Everyone holding the name would dial the new address: only where the same
  // members may be handed it (docs/edges.md "Addresses only for some countries").
  if (!sameAudience(f.from.audience, f.to.audience))
    return { move: false, reason: 'other_audience' };
  if (!f.eligibleZones.includes(f.name.zoneLocationId))
    return { move: false, reason: 'zone_not_eligible' };
  if (f.name.movedAt !== undefined && f.now - f.name.movedAt < f.moveQuietDays * 86_400_000)
    return { move: false, reason: 'moved_recently' };
  return { move: true };
}

// --- what a name should hold now ------------------------------------------------------------

/** Edge statuses whose address a name may point at. */
const SERVING_STATUSES = new Set(['active', 'draining']);
/** Edge statuses whose address is going away: its names are removed first. */
const ENDING_STATUSES = new Set(['destroying', 'destroyed', 'failed', 'cancelled']);

export type NameTarget =
  | { kind: 'serve'; v4: string; v6: string | null }
  | { kind: 'remove' }
  /** The address is neither serving nor ending (quarantined, held for the operator): leave the records. */
  | { kind: 'hold' };

export function nameTargetOf(
  edge: { status: string; addresses: { v4?: string; v6?: string } } | null,
): NameTarget {
  if (!edge || ENDING_STATUSES.has(edge.status)) return { kind: 'remove' };
  if (SERVING_STATUSES.has(edge.status) && edge.addresses.v4)
    return { kind: 'serve', v4: edge.addresses.v4, v6: edge.addresses.v6 ?? null };
  return { kind: 'hold' };
}
