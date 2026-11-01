/**
 * A node's provider set as the database holds it, read for the pure rules in
 * `providerSet.ts` (docs/edges.md § "Provider sets"): the picks with their
 * account and location rows, which coverage listeners each pick can carry,
 * what the pool publishes now, and what still cools.
 *
 * Exports:
 *   coolingOf(relay, now)           the location ids cooling on this origin
 *   isCooling(relay, locationId, now)
 *   carries(pick, listener, opts)   whether a pick can front a listener
 *   setPicksOf(db, relay)           the set's rows (null = no set)
 *   setStateOf(db, relay)           requirement + published + deficit + targets
 *   publishedRefOf(edge, listenerKey)
 *   admissionOf(state, ref)         what one more publication does to the deficit
 *   takesSlot(state, relay, ref)    whether a publish at `ref` would get a pool slot now
 *   slotsOf(state, relay)           free pool slots, and how many the deficit holds
 */
import type { Doc, Id } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';
import { listenerLayers } from './layers';
import { locationKeyOf } from './locations';
import { accountsForSlot } from './rotation';
import { frontsAllowed } from './providers/capabilities';
import { placeProblemOf } from './l7Place';
import { websocketNodeOf } from './websocketNode';
import { allocatePoolIndex, freeSlotCount } from './pool';
import {
  coverTargets,
  coverageDeficit,
  requirementOf,
  type PublishedRef,
  type Requirement,
  type SetListener,
  type SetPick,
  type Target,
} from './providerSet';

type Relay = Doc<'relays'>;
type Listener = Doc<'relayListeners'>;

/** The location ids that still cool on this origin. */
export function coolingOf(relay: Pick<Relay, 'cooling'>, now: number = Date.now()): Set<string> {
  return new Set(
    (relay.cooling ?? []).filter((c) => c.until > now).map((c) => c.locationId as string),
  );
}

export function isCooling(
  relay: Pick<Relay, 'cooling'>,
  locationId: string | null | undefined,
  now: number = Date.now(),
): boolean {
  return !!locationId && coolingOf(relay, now).has(locationId);
}

/**
 * The cooling list after a detector burn in `locationId` (D6): pruned of what
 * already ended, the burned pick cooling until `until` (the later end wins).
 */
export function withCooling(
  cooling: Relay['cooling'],
  locationId: Id<'edgeLocations'>,
  until: number,
  now: number,
): NonNullable<Relay['cooling']> {
  const kept = (cooling ?? []).filter((c) => c.until > now && c.locationId !== locationId);
  const prev = (cooling ?? []).find((c) => c.locationId === locationId && c.until > now);
  return [...kept, { locationId, until: Math.max(until, prev?.until ?? 0) }];
}

export interface SetPickRow {
  pick: SetPick;
  location: Doc<'edgeLocations'>;
  account: Doc<'edgeProviderAccounts'>;
  /** Switched on, its account enabled, tested and allowed to front: automatic work may use it. */
  usable: boolean;
}

/**
 * Whether a pick can front a listener: its provider carries the listener's
 * layer, protocol and port, and the listener's provider or account scope (if
 * any) names it. A set pick is the operator's choice, so L7 is allowed (D4).
 * A load balancer never carries a WebSocket node's HTTP transport
 * (`websocketNode`, lib/edges/websocketNode.ts).
 */
export function carries(
  row: Pick<SetPickRow, 'account'> & { location?: Pick<SetPickRow['location'], 'networkId'> },
  listener: Pick<
    Listener,
    | 'protocol'
    | 'streamTransport'
    | 'security'
    | 'originPort'
    | 'originTransport'
    | 'providerScope'
    | 'tlsNames'
    | 'networkId'
  >,
  opts: { websocketNode?: boolean; originAddress?: string } = {},
): boolean {
  const scope = listener.providerScope;
  if (scope?.provider && scope.provider !== row.account.provider) return false;
  if (scope?.accountId && scope.accountId !== row.account._id) return false;
  // A transport scoped to a network (docs/edges.md "Networks") is fronted only
  // from a location on it; a location whose network is not known carries none.
  if (listener.networkId && row.location?.networkId !== listener.networkId) return false;
  const proto = {
    protocol: listener.protocol,
    streamTransport: listener.streamTransport,
    security: listener.security,
  };
  return (
    // Whether a DNS account fronts is applied to a pick as `usable` (setPicksOf).
    accountsForSlot([{ provider: row.account.provider, frontsTraffic: true }], {
      layers: listenerLayers(listener, {
        websocketNode: opts.websocketNode,
        originAddress: opts.originAddress,
      }).layers,
      proto,
      originPort: listener.originPort,
      allowL7: true,
      originTransport: listener.originTransport,
      originAddress: opts.originAddress,
    }).length > 0
  );
}

/** The set's picks with their rows, in set order (null = the origin has no set). */
export async function setPicksOf(
  db: DatabaseReader,
  relay: Pick<Relay, 'providerSet'>,
): Promise<SetPickRow[] | null> {
  if (!relay.providerSet) return null;
  const out: SetPickRow[] = [];
  for (const p of relay.providerSet) {
    const location = await db.get(p.locationId);
    if (!location) continue;
    const account = await db.get(location.accountId);
    if (!account) continue;
    // A DNS account picked while it was set to DNS and fronting is not usable
    // once it is DNS only: nothing new is placed there (its edges are kept).
    const fronts = frontsAllowed(account);
    // A place no new edge can be planned in carries nothing (a CDN place with
    // no zone, a refused check, its DNS account gone or off, an unread
    // encryption mode; a Scaleway location with no project to create in).
    const placeOk = location.enabled && !(await placeProblemOf(db, account, location));
    out.push({
      pick: {
        locationId: location._id as string,
        provider: account.provider,
        locationKey: locationKeyOf(account.provider, location.placeKey),
      },
      location,
      account,
      usable:
        fronts && placeOk && account.enabled && !!account.lastTestOkAt && !account.lastTestError,
    });
  }
  return out;
}

export function publishedRefOf(
  edge: Pick<Doc<'edges'>, 'locationId' | 'provider' | 'placeKey'>,
  listenerKey: string,
): PublishedRef {
  return {
    listenerKey,
    locationId: (edge.locationId as string | undefined) ?? null,
    provider: edge.provider ?? null,
    locationKey:
      edge.provider && edge.placeKey ? locationKeyOf(edge.provider, edge.placeKey) : null,
  };
}

export interface SetState {
  picks: SetPickRow[] | null;
  /** The node is a WebSocket node: no load balancer carries its HTTP transports. */
  websocketNode: boolean;
  /** Deployed, enabled, not retired. */
  listeners: Listener[];
  requirement: Requirement;
  /** What the pool publishes now (an edge per entry, pool order). */
  published: Array<PublishedRef & { edgeId: Id<'edges'> }>;
  deficit: number;
  targets: Target[];
}

/**
 * The origin's requirement and where it stands. A pick that is not usable
 * (switched off, a CDN place no new edge can be planned in, its account
 * disabled or untested) carries nothing: like a
 * cooling one, automatic work is never asked to provision into it.
 */
export async function setStateOf(
  db: DatabaseReader,
  relay: Relay,
  now: number = Date.now(),
): Promise<SetState> {
  const rows = await db
    .query('relayListeners')
    .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
    .collect();
  const listeners = rows.filter((l) => l.deployed && l.enabled && !l.retired);
  const picks = await setPicksOf(db, relay);
  const websocketNode = await websocketNodeOf(db, relay.origin);
  const setListeners: SetListener[] = listeners.map((l) => ({
    listenerKey: l.listenerKey,
    carriers: (picks ?? [])
      .filter(
        (p) => p.usable && carries(p, l, { websocketNode, originAddress: relay.originAddress }),
      )
      .map((p) => p.pick.locationId),
  }));
  const requirement = requirementOf(
    setListeners,
    picks ? picks.map((p) => p.pick) : null,
    coolingOf(relay, now),
  );
  // Only coverage listeners count: an edge of a disabled or retired listener
  // serves nobody, so it neither covers a transport nor holds a pick.
  const keyOf = new Map(listeners.map((l) => [l._id as string, l.listenerKey]));
  const published: SetState['published'] = [];
  for (const id of relay.publishedEdgeIds) {
    if (!id) continue;
    const e = await db.get(id);
    if (!e || e.publication !== 'published') continue;
    const key = keyOf.get(e.listenerId as string);
    if (key) published.push({ ...publishedRefOf(e, key), edgeId: e._id });
  }
  const targets = coverTargets(requirement, published);
  return {
    picks,
    websocketNode,
    listeners,
    requirement,
    published,
    deficit: targets.length,
    targets,
  };
}

/** What publishing one more edge does: whether it lowers the deficit, and the deficit now. */
export function admissionOf(
  state: Pick<SetState, 'requirement' | 'published' | 'deficit'>,
  ref: PublishedRef,
): { lowersDeficit: boolean; deficit: number } {
  const after = coverageDeficit(state.requirement, [...state.published, ref]);
  return { lowersDeficit: after < state.deficit, deficit: state.deficit };
}

/**
 * Whether a publish of an edge at `ref` would get a pool slot now: the
 * reserved allocation every publish path applies (`allocatePoolIndex`). False
 * means it would end as a spare (`pool_full`, or `pool_reserved`: the free
 * slots are held for what the origin still lacks).
 */
export function takesSlot(
  state: Pick<SetState, 'requirement' | 'published' | 'deficit'>,
  relay: Pick<Relay, 'publishedEdgeIds' | 'desiredPublished'>,
  ref: PublishedRef,
): boolean {
  return (
    'index' in
    allocatePoolIndex(relay.publishedEdgeIds, relay.desiredPublished, admissionOf(state, ref))
  );
}

/** Free pool slots, and how many of them are held for the deficit (only an edge that lowers it may take those). */
export function slotsOf(
  state: Pick<SetState, 'deficit'>,
  relay: Pick<Relay, 'publishedEdgeIds' | 'desiredPublished'>,
): { free: number; held: number } {
  const free = freeSlotCount(relay.publishedEdgeIds, relay.desiredPublished);
  return { free, held: Math.min(free, state.deficit) };
}
