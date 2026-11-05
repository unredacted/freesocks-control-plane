/**
 * How far a member's whole path is through each address (pure; unit-tested).
 * docs/edges.md "Latency over the whole path" is the contract; in short:
 *
 * Every member's traffic leaves the service at the NODE, so the nearest address
 * is not always the fastest: a member -> an address next door -> a node an
 * ocean away is longer than the same member -> an address beside the node. A path
 * is the member's leg (their country to the address) plus the node's leg (the
 * address to the node), in milliseconds of round trip:
 *
 *  - the member's leg is MEASURED where probes in that country timed a bare
 *    TCP connect to an address of that location (`edgeLatency`, the censored
 *    countries with odd routes); elsewhere it is estimated from the distance
 *    between the country's point and the point of the location's country
 *    (`memberPlace.country`, src/shared/countryPoints.ts);
 *  - the node's leg is estimated from the distance between the location's
 *    point and the node's own map position (`backendServers.locationLat/Lng`):
 *    nothing measures it.
 *
 * Figures are coarse, so they never order members exactly: each address gets
 * a BAND (near, medium, far) relative to the best path among the member's
 * candidates, and members spread over the addresses of one band as before. An
 * address with no figure (an L7 front: anycast, near everywhere; a location
 * with no place country; a node with no map position) ranks with the nearest,
 * so latency only ever moves a member off an address known to be farther.
 */
import { COUNTRY_POINTS } from '../../../src/shared/countryPoints';

/** 0 near, 1 medium, 2 far. */
export type LatencyBand = 0 | 1 | 2;

/** The constants of the estimate and the bands (docs/edges.md). */
export const LATENCY = {
  /** Round trip per great-circle km: fibre at ~200 km/ms, routes ~1.5x the straight line. */
  msPerKm: 0.015,
  /** A member's own access network, added to an estimated member leg. */
  accessMs: 10,
  /** Near: within this factor of the best path, or this many ms of it (whichever is larger). */
  nearRatio: 1.3,
  nearSlackMs: 25,
  /** Medium: within this factor of the best path, or this many ms of it; far beyond. */
  mediumRatio: 2,
  mediumSlackMs: 75,
} as const;

export interface GeoPoint {
  lat: number;
  lng: number;
}

/** Great-circle distance in km (haversine on a sphere). */
export function greatCircleKm(a: GeoPoint, b: GeoPoint): number {
  const rad = Math.PI / 180;
  const dLat = (b.lat - a.lat) * rad;
  const dLng = (b.lng - a.lng) * rad;
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLng / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)));
}

/** A country's point, or null for a code that names none. */
export function countryPoint(code: string | null | undefined): GeoPoint | null {
  const p = code ? COUNTRY_POINTS[code.toUpperCase()] : undefined;
  return p ? { lat: p[0], lng: p[1] } : null;
}

/**
 * What a render knows about paths on one node (edgeLatency.ts
 * `latencyInputsFor`): the node's map position, and the measured member legs
 * per location (`<provider>:<placeKey>`) and country.
 */
export interface LatencyInputs {
  node: GeoPoint | null;
  measured: Record<string, Record<string, number>>;
}

/** The parts of an address a path needs. */
export interface PathEdge {
  layer?: 'l4' | 'l7';
  addresses: { hostname?: string };
  locationKey?: string;
  memberPlace?: { country?: string };
}

export interface PathFigure {
  /** The whole path, ms of round trip. */
  ms: number;
  /** Whether the member's leg was measured (else estimated from distance). */
  measured: boolean;
}

/**
 * The whole path from a member in `country` through `edge` to the node, or
 * null when it cannot be told (an L7 front, no place country, a country with no
 * point, no node position).
 */
export function pathFigure(
  edge: PathEdge,
  country: string,
  inputs: LatencyInputs,
): PathFigure | null {
  const l7 = (edge.layer ?? (edge.addresses.hostname ? 'l7' : 'l4')) === 'l7';
  if (l7 || !inputs.node) return null;
  const place = countryPoint(edge.memberPlace?.country);
  if (!place) return null;
  const nodeLeg = greatCircleKm(place, inputs.node) * LATENCY.msPerKm;
  const measured = edge.locationKey ? inputs.measured[edge.locationKey]?.[country] : undefined;
  if (measured !== undefined) return { ms: Math.round(measured + nodeLeg), measured: true };
  const member = countryPoint(country);
  if (!member) return null;
  const memberLeg = LATENCY.accessMs + greatCircleKm(member, place) * LATENCY.msPerKm;
  return { ms: Math.round(memberLeg + nodeLeg), measured: false };
}

/** One path's band against the best path (`bestMs` the smallest of the candidates). */
export function bandOf(ms: number, bestMs: number): LatencyBand {
  if (ms <= Math.max(bestMs * LATENCY.nearRatio, bestMs + LATENCY.nearSlackMs)) return 0;
  if (ms <= Math.max(bestMs * LATENCY.mediumRatio, bestMs + LATENCY.mediumSlackMs)) return 1;
  return 2;
}

/**
 * The band of each position: against the best figure among the positions in
 * `candidates` (the member's assignable addresses not blocked there). A
 * position without a figure, and every position when no candidate has one, is
 * near (0).
 */
export function bandsOf(
  figures: readonly (number | null | undefined)[],
  candidates: readonly boolean[],
): LatencyBand[] {
  let best: number | null = null;
  figures.forEach((ms, i) => {
    if (candidates[i] && typeof ms === 'number' && (best === null || ms < best)) best = ms;
  });
  return figures.map((ms) => (best === null || typeof ms !== 'number' ? 0 : bandOf(ms, best)));
}

/** Each address's whole path from `country` (`pathFigure`), for those with a figure: the assignment's `pathMs`. */
export function pathMsOf(
  pool: readonly (PathEdge & { edgeId: string })[],
  country: string,
  inputs: LatencyInputs,
): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of pool) {
    const f = pathFigure(e, country, inputs);
    if (f) out.set(e.edgeId, f.ms);
  }
  return out;
}
