/**
 * Fleet-wide limits on AUTOMATIC rotation (docs/edges.md § "Operations
 * safety"). A censor that blocks a provider range or a protocol makes many
 * origins look suspected at once; replacing every address then burns budget
 * and lands on the same block. Two guards, both read inside the transaction
 * that starts a detector rotation (`edgeRotations.collectStartBlockers`):
 *
 *  - the BRAKE (`edge:fleetBrake`): engaged by a detector pass in which more
 *    than `edge.detect.fleetBreakerPct` percent of the evaluated origins are
 *    suspected (and at least FLEET_BRAKE_MIN_SUSPECTED of them). While it is
 *    engaged no detector rotation starts anywhere; it releases on the first
 *    pass back under the threshold. Manual rotations are never held.
 *  - the fleet DAILY CAP (`edge:fleetRotations`): detector rotations per UTC
 *    day across all origins (`edge.detect.fleetRotationsPerDay`, 0 = none),
 *    counted in the same mutation that starts one.
 */
import type { DatabaseReader, DatabaseWriter } from '../../_generated/server';
import { readStateJson, writeStateJson } from '../appStateJson';

export const FLEET_BRAKE_KEY = 'edge:fleetBrake';
export const FLEET_ROTATIONS_KEY = 'edge:fleetRotations';
/** A brake needs this many suspected origins, so a small fleet keeps automatic rotation. */
export const FLEET_BRAKE_MIN_SUSPECTED = 3;

export interface FleetBrakeState {
  engaged: boolean;
  /** When the current engagement began (null while released). */
  since: number | null;
  suspected: number;
  evaluated: number;
  threshold: number;
  updatedAt: number | null;
}

export const FLEET_BRAKE_RELEASED: FleetBrakeState = {
  engaged: false,
  since: null,
  suspected: 0,
  evaluated: 0,
  threshold: 0,
  updatedAt: null,
};

/** Whether one detector pass engages the brake (pure). */
export function fleetBrakeEngages(a: {
  suspected: number;
  evaluated: number;
  thresholdPct: number;
}): boolean {
  if (a.evaluated <= 0 || a.suspected < FLEET_BRAKE_MIN_SUSPECTED) return false;
  return a.suspected * 100 > a.thresholdPct * a.evaluated;
}

export async function readFleetBrake(db: DatabaseReader): Promise<FleetBrakeState> {
  const v = await readStateJson<Partial<FleetBrakeState>>(db, FLEET_BRAKE_KEY);
  if (!v) return FLEET_BRAKE_RELEASED;
  return {
    engaged: v.engaged === true,
    since: typeof v.since === 'number' ? v.since : null,
    suspected: typeof v.suspected === 'number' ? v.suspected : 0,
    evaluated: typeof v.evaluated === 'number' ? v.evaluated : 0,
    threshold: typeof v.threshold === 'number' ? v.threshold : 0,
    updatedAt: typeof v.updatedAt === 'number' ? v.updatedAt : null,
  };
}

export async function writeFleetBrake(db: DatabaseWriter, next: FleetBrakeState): Promise<void> {
  await writeStateJson(db, FLEET_BRAKE_KEY, next);
}

/** The UTC day key (YYYY-MM-DD) the fleet counter is bucketed by. */
export function fleetDayKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** Detector rotations started today across the fleet. */
export async function fleetRotationsToday(db: DatabaseReader, now: number): Promise<number> {
  const v = await readStateJson<{ day?: string; count?: number }>(db, FLEET_ROTATIONS_KEY);
  return v && v.day === fleetDayKey(now) && typeof v.count === 'number' ? v.count : 0;
}

export async function countFleetRotation(db: DatabaseWriter, now: number): Promise<number> {
  const used = (await fleetRotationsToday(db, now)) + 1;
  await writeStateJson(db, FLEET_ROTATIONS_KEY, { day: fleetDayKey(now), count: used });
  return used;
}
