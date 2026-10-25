/**
 * Which clients a REALITY transport lets in, from its `minClientVer` /
 * `maxClientVer` and the node's Xray version (docs/client-compatibility.md
 * § "REALITY client versions"). Pure: the server judges a transport with it
 * (protect plan, test card, attention) and the admin UI words the verdict.
 *
 * Every REALITY client puts a version in its Client Hello, and the server
 * compares it with the transport's bounds. Xray-based clients send their own
 * Xray version; sing-box (and the apps built on it) sends 1.8.1, Mihomo 1.8.2.
 * Xray-core v26.7.11 (commit af7eb680) made an ABSENT `minClientVer` mean
 * 26.3.27, so a transport that sets none refuses every sing-box and Mihomo
 * client while an up-to-date Xray client connects; v26.9.9 (commit 47cfe999)
 * took that default out again. `"minClientVer": "1.8.1"` admits them all on
 * any Xray release, which is what FCP's own profile template sets.
 */
import { z } from 'zod';

/** The minimum Xray assumes when a transport sets none, on the releases below. */
export const XRAY_DEFAULT_MIN_CLIENT_VER = '26.3.27';
/** The first Xray-core release with that default. */
export const XRAY_DEFAULT_MIN_SINCE = '26.7.11';
/** The last release with it (v26.7.28), and the first without it again (v26.9.9). */
export const XRAY_DEFAULT_MIN_LAST = '26.7.28';
export const XRAY_DEFAULT_MIN_UNTIL = '26.9.9';
/** What admits every client family below (FCP's profile template sets it). */
export const ADMITTING_MIN_CLIENT_VER = '1.8.1';

/** Client families that do not send an Xray version, and the version they send. */
export const REALITY_CLIENT_FAMILIES = ['singbox', 'mihomo'] as const;
export type RealityClientFamily = (typeof REALITY_CLIENT_FAMILIES)[number];
export const REALITY_CLIENT_VERSIONS: Record<RealityClientFamily, string> = {
  singbox: '1.8.1',
  mihomo: '1.8.2',
};

/**
 * Why a transport refuses a family:
 *  - `core_default`: no `minClientVer`, and the node's Xray applies its default;
 *  - `core_unknown`: no `minClientVer`, and the node's Xray version could not be read
 *    (it refuses them if it is v26.7.11 to v26.7.28);
 *  - `min_above`: the `minClientVer` set is above what the family sends;
 *  - `max_below`: the `maxClientVer` set is below it.
 */
export const REALITY_REFUSAL_CAUSES = [
  'core_default',
  'core_unknown',
  'min_above',
  'max_below',
] as const;
export type RealityRefusalCause = (typeof REALITY_REFUSAL_CAUSES)[number];

export const RealityClientRefusal = z.object({
  cause: z.enum(REALITY_REFUSAL_CAUSES),
  /** The families it refuses (never empty). */
  refuses: z.array(z.enum(REALITY_CLIENT_FAMILIES)),
  /** The node's Xray version as the panel reports it; null when unknown. */
  xrayVersion: z.string().nullable(),
  minClientVer: z.string().nullable(),
  maxClientVer: z.string().nullable(),
});
export type RealityClientRefusal = z.infer<typeof RealityClientRefusal>;

/** A transport's client bounds as its `realitySettings` states them (null = not set). */
export interface RealityClientBounds {
  minClientVer: string | null;
  maxClientVer: string | null;
}

type Version = readonly [number, number, number];

/** A bound as Xray reads it: one to three dot-separated numbers below 256. */
function parseBound(raw: string): Version | null {
  const parts = raw.trim().split('.');
  if (parts.length > 3 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  const n = parts.map(Number);
  return [n[0] ?? 0, n[1] ?? 0, n[2] ?? 0];
}

/** The first `x.y.z` in what the panel reports (`26.7.28`, `v26.7.28`, `Xray 26.7.28 (...)`). */
export function xrayVersionOf(raw: string | null | undefined): Version | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(raw ?? '');
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compare(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

const v = (s: string) => parseBound(s)!;

/** A bound that is set: a non-empty string (Xray reads an empty one as unset). */
function setBound(raw: unknown): string | null {
  return typeof raw === 'string' && raw.trim() !== '' ? raw.trim() : null;
}

/** The bounds of a raw `realitySettings` object: only these two keys are read. */
export function realityClientBoundsOf(realitySettings: unknown): RealityClientBounds {
  const rs =
    realitySettings && typeof realitySettings === 'object'
      ? (realitySettings as Record<string, unknown>)
      : {};
  return { minClientVer: setBound(rs.minClientVer), maxClientVer: setBound(rs.maxClientVer) };
}

/**
 * The families a transport refuses, and why; null when it admits them all, or
 * when a bound is not one Xray could read (the node would not start on it, and
 * that is not this check's to say).
 */
export function realityClientRefusal(
  bounds: RealityClientBounds,
  xrayVersion: string | null | undefined,
): RealityClientRefusal | null {
  const minRaw = setBound(bounds.minClientVer);
  const maxRaw = setBound(bounds.maxClientVer);
  const min = minRaw ? parseBound(minRaw) : null;
  const max = maxRaw ? parseBound(maxRaw) : null;
  if ((minRaw && !min) || (maxRaw && !max)) return null;
  const core = xrayVersionOf(xrayVersion);
  let floor: Version | null = min;
  let floorCause: RealityRefusalCause = 'min_above';
  if (!min) {
    const defaulted =
      !core ||
      (compare(core, v(XRAY_DEFAULT_MIN_SINCE)) >= 0 &&
        compare(core, v(XRAY_DEFAULT_MIN_UNTIL)) < 0);
    if (defaulted) {
      floor = v(XRAY_DEFAULT_MIN_CLIENT_VER);
      floorCause = core ? 'core_default' : 'core_unknown';
    }
  }
  const belowFloor = REALITY_CLIENT_FAMILIES.filter(
    (f) => floor !== null && compare(v(REALITY_CLIENT_VERSIONS[f]), floor) < 0,
  );
  const aboveMax = REALITY_CLIENT_FAMILIES.filter(
    (f) => max !== null && compare(v(REALITY_CLIENT_VERSIONS[f]), max) > 0,
  );
  const refuses = REALITY_CLIENT_FAMILIES.filter(
    (f) => belowFloor.includes(f) || aboveMax.includes(f),
  );
  if (refuses.length === 0) return null;
  return {
    cause: belowFloor.length > 0 ? floorCause : 'max_below',
    refuses,
    xrayVersion: xrayVersion?.trim() || null,
    minClientVer: minRaw,
    maxClientVer: maxRaw,
  };
}

/** Whether two verdicts say the same (a stored fact is rewritten only when it moved). */
export function sameRefusal(
  a: RealityClientRefusal | null | undefined,
  b: RealityClientRefusal | null | undefined,
): boolean {
  if (!a || !b) return !a && !b;
  return (
    a.cause === b.cause &&
    a.refuses.join() === b.refuses.join() &&
    a.xrayVersion === b.xrayVersion &&
    a.minClientVer === b.minClientVer &&
    a.maxClientVer === b.maxClientVer
  );
}
