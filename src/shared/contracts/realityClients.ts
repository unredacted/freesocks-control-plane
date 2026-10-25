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
 * client while an up-to-date Xray client connects; v26.9.8 (commit 47cfe999)
 * took that default out again. `"minClientVer": "1.8.1"` admits them all on
 * those releases, which is what FCP's own profile template sets.
 *
 * The same commit brought XTLS/REALITY 8cdf7bf9: from v26.9.8 the server
 * refuses a Client Hello that does not offer X25519MLKEM768 ahead of X25519,
 * and sing-box strips that key share (SagerNet/sing-box issue 4520, open as of
 * 1.14.1), so no transport setting lets sing-box in there. Revisit
 * `core_key_share` once a sing-box release sends it.
 */
import { z } from 'zod';

/** The minimum Xray assumes when a transport sets none, on the releases below. */
export const XRAY_DEFAULT_MIN_CLIENT_VER = '26.3.27';
/** The first Xray-core release with that default. */
export const XRAY_DEFAULT_MIN_SINCE = '26.7.11';
/** The last published release with it (v26.7.28), and the first build without it (v26.9.8). */
export const XRAY_DEFAULT_MIN_LAST = '26.7.28';
export const XRAY_DEFAULT_MIN_UNTIL = '26.9.8';
/** The first Xray-core build whose REALITY server needs an X25519MLKEM768 key share. */
export const XRAY_KEY_SHARE_SINCE = '26.9.8';
/** What admits every client family below on the default releases (FCP's profile template sets it). */
export const ADMITTING_MIN_CLIENT_VER = '1.8.1';

/** Client families that do not send an Xray version, and the version they send. */
export const REALITY_CLIENT_FAMILIES = ['singbox', 'mihomo'] as const;
export type RealityClientFamily = (typeof REALITY_CLIENT_FAMILIES)[number];
export const REALITY_CLIENT_VERSIONS: Record<RealityClientFamily, string> = {
  singbox: '1.8.1',
  mihomo: '1.8.2',
};

/**
 * Why a transport refuses a family, one reason per restriction:
 *  - `min_above`: the `minClientVer` set is above what the family sends;
 *  - `core_default`: no `minClientVer`, and the node's Xray (v26.7.11 to v26.7.28) takes 26.3.27;
 *  - `max_below`: the `maxClientVer` set is below what the family sends;
 *  - `core_key_share`: the node's Xray (v26.9.8 on) needs an X25519MLKEM768 key
 *    share sing-box does not send, whatever the transport sets;
 *  - `core_unknown`: the node's Xray version could not be read, and one of the
 *    two core rules above may apply (never "they get in" while it is unknown).
 */
export const REALITY_REFUSAL_CAUSES = [
  'min_above',
  'core_default',
  'max_below',
  'core_key_share',
  'core_unknown',
] as const;
export type RealityRefusalCause = (typeof REALITY_REFUSAL_CAUSES)[number];

const Family = z.enum(REALITY_CLIENT_FAMILIES);
export const RealityClientRefusal = z.object({
  /** Every family it refuses, any reason (never empty). */
  refuses: z.array(Family),
  /** Each restriction and the families it refuses, in REALITY_REFUSAL_CAUSES order (never empty). */
  reasons: z.array(z.object({ cause: z.enum(REALITY_REFUSAL_CAUSES), families: z.array(Family) })),
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
 * The families a transport refuses, and every reason; null when it admits them
 * all, or when a bound is not one Xray could read (the node would not start on
 * it, and that is not this check's to say).
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
  const sent = (f: RealityClientFamily) => v(REALITY_CLIENT_VERSIONS[f]);
  const below = (floor: Version) =>
    REALITY_CLIENT_FAMILIES.filter((f) => compare(sent(f), floor) < 0);
  const reasons: RealityClientRefusal['reasons'] = [];
  const add = (cause: RealityRefusalCause, families: RealityClientFamily[]) => {
    if (families.length > 0) reasons.push({ cause, families });
  };
  if (min) add('min_above', below(min));
  else if (core && inDefaultWindow(core))
    add('core_default', below(v(XRAY_DEFAULT_MIN_CLIENT_VER)));
  if (max)
    add(
      'max_below',
      REALITY_CLIENT_FAMILIES.filter((f) => compare(sent(f), max) > 0),
    );
  if (core && compare(core, v(XRAY_KEY_SHARE_SINCE)) >= 0) add('core_key_share', ['singbox']);
  if (!core) {
    // Either core rule may hold: the default minimum (no minClientVer set) or the key share.
    const known = new Set(reasons.flatMap((r) => r.families));
    const risk: RealityClientFamily[] = min ? ['singbox'] : [...REALITY_CLIENT_FAMILIES];
    add(
      'core_unknown',
      risk.filter((f) => !known.has(f)),
    );
  }
  if (reasons.length === 0) return null;
  const refused = new Set(reasons.flatMap((r) => r.families));
  return {
    refuses: REALITY_CLIENT_FAMILIES.filter((f) => refused.has(f)),
    reasons,
    xrayVersion: xrayVersion?.trim() || null,
    minClientVer: minRaw,
    maxClientVer: maxRaw,
  };
}

function inDefaultWindow(core: Version): boolean {
  return (
    compare(core, v(XRAY_DEFAULT_MIN_SINCE)) >= 0 && compare(core, v(XRAY_DEFAULT_MIN_UNTIL)) < 0
  );
}

/** Whether two verdicts say the same (a stored fact is rewritten only when it moved). */
export function sameRefusal(
  a: RealityClientRefusal | null | undefined,
  b: RealityClientRefusal | null | undefined,
): boolean {
  if (!a || !b) return !a && !b;
  const reasons = (r: RealityClientRefusal) =>
    r.reasons.map((x) => `${x.cause}:${x.families.join('+')}`).join();
  return (
    reasons(a) === reasons(b) &&
    a.refuses.join() === b.refuses.join() &&
    a.xrayVersion === b.xrayVersion &&
    a.minClientVer === b.minClientVer &&
    a.maxClientVer === b.maxClientVer
  );
}
