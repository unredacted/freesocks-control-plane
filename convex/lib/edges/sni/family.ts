/**
 * Server-name families (pure; unit-tested): importing a pasted list, judging a
 * qualification handshake, and choosing which names go onto a transport.
 *
 * The backend allowlist of a transport is ONE list with a hard cap, and it has
 * three kinds of tenant: the family's names, names that are not the family's
 * but that an origin still hands out (they must keep working), and names that
 * were retired but are still inside their drain (members may still hold them).
 * The cap is over ALL of them, so the family's share is what is left after the
 * other two and a headroom kept free for the next drain: retiring one name and
 * adding its replacement needs both on the backend at once.
 */
import { normalizeName } from '../registration';

/** Production Xray takes 1024 names on one transport (measured); this is the working cap. */
export const PANEL_ALLOWLIST_MAX = 512;
export const DRAIN_HEADROOM = 64;
export const MAX_NAMES_PER_FAMILY = 4096;
export const MAX_IMPORT_LINES = 1000;

export type ImportVerdict = 'added' | 'duplicate' | 'invalid' | 'in_other_family' | 'burned';

export interface ImportLine {
  input: string;
  name: string | null;
  verdict: ImportVerdict;
}

/**
 * Judge a pasted list line by line. `existing` maps every name the fleet
 * already knows to where it lives; nothing is decided silently.
 */
export function judgeImport(
  lines: readonly string[],
  familyId: string,
  existing: ReadonlyMap<string, { familyId: string; status: string }>,
): ImportLine[] {
  const seen = new Set<string>();
  return lines
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'))
    .slice(0, MAX_IMPORT_LINES)
    .map((input) => {
      const name = normalizeName(input);
      if (!name) return { input: input.slice(0, 120), name: null, verdict: 'invalid' as const };
      if (seen.has(name)) return { input, name, verdict: 'duplicate' as const };
      seen.add(name);
      const known = existing.get(name);
      if (!known) return { input, name, verdict: 'added' as const };
      if (known.status === 'burned') return { input, name, verdict: 'burned' as const };
      return {
        input,
        name,
        verdict:
          known.familyId === familyId ? ('duplicate' as const) : ('in_other_family' as const),
      };
    });
}

// --- qualification -------------------------------------------------------------------------------

/** What one handshake against the family's target showed. */
export interface HandshakeResult {
  ok: boolean;
  /** The chain verified for the presented name. */
  authorized?: boolean;
  protocol?: string | null;
  alpn?: string | null;
  /** A code word from the dialler: `timeout`, `refused`, `private_address`, `resolve_failed`... */
  error?: string;
}

export type QualificationCode =
  | 'q_timeout'
  | 'q_unreachable'
  | 'q_private_target'
  | 'q_resolve'
  | 'q_cert'
  | 'q_tls12'
  | 'q_no_h2';

export interface Qualification {
  ok: boolean;
  code?: QualificationCode;
  tlsVersion?: string;
  alpn?: string;
}

/**
 * A name qualifies when the target completes a TLS 1.3 handshake for it with a
 * certificate valid for that name. HTTP/2 is recorded, and required only when
 * the family asks. This is what an unauthenticated prober presenting the name
 * to a node would be shown, since REALITY forwards it to the target.
 */
export function judgeHandshake(r: HandshakeResult, opts: { requireH2: boolean }): Qualification {
  if (!r.ok) {
    const e = r.error ?? '';
    if (e === 'timeout') return { ok: false, code: 'q_timeout' };
    if (e === 'private_address') return { ok: false, code: 'q_private_target' };
    if (e === 'no_address' || e.startsWith('resolve') || e === 'ENOTFOUND')
      return { ok: false, code: 'q_resolve' };
    if (e === 'cert_invalid' || e.startsWith('cert')) return { ok: false, code: 'q_cert' };
    return { ok: false, code: 'q_unreachable' };
  }
  const tlsVersion = r.protocol ?? undefined;
  const alpn = r.alpn || undefined;
  if (!r.authorized) return { ok: false, code: 'q_cert', tlsVersion, alpn };
  if (tlsVersion !== 'TLSv1.3') return { ok: false, code: 'q_tls12', tlsVersion, alpn };
  if (opts.requireH2 && alpn !== 'h2') return { ok: false, code: 'q_no_h2', tlsVersion, alpn };
  return { ok: true, tlsVersion, alpn };
}

// --- what goes onto the transport ----------------------------------------------------------------------

export interface FamilyNameLike {
  name: string;
  seq: number;
  status: string;
  qualified: boolean;
}

export interface AllowlistPlan {
  /** The complete list to write, in a stable order. */
  names: string[];
  /** Eligible family names that did not fit (the operator should know). */
  overflow: number;
  /** How many slots the family could use. */
  familyBudget: number;
}

/**
 * The backend allowlist for one transport. `retained` = names on the transport today
 * that are not the family's but that an origin still hands out, or that are still
 * draining: they stay, whatever the family says. The family then fills what is
 * left under the cap minus the drain headroom, in `seq` order, so every node on
 * the transport and every listener sees the same choice.
 */
export function planAllowlist(
  family: readonly FamilyNameLike[],
  retained: readonly string[],
  opts: { max?: number; headroom?: number } = {},
): AllowlistPlan {
  const max = opts.max ?? PANEL_ALLOWLIST_MAX;
  const headroom = opts.headroom ?? DRAIN_HEADROOM;
  const kept = [...new Set(retained)];
  const eligible = family
    .filter((n) => n.status === 'active' && n.qualified && !kept.includes(n.name))
    .sort((a, b) => a.seq - b.seq);
  const familyBudget = Math.max(0, max - headroom - kept.length);
  const chosen = eligible.slice(0, familyBudget).map((n) => n.name);
  return {
    names: [...kept, ...chosen],
    overflow: Math.max(0, eligible.length - chosen.length),
    familyBudget,
  };
}

/** `host:port` of a static target, as the backend spells a REALITY target. */
export function targetString(t: { address: string; port: number }): string {
  return t.address.includes(':') ? `[${t.address}]:${t.port}` : `${t.address}:${t.port}`;
}

export function sameTarget(
  a: { address: string; port: number } | null | undefined,
  b: { address: string; port: number },
): boolean {
  return !!a && a.address.toLowerCase() === b.address.toLowerCase() && a.port === b.port;
}
