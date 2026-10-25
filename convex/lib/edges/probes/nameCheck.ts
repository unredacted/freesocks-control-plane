/**
 * Name checks from inside a country (pure; unit-tested): a TLS handshake that
 * presents ONE server name to ONE of FCP's own member-facing addresses, from
 * vantages in one country (docs/edges.md "Checks from inside a country").
 *
 * Only two sources can aim a chosen name at a chosen address:
 *  - Globalping: an `http` measurement over HTTPS with `request.host` = the
 *    name (the probe sends it as SNI and Host, never rejects a certificate,
 *    and reports `tls.authorized`). `HEAD /`, nothing else. A later
 *    measurement names the first as its `locations`, so every name of a batch
 *    is tried from the same probes.
 *  - RIPE Atlas: `sslcert` with `hostname` = the name, on probes pinned by id.
 *    The presented chain comes back as PEM and is checked against the name
 *    here (`certCovers`, injected: X.509 parsing is Node-only).
 * check-host.net cannot (one URL is both the address dialled and the name).
 *
 * Nothing sent identifies FreeSocks: no FreeSocks name, header, path, query or
 * description. Error text is stored only as a short class, scrubbed of the
 * name and the address.
 */
import { normalizeCountry, shortError, type VantageClass } from './types';

/** What one vantage saw. See the table in docs/edges.md. */
export type NameOutcome =
  | 'ok'
  | 'answered'
  | 'cert_mismatch'
  | 'reset'
  | 'timeout'
  | 'refused'
  | 'error';

export type VantageSource = 'globalping' | 'ripeatlas';

/**
 * Where a failed check stopped: before the connection was up (`connect`),
 * during the TLS handshake (`handshake`), or after it while waiting for the
 * answer (`response`). Absent = not known from what the source reported.
 */
export type NameStage = 'connect' | 'handshake' | 'response';

export interface NameVantageResult {
  asn?: string;
  network?: string;
  vantageClass: VantageClass;
  outcome: NameOutcome;
  /** Failures only: where it stopped (`classifyStage`). */
  stage?: NameStage;
  /**
   * An opaque key of the vantage (a short hash), equal for the same vantage
   * across the measurements of one batch: what pairs a check of FCP's address
   * with the check of the name's real site (lib/edges/sni/realHost.ts).
   * Never a location or a probe id in the clear.
   */
  vantage?: string;
  rttMs?: number;
  /**
   * Phase timings, when the source reports them: the TCP connect, and the TLS
   * handshake after it (Globalping `timings.tcp` / `.tls`; Atlas `ttc` and
   * `rt - ttc`). No DNS phase: a vantage dials the address literal.
   */
  tcpMs?: number;
  tlsMs?: number;
  /** A short storable class of what went wrong (never a name or an address). */
  error?: string;
}

/** A non-negative whole number of milliseconds, else undefined. */
function msOf(x: unknown): number | undefined {
  const n = typeof x === 'number' ? x : Number.NaN;
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : undefined;
}

/** `{tcpMs, tlsMs}` with only the phases that were measured. */
function phases(tcp: unknown, tls: unknown): { tcpMs?: number; tlsMs?: number } {
  const tcpMs = msOf(tcp);
  const tlsMs = msOf(tls);
  return {
    ...(tcpMs !== undefined ? { tcpMs } : {}),
    ...(tlsMs !== undefined ? { tlsMs } : {}),
  };
}

export interface NameCheckTarget {
  /** An IP literal, or a hostname for an origin whose address is a name. */
  address: string;
  port: number;
  /** The server name presented (SNI) and, for Globalping, the Host. */
  name: string;
}

const isIpLiteral = (a: string) => /^[0-9.]+$/.test(a) || a.includes(':');

/**
 * A connection error's text, as a class. A reset (or a close before the
 * handshake finished) and a timeout are what SNI filtering looks like; a
 * refusal happens before any name is sent, so it says nothing about the name.
 */
export function classifyConnectError(text: unknown): NameOutcome {
  const s = typeof text === 'string' ? text : text instanceof Error ? text.message : '';
  if (/ECONNREFUSED|refused/i.test(s)) return 'refused';
  if (/ECONNRESET|reset|socket hang up|disconnected before secure|\bEOF\b|closed/i.test(s))
    return 'reset';
  if (/timeout|timed out|ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT/i.test(s)) return 'timeout';
  return 'error';
}

/**
 * Where a failure stopped, from its text: Globalping names the phase of a
 * timeout ("... establishing the TCP connection", "... during the TLS
 * handshake", "... first response byte") and passes socket errors through
 * (`connect ECONNREFUSED`, `read ECONNRESET`); Atlas prefixes a connect
 * failure with `connect:`. A reset or an early close after the connection was
 * up is the handshake (it is the first thing sent). Unknown = undefined.
 */
export function classifyStage(text: unknown): NameStage | undefined {
  const s = typeof text === 'string' ? text : text instanceof Error ? text.message : '';
  if (/first response byte|downloading the response/i.test(s)) return 'response';
  if (/TCP connection|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|\bconnect\b/i.test(s)) return 'connect';
  if (
    /TLS handshake|ECONNRESET|reset|socket hang up|disconnected before secure|EPROTO|\bEOF\b|\bread\b|alert/i.test(
      s,
    )
  )
    return 'handshake';
  return undefined;
}

/** A short opaque key for one vantage (FNV-1a over what identifies it), never the parts. */
export function vantageKeyOf(parts: readonly unknown[]): string {
  let h = 0x811c9dc5;
  const s = parts.map((p) => String(p ?? '')).join('|');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

// --- Globalping ----------------------------------------------------------------------------------

export type GlobalpingLocations =
  | { country: string; limit: number; preferEyeball?: boolean }
  | { reuse: string };

/** One name, one address: `HEAD /` over HTTPS with the name as SNI and Host. */
export function globalpingNameRequest(t: NameCheckTarget, where: GlobalpingLocations) {
  const locations =
    'reuse' in where
      ? where.reuse
      : [
          {
            country: where.country,
            limit: Math.max(1, Math.min(where.limit, 10)),
            ...(where.preferEyeball ? { tags: ['eyeball-network'] } : {}),
          },
        ];
  return {
    type: 'http' as const,
    target: t.address,
    inProgressUpdates: false,
    locations,
    measurementOptions: {
      protocol: 'HTTPS' as const,
      port: t.port,
      request: { method: 'HEAD' as const, path: '/', host: t.name },
      // A name is resolved by the probe; pin it to v4, what every member reaches for first.
      ...(isIpLiteral(t.address) ? {} : { ipVersion: 4 as const }),
    },
  };
}

interface GlobalpingItem {
  probe?: {
    country?: unknown;
    asn?: unknown;
    network?: unknown;
    tags?: unknown;
    city?: unknown;
    latitude?: unknown;
    longitude?: unknown;
  };
  result?: {
    status?: unknown;
    statusCode?: unknown;
    rawOutput?: unknown;
    timings?: { total?: unknown; tcp?: unknown; tls?: unknown };
    tls?: { authorized?: unknown; error?: unknown } | null;
  };
}

function vantageClassOf(tags: unknown): VantageClass {
  if (!Array.isArray(tags)) return 'unknown';
  const t = tags.map((x) => String(x).toLowerCase());
  if (t.includes('eyeball-network')) return 'eyeball';
  if (t.includes('datacenter-network')) return 'datacenter';
  return 'unknown';
}

/**
 * A finished measurement's items as outcomes. Only probes in `country` count
 * (a reused measurement has the same probes; anything else is not evidence
 * for that country). A finished test with TLS details is `ok` or
 * `cert_mismatch`; without them the far end still `answered`. A failed test is
 * the connection error, classified. Anything still running is dropped.
 */
export function parseGlobalpingNameResults(
  items: unknown,
  country: string,
  redact: readonly string[] = [],
): NameVantageResult[] {
  if (!Array.isArray(items)) return [];
  const out: NameVantageResult[] = [];
  // Globalping gives no probe id: a vantage is what describes it (a measurement
  // that reuses another's probes reports the same descriptions). Two probes
  // described alike are told apart by their order.
  const seen = new Map<string, number>();
  for (const raw of items as GlobalpingItem[]) {
    if (normalizeCountry(raw.probe?.country) !== country) continue;
    const asn = raw.probe?.asn != null ? `AS${String(raw.probe.asn)}` : undefined;
    const network = typeof raw.probe?.network === 'string' ? raw.probe.network : undefined;
    const described = vantageKeyOf([
      'gp',
      raw.probe?.asn,
      network,
      raw.probe?.city,
      raw.probe?.latitude,
      raw.probe?.longitude,
    ]);
    const nth = seen.get(described) ?? 0;
    seen.set(described, nth + 1);
    const base = {
      ...(asn ? { asn } : {}),
      ...(network ? { network: network.slice(0, 80) } : {}),
      vantageClass: vantageClassOf(raw.probe?.tags),
      vantage: nth === 0 ? described : vantageKeyOf([described, nth]),
    };
    const status = String(raw.result?.status ?? '');
    if (status === 'finished') {
      const tls = raw.result?.tls;
      const total = Number(raw.result?.timings?.total);
      const rttMs = Number.isFinite(total) ? Math.round(total) : undefined;
      const timed = phases(raw.result?.timings?.tcp, raw.result?.timings?.tls);
      if (tls && typeof tls.authorized === 'boolean') {
        out.push({
          ...base,
          outcome: tls.authorized ? 'ok' : 'cert_mismatch',
          ...(rttMs !== undefined ? { rttMs } : {}),
          ...timed,
          ...(tls.authorized ? {} : { error: shortError(tls.error ?? 'cert', 60, redact) }),
        });
      } else {
        out.push({
          ...base,
          outcome: 'answered',
          ...(rttMs !== undefined ? { rttMs } : {}),
          ...timed,
        });
      }
    } else if (status === 'failed') {
      const text = raw.result?.rawOutput;
      const stage = classifyStage(text);
      out.push({
        ...base,
        outcome: classifyConnectError(text),
        ...(stage ? { stage } : {}),
        error: shortError(text ?? 'failed', 60, redact),
      });
    }
  }
  return out;
}

/** A Globalping refusal that means "no probe matched": worth one retry without the eyeball tag. */
export function isNoProbesError(status: number | undefined, body: unknown): boolean {
  if (status !== 422) return false;
  const text = JSON.stringify(body ?? '').toLowerCase();
  return text.includes('no_probes_found') || text.includes('no suitable probes');
}

// --- RIPE Atlas ----------------------------------------------------------------------------------

export interface AtlasProbeRow {
  id: number;
  asn?: string;
}

/** Connected probes of one country, with their ASN (the public probe registry). */
export function atlasProbeQuery(country: string): string {
  return new URLSearchParams({
    country_code: country,
    status: '1',
    fields: 'id,asn_v4,asn_v6',
    page_size: '100',
  }).toString();
}

export function parseAtlasProbes(body: unknown, af: 4 | 6): AtlasProbeRow[] {
  const rows = (body as { results?: unknown } | null)?.results;
  if (!Array.isArray(rows)) return [];
  const out: AtlasProbeRow[] = [];
  for (const raw of rows as Array<Record<string, unknown>>) {
    const id = typeof raw.id === 'number' ? raw.id : Number(raw.id);
    if (!Number.isInteger(id) || id <= 0) continue;
    const a = raw[af === 6 ? 'asn_v6' : 'asn_v4'];
    const asn = typeof a === 'number' && Number.isFinite(a) ? `AS${a}` : undefined;
    out.push({ id, ...(asn ? { asn } : {}) });
  }
  return out;
}

/**
 * Up to `limit` probes, one per ASN first (networks are what the scoring
 * counts), then any other; stable by id so a country's batches keep using the
 * same few probes rather than touching new hosts each time.
 */
export function pickAtlasProbes(rows: readonly AtlasProbeRow[], limit: number): AtlasProbeRow[] {
  const sorted = [...rows].sort((a, b) => a.id - b.id);
  const picked: AtlasProbeRow[] = [];
  const asns = new Set<string>();
  for (const r of sorted) {
    if (picked.length >= limit) break;
    if (r.asn && asns.has(r.asn)) continue;
    picked.push(r);
    if (r.asn) asns.add(r.asn);
  }
  for (const r of sorted) {
    if (picked.length >= limit) break;
    if (!picked.includes(r)) picked.push(r);
  }
  return picked;
}

/** One request, one definition per name, every definition on the same probes. */
export function atlasNameBody(
  targets: readonly NameCheckTarget[],
  probeIds: readonly number[],
  af: 4 | 6,
) {
  return {
    definitions: targets.map((t) => ({
      type: 'sslcert',
      af,
      target: t.address,
      port: t.port,
      hostname: t.name,
      // Non-identifying, and PRIVATE: a public measurement would publish the
      // address next to the name, and could never be made private again.
      description: 'tls check',
      is_oneoff: true,
      is_public: false,
    })),
    probes: [{ type: 'probes', value: probeIds.join(','), requested: probeIds.length }],
    is_oneoff: true,
  };
}

/** `cert[0]` (PEM) covers `name`: true / false, or null when it cannot be read. */
export type CertCovers = (pem: string, name: string) => boolean | null;

/**
 * One measurement's `/results/` as outcomes: `err` is the connection error,
 * classified; a chain is `ok` when its leaf covers the name, else
 * `cert_mismatch`; an `alert` (Atlas does not speak TLS 1.3, so a TLS
 * 1.3-only target answers with one) or a bare `rt` is `answered`.
 */
export function parseAtlasNameResults(
  body: unknown,
  name: string,
  opts: { asnByProbe: Record<number, string>; certCovers: CertCovers; redact?: readonly string[] },
): NameVantageResult[] {
  if (!Array.isArray(body)) return [];
  const out: NameVantageResult[] = [];
  for (const raw of body as Array<Record<string, unknown>>) {
    const prb = typeof raw.prb_id === 'number' ? raw.prb_id : Number(raw.prb_id);
    const asn = Number.isFinite(prb) ? opts.asnByProbe[prb] : undefined;
    const base = {
      ...(asn ? { asn } : {}),
      vantageClass: 'unknown' as const,
      ...(Number.isFinite(prb) ? { vantage: vantageKeyOf(['atlas', prb]) } : {}),
    };
    const rt = Number(raw.rt);
    const rttMs = Number.isFinite(rt) ? { rttMs: Math.round(rt) } : {};
    // `ttc` = the TCP connect; `rt` = from starting to connect to the server's
    // answer, so the handshake after the connect is `rt - ttc`.
    const ttc = Number(raw.ttc);
    const timed = phases(
      raw.ttc,
      Number.isFinite(ttc) && Number.isFinite(rt) && rt >= ttc ? rt - ttc : undefined,
    );
    if (raw.err !== undefined || raw.dnserr !== undefined) {
      const text = raw.err ?? raw.dnserr;
      const stage = raw.err !== undefined ? classifyStage(text) : undefined;
      out.push({
        ...base,
        outcome: classifyConnectError(text),
        ...(stage ? { stage } : {}),
        error: shortError(text, 60, [name, ...(opts.redact ?? [])]),
      });
    } else if (Array.isArray(raw.cert) && typeof raw.cert[0] === 'string') {
      const covers = opts.certCovers(raw.cert[0], name);
      out.push({
        ...base,
        outcome: covers === true ? 'ok' : covers === false ? 'cert_mismatch' : 'answered',
        ...rttMs,
        ...timed,
      });
    } else if (raw.alert !== undefined || raw.rt !== undefined) {
      out.push({
        ...base,
        outcome: 'answered',
        ...rttMs,
        ...timed,
        ...(raw.alert ? { error: 'tls_alert' } : {}),
      });
    }
  }
  return out;
}
