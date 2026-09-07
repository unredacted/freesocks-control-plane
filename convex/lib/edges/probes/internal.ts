/**
 * The internal probe: FCP's own host opens a TLS connection to the edge. This
 * is NOT a country signal (FCP is not in a censored network); it distinguishes
 * "the edge is down / blackholed for everyone" from "blocked in country X" so
 * the detector never rotates away from an outage as if it were a block. Any
 * answer at all (even a TLS handshake error: a REALITY edge will not present a
 * certificate for a random SNI) counts as reachable; only connection-level
 * failures count as unreachable.
 */
import { shortError, type ProbeResult, type ProbeTarget } from './types';
import type { FetchLike } from './checkhost';

const CONNECT_FAILURE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
  'ABORT_ERR',
]);

/** Classify a fetch failure: connection-level → unreachable; TLS-level → reachable. */
export function classifyInternalError(err: unknown): { ok: boolean; error: string } {
  const e = err as { name?: string; code?: string; cause?: { code?: string; message?: string } };
  const code = String(e?.cause?.code ?? e?.code ?? e?.name ?? '');
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError')
    return { ok: false, error: 'timeout' };
  if (CONNECT_FAILURE_CODES.has(code)) return { ok: false, error: code };
  // Anything TLS/protocol-shaped means a peer answered on the port.
  if (
    /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO|SELF_SIGNED|EPROTO|HOSTNAME_MISMATCH)/.test(
      code,
    ) ||
    /certificate|tls|ssl|handshake/i.test(e?.cause?.message ?? '')
  ) {
    return { ok: true, error: shortError(code || 'tls') };
  }
  return { ok: false, error: shortError(code || (err instanceof Error ? err.message : 'error')) };
}

export async function internalProbe(
  fetchFn: FetchLike,
  target: ProbeTarget,
  timeoutMs = 6000,
): Promise<ProbeResult> {
  const host = target.ipVersion === 6 ? `[${target.address}]` : target.address;
  const started = Date.now();
  try {
    await fetchFn(`https://${host}:${target.port}/`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { country: 'XX', vantageClass: 'datacenter', ok: true, rttMs: Date.now() - started };
  } catch (err) {
    const c = classifyInternalError(err);
    return {
      country: 'XX',
      vantageClass: 'datacenter',
      ok: c.ok,
      rttMs: c.ok ? Date.now() - started : undefined,
      error: c.error,
    };
  }
}
