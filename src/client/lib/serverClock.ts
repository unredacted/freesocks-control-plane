/**
 * Server-time offset (Phase 3 clock-skew handling), shared by PoP signing and
 * the HPKE epoch freshness check. Fetched once from /healthz: a device whose
 * clock is off still signs inside the PoP window and still sees a current
 * epoch as current. Any failure leaves the offset at 0. Stable per session.
 */
let _tsOffset = 0;
let _tsFetched = false;
let _tsFetch: Promise<void> | null = null;

async function refreshTimeOffset(): Promise<void> {
  try {
    const t0 = Date.now();
    const res = await fetch('/healthz', { credentials: 'omit' });
    if (!res.ok) return;
    const body = (await res.json()) as { timestamp?: string };
    const serverMs = body.timestamp ? Date.parse(body.timestamp) : NaN;
    if (!Number.isFinite(serverMs)) return;
    const t1 = Date.now();
    _tsOffset = serverMs - (t0 + (t1 - t0) / 2); // server time at round-trip midpoint
  } catch {
    /* keep 0 */
  }
}

/** serverTime - localTime in ms (0 until known or when unavailable). */
export async function serverTimeOffset(): Promise<number> {
  if (_tsFetched) return _tsOffset;
  _tsFetch ??= refreshTimeOffset().then(() => {
    _tsFetched = true;
  });
  await _tsFetch;
  return _tsOffset;
}
