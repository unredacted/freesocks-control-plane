/**
 * Test helper: a fake Scaleway load-balancer API (the ZonedAPI methods the
 * adapter calls, installed with `__setScalewayApiFactory`) that behaves like
 * the real one where it matters: every change answers at once, then the LB
 * reads `pending` for `applyReads` reads before it is `ready` again. A backend
 * or frontend sent while the LB is still applying is accepted and never
 * applied (what was observed: a ready LB, a frontend, a healthy backend, and both
 * addresses resetting every connection), so `answers()` stays false until
 * the frontend is saved again on a ready LB. Not a test file itself. Every
 * value is RFC 5737 / 3849 / `*.example`.
 */

export interface FakeScalewayOptions {
  /** Reads of `pending` after each change (create, update). */
  applyReads?: number;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export function fakeScaleway(opts: FakeScalewayOptions = {}) {
  const applyReads = opts.applyReads ?? 2;
  /** Every call by method name, in order (`getLb:pending` / `getLb:ready` for reads). */
  const calls: string[] = [];
  /** Changes the LB accepted while it was still applying another one (never applied). */
  const lost: string[] = [];
  /** What the LB's instances really serve. */
  const applied = new Set<string>();
  let pendingReads = 0;
  /** A status that overrides the settle model (`error`, `locked`...). */
  let forced: string | null = null;
  let lbName = '';
  const ips: Array<{ id: string; ipAddress: string; tags: string[]; lbId?: string }> = [];
  const backends: Array<{ id: string; name: string }> = [];
  const frontends: Array<Record<string, any>> = [];

  const list = (items: unknown[]) => Object.assign(Promise.resolve({}), { all: async () => items });
  const status = () => forced ?? (pendingReads > 0 ? 'pending' : 'ready');
  /** A change: lost when the LB is still applying the previous one. */
  const change = (what: string) => {
    if (status() !== 'ready') lost.push(what);
    else applied.add(what);
    pendingReads = applyReads;
  };
  const lbView = () => ({
    id: 'lb-1',
    name: lbName,
    status: status(),
    type: 'LB-GP-L',
    zone: 'fr-par-1',
    ip: ips.map((ip) => ({ id: ip.id, ipAddress: ip.ipAddress, tags: ip.tags, lbId: 'lb-1' })),
    instances: [],
  });

  const api: Record<string, (...args: any[]) => any> = {
    createIp: async (r: { isIpv6: boolean; tags: string[] }) => {
      calls.push('createIp');
      const ip = r.isIpv6
        ? { id: 'ip6-1', ipAddress: '2001:db8::80', tags: r.tags }
        : { id: 'ip4-1', ipAddress: '198.51.100.80', tags: r.tags };
      ips.push(ip);
      return ip;
    },
    createLb: async (r: { name: string }) => {
      calls.push('createLb');
      lbName = r.name;
      applied.clear();
      pendingReads = applyReads;
      return lbView();
    },
    getLb: async () => {
      const view = lbView();
      calls.push(`getLb:${view.status}`);
      if (!forced && pendingReads > 0) pendingReads--;
      return view;
    },
    createBackend: async (r: { name: string }) => {
      calls.push('createBackend');
      change('backend');
      const b = { id: 'be-1', name: r.name };
      backends.push(b);
      return b;
    },
    createFrontend: async (r: Record<string, any>) => {
      calls.push('createFrontend');
      change('frontend');
      const f = {
        id: 'fe-1',
        name: r.name,
        inboundPort: r.inboundPort,
        backend: { id: r.backendId },
        // The API answers int64 milliseconds; the SDK passes them through.
        timeoutClient: r.timeoutClient,
        certificateIds: [],
        enableHttp3: r.enableHttp3,
        enableAccessLogs: r.enableAccessLogs,
        ...(r.connectionRateLimit ? { connectionRateLimit: r.connectionRateLimit } : {}),
      };
      frontends.push(f);
      return f;
    },
    getFrontend: async (r: { frontendId: string }) => {
      calls.push('getFrontend');
      const f = frontends.find((x) => x.id === r.frontendId);
      if (!f) throw Object.assign(new Error('not found'), { status: 404 });
      return f;
    },
    updateFrontend: async (r: Record<string, any>) => {
      calls.push('updateFrontend');
      const f = frontends.find((x) => x.id === r.frontendId);
      if (!f) throw Object.assign(new Error('not found'), { status: 404 });
      const ready = status() === 'ready';
      change('frontend');
      // Saved again on a ready LB: the frontend it had lost is served now.
      if (ready) {
        const kept = lost.filter((x) => x !== 'frontend');
        lost.length = 0;
        lost.push(...kept);
      }
      return f;
    },
    getLbStats: async () => ({
      backendServersStats: [
        { ip: '198.51.100.7', lastHealthCheckStatus: 'passed', serverState: 'running' },
      ],
    }),
    listIPs: () => list(ips),
    listLbs: () => list(lbName ? [lbView()] : []),
    listBackends: (r: { name?: string }) =>
      list(backends.filter((b) => !r.name || b.name === r.name)),
    listFrontends: (r: { name?: string }) =>
      list(frontends.filter((f) => !r.name || f.name === r.name)),
    listLbTypes: () => list([{ name: 'LB-GP-L', multicloud: true }]),
  };

  return {
    api,
    calls,
    lost: () => [...lost],
    /** Whether the address really answers: the backend and the frontend both applied. */
    answers: () => applied.has('backend') && applied.has('frontend'),
    /** Hold the LB in a status the settle model never leaves (null = back to the model). */
    force: (s: string | null) => {
      forced = s;
    },
    /** The LB applies something FCP did not send for `reads` reads (a change meanwhile is lost). */
    busyFor: (reads: number) => {
      pendingReads = reads;
    },
  };
}
export type FakeScaleway = ReturnType<typeof fakeScaleway>;
