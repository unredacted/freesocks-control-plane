'use node';
/**
 * The origin probe's `"use node"` half: real sockets for lib/edges/originProbe.ts
 * (TLS with SNI and chain verification, the peer certificate's names, one
 * request with a foreign Host header). One bounded outbound operation per
 * target; the isolate side (edgeOriginProbe.ts) reads and writes everything.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import {
  dnsNamesOfSan,
  probeOriginTransport,
  type OriginProbeDeps,
  type OriginProbeOutcome,
} from './lib/edges/originProbe';
import { classifyHandshakeError, classifyInternalError } from './lib/edges/probes/internal';
import { listenerProtoFields } from './lib/edgeProtocolIds';

const defaultDeps: OriginProbeDeps = {
  lookup: async (name) => {
    const dns = await import('node:dns/promises');
    const answers = await dns.lookup(name, { all: true, verbatim: true });
    return answers.map((a) => a.address);
  },
  tcpConnect: async ({ host, port, timeoutMs }) => {
    const net = await import('node:net');
    return new Promise((resolve) => {
      let settled = false;
      const done = (r: { ok: boolean; error?: string }) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(r);
      };
      const socket = net.connect({ host, port }, () => done({ ok: true }));
      socket.setTimeout(timeoutMs, () => done({ ok: false, error: 'timeout' }));
      socket.on('error', (err) => {
        const c = classifyInternalError(err);
        done({ ok: c.ok, error: c.error });
      });
    });
  },
  tlsInspect: async ({ host, port, servername, timeoutMs }) => {
    const tls = await import('node:tls');
    return new Promise((resolve) => {
      let settled = false;
      const done = (r: { ok: boolean; authorized: boolean; names: string[]; error?: string }) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(r);
      };
      const socket = tls.connect(
        { host, port, servername, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] },
        () => {
          const cert = socket.getPeerCertificate();
          const cn = (cert?.subject as { CN?: string } | undefined)?.CN;
          const names = [...dnsNamesOfSan(cert?.subjectaltname), ...(cn ? [cn] : [])];
          done({ ok: true, authorized: socket.authorized, names });
        },
      );
      socket.setTimeout(timeoutMs, () =>
        done({ ok: false, authorized: false, names: [], error: 'timeout' }),
      );
      socket.on('error', (err) =>
        done({ ok: false, authorized: false, names: [], error: classifyHandshakeError(err).error }),
      );
    });
  },
  httpsStatus: async ({ host, port, servername, hostHeader, timeoutMs }) => {
    const tls = await import('node:tls');
    return new Promise((resolve) => {
      let settled = false;
      let buffered = '';
      const done = (r: { status: number | null; error?: string }) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(r);
      };
      const socket = tls.connect(
        { host, port, servername, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] },
        () => {
          socket.write(
            `GET / HTTP/1.1\r\nHost: ${hostHeader}\r\nUser-Agent: fcp-origin-probe/1\r\nConnection: close\r\n\r\n`,
          );
        },
      );
      socket.on('data', (chunk: Buffer) => {
        buffered += chunk.toString('latin1');
        const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(buffered);
        if (m) done({ status: Number(m[1]) });
        else if (buffered.length >= 16) done({ status: null, error: 'not_http' });
      });
      socket.on('end', () => done({ status: null, error: 'no_response' }));
      socket.setTimeout(timeoutMs, () => done({ status: null, error: 'timeout' }));
      socket.on('error', (err) => done({ status: null, error: classifyHandshakeError(err).error }));
    });
  },
};

let deps: OriginProbeDeps = defaultDeps;
/** Test seam: run the probe without opening a socket. */
export function __setOriginProbeDepsForTests(d: OriginProbeDeps | null): void {
  deps = d ?? defaultDeps;
}

export const probe = internalAction({
  args: {
    targets: v.array(
      v.object({
        listenerKey: v.string(),
        originAddress: v.string(),
        originPort: v.number(),
        streamTransport: listenerProtoFields.streamTransport,
        security: listenerProtoFields.security,
        tlsNames: v.array(v.string()),
      }),
    ),
    timeoutMs: v.optional(v.number()),
  },
  handler: async (_ctx, { targets, timeoutMs }): Promise<OriginProbeOutcome[]> => {
    const out: OriginProbeOutcome[] = [];
    for (const t of targets) out.push(await probeOriginTransport(deps, t, timeoutMs ?? 6000));
    return out;
  },
});
