'use node';
/**
 * Qualify server names against their family's TARGET (never against a node):
 * one TLS handshake per name, presenting that name, verifying the chain for it
 * and recording the TLS version and ALPN. This is what an unauthenticated
 * prober presenting the name to a REALITY node would be shown, because REALITY
 * forwards such a handshake to the target.
 *
 * The target is operator-supplied, so the dial is guarded like the internal
 * probe: a hostname is resolved, EVERY answer must be public, and the
 * connection goes to one of those verified literals (never to the name again).
 * At most two handshakes a second per run, so a target never sees a scan.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import { runWithCronOutcome } from './cronHeartbeat';
import { isPublicIpLiteral } from './lib/edges/ip';
import { classifyHandshakeError, resolvePublic } from './lib/edges/probes/internal';
import { judgeHandshake, type HandshakeResult } from './lib/edges/sni/family';

const TIMEOUT_MS = 8000;
const GAP_MS = 500;

async function lookup(name: string): Promise<string[]> {
  const dns = await import('node:dns/promises');
  return (await dns.lookup(name, { all: true, verbatim: true })).map((a) => a.address);
}

export async function tlsInspect(args: {
  host: string;
  port: number;
  servername: string;
}): Promise<HandshakeResult> {
  const tls = await import('node:tls');
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: HandshakeResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    const socket = tls.connect(
      {
        host: args.host,
        port: args.port,
        servername: args.servername,
        // Completing the handshake is the point; validity is judged afterwards
        // so a bad certificate is reported as that, not as a transport error.
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
      },
      () =>
        done({
          ok: true,
          authorized: socket.authorized,
          protocol: socket.getProtocol(),
          alpn: socket.alpnProtocol || null,
        }),
    );
    socket.setTimeout(TIMEOUT_MS, () => done({ ok: false, error: 'timeout' }));
    socket.on('error', (err) => done({ ok: false, error: classifyHandshakeError(err).error }));
  });
}

async function dialAddress(
  address: string,
): Promise<{ ok: true; host: string } | { ok: false; error: string }> {
  const literal = /^[0-9.]+$/.test(address) || address.includes(':');
  if (literal)
    return isPublicIpLiteral(address)
      ? { ok: true, host: address }
      : { ok: false, error: 'private_address' };
  const r = await resolvePublic(address, lookup);
  return r.ok ? { ok: true, host: r.addresses[0]! } : { ok: false, error: r.error };
}

export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; ok: number }> =>
    runWithCronOutcome(ctx, 'sni-qualify', async () => {
      const { names } = await ctx.runQuery(internal.sniFamilies.dueForQualification, {});
      let ok = 0;
      const dialled = new Map<string, Awaited<ReturnType<typeof dialAddress>>>();
      for (const n of names) {
        if (!dialled.has(n.address)) dialled.set(n.address, await dialAddress(n.address));
        const at = dialled.get(n.address)!;
        const shake: HandshakeResult = at.ok
          ? await tlsInspect({ host: at.host, port: n.port, servername: n.name })
          : { ok: false, error: at.error };
        const verdict = judgeHandshake(shake, { requireH2: n.requireH2 });
        if (verdict.ok) ok++;
        await ctx.runMutation(internal.sniFamilies.recordQualification, {
          id: n.id,
          ok: verdict.ok,
          code: verdict.code,
          tlsVersion: verdict.tlsVersion,
          alpn: verdict.alpn,
        });
        await new Promise((r) => setTimeout(r, GAP_MS));
      }
      return { checked: names.length, ok };
    }),
});

/** Qualify now (the operator pressed "check"): the same run, on demand. */
export const runNow = internalAction({
  args: { confirm: v.optional(v.boolean()) },
  handler: async (ctx): Promise<{ checked: number; ok: number }> =>
    ctx.runAction(internal.sniQualifyOps.run, {}),
});
