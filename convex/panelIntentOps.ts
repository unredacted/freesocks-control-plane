'use node';
/**
 * The node-runtime half of node intents: origin DNS records through the
 * Cloudflare client (obligations persisted before every call, discovery by
 * name and marker after an uncertain one), public resolution, and the front
 * ingress check (TLS to the origin name, the WebSocket path answered, a
 * foreign Host answered). Nothing here writes a workflow row directly: every
 * outcome goes through the fenced mutations in panelIntents.ts.
 */
import { promises as dns } from 'node:dns';
import * as https from 'node:https';
import * as tls from 'node:tls';
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { cloudflareDnsClient } from './lib/edges/providers/dns/cloudflareDns';
import type { DnsClient } from './lib/edges/providers/dns/types';
import {
  originMarker,
  planRecord,
  verifyResolution,
  type DesiredRecord,
} from './lib/panel/originDns';

const fence = { intentId: v.id('panelNodeIntents'), generation: v.number(), attemptId: v.string() };

type DnsClientFactory = (cfg: {
  apiToken: string;
  zoneId: string;
  zoneName: string;
  accountId: string;
}) => DnsClient;
let dnsFactory: DnsClientFactory = cloudflareDnsClient;
/** Test seam: an in-memory DnsClient. */
export function __setDnsClientFactoryForTests(f: DnsClientFactory | null): void {
  dnsFactory = f ?? cloudflareDnsClient;
}

/**
 * Ensure the A (and, when published, AAAA) record of a front node's origin
 * name. Per record: an obligation is opened before the call; a conflict at
 * the name (a foreign record, a CNAME) is reported, never replaced; FCP's own
 * record with other content is replaced (delete, then create, each its own
 * obligation step); an uncertain answer leaves the obligation unresolved and
 * the next run discovers by name + marker before anything is sent again.
 */
export const ensureOriginDns = internalAction({
  args: fence,
  handler: async (
    ctx,
    f,
  ): Promise<{ state: 'created' | 'kept' | 'conflict' | 'unresolved' | 'none' }> => {
    const c = await ctx.runQuery(internal.panelIntents.loadForRun, f);
    if (!c) return { state: 'none' };
    const zone = c.setup.originDns;
    if (!zone || c.intent.settings.originHostnameSource !== 'managed' || !c.hostname)
      return { state: 'none' };
    const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
      id: zone.accountId,
    });
    const apiToken = (acct?.credentials as { apiToken?: string } | undefined)?.apiToken;
    if (!acct || !apiToken) {
      await ctx.runMutation(internal.panelIntents.progress, {
        ...f,
        patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'conflict' } },
      });
      return { state: 'conflict' };
    }
    const client = dnsFactory({
      apiToken,
      zoneId: zone.zoneId,
      zoneName: zone.zoneName,
      accountId: zone.accountId,
    });
    const marker = originMarker(c.server.slug, c.intent.name);
    const desired: DesiredRecord[] = [];
    if (c.intent.observed.publicIps.v4)
      desired.push({ type: 'A', name: c.hostname, content: c.intent.observed.publicIps.v4 });
    if (c.intent.settings.publishV6 && c.intent.observed.publicIps.v6)
      desired.push({ type: 'AAAA', name: c.hostname, content: c.intent.observed.publicIps.v6 });
    if (desired.length === 0) return { state: 'none' };

    let created = false;
    for (const d of desired) {
      const identity = `${d.type}:${d.name}`;
      // Discovery FIRST: it settles the previous attempt on this identity, if any.
      const existing = await client.findRecordsByName(d.name);
      const blocking = await ctx.runQuery(internal.panelObligations.blockingFor, {
        backendServerId: c.server._id,
        kind: 'dns.record',
        identity,
      });
      const plan = planRecord(existing, d, marker);
      if (blocking) {
        const mine = existing.find((r) => r.type === d.type && r.comment === marker);
        if (mine) {
          await ctx.runMutation(internal.panelObligations.mark, {
            id: blocking._id,
            state: 'confirmed',
            resourceRef: mine.id,
            recordId: mine.id,
          });
        } else if (plan.action === 'conflict') {
          await ctx.runMutation(internal.panelObligations.mark, {
            id: blocking._id,
            state: 'failed',
            code: `servers.origin_name_taken:${plan.reason}`,
          });
        } else return { state: 'unresolved' };
      }
      if (plan.action === 'conflict') {
        await ctx.runMutation(internal.panelIntents.progress, {
          ...f,
          patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'conflict' } },
        });
        return { state: 'conflict' };
      }
      if (plan.action === 'keep') continue;
      if (plan.action === 'replace') {
        const del = await ctx.runMutation(internal.panelObligations.open, {
          backendServerId: c.server._id,
          ownerKind: 'intent',
          ownerId: f.intentId,
          ownerGeneration: f.generation,
          attemptId: f.attemptId,
          kind: 'dns.record',
          identity,
          verb: 'delete',
          ownership: 'created',
          intent: JSON.stringify({ ...d, deleteId: plan.deleteId }),
          dns: { ...zone, marker, recordId: plan.deleteId },
        });
        if (!del.ok) return { state: 'unresolved' };
        await ctx.runMutation(internal.panelObligations.mark, { id: del.id, state: 'sent' });
        try {
          await client.deleteRecord(plan.deleteId);
          await ctx.runMutation(internal.panelObligations.mark, { id: del.id, state: 'confirmed' });
        } catch {
          await ctx.runMutation(internal.panelObligations.mark, {
            id: del.id,
            state: 'unresolved',
          });
          return { state: 'unresolved' };
        }
      }
      const ob = await ctx.runMutation(internal.panelObligations.open, {
        backendServerId: c.server._id,
        ownerKind: 'intent',
        ownerId: f.intentId,
        ownerGeneration: f.generation,
        attemptId: f.attemptId,
        kind: 'dns.record',
        identity,
        verb: 'create',
        ownership: 'created',
        intent: JSON.stringify(d),
        dns: { ...zone, marker },
      });
      if (!ob.ok) return { state: 'unresolved' };
      await ctx.runMutation(internal.panelObligations.mark, { id: ob.id, state: 'sent' });
      try {
        const rec = await client.createRecord({ ...d, proxied: false, comment: marker });
        await ctx.runMutation(internal.panelObligations.mark, {
          id: ob.id,
          state: 'confirmed',
          resourceRef: rec.id,
          recordId: rec.id,
        });
        created = true;
      } catch {
        await ctx.runMutation(internal.panelObligations.mark, { id: ob.id, state: 'unresolved' });
        return { state: 'unresolved' };
      }
    }
    await ctx.runMutation(internal.panelIntents.progress, {
      ...f,
      patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'created' } },
    });
    return { state: created ? 'created' : 'kept' };
  },
});

/** Delete the origin records an intent's obligations own (retirement). Ownership re-checked first. */
export const withdrawOriginDns = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<{ removed: number; unresolved: number }> => {
    const rows = await ctx.runQuery(internal.panelObligations.listForOwner, {
      ownerKind: 'intent',
      ownerId: intentId,
    });
    let removed = 0;
    let unresolved = 0;
    for (const o of rows) {
      if (
        o.kind !== 'dns.record' ||
        o.verb !== 'create' ||
        o.state !== 'confirmed' ||
        !o.dns?.recordId
      )
        continue;
      const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
        id: o.dns.accountId as Id<'edgeProviderAccounts'>,
      });
      const apiToken = (acct?.credentials as { apiToken?: string } | undefined)?.apiToken;
      if (!apiToken) {
        unresolved++;
        continue;
      }
      // Cleanup uses the obligation's own account and zone, never the setup's current one.
      const client = dnsFactory({
        apiToken,
        zoneId: o.dns.zoneId,
        zoneName: o.dns.zoneName,
        accountId: o.dns.accountId,
      });
      const rec = await client.getRecord(o.dns.recordId);
      if (rec && rec.comment !== o.dns.marker) {
        unresolved++;
        continue;
      }
      try {
        await client.deleteRecord(o.dns.recordId);
        await ctx.runMutation(internal.panelObligations.mark, {
          id: o._id,
          state: 'failed',
          code: 'withdrawn',
        });
        removed++;
      } catch {
        unresolved++;
      }
    }
    return { removed, unresolved };
  },
});

async function resolveBoth(name: string): Promise<{ v4: string[]; v6: string[] }> {
  const [v4, v6] = await Promise.all([
    dns.resolve4(name).catch(() => [] as string[]),
    dns.resolve6(name).catch(() => [] as string[]),
  ]);
  return { v4, v6 };
}

function tlsCheck(
  host: string,
  port: number,
  servername: string,
): Promise<{ valid: boolean; names: string[] }> {
  return new Promise((resolve) => {
    const s = tls.connect(
      { host, port, servername, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = s.getPeerCertificate();
        const names = String(cert?.subjectaltname ?? '')
          .split(',')
          .map((x) => x.trim().replace(/^DNS:/i, '').toLowerCase())
          .filter(Boolean);
        resolve({
          valid: s.authorized === true && names.includes(servername.toLowerCase()),
          names,
        });
        s.end();
      },
    );
    s.on('error', () => resolve({ valid: false, names: [] }));
    s.on('timeout', () => {
      s.destroy();
      resolve({ valid: false, names: [] });
    });
  });
}

function httpsStatus(
  host: string,
  port: number,
  servername: string,
  hostHeader: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<number | null> {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host,
        port,
        servername,
        path,
        method: 'GET',
        headers: { host: hostHeader, ...headers },
        rejectUnauthorized: false,
        timeout: 8000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? null);
      },
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

/**
 * The external hop of a front node, as the world sees it: the name resolves
 * to the intended addresses, TLS presents a publicly valid certificate naming
 * it, the WebSocket path is proxied (an upgrade attempt is answered by the
 * inbound, not the decoy's 404), and a foreign Host header is answered.
 */
export const checkFrontIngress = internalAction({
  args: {
    hostname: v.string(),
    port: v.number(),
    path: v.string(),
    expected: v.object({ v4: v.union(v.string(), v.null()), v6: v.union(v.string(), v.null()) }),
  },
  handler: async (_ctx, a) => {
    const answers = await resolveBoth(a.hostname);
    const resolves = verifyResolution(answers, a.expected);
    const dial = a.expected.v4 ?? answers.v4[0] ?? a.hostname;
    const cert = await tlsCheck(dial, a.port, a.hostname);
    const upgrade = await httpsStatus(dial, a.port, a.hostname, a.hostname, a.path, {
      connection: 'Upgrade',
      upgrade: 'websocket',
      'sec-websocket-version': '13',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
    });
    const foreign = await httpsStatus(
      dial,
      a.port,
      'foreign-host.invalid',
      'foreign-host.invalid',
      '/',
    );
    return {
      resolves,
      answers,
      tlsValid: cert.valid,
      certNames: cert.names,
      // Xray answers a WebSocket handshake with 101 (or 400 for a bad one); the decoy answers 404.
      pathProxied: upgrade === 101 || upgrade === 400,
      foreignHostAnswered: foreign !== null && foreign < 500,
    };
  },
});
