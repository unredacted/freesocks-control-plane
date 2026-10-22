'use node';
/**
 * The node-runtime half of node intents: origin DNS records through the
 * Cloudflare client (obligations persisted before every call, discovery by
 * name and marker after an uncertain one), public resolution, and the front
 * ingress check (TLS to the origin name, the WebSocket path answered, a
 * foreign Host answered). Nothing here writes a workflow row directly: every
 * outcome goes through the fenced mutations in nodeIntents.ts.
 */
import { promises as dns } from 'node:dns';
import * as https from 'node:https';
import * as tls from 'node:tls';
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { cloudflareDnsClient } from './lib/edges/providers/dns/cloudflareDns';
import { CLAIM_LEASE_MS } from './lib/backend/fencing';
import { blocksIdentity } from './lib/backend/obligations';
import {
  originMarker,
  planRecord,
  verifyResolution,
  type DesiredRecord,
} from './lib/backend/originDns';

const fence = { intentId: v.id('panelNodeIntents'), generation: v.number(), attemptId: v.string() };

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
    const c = await ctx.runQuery(internal.nodeIntents.loadForRun, f);
    if (!c) return { state: 'none' };
    const zone = c.setup.originDns;
    const managed = !!zone && c.intent.settings.originHostnameSource === 'managed' && !!c.hostname;
    // The marker names the node as it was enrolled: a rename never makes FCP's
    // own record read as somebody else's.
    const marker = originMarker(c.server.slug, c.intent.formerNames?.[0] ?? c.intent.name);
    const desired: DesiredRecord[] = [];
    if (managed && c.intent.observed.publicIps.v4)
      desired.push({ type: 'A', name: c.hostname!, content: c.intent.observed.publicIps.v4 });
    if (managed && c.intent.settings.publishV6 && c.intent.observed.publicIps.v6)
      desired.push({ type: 'AAAA', name: c.hostname!, content: c.intent.observed.publicIps.v6 });

    // A record FCP owns that is no longer desired (v6 withdrawn, an address
    // family gone from the observations, the node given a hostname of its
    // own) is deleted first, so what resolves is exactly what is desired.
    const owned = await ctx.runQuery(internal.backendObligations.listForOwner, {
      ownerKind: 'intent',
      ownerId: f.intentId,
    });
    let withdrawn = false;
    for (const o of owned) {
      if (!ownsRecord(o) || desired.some((d) => `${d.type}:${d.name}` === o.identity)) continue;
      if ((await withdrawRecord(ctx, o)) === 'unresolved') return { state: 'unresolved' };
      withdrawn = true;
    }
    if (!managed) {
      if (withdrawn)
        await ctx.runMutation(internal.nodeIntents.progress, {
          ...f,
          patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'none' } },
        });
      return { state: 'none' };
    }
    const z = zone!;
    const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
      id: z.accountId,
    });
    const apiToken = (acct?.credentials as { apiToken?: string } | undefined)?.apiToken;
    if (!acct || !apiToken) {
      await ctx.runMutation(internal.nodeIntents.progress, {
        ...f,
        patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'conflict' } },
      });
      return { state: 'conflict' };
    }
    const client = cloudflareDnsClient({
      apiToken,
      zoneId: z.zoneId,
      zoneName: z.zoneName,
      accountId: z.accountId,
    });
    if (desired.length === 0) return { state: 'none' };

    let created = false;
    for (const d of desired) {
      const identity = `${d.type}:${d.name}`;
      // Discovery FIRST: it settles the previous attempt on this identity, if any.
      const existing = await client.findRecordsByName(d.name);
      const blocking = await ctx.runQuery(internal.backendObligations.blockingFor, {
        backendServerId: c.server._id,
        kind: 'dns.record',
        identity,
      });
      const plan = planRecord(existing, d, marker);
      if (blocking) {
        const mine = existing.find((r) => r.type === d.type && r.comment === marker);
        const settle = (patch: {
          state: 'confirmed' | 'failed';
          code?: string;
          recordId?: string;
        }) =>
          ctx.runMutation(internal.backendObligations.mark, {
            id: blocking._id,
            ...patch,
            ...(patch.recordId ? { resourceRef: patch.recordId } : {}),
          });
        if (blocking.verb === 'delete') {
          // A delete whose answer was lost: the record's ABSENCE is its
          // postcondition; its presence means the delete never applied (a
          // fresh delete may run, the same action after discovery).
          if (mine && mine.id === blocking.dns?.recordId)
            await settle({ state: 'failed', code: 'servers.delete_not_applied' });
          else await settle({ state: 'confirmed' });
        } else if (mine) {
          await settle({ state: 'confirmed', recordId: mine.id });
        } else if (plan.action === 'conflict') {
          await settle({ state: 'failed', code: `servers.origin_name_taken:${plan.reason}` });
        } else {
          // A create whose answer was lost and whose record the zone does not
          // hold (the listing is read-after-write): it never landed. Settled,
          // so a fresh create may run; never a second create on an unknown.
          await settle({ state: 'failed', code: 'servers.create_not_observed' });
        }
      }
      if (plan.action === 'conflict') {
        await ctx.runMutation(internal.nodeIntents.progress, {
          ...f,
          patch: { origin: { hostname: c.hostname, address: c.originAddress, dns: 'conflict' } },
        });
        return { state: 'conflict' };
      }
      if (plan.action === 'keep') continue;
      if (plan.action === 'replace') {
        const del = await ctx.runMutation(internal.backendObligations.open, {
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
          dns: { ...z, marker, recordId: plan.deleteId },
        });
        if (!del.ok) return { state: 'unresolved' };
        await ctx.runMutation(internal.backendObligations.mark, { id: del.id, state: 'sent' });
        try {
          await client.deleteRecord(plan.deleteId);
          await ctx.runMutation(internal.backendObligations.mark, {
            id: del.id,
            state: 'confirmed',
          });
          // The create obligation that owned the replaced record is settled
          // with it: retirement must not try to delete a record twice.
          for (const o of owned)
            if (ownsRecord(o) && o.dns?.recordId === plan.deleteId)
              await ctx.runMutation(internal.backendObligations.mark, {
                id: o._id,
                state: 'failed',
                code: 'replaced',
              });
        } catch {
          await ctx.runMutation(internal.backendObligations.mark, {
            id: del.id,
            state: 'unresolved',
          });
          return { state: 'unresolved' };
        }
      }
      const ob = await ctx.runMutation(internal.backendObligations.open, {
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
        dns: { ...z, marker },
      });
      if (!ob.ok) return { state: 'unresolved' };
      await ctx.runMutation(internal.backendObligations.mark, { id: ob.id, state: 'sent' });
      try {
        const rec = await client.createRecord({ ...d, proxied: false, comment: marker });
        await ctx.runMutation(internal.backendObligations.mark, {
          id: ob.id,
          state: 'confirmed',
          resourceRef: rec.id,
          recordId: rec.id,
        });
        created = true;
      } catch {
        await ctx.runMutation(internal.backendObligations.mark, { id: ob.id, state: 'unresolved' });
        return { state: 'unresolved' };
      }
    }
    // Proof that the name resolves holds while FCP's records stay what they
    // were when it was taken: every role run reconciles again, and a kept
    // record never sends the node back to `created` (the role waits on
    // `resolves`). A record written or withdrawn here asks for it again.
    const proven =
      !created &&
      !withdrawn &&
      c.intent.origin.dns === 'resolves' &&
      c.intent.origin.hostname === c.hostname;
    await ctx.runMutation(internal.nodeIntents.progress, {
      ...f,
      patch: {
        origin: {
          hostname: c.hostname,
          address: c.originAddress,
          dns: proven ? 'resolves' : 'created',
        },
      },
    });
    return { state: created ? 'created' : 'kept' };
  },
});

type Obligation = Doc<'backendObligations'>;

/** A confirmed create obligation holding a record id: FCP owns that record. */
function ownsRecord(o: Obligation): boolean {
  return (
    o.kind === 'dns.record' && o.verb === 'create' && o.state === 'confirmed' && !!o.dns?.recordId
  );
}

/**
 * The client an obligation's record is reached with: in the obligation's OWN
 * zone, through its own account or, once that account is gone (another account
 * holding the same zone replaced it, and it was removed), through the account
 * the backend's setup uses for that zone now. Whichever account wrote a
 * record, the marker is what makes it FCP's.
 */
async function clientFor(ctx: ActionCtx, o: Obligation) {
  const d = o.dns!;
  const tokenOf = async (id: string) =>
    (
      (
        await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
          id: id as Id<'edgeProviderAccounts'>,
        })
      )?.credentials as { apiToken?: string } | undefined
    )?.apiToken;
  let accountId: string = d.accountId;
  let apiToken = await tokenOf(accountId);
  if (!apiToken) {
    const now = await ctx.runQuery(internal.nodeIntents.originZoneOf, {
      backendServerId: o.backendServerId,
    });
    if (!now || now.zoneId !== d.zoneId) return null;
    accountId = now.accountId;
    apiToken = await tokenOf(accountId);
  }
  if (!apiToken) return null;
  return cloudflareDnsClient({ apiToken, zoneId: d.zoneId, zoneName: d.zoneName, accountId });
}

/**
 * Delete a record an obligation owns. Ownership (the marker) is re-checked in
 * the obligation's OWN zone (`clientFor`), never the setup's current one; a
 * record already gone counts as withdrawn.
 */
async function withdrawRecord(ctx: ActionCtx, o: Obligation): Promise<'removed' | 'unresolved'> {
  const d = o.dns!;
  const client = await clientFor(ctx, o);
  if (!client) return 'unresolved';
  const rec = await client.getRecord(d.recordId!);
  if (rec && rec.comment !== d.marker) return 'unresolved';
  if (rec) {
    try {
      await client.deleteRecord(d.recordId!);
    } catch {
      return 'unresolved';
    }
  }
  await ctx.runMutation(internal.backendObligations.mark, {
    id: o._id,
    state: 'failed',
    code: 'withdrawn',
  });
  return 'removed';
}

/**
 * A record write whose outcome was never settled (its attempt died, or its
 * answer was lost): whatever landed under the name with FCP's marker is
 * deleted, and the write is settled as withdrawn.
 */
async function withdrawUnsettled(ctx: ActionCtx, o: Obligation): Promise<'removed' | 'unresolved'> {
  const client = await clientFor(ctx, o);
  if (!client) return 'unresolved';
  const want = JSON.parse(o.intent) as { type: string; name: string };
  try {
    for (const r of await client.findRecordsByName(want.name))
      if (r.type === want.type && r.comment === o.dns!.marker) await client.deleteRecord(r.id);
  } catch {
    return 'unresolved';
  }
  await ctx.runMutation(internal.backendObligations.mark, {
    id: o._id,
    state: 'failed',
    code: 'withdrawn',
  });
  return 'removed';
}

/**
 * Delete the origin records an intent's obligations own (retirement). Ownership
 * re-checked first. A record write still outstanding may land yet: it is
 * waited for while the attempt that opened it can still be running (a lease),
 * then looked for by name and marker and withdrawn if it landed. The node is
 * retiring, so no attempt opens another one.
 */
export const withdrawOriginDns = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<{ removed: number; unresolved: number }> => {
    const rows = await ctx.runQuery(internal.backendObligations.listForOwner, {
      ownerKind: 'intent',
      ownerId: intentId,
    });
    let removed = 0;
    let unresolved = 0;
    for (const o of rows) {
      let out: 'removed' | 'unresolved' | null = null;
      if (ownsRecord(o)) out = await withdrawRecord(ctx, o);
      else if (o.kind === 'dns.record' && o.dns && blocksIdentity(o))
        out =
          Date.now() - o.updatedAt < CLAIM_LEASE_MS
            ? 'unresolved'
            : await withdrawUnsettled(ctx, o);
      if (out === 'removed') removed++;
      else if (out === 'unresolved') unresolved++;
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

/**
 * The origin name as public resolvers answer it, against the addresses FCP's
 * records hold: DNS only, nothing dialled. The role sets the machine up (an
 * ACME certificate needs the name) only once FCP says the name resolves, and
 * reports applied after that, so this is proved before the applied report;
 * the full ingress check (`checkFrontIngress`) follows the report.
 */
export interface OriginResolution {
  resolves: boolean;
  answers: { v4: string[]; v6: string[] };
}
type OriginResolver = (a: {
  hostname: string;
  expected: { v4: string | null; v6: string | null };
}) => Promise<OriginResolution>;
let originResolver: OriginResolver | null = null;
/** Test seam: answer the origin name's resolution without DNS (null = the real lookup). */
export function __setOriginResolutionForTests(f: OriginResolver | null): void {
  originResolver = f;
}

export const checkOriginResolves = internalAction({
  args: {
    hostname: v.string(),
    expected: v.object({ v4: v.union(v.string(), v.null()), v6: v.union(v.string(), v.null()) }),
  },
  handler: async (_ctx, a): Promise<OriginResolution> => {
    if (originResolver) return originResolver(a);
    const answers = await resolveBoth(a.hostname);
    return { resolves: verifyResolution(answers, a.expected), answers };
  },
});

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
    // A transport that ACCEPTS the WebSocket handshake answers 101: Node hands
    // that to 'upgrade' (never 'response'), and without a listener it destroys
    // the socket and only emits 'close', taking the timeout with it. The check
    // then never returned and held the node's reconcile forever.
    req.on('upgrade', (res, socket) => {
      socket.destroy();
      resolve(res.statusCode ?? null);
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    // Last resort: whatever closed the request without an answer is no answer
    // (a settled promise ignores a later resolve).
    req.on('close', () => resolve(null));
    req.end();
  });
}

/**
 * The external hop of a front node, as the world sees it: the name resolves
 * to the intended addresses, TLS presents a publicly valid certificate naming
 * it, the WebSocket path is proxied (an upgrade attempt is answered by the
 * transport, not the decoy's 404), and a foreign Host header is answered.
 */
export interface FrontIngressCheck {
  resolves: boolean;
  answers: { v4: string[]; v6: string[] };
  tlsValid: boolean;
  certNames: string[];
  pathProxied: boolean;
  foreignHostAnswered: boolean;
}
type FrontIngressChecker = (a: {
  hostname: string;
  port: number;
  path: string;
  expected: { v4: string | null; v6: string | null };
}) => Promise<FrontIngressCheck>;
let ingressChecker: FrontIngressChecker | null = null;
/** Test seam: answer the external-hop check without DNS or sockets (null = the real check). */
export function __setFrontIngressCheckForTests(f: FrontIngressChecker | null): void {
  ingressChecker = f;
}

export const checkFrontIngress = internalAction({
  args: {
    hostname: v.string(),
    port: v.number(),
    path: v.string(),
    expected: v.object({ v4: v.union(v.string(), v.null()), v6: v.union(v.string(), v.null()) }),
  },
  handler: async (_ctx, a): Promise<FrontIngressCheck> => {
    if (ingressChecker) return ingressChecker(a);
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
