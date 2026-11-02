'use node';
/**
 * Names for load balancer addresses: the DNS calls (edgeNames.ts is the DB
 * half). One pass = claim (`edgeNames.begin`), read the name back from its
 * zone, write only what differs from what it should hold, settle. Discovery
 * comes first on every pass, so a pass whose answer was lost is settled by
 * what the zone holds (FCP's records carry the name's marker), never by a
 * second blind create.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { cloudflareDnsClient } from './lib/edges/providers/dns/cloudflareDns';
import type { DnsClient, DnsRecord } from './lib/edges/providers/dns/types';
import { EdgeProviderError } from './lib/edges/providers/http';
import { ADDRESS_NAME_TTL_S, planNameRecords } from './lib/edges/addressNames';
import type { NameOrder } from './edgeNames';

type Outcome =
  | { kind: 'done'; records: Array<{ type: 'A' | 'AAAA'; recordId: string; content: string }> }
  | { kind: 'conflict'; reason: string }
  | { kind: 'failed'; code: string; final: boolean };
type Zone = { apiToken: string; zoneId: string; zoneName: string; accountId: string };
type ClientFactory = (provider: string, zone: Zone) => DnsClient | null;

const realFactory: ClientFactory = (provider, zone) =>
  provider === 'cloudflare' ? cloudflareDnsClient(zone) : null;
let factory: ClientFactory = realFactory;

/** Test seam: the DNS client a name's zone is written through. */
export function __setAddressNameDnsFactory(f: ClientFactory | null): void {
  factory = f ?? realFactory;
}

/** One pass over a name (by id), or for an address that wants one (by edge id). */
export const work = internalAction({
  args: { nameId: v.optional(v.id('edgeNames')), edgeId: v.optional(v.id('edges')) },
  handler: async (ctx, a): Promise<string> => {
    const order: NameOrder = await ctx.runMutation(internal.edgeNames.begin, a);
    if (order.kind !== 'order') return order.kind;
    const settle = (outcome: Outcome) =>
      ctx.runMutation(internal.edgeNames.settle, {
        nameId: order.nameId,
        opId: order.opId,
        outcome,
      });
    const client = await clientFor(ctx, order.zone);
    if (!client) {
      await settle({ kind: 'failed', code: 'name_zone_unreachable', final: true });
      return 'failed';
    }
    try {
      const existing = await client.findRecordsByName(order.fqdn);
      if (order.desired.length === 0) {
        // Removing: FCP's own records go; anything else at the name is not ours.
        for (const r of existing) if (r.comment === order.marker) await client.deleteRecord(r.id);
        const left = (await client.findRecordsByName(order.fqdn)).filter(
          (r) => r.comment === order.marker,
        );
        await settle({ kind: 'done', records: left.map(asRecord).filter(isAddressRecord) });
        return left.length === 0 ? 'removed' : 'pending';
      }
      const plan = planNameRecords(existing, order.desired, order.marker, order.fqdn);
      if (plan.kind === 'conflict') {
        await settle({ kind: 'conflict', reason: plan.reason });
        return 'conflict';
      }
      const records = plan.kept.map((k) => ({ type: k.type, recordId: k.id, content: k.content }));
      for (const step of plan.steps) {
        if (step.action === 'delete') {
          await client.deleteRecord(step.id);
          continue;
        }
        const args = {
          ...step.record,
          proxied: false,
          ttl: ADDRESS_NAME_TTL_S,
          comment: order.marker,
        };
        let rec: DnsRecord;
        if (step.action === 'update' && client.updateRecord) {
          rec = await client.updateRecord(step.id, args);
        } else {
          if (step.action === 'update') await client.deleteRecord(step.id);
          rec = await client.createRecord(args);
        }
        records.push({ type: step.record.type, recordId: rec.id, content: step.record.content });
      }
      await settle({ kind: 'done', records });
      return 'done';
    } catch (err) {
      await settle({ kind: 'failed', code: codeOf(err), final: false });
      return 'failed';
    }
  },
});

function asRecord(r: DnsRecord): { type: string; recordId: string; content: string } {
  return { type: r.type, recordId: r.id, content: r.content };
}

function isAddressRecord(r: {
  type: string;
  recordId: string;
  content: string;
}): r is { type: 'A' | 'AAAA'; recordId: string; content: string } {
  return r.type === 'A' || r.type === 'AAAA';
}

/** The zone's DNS client through the DNS account's own credentials (null: unusable now). */
async function clientFor(
  ctx: ActionCtx,
  zone: { dnsAccountId: Id<'edgeProviderAccounts'>; zoneId: string; zoneName: string },
): Promise<DnsClient | null> {
  const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
    id: zone.dnsAccountId,
  });
  const apiToken = (acct?.credentials as { apiToken?: string } | undefined)?.apiToken;
  if (!acct || !apiToken) return null;
  return factory(acct.provider, {
    apiToken,
    zoneId: zone.zoneId,
    zoneName: zone.zoneName,
    accountId: zone.dnsAccountId,
  });
}

/** A short code for a failed call, from the provider's status (never its words). */
function codeOf(err: unknown): string {
  const status = err instanceof EdgeProviderError ? err.meta.status : undefined;
  if (status === 401 || status === 403) return 'name_dns_refused';
  if (status === 429) return 'name_dns_rate_limited';
  if (status !== undefined && status >= 400 && status < 500) return 'name_dns_refused';
  return 'name_dns_unreachable';
}
