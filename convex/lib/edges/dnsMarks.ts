/**
 * The `DnsMarkStore` an action hands a DNS client: FCP's `dnsRecordMarks`
 * table through internal queries and mutations (convex/dnsRecordMarks.ts).
 */
import { internal } from '../../_generated/api';
import type { ActionCtx } from '../../_generated/server';
import type { DnsMarkStore } from './providers/dns/types';

export function dnsMarkStoreFor(ctx: Pick<ActionCtx, 'runQuery' | 'runMutation'>): DnsMarkStore {
  return {
    async forName(zone, name) {
      return await ctx.runQuery(internal.dnsRecordMarks.forName, { zone, name });
    },
    async set(zone, mark) {
      await ctx.runMutation(internal.dnsRecordMarks.set, {
        zone,
        name: mark.name,
        type: mark.type,
        content: mark.content,
        marker: mark.marker,
      });
    },
    async remove(zone, key) {
      await ctx.runMutation(internal.dnsRecordMarks.remove, {
        zone,
        name: key.name,
        type: key.type,
        content: key.content,
      });
    },
  };
}
