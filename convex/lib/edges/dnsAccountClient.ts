'use node';
/**
 * A DNS client for one zone of a DNS account, built from the account row: its
 * provider picks the client (`providers/dns/clients.ts`), its token signs the
 * calls, and the client gets FCP's private mark store (a provider whose
 * records hold no comment keeps its ownership markers there). Null when the
 * account is gone, has no token, or is not a DNS provider's.
 */
import { internal } from '../../_generated/api';
import type { ActionCtx } from '../../_generated/server';
import type { Id } from '../../_generated/dataModel';
import { dnsClientForProvider } from './providers/dns/clients';
import type { DnsClient } from './providers/dns/types';
import { dnsMarkStoreFor } from './dnsMarks';

export async function dnsClientForAccount(
  ctx: ActionCtx,
  accountId: string,
  zone: { zoneId: string; zoneName: string },
): Promise<DnsClient | null> {
  const acct = await ctx.runQuery(internal.edgeProviderAccounts.getWithSecret, {
    id: accountId as Id<'edgeProviderAccounts'>,
  });
  const apiToken = (acct?.credentials as { apiToken?: string } | undefined)?.apiToken;
  if (!acct || !apiToken) return null;
  return dnsClientForProvider(acct.provider, {
    apiToken,
    zoneId: zone.zoneId,
    zoneName: zone.zoneName,
    accountId,
    marks: dnsMarkStoreFor(ctx),
  });
}
