'use node';
/**
 * The one place a DNS client is chosen: by the DNS account's provider. Every
 * writer of FCP's DNS records (the Fastly and CloudFront fronts, origin names,
 * address names, a credential rotation's reach check) builds its client here.
 */
import type { DnsProviderId, DnsZoneConfig } from '../types';
import { cloudflareDnsClient } from './cloudflareDns';
import { gandiDnsClient } from './gandiDns';
import type { DnsClient } from './types';

export const DNS_PROVIDER_IDS = ['cloudflare', 'gandi'] as const satisfies readonly DnsProviderId[];

export function isDnsProviderId(v: unknown): v is DnsProviderId {
  return typeof v === 'string' && (DNS_PROVIDER_IDS as readonly string[]).includes(v);
}

/** The client for a zone; null for a provider that holds no DNS records. */
export function dnsClientForProvider(provider: string, cfg: DnsZoneConfig): DnsClient | null {
  if (!isDnsProviderId(provider)) return null;
  return dnsClientForZone({ ...cfg, provider });
}

export function dnsClientForZone(cfg: DnsZoneConfig): DnsClient {
  const provider: DnsProviderId = cfg.provider ?? 'cloudflare';
  switch (provider) {
    case 'cloudflare':
      return cloudflareDnsClient(cfg);
    case 'gandi':
      return gandiDnsClient(cfg);
  }
}
