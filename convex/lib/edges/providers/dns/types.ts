/**
 * The DNS writer an L7 adapter uses for records that live in ANOTHER provider's
 * zone (a Fastly edge's ACME validation CNAME and traffic CNAME live in a
 * Cloudflare zone). Implemented by ./cloudflareDns.ts; injected so the Fastly
 * adapter and its tests never depend on the Cloudflare SDK directly.
 *
 * Every record FCP writes carries a `comment` marker (the edge's provider-side
 * resource name) so discovery can prove ownership: a record with the right
 * name but a foreign comment/content is never adopted or deleted.
 */
export type DnsRecordType = 'A' | 'AAAA' | 'CNAME';

export interface DnsRecord {
  id: string;
  type: DnsRecordType;
  /** Fully qualified, lowercase. */
  name: string;
  content: string;
  proxied: boolean;
  comment?: string;
}

export interface DnsCreateArgs {
  type: DnsRecordType;
  name: string;
  content: string;
  proxied: boolean;
  /** Ownership marker (≤100 chars on every plan). */
  comment: string;
}

export interface DnsClient {
  /** The zone the client writes into (recorded in every DNS ledger resource's meta). */
  readonly zoneId: string;
  readonly zoneName: string;
  readonly accountId: string;
  createRecord(args: DnsCreateArgs): Promise<DnsRecord>;
  /** Records with exactly this name (and type when given); one request, no pagination. */
  findRecordsByName(name: string, type?: DnsRecordType): Promise<DnsRecord[]>;
  /** null when the record is gone. */
  getRecord(id: string): Promise<DnsRecord | null>;
  /** Idempotent: a missing record is a success. */
  deleteRecord(id: string): Promise<void>;
  /** CAA records at the zone apex (issuance preflight); empty = unrestricted. */
  listCaa(): Promise<Array<{ flags: number; tag: string; value: string }>>;
}
