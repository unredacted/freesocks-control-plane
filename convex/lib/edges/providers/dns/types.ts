/**
 * The DNS writer an L7 adapter uses for records that live in ANOTHER provider's
 * zone (a Fastly edge's ACME validation CNAME and traffic CNAME live in a
 * Cloudflare or Gandi zone). Implemented by ./cloudflareDns.ts and
 * ./gandiDns.ts, chosen by the DNS account's provider (./clients.ts); injected
 * so the Fastly adapter and its tests never depend on either directly.
 *
 * Every record FCP writes carries a `comment` marker (the edge's provider-side
 * resource name) so discovery can prove ownership: a record with the right
 * name but a foreign comment/content is never adopted or deleted. Cloudflare
 * stores it on the record; Gandi has no such field, so its client keeps it in
 * FCP's own `dnsRecordMarks` table (`DnsMarkStore`), never in public DNS.
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
  /** Seconds; absent or 1 = automatic (the only value a proxied record takes). */
  ttl?: number;
  /** Extra `name:value` labels (paid zones only). */
  tags?: string[];
  /** Per-record settings: CNAME flattening, one address family for a proxied name. */
  settings?: { flatten_cname?: boolean; ipv4_only?: boolean; ipv6_only?: boolean };
}

/**
 * FCP's private record of which record carries which ownership marker, for a
 * DNS provider whose records cannot hold a comment (Gandi LiveDNS): the
 * `dnsRecordMarks` table, read and written through the action that builds the
 * client. A record is keyed by its zone, name, type and content (normalized).
 */
export interface DnsRecordMark {
  type: DnsRecordType;
  /** Fully qualified, lowercase. */
  name: string;
  content: string;
  marker: string;
}
export interface DnsMarkStore {
  forName(zone: string, name: string): Promise<DnsRecordMark[]>;
  /** Upsert by (zone, name, type, content). */
  set(zone: string, mark: DnsRecordMark): Promise<void>;
  /** Idempotent. */
  remove(zone: string, key: Omit<DnsRecordMark, 'marker'>): Promise<void>;
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
  /**
   * Change a record's content in place (a moved name: deleting then creating
   * would leave a moment with no record, which a resolver can cache for the
   * zone's negative TTL). Optional: a client without it cannot move a name.
   */
  updateRecord?(id: string, args: DnsCreateArgs): Promise<DnsRecord>;
  /** CAA records at the zone apex (issuance preflight); empty = unrestricted. */
  listCaa(): Promise<Array<{ flags: number; tag: string; value: string }>>;
  /**
   * Whether the zone answers EVERY CNAME flattened (Cloudflare's zone setting
   * `cname_flattening: flatten_all`): a certificate authority looking up a
   * validation CNAME then finds the target's addresses (none) instead, and
   * issuance never completes. `null` when the credentials may not read it.
   * Optional: a client without the setting has nothing to say.
   */
  flattensAllCnames?(): Promise<boolean | null>;
  /** The zone itself as these credentials read it (a location check, a rotation's reach check). */
  readZone(): Promise<{
    id: string;
    name: string;
    status: string;
    paused: boolean;
    /** The zone's plan (Cloudflare `legacy_id`, e.g. `free`): what its records may carry. */
    plan?: string;
  }>;
}
