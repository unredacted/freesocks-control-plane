'use node';
/**
 * Gandi LiveDNS (API v5) as a `DnsClient`: a hand-rolled client on
 * `providerFetch` (no transport retries, redirects refused, bodies capped,
 * errors reduced to a status and a short code). There is no maintained Gandi
 * SDK for JavaScript; the API is small enough that one would add nothing.
 * Source: https://api.gandi.net/docs/livedns/ and /docs/authentication/, 2026-11-08.
 *
 * How LiveDNS differs from Cloudflare, and what this client does about it:
 *  - Records are RRsets: one (name, type) holds a list of values, and nothing
 *    has an id. A record here is ONE value of an RRset, and its id is
 *    `<type>|<fqdn>|<value>` (deterministic: a lost answer is found again by
 *    what it holds). A value joins an RRset through PATCH `add_rrset_values`
 *    and leaves it through `remove_rrset_values`; an update does both in one
 *    PATCH, so a moved name never has a moment with no record.
 *  - Records carry no comment. FCP's ownership marker is kept PRIVATELY, in
 *    FCP's own `dnsRecordMarks` table through the `DnsMarkStore` the caller
 *    passes: never as a TXT record or anything else a resolver could read,
 *    since a public marker would link front names to one operator. The mark is
 *    written BEFORE the record, so a create whose answer was lost is owned when
 *    discovery finds it; it is removed when the record is deleted, or when the
 *    create was refused for good. Without a store the client reads and deletes
 *    but refuses to create (`dns_marks_unavailable`): an unmarked record could
 *    never be told apart from a foreign one again.
 *  - Nothing is proxied and no CNAME is flattened (LiveDNS has a separate,
 *    apex-only ALIAS type): `proxied: true` and `flatten_cname` are refused,
 *    record tags and the per-record address-family settings are ignored.
 *  - The TTL floor is 300 seconds; Cloudflare's "automatic" (absent or 1) is
 *    sent as that floor.
 *  - A domain can sit in LiveDNS without being delegated to it: records are
 *    accepted and never served. `readZone` compares the public NS answer with
 *    the zone's LiveDNS name servers and answers `not_delegated` only when the
 *    public answer exists and names none of them.
 *
 * Auth: a personal access token (`Authorization: Bearer`), scoped to the
 * organization's domains and the LiveDNS permissions when it is created. The
 * legacy API key (`Authorization: Apikey`) is deprecated and is not accepted.
 */
import { z } from 'zod';
import { normalizeAddress } from '../../hosts';
import { EdgeProviderError, providerFetch } from '../http';
import type { DnsZoneConfig } from '../types';
import type {
  DnsClient,
  DnsCreateArgs,
  DnsMarkStore,
  DnsRecord,
  DnsRecordMark,
  DnsRecordType,
} from './types';

export const GANDI_API_BASE = 'https://api.gandi.net/v5/livedns';
/** LiveDNS refuses a TTL below this (`rrset_ttl` minimum). */
export const GANDI_MIN_TTL_S = 300;
/** One page of the domain listing; more is `truncated`. */
export const GANDI_DOMAIN_PAGE = 100;

const RRSET = z
  .object({
    rrset_name: z.string(),
    rrset_type: z.string(),
    rrset_ttl: z.number().optional(),
    rrset_values: z.array(z.string()),
  })
  .passthrough();
type Rrset = z.infer<typeof RRSET>;

const DOMAIN = z.object({ fqdn: z.string() }).passthrough();

/** Lower case, no trailing dot. */
export function normalizeDnsName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** A record's content as compared everywhere: an address canonical, a name lower case without the dot. */
export function normalizeContent(type: string, content: string): string {
  const t = content.trim();
  if (type === 'A' || type === 'AAAA' || type === 'CNAME') return normalizeAddress(t);
  return t;
}

/** What LiveDNS stores for a value FCP writes (a CNAME target fully qualified). */
function wireValue(type: DnsRecordType, content: string): string {
  const c = normalizeContent(type, content);
  return type === 'CNAME' ? `${c}.` : c;
}

export function gandiRecordId(type: string, name: string, content: string): string {
  return `${type}|${normalizeDnsName(name)}|${normalizeContent(type, content)}`;
}

export function parseGandiRecordId(
  id: string,
): { type: DnsRecordType; name: string; content: string } | null {
  const a = id.indexOf('|');
  const b = a < 0 ? -1 : id.indexOf('|', a + 1);
  if (a <= 0 || b <= a + 1 || b === id.length - 1) return null;
  return {
    type: id.slice(0, a) as DnsRecordType,
    name: id.slice(a + 1, b),
    content: id.slice(b + 1),
  };
}

/** The RRset name LiveDNS uses for `fqdn` in `zone` (`@` at the apex); null when outside it. */
export function rrsetNameOf(fqdn: string, zone: string): string | null {
  const n = normalizeDnsName(fqdn);
  const z = normalizeDnsName(zone);
  if (n === z) return '@';
  return n.endsWith(`.${z}`) ? n.slice(0, -(z.length + 1)) : null;
}

function fqdnOf(rrsetName: string, zone: string): string {
  const z = normalizeDnsName(zone);
  return rrsetName === '@' ? z : `${normalizeDnsName(rrsetName)}.${z}`;
}

/** A refusal raised here, before or instead of a provider call. */
function refusal(step: string, code: string, status?: number): EdgeProviderError {
  return new EdgeProviderError(`gandi ${code} on ${step}`, {
    provider: 'gandi',
    step,
    ...(status !== undefined ? { status } : {}),
    code,
    retryable: false,
    timedOut: false,
  });
}

function isNotFound(e: unknown): boolean {
  return e instanceof EdgeProviderError && e.meta.status === 404;
}

/** Statuses after which a create certainly did not land (no 404, 408, 409, 429: those are unknown). */
function createRefusedForGood(e: unknown): boolean {
  if (!(e instanceof EdgeProviderError)) return false;
  const s = e.meta.status;
  return s !== undefined && s >= 400 && s < 500 && ![404, 408, 409, 429].includes(s);
}

export type NsLookup = (zone: string) => Promise<string[]>;

/** Public NS of a zone; `[]` when it has none (no data / no such name). */
export async function dnsNsLookup(zone: string): Promise<string[]> {
  const { Resolver } = await import('node:dns/promises');
  const resolver = new Resolver({ timeout: 4_000, tries: 2 });
  try {
    return await resolver.resolveNs(zone);
  } catch (e) {
    const code = (e as { code?: unknown }).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') return [];
    throw e;
  }
}

let nsLookupOverride: NsLookup | null = null;
/** Test seam: answer NS lookups from a table (the offline suite refuses real DNS). */
export function __setGandiNsLookup(f: NsLookup | null): void {
  nsLookupOverride = f;
}

/** One authenticated LiveDNS call. */
export function gandiCall<T>(
  apiToken: string,
  step: string,
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
  path: string,
  schema: z.ZodType<T>,
  body?: unknown,
  okStatuses?: number[],
): Promise<T> {
  return providerFetch({
    provider: 'gandi',
    step,
    url: `${GANDI_API_BASE}${path}`,
    method,
    headers: { authorization: `Bearer ${apiToken}` },
    ...(body !== undefined ? { body } : {}),
    schema,
    ...(okStatuses ? { okStatuses } : {}),
  });
}

const seg = (s: string) => encodeURIComponent(s);

/**
 * The domains the token reaches in LiveDNS (one page). A 401 / 403 is the
 * token refused; the caller words it.
 */
export async function listGandiDomains(
  apiToken: string,
  step: string,
): Promise<{ domains: string[]; truncated: boolean }> {
  const rows = await gandiCall(
    apiToken,
    step,
    'GET',
    `/domains?per_page=${GANDI_DOMAIN_PAGE}`,
    z.array(DOMAIN),
  );
  return {
    domains: rows.map((r) => normalizeDnsName(r.fqdn)),
    truncated: rows.length >= GANDI_DOMAIN_PAGE,
  };
}

/** A `DnsClient` bound to one LiveDNS domain. `cfg.marks` holds the ownership markers. */
export function gandiDnsClient(cfg: DnsZoneConfig): DnsClient {
  const zone = normalizeDnsName(cfg.zoneName || cfg.zoneId);
  const domainPath = `/domains/${seg(zone)}`;
  const marks: DnsMarkStore | undefined = cfg.marks;

  const call = <T>(
    step: string,
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    path: string,
    schema: z.ZodType<T>,
    body?: unknown,
    okStatuses?: number[],
  ) => gandiCall(cfg.apiToken, step, method, `${domainPath}${path}`, schema, body, okStatuses);

  const relative = (name: string, step: string): string => {
    const r = rrsetNameOf(name, zone);
    if (r === null) throw refusal(step, 'dns_name_outside_zone');
    return r;
  };

  /** One RRset, or null when there is none. */
  async function readRrset(step: string, rel: string, type: string): Promise<Rrset | null> {
    try {
      return await call(step, 'GET', `/records/${seg(rel)}/${seg(type)}`, RRSET);
    } catch (e) {
      if (isNotFound(e)) return null;
      throw e;
    }
  }

  async function marksAt(name: string): Promise<DnsRecordMark[]> {
    return marks ? await marks.forName(zone, normalizeDnsName(name)) : [];
  }

  function recordsOf(rrsets: Rrset[], marked: DnsRecordMark[]): DnsRecord[] {
    const out: DnsRecord[] = [];
    for (const s of rrsets) {
      const name = fqdnOf(s.rrset_name, zone);
      for (const raw of s.rrset_values) {
        const content = normalizeContent(s.rrset_type, raw);
        const mark = marked.find(
          (m) => m.type === s.rrset_type && m.name === name && m.content === content,
        );
        out.push({
          id: gandiRecordId(s.rrset_type, name, content),
          type: s.rrset_type as DnsRecordType,
          name,
          content,
          proxied: false,
          ...(mark ? { comment: mark.marker } : {}),
        });
      }
    }
    return out;
  }

  function checkArgs(args: DnsCreateArgs, step: string): void {
    if (args.proxied) throw refusal(step, 'dns_proxy_unsupported');
    if (args.settings?.flatten_cname) throw refusal(step, 'dns_flatten_unsupported');
  }

  const ttlOf = (args: DnsCreateArgs) =>
    Math.max(GANDI_MIN_TTL_S, args.ttl && args.ttl > 1 ? args.ttl : GANDI_MIN_TTL_S);

  return {
    zoneId: cfg.zoneId,
    zoneName: cfg.zoneName,
    accountId: cfg.accountId,

    async createRecord(args: DnsCreateArgs): Promise<DnsRecord> {
      const step = 'dns-create';
      checkArgs(args, step);
      if (!marks) throw refusal(step, 'dns_marks_unavailable');
      const name = normalizeDnsName(args.name);
      const rel = relative(name, step);
      const content = normalizeContent(args.type, args.content);
      const key = { type: args.type, name, content };
      const record: DnsRecord = {
        id: gandiRecordId(args.type, name, content),
        type: args.type,
        name,
        content,
        proxied: false,
        comment: args.comment,
      };
      const existing = await readRrset(step, rel, args.type);
      const present = existing?.rrset_values.some(
        (v) => normalizeContent(args.type, v) === content,
      );
      if (present) {
        // Already there: ours when it carries this marker (a create whose
        // answer was lost), otherwise someone else's and never taken over.
        const mark = (await marksAt(name)).find(
          (m) => m.type === key.type && m.content === key.content,
        );
        if (mark?.marker === args.comment) return record;
        throw refusal(step, 'dns_record_exists', 409);
      }
      await marks.set(zone, { ...key, marker: args.comment });
      const value = wireValue(args.type, content);
      try {
        if (existing)
          await call(step, 'PATCH', `/records/${seg(rel)}/${seg(args.type)}`, z.unknown(), {
            add_rrset_values: [value],
          });
        else
          await call(step, 'POST', `/records/${seg(rel)}/${seg(args.type)}`, z.unknown(), {
            rrset_values: [value],
            rrset_ttl: ttlOf(args),
          });
      } catch (e) {
        if (createRefusedForGood(e)) await marks.remove(zone, key);
        throw e;
      }
      return record;
    },

    async findRecordsByName(name: string, type?: DnsRecordType): Promise<DnsRecord[]> {
      const step = 'dns-list';
      const rel = relative(name, step);
      let rrsets: Rrset[];
      if (type) {
        const one = await readRrset(step, rel, type);
        rrsets = one ? [one] : [];
      } else {
        try {
          rrsets = await call(step, 'GET', `/records/${seg(rel)}`, z.array(RRSET));
        } catch (e) {
          if (!isNotFound(e)) throw e;
          rrsets = [];
        }
      }
      if (rrsets.length === 0) return [];
      return recordsOf(rrsets, await marksAt(name));
    },

    async getRecord(id: string): Promise<DnsRecord | null> {
      const step = 'dns-get';
      const key = parseGandiRecordId(id);
      if (!key) return null;
      const rel = rrsetNameOf(key.name, zone);
      if (rel === null) return null;
      const rrset = await readRrset(step, rel, key.type);
      if (!rrset) return null;
      return (
        recordsOf([rrset], await marksAt(key.name)).find((r) => r.content === key.content) ?? null
      );
    },

    async deleteRecord(id: string): Promise<void> {
      const step = 'dns-delete';
      const key = parseGandiRecordId(id);
      if (!key) throw refusal(step, 'dns_record_id_invalid');
      const rel = relative(key.name, step);
      const rrset = await readRrset(step, rel, key.type);
      const values = rrset?.rrset_values ?? [];
      const ours = values.filter((v) => normalizeContent(key.type, v) === key.content);
      if (ours.length > 0) {
        const path = `/records/${seg(rel)}/${seg(key.type)}`;
        if (ours.length === values.length)
          await call(step, 'DELETE', path, z.unknown(), undefined, [404]);
        else await call(step, 'PATCH', path, z.unknown(), { remove_rrset_values: ours }, [404]);
      }
      // Gone either way: its mark goes too (idempotent).
      if (marks) await marks.remove(zone, key);
    },

    async updateRecord(id: string, args: DnsCreateArgs): Promise<DnsRecord> {
      const step = 'dns-update';
      checkArgs(args, step);
      if (!marks) throw refusal(step, 'dns_marks_unavailable');
      const from = parseGandiRecordId(id);
      if (!from) throw refusal(step, 'dns_record_id_invalid');
      const name = normalizeDnsName(args.name);
      // A value moves within its own RRset; another name or type is a new record.
      if (from.name !== name || from.type !== args.type)
        throw refusal(step, 'dns_update_moves_record');
      const rel = relative(name, step);
      const content = normalizeContent(args.type, args.content);
      const to = { type: args.type, name, content };
      const record: DnsRecord = {
        id: gandiRecordId(args.type, name, content),
        type: args.type,
        name,
        content,
        proxied: false,
        comment: args.comment,
      };
      await marks.set(zone, { ...to, marker: args.comment });
      if (content === from.content) return record;
      const rrset = await readRrset(step, rel, args.type);
      const path = `/records/${seg(rel)}/${seg(args.type)}`;
      const values = rrset?.rrset_values ?? [];
      const oldWire = values.filter((v) => normalizeContent(args.type, v) === from.content);
      const newWire = wireValue(args.type, content);
      if (!rrset || oldWire.length === values.length) {
        // The RRset holds only the value that moves (always so for a CNAME):
        // replaced whole in one request.
        await call(step, 'PUT', path, z.unknown(), {
          rrset_values: [newWire],
          rrset_ttl: rrset?.rrset_ttl ?? ttlOf(args),
        });
      } else {
        // Other values stay: one PATCH adds the new value and drops the old.
        await call(step, 'PATCH', path, z.unknown(), {
          add_rrset_values: [newWire],
          ...(oldWire.length > 0 ? { remove_rrset_values: oldWire } : {}),
        });
      }
      await marks.remove(zone, from);
      return record;
    },

    async listCaa(): Promise<Array<{ flags: number; tag: string; value: string }>> {
      const rrset = await readRrset('dns-caa', '@', 'CAA');
      return (rrset?.rrset_values ?? []).flatMap((v) => {
        const m = /^(\d+)\s+(\S+)\s+"?(.*?)"?$/.exec(v.trim());
        return m ? [{ flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3] }] : [];
      });
    },

    // LiveDNS never flattens a CNAME (its apex alias is the separate ALIAS type).
    async flattensAllCnames(): Promise<boolean | null> {
      return false;
    },

    async readZone() {
      const domain = await call('location', 'GET', '', DOMAIN);
      const name = normalizeDnsName(domain.fqdn);
      return { id: name, name, status: await delegationOf(name), paused: false };
    },
  };

  /**
   * `active` unless the zone is publicly delegated to OTHER name servers
   * (`not_delegated`): records written to LiveDNS would then never be served.
   * A lookup that fails, or a zone LiveDNS lists no name servers for, cannot
   * prove that and stays `active`.
   */
  async function delegationOf(name: string): Promise<string> {
    let own: string[];
    try {
      own = await call('location', 'GET', '/nameservers', z.array(z.string()));
    } catch (e) {
      if (e instanceof EdgeProviderError && e.meta.status !== undefined && e.meta.status < 500)
        return 'active';
      throw e;
    }
    let pub: string[];
    try {
      pub = await (nsLookupOverride ?? dnsNsLookup)(name);
    } catch {
      return 'active';
    }
    if (own.length === 0 || pub.length === 0) return 'active';
    const mine = new Set(own.map(normalizeDnsName));
    return pub.some((n) => mine.has(normalizeDnsName(n))) ? 'active' : 'not_delegated';
  }
}

/**
 * Whether a LiveDNS answer refused the token itself (a 401, or a 403 for a
 * token without the LiveDNS permission): the credential test words it.
 */
export function gandiTokenRefused(e: unknown): boolean {
  return (
    e instanceof EdgeProviderError &&
    !e.meta.retryable &&
    (e.meta.status === 401 || e.meta.status === 403)
  );
}

/** The refused-token error the credential test reports (`token_rejected`, its detail kept). */
export function gandiTokenRejected(step: string, answer: EdgeProviderError): EdgeProviderError {
  return new EdgeProviderError(`gandi token rejected on ${step}`, {
    provider: 'gandi',
    step,
    status: answer.meta.status,
    code: 'token_rejected',
    ...(answer.meta.detail ? { detail: answer.meta.detail } : {}),
    retryable: false,
    timedOut: false,
  });
}
