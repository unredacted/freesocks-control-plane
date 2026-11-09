/**
 * Test helper: an in-memory Gandi LiveDNS (API v5) behind `mockFetch`, with the
 * answers the docs give (https://api.gandi.net/docs/livedns/, 2026-11-08):
 * a record set is (name, type) -> values; POST answers 201 (created), 200 (the
 * same values already there) or 409 (other values there); PATCH adds and
 * removes values and answers 204 when the set is left empty; PUT replaces;
 * DELETE answers 204; a missing set or domain is 404. Plus an in-memory
 * `DnsMarkStore`. Not a test file itself.
 */
import {
  jsonRes,
  mockFetch,
  type Captured,
  type FetchStub,
  type PartialHandler,
} from './mockFetch';
import type { DnsMarkStore, DnsRecordMark } from '../providers/dns/types';

export interface FakeGandi {
  /** The installed fetch stub (`fakeGandi`); absent for `fakeGandiApi`, whose handler the caller routes. */
  stub: FetchStub;
  /** Answers LiveDNS calls; null for any other host (compose with `routeFetch`). */
  handler: PartialHandler;
  /** `<zone>|<rrset_name>|<type>` -> values as LiveDNS stores them. */
  sets: Map<string, { ttl: number; values: string[] }>;
  /** The domains the token reaches. */
  domains: string[];
  /** The zone's LiveDNS name servers. */
  nameservers: string[];
  /** Answer every call with this status (a refused or unknown token). */
  failWith: number | null;
}

const PREFIX = '/v5/livedns';

/** The fake installed as the global fetch (every other host answers 404). */
export function fakeGandi(opts: { domains?: string[]; nameservers?: string[] } = {}): FakeGandi {
  const fake = fakeGandiApi(opts);
  fake.stub = mockFetch(
    async (c, i) => (await fake.handler(c, i)) ?? jsonRes({ message: 'not found' }, 404),
  );
  return fake;
}

/** The fake, not installed: route its `handler` alongside other fakes. */
export function fakeGandiApi(opts: { domains?: string[]; nameservers?: string[] } = {}): FakeGandi {
  const fake: FakeGandi = {
    stub: undefined as unknown as FetchStub,
    handler: () => null,
    sets: new Map(),
    domains: opts.domains ?? ['example.org'],
    nameservers: opts.nameservers ?? ['ns-1-a.gandi.net', 'ns-2-b.gandi.net'],
    failWith: null,
  };
  const key = (zone: string, name: string, type: string) => `${zone}|${name}|${type}`;
  const rrset = (name: string, type: string, s: { ttl: number; values: string[] }) => ({
    rrset_name: name,
    rrset_type: type,
    rrset_ttl: s.ttl,
    rrset_values: [...s.values],
    rrset_href: `https://api.gandi.net${PREFIX}/domains/x/records/${name}/${type}`,
  });
  const notFound = () => jsonRes({ code: 404, message: 'Not Found', object: 'HTTPNotFound' }, 404);
  const empty = (status: number) => new Response(null, { status });

  fake.handler = (c: Captured) => {
    if (new URL(c.url).host !== 'api.gandi.net') return null;
    if (fake.failWith !== null)
      return jsonRes(
        { code: fake.failWith, message: 'refused', object: 'HTTPError' },
        fake.failWith,
      );
    if (c.headers.authorization !== 'Bearer SECRET_GANDI') return jsonRes({ code: 401 }, 401);
    const path = decodeURIComponent(c.path);
    if (!path.startsWith(PREFIX)) return notFound();
    const parts = path.slice(PREFIX.length).split('/').filter(Boolean);
    if (parts[0] !== 'domains') return notFound();
    if (parts.length === 1 && c.method === 'GET')
      return jsonRes(fake.domains.map((fqdn) => ({ fqdn, domain_href: `x/${fqdn}` })));
    const zone = parts[1]!;
    if (!fake.domains.includes(zone)) return notFound();
    if (parts.length === 2 && c.method === 'GET')
      return jsonRes({ fqdn: zone, automatic_snapshots: false });
    if (parts[2] === 'nameservers' && c.method === 'GET') return jsonRes(fake.nameservers);
    if (parts[2] !== 'records') return notFound();
    const name = parts[3]!;
    const type = parts[4];
    if (!type) {
      if (c.method !== 'GET') return notFound();
      const out = [...fake.sets.entries()]
        .filter(([k]) => k.startsWith(`${zone}|${name}|`))
        .map(([k, s]) => rrset(name, k.split('|')[2]!, s));
      return out.length > 0 ? jsonRes(out) : notFound();
    }
    const k = key(zone, name, type);
    const cur = fake.sets.get(k);
    const body = (c.body ?? {}) as {
      rrset_values?: string[];
      rrset_ttl?: number;
      add_rrset_values?: string[];
      remove_rrset_values?: string[];
    };
    switch (c.method) {
      case 'GET':
        return cur ? jsonRes(rrset(name, type, cur)) : notFound();
      case 'POST': {
        const values = body.rrset_values ?? [];
        if (cur) {
          const same =
            cur.values.length === values.length && values.every((v) => cur.values.includes(v));
          return same ? jsonRes({ message: 'unchanged' }) : jsonRes({ code: 409 }, 409);
        }
        if (type === 'CNAME' && values.length > 1) return jsonRes({ code: 400 }, 400);
        fake.sets.set(k, { ttl: body.rrset_ttl ?? 10800, values: [...values] });
        return jsonRes({ message: 'DNS Record Created' }, 201);
      }
      case 'PUT':
        fake.sets.set(k, { ttl: body.rrset_ttl ?? 10800, values: [...(body.rrset_values ?? [])] });
        return jsonRes({ message: 'DNS Record Created' }, 201);
      case 'PATCH': {
        const values = (cur?.values ?? [])
          .filter((v) => !(body.remove_rrset_values ?? []).includes(v))
          .concat((body.add_rrset_values ?? []).filter((v) => !cur?.values.includes(v)));
        if (type === 'CNAME' && values.length > 1) return jsonRes({ code: 400 }, 400);
        if (values.length === 0) {
          fake.sets.delete(k);
          return empty(204);
        }
        fake.sets.set(k, { ttl: body.rrset_ttl ?? cur?.ttl ?? 10800, values });
        return jsonRes(rrset(name, type, fake.sets.get(k)!));
      }
      case 'DELETE':
        fake.sets.delete(k);
        return empty(204);
    }
    return notFound();
  };
  return fake;
}

/** The fake's records as flat rows (fully qualified names, values without the trailing dot). */
export function gandiRows(fake: FakeGandi): Array<{ name: string; type: string; content: string }> {
  const out: Array<{ name: string; type: string; content: string }> = [];
  for (const [k, s] of fake.sets) {
    const [zone, name, type] = k.split('|') as [string, string, string];
    for (const v of s.values)
      out.push({
        name: name === '@' ? zone : `${name}.${zone}`,
        type,
        content: v.replace(/\.$/, ''),
      });
  }
  return out;
}

/** An in-memory `DnsMarkStore` (the `dnsRecordMarks` table's stand-in). */
export function memoryMarks(): DnsMarkStore & { rows: Array<DnsRecordMark & { zone: string }> } {
  const rows: Array<DnsRecordMark & { zone: string }> = [];
  const same = (
    a: { zone: string } & Omit<DnsRecordMark, 'marker'>,
    zone: string,
    k: Omit<DnsRecordMark, 'marker'>,
  ) => a.zone === zone && a.name === k.name && a.type === k.type && a.content === k.content;
  return {
    rows,
    async forName(zone, name) {
      return rows.filter((r) => r.zone === zone && r.name === name).map(({ zone: _z, ...m }) => m);
    },
    async set(zone, mark) {
      const i = rows.findIndex((r) => same(r, zone, mark));
      if (i >= 0) rows[i] = { ...mark, zone };
      else rows.push({ ...mark, zone });
    },
    async remove(zone, k) {
      for (let i = rows.length - 1; i >= 0; i--) if (same(rows[i]!, zone, k)) rows.splice(i, 1);
    },
  };
}
