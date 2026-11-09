import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { fakeGandi, memoryMarks, type FakeGandi } from '../../testing/fakeGandi';
import { errorBlob } from '../../testing/mockFetch';
import { EdgeProviderError } from '../http';
import { gandiProvider } from '../gandi';
import {
  __setGandiNsLookup,
  gandiDnsClient,
  gandiRecordId,
  parseGandiRecordId,
  rrsetNameOf,
} from './gandiDns';
import { dnsClientForProvider, dnsClientForZone } from './clients';

const TOKEN = 'SECRET_GANDI';
const ZONE = 'example.org';
const MARKER = 'fcp:fcp-relay-o1-0badf00d';

let api: FakeGandi;
let marks: ReturnType<typeof memoryMarks>;

function client(withMarks = true) {
  return gandiDnsClient({
    provider: 'gandi',
    apiToken: TOKEN,
    zoneId: ZONE,
    zoneName: ZONE,
    accountId: 'acct_gandi',
    ...(withMarks ? { marks } : {}),
  });
}

const cname = (name: string, content: string, comment = MARKER) => ({
  type: 'CNAME' as const,
  name,
  content,
  proxied: false,
  comment,
});

beforeEach(() => {
  api = fakeGandi();
  marks = memoryMarks();
  __setGandiNsLookup(async () => ['ns-1-a.gandi.net.']);
});

afterEach(() => {
  __setGandiNsLookup(null);
  vi.unstubAllGlobals();
});

describe('gandi record ids and names', () => {
  test('an id names the type, the name and the value, and parses back (an IPv6 value too)', () => {
    const id = gandiRecordId('AAAA', 'A.Example.org.', '2001:DB8:0:0::1');
    expect(id).toBe('AAAA|a.example.org|2001:db8::1');
    expect(parseGandiRecordId(id)).toEqual({
      type: 'AAAA',
      name: 'a.example.org',
      content: '2001:db8::1',
    });
    expect(parseGandiRecordId('nonsense')).toBeNull();
  });

  test('names are relative to the zone, the apex is @, a name outside it is null', () => {
    expect(rrsetNameOf('front.example.org', ZONE)).toBe('front');
    expect(rrsetNameOf('a.b.example.org.', ZONE)).toBe('a.b');
    expect(rrsetNameOf('example.org', ZONE)).toBe('@');
    expect(rrsetNameOf('example.net', ZONE)).toBeNull();
    expect(rrsetNameOf('badexample.org', ZONE)).toBeNull();
  });
});

describe('gandi DNS client', () => {
  test('a create writes the mark first, then the record; the marker never leaves FCP', async () => {
    const rec = await client().createRecord({
      ...cname('front.example.org', 'svc.cdn.example'),
      ttl: 1,
    });
    expect(rec).toMatchObject({
      id: 'CNAME|front.example.org|svc.cdn.example',
      content: 'svc.cdn.example',
      comment: MARKER,
      proxied: false,
    });
    // LiveDNS holds the target fully qualified, at the TTL floor (automatic = 300).
    expect(api.sets.get('example.org|front|CNAME')).toEqual({
      ttl: 300,
      values: ['svc.cdn.example.'],
    });
    expect(marks.rows).toEqual([
      {
        zone: ZONE,
        type: 'CNAME',
        name: 'front.example.org',
        content: 'svc.cdn.example',
        marker: MARKER,
      },
    ]);
    // Privacy: no request carries the marker (nothing public can link fronts).
    for (const c of api.stub.calls) expect(c.rawBody ?? '').not.toContain('fcp-relay');
    expect(api.stub.calls.every((c) => c.headers.authorization === `Bearer ${TOKEN}`)).toBe(true);
    expect(api.stub.calls.every((c) => c.redirect === 'manual')).toBe(true);
  });

  test('records read back carry the marker from the mark store; a foreign one carries none', async () => {
    await client().createRecord(cname('front.example.org', 'svc.cdn.example'));
    api.sets.set('example.org|front|TXT', { ttl: 300, values: ['"someone else"'] });
    const found = await client().findRecordsByName('front.example.org');
    expect(found.find((r) => r.type === 'CNAME')?.comment).toBe(MARKER);
    expect(found.find((r) => (r.type as string) === 'TXT')?.comment).toBeUndefined();
    expect(await client().findRecordsByName('front.example.org', 'CNAME')).toHaveLength(1);
    expect(await client().findRecordsByName('missing.example.org')).toEqual([]);
    const got = await client().getRecord('CNAME|front.example.org|svc.cdn.example');
    expect(got?.comment).toBe(MARKER);
    expect(await client().getRecord('CNAME|front.example.org|other.example')).toBeNull();
  });

  test('a create whose answer was lost is found and settled, never written twice', async () => {
    const args = cname('front.example.org', 'svc.cdn.example');
    await client().createRecord(args);
    const writes = () => api.stub.calls.filter((c) => c.method !== 'GET').length;
    const before = writes();
    // The retry after a lost answer: the record is there with our mark.
    const again = await client().createRecord(args);
    expect(again.comment).toBe(MARKER);
    expect(writes()).toBe(before);
  });

  test('an identical record FCP did not write is refused, never taken over', async () => {
    api.sets.set('example.org|front|CNAME', { ttl: 300, values: ['svc.cdn.example.'] });
    const err = await client()
      .createRecord(cname('front.example.org', 'svc.cdn.example'))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EdgeProviderError);
    expect((err as EdgeProviderError).meta).toMatchObject({
      code: 'dns_record_exists',
      status: 409,
    });
    expect(marks.rows).toEqual([]);
  });

  test('a create refused for good drops its mark; one with an unknown outcome keeps it', async () => {
    // A second CNAME value at a name: LiveDNS refuses it (400).
    api.sets.set('example.org|front|CNAME', { ttl: 300, values: ['other.example.'] });
    await expect(
      client().createRecord(cname('front.example.org', 'svc.cdn.example')),
    ).rejects.toThrow();
    expect(marks.rows).toEqual([]);
    // A 503: the record may exist, so the mark stays for discovery.
    api.sets.clear();
    api.failWith = 503;
    await expect(
      client().createRecord(cname('x.example.org', 'svc.cdn.example')),
    ).rejects.toThrow();
    api.failWith = null;
    // The failing GET came before the mark: nothing was written.
    expect(marks.rows).toEqual([]);
  });

  test('A records of several values: one is added and removed alone', async () => {
    api.sets.set('example.org|n|A', { ttl: 600, values: ['192.0.2.9'] });
    const rec = await client().createRecord({
      type: 'A',
      name: 'n.example.org',
      content: '192.0.2.10',
      proxied: false,
      comment: MARKER,
    });
    expect(api.sets.get('example.org|n|A')?.values).toEqual(['192.0.2.9', '192.0.2.10']);
    expect(api.stub.calls.some((c) => c.method === 'PATCH')).toBe(true);
    await client().deleteRecord(rec.id);
    expect(api.sets.get('example.org|n|A')?.values).toEqual(['192.0.2.9']);
    expect(marks.rows).toEqual([]);
  });

  test('a delete of the last value deletes the set; a gone record is a success', async () => {
    const rec = await client().createRecord({
      type: 'AAAA',
      name: 'n.example.org',
      content: '2001:db8::1',
      proxied: false,
      comment: MARKER,
    });
    await client().deleteRecord(rec.id);
    expect(api.sets.has('example.org|n|AAAA')).toBe(false);
    await client().deleteRecord(rec.id);
    expect(api.stub.calls.filter((c) => c.method === 'DELETE')).toHaveLength(1);
  });

  test('an update replaces a one-value set in ONE request and moves the mark', async () => {
    const rec = await client().createRecord(cname('front.example.org', 'old.cdn.example'));
    const n = api.stub.calls.length;
    const moved = await client().updateRecord!(
      rec.id,
      cname('front.example.org', 'new.cdn.example'),
    );
    const writes = api.stub.calls.slice(n).filter((c) => c.method !== 'GET');
    expect(writes.map((c) => c.method)).toEqual(['PUT']);
    expect(api.sets.get('example.org|front|CNAME')?.values).toEqual(['new.cdn.example.']);
    expect(moved.id).toBe('CNAME|front.example.org|new.cdn.example');
    expect(marks.rows.map((r) => r.content)).toEqual(['new.cdn.example']);
  });

  test('an update in a set with other values adds and removes in one PATCH', async () => {
    api.sets.set('example.org|n|A', { ttl: 300, values: ['192.0.2.9'] });
    const rec = await client().createRecord({
      type: 'A',
      name: 'n.example.org',
      content: '192.0.2.10',
      proxied: false,
      comment: MARKER,
    });
    const n = api.stub.calls.length;
    await client().updateRecord!(rec.id, {
      type: 'A',
      name: 'n.example.org',
      content: '192.0.2.11',
      proxied: false,
      comment: MARKER,
    });
    const patch = api.stub.calls.slice(n).find((c) => c.method === 'PATCH');
    expect(patch?.body).toEqual({
      add_rrset_values: ['192.0.2.11'],
      remove_rrset_values: ['192.0.2.10'],
    });
    expect(api.sets.get('example.org|n|A')?.values).toEqual(['192.0.2.9', '192.0.2.11']);
  });

  test('what LiveDNS cannot do is refused before any call', async () => {
    const proxied = await client()
      .createRecord({ ...cname('a.example.org', 'b.example'), proxied: true })
      .catch((e: EdgeProviderError) => e.meta.code);
    expect(proxied).toBe('dns_proxy_unsupported');
    const flat = await client()
      .createRecord({ ...cname('a.example.org', 'b.example'), settings: { flatten_cname: true } })
      .catch((e: EdgeProviderError) => e.meta.code);
    expect(flat).toBe('dns_flatten_unsupported');
    const outside = await client()
      .createRecord(cname('a.example.net', 'b.example'))
      .catch((e: EdgeProviderError) => e.meta.code);
    expect(outside).toBe('dns_name_outside_zone');
    expect(api.stub.calls).toHaveLength(0);
  });

  test('without a mark store a client reads and deletes but never creates', async () => {
    const code = await client(false)
      .createRecord(cname('a.example.org', 'b.example'))
      .catch((e: EdgeProviderError) => e.meta.code);
    expect(code).toBe('dns_marks_unavailable');
    expect(await client(false).findRecordsByName('a.example.org')).toEqual([]);
  });

  test('CAA at the apex, and CNAMEs are never flattened', async () => {
    api.sets.set('example.org|@|CAA', {
      ttl: 300,
      values: ['0 issue "letsencrypt.org"', '128 iodef "mailto:x@example.org"'],
    });
    expect(await client().listCaa()).toEqual([
      { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
      { flags: 128, tag: 'iodef', value: 'mailto:x@example.org' },
    ]);
    expect(await client().flattensAllCnames!()).toBe(false);
  });

  test('a zone delegated elsewhere reads not_delegated; an unknowable answer stays active', async () => {
    expect(await client().readZone()).toEqual({
      id: ZONE,
      name: ZONE,
      status: 'active',
      paused: false,
    });
    __setGandiNsLookup(async () => ['ns1.elsewhere.example']);
    expect((await client().readZone()).status).toBe('not_delegated');
    __setGandiNsLookup(async () => {
      throw new Error('SERVFAIL');
    });
    expect((await client().readZone()).status).toBe('active');
  });

  test('errors carry no token and no response body', async () => {
    api.failWith = 403;
    const err = await client()
      .findRecordsByName('front.example.org')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EdgeProviderError);
    expect(errorBlob(err)).not.toContain(TOKEN);
    expect(errorBlob(err)).not.toContain('refused');
  });

  test('the factory picks the client by the DNS account provider', () => {
    const z = { apiToken: TOKEN, zoneId: ZONE, zoneName: ZONE, accountId: 'a' };
    expect(dnsClientForProvider('gandi', z)?.zoneName).toBe(ZONE);
    expect(dnsClientForProvider('fastly', z)).toBeNull();
    expect(dnsClientForZone({ ...z, provider: 'gandi' }).zoneId).toBe(ZONE);
  });
});

describe('gandi adapter (the account half)', () => {
  const cfg = { type: 'gandi' as const, apiToken: TOKEN, zoneId: ZONE, zoneName: ZONE };

  test('a token that reaches domains passes; one that reaches none fails no_zones', async () => {
    expect(await gandiProvider.testCredentials(cfg)).toEqual({ ok: true, detail: 'zones_1' });
    api.domains = [];
    expect(await gandiProvider.testCredentials(cfg)).toMatchObject({ ok: false, code: 'no_zones' });
  });

  test('a refused token (401, or 403 without the LiveDNS permission) is token_rejected', async () => {
    for (const status of [401, 403]) {
      api.failWith = status;
      expect(await gandiProvider.testCredentials(cfg)).toMatchObject({
        ok: false,
        code: 'token_rejected',
      });
    }
  });

  test('the domains are the zone list, named by themselves', async () => {
    api.domains = ['example.org', 'example.net'];
    expect(await gandiProvider.discoverOptions!({ apiToken: TOKEN })).toEqual({
      zones: [
        { id: 'example.org', label: 'example.org' },
        { id: 'example.net', label: 'example.net' },
      ],
    });
    expect(await gandiProvider.discoverOptions!({})).toEqual({});
  });

  test('a location check: usable, delegated elsewhere, unknown to the token', async () => {
    expect(await gandiProvider.checkLocation!(cfg)).toMatchObject({
      ok: true,
      label: ZONE,
      zoneName: ZONE,
    });
    __setGandiNsLookup(async () => ['ns1.elsewhere.example']);
    expect(await gandiProvider.checkLocation!(cfg)).toMatchObject({
      ok: false,
      code: 'zone_not_active',
      observed: { zoneStatus: 'not_delegated' },
    });
    expect(
      await gandiProvider.checkLocation!({ ...cfg, zoneId: 'other.org', zoneName: 'other.org' }),
    ).toMatchObject({ ok: false, code: 'zone_unreadable' });
  });

  test('it builds no edge', async () => {
    expect(() => gandiProvider.planProvision(cfg, { name: 'x', listeners: [] }, {})).toThrow(
      /builds no edge/,
    );
    expect(await gandiProvider.runDestroy(cfg, {} as never, { steps: [], resources: [] })).toEqual({
      status: 'confirmed_gone',
    });
  });
});
