'use node';
/**
 * Checks of server names from inside a country, the "use node" half: one
 * batch (one address, one country, a few names) against one source. The
 * Globalping SDK and X.509 parsing live here; everything that decides lives in
 * pure modules (lib/edges/probes/nameCheck.ts, lib/edges/sni/vantage.ts).
 *
 * Every name of a batch is measured from the SAME vantages: Globalping reuses
 * the first measurement's probes (`locations` = its id), Atlas pins one probe
 * list for every definition. Calls to one service are spaced by
 * `edge.probe.sourceSpacingMs`. Nothing about the member side is involved:
 * the address is FCP's own, the name is a public site's.
 */
import { v } from 'convex/values';
import { X509Certificate } from 'node:crypto';
import Globalping from 'globalping';
import { internalAction, type ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { GLOBALPING_USER_AGENT, type GlobalpingLike } from './lib/edges/probes/globalping';
import { RIPE_ATLAS_BASE } from './lib/edges/probes/ripeatlas';
import { resolvePublic } from './lib/edges/probes/internal';
import { addressFamily } from './lib/edges/ip';
import { normalizeAddress } from './lib/edges/hosts';
import { tlsInspect } from './sniQualifyOps';
import type { RealHostSkip } from '../src/shared/contracts/edgeCodes';
import {
  atlasNameBody,
  atlasProbeQuery,
  globalpingNameRequest,
  isNoProbesError,
  parseAtlasNameResults,
  parseAtlasProbes,
  parseGlobalpingNameResults,
  pickAtlasProbes,
  type CertCovers,
  type NameVantageResult,
} from './lib/edges/probes/nameCheck';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const GLOBALPING_DEADLINE_MS = 75_000;
const ATLAS_DEADLINE_MS = 150_000;

let globalpingFactory: (token: string) => GlobalpingLike = (token) =>
  new Globalping({
    auth: token || undefined,
    userAgent: GLOBALPING_USER_AGENT,
    timeout: 20_000,
  }) as unknown as GlobalpingLike;

/** Test seam: swap the SDK client. */
export function __setVantageGlobalpingFactory(f: typeof globalpingFactory | null): void {
  globalpingFactory =
    f ??
    ((token) =>
      new Globalping({
        auth: token || undefined,
        userAgent: GLOBALPING_USER_AGENT,
        timeout: 20_000,
      }) as unknown as GlobalpingLike);
}

const x509Covers: CertCovers = (pem, name) => {
  try {
    return new X509Certificate(pem).checkHost(name) !== undefined;
  } catch {
    return null;
  }
};
let certCovers: CertCovers = x509Covers;
/** Test seam: the leaf-certificate check (a fixture has no real chain). */
export function __setVantageCertCovers(f: CertCovers | null): void {
  certCovers = f ?? x509Covers;
}

interface Row {
  id: Id<'sniVantageProbes'>;
  name: string;
  /** What is dialled: FCP's address, or for a real-host control the real site's. */
  address: string;
  port: number;
  /** A real-host control: the real site's address (also `address`). */
  realAddress?: string;
}
interface Settled {
  done: Array<{
    id: Id<'sniVantageProbes'>;
    externalId?: string;
    results: NameVantageResult[];
    realAddress?: string;
  }>;
  failed: Array<{ id: Id<'sniVantageProbes'>; error: string; realAddress?: string }>;
}

// --- real-host controls -------------------------------------------------------------------------

/** The real site is dialled on HTTPS: a name's public site answers there. */
const REAL_HOST_PORT = 443;

export interface RealHostDeps {
  /** Every answer for `name` in one address family (the system resolver). */
  lookup: (name: string, family: 4 | 6) => Promise<string[]>;
  /** One TLS handshake from FCP's host presenting `servername`: completed with a chain valid for it. */
  serves: (host: string, servername: string) => Promise<boolean>;
}

const defaultRealHostDeps: RealHostDeps = {
  lookup: async (name, family) => {
    const dns = await import('node:dns/promises');
    return (await dns.lookup(name, { all: true, family, verbatim: true })).map((a) => a.address);
  },
  serves: async (host, servername) => {
    const r = await tlsInspect({ host, port: REAL_HOST_PORT, servername });
    return r.ok && r.authorized === true;
  },
};
let realHostDeps: RealHostDeps = defaultRealHostDeps;
/** Test seam: the resolver and FCP's own handshake. */
export function __setRealHostDeps(d: Partial<RealHostDeps> | null): void {
  realHostDeps = d ? { ...defaultRealHostDeps, ...d } : defaultRealHostDeps;
}

/**
 * The real site of `name` as a vantage should dial it: its public DNS answer
 * in the family of FCP's address (every answer public, the first that is not
 * one of FCP's own), and only once a handshake from FCP's own host shows it
 * serves the name. Otherwise a skip code and nothing is dialled from the country.
 */
export async function realSiteOf(
  name: string,
  family: 4 | 6,
  own: ReadonlySet<string>,
): Promise<{ ok: true; address: string } | { ok: false; error: RealHostSkip }> {
  const r = await resolvePublic(name, (n) => realHostDeps.lookup(n, family));
  if (!r.ok)
    return { ok: false, error: r.error === 'private_address' ? 'real_private' : 'real_resolve' };
  // Canonical spellings on both sides (`own` is canonical already), and the
  // lowest answer, not the first: a resolver that rotates its answers still
  // gives every source of a batch the same real site.
  const answers = [...new Set(r.addresses.map(normalizeAddress))].sort();
  const address = answers.find((a) => !own.has(a));
  if (!address) return { ok: false, error: 'real_is_ours' };
  let serves = false;
  try {
    serves = await realHostDeps.serves(address, name);
  } catch {
    serves = false;
  }
  return serves ? { ok: true, address } : { ok: false, error: 'real_not_serving' };
}

async function runGlobalping(
  rows: readonly Row[],
  c: { country: string; perCountryLimit: number; preferEyeball: boolean; spacingMs: number },
  token: string,
): Promise<Settled> {
  const client = globalpingFactory(token);
  const out: Settled = { done: [], failed: [] };
  const created: Array<{ row: Row; id: string }> = [];
  let first: string | null = null;
  for (const [i, row] of rows.entries()) {
    if (i > 0) await sleep(c.spacingMs);
    const where = first
      ? { reuse: first }
      : { country: c.country, limit: c.perCountryLimit, preferEyeball: c.preferEyeball };
    let res = await client.createMeasurement(globalpingNameRequest(row, where));
    // Few probes in a country: the eyeball tag may match none. Once, without it.
    if (!res.ok && !first && c.preferEyeball && isNoProbesError(res.response?.status, res.data))
      res = await client.createMeasurement(
        globalpingNameRequest(row, { country: c.country, limit: c.perCountryLimit }),
      );
    const id = res.ok ? (res.data as { id?: unknown } | undefined)?.id : undefined;
    if (typeof id !== 'string') {
      out.failed.push({
        id: row.id,
        error: isNoProbesError(res.response?.status, res.data) ? 'no_probes' : 'create_failed',
      });
      continue;
    }
    first ??= id;
    created.push({ row, id });
  }
  const deadline = Date.now() + GLOBALPING_DEADLINE_MS;
  const pending = new Map(created.map((x) => [x.row.id as string, x]));
  while (pending.size > 0 && Date.now() < deadline) {
    await sleep(3000);
    for (const [key, { row, id }] of pending) {
      const res = await client.getMeasurement(id);
      const data = res.ok ? (res.data as { status?: unknown; results?: unknown }) : null;
      if (!data || data.status !== 'finished') continue;
      out.done.push({
        id: row.id,
        externalId: id,
        results: parseGlobalpingNameResults(data.results, c.country, [row.name, row.address]),
      });
      pending.delete(key);
    }
  }
  for (const { row } of pending.values()) out.failed.push({ id: row.id, error: 'timeout' });
  return out;
}

async function atlasJson(url: string, key: string, init: RequestInit = {}) {
  const res = await fetch(url, {
    ...init,
    headers: {
      authorization: `Key ${key}`,
      accept: 'application/json',
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
  });
  return { ok: res.ok, status: res.status, body: res.ok ? ((await res.json()) as unknown) : null };
}

async function runAtlas(
  rows: readonly Row[],
  c: { country: string; perCountryLimit: number },
  key: string,
): Promise<Settled> {
  const out: Settled = { done: [], failed: [] };
  const failAll = (error: string) => {
    for (const r of rows) out.failed.push({ id: r.id, error });
    return out;
  };
  if (!key) return failAll('no_key');
  const af = rows[0]!.address.includes(':') ? 6 : 4;
  const probes = await atlasJson(`${RIPE_ATLAS_BASE}/probes/?${atlasProbeQuery(c.country)}`, key);
  if (!probes.ok) return failAll('probe_list_failed');
  const picked = pickAtlasProbes(parseAtlasProbes(probes.body, af), c.perCountryLimit);
  if (picked.length === 0) return failAll('no_probes');
  const asnByProbe: Record<number, string> = {};
  for (const p of picked) if (p.asn) asnByProbe[p.id] = p.asn;
  const created = await atlasJson(`${RIPE_ATLAS_BASE}/measurements/`, key, {
    method: 'POST',
    body: JSON.stringify(
      atlasNameBody(
        rows,
        picked.map((p) => p.id),
        af,
      ),
    ),
  });
  const ids = (created.body as { measurements?: unknown } | null)?.measurements;
  if (!created.ok || !Array.isArray(ids) || ids.length !== rows.length)
    return failAll('create_failed');
  const deadline = Date.now() + ATLAS_DEADLINE_MS;
  const pending = new Map(rows.map((r, i) => [r.id as string, { row: r, mid: Number(ids[i]) }]));
  const last = new Map<string, NameVantageResult[]>();
  while (pending.size > 0 && Date.now() < deadline) {
    await sleep(10_000);
    for (const [k, { row, mid }] of pending) {
      const res = await atlasJson(`${RIPE_ATLAS_BASE}/measurements/${mid}/results/`, key);
      if (!res.ok) continue;
      const results = parseAtlasNameResults(res.body, row.name, {
        asnByProbe,
        certCovers,
        redact: [row.address],
      });
      last.set(k, results);
      if (Array.isArray(res.body) && res.body.length >= picked.length) {
        out.done.push({ id: row.id, externalId: String(mid), results });
        pending.delete(k);
      }
    }
  }
  // Partial answers are evidence too; a measurement nobody answered timed out.
  for (const [k, { row, mid }] of pending) {
    const results = last.get(k) ?? [];
    if (results.length > 0) out.done.push({ id: row.id, externalId: String(mid), results });
    else out.failed.push({ id: row.id, error: 'timeout' });
  }
  return out;
}

export const executeBatch = internalAction({
  args: { batch: v.string(), source: v.union(v.literal('globalping'), v.literal('ripeatlas')) },
  handler: async (ctx: ActionCtx, { batch, source }): Promise<null> => {
    const c = await ctx.runQuery(internal.sniVantage.batchContext, { batch, source });
    if (!c) return null;
    // A gate closed after the plan (switched off, country or source taken out,
    // edges frozen): settle the rows, dial nothing.
    if (c.gate) {
      await ctx.runMutation(internal.sniVantage.finishBatch, {
        batch,
        done: [],
        failed: c.rows.map((r) => ({ id: r.id, error: c.gate! })),
      });
      return null;
    }
    const valid = c.rows.filter((r) => r.valid);
    const moved = c.rows.filter((r) => !r.valid).map((r) => ({ id: r.id, error: 'target_moved' }));
    if (valid.length === 0) {
      await ctx.runMutation(internal.sniVantage.finishBatch, { batch, done: [], failed: moved });
      return null;
    }
    await ctx.runMutation(internal.sniVantage.markRunning, { ids: valid.map((r) => r.id) });
    // A real-host control dials the name's real site instead of FCP's address,
    // once FCP's own host has found it (public, not ours) and seen it serve the
    // name; otherwise it is settled with the reason and nothing is dialled.
    const own = new Set(c.own);
    const dial: Row[] = [];
    const skipped: Settled['failed'] = [];
    for (const r of valid) {
      if (r.role !== 'real_host') {
        dial.push(r);
        continue;
      }
      // Real-host controls turned off since the plan: the real site is not visited.
      if (!c.realHostOn) {
        skipped.push({ id: r.id, error: 'gate_real_host' });
        continue;
      }
      const site = await realSiteOf(r.name, addressFamily(r.address) === 'v6' ? 6 : 4, own);
      if (site.ok)
        dial.push({ ...r, address: site.address, port: REAL_HOST_PORT, realAddress: site.address });
      else skipped.push({ id: r.id, error: site.error });
    }
    let settled: Settled;
    try {
      settled =
        dial.length === 0
          ? { done: [], failed: [] }
          : source === 'globalping'
            ? await runGlobalping(dial, c, c.secrets.globalpingToken)
            : await runAtlas(dial, c, c.secrets.ripeAtlasKey);
    } catch {
      // Service text is never stored: the run failed, that is all.
      settled = { done: [], failed: dial.map((r) => ({ id: r.id, error: 'source_error' })) };
    }
    const realOf = new Map(dial.filter((r) => r.realAddress).map((r) => [r.id, r.realAddress!]));
    const withReal = <T extends { id: Id<'sniVantageProbes'> }>(x: T) =>
      realOf.has(x.id) ? { ...x, realAddress: realOf.get(x.id)! } : x;
    await ctx.runMutation(internal.sniVantage.finishBatch, {
      batch,
      done: settled.done.map(withReal),
      failed: [...settled.failed.map(withReal), ...skipped, ...moved],
    });
    return null;
  },
});
