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
  address: string;
  port: number;
}
interface Settled {
  done: Array<{ id: Id<'sniVantageProbes'>; externalId?: string; results: NameVantageResult[] }>;
  failed: Array<{ id: Id<'sniVantageProbes'>; error: string }>;
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
    const valid = c.rows.filter((r) => r.valid);
    const moved = c.rows.filter((r) => !r.valid).map((r) => ({ id: r.id, error: 'target_moved' }));
    if (valid.length === 0) {
      await ctx.runMutation(internal.sniVantage.finishBatch, { batch, done: [], failed: moved });
      return null;
    }
    await ctx.runMutation(internal.sniVantage.markRunning, { ids: valid.map((r) => r.id) });
    let settled: Settled;
    try {
      settled =
        source === 'globalping'
          ? await runGlobalping(valid, c, c.secrets.globalpingToken)
          : await runAtlas(valid, c, c.secrets.ripeAtlasKey);
    } catch {
      // Service text is never stored: the run failed, that is all.
      settled = { done: [], failed: valid.map((r) => ({ id: r.id, error: 'source_error' })) };
    }
    await ctx.runMutation(internal.sniVantage.finishBatch, {
      batch,
      done: settled.done,
      failed: [...settled.failed, ...moved],
    });
    return null;
  },
});
