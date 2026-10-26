'use node';
/**
 * Finding names, the network side (docs/edges.md "Finding names"). Every
 * action here stays well inside the 120 s action limit and writes its results
 * back through `sniHunt.ts` with a compare-and-set, so a run that is cut off,
 * cancelled or duplicated changes nothing it should not:
 *
 *  - `downloadList`: the top-sites list, once per sweep, stored in chunks
 *    (`sniHuntChunks`) for the run's life.
 *  - `sweepStep`: one step of a sweep. It holds the run's lease, resolves
 *    chunks of names with ordinary lookups (A, and AAAA whenever a hunting
 *    network has IPv6 ranges) at no more than `lookupsPerSecond`, checkpoints
 *    after every chunk, stops at a 60 s deadline and schedules the next step.
 *  - `check`: due candidates, each with qualification's own handshake
 *    (against the family's target, or the candidate's own address for a
 *    network candidate), then, after a pass, an X25519-only and an
 *    X25519MLKEM768-only offer. The same pace as qualification.
 *  - `readCert`: the names on a family target's certificate (FCP talks only to
 *    that target).
 *  - `ctStep`: one certificate-transparency page, within the hourly budget.
 *
 * Nothing scans an address range: names are resolved, and only a family's
 * target or a candidate's own answers are dialled, on the target's port.
 */
import { randomUUID } from 'node:crypto';
import { Globalping } from 'globalping';
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { isPublicIpLiteral } from './lib/edges/ip';
import { judgeHandshake, type HandshakeResult } from './lib/edges/sni/family';
import { qualificationNetworkCode, type NetworkPrefixes } from './lib/edges/networks';
import { dialAddress, tlsInspect } from './sniQualifyOps';
import { compileRanges, hasV6, networksHit } from './lib/edges/sni/hunt/ranges';
import {
  SWEEP_CHUNK_ENTRIES,
  TRANCO_LATEST_URL,
  certSpotterUrl,
  decodeChunk,
  encodeChunk,
  parseCertSpotterPage,
  parseTrancoLatest,
  retryAfterMs,
  trancoDownloadUrl,
  trancoEntries,
  type ListEntry,
} from './lib/edges/sni/hunt/sources';
import {
  answersOnNetwork,
  extraFact,
  ownTargetCode,
  shownAnswers,
} from './lib/edges/sni/hunt/check';
import type { ClaimedCheck, OoniItem, TimingItem, UpsertTally } from './sniHunt';
import {
  GLOBALPING_USER_AGENT,
  globalpingTestsOf,
  globalpingFits,
  type GlobalpingLike,
} from './lib/edges/probes/globalping';
import {
  globalpingNameRequest,
  isNoProbesError,
  parseGlobalpingNameResults,
} from './lib/edges/probes/nameCheck';
import {
  ooniUrl,
  parseOoni,
  placeKey,
  timingOf,
  timingRequest,
} from './lib/edges/sni/hunt/evidence';

/** A step stops starting chunks past this (the action limit is 120 s). */
const STEP_DEADLINE_MS = 60_000;
/** A check run stops starting candidates past this. */
const CHECK_DEADLINE_MS = 60_000;
/** Names per checkpoint (a chunk of the stored list is a multiple of it). */
const SWEEP_BATCH = 100;
/** What a batch may take beyond its paced lookups (the slowest lookup's timeout). */
const LOOKUP_TAIL_MS = 8_000;
/** The next step starts this long after a step ends. */
const STEP_GAP_MS = 5_000;
/** Between handshakes: the same pace as qualification. */
const HANDSHAKE_GAP_MS = 500;
/** The next certificate-transparency page, when the budget allows one. */
const CT_GAP_MS = 10_000;
const LIST_TIMEOUT_MS = 60_000;
const LIST_MAX_BYTES = 64 * 1024 * 1024;
const CT_TIMEOUT_MS = 20_000;
const CT_MAX_BYTES = 8 * 1024 * 1024;

export interface HuntDeps {
  fetch: typeof fetch;
  /** Ordinary lookups through the host's resolver; [] when the name has none. */
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  /** What qualification resolves a target with. */
  lookup(name: string): Promise<string[]>;
  tlsInspect: typeof tlsInspect;
  /** A Globalping client for one token. */
  globalping(token: string): GlobalpingLike;
  now(): number;
  sleep(ms: number): Promise<void>;
}

async function resolver() {
  const dns = await import('node:dns');
  return new dns.promises.Resolver({ timeout: 3000, tries: 2 });
}

const realDeps: HuntDeps = {
  fetch: (...args) => fetch(...args),
  resolve4: async (name) => {
    try {
      return await (await resolver()).resolve4(name);
    } catch {
      return [];
    }
  },
  resolve6: async (name) => {
    try {
      return await (await resolver()).resolve6(name);
    } catch {
      return [];
    }
  },
  lookup: async (name) => {
    const dns = await import('node:dns/promises');
    return (await dns.lookup(name, { all: true, verbatim: true })).map((x) => x.address);
  },
  tlsInspect,
  globalping: (token) =>
    new Globalping({
      auth: token || undefined,
      userAgent: GLOBALPING_USER_AGENT,
      timeout: 20_000,
    }) as unknown as GlobalpingLike,
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};
let deps: HuntDeps = realDeps;

/** Test seam: swap the network (resolver, dial, handshake, clock). */
export function __setHuntDepsForTests(d: Partial<HuntDeps> | null): void {
  deps = d ? { ...realDeps, ...d } : realDeps;
}

async function readCapped(res: Response, max: number): Promise<string | null> {
  const declared = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > max) return null;
  const body = res.body;
  if (!body) return '';
  const reader = body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    parts.push(value);
  }
  return Buffer.concat(parts).toString('utf8');
}

// --- the list -------------------------------------------------------------------------------------

export const downloadList = internalAction({
  args: { runId: v.id('sniHuntRuns'), gen: v.number() },
  handler: async (ctx, a): Promise<{ ok: boolean; error?: string; total?: number }> => {
    const info: { depth: number; wwwDepth: number } | null = await ctx.runQuery(
      internal.sniHunt.runInfo,
      a,
    );
    if (!info) return { ok: false };
    const fail = async (error: string) => {
      await ctx.runMutation(internal.sniHunt.runFailed, { ...a, error });
      return { ok: false, error };
    };
    let latest: ReturnType<typeof parseTrancoLatest>;
    try {
      const res = await deps.fetch(TRANCO_LATEST_URL, {
        signal: AbortSignal.timeout(20_000),
        redirect: 'error',
      });
      if (!res.ok) return await fail('list_unavailable');
      latest = parseTrancoLatest(JSON.parse((await readCapped(res, 64 * 1024)) ?? 'null'));
    } catch {
      return await fail('list_unreachable');
    }
    if (!latest) return await fail('list_bad_answer');
    let csv: string | null;
    try {
      // The list service answers the download with a redirect to its file store.
      const res = await deps.fetch(trancoDownloadUrl(latest.listId, info.depth), {
        signal: AbortSignal.timeout(LIST_TIMEOUT_MS),
      });
      if (!res.ok) return await fail('list_unavailable');
      csv = await readCapped(res, LIST_MAX_BYTES);
    } catch {
      return await fail('list_unreachable');
    }
    if (csv === null) return await fail('list_too_large');
    const entries = trancoEntries(csv, info.depth, info.wwwDepth);
    if (entries.length === 0) return await fail('list_bad_answer');
    const chunks: Id<'sniHuntChunks'>[] = [];
    try {
      for (let i = 0; i < entries.length; i += SWEEP_CHUNK_ENTRIES) {
        const id: Id<'sniHuntChunks'> | null = await ctx.runMutation(internal.sniHunt.storeChunk, {
          ...a,
          index: i / SWEEP_CHUNK_ENTRIES,
          text: encodeChunk(entries.slice(i, i + SWEEP_CHUNK_ENTRIES)),
        });
        // Cancelled while downloading: what was stored goes with the run.
        if (!id) return { ok: false };
        chunks.push(id);
      }
    } catch {
      return await fail('store_failed');
    }
    const r: { ok: boolean } = await ctx.runMutation(internal.sniHunt.listReady, {
      ...a,
      chunks,
      total: entries.length,
      listId: latest.listId,
      listDate: latest.date,
    });
    return { ok: r.ok, total: entries.length };
  },
});

// --- the sweep ------------------------------------------------------------------------------------

/**
 * Resolve names at no more than `perSecond` lookups a second: each lookup
 * starts on its own slot, so the pace holds whatever the answers take.
 */
async function resolvePaced(
  names: readonly string[],
  withV6: boolean,
  perSecond: number,
): Promise<string[][]> {
  const slot = 1000 / perSecond;
  const pending: Promise<string[]>[] = [];
  for (const name of names) {
    pending.push(deps.resolve4(name));
    await deps.sleep(slot);
    if (withV6) {
      pending.push(deps.resolve6(name));
      await deps.sleep(slot);
    }
  }
  const answers = await Promise.all(pending);
  const per = withV6 ? 2 : 1;
  return names.map((_, i) => answers.slice(i * per, i * per + per).flat());
}

type StepOutcome = {
  claimed: boolean;
  done?: boolean;
  discarded?: boolean;
  failed?: boolean;
  batches?: number;
};

export const sweepStep = internalAction({
  args: { runId: v.id('sniHuntRuns') },
  handler: async (ctx, a): Promise<StepOutcome> => {
    const started = deps.now();
    const leaseId = randomUUID();
    const claim: {
      gen: number;
      cursor: number;
      total: number;
      chunks: string[];
      lookupsPerSecond: number;
    } | null = await ctx.runMutation(internal.sniHunt.stepClaim, {
      runId: a.runId,
      leaseId,
      now: deps.now(),
    });
    if (!claim) return { claimed: false };
    const read: { key: string; prefixes: NetworkPrefixes }[] = await ctx.runQuery(
      internal.sniHunt.sweepNetworks,
      {},
    );
    const networks = read.map((n) => ({
      key: n.key,
      ranges: compileRanges(n.prefixes),
    }));
    // No network is hunting any more: the run ends here rather than idle on.
    if (networks.length === 0) {
      await ctx.runMutation(internal.sniHunt.runFailed, {
        runId: a.runId,
        gen: claim.gen,
        error: 'no_network',
      });
      return { claimed: true, failed: true };
    }
    const withV6 = networks.some((n) => hasV6(n.ranges));
    const perName = withV6 ? 2 : 1;
    const batchMs = ((SWEEP_BATCH * perName) / claim.lookupsPerSecond) * 1000 + LOOKUP_TAIL_MS;
    let cursor = claim.cursor;
    let chunk = null as { index: number; entries: ListEntry[] } | null;
    let batches = 0;
    while (cursor < claim.total) {
      if (deps.now() - started + batchMs > STEP_DEADLINE_MS) break;
      const index = Math.floor(cursor / SWEEP_CHUNK_ENTRIES);
      if (chunk?.index !== index) {
        const text: string | null = await ctx.runQuery(internal.sniHunt.chunkText, {
          id: claim.chunks[index] as Id<'sniHuntChunks'>,
        });
        if (text === null) {
          await ctx.runMutation(internal.sniHunt.runFailed, {
            runId: a.runId,
            gen: claim.gen,
            error: 'list_lost',
          });
          return { claimed: true, failed: true };
        }
        chunk = { index, entries: decodeChunk(text) };
      }
      const offset = cursor - index * SWEEP_CHUNK_ENTRIES;
      const batch = chunk.entries.slice(offset, offset + SWEEP_BATCH);
      if (batch.length === 0) break;
      const answers = await resolvePaced(
        batch.map((e) => e.name),
        withV6,
        claim.lookupsPerSecond,
      );
      const hits = batch.flatMap((e, i) => {
        const hit = networksHit(answers[i]!, networks);
        return hit.length > 0 ? [{ name: e.name, rank: e.rank, networks: hit }] : [];
      });
      const r: { ok: boolean; done?: boolean } = await ctx.runMutation(
        internal.sniHunt.stepCheckpoint,
        {
          runId: a.runId,
          gen: claim.gen,
          leaseId,
          from: cursor,
          to: cursor + batch.length,
          lookups: batch.length * perName,
          hits,
          now: deps.now(),
        },
      );
      // Cancelled, overtaken or out of its lease: what it resolved is discarded.
      if (!r.ok) return { claimed: true, discarded: true, batches };
      batches++;
      cursor += batch.length;
      if (r.done) return { claimed: true, done: true, batches };
    }
    await ctx.runMutation(internal.sniHunt.stepRelease, { runId: a.runId, leaseId });
    await ctx.scheduler.runAfter(STEP_GAP_MS, internal.sniHuntOps.sweepStep, { runId: a.runId });
    return { claimed: true, batches };
  },
});

// --- checks ---------------------------------------------------------------------------------------

type CheckResult = {
  code: string | null;
  dialled?: string;
  port?: number;
  tlsVersion?: string;
  alpn?: string;
  answers: { v4: number; v6: number; onNetwork: 'all' | 'some' | 'none' | 'unknown' };
  shown: string[];
  extra?: { x25519?: boolean; mlkem?: boolean; error?: string };
};

/**
 * One candidate. The verdict is the one qualification would give it: for a
 * family candidate the family's target is dialled (through the same guarded
 * dial) presenting the name, and the target and the name must both be on the
 * family's network; a network candidate is its own target. Every A and AAAA
 * answer counts for the network.
 */
async function checkOne(c: ClaimedCheck, p: NetworkPrefixes | undefined): Promise<CheckResult> {
  const [a4, a6] = await Promise.all([deps.resolve4(c.name), deps.resolve6(c.name)]);
  const answers = [...a4, ...a6];
  const base = {
    answers: { v4: a4.length, v6: a6.length, onNetwork: answersOnNetwork(answers, p) },
    shown: shownAnswers(answers, p),
  };
  let shake: HandshakeResult;
  let dial: { host: string; port: number } | null = null;
  let requireH2: boolean;
  if (c.target) {
    requireH2 = c.target.requireH2;
    const at = await dialAddress(c.target.address, deps.lookup);
    if (!at.ok) shake = { ok: false, error: at.error };
    else {
      const off = p ? qualificationNetworkCode(at.all, answers, p) : null;
      if (off) shake = { ok: false, error: off };
      else {
        dial = { host: at.host, port: c.target.port };
        shake = await deps.tlsInspect({ ...dial, servername: c.name });
      }
    }
  } else {
    // A possible target: dialled on one of its own public answers, h2 required.
    requireH2 = true;
    if (answers.length === 0) shake = { ok: false, error: 'no_address' };
    else if (!answers.every((ip) => isPublicIpLiteral(ip)))
      shake = { ok: false, error: 'private_address' };
    else {
      const off = p ? ownTargetCode(qualificationNetworkCode(answers, answers, p)) : null;
      if (off) shake = { ok: false, error: off };
      else {
        dial = { host: a4[0] ?? a6[0]!, port: 443 };
        shake = await deps.tlsInspect({ ...dial, servername: c.name });
      }
    }
  }
  const verdict = judgeHandshake(shake, { requireH2 });
  const out: CheckResult = {
    ...base,
    ...(dial ? { dialled: dial.host, port: dial.port } : {}),
    code: verdict.ok ? null : (verdict.code ?? 'q_unreachable'),
    ...(verdict.tlsVersion ? { tlsVersion: verdict.tlsVersion } : {}),
    ...(verdict.alpn ? { alpn: verdict.alpn } : {}),
  };
  if (!verdict.ok || !dial) return out;
  // Two more facts, recorded apart: whichever way they go (a runtime that
  // does not know the group throws), the verdict stands.
  const at = dial;
  const extraShake = async (ecdhCurve: string): Promise<HandshakeResult> => {
    try {
      return await deps.tlsInspect({ ...at, servername: c.name, ecdhCurve });
    } catch {
      return { ok: false, error: 'unsupported' };
    }
  };
  await deps.sleep(HANDSHAKE_GAP_MS);
  const x = extraFact(await extraShake('X25519'));
  await deps.sleep(HANDSHAKE_GAP_MS);
  const m = extraFact(await extraShake('X25519MLKEM768'));
  const error = x.error ?? m.error;
  out.extra = {
    ...(x.value !== undefined ? { x25519: x.value } : {}),
    ...(m.value !== undefined ? { mlkem: m.value } : {}),
    ...(error ? { error } : {}),
  };
  return out;
}

export const check = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; released: number }> => {
    const started = deps.now();
    const {
      checks,
      networks,
    }: { checks: ClaimedCheck[]; networks: Record<string, NetworkPrefixes> } =
      await ctx.runMutation(internal.sniHunt.claimChecks, { now: deps.now() });
    let done = 0;
    for (const c of checks) {
      if (deps.now() - started > CHECK_DEADLINE_MS) break;
      let r: CheckResult;
      try {
        r = await checkOne(c, c.network ? networks[c.network] : undefined);
      } catch {
        r = {
          code: 'q_unreachable',
          answers: { v4: 0, v6: 0, onNetwork: 'unknown' },
          shown: [],
        };
      }
      await ctx.runMutation(internal.sniHunt.recordCheck, {
        id: c.id,
        gen: c.gen,
        at: deps.now(),
        ...r,
      });
      done++;
      await deps.sleep(HANDSHAKE_GAP_MS);
    }
    const left = checks.slice(done).map((c) => ({ id: c.id, gen: c.gen }));
    if (left.length > 0) await ctx.runMutation(internal.sniHunt.releaseChecks, { items: left });
    return { checked: done, released: left.length };
  },
});

// --- a target's certificate, certificate transparency --------------------------------------------

type CertOutcome =
  | ({ ok: true; listed: number } & UpsertTally)
  | { ok: false; code: string | undefined };

export const readCert = internalAction({
  args: { slug: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a): Promise<CertOutcome> => {
    const t: { address: string; port: number; servername: string } = await ctx.runQuery(
      internal.sniHunt.certTarget,
      { slug: a.slug },
    );
    const at = await dialAddress(t.address, deps.lookup);
    if (!at.ok) return { ok: false as const, code: judgeHandshake(at, { requireH2: false }).code };
    const shake = await deps.tlsInspect({
      host: at.host,
      port: t.port,
      servername: t.servername,
      wantNames: true,
    });
    if (!shake.ok)
      return { ok: false as const, code: judgeHandshake(shake, { requireH2: false }).code };
    const tally: UpsertTally = await ctx.runMutation(internal.sniHunt.addFamilyCandidates, {
      slug: a.slug,
      source: 'cert',
      names: shake.names ?? [],
      ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
    });
    return { ok: true as const, listed: shake.names?.length ?? 0, ...tally };
  },
});

export const ctStep = internalAction({
  args: {},
  handler: async (ctx): Promise<{ read: boolean; kind?: string }> => {
    const claim: { id: Id<'sniHuntCt'>; domain: string; after: string | null } | null =
      await ctx.runMutation(internal.sniHunt.claimCt, { now: deps.now() });
    if (!claim) return { read: false };
    let outcome:
      | { kind: 'page'; names: string[]; lastId: string | null; done: boolean }
      | { kind: 'rate_limited'; retryAt: number }
      | { kind: 'error'; code: string };
    try {
      const res = await deps.fetch(certSpotterUrl(claim.domain, claim.after ?? undefined), {
        signal: AbortSignal.timeout(CT_TIMEOUT_MS),
        redirect: 'error',
        headers: { accept: 'application/json' },
      });
      if (res.status === 429)
        outcome = {
          kind: 'rate_limited',
          retryAt: retryAfterMs(res.headers.get('retry-after'), deps.now()),
        };
      else if (!res.ok) outcome = { kind: 'error', code: `http_${res.status}` };
      else {
        const text = await readCapped(res, CT_MAX_BYTES);
        const page = text === null ? null : parseCertSpotterPage(JSON.parse(text));
        outcome = page ? { kind: 'page', ...page } : { kind: 'error', code: 'bad_answer' };
      }
    } catch (err) {
      const name = (err as { name?: string })?.name;
      outcome = {
        kind: 'error',
        code: name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'unreachable',
      };
    }
    await ctx.runMutation(internal.sniHunt.recordCt, { id: claim.id, outcome, now: deps.now() });
    // More may be due and the budget may still have room: the next claim decides.
    if (outcome.kind === 'page')
      await ctx.scheduler.runAfter(CT_GAP_MS, internal.sniHuntOps.ctStep, {});
    return { read: true, kind: outcome.kind };
  },
});

// --- evidence: timing and OONI -----------------------------------------------------------------------

/** A measurement is given at most this long to finish. */
const MEASURE_DEADLINE_MS = 45_000;
const OONI_TIMEOUT_MS = 20_000;
/**
 * One deadline for a whole evidence run, inside the 120 s action limit: no
 * timing starts past 40 s and none waits past 70 s; no OONI request starts
 * past 75 s and none waits past 100 s. What a run cannot get to is handed back
 * (`releaseEvidence`).
 */
const TIMING_START_UNTIL_MS = 40_000;
const TIMING_WAIT_UNTIL_MS = 70_000;
const OONI_START_UNTIL_MS = 75_000;
const RUN_END_MS = 100_000;

/** One Globalping measurement, created and waited for (at most `waitMs`); its items, or null. */
async function measure(
  client: GlobalpingLike,
  req: unknown,
  waitMs: number,
): Promise<unknown[] | null> {
  const res = await client.createMeasurement(req);
  const id = res.ok ? (res.data as { id?: unknown } | undefined)?.id : undefined;
  if (typeof id !== 'string') return null;
  const deadline = deps.now() + Math.max(0, waitMs);
  while (deps.now() < deadline) {
    await deps.sleep(2000);
    const r = await client.getMeasurement(id);
    const data = r.ok ? (r.data as { status?: unknown; results?: unknown }) : null;
    if (data?.status === 'finished') return Array.isArray(data.results) ? data.results : [];
  }
  return null;
}

async function ooniFor(domain: string, curated: readonly string[], timeoutMs: number) {
  try {
    const res = await deps.fetch(ooniUrl(domain, deps.now()), {
      signal: AbortSignal.timeout(Math.max(1000, timeoutMs)),
      redirect: 'error',
      headers: { accept: 'application/json' },
    });
    if (!res.ok) return null;
    const text = await readCapped(res, 2 * 1024 * 1024);
    return text === null ? null : parseOoni(JSON.parse(text), curated);
  } catch {
    return null;
  }
}

/**
 * Evidence for the shortlist: timing from the network's place (the family's
 * target presenting the name, which is what REALITY relays to; the candidate's
 * own site at the same time, apart), and OONI for the exact name and, as
 * context, its site. Bounded by one deadline for the whole run.
 */
export const evidence = internalAction({
  args: {},
  handler: async (ctx): Promise<{ timed: number; ooni: number; released: number }> => {
    const started = deps.now();
    const until = (ms: number) => started + ms - deps.now();
    const work: { timing: TimingItem[]; ooni: OoniItem[]; curated: string[]; token: string } =
      await ctx.runMutation(internal.sniHunt.claimEvidence, { now: started });
    const release: Array<{
      id: Id<'sniCandidates'>;
      calls: Id<'sniHuntCalls'>[];
      measure: boolean;
    }> = [];
    let timed = 0;
    if (work.timing.length > 0) {
      const client = deps.globalping(work.token);
      let stop = false;
      for (const t of work.timing) {
        const req = timingRequest({ address: t.address, port: t.port, host: t.host }, t.place);
        if (!stop && until(TIMING_START_UNTIL_MS) <= 0) stop = true;
        if (!stop) {
          const tests = globalpingTestsOf(req) * (t.own ? 2 : 1);
          if ((await globalpingFits(client, tests)) === false) stop = true;
        }
        if (stop) {
          release.push({ id: t.id, calls: t.calls, measure: t.measure });
          continue;
        }
        const wait = Math.min(MEASURE_DEADLINE_MS, until(TIMING_WAIT_UNTIL_MS));
        // The target and the candidate's own site from the same place, at the same time.
        const [items, ownItems] = await Promise.all([
          measure(client, req, wait),
          t.own
            ? measure(
                client,
                timingRequest({ address: t.own.address, port: t.own.port, host: t.host }, t.place),
                wait,
              )
            : Promise.resolve(null),
        ]);
        const main = items ? timingOf(items, t.place.country) : null;
        const o = ownItems ? timingOf(ownItems, t.place.country) : null;
        await ctx.runMutation(internal.sniHunt.recordTiming, {
          id: t.id,
          at: deps.now(),
          place: placeKey(t.place),
          endpoint: t.address,
          port: t.port,
          ...(main ? { timing: main } : {}),
          ...(o && t.own ? { own: { endpoint: t.own.address, port: t.own.port, timing: o } } : {}),
        });
        if (main) timed++;
      }
    }
    let read = 0;
    if (work.ooni.length > 0 && until(OONI_START_UNTIL_MS) <= 0) {
      for (const o of work.ooni) release.push({ id: o.id, calls: [], measure: o.measure });
    } else if (work.ooni.length > 0) {
      const timeout = Math.min(OONI_TIMEOUT_MS, until(RUN_END_MS));
      const answers = await Promise.all(
        work.ooni.map(async (o) => {
          // The site's apex and www: context only, never scored for another name.
          const siteNames = [...new Set([o.site, `www.${o.site}`])].filter((d) => d !== o.name);
          const [exact, ...sites] = await Promise.all([
            ooniFor(o.name, work.curated, timeout),
            ...siteNames.map((d) => ooniFor(d, work.curated, timeout)),
          ]);
          return { o, exact, sites };
        }),
      );
      for (const { o, exact, sites } of answers) {
        if (!exact) continue;
        const site: NonNullable<typeof exact> = [];
        for (const r of sites) {
          if (!r) continue;
          for (const x of r) {
            const prev = site.find((y) => y.cc === x.cc);
            if (!prev) site.push(x);
            else if (x.measurements > prev.measurements) Object.assign(prev, x);
          }
        }
        await ctx.runMutation(internal.sniHunt.recordOoni, {
          id: o.id,
          at: deps.now(),
          exact,
          site,
        });
        read++;
      }
    }
    if (release.length > 0)
      await ctx.runMutation(internal.sniHunt.releaseEvidence, { items: release, now: deps.now() });
    return { timed, ooni: read, released: release.length };
  },
});

// --- evidence: real-site checks from inside a country ----------------------------------------------

/**
 * One in-country batch (admitted by the vantage planner): Globalping `HEAD /`
 * from probes in the country to each candidate's own on-network address,
 * presenting its name, every name from the first measurement's probes. Its
 * gates are checked again first; a closed gate settles the rows without
 * dialling anything, and an address that is one of FCP's own is never dialled.
 */
export const countryBatch = internalAction({
  args: { batch: v.string() },
  handler: async (ctx, a): Promise<{ measured: number; gate: string | null }> => {
    const c: {
      gate: string | null;
      country: string;
      perCountryLimit: number;
      preferEyeball: boolean;
      spacingMs: number;
      token: string;
      rows: Array<{ id: Id<'sniHuntProbes'>; name: string; address: string; ours: boolean }>;
    } | null = await ctx.runQuery(internal.sniHunt.countryBatchContext, a);
    if (!c) return { measured: 0, gate: null };
    type Settle = {
      id: Id<'sniHuntProbes'>;
      status: 'finished' | 'failed' | 'skipped';
      results: Array<{
        vantage?: string;
        asn?: string;
        network?: string;
        outcome: string;
        stage?: string;
      }>;
      error?: string;
    };
    const settle: Settle[] = [];
    if (c.gate) {
      for (const r of c.rows)
        settle.push({ id: r.id, status: 'skipped', results: [], error: c.gate });
      await ctx.runMutation(internal.sniHunt.recordCountryBatch, {
        batch: a.batch,
        rows: settle,
        now: deps.now(),
      });
      return { measured: 0, gate: c.gate };
    }
    const client = deps.globalping(c.token);
    const created: Array<{ row: (typeof c.rows)[number]; mid: string }> = [];
    let first: string | null = null;
    for (const [i, row] of c.rows.entries()) {
      if (row.ours) {
        settle.push({ id: row.id, status: 'skipped', results: [], error: 'real_is_ours' });
        continue;
      }
      if (i > 0) await deps.sleep(c.spacingMs);
      const t = { address: row.address, port: 443, name: row.name };
      const where = first
        ? { reuse: first }
        : { country: c.country, limit: c.perCountryLimit, preferEyeball: c.preferEyeball };
      let res = await client.createMeasurement(globalpingNameRequest(t, where));
      if (!res.ok && !first && c.preferEyeball && isNoProbesError(res.response?.status, res.data))
        res = await client.createMeasurement(
          globalpingNameRequest(t, { country: c.country, limit: c.perCountryLimit }),
        );
      const mid = res.ok ? (res.data as { id?: unknown } | undefined)?.id : undefined;
      if (typeof mid !== 'string') {
        settle.push({
          id: row.id,
          status: 'failed',
          results: [],
          error: isNoProbesError(res.response?.status, res.data) ? 'no_probes' : 'create_failed',
        });
        continue;
      }
      first ??= mid;
      created.push({ row, mid });
    }
    const deadline = deps.now() + MEASURE_DEADLINE_MS;
    const pending = new Map(created.map((x) => [x.mid, x]));
    while (pending.size > 0 && deps.now() < deadline) {
      await deps.sleep(3000);
      for (const [mid, { row }] of pending) {
        const r = await client.getMeasurement(mid);
        const data = r.ok ? (r.data as { status?: unknown; results?: unknown }) : null;
        if (data?.status !== 'finished') continue;
        const results = parseGlobalpingNameResults(data.results, c.country, [
          row.name,
          row.address,
        ]);
        settle.push({
          id: row.id,
          status: 'finished',
          results: results.map((x) => ({
            ...(x.vantage ? { vantage: x.vantage } : {}),
            ...(x.asn ? { asn: x.asn } : {}),
            ...(x.network ? { network: x.network } : {}),
            outcome: x.outcome,
            ...(x.stage ? { stage: x.stage } : {}),
          })),
        });
        pending.delete(mid);
      }
    }
    for (const { row } of pending.values())
      settle.push({ id: row.id, status: 'failed', results: [], error: 'timeout' });
    await ctx.runMutation(internal.sniHunt.recordCountryBatch, {
      batch: a.batch,
      rows: settle,
      now: deps.now(),
    });
    return { measured: created.length, gate: null };
  },
});
