'use node';
/**
 * Reachability probe executor — the "use node" half (the Globalping SDK and
 * outbound fetches live here). One run per invocation: start the measurement,
 * poll until it finishes or the source's ceiling passes, then hand the results
 * to probes.finishRun. Nothing here reads or writes member data; the
 * target is one of FCP's own edge addresses.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import Globalping from 'globalping';
import {
  GLOBALPING_USER_AGENT,
  globalpingPoll,
  globalpingStart,
  type GlobalpingLike,
} from './lib/edges/probes/globalping';
import { checkhostNodes, checkhostPoll, checkhostStart } from './lib/edges/probes/checkhost';
import { ripeAtlasPoll, ripeAtlasStart, type AtlasStarted } from './lib/edges/probes/ripeatlas';
import { internalProbe } from './lib/edges/probes/internal';
import { shortError, type ProbeResult, type ProbeTarget } from './lib/edges/probes/types';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

let globalpingFactory: (token: string) => GlobalpingLike = (token) =>
  new Globalping({
    auth: token || undefined,
    userAgent: GLOBALPING_USER_AGENT,
    timeout: 20_000,
  }) as unknown as GlobalpingLike;

/** Test seam: swap the SDK client. */
export function __setGlobalpingFactory(f: typeof globalpingFactory | null): void {
  globalpingFactory =
    f ?? ((token) => new Globalping({ auth: token || undefined }) as unknown as GlobalpingLike);
}

function parseTarget(target: string, ipVersion: 4 | 6): ProbeTarget {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(target);
  if (!m) return { address: target, port: 443, ipVersion };
  return { address: m[1], port: Number(m[2]), ipVersion };
}

async function finish(ctx: ActionCtx, runId: Id<'probeRuns'>, results: ProbeResult[]) {
  await ctx.runMutation(internal.probes.finishRun, { runId, results });
}

async function fail(ctx: ActionCtx, runId: Id<'probeRuns'>, err: unknown, timeout = false) {
  await ctx.runMutation(internal.probes.failRun, { runId, error: shortError(err), timeout });
}

export const execute = internalAction({
  args: { runId: v.id('probeRuns') },
  handler: async (ctx, { runId }): Promise<null> => {
    const c = await ctx.runQuery(internal.probes.runContext, { runId });
    if (!c || c.run.status !== 'requested') return null;
    const { run, cfg, secrets } = c;
    const target = parseTarget(run.target, run.ipVersion);
    const opts = {
      countries: cfg.probe.countries,
      perCountryLimit: cfg.probe.perCountryLimit,
      preferEyeball: cfg.probe.preferEyeball,
    };
    try {
      switch (run.source) {
        case 'internal': {
          await ctx.runMutation(internal.probes.markRunning, { runId });
          const r = await internalProbe(fetch, target);
          await finish(ctx, runId, [r]);
          return null;
        }
        case 'globalping': {
          const client = globalpingFactory(secrets.globalpingToken);
          const started = await globalpingStart(client, target, opts);
          await ctx.runMutation(internal.probes.markRunning, {
            runId,
            externalId: started.externalId,
          });
          const deadline = Date.now() + 60_000;
          while (Date.now() < deadline) {
            await sleep(3000);
            const p = await globalpingPoll(client, started.externalId);
            if (p.status === 'finished') {
              await finish(ctx, runId, p.results);
              return null;
            }
          }
          await fail(ctx, runId, 'globalping timeout', true);
          return null;
        }
        case 'checkhost': {
          const nodes = await checkhostNodes(fetch);
          const started = await checkhostStart(fetch, target, opts, nodes);
          await ctx.runMutation(internal.probes.markRunning, {
            runId,
            externalId: started.externalId,
          });
          const asns: Record<string, string | undefined> = {};
          for (const n of nodes) asns[n.host] = n.asn;
          const deadline = Date.now() + 40_000;
          let last: ProbeResult[] = [];
          while (Date.now() < deadline) {
            await sleep(3000);
            const p = await checkhostPoll(fetch, started.externalId, started.nodeCountries, asns);
            last = p.results;
            if (p.status === 'finished') {
              await finish(ctx, runId, p.results);
              return null;
            }
          }
          // Partial answers are still evidence; pending nodes are simply absent.
          if (last.length > 0) await finish(ctx, runId, last);
          else await fail(ctx, runId, 'check-host timeout', true);
          return null;
        }
        case 'ripeatlas': {
          if (!secrets.ripeAtlasKey) {
            await fail(ctx, runId, 'ripe atlas key not set');
            return null;
          }
          const started: AtlasStarted = await ripeAtlasStart(
            fetch,
            secrets.ripeAtlasKey,
            target,
            opts,
          );
          await ctx.runMutation(internal.probes.markRunning, {
            runId,
            externalId: JSON.stringify(started.measurements).slice(0, 200),
          });
          const deadline = Date.now() + 150_000;
          let last: ProbeResult[] = [];
          while (Date.now() < deadline) {
            await sleep(10_000);
            const p = await ripeAtlasPoll(
              fetch,
              secrets.ripeAtlasKey,
              started,
              cfg.probe.perCountryLimit,
            );
            last = p.results;
            if (p.status === 'finished') {
              await finish(ctx, runId, p.results);
              return null;
            }
          }
          if (last.length > 0) await finish(ctx, runId, last);
          else await fail(ctx, runId, 'ripe atlas timeout', true);
          return null;
        }
        default:
          await fail(ctx, runId, `unknown source ${String(run.source)}`);
          return null;
      }
    } catch (err) {
      await fail(ctx, runId, err);
      return null;
    }
  },
});
