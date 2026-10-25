/**
 * The country view, DB half (docs/edges.md "The country view"): one read of
 * every enabled origin, its listeners, active edges and published pool, and
 * the per-country evidence of each (edge tracks, marks, location grades,
 * address-level probes, the names' marks, the checks from inside, member
 * reports), handed to the pure builder (lib/edges/country/view.ts) once per
 * country. Read only: nothing here writes.
 *
 * Admin only. No member row is read: "handed" is computed over synthetic
 * render keys. The response carries addresses and names (the admin pages
 * already show them); audit rows are untouched.
 */
import { v } from 'convex/values';
import { internalQuery, type QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { resolveEdgeConfig, controlCountriesOf } from './lib/edgeConfig';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { resolveSniConfig, resolveSniVantageConfig, vantageCountries } from './lib/sniConfig';
import { resolveEdgeSecrets } from './lib/edgeConfig';
import { usableSources } from './lib/sniConfig';
import { resolveMemberCountryConfig } from './memberCountry';
import { publishedEdgesOf, deliveryStyleOf } from './edgeRender';
import { listenersOf } from './relayListeners';
import { effectiveRule, ruleCanEmitV6, ruleForDelivery } from './lib/edges/render';
import { countryGroupKey } from './lib/edges/country/group';
import { dayOf, suspectNames, type NameCount } from './lib/edges/sni/health';
import { suggest } from './lib/edges/sni/vantage';
import {
  buildCountryView,
  type EdgeInput,
  type NameFacts,
  type OriginInput,
  type ReachRow,
  type ViewSettings,
} from './lib/edges/country/view';

type Db = QueryCtx['db'];
const DAY = 86_400_000;
/** Report rows read per country, newest days first (the names page reads them the same way). */
const REPORT_ROWS = 8000;

/** The same shape for every reachability summary (an edge, an origin). */
function reachRows(r: Doc<'edges'>['reachability']): ReachRow[] {
  return (r?.byCountry ?? []).map((c) => ({
    country: c.country,
    verdict: c.verdict,
    ...(c.v6Verdict ? { v6Verdict: c.v6Verdict } : {}),
    ...(c.nameVerdict ? { nameVerdict: c.nameVerdict } : {}),
    okVantages: c.okVantages,
    failVantages: c.failVantages,
    lastAt: c.lastAt,
    ...(c.wasReachable !== undefined ? { wasReachable: c.wasReachable } : {}),
    ...(c.neverReached ? { neverReached: c.neverReached } : {}),
  }));
}

/** Everything that does not depend on the country, read once. */
interface Loaded {
  origins: Array<{
    input: Omit<OriginInput, 'edges'>;
    edges: Array<{
      doc: Doc<'edges'>;
      base: Omit<EdgeInput, 'evidence' | 'mark' | 'locationMark' | 'grade'>;
    }>;
    style: 'subscription' | 'single-key';
  }>;
  names: Set<string>;
}

async function load(db: Db): Promise<Loaded> {
  const relays = (
    await db
      .query('relays')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect()
  ).sort((a, b) => a.slug.localeCompare(b.slug));
  const locationLabels = new Map<string, string | null>();
  const labelOf = async (id: Id<'edgeLocations'> | undefined) => {
    if (!id) return null;
    if (!locationLabels.has(id)) locationLabels.set(id, (await db.get(id))?.label ?? null);
    return locationLabels.get(id) ?? null;
  };
  const names = new Set<string>();
  const origins: Loaded['origins'] = [];
  for (const relay of relays) {
    const listeners = (await listenersOf({ db }, relay._id))
      .filter((l) => !l.retired)
      .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey));
    const { published } = await publishedEdgesOf(
      { db },
      relay,
      { kind: 'member' },
      { includeIneligible: true },
    );
    const active = await db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id).eq('status', 'active'))
      .collect();
    const edges: Loaded['origins'][number]['edges'] = [];
    for (const e of active) {
      edges.push({
        doc: e,
        base: {
          edgeId: e._id,
          listenerId: e.listenerId,
          layer: e.layer === 'l7' || e.addresses.hostname ? 'l7' : 'l4',
          provider: e.provider ?? null,
          location: await labelOf(e.locationId),
          status: e.status,
          publication: e.publication,
          poolIndex: e.poolIndex ?? null,
          addresses: {
            ...(e.addresses.v4 ? { v4: e.addresses.v4 } : {}),
            ...(e.addresses.v6 ? { v6: e.addresses.v6 } : {}),
            ...(e.addresses.hostname ? { hostname: e.addresses.hostname } : {}),
          },
          countryState: e.countryState?.byCountry ?? [],
          reachability: reachRows(e.reachability),
        },
      });
    }
    for (const l of listeners)
      for (const n of l.tlsNames ?? [])
        if (n.status === 'active' || n.drainUntil) names.add(n.name);
    origins.push({
      input: {
        relayId: relay._id,
        slug: relay.slug,
        label: relay.label ?? null,
        kind: relay.origin.kind,
        nodeName: relay.origin.kind === 'panel-node' ? relay.origin.nodeName : null,
        enabled: relay.enabled,
        direct: relay.probeNode
          ? { address: relay.originAddress, reachability: reachRows(relay.reachability) }
          : null,
        listeners: listeners.map((l) => ({
          listenerId: l._id,
          key: l.listenerKey,
          protocol: l.protocol,
          streamTransport: l.streamTransport,
          security: l.security,
          usable: l.enabled && l.deployed && !l.retired,
          sniPick: l.sniPick ?? null,
          names: (l.tlsNames ?? []).map((n) => ({
            name: n.name,
            status: n.status,
            ...(n.drainUntil ? { drainUntil: n.drainUntil } : {}),
            blockedIn: n.blockedIn ?? [],
            provenIn: n.provenIn ?? [],
          })),
        })),
        published,
      },
      edges,
      style: relay.backendServerId
        ? await deliveryStyleOf({ db }, relay.backendServerId)
        : 'subscription',
    });
  }
  return { origins, names };
}

/** The settings the builder needs, and the switches the page shows. */
async function settingsOf(db: Db) {
  const [cfg, sni, vantage, censored, member, secrets] = await Promise.all([
    resolveEdgeConfig(db),
    resolveSniConfig(db),
    resolveSniVantageConfig(db),
    resolveCensoredCountries(db),
    resolveMemberCountryConfig(db),
    resolveEdgeSecrets(db),
  ]);
  const rule = effectiveRule(cfg.render, cfg.render.clients.other);
  const vantageOn = sni.enabled && vantage.enabled && usableSources(vantage, secrets).length > 0;
  return {
    cfg,
    sni,
    vantage,
    censored,
    rule,
    switches: {
      probes: cfg.probe.enabled,
      countryChecks: cfg.country.enabled,
      steering: member.steer,
      render: cfg.enabled && cfg.render.enabled && rule.enabled,
      names: sni.enabled,
      nameChecks: vantageOn,
      realHost: vantageOn && vantage.realHost,
    },
    nameCheckCountries: vantageOn ? vantageCountries(vantage, sni.curatedCountries) : [],
    controls: controlCountriesOf(cfg, censored.codes),
  };
}

type Settings = Awaited<ReturnType<typeof settingsOf>>;

/** One country's per-name facts: the family, the mark, the checks (judged now), the reports. */
async function nameFactsFor(
  db: Db,
  names: ReadonlySet<string>,
  country: string,
  st: Settings,
  withReports: boolean,
  now: number,
): Promise<Map<string, NameFacts>> {
  const docs = new Map<string, Doc<'sniNames'> | null>();
  const families = new Map<string, Doc<'sniFamilies'> | null>();
  for (const name of names) {
    const n = await db
      .query('sniNames')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    docs.set(name, n);
    if (n && !families.has(n.familyId)) families.set(n.familyId, await db.get(n.familyId));
  }
  // Member reports there, per family (a suspect is judged against its family's other names).
  const suspects = new Set<string>();
  const weights = new Map<string, number>();
  if (withReports) {
    const since = dayOf(now - st.sni.reportWindowDays * DAY);
    const byFamily = new Map<string, NameCount[]>();
    for (const row of await db
      .query('sniReportCounts')
      .withIndex('by_country_day', (q) => q.eq('country', country).gte('day', since))
      .order('desc')
      .take(REPORT_ROWS)) {
      weights.set(row.name, (weights.get(row.name) ?? 0) + row.weight);
      const fam = docs.get(row.name)?.familyId;
      if (!fam) continue;
      byFamily.set(fam, [
        ...(byFamily.get(fam) ?? []),
        { name: row.name, country: row.country, weight: row.weight },
      ]);
    }
    for (const counts of byFamily.values())
      for (const [name, countries] of suspectNames(counts))
        if (countries.includes(country)) suspects.add(name);
  }
  const out = new Map<string, NameFacts>();
  for (const name of names) {
    const n = docs.get(name) ?? null;
    const markRow = await db
      .query('sniNameCountry')
      .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', country))
      .unique();
    const ev = await db
      .query('sniVantageEvidence')
      .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', country))
      .unique();
    const s = ev
      ? suggest(
          {
            measurements: ev.measurements,
            okVantages: ev.okVantages,
            okNetworks: ev.okNetworks,
            lastOkAt: ev.lastOkAt ?? null,
            lastFailAt: ev.lastFailAt ?? null,
            lastAt: ev.lastAt ?? null,
            latest: ev.latest,
            streak: ev.streak ?? null,
          },
          {
            reportSuspect: suspects.has(name),
            minVantages: st.vantage.minVantages,
            minNetworks: st.vantage.minNetworks,
          },
        )
      : null;
    const weight = weights.get(name);
    out.set(name, {
      family: n ? (families.get(n.familyId)?.slug ?? null) : null,
      qualified: n ? n.qualification.state === 'ok' : null,
      mark: markRow
        ? { state: markRow.state, source: markRow.source, at: markRow.updatedAt }
        : null,
      checks: ev
        ? {
            latest: ev.latest,
            okVantages: ev.okVantages,
            okNetworks: ev.okNetworks,
            failVantages: ev.streak?.nameFailures ?? 0,
            failNetworks: ev.streak?.networks ?? 0,
            pathFailures: ev.streak?.pathFailures ?? 0,
            suggestion: s?.suggestion ?? null,
            reason: s?.reason ?? null,
            lastAt: ev.lastAt ?? null,
            lastOkAt: ev.lastOkAt ?? null,
          }
        : null,
      reports:
        weight !== undefined
          ? { weight: Math.round(weight * 100) / 100, suspect: suspects.has(name) }
          : null,
      realHost: ev?.realHost
        ? {
            at: ev.realHost.at,
            target: ev.realHost.target,
            realAddress: ev.realHost.realAddress ?? null,
            reading: ev.realHost.reading,
            counts: ev.realHost.counts,
            vantages: ev.realHost.vantages,
            networks: ev.realHost.networks,
          }
        : null,
    });
  }
  return out;
}

/** The per-country inputs of every edge: its evidence row, its mark, its location's mark and grade. */
async function edgesFor(db: Db, loaded: Loaded, country: string) {
  const out = new Map<string, EdgeInput[]>();
  for (const o of loaded.origins) {
    const list: EdgeInput[] = [];
    for (const { doc, base } of o.edges) {
      const ev = await db
        .query('edgeCountryEvidence')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', doc._id).eq('country', country))
        .unique();
      const mark = await db
        .query('countryMarks')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', doc._id).eq('country', country))
        .first();
      const groupKey = countryGroupKey(doc);
      const groupMark = await db
        .query('countryMarks')
        .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey).eq('country', country))
        .first();
      const grade = await db
        .query('countryGroupGrades')
        .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey).eq('country', country))
        .unique();
      list.push({
        ...base,
        evidence: ev
          ? {
              address: {
                state: ev.address.state,
                ...(ev.address.reason ? { reason: ev.address.reason } : {}),
                ...(ev.address.decidedAt !== undefined ? { decidedAt: ev.address.decidedAt } : {}),
                ...(ev.address.until !== undefined ? { until: ev.address.until } : {}),
                blockedRounds: ev.address.blockedRounds,
              },
              handshake: {
                state: ev.handshake.state,
                ...(ev.handshake.reason ? { reason: ev.handshake.reason } : {}),
                ...(ev.handshake.until !== undefined ? { until: ev.handshake.until } : {}),
                ...(ev.handshake.lastBatchAt !== undefined
                  ? { lastBatchAt: ev.handshake.lastBatchAt }
                  : {}),
                pathBatches: ev.handshake.pathBatches,
              },
              ...(ev.lastRound
                ? {
                    lastRound: {
                      at: ev.lastRound.at,
                      result: ev.lastRound.result,
                      ...(ev.lastRound.reason ? { reason: ev.lastRound.reason } : {}),
                      ok: ev.lastRound.ok,
                      fail: ev.lastRound.fail,
                      networks: ev.lastRound.networks,
                      controlsOk: ev.lastRound.controlsOk,
                      ...(ev.lastRound.v6Result ? { v6Result: ev.lastRound.v6Result } : {}),
                    },
                  }
                : {}),
              combined: ev.combined,
              ...(ev.stateUntil !== undefined ? { stateUntil: ev.stateUntil } : {}),
            }
          : null,
        mark: mark?.scope === 'edge' ? { state: mark.state, at: mark.at } : null,
        locationMark:
          groupMark?.scope === 'group' ? { state: groupMark.state, at: groupMark.at } : null,
        grade: grade
          ? {
              state: grade.state,
              counts: grade.counts,
              ...(grade.until !== undefined ? { until: grade.until } : {}),
            }
          : null,
      });
    }
    out.set(o.input.relayId, list);
  }
  return out;
}

function viewSettings(
  st: Settings,
  country: string,
  now: number,
  style: 'subscription' | 'single-key',
): ViewSettings {
  const rule = ruleForDelivery(st.rule, style);
  return {
    now,
    country,
    curated: st.sni.curatedCountries,
    steering: st.switches.steering,
    render: st.switches.render,
    rule: {
      includeBackup: rule.includeBackup,
      // A plain list of links (no auto group): the most conservative path.
      canEmitV6: ruleCanEmitV6(rule, false),
      namesPerEndpoint: rule.namesPerEndpoint,
      backupNames: rule.backupNames,
    },
    preferDistinctProviders: st.cfg.render.preferDistinctProviders,
    minProvenForExclusive: st.cfg.country.minProvenForExclusive,
  };
}

async function viewOf(
  db: Db,
  loaded: Loaded,
  st: Settings,
  country: string,
  now: number,
  withReports: boolean,
) {
  const facts = await nameFactsFor(db, loaded.names, country, st, withReports, now);
  const edges = await edgesFor(db, loaded, country);
  // Each origin is built with its own delivery style (a single-key backend hands out no backup).
  const origins = [];
  const totals = {
    addresses: { proven: 0, blocked: 0, unknown: 0 },
    names: { proven: 0, blocked: 0, unknown: 0 },
    originsAtRisk: 0,
    lastEvidenceAt: null as number | null,
  };
  const seen = new Set<string>();
  for (const o of loaded.origins) {
    const r = buildCountryView(
      [{ ...o.input, edges: edges.get(o.input.relayId) ?? [] }],
      (name) => facts.get(name) ?? null,
      viewSettings(st, country, now, o.style),
    );
    origins.push(...r.origins);
    for (const k of ['proven', 'blocked', 'unknown'] as const)
      totals.addresses[k] += r.totals.addresses[k];
    totals.originsAtRisk += r.totals.originsAtRisk;
    if (r.totals.lastEvidenceAt !== null)
      totals.lastEvidenceAt = Math.max(totals.lastEvidenceAt ?? 0, r.totals.lastEvidenceAt);
    // Names count once across origins (the first listener that carries one decides).
    for (const ov of r.origins)
      for (const l of ov.listeners)
        for (const n of l.names)
          if (n.status === 'active' && !seen.has(n.name)) {
            seen.add(n.name);
            totals.names[n.state]++;
          }
  }
  return { origins, totals };
}

function listedOf(st: Settings, country: string) {
  const row = st.censored.list.find((c) => c.code === country);
  return row
    ? {
        checkEdges: row.checkEdges,
        checkNamesInside: row.checkNamesInside,
        nameChecksRun: st.nameCheckCountries.includes(country),
      }
    : null;
}

/** Every listed country, in list order, with its totals. */
export const summary = internalQuery({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const st = await settingsOf(ctx.db);
    const loaded = await load(ctx.db);
    const countries = [];
    for (const c of st.censored.list) {
      const { totals, origins } = await viewOf(ctx.db, loaded, st, c.code, now, false);
      const handedBlocked = origins.flatMap((o) =>
        o.listeners.filter((l) => l.members.computed).map((l) => l.members.onBlockedAddress),
      );
      countries.push({
        country: c.code,
        listed: listedOf(st, c.code)!,
        totals,
        /** The worst share of members on an address blocked there, over every transport. */
        worstOnBlocked: handedBlocked.length > 0 ? Math.max(...handedBlocked) : null,
      });
    }
    return {
      generatedAt: now,
      switches: st.switches,
      controls: st.controls,
      origins: loaded.origins.length,
      countries,
    };
  },
});

/** One country in full. `country` is any ISO code; an unlisted one says so. */
export const country = internalQuery({
  args: { country: v.string() },
  handler: async (ctx, a) => {
    const now = Date.now();
    const code = a.country.trim().toUpperCase();
    const st = await settingsOf(ctx.db);
    const loaded = await load(ctx.db);
    const { origins, totals } = await viewOf(ctx.db, loaded, st, code, now, true);
    return {
      country: code,
      generatedAt: now,
      listed: listedOf(st, code),
      switches: st.switches,
      controls: st.controls,
      curated: st.sni.curatedCountries.includes(code),
      totals,
      origins,
    };
  },
});
