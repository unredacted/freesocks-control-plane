/**
 * The country view, DB half (docs/edges.md "The country view"): one read of
 * every enabled origin, its listeners, active edges and published pool, and
 * the per-country evidence of each (edge tracks, marks, location grades,
 * address-level probes, the names' marks, the checks from inside, member
 * reports), handed to the pure builder (lib/edges/country/view.ts) once per
 * country. Read only: nothing here writes.
 *
 * Every per-edge, per-location and per-name read covers EVERY country in one
 * index range (`prefetch`), and each country is then built in memory: the
 * summary of a 40-country list costs the reads of one country (a transaction
 * may touch 4,096 index ranges).
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
import { readingOf } from './lib/edges/sni/realHost';
import {
  actedState,
  buildCountryView,
  type EdgeInput,
  type NameFacts,
  type OriginInput,
  type ReachRow,
  type ViewSettings,
} from './lib/edges/country/view';

type Db = QueryCtx['db'];
const DAY = 86_400_000;
/** Report rows read for one country, newest days first (the checks from inside read them the same way). */
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
      groupKey: string;
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
        groupKey: countryGroupKey(e),
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

const keyOf = (ref: string, country: string) => `${ref}|${country}`;

/**
 * Every country's evidence rows of every edge, location and name, read once:
 * one index range per edge, location and name, whatever the number of
 * countries (rows per key are bounded by the countries checked).
 */
interface Prefetched {
  edgeEvidence: Map<string, Doc<'edgeCountryEvidence'>>;
  edgeMarks: Map<string, Doc<'countryMarks'>>;
  groupMarks: Map<string, Doc<'countryMarks'>>;
  grades: Map<string, Doc<'countryGroupGrades'>>;
  names: Map<string, Doc<'sniNames'> | null>;
  families: Map<string, Doc<'sniFamilies'> | null>;
  nameMarks: Map<string, Doc<'sniNameCountry'>>;
  vantage: Map<string, Doc<'sniVantageEvidence'>>;
}

async function prefetch(db: Db, loaded: Loaded): Promise<Prefetched> {
  const p: Prefetched = {
    edgeEvidence: new Map(),
    edgeMarks: new Map(),
    groupMarks: new Map(),
    grades: new Map(),
    names: new Map(),
    families: new Map(),
    nameMarks: new Map(),
    vantage: new Map(),
  };
  const groups = new Set<string>();
  for (const o of loaded.origins)
    for (const { doc, groupKey } of o.edges) {
      groups.add(groupKey);
      for (const r of await db
        .query('edgeCountryEvidence')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', doc._id))
        .collect())
        p.edgeEvidence.set(keyOf(doc._id, r.country), r);
      for (const m of await db
        .query('countryMarks')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', doc._id))
        .collect())
        if (m.scope === 'edge') p.edgeMarks.set(keyOf(doc._id, m.country), m);
    }
  for (const g of groups) {
    for (const m of await db
      .query('countryMarks')
      .withIndex('by_group_country', (q) => q.eq('groupKey', g))
      .collect())
      if (m.scope === 'group') p.groupMarks.set(keyOf(g, m.country), m);
    for (const r of await db
      .query('countryGroupGrades')
      .withIndex('by_group_country', (q) => q.eq('groupKey', g))
      .collect())
      p.grades.set(keyOf(g, r.country), r);
  }
  for (const name of loaded.names) {
    const n = await db
      .query('sniNames')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    p.names.set(name, n);
    if (n && !p.families.has(n.familyId)) p.families.set(n.familyId, await db.get(n.familyId));
    for (const m of await db
      .query('sniNameCountry')
      .withIndex('by_name', (q) => q.eq('name', name))
      .collect())
      p.nameMarks.set(keyOf(name, m.country), m);
    for (const e of await db
      .query('sniVantageEvidence')
      .withIndex('by_name_country', (q) => q.eq('name', name))
      .collect())
      p.vantage.set(keyOf(name, e.country), e);
  }
  return p;
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
  // The rule's own switch already folds in `edge.render.enabled`; the automation
  // switch (`edge.enabled`) does not gate delivery, so it does not gate this either.
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
      render: rule.enabled,
      names: sni.enabled,
      nameChecks: vantageOn,
      realHost: vantageOn && vantage.realHost,
    },
    nameCheckCountries: vantageOn ? vantageCountries(vantage, sni.curatedCountries) : [],
    controls: controlCountriesOf(cfg, censored.codes),
  };
}

type Settings = Awaited<ReturnType<typeof settingsOf>>;

/**
 * Member reports from one country: weight per name, and the names its family's
 * reports single out (`suspectNames`, against EVERY name of the family, as the
 * family page judges them). Read for one country at a time (the detail route).
 */
async function reportsFor(
  db: Db,
  pre: Prefetched,
  country: string,
  st: Settings,
  now: number,
): Promise<{ weights: Map<string, number>; suspects: Set<string> }> {
  const weights = new Map<string, number>();
  const suspects = new Set<string>();
  const since = dayOf(now - st.sni.reportWindowDays * DAY);
  const rows = await db
    .query('sniReportCounts')
    .withIndex('by_country_day', (q) => q.eq('country', country).gte('day', since))
    .order('desc')
    .take(REPORT_ROWS);
  if (rows.length === 0) return { weights, suspects };
  // Each shown name's family, with all of its names (a suspect is judged against them all).
  const familyOf = new Map<string, string>();
  for (const familyId of pre.families.keys())
    for (const n of await db
      .query('sniNames')
      .withIndex('by_family_seq', (q) => q.eq('familyId', familyId as Id<'sniFamilies'>))
      .collect())
      familyOf.set(n.name, familyId);
  const byFamily = new Map<string, NameCount[]>();
  for (const row of rows) {
    weights.set(row.name, (weights.get(row.name) ?? 0) + row.weight);
    const fam = familyOf.get(row.name);
    if (!fam) continue;
    let list = byFamily.get(fam);
    if (!list) byFamily.set(fam, (list = []));
    list.push({ name: row.name, country: row.country, weight: row.weight });
  }
  for (const counts of byFamily.values())
    for (const [name, countries] of suspectNames(counts))
      if (countries.includes(country)) suspects.add(name);
  return { weights, suspects };
}

/** One country's per-name facts, from the prefetched rows: the family, the mark, the checks (judged now). */
function nameFactsFor(
  pre: Prefetched,
  names: ReadonlySet<string>,
  country: string,
  st: Settings,
  reports: { weights: Map<string, number>; suspects: Set<string> } | null,
): Map<string, NameFacts> {
  const out = new Map<string, NameFacts>();
  for (const name of names) {
    const n = pre.names.get(name) ?? null;
    const markRow = pre.nameMarks.get(keyOf(name, country));
    const ev = pre.vantage.get(keyOf(name, country));
    const suspect = reports?.suspects.has(name) ?? false;
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
            reportSuspect: suspect,
            minVantages: st.vantage.minVantages,
            minNetworks: st.vantage.minNetworks,
          },
        )
      : null;
    const weight = reports?.weights.get(name);
    out.set(name, {
      family: n ? (pre.families.get(n.familyId)?.slug ?? null) : null,
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
      reports: weight !== undefined ? { weight: Math.round(weight * 100) / 100, suspect } : null,
      realHost: ev?.realHost
        ? {
            at: ev.realHost.at,
            target: ev.realHost.target,
            realAddress: ev.realHost.realAddress ?? null,
            // Judged now from the stored counts: the floors move independently.
            reading: readingOf(ev.realHost.counts, ev.realHost.networks, {
              minVantages: st.vantage.minVantages,
              minNetworks: st.vantage.minNetworks,
            }),
            counts: ev.realHost.counts,
            vantages: ev.realHost.vantages,
            networks: ev.realHost.networks,
          }
        : null,
    });
  }
  return out;
}

/** The per-country inputs of every edge, from the prefetched rows. */
function edgesFor(pre: Prefetched, loaded: Loaded, country: string): Map<string, EdgeInput[]> {
  const out = new Map<string, EdgeInput[]>();
  for (const o of loaded.origins) {
    const list: EdgeInput[] = [];
    for (const { doc, groupKey, base } of o.edges) {
      const ev = pre.edgeEvidence.get(keyOf(doc._id, country));
      const mark = pre.edgeMarks.get(keyOf(doc._id, country));
      const groupMark = pre.groupMarks.get(keyOf(groupKey, country));
      const grade = pre.grades.get(keyOf(groupKey, country));
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
        mark: mark ? { state: mark.state, at: mark.at } : null,
        locationMark: groupMark ? { state: groupMark.state, at: groupMark.at } : null,
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

/** One country's view, in memory. */
function viewOf(
  loaded: Loaded,
  pre: Prefetched,
  st: Settings,
  country: string,
  now: number,
  reports: { weights: Map<string, number>; suspects: Set<string> } | null,
) {
  const facts = nameFactsFor(pre, loaded.names, country, st, reports);
  const edges = edgesFor(pre, loaded, country);
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
    // Names count once across origins, by the state delivery acts on (a mere
    // suggestion of the checks counts as not judged): the list and the page agree.
    for (const ov of r.origins)
      for (const l of ov.listeners)
        for (const n of l.names)
          if (n.status === 'active' && !seen.has(n.name)) {
            seen.add(n.name);
            totals.names[actedState(n)]++;
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
    const pre = await prefetch(ctx.db, loaded);
    const countries = [];
    for (const c of st.censored.list) {
      const { totals, origins } = viewOf(loaded, pre, st, c.code, now, null);
      const handedBlocked = origins.flatMap((o) =>
        o.listeners.filter((l) => l.members.computed).map((l) => l.members.onBlockedAddress),
      );
      countries.push({
        country: c.code,
        listed: listedOf(st, c.code)!,
        totals,
        /** The worst share of members holding an address blocked there, over every transport. */
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
    const pre = await prefetch(ctx.db, loaded);
    const reports = await reportsFor(ctx.db, pre, code, st, now);
    const { origins, totals } = viewOf(loaded, pre, st, code, now, reports);
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
