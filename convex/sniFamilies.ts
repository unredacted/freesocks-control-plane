/**
 * Server-name families (REALITY): the only writer of `sniFamilies`,
 * `sniNames`, `sniInboundBindings` and `sniInboundNameHistory`.
 *
 * A family is a TARGET plus the names that target genuinely serves. A name may
 * be used only once it qualifies against the target (sniQualifyOps.ts). Binding
 * a family to a panel inbound makes it the one authoritative allowlist for that
 * inbound; what reaches members is decided later, per node, by proof.
 *
 * Audit payloads carry slugs and COUNTS only, never a hostname.
 */
import { dayOf, suspectNames, type NameCount } from './lib/edges/sni/health';
import { ConvexError, v } from 'convex/values';
import {
  internalMutation,
  internalQuery,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { isPublicIpLiteral } from './lib/edges/ip';
import { bumpEpochAndRefresh } from './lib/edges/relayGuards';
import { normalizeName } from './lib/edges/registration';
import { hostSniOf, retireFamilyNames } from './relayListeners';
import {
  MAX_NAMES_PER_FAMILY,
  judgeImport,
  sameTarget,
  type Qualification,
} from './lib/edges/sni/family';
import { parseRealityTarget } from './lib/edges/inboundMapping';
import { resolveSniConfig, sniConfigWrites } from './lib/sniConfig';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};
const actor = { actorAdminId: v.optional(v.id('adminUsers')) };
const SLUG = /^[a-z0-9][a-z0-9-]{0,39}$/;

async function audit(
  ctx: MutationCtx,
  action: string,
  actorAdminId: Id<'adminUsers'> | undefined,
  payload: Record<string, unknown>,
) {
  await writeAuditLog(ctx, {
    actorType: 'admin',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'sni_family',
    payload,
  });
}

async function familyBySlug(ctx: { db: QueryCtx['db'] }, slug: string) {
  const f = await ctx.db
    .query('sniFamilies')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  return f ?? refuse('not_found', 'No such family');
}

const namesOf = (ctx: { db: QueryCtx['db'] }, familyId: Id<'sniFamilies'>) =>
  ctx.db
    .query('sniNames')
    .withIndex('by_family_seq', (q) => q.eq('familyId', familyId))
    .collect();

/** A target is a PUBLIC place: a literal must be public, a name is resolved and checked at dial time. */
function checkTarget(address: string, port: number) {
  const a = address.trim().toLowerCase();
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    refuse('validation', 'A port is 1 to 65535');
  const literal = /^[0-9.]+$/.test(a) || a.includes(':');
  if (literal ? !isPublicIpLiteral(a) : !normalizeName(a))
    refuse('edge.sni.bad_target', 'The target must be a public address or hostname');
  return { kind: 'static' as const, address: a, port };
}

// --- config ---------------------------------------------------------------------------------------

export const configView = internalQuery({
  args: {},
  handler: async (ctx) => ({ config: await resolveSniConfig(ctx.db) }),
});

export const patchConfig = internalMutation({
  args: { patch: v.any(), ...actor },
  handler: async (ctx, { patch, actorAdminId }) => {
    const { writes, changedKeys } = sniConfigWrites(
      (patch && typeof patch === 'object' ? patch : {}) as Record<string, unknown>,
    );
    for (const w of writes) await upsertSettingRow(ctx, w.key, w.value, actorAdminId);
    if (changedKeys.length > 0)
      await audit(ctx, 'edge.sni.config.update', actorAdminId, { changedKeys });
    return { changedKeys };
  },
});

// --- families ----------------------------------------------------------------------------------------

function summarize(f: Doc<'sniFamilies'>, names: Doc<'sniNames'>[], bindings: number) {
  const count = (p: (n: Doc<'sniNames'>) => boolean) => names.filter(p).length;
  return {
    id: f._id as string,
    slug: f.slug,
    label: f.label,
    target: f.target,
    enabled: f.enabled,
    requireH2: f.requireH2,
    bindings,
    counts: {
      total: names.length,
      ready: count((n) => n.status === 'active' && n.qualification.state === 'ok'),
      waiting: count((n) => n.status === 'active' && n.qualification.state === 'pending'),
      failing: count((n) => n.status === 'active' && n.qualification.state === 'failed'),
      suspended: count((n) => n.status === 'suspended'),
      retired: count((n) => n.status === 'retired'),
      burned: count((n) => n.status === 'burned'),
    },
  };
}

export const list = internalQuery({
  args: {},
  handler: async (ctx) => {
    const families = await ctx.db.query('sniFamilies').collect();
    const out = [];
    for (const f of families.sort((a, b) => a.slug.localeCompare(b.slug))) {
      const bindings = await ctx.db
        .query('sniInboundBindings')
        .withIndex('by_family', (q) => q.eq('familyId', f._id))
        .collect();
      out.push(summarize(f, await namesOf(ctx, f._id), bindings.length));
    }
    return { families: out };
  },
});

export const detail = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const f = await familyBySlug(ctx, slug);
    const names = await namesOf(ctx, f._id);
    const bindings = await ctx.db
      .query('sniInboundBindings')
      .withIndex('by_family', (q) => q.eq('familyId', f._id))
      .collect();
    const servers = new Map<string, string>();
    for (const b of bindings) {
      const s = await ctx.db.get(b.backendServerId);
      servers.set(b.backendServerId as string, s?.slug ?? '');
    }
    // One read for the whole judgement table (small: names x curated countries).
    const judged = new Map<string, { blockedIn: string[]; provenIn: string[] }>();
    const mine = new Set(names.map((n) => n.name));
    for (const row of await ctx.db.query('sniNameCountry').collect()) {
      if (!mine.has(row.name)) continue;
      const at = judged.get(row.name) ?? { blockedIn: [], provenIn: [] };
      (row.state === 'blocked' ? at.blockedIn : at.provenIn).push(row.country);
      judged.set(row.name, at);
    }
    // The newest rollout of each binding: what the page follows.
    const latest = new Map<string, string>();
    for (const b of bindings) {
      const rollouts = await ctx.db
        .query('sniRollouts')
        .withIndex('by_binding', (q) => q.eq('bindingId', b._id))
        .collect();
      const newest = rollouts.sort((x, y) => y.generation - x.generation)[0];
      if (newest) latest.set(b._id as string, newest._id as string);
    }
    // Where member reports single a name out (a hint; lib/edges/sni/health.ts).
    const sniCfg = await resolveSniConfig(ctx.db);
    const since = dayOf(Date.now() - sniCfg.reportWindowDays * 86_400_000);
    const counts: NameCount[] = [];
    // Rows exist only for names that were reported, so this is bounded by report
    // volume (rate-limited and deduplicated per member), not by the family's
    // size. Still capped, newest days first: a read limit is a 500 (docs).
    for (const row of await ctx.db
      .query('sniReportCounts')
      .withIndex('by_day', (q) => q.gte('day', since))
      .order('desc')
      .take(8000))
      if (mine.has(row.name) && sniCfg.curatedCountries.includes(row.country))
        counts.push({ name: row.name, country: row.country, weight: row.weight });
    const suspects = suspectNames(counts);
    return {
      family: summarize(f, names, bindings.length),
      curatedCountries: sniCfg.curatedCountries,
      names: names.map((n) => ({
        blockedIn: (judged.get(n.name)?.blockedIn ?? []).sort(),
        provenIn: (judged.get(n.name)?.provenIn ?? []).sort(),
        // Not where it is already judged blocked: that hint has been acted on.
        suspectIn: (suspects.get(n.name) ?? []).filter(
          (c) => !(judged.get(n.name)?.blockedIn ?? []).includes(c),
        ),
        name: n.name,
        seq: n.seq,
        status: n.status,
        qualification: n.qualification.state,
        code: n.qualification.code ?? null,
        tlsVersion: n.qualification.tlsVersion ?? null,
        alpn: n.qualification.alpn ?? null,
        checkedAt: n.checkedAt ? new Date(n.checkedAt).toISOString() : null,
      })),
      bindings: bindings.map((b) => ({
        id: b._id as string,
        backendSlug: servers.get(b.backendServerId as string) ?? '',
        profileUuid: b.profileUuid,
        inboundTag: b.inboundTag,
        generation: b.generation,
        panelConfirmedGeneration: b.panelConfirmedGeneration,
        rolloutId: latest.get(b._id as string) ?? null,
      })),
    };
  },
});

export const create = internalMutation({
  args: {
    slug: v.string(),
    label: v.string(),
    targetAddress: v.string(),
    targetPort: v.number(),
    requireH2: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    if (!SLUG.test(a.slug)) refuse('validation', 'A slug is lowercase letters, digits and dashes');
    const exists = await ctx.db
      .query('sniFamilies')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (exists) refuse('conflict', 'A family with that slug exists');
    const target = checkTarget(a.targetAddress, a.targetPort);
    const id = await ctx.db.insert('sniFamilies', {
      slug: a.slug,
      label: a.label.trim().slice(0, 80) || a.slug,
      target,
      enabled: true,
      requireH2: a.requireH2 ?? false,
      nextSeq: 1,
      updatedAt: Date.now(),
    });
    await audit(ctx, 'edge.sni.family.create', a.actorAdminId, {
      slug: a.slug,
      targetKind: 'static',
    });
    return { id: id as string, slug: a.slug };
  },
});

/**
 * Label, the enabled switch and the HTTP/2 requirement. The TARGET is
 * immutable: every name was qualified against it, and an inbound's allowlist is
 * only safe for the target it was built for. A different target is a new family.
 */
export const update = internalMutation({
  args: {
    slug: v.string(),
    label: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
    requireH2: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const f = await familyBySlug(ctx, a.slug);
    const patch: Partial<Doc<'sniFamilies'>> = { updatedAt: Date.now() };
    if (a.label !== undefined) patch.label = a.label.trim().slice(0, 80) || f.slug;
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.requireH2 !== undefined && a.requireH2 !== f.requireH2) {
      patch.requireH2 = a.requireH2;
      // The bar moved: every name is judged again.
      for (const n of await namesOf(ctx, f._id))
        if (n.status === 'active' || n.status === 'suspended')
          await ctx.db.patch(n._id, { checkedAt: 0, updatedAt: Date.now() });
    }
    await ctx.db.patch(f._id, patch);
    await audit(ctx, 'edge.sni.family.update', a.actorAdminId, { slug: f.slug });
    return { ok: true as const };
  },
});

export const remove = internalMutation({
  args: { slug: v.string(), ...actor },
  handler: async (ctx, a) => {
    const f = await familyBySlug(ctx, a.slug);
    const bound = await ctx.db
      .query('sniInboundBindings')
      .withIndex('by_family', (q) => q.eq('familyId', f._id))
      .first();
    if (bound)
      refuse('edge.sni.family_in_use', 'An inbound still uses this family. Unbind it first');
    const names = await namesOf(ctx, f._id);
    // A burned name stays known (it must never be offered again, by any family).
    for (const n of names) if (n.status !== 'burned') await ctx.db.delete(n._id);
    if (names.some((n) => n.status === 'burned'))
      await ctx.db.patch(f._id, { enabled: false, updatedAt: Date.now() });
    else await ctx.db.delete(f._id);
    await audit(ctx, 'edge.sni.family.delete', a.actorAdminId, {
      slug: f.slug,
      nameCount: names.length,
    });
    return { ok: true as const };
  },
});

// --- names ---------------------------------------------------------------------------------------------

export const importNames = internalMutation({
  args: { slug: v.string(), lines: v.array(v.string()), ...actor },
  handler: async (ctx, a) => {
    const f = await familyBySlug(ctx, a.slug);
    const existing = new Map<string, { familyId: string; status: string }>();
    const wanted = new Set(a.lines.map((l) => normalizeName(l)).filter((n): n is string => !!n));
    for (const name of wanted) {
      const row = await ctx.db
        .query('sniNames')
        .withIndex('by_name', (q) => q.eq('name', name))
        .unique();
      if (row) existing.set(name, { familyId: row.familyId as string, status: row.status });
    }
    const verdicts = judgeImport(a.lines, f._id as string, existing);
    const current = (await namesOf(ctx, f._id)).length;
    let seq = f.nextSeq;
    let added = 0;
    for (const l of verdicts) {
      if (l.verdict !== 'added' || !l.name) continue;
      if (current + added >= MAX_NAMES_PER_FAMILY)
        return refuse('edge.sni.cap', `A family holds at most ${MAX_NAMES_PER_FAMILY} names`);
      await ctx.db.insert('sniNames', {
        familyId: f._id,
        name: l.name,
        seq: seq++,
        status: 'active',
        qualification: { state: 'pending', consecutiveFails: 0 },
        checkedAt: 0,
        updatedAt: Date.now(),
      });
      added++;
    }
    await ctx.db.patch(f._id, { nextSeq: seq, updatedAt: Date.now() });
    await audit(ctx, 'edge.sni.names.import', a.actorAdminId, {
      slug: f.slug,
      added,
      rejected: verdicts.length - added,
    });
    return { added, lines: verdicts };
  },
});

/** retire / reactivate / burn / recheck, by name. A burned name never comes back. */
export const setNames = internalMutation({
  args: {
    slug: v.string(),
    names: v.array(v.string()),
    action: v.union(
      v.literal('retire'),
      v.literal('reactivate'),
      v.literal('burn'),
      v.literal('recheck'),
    ),
    ...actor,
  },
  handler: async (ctx, a) => {
    const f = await familyBySlug(ctx, a.slug);
    const wanted = new Set(a.names.map((n) => normalizeName(n)).filter((n): n is string => !!n));
    let count = 0;
    for (const n of await namesOf(ctx, f._id)) {
      if (!wanted.has(n.name) || n.status === 'burned') continue;
      const now = Date.now();
      if (a.action === 'burn') await ctx.db.patch(n._id, { status: 'burned', updatedAt: now });
      else if (a.action === 'retire' && n.status !== 'retired')
        await ctx.db.patch(n._id, { status: 'retired', updatedAt: now });
      else if (a.action === 'reactivate' && n.status !== 'active')
        await ctx.db.patch(n._id, {
          status: 'active',
          qualification: { state: 'pending', consecutiveFails: 0 },
          checkedAt: 0,
          updatedAt: now,
        });
      else if (a.action === 'recheck') await ctx.db.patch(n._id, { checkedAt: 0, updatedAt: now });
      else continue;
      count++;
    }
    // A name out of use here leaves the relays too. A burn may take a relay's
    // last name (a name known blocked is worse than none); a retire may not.
    const left =
      a.action === 'burn' || a.action === 'retire'
        ? await retireFamilyNames(ctx, [...wanted], { keepLast: a.action !== 'burn', by: 'admin' })
        : null;
    await audit(ctx, `edge.sni.names.${a.action}`, a.actorAdminId, {
      slug: f.slug,
      count,
      ...(left ? { listeners: left.listeners, skipped: left.skipped } : {}),
    });
    return { count, relays: left };
  },
});

// --- per-country judgement ----------------------------------------------------------------------------

/** The marks of one name, as they are copied onto a listener's entry for it. */
export async function countryMarks(ctx: { db: QueryCtx['db'] }, name: string) {
  const rows = await ctx.db
    .query('sniNameCountry')
    .withIndex('by_name', (q) => q.eq('name', name))
    .collect();
  const blockedIn = rows
    .filter((r) => r.state === 'blocked')
    .map((r) => r.country)
    .sort();
  const provenIn = rows
    .filter((r) => r.state === 'proven')
    .map((r) => r.country)
    .sort();
  return {
    ...(blockedIn.length ? { blockedIn } : {}),
    ...(provenIn.length ? { provenIn } : {}),
  };
}

/**
 * An operator's judgement: these names work / are blocked / are unjudged in one
 * curated country. A name that is fine elsewhere can be blocked in one place, so
 * "usable" is per country. The marks are copied onto every relay listener that
 * carries the name (a render reads them from there, with no extra reads), and
 * those relays' renders move on at once.
 */
export const setCountry = internalMutation({
  args: {
    slug: v.string(),
    names: v.array(v.string()),
    country: v.string(),
    state: v.union(v.literal('proven'), v.literal('blocked'), v.literal('unknown')),
    ...actor,
  },
  handler: async (ctx, a) => {
    const f = await familyBySlug(ctx, a.slug);
    const country = a.country.trim().toUpperCase();
    const { curatedCountries } = await resolveSniConfig(ctx.db);
    if (!curatedCountries.includes(country))
      refuse('edge.sni.country_not_curated', 'That country is not on the curated list');
    const mine = new Set((await namesOf(ctx, f._id)).map((n) => n.name));
    const wanted = [
      ...new Set(a.names.map((n) => normalizeName(n)).filter((n): n is string => !!n)),
    ].filter((n) => mine.has(n));
    const now = Date.now();
    for (const name of wanted) {
      const row = await ctx.db
        .query('sniNameCountry')
        .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', country))
        .unique();
      if (a.state === 'unknown') {
        if (row) await ctx.db.delete(row._id);
      } else if (row)
        await ctx.db.patch(row._id, { state: a.state, source: 'operator', updatedAt: now });
      else
        await ctx.db.insert('sniNameCountry', {
          name,
          country,
          state: a.state,
          source: 'operator',
          updatedAt: now,
        });
    }
    // Copy the marks onto every listener entry for these names.
    const touched = new Set(wanted);
    const listeners = await ctx.db.query('relayListeners').collect();
    const relays = new Set<Id<'relays'>>();
    // Listeners whose panel Host name (`hostSniOf`) moves with the marks.
    const hostMoved = new Map<Id<'relayListeners'>, Id<'relays'>>();
    for (const l of listeners) {
      if (l.retired || !(l.tlsNames ?? []).some((n) => touched.has(n.name))) continue;
      const next = [];
      for (const n of l.tlsNames ?? []) {
        if (!touched.has(n.name)) {
          next.push(n);
          continue;
        }
        const { blockedIn: _b, provenIn: _p, ...rest } = n;
        next.push({ ...rest, ...(await countryMarks(ctx, n.name)) });
      }
      await ctx.db.patch(l._id, {
        tlsNames: next,
        namesRevision: (l.namesRevision ?? 0) + 1,
        updatedAt: now,
      });
      relays.add(l.relayId);
      if (l.host?.uuid && hostSniOf(l) !== hostSniOf({ tlsNames: next }))
        hostMoved.set(l._id, l.relayId);
    }
    for (const relayId of relays) {
      const relay = await ctx.db.get(relayId);
      if (!relay) continue;
      await bumpEpochAndRefresh(ctx, relay);
      // The Host follows its name (as it does on a retire): a name just judged
      // blocked must not stay on the panel Host, which is what a member who
      // copies the raw config gets.
      if (relay.hostMode !== 'fcp') continue;
      for (const [listenerId, rid] of hostMoved)
        if (rid === relayId)
          await ctx.scheduler.runAfter(0, internal.hostOps.resyncSni, { listenerId });
    }
    await audit(ctx, 'edge.sni.names.country', a.actorAdminId, {
      slug: f.slug,
      country,
      state: a.state,
      count: wanted.length,
    });
    return { count: wanted.length, relays: relays.size };
  },
});

// --- qualification ---------------------------------------------------------------------------------------

/** The oldest-checked names that are due, with their family's target. */
export const dueForQualification = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveSniConfig(ctx.db);
    if (!cfg.enabled) return { names: [] };
    const cutoff = Date.now() - cfg.requalifyHours * 3_600_000;
    const due = await ctx.db
      .query('sniNames')
      .withIndex('by_checked', (q) => q.lt('checkedAt', cutoff))
      .take(cfg.qualifyPerTick * 4);
    const out: {
      id: Id<'sniNames'>;
      name: string;
      address: string;
      port: number;
      requireH2: boolean;
    }[] = [];
    const families = new Map<string, Doc<'sniFamilies'> | null>();
    for (const n of due) {
      if (n.status !== 'active' && n.status !== 'suspended') continue;
      const key = n.familyId as string;
      if (!families.has(key)) families.set(key, await ctx.db.get(n.familyId));
      const f = families.get(key);
      if (!f || !f.enabled) continue;
      out.push({
        id: n._id,
        name: n.name,
        address: f.target.address,
        port: f.target.port,
        requireH2: f.requireH2,
      });
      if (out.length >= cfg.qualifyPerTick) break;
    }
    return { names: out };
  },
});

export const recordQualification = internalMutation({
  args: {
    id: v.id('sniNames'),
    ok: v.boolean(),
    code: v.optional(v.string()),
    tlsVersion: v.optional(v.string()),
    alpn: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const n = await ctx.db.get(a.id);
    if (!n || (n.status !== 'active' && n.status !== 'suspended')) return null;
    const cfg = await resolveSniConfig(ctx.db);
    const fails = a.ok ? 0 : n.qualification.consecutiveFails + 1;
    const q: Qualification & { state: 'ok' | 'failed'; consecutiveFails: number } = {
      ok: a.ok,
      state: a.ok ? 'ok' : 'failed',
      consecutiveFails: fails,
    };
    // A name that stops qualifying is suspended (the target no longer serves
    // it); one that qualifies again comes back by itself.
    const status: Doc<'sniNames'>['status'] = a.ok
      ? 'active'
      : fails >= cfg.suspendAfterFails
        ? 'suspended'
        : n.status;
    // The target stopped serving it: it leaves the relays, but never as a
    // relay's last name (a doubtful name still serves members; none serves nobody).
    if (status === 'suspended' && n.status !== 'suspended')
      await retireFamilyNames(ctx, [n.name], { keepLast: true, by: 'admin' });
    await ctx.db.patch(a.id, {
      status,
      qualification: {
        state: q.state,
        consecutiveFails: fails,
        ...(a.code ? { code: a.code } : {}),
        ...(a.tlsVersion ? { tlsVersion: a.tlsVersion } : {}),
        ...(a.alpn ? { alpn: a.alpn } : {}),
      },
      checkedAt: Date.now(),
      updatedAt: Date.now(),
    });
    return null;
  },
});

// --- binding a family to an inbound ---------------------------------------------------------------------------

export const bind = internalMutation({
  args: { slug: v.string(), backendSlug: v.string(), inboundTag: v.string(), ...actor },
  handler: async (ctx, a) => {
    const cfg = await resolveSniConfig(ctx.db);
    if (!cfg.enabled) refuse('edge.sni.disabled', 'Server-name families are switched off');
    const f = await familyBySlug(ctx, a.slug);
    if (!f.enabled) refuse('edge.sni.disabled', 'This family is switched off');
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', a.backendSlug))
      .unique();
    if (!server) return refuse('not_found', 'Backend server not found');
    const profiles = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
      .collect();
    const hits = profiles.flatMap((p) =>
      p.inbounds.filter((i) => i.tag === a.inboundTag).map((i) => ({ p, i })),
    );
    if (hits.length !== 1)
      return refuse(
        'servers.unknown_inbound',
        'That inbound is not on this panel. Refresh Servers',
      );
    const { p, i } = hits[0];
    if (i.security !== 'reality' || !i.reality)
      return refuse('servers.not_reality', 'Only a REALITY inbound takes a server-name family');
    // An allowlist is only safe for the target it was qualified against.
    if (!sameTarget(parseRealityTarget(i.reality.target), f.target))
      refuse(
        'edge.sni.target_mismatch',
        'The inbound forwards to a different target than this family was checked against',
      );
    const taken = await ctx.db
      .query('sniInboundBindings')
      .withIndex('by_server_inbound', (q) =>
        q.eq('backendServerId', server._id).eq('inboundUuid', i.inboundUuid),
      )
      .unique();
    if (taken) refuse('conflict', 'This inbound already has a family');
    // Everything the inbound lists today has been accepted before: none of it
    // can ever serve as a witness that a NEW generation was applied.
    for (const name of i.reality.serverNames) {
      const norm = normalizeName(name);
      if (!norm) continue;
      const seen = await ctx.db
        .query('sniInboundNameHistory')
        .withIndex('by_inbound_name', (q) =>
          q.eq('backendServerId', server._id).eq('inboundUuid', i.inboundUuid).eq('name', norm),
        )
        .unique();
      if (!seen)
        await ctx.db.insert('sniInboundNameHistory', {
          backendServerId: server._id,
          inboundUuid: i.inboundUuid,
          name: norm,
          firstSeenGeneration: 0,
        });
    }
    const id = await ctx.db.insert('sniInboundBindings', {
      backendServerId: server._id,
      profileUuid: p.profileUuid,
      inboundTag: i.tag,
      inboundUuid: i.inboundUuid,
      familyId: f._id,
      generation: 0,
      panelConfirmedGeneration: 0,
      updatedAt: Date.now(),
    });
    await audit(ctx, 'edge.sni.inbound.bind', a.actorAdminId, {
      slug: f.slug,
      backendSlug: server.slug,
      inboundTag: i.tag,
    });
    return { id: id as string };
  },
});

/** Unbind: the names stay on the panel and on the relays; only the management link goes. */
export const unbind = internalMutation({
  args: { bindingId: v.id('sniInboundBindings'), ...actor },
  handler: async (ctx, a) => {
    const b = await ctx.db.get(a.bindingId);
    if (!b) return refuse('not_found', 'No such binding');
    const f = await ctx.db.get(b.familyId);
    const server = await ctx.db.get(b.backendServerId);
    await ctx.db.delete(b._id);
    await audit(ctx, 'edge.sni.inbound.unbind', a.actorAdminId, {
      slug: f?.slug ?? '',
      backendSlug: server?.slug ?? '',
      inboundTag: b.inboundTag,
    });
    return { ok: true as const };
  },
});
