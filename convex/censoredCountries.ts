/**
 * The censored-country list (lib/censoredCountries.ts): the admin read and
 * write, the seed that copies the old keys into it once, and the connection
 * mode suggestion that reads it with the status page's availability matrix.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { backendIdValidator, type BackendId } from './lib/backendIds';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import {
  CENSORED_COUNTRIES_KEY,
  LEGACY_COUNTRY_KEYS,
  MAX_CENSORED_COUNTRIES,
  censoredCountriesDiff,
  normalizeCode,
  resolveCensoredCountries,
  validateCensoredCountries,
} from './lib/censoredCountries';
import { suggestModeFor } from './lib/modeSuggestion';
import {
  COUNTRY_MODES_KEY,
  parseCountryModes,
  preferredModesFor,
  type CountryModes,
} from './lib/countryModes';
import { ELSEWHERE } from './lib/memberCountry';
import { resolveCountryExits } from './countryExits';
import { resolveMemberCountryConfig } from './memberCountry';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './lib/placement';
import { resolveDefaultModeId, resolveModeCatalog } from './lib/connectionModes';
import { resolveStatusConfig } from './lib/statusPage';

// --- the keys the list replaced ---------------------------------------------------------------------

/**
 * The four keys the list replaced (lib/censoredCountries.ts
 * `LEGACY_COUNTRY_KEYS`, all but `status.censorship`, which is the status
 * page's matrix itself). Deleted once the list is stored: until then they are
 * still the live source.
 */
export const RETIRED_COUNTRY_KEYS = [
  LEGACY_COUNTRY_KEYS.curated,
  LEGACY_COUNTRY_KEYS.probe,
  LEGACY_COUNTRY_KEYS.vantage,
  LEGACY_COUNTRY_KEYS.privacy,
] as const;

/** Where the retired keys' values are kept, for a rollback (`restoreLegacyKeys`). */
export const LEGACY_COUNTRY_BACKUP_KEY = 'censorship:legacyKeys';

async function readLegacyBackup(
  db: DatabaseReader,
): Promise<{ row: { _id: Id<'appState'> } | null; values: Record<string, string> }> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', LEGACY_COUNTRY_BACKUP_KEY))
    .unique();
  let values: Record<string, string> = {};
  try {
    const parsed = row ? (JSON.parse(row.value) as unknown) : {};
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
      values = Object.fromEntries(
        Object.entries(parsed as Record<string, unknown>).filter(
          (e): e is [string, string] => typeof e[1] === 'string',
        ),
      );
  } catch {
    values = {};
  }
  return { row, values };
}

async function legacyRows(db: DatabaseReader) {
  const rows = [];
  for (const key of RETIRED_COUNTRY_KEYS) {
    const row = await db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) rows.push(row);
  }
  return rows;
}

/**
 * Old keys present now whose value differs from the one kept when they were
 * retired: written again afterwards (an older build ran after a restore). The
 * list does not reflect such a change, so it is shown on the card, never
 * deleted unseen.
 */
export async function changedLegacyKeys(db: DatabaseReader): Promise<string[]> {
  const { values } = await readLegacyBackup(db);
  return (await legacyRows(db))
    .filter((r) => values[r.key] !== undefined && values[r.key] !== r.value)
    .map((r) => r.key);
}

/**
 * Delete the old keys (the list must be stored). Their values go to the
 * backup first; an earlier backup of a key is never overwritten, unless
 * `supersede` (the admin just saved the list, so the newest values are the
 * ones a rollback should get). Without `supersede` a key changed since its
 * backup is KEPT (`kept`): deleting it would lose a change the list does not
 * have. Audited by key name.
 */
export async function retireLegacyKeys(
  ctx: MutationCtx,
  opts: { supersede: boolean },
): Promise<{ retired: string[]; kept: string[] }> {
  const rows = await legacyRows(ctx.db);
  if (rows.length === 0) return { retired: [], kept: [] };
  const now = Date.now();
  const backup = await readLegacyBackup(ctx.db);
  const values = { ...backup.values };
  const retired: string[] = [];
  const kept: string[] = [];
  for (const row of rows) {
    const before = values[row.key];
    if (!opts.supersede && before !== undefined && before !== row.value) {
      kept.push(row.key);
      continue;
    }
    values[row.key] = opts.supersede || before === undefined ? row.value : before;
    await ctx.db.delete(row._id);
    retired.push(row.key);
  }
  if (retired.length > 0) {
    if (backup.row)
      await ctx.db.patch(backup.row._id, { value: JSON.stringify(values), updatedAt: now });
    else
      await ctx.db.insert('appState', {
        key: LEGACY_COUNTRY_BACKUP_KEY,
        value: JSON.stringify(values),
        updatedAt: now,
      });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'censorship.legacy_keys.retire',
      targetType: 'app_setting',
      targetId: CENSORED_COUNTRIES_KEY,
      payload: { keys: retired.join(','), count: retired.length },
    });
  }
  if (kept.length > 0) {
    console.warn(
      `[censored countries] kept ${kept.join(', ')}: changed since they were retired; review the list under Settings, Censored countries, and save`,
    );
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'censorship.legacy_keys.changed',
      targetType: 'app_setting',
      targetId: CENSORED_COUNTRIES_KEY,
      payload: { keys: kept.join(','), count: kept.length },
    });
  }
  return { retired, kept };
}

/** Put back the backed-up keys that are missing now (never over one written since). */
export async function restoreLegacyKeys(ctx: MutationCtx): Promise<{ restored: string[] }> {
  const { values } = await readLegacyBackup(ctx.db);
  const present = new Set((await legacyRows(ctx.db)).map((r) => r.key));
  const restored: string[] = [];
  for (const key of RETIRED_COUNTRY_KEYS) {
    const value = values[key];
    if (value === undefined || present.has(key)) continue;
    await upsertSettingRow(ctx, key, value);
    restored.push(key);
  }
  if (restored.length > 0)
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'censorship.legacy_keys.restore',
      targetType: 'app_setting',
      targetId: CENSORED_COUNTRIES_KEY,
      payload: { keys: restored.join(','), count: restored.length },
    });
  return { restored };
}

/**
 * The admin view: the list, whether it is stored yet, the cap, and any old
 * key changed after it was retired (an older build ran; the list does not
 * have that change).
 */
export const view = internalQuery({
  args: {},
  handler: async (ctx) => {
    const c = await resolveCensoredCountries(ctx.db);
    return {
      countries: c.list,
      stored: c.source === 'stored',
      max: MAX_CENSORED_COUNTRIES,
      legacyChanged: c.source === 'stored' ? await changedLegacyKeys(ctx.db) : [],
    };
  },
});

/** Replace the whole list (the admin card always submits all of it). */
export const set = internalMutation({
  args: { countries: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { countries, actorAdminId }) => {
    const checked = validateCensoredCountries(countries);
    if (!checked.ok) throw new ConvexError({ code: 'validation', message: checked.message });
    const before = await resolveCensoredCountries(ctx.db);
    await upsertSettingRow(ctx, CENSORED_COUNTRIES_KEY, JSON.stringify(checked.list), actorAdminId);
    const diff = censoredCountriesDiff(before.list, checked.list);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'censorship.countries.update',
      targetType: 'app_setting',
      targetId: CENSORED_COUNTRIES_KEY,
      payload: {
        added: diff.added.join(','),
        removed: diff.removed.join(','),
        flagsChanged: diff.flagsChanged.join(','),
        count: checked.list.length,
      },
    });
    // A country that left the list takes every member's choice and guess of it
    // with it (convex/memberCountry.ts).
    for (const country of diff.removed)
      await ctx.scheduler.runAfter(0, internal.memberCountry.sweepCountry, { country });
    // The saved list supersedes the keys it replaced, a change made to them
    // under an older build included: they go, their newest values kept.
    await retireLegacyKeys(ctx, { supersede: true });
    const after = await resolveCensoredCountries(ctx.db);
    return {
      countries: after.list,
      stored: true,
      max: MAX_CENSORED_COUNTRIES,
      legacyChanged: [] as string[],
    };
  },
});

/** Everything the mode suggestion reads, once per request. */
async function suggestionInputs(db: DatabaseReader, backend: BackendId) {
  const [listed, catalog, status, countryModes] = await Promise.all([
    resolveCensoredCountries(db),
    resolveCatalogWithAvailability(db),
    resolveStatusConfig(db),
    resolveCountryModes(db),
  ]);
  const defaultId = effectiveDefaultFor(catalog, backend) ?? (await resolveDefaultModeId(db));
  const modes = catalog.modes.map((m) => ({
    id: m.id,
    isCensorshipRecommended: m.isCensorshipRecommended,
    available: m.availableBackends.includes(backend),
  }));
  return { listed: listed.codes, status, countryModes, defaultId, modes };
}

function suggestIn(inputs: Awaited<ReturnType<typeof suggestionInputs>>, code: string | null) {
  return suggestModeFor({
    country: code,
    listed: inputs.listed,
    cells: inputs.status.censorshipRows.find((r) => r.countryCode === code)?.cells ?? null,
    modes: inputs.modes,
    defaultId: inputs.defaultId,
    preferred: preferredModesFor(inputs.countryModes, code),
  });
}

/** The stored `delivery.country.modes` setting, fail-safe (lib/countryModes.ts). */
export async function resolveCountryModes(db: DatabaseReader): Promise<CountryModes[]> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', COUNTRY_MODES_KEY))
    .unique();
  if (!row) return [];
  try {
    return parseCountryModes(JSON.parse(row.value));
  } catch {
    return [];
  }
}

/**
 * The connection mode to highlight for a member of `backend` whose request the
 * CDN places in `country` (lib/modeSuggestion.ts). Only the verdict leaves.
 */
export const suggestMode = internalQuery({
  args: { backend: backendIdValidator, country: v.union(v.string(), v.null()) },
  handler: async (ctx, { backend, country }): Promise<string> => {
    const code = country ? country.trim().toUpperCase() : null;
    return suggestIn(await suggestionInputs(ctx.db, backend), code);
  },
});

/**
 * Sign-up, before the first key: for each country the question offers, the
 * mode to suggest and the locations Automatic tries first (the exit locations
 * of that country while ordering by country is on, else none). Read only by
 * the sealed region view, so a member's pick re-runs the suggestion on the
 * page without sending the country anywhere.
 */
export const suggestionsForCountries = internalQuery({
  args: { userId: v.id('users'), countries: v.array(v.string()) },
  handler: async (
    ctx,
    { userId, countries },
  ): Promise<Record<string, { modeId: string; locations: string[] }>> => {
    const user = await ctx.db.get(userId);
    const tier = user ? await ctx.db.get(user.tierId) : null;
    if (!tier) return {};
    const inputs = await suggestionInputs(ctx.db, tier.backend);
    const [exits, steer, modeCatalog] = await Promise.all([
      resolveCountryExits(ctx.db),
      resolveMemberCountryConfig(ctx.db).then((c) => c.steer),
      resolveModeCatalog(ctx.db),
    ]);
    // Exit locations only place freedom-family keys (lib/countryExits.ts), so
    // a suggestion into another family recommends none.
    const isFreedom = (id: string) =>
      modeCatalog.modes.find((m) => m.id === id)?.family === 'freedom';
    const out: Record<string, { modeId: string; locations: string[] }> = {};
    for (const raw of countries.slice(0, MAX_CENSORED_COUNTRIES + 1)) {
      const up = raw.trim().toUpperCase();
      const code = up === ELSEWHERE ? ELSEWHERE : normalizeCode(up);
      if (!code) continue;
      const modeId = suggestIn(inputs, code === ELSEWHERE ? null : code);
      out[code] = {
        modeId,
        locations:
          steer && isFreedom(modeId)
            ? (exits.find((e) => e.country === code)?.locations ?? [])
            : [],
      };
    }
    return out;
  },
});

/**
 * Whether the CDN places this request in a country on the list: the account
 * view's flag behind the onboarding mirror suggestion. Only the verdict leaves;
 * the list stays server-side, and neither the country nor the verdict is stored.
 */
export const isListed = internalQuery({
  args: { country: v.union(v.string(), v.null()) },
  handler: async (ctx, { country }): Promise<boolean> => {
    const code = normalizeCode(country);
    if (!code) return false;
    return (await resolveCensoredCountries(ctx.db)).codes.includes(code);
  },
});
