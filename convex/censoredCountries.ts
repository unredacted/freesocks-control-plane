/**
 * The censored-country list (lib/censoredCountries.ts): the admin read and
 * write, the seed that copies the old keys into it once, and the connection
 * mode suggestion that reads it with the status page's availability matrix.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { ConvexError, v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { backendIdValidator } from './lib/backendIds';
import {
  CENSORED_COUNTRIES_KEY,
  MAX_CENSORED_COUNTRIES,
  censoredCountriesDiff,
  resolveCensoredCountries,
  validateCensoredCountries,
} from './lib/censoredCountries';
import { suggestModeFor } from './lib/modeSuggestion';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './lib/placement';
import { resolveDefaultModeId } from './lib/connectionModes';
import { resolveStatusConfig } from './lib/statusPage';

/** The admin view: the list, whether it is stored yet, and the cap. */
export const view = internalQuery({
  args: {},
  handler: async (ctx) => {
    const c = await resolveCensoredCountries(ctx.db);
    return { countries: c.list, stored: c.source === 'stored', max: MAX_CENSORED_COUNTRIES };
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
    const after = await resolveCensoredCountries(ctx.db);
    return { countries: after.list, stored: true, max: MAX_CENSORED_COUNTRIES };
  },
});

/**
 * The connection mode to highlight for a member of `backend` whose request the
 * CDN places in `country` (lib/modeSuggestion.ts). Only the verdict leaves.
 */
export const suggestMode = internalQuery({
  args: { backend: backendIdValidator, country: v.union(v.string(), v.null()) },
  handler: async (ctx, { backend, country }): Promise<string> => {
    const [listed, catalog, status] = await Promise.all([
      resolveCensoredCountries(ctx.db),
      resolveCatalogWithAvailability(ctx.db),
      resolveStatusConfig(ctx.db),
    ]);
    const defaultId = effectiveDefaultFor(catalog, backend) ?? (await resolveDefaultModeId(ctx.db));
    const code = country ? country.trim().toUpperCase() : null;
    return suggestModeFor({
      country: code,
      listed: listed.codes,
      cells: status.censorshipRows.find((r) => r.countryCode === code)?.cells ?? null,
      modes: catalog.modes.map((m) => ({
        id: m.id,
        isCensorshipRecommended: m.isCensorshipRecommended,
        available: m.availableBackends.includes(backend),
      })),
      defaultId,
    });
  },
});
