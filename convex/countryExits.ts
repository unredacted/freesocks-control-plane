/**
 * Exit location by country (lib/countryExits.ts holds the rules; docs/edges.md
 * "Exit location by country", docs/privacy.md "Where a member connects from"):
 * the setting's read, the codes a new key narrows to, the account page's
 * one-time suggestion, the country view's line and the rollback helper.
 * Nothing here stores a country: the member's choice stays on their key.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { backendIdValidator } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { resolveModeCatalog } from './lib/connectionModes';
import {
  COUNTRY_EXITS_KEY,
  exitLocationsFor,
  parseCountryExits,
  type CountryExit,
} from './lib/countryExits';
import { resolveLocations } from './lib/locations';
import { liveChoice, type MemberFamily } from './lib/memberCountry';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './lib/placement';
import { resolveMemberCountryConfig } from './memberCountry';
import { currentOrActiveSub } from './subscriptions';

export async function resolveCountryExits(db: DatabaseReader): Promise<CountryExit[]> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', COUNTRY_EXITS_KEY))
    .unique();
  if (!row) return [];
  try {
    return parseCountryExits(JSON.parse(row.value));
  } catch {
    return [];
  }
}

/** The family of the mode a new key issues into (its own, else the effective default): fail closed. */
async function familyOfMode(
  db: DatabaseReader,
  backend: Doc<'subscriptions'>['backend'],
  modeId: string | null,
): Promise<MemberFamily> {
  const slug = modeId ?? effectiveDefaultFor(await resolveCatalogWithAvailability(db), backend);
  if (!slug) return 'none';
  const family = (await resolveModeCatalog(db)).modes.find((m) => m.id === slug)?.family;
  return family === 'freedom' ? 'freedom' : family === 'privacy' ? 'privacy' : 'none';
}

/** What the rules read for one member and the mode their new key issues into. */
async function exitsOf(
  db: DatabaseReader,
  user: Doc<'users'>,
  backend: Doc<'subscriptions'>['backend'],
  modeId: string | null,
): Promise<{ codes: string[]; choice: string | null; sub: Doc<'subscriptions'> | null }> {
  const sub = await currentOrActiveSub(db, user);
  if (!capabilitiesOf(backend).placement) return { codes: [], choice: null, sub };
  const exits = await resolveCountryExits(db);
  if (exits.length === 0) return { codes: [], choice: null, sub };
  const listed = (await resolveCensoredCountries(db)).codes;
  const choice = sub ? liveChoice(sub, listed) : null;
  const codes = exitLocationsFor({
    exits,
    steer: (await resolveMemberCountryConfig(db)).steer,
    preferredLocation: user.preferredLocation ?? null,
    choice,
    family: await familyOfMode(db, backend, modeId),
  });
  return { codes, choice, sub };
}

/**
 * The location codes a NEW key of this member narrows to, in order ([] =
 * today's choice). Read from the key being replaced, so the first key at
 * sign-up (no choice yet) is placed as before.
 */
export const forIssue = internalQuery({
  args: {
    userId: v.id('users'),
    backend: backendIdValidator,
    modeId: v.union(v.string(), v.null()),
  },
  handler: async (ctx, { userId, backend, modeId }): Promise<string[]> => {
    const user = await ctx.db.get(userId);
    if (!user) return [];
    return (await exitsOf(ctx.db, user, backend, modeId)).codes;
  },
});

export interface MemberExit {
  /** The member's own country choice (shown back to them only). */
  country: string;
  /** The location a one-time move would land in (the first exit there is now). */
  code: string;
  label: string;
}

/**
 * The account page's one-time suggestion, or null: a member on Automatic
 * whose country choice has an exit location, while their key is somewhere
 * else. The first exit location that is in the catalog and online is offered.
 */
export async function memberExitOf(
  db: DatabaseReader,
  user: Doc<'users'>,
  backend: Doc<'subscriptions'>['backend'],
): Promise<MemberExit | null> {
  const { codes, choice, sub } = await exitsOf(db, user, backend, user.connectionModeId ?? null);
  if (codes.length === 0 || !choice || !sub) return null;
  const server = sub.backendServerId ? await db.get(sub.backendServerId) : null;
  if (server?.location && codes.includes(server.location)) return null;
  const catalog = await resolveLocations(db);
  for (const code of codes) {
    const at = catalog.find((l) => l.code === code);
    if (at?.online) return { country: choice, code, label: at.label };
  }
  return null;
}

export const memberExit = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<MemberExit | null> => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    const tier = await ctx.db.get(user.tierId);
    if (!tier) return null;
    return memberExitOf(ctx.db, user, tier.backend);
  },
});

/** The country view's line: where new keys on Automatic of members who chose this country go. */
export async function countryExitLabels(
  db: DatabaseReader,
  country: string,
): Promise<Array<{ code: string; label: string }>> {
  const entry = (await resolveCountryExits(db)).find((e) => e.country === country);
  if (!entry) return [];
  const catalog = await resolveLocations(db);
  return entry.locations.map((code) => ({
    code,
    label: catalog.find((l) => l.code === code)?.label ?? code,
  }));
}

/**
 * Rollback (docs/edges.md "Exit location by country"): run before deploying a
 * build older than this one. Deletes the setting; keys already issued stay
 * where they are, and new keys on Automatic go least-loaded again.
 */
export const clearForRollback = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ cleared: boolean }> => {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', COUNTRY_EXITS_KEY))
      .unique();
    if (!row) return { cleared: false };
    await ctx.db.delete(row._id);
    return { cleared: true };
  },
});
