/**
 * Registered-function wrappers over lib/connectionProfiles so actions (which run
 * outside the DB) can `runQuery` them. All internal — the public catalog ships
 * via publicConfig.get (id/label/isDefault/available), never the squad UUID.
 */
import { internalQuery } from './_generated/server';
import { v } from 'convex/values';
import {
  resolveConnectionProfiles,
  resolveProfilePool,
  pickSquadFromPool,
  DEFAULT_CONNECTION_PROFILE,
} from './lib/connectionProfiles';

/** The squad a NEW key issues into: the LEAST-LOADED squad of the profile's
 *  pool (panel-authoritative member counts, cached by the healthcheck cron;
 *  single-squad pools short-circuit). null when unknown/unbound — the caller
 *  then falls back to the tier's own squad. Callers persist the pick on the
 *  subscription row so later tier pushes re-send the SAME squad. */
export const resolveSquad = internalQuery({
  args: { profileId: v.union(v.literal('evade'), v.literal('privacy'), v.null()) },
  handler: async (ctx, { profileId }) =>
    pickSquadFromPool(ctx.db, await resolveProfilePool(ctx.db, profileId)),
});

/** Admin/status view + the switchProfile validity check: id/label/isDefault plus
 *  a `squadBound` boolean — NEVER the squad UUIDs. */
export const list = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await resolveConnectionProfiles(ctx.db)).map((p) => ({
      id: p.id,
      label: p.label,
      isDefault: p.isDefault,
      squadBound: p.squadUuids.length > 0,
    })),
});

/** The resolved default profile id (for AccountView when a member hasn't chosen). */
export const defaultId = internalQuery({
  args: {},
  handler: async (ctx) => {
    const profiles = await resolveConnectionProfiles(ctx.db);
    return profiles.find((p) => p.isDefault)?.id ?? DEFAULT_CONNECTION_PROFILE;
  },
});
