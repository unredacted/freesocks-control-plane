/**
 * Registered-function wrappers over lib/connectionProfiles so actions (which run
 * outside the DB) can `runQuery` them. All internal — the public catalog ships
 * via publicConfig.get (id/label/isDefault/available), never the squad UUID.
 */
import { internalQuery } from './_generated/server';
import { v } from 'convex/values';
import {
  resolveConnectionProfiles,
  resolveProfileSquad,
  DEFAULT_CONNECTION_PROFILE,
} from './lib/connectionProfiles';

/** The squad a profile issues into (issuance path). null when unknown/unbound —
 *  the caller then falls back to the tier's own squad. */
export const resolveSquad = internalQuery({
  args: { profileId: v.union(v.literal('evade'), v.literal('privacy'), v.null()) },
  handler: (ctx, { profileId }) => resolveProfileSquad(ctx.db, profileId),
});

/** Admin/status view + the switchProfile validity check: id/label/isDefault plus
 *  a `squadBound` boolean — NEVER the squad UUID. */
export const list = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await resolveConnectionProfiles(ctx.db)).map((p) => ({
      id: p.id,
      label: p.label,
      isDefault: p.isDefault,
      squadBound: p.squadUuid !== null,
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
