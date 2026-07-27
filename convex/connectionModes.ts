/**
 * Registered-function wrappers over lib/connectionModes so actions can
 * `runQuery` them. All internal — the public catalog ships via publicConfig.get
 * (id/label/description/deliveryStyle/isDefault/available), never a squad UUID.
 * Placement resolution (which node a key is homed to) is Remnawave-specific and
 * lives in convex/remnawaveNodes.ts, not here.
 */
import { internalQuery } from './_generated/server';
import {
  resolveConnectionModeFamilies,
  resolveConnectionModes,
  resolveDefaultModeId,
} from './lib/connectionModes';
import { resolveBoundModeIds } from './lib/remnawavePlacement';

/** Admin/status view + the switch-mode validity check: id/family/label/
 *  deliveryStyle/isDefault plus `enabled` (admin toggle, family AND sub-mode) and
 *  `bound` (a placement pool is bound) — NEVER a UUID. Deprecated legacy aliases
 *  are excluded: they exist only so pre-migration rows validate, and surfacing
 *  them would put dead ids in the admin UI. */
export const list = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [modes, bound] = await Promise.all([
      resolveConnectionModes(ctx.db),
      resolveBoundModeIds(ctx.db),
    ]);
    return modes
      .filter((m) => !m.deprecated)
      .map((m) => ({
        id: m.id,
        family: m.family ?? null,
        label: m.label,
        deliveryStyle: m.deliveryStyle,
        isDefault: m.isDefault,
        isFamilyDefault: m.isFamilyDefault,
        enabled: m.enabled,
        bound: bound.has(m.id),
      }));
  },
});

/** The family catalog for the admin editor (label/description/enabled). */
export const families = internalQuery({
  args: {},
  handler: (ctx) => resolveConnectionModeFamilies(ctx.db),
});

/** The resolved default mode id (for AccountView when a member hasn't chosen). */
export const defaultId = internalQuery({
  args: {},
  handler: (ctx) => resolveDefaultModeId(ctx.db),
});
