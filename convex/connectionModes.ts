/**
 * Registered-function wrappers over lib/connectionModes so actions can
 * `runQuery` them. All internal — the public catalog ships via publicConfig.get
 * (id/label/description/deliveryStyle/isDefault/available), never a squad UUID.
 * Placement resolution (which node a key is homed to) is Remnawave-specific and
 * lives in convex/remnawaveNodes.ts, not here.
 */
import { internalQuery } from './_generated/server';
import { resolveConnectionModes, resolveDefaultModeId } from './lib/connectionModes';
import { resolveBoundModeIds } from './lib/remnawavePlacement';

/** Admin/status view + the switch-mode validity check: id/label/deliveryStyle/
 *  isDefault plus a `bound` boolean (a placement pool is bound) — NEVER a UUID. */
export const list = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [modes, bound] = await Promise.all([
      resolveConnectionModes(ctx.db),
      resolveBoundModeIds(ctx.db),
    ]);
    return modes.map((m) => ({
      id: m.id,
      label: m.label,
      deliveryStyle: m.deliveryStyle,
      isDefault: m.isDefault,
      bound: bound.has(m.id),
    }));
  },
});

/** The resolved default mode id (for AccountView when a member hasn't chosen). */
export const defaultId = internalQuery({
  args: {},
  handler: (ctx) => resolveDefaultModeId(ctx.db),
});
