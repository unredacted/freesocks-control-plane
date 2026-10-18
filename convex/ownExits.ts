/**
 * FCP's own exit addresses (lib/ownExits.ts), kept as one `appState` row so the
 * fronted subscription route reads them in one indexed lookup. Rebuilt hourly
 * (cron `own-exits-refresh`), at every deploy and when the operator edits the
 * extra ranges. Infrastructure addresses only: a node's public and management
 * addresses, origin addresses, panel and inventory node addresses, edge
 * addresses, and `delivery.country.ownExitRanges`. Never a member's address.
 */
import { internalMutation } from './_generated/server';
import { buildOwnExits } from './lib/ownExits';
import { MEMBER_COUNTRY_KEYS, memberCountryConfig } from './lib/memberCountry';
import { recordHeartbeat } from './cronHeartbeat';

export const OWN_EXITS_STATE_KEY = 'delivery:ownExits';

export const refresh = internalMutation({
  args: {},
  handler: async (ctx) => {
    await recordHeartbeat(ctx, 'own-exits-refresh');
    const addresses: unknown[] = [];
    for (const i of await ctx.db.query('panelNodeIntents').collect()) {
      const o = i.observed;
      if (o) addresses.push(o.publicIps.v4, o.publicIps.v6, o.management.address);
    }
    for (const n of await ctx.db.query('panelNodes').collect()) addresses.push(n.address);
    for (const n of await ctx.db.query('backendNodeInventory').collect()) addresses.push(n.address);
    for (const r of await ctx.db.query('relays').collect()) addresses.push(r.originAddress);
    for (const e of await ctx.db.query('edges').collect())
      addresses.push(e.addresses.v4, e.addresses.v6);
    const rangesRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', MEMBER_COUNTRY_KEYS.ownExitRanges))
      .unique();
    let ranges: unknown;
    try {
      ranges = rangesRow ? JSON.parse(rangesRow.value) : [];
    } catch {
      ranges = [];
    }
    const exits = buildOwnExits(
      addresses,
      memberCountryConfig({ [MEMBER_COUNTRY_KEYS.ownExitRanges]: ranges }).ownExitRanges,
    );
    const value = JSON.stringify(exits);
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', OWN_EXITS_STATE_KEY))
      .unique();
    if (row) {
      if (row.value !== value) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
    } else
      await ctx.db.insert('appState', { key: OWN_EXITS_STATE_KEY, value, updatedAt: Date.now() });
    return {
      v4: exits.v4.length,
      v6Prefixes: exits.v6Prefixes.length,
      cidrs: exits.cidrs.length,
    };
  },
});
