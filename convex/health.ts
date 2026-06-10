/**
 * A3: a DEEP readiness probe, distinct from /healthz (process-liveness only).
 * `dbPing` does a real datastore round-trip, so /readyz turns red when Postgres
 * is wedged / the connection pool is exhausted — the signal an external uptime
 * monitor should alert on. Cheap (an indexed take(1)); safe to poll.
 */
import { internalQuery } from './_generated/server';

export const dbPing = internalQuery({
  args: {},
  handler: async (ctx): Promise<{ ok: true }> => {
    // Any real read exercises the datastore connection. appSettings is tiny.
    await ctx.db.query('appSettings').take(1);
    return { ok: true };
  },
});
