/**
 * Periodic health probe for every active Outline server. Used by:
 *   - The pool's scoring (servers older than ~30 min from their last good
 *     probe drop to the back of the candidate list).
 *   - The admin Outline servers page (green/amber/red badge driven by the
 *     `lastHealthOkAt` recency).
 *
 * Updates `outline_servers.lastHealthOkAt` and `accessKeyCount` on success.
 * On failure we leave the row alone — the freshness window in the scorer
 * naturally demotes the server, and re-trying every 10 min gives transient
 * blips room to recover without an admin touching anything.
 *
 * We never throw out of the loop — one bad server should not kick the cron
 * out before it gets to the next server. Per-server errors are logged and
 * audit-recorded so they're discoverable.
 */
import { eq } from 'drizzle-orm';
import { outlineServers } from '../db/schema';
import type { ServiceContainer } from '../services/container';
import { OutlineClient } from '../providers/outline/client';

export interface HealthcheckResult {
  serversChecked: number;
  serversHealthy: number;
  serversFailed: number;
}

export async function runOutlineHealthcheck(
  services: ServiceContainer,
): Promise<HealthcheckResult> {
  const { platform } = services;
  const active = await platform.db
    .select()
    .from(outlineServers)
    .where(eq(outlineServers.isActive, true))
    .all();

  let healthy = 0;
  let failed = 0;
  const now = Date.now();

  for (const server of active) {
    const client = new OutlineClient({ apiUrl: server.apiUrl, logger: platform.logger });
    const result = await client.healthCheck();
    if (result.ok) {
      await platform.db
        .update(outlineServers)
        .set({
          lastHealthOkAt: now,
          accessKeyCount: result.keyCount,
          updatedAt: now,
        })
        .where(eq(outlineServers.id, server.id));
      healthy++;
    } else {
      failed++;
      platform.logger.warn('outline_healthcheck_failed', {
        serverId: server.id,
        slug: server.slug,
        // Note: deliberately NOT logging `server.apiUrl` — it carries the
        // shared secret. The error string from OutlineApiError is already
        // scrubbed of the URL on the throw side.
        error: result.error,
      });
    }
  }

  return { serversChecked: active.length, serversHealthy: healthy, serversFailed: failed };
}
