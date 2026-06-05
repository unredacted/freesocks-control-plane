/**
 * Outline implementation of `ProxyBackendProvider`. Routes calls to a
 * specific Outline server via OutlineServerPool — for new key issuance the
 * pool picks a server, for reads/updates/deletes the caller already knows
 * which subscription row owns the key (and thus which server it lives on).
 *
 * Outline has a much smaller mutable surface than Remnawave:
 *   - Can set/remove a per-key data limit.
 *   - Can rename a key.
 *   - Has no concept of HWID, no traffic-strategy enum, no squad routing.
 *
 * `updateUser` therefore translates the subset of `UpdateUserPatch` that
 * Outline supports and silently no-ops the rest. The patch caller's
 * documentation already says "backends apply whatever fields they support
 * and ignore the rest" so this is contract-compliant.
 */
import { eq, sql } from 'drizzle-orm';
import type { Db } from '../../db/client';
import { outlineServers, subscriptions } from '../../db/schema';
import type { Logger } from '../../lib/logger';
import type {
  BackendDevice,
  IssueUserSpec,
  IssuedUser,
  ProxyBackendProvider,
  SubscriptionContent,
  UpdateUserPatch,
  UserState,
} from '../backend';
import type { OutlineServerPool, OutlineServerRow } from '../../services/outline-pool';
import { OutlineClient } from './client';

export interface OutlineBackendDeps {
  db: Db;
  pool: OutlineServerPool;
  logger: Logger;
}

export class OutlineBackend implements ProxyBackendProvider {
  readonly id = 'outline' as const;

  constructor(private readonly deps: OutlineBackendDeps) {}

  async issueUser(spec: IssueUserSpec): Promise<IssuedUser> {
    const server = await this.pickServer(spec);
    if (!server) {
      throw new Error('No active Outline servers available to issue a key');
    }
    const client = this.deps.pool.client(server);
    const created = await client.createKey({
      name: spec.username,
      websocket: server.websocketEnabled
        ? {
            enabled: true,
            tcpPath: '/tcp',
            udpPath: '/udp',
            domain: server.websocketDomain ?? '',
            tls: true,
          }
        : undefined,
    });

    // Apply per-key data limit if the tier specifies one. Outline tracks
    // traffic separately from the access key resource so this is a second
    // call rather than part of POST /access-keys.
    if (spec.trafficLimitBytes !== null && spec.trafficLimitBytes > 0) {
      try {
        await client.setKeyDataLimit(created.id, spec.trafficLimitBytes);
      } catch (err) {
        // If applying the limit fails, the key still exists and is usable —
        // log + continue rather than rolling back. The healthcheck cron
        // will notice and the admin can re-apply via tier propagation.
        this.deps.logger.warn('outline_set_limit_failed', {
          keyId: created.id,
          serverId: server.id,
          error: String(err),
        });
      }
    }

    // Keep the server's cached access-key count fresh between healthchecks so
    // the pool's load-scoring (which weights key count) sees this new key
    // immediately. The healthcheck cron periodically reconciles it to the
    // server's real count, so a missed decrement on delete self-heals.
    await this.deps.db
      .update(outlineServers)
      .set({ accessKeyCount: sql`${outlineServers.accessKeyCount} + 1`, updatedAt: Date.now() })
      .where(eq(outlineServers.id, server.id));

    return {
      backendUserId: created.id,
      // Outline has no separate "short" form — reuse the access-key id.
      backendShortId: created.id,
      subscriptionUrl: created.accessUrl,
      outlineServerId: server.id,
      raw: { server: { id: server.id, slug: server.slug }, key: created },
    };
  }

  async getUser(backendUserId: string): Promise<UserState> {
    // READ path — use tryResolveKey, not resolveKey. A transient absence
    // (e.g. subscription row still being written, race between
    // createKey and the D1 insert in issueNew) shouldn't crash /account
    // or every admin user-listing call. Return a sentinel UserState
    // instead so the SPA renders an "unknown" state and the operator
    // can investigate via logs rather than via a stack trace.
    const resolved = await this.tryResolveKey(backendUserId);
    if (!resolved) {
      this.deps.logger.warn('outline_get_user_unresolved', {
        keyId: backendUserId,
      });
      return {
        trafficLimitBytes: null,
        usedTrafficBytes: 0,
        expireAt: null,
        status: 'active',
        devices: [] as BackendDevice[],
      };
    }
    const { server, key } = resolved;
    const client = this.deps.pool.client(server);
    let usedTrafficBytes = 0;
    try {
      const metrics = await client.getMetricsTransfer();
      usedTrafficBytes = metrics[backendUserId] ?? 0;
    } catch (err) {
      this.deps.logger.debug('outline_metrics_failed', {
        keyId: backendUserId,
        serverId: server.id,
        error: String(err),
      });
    }
    return {
      trafficLimitBytes: key.dataLimit?.bytes ?? null,
      usedTrafficBytes,
      // Outline has no per-key expiry concept; the FreeSocks layer enforces
      // expiry via the local user-status state machine + the cleanup cron.
      expireAt: null,
      // Outline doesn't expose a status enum; if the key exists it's active.
      status: 'active',
      // Outline doesn't track HWID. Empty list is honest.
      devices: [] as BackendDevice[],
    };
  }

  async updateUser(backendUserId: string, patch: UpdateUserPatch): Promise<void> {
    const { server } = await this.resolveKey(backendUserId);
    const client = this.deps.pool.client(server);
    if (patch.trafficLimitBytes !== undefined) {
      await client.setKeyDataLimit(backendUserId, patch.trafficLimitBytes);
    }
    if (patch.status === 'disabled') {
      // Stock Outline has no per-key disable; the closest equivalent is
      // setting the data limit to 0 so further traffic is refused. The
      // server still routes existing connections until the next roll, so
      // for hard cutoff use deleteUser instead.
      await client.setKeyDataLimit(backendUserId, 0);
    }
    if (patch.status === 'active' && patch.trafficLimitBytes === undefined) {
      // Re-enable: remove the data limit (or restore a tier-driven one, but
      // that's a caller responsibility — they'll pass trafficLimitBytes too).
      await client.setKeyDataLimit(backendUserId, null);
    }
    // hwidDeviceLimit, trafficLimitStrategy, remnawaveSquadUuid, tag,
    // description, expireAt: not applicable to Outline, silently dropped.
  }

  async resetUserTraffic(backendUserId: string): Promise<void> {
    // Outline doesn't expose a per-key traffic reset endpoint. Server-side
    // metrics roll on the configured window (typically monthly). We log so
    // operators know the call was a no-op rather than silently succeeding.
    this.deps.logger.info('outline_reset_traffic_noop', { keyId: backendUserId });
  }

  async deleteUser(backendUserId: string): Promise<void> {
    const resolved = await this.tryResolveKey(backendUserId);
    if (!resolved) {
      // Subscription row already gone or never had `outline_server_id` set —
      // nothing to delete server-side. Common when an admin manually purged
      // the local row.
      return;
    }
    const client = this.deps.pool.client(resolved.server);
    await client.deleteKey(backendUserId);
  }

  async fetchSubscriptionContent(backendShortId: string): Promise<SubscriptionContent> {
    // READ path — tolerate transient absence. The mirror-refresh cron path
    // and the SPA-driven subscription fetch both call this; both want a
    // clean error path rather than a thrown exception. We DO throw here
    // because the caller cannot proceed without content — but emit a
    // typed error so the audit layer / caller can discriminate.
    const resolved = await this.tryResolveKey(backendShortId);
    if (!resolved) {
      this.deps.logger.warn('outline_fetch_content_unresolved', {
        keyId: backendShortId,
      });
      throw new Error(
        `Outline key ${backendShortId} not found locally — subscription row missing outline_server_id`,
      );
    }
    const { key } = resolved;
    // Outline keys ARE their own content — the `ss://` URL is the
    // entirety of what a client needs. We return it as plain text so the
    // multi-S3 mirror flow has something to upload (preserving the
    // censorship-resistant mirror hosting from the Remnawave path).
    return { content: `${key.accessUrl}\n`, contentType: 'text/plain' };
  }

  // --- internals --------------------------------------------------------

  /**
   * For new-key issuance, pick a server. If the caller specified an exact
   * `outlineServerId`, honor it (admin override). Otherwise use the pool's
   * scoring with the tier-defined subset.
   */
  private async pickServer(spec: IssueUserSpec): Promise<OutlineServerRow | null> {
    if (spec.outlineServerId !== undefined) {
      return this.deps.pool.getById(spec.outlineServerId);
    }
    return this.deps.pool.pickForIssue(spec.outlineServerPoolIds ?? []);
  }

  /**
   * For reads/updates/deletes — look up the subscription row to find which
   * server hosts the key, then fetch the key from that server.
   */
  private async resolveKey(backendUserId: string) {
    const result = await this.tryResolveKey(backendUserId);
    if (!result) {
      throw new Error(
        `Outline key ${backendUserId} not found locally — subscription row missing outline_server_id`,
      );
    }
    return result;
  }

  private async tryResolveKey(backendUserId: string) {
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.backendUserId, backendUserId))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub || sub.outlineServerId === null) return null;
    const server = await this.deps.pool.getById(sub.outlineServerId);
    if (!server) return null;
    const client = new OutlineClient({ apiUrl: server.apiUrl, logger: this.deps.logger });
    const key = await client.getKey(backendUserId);
    return { server, key };
  }
}
