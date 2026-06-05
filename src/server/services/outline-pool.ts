/**
 * Picks an Outline server for new key issuance, and resolves a server row
 * (with TLS-validated client) when reading or updating an existing key.
 *
 * Scoring mirrors the original codebase:
 *
 *     score = WEIGHT_LATENCY * latency_ms + WEIGHT_KEY_COUNT * access_key_count
 *
 * Lower score wins. `latency_ms` is approximated from the cached
 * `last_health_ok_at` round-trip time captured by the `outline-healthcheck`
 * cron (a future enhancement — for v1 the column is just a freshness signal
 * and we treat all reachable servers as latency-equivalent). `access_key_count`
 * is the per-server count cached on the row.
 *
 * Tie-break: among the top-3 scored servers, pick uniformly at random. This
 * avoids thundering-herd onto the single lowest-loaded server during a viral
 * traffic spike.
 */
import { and, eq, inArray } from 'drizzle-orm';
import type { Db } from '../db/client';
import { outlineServers } from '../db/schema';
import type { Logger } from '../lib/logger';
import { OutlineClient } from '../providers/outline/client';
import type { AppSettingsService } from './app-settings';

export type OutlineServerRow = typeof outlineServers.$inferSelect;

export interface OutlineServerPoolDeps {
  db: Db;
  logger: Logger;
  /**
   * Optional. When present, `pickForIssue` reads the scoring weights from
   * `app_settings` so admins can rebalance latency-vs-key-count without a
   * redeploy. When absent (e.g. in unit tests), falls back to the compiled
   * defaults below.
   */
  appSettings?: AppSettingsService;
}

const DEFAULT_LATENCY_WEIGHT = 1;
const DEFAULT_KEY_COUNT_WEIGHT = 100;

export class OutlineServerPool {
  constructor(private readonly deps: OutlineServerPoolDeps) {}

  /**
   * Pick a server for a new key. Optional `pool` filters to a tier-specified
   * subset (admin can scope an Outline tier to issue from a chosen subset of
   * servers); empty `pool` means "any active server".
   */
  async pickForIssue(pool: number[] = []): Promise<OutlineServerRow | null> {
    const conditions = [eq(outlineServers.isActive, true)];
    if (pool.length > 0) conditions.push(inArray(outlineServers.id, pool));
    const candidates = await this.deps.db
      .select()
      .from(outlineServers)
      .where(and(...conditions))
      .all();
    if (candidates.length === 0) return null;

    // Filter to servers that have been reachable recently (within ~30 min).
    // If none qualify, fall back to the full candidate list — a stale server
    // is better than no server, and the next issue attempt will surface the
    // health failure cleanly.
    const now = Date.now();
    const fresh = candidates.filter(
      (s) => s.lastHealthOkAt !== null && now - s.lastHealthOkAt < 30 * 60_000,
    );
    const usable = fresh.length > 0 ? fresh : candidates;

    const weights = await this.resolveWeights();
    const scored = usable
      .map((s) => ({ s, score: scoreServer(s, weights) }))
      // Lower score wins; the admin-set `priority` (ascending) breaks ties so
      // it's an effective knob rather than dead metadata.
      .sort((a, b) => a.score - b.score || a.s.priority - b.s.priority);
    // Randomize within the top 3 to spread load. Use the CSPRNG (not
    // Math.random) to avoid a predictable selection pattern — cheap here.
    const top = scored.slice(0, Math.min(3, scored.length));
    const pick = new Uint32Array(1);
    crypto.getRandomValues(pick);
    const winner = top[pick[0]! % top.length]!;
    return winner.s;
  }

  /**
   * Resolve the scoring weights from `app_settings`, with defaults baked in.
   * AppSettingsService is KV-cached so this is cheap per call; if no service
   * was injected (e.g. in tests), use the compiled defaults.
   */
  private async resolveWeights(): Promise<{ latency: number; keyCount: number }> {
    if (!this.deps.appSettings) {
      return { latency: DEFAULT_LATENCY_WEIGHT, keyCount: DEFAULT_KEY_COUNT_WEIGHT };
    }
    try {
      const all = await this.deps.appSettings.getAll();
      return {
        latency: all['outline.scoring.latency_weight'] ?? DEFAULT_LATENCY_WEIGHT,
        keyCount: all['outline.scoring.key_count_weight'] ?? DEFAULT_KEY_COUNT_WEIGHT,
      };
    } catch (err) {
      // A read failure shouldn't block issuance — fall back to defaults and
      // log so it surfaces in monitoring.
      this.deps.logger.warn('outline_pool_weights_fallback', { error: String(err) });
      return { latency: DEFAULT_LATENCY_WEIGHT, keyCount: DEFAULT_KEY_COUNT_WEIGHT };
    }
  }

  /** Look up a single server by id. */
  async getById(id: number): Promise<OutlineServerRow | null> {
    const row = await this.deps.db
      .select()
      .from(outlineServers)
      .where(eq(outlineServers.id, id))
      .limit(1)
      .all();
    return row[0] ?? null;
  }

  /** Construct a client for an already-loaded server row. */
  client(server: OutlineServerRow): OutlineClient {
    return new OutlineClient({
      apiUrl: server.apiUrl,
      logger: this.deps.logger,
    });
  }
}

/**
 * Lower score = better. With no real latency data yet, we lean heavily on
 * access-key count to balance load. Weights are admin-tunable via the
 * `outline.scoring.latency_weight` and `outline.scoring.key_count_weight`
 * app settings (defaults 1 and 100, matching the original codebase). When
 * the Outline healthcheck cron starts capturing real RTT, drop the
 * key-count weight and let real numbers do the work.
 */
function scoreServer(s: OutlineServerRow, weights: { latency: number; keyCount: number }): number {
  const latencyMs = 0; // placeholder until healthcheck captures real RTT
  return weights.latency * latencyMs + weights.keyCount * s.accessKeyCount;
}
