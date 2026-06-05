import type { KvStore } from '../kv/interface';
import { hmacSha256Hex } from '../lib/crypto';

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/**
 * KV-backed soft rate limiter.
 *
 * KV is *eventually* consistent and not transactional, so this can never be a
 * strict counter. Two concurrent calls can both observe count=N and write
 * count=N+1, allowing a small burst over `max`. That is acceptable for the
 * free-tier use case because:
 *
 *   1. The durable record of grants is in D1 (`free_grants`). The free-tier
 *      service does an authoritative check there inside its issuance flow
 *      (see `FreeTierService.tryReissue`) before issuing a second key from
 *      the same IP, regardless of what KV says.
 *   2. KV's purpose is the FAST path — reject the obvious abuse without
 *      hitting D1. Slow-path correctness is provided by D1.
 *
 * Concrete failure mode of the previous read-then-put implementation: a
 * burst of concurrent requests could each see count=0 and bypass the cap
 * entirely. The mitigation here is to (a) write FIRST (best-effort), (b)
 * still return the pre-write value so a clear over-cap is rejected, and
 * (c) rely on the D1 backstop in `free-tier.ts` for the durable check.
 */
export class RateLimitService {
  constructor(
    private readonly kv: KvStore,
    private readonly ipHashSalt: string,
  ) {}

  async hashIp(ip: string): Promise<string> {
    return hmacSha256Hex(this.ipHashSalt, ip);
  }

  dayBucket(now = Date.now()): number {
    return Math.floor(now / 86_400_000);
  }

  hourBucket(now = Date.now()): number {
    return Math.floor(now / 3_600_000);
  }

  /**
   * Best-effort soft cap. Returns `allowed=false` if the existing counter
   * already exceeds `max`. Always increments. Use D1 for the authoritative
   * check on critical paths.
   */
  async checkAndIncrement(key: string, max: number, windowSec: number): Promise<RateLimitDecision> {
    const current = parseInt((await this.kv.get(key)) ?? '0', 10);
    // Increment unconditionally; concurrent callers may both observe `current`
    // and overshoot by their concurrency factor — D1 backstops this.
    await this.kv.put(key, String(current + 1), {
      expirationTtl: windowSec,
    });
    if (current >= max) {
      return { allowed: false, remaining: 0, retryAfterSeconds: windowSec };
    }
    return { allowed: true, remaining: Math.max(0, max - current - 1), retryAfterSeconds: 0 };
  }
}
