import { describe, expect, it, beforeEach } from 'vitest';
import { RateLimitService } from '../../../src/server/services/rate-limit';
import type { KvStore } from '../../../src/server/kv/interface';

class InMemoryKv implements KvStore {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string) {
    const r = this.store.get(key);
    if (!r) return null;
    if (r.expiresAt && r.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return r.value;
  }
  async getJson<T>(key: string) {
    const v = await this.get(key);
    return v ? (JSON.parse(v) as T) : null;
  }
  async put(key: string, value: string, opts?: { expirationTtl?: number }) {
    const expiresAt = opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
  }
  async putJson(key: string, value: unknown, opts?: { expirationTtl?: number }) {
    await this.put(key, JSON.stringify(value), opts);
  }
  async delete(key: string) {
    this.store.delete(key);
  }
  async list() {
    return { keys: [], list_complete: true };
  }
}

describe('RateLimitService', () => {
  let kv: InMemoryKv;
  let svc: RateLimitService;

  beforeEach(() => {
    kv = new InMemoryKv();
    svc = new RateLimitService(kv, 'test-salt');
  });

  it('hashIp produces deterministic output for same IP', async () => {
    const a = await svc.hashIp('1.2.3.4');
    const b = await svc.hashIp('1.2.3.4');
    expect(a).toBe(b);
    expect(a).toHaveLength(64);
  });

  it('hashIp differs across IPs', async () => {
    const a = await svc.hashIp('1.2.3.4');
    const b = await svc.hashIp('5.6.7.8');
    expect(a).not.toBe(b);
  });

  it('checkAndIncrement allows up to max then blocks', async () => {
    const r1 = await svc.checkAndIncrement('k', 2, 60);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(1);
    const r2 = await svc.checkAndIncrement('k', 2, 60);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(0);
    const r3 = await svc.checkAndIncrement('k', 2, 60);
    expect(r3.allowed).toBe(false);
  });

  it('dayBucket changes across day boundaries', () => {
    const a = svc.dayBucket(new Date('2026-04-29T23:59:59Z').getTime());
    const b = svc.dayBucket(new Date('2026-04-30T00:00:01Z').getTime());
    expect(a).not.toBe(b);
  });
});
