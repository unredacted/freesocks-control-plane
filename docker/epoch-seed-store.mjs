import { Buffer } from 'node:buffer';
import { timingSafeEqual } from 'node:crypto';
import { env } from 'node:process';

const MAX_SEEDS = 128;
const MAX_LIFETIME_MS = 45 * 60_000;

export function createSeedStore(token, now = Date.now) {
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    throw new Error('HPKE_EPOCH_STORE_TOKEN must be a 32-byte hex secret');
  }
  const authorization = Buffer.from('Bearer ' + token);
  const seeds = new Map();

  function prune() {
    const current = now();
    for (const [kid, entry] of seeds) {
      if (entry.expiresAt <= current) seeds.delete(kid);
    }
  }

  async function fetch(req) {
    const path = new URL(req.url).pathname;
    if (req.method === 'GET' && path === '/healthz') return new Response(null, { status: 204 });
    const presented = Buffer.from(req.headers.get('authorization') ?? '');
    if (presented.length !== authorization.length || !timingSafeEqual(presented, authorization)) {
      return new Response(null, { status: 401 });
    }
    const kid = /^\/v1\/seeds\/([a-f0-9]{16})$/.exec(path)?.[1];
    if (!kid) return new Response(null, { status: 404 });
    prune();
    const existing = seeds.get(kid);
    if (req.method === 'HEAD') return new Response(null, { status: existing ? 204 : 404 });
    if (req.method === 'GET') {
      return existing
        ? Response.json({ seed: existing.seed }, { headers: { 'cache-control': 'no-store' } })
        : new Response(null, { status: 404 });
    }
    if (req.method !== 'PUT') return new Response(null, { status: 405 });
    const body = await req.json().catch(() => null);
    const current = now();
    if (
      !body ||
      typeof body.seed !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.seed) ||
      !Number.isSafeInteger(body.expiresAt) ||
      body.expiresAt <= current ||
      body.expiresAt > current + MAX_LIFETIME_MS
    ) {
      return new Response(null, { status: 400 });
    }
    // Re-read after parsing to account for another request accepted meanwhile.
    prune();
    const previous = seeds.get(kid);
    if (previous) {
      return new Response(null, {
        status: previous.seed === body.seed && previous.expiresAt === body.expiresAt ? 204 : 409,
      });
    }
    if (seeds.size >= MAX_SEEDS) return new Response(null, { status: 503 });
    seeds.set(kid, { seed: body.seed, expiresAt: body.expiresAt });
    return new Response(null, { status: 204 });
  }

  return { fetch, prune };
}

if (import.meta.main) {
  const store = createSeedStore(env.HPKE_EPOCH_STORE_TOKEN ?? '');
  setInterval(store.prune, 10_000).unref();
  globalThis.Bun.serve({
    hostname: '0.0.0.0',
    port: 8080,
    maxRequestBodySize: 1024,
    fetch: store.fetch,
  });
}
