/**
 * Fastly Compute entry point.
 *
 * Status: scaffolded. The platform adapter, KV store impl, libSQL DB client,
 * and Hono app all run on Fastly's StarlingMonkey JS runtime in principle —
 * but a real Fastly deploy has not been part of this repo's CI surface yet.
 * Treat the first deploy on Fastly as a beta and expect to iron out a few
 * package-resolution / global-shim differences. See `docs/fastly-setup.md`.
 *
 * Differences from the Workers entry (`workers.ts`):
 *
 *   - Uses `addEventListener('fetch', e => e.respondWith(...))` rather than
 *     `export default { fetch }`. Fastly's runtime exclusively supports the
 *     listener form today.
 *   - There is no `scheduled` handler — Fastly has no native cron triggers.
 *     The dispatcher at `/api/internal/cron/run-task` is the cron lever for
 *     this target; wire an external scheduler (GitHub Actions, cron-job.org,
 *     a Cloudflare Worker, etc.) to call it on the desired cadence.
 *   - The platform adapter is built per-request (Fastly has no warm
 *     in-memory cache the way Workers does; module-level globals do persist
 *     within an instance but we don't rely on them).
 *   - Static assets: this entry does NOT serve the SPA bundle. Operators
 *     host the SPA on a separate Fastly service (or any static-asset host)
 *     and proxy `/api/*` to this compute service. See the Fastly setup doc.
 *
 * Fastly imports below are typed structurally in `platform/fastly.ts` so
 * `tsc -b` on the Workers/Node toolchain doesn't break. The real runtime
 * imports are pulled in here.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { createApp } from '../src/server/app';
import { buildFastlyAdapter, type FastlyRuntimeBindings } from '../src/server/platform/fastly';

// These imports resolve under the Fastly build toolchain (`js-compute-runtime`).
// They will not resolve under `tsc -b` for the Workers or Node bundles; that's
// expected — `tsconfig.json` excludes `src-entries/fastly.ts` from the default
// build, and the Fastly build runs a separate compile pass.
// @ts-ignore — virtual module provided by Fastly runtime
import { env } from 'fastly:env';
// @ts-ignore — virtual module provided by Fastly runtime
import { KVStore } from 'fastly:kv-store';
// @ts-ignore — virtual module provided by Fastly runtime
import { ConfigStore } from 'fastly:config-store';
// @ts-ignore — virtual module provided by Fastly runtime
import { SecretStore } from 'fastly:secret-store';

addEventListener('fetch', (event: any) => event.respondWith(handleRequest(event)));

async function handleRequest(event: any): Promise<Response> {
  const request = event.request as Request;

  // Build the platform bindings bag. Each store is referenced by the binding
  // name declared in `fastly.toml`. KV bindings are the same names the
  // Workers adapter uses (`FS_SESSIONS_KV` etc.) so the codebase stays
  // platform-agnostic.
  const bindings: FastlyRuntimeBindings = {
    kv: {
      FS_SESSIONS_KV: new KVStore('FS_SESSIONS_KV'),
      FS_CACHE_KV: new KVStore('FS_CACHE_KV'),
      FS_RATELIMIT_KV: new KVStore('FS_RATELIMIT_KV'),
    },
    // Secret Store is optional — operators can run with env-only and skip
    // it if they're comfortable. Wrap in try/catch because requesting a
    // non-existent store throws on some SDK versions.
    secretStore: tryBind(() => new SecretStore('fs_secrets')),
    configStore: tryBind(() => new ConfigStore('fs_config')),
    env: { get: (k: string) => env(k) },
  };

  // Read the libSQL connection details up-front. These must come from the
  // Secret Store (auth token) and Config Store (URL — non-secret); we pull
  // both via the same env-fallback chain the rest of the adapter uses.
  const turso = await readTurso(bindings);
  const platform = await buildFastlyAdapter({ bindings, turso });

  // Build the Hono app once per request. Fastly's StarlingMonkey runtime
  // tolerates this — the cost is in microseconds and Hono is a pure
  // value-construction graph with no side effects.
  const app = createApp(platform);
  return app.fetch(request);
}

function tryBind<T>(ctor: () => T): T | undefined {
  try {
    return ctor();
  } catch {
    return undefined;
  }
}

async function readTurso(
  bindings: FastlyRuntimeBindings,
): Promise<{ url: string; authToken?: string }> {
  // URL is non-secret — Config Store is the natural home, env is the
  // fallback. Auth token IS secret — Secret Store first, env fallback only
  // if the operator is willing.
  const url =
    bindings.configStore?.get('TURSO_DATABASE_URL') ?? bindings.env.get('TURSO_DATABASE_URL');
  if (!url) throw new Error('TURSO_DATABASE_URL is not set');
  let authToken: string | undefined;
  if (bindings.secretStore) {
    const secret = await bindings.secretStore.get('TURSO_AUTH_TOKEN');
    if (secret) authToken = secret.plaintext();
  }
  if (!authToken) {
    const fromEnv = bindings.env.get('TURSO_AUTH_TOKEN');
    if (fromEnv) authToken = fromEnv;
  }
  return { url, authToken };
}
