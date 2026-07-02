import { defineConfig } from 'vitest/config';

/**
 * Integration tests that drive FCP's provider code against a REAL backend
 * (a live Remnawave panel from docker-compose.remnawave-test.yml). Kept out of
 * the default fast/offline suite (vitest.config.ts excludes `*.integration.test.ts`).
 * Run via `bun run test:integration:remnawave`, which stands up the panel,
 * bootstraps a token into the env, runs these, and tears the panel down.
 *
 * node environment: these make real network calls (undici fetch), not the
 * edge-runtime polyfill the convex-test suites use.
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.integration.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Real panel state is shared across the lifecycle assertions — run serially.
    fileParallelism: false,
  },
});
