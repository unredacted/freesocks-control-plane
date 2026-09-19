import { defineConfig } from 'vitest/config';

/**
 * Node-side integration tests: a live Remnawave panel WITH a panel-managed
 * node, a TLS 1.3 target and a pinned Xray client
 * (docker-compose.remnawave-node-test.yml). Slow (the node restarts Xray), so
 * they have their own command and never run with the fast suite:
 * `bun run test:integration:remnawave-node`.
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['convex/**/*.node-integration.test.ts'],
    exclude: ['**/node_modules/**', '**/.claude/**', '**/dist/**'],
    testTimeout: 300_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
