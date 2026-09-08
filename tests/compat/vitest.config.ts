import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/compat/**/*.integration.test.ts'],
    server: { deps: { inline: ['convex-test'] } },
    fileParallelism: false,
    testTimeout: 90_000,
    hookTimeout: 120_000,
    reporters: ['default', ['junit', { outputFile: 'test-results/compat/integration.xml' }]],
  },
});
