import path from 'node:path';
import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: [
      // Mirror vite.config.ts so modules using the '@' alias (the i18n shim's
      // paraglide import) stay unit-testable.
      { find: '@', replacement: path.resolve(__dirname, './src') },
      { find: '@client', replacement: path.resolve(__dirname, './src/client') },
      { find: '@shared', replacement: path.resolve(__dirname, './src/shared') },
      // Every convex-test instance is tracked, so the runner below can end the
      // scheduled work each test leaves behind (only the bare specifier: the
      // tracked module imports the real one by its path).
      {
        find: /^convex-test$/,
        replacement: path.resolve(__dirname, './convex/lib/edges/testing/convexTest.tracked.ts'),
      },
    ],
  },
  test: {
    environment: 'edge-runtime',
    server: { deps: { inline: ['convex-test'] } },
    // A test's scheduled functions end with the test, before its afterEach hooks
    // run, and one further out than Node can arm a timer never fires mid-suite.
    runner: path.resolve(__dirname, './convex/lib/edges/testing/scheduledWork.runner.ts'),
    // convex-test suites default to edge-runtime (the global env above). Shared
    // crypto tests opt into the node env per-file via a `@vitest-environment node`
    // docblock, since that code runs in the browser + the "use node" action.
    include: ['convex/**/*.test.ts', 'src/**/*.test.ts'],
    // `*.integration.test.ts` hit a REAL backend (a live Remnawave panel) and
    // run under their own node-env config (vitest.integration.config.ts) via
    // `bun run test:integration:remnawave` — never in the fast, offline suite.
    exclude: [
      ...configDefaults.exclude,
      '**/*.integration.test.ts',
      '**/*.node-integration.test.ts',
    ],
  },
});
