import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'edge-runtime',
    server: { deps: { inline: ['convex-test'] } },
    // convex-test suites default to edge-runtime (the global env above). Shared
    // crypto tests opt into the node env per-file via a `@vitest-environment node`
    // docblock, since that code runs in the browser + the "use node" action.
    include: ['convex/**/*.test.ts', 'src/**/*.test.ts'],
    // `*.integration.test.ts` hit a REAL backend (a live Remnawave panel) and
    // run under their own node-env config (vitest.integration.config.ts) via
    // `bun run test:integration:remnawave` — never in the fast, offline suite.
    exclude: [...configDefaults.exclude, '**/*.integration.test.ts'],
  },
});
