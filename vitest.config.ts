import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'edge-runtime',
    server: { deps: { inline: ['convex-test'] } },
    // convex-test suites default to edge-runtime (the global env above). Shared
    // crypto tests opt into the node env per-file via a `@vitest-environment node`
    // docblock, since that code runs in the browser + the "use node" action.
    include: ['convex/**/*.test.ts', 'src/**/*.test.ts'],
  },
});
