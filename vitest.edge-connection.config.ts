import { defineConfig } from 'vitest/config';
import { BaseSequencer, type TestSpecification } from 'vitest/node';

/**
 * The wiring test runs first: it proves the stack with hand-written configs
 * and leaves the panel empty again, and the member test then sets the backend
 * up from scratch on the same panel and nodes.
 */
class WiringFirst extends BaseSequencer {
  async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    const rank = (f: TestSpecification) =>
      f.moduleId.endsWith('wiring.integration.test.ts') ? 0 : 1;
    return [...files].sort((a, b) => rank(a) - rank(b));
  }
}

/**
 * The edge connection release gate (scripts/edge-connection-integration.sh):
 * FCP in convex-test against a real panel, real relay nodes, fake edges and a
 * real sing-box client. Runs only inside the runner container of
 * docker-compose.edge-connection-test.yml (`bun run test:integration:edge-connection`);
 * never part of the fast suite.
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/edge-connection/**/*.integration.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    server: { deps: { inline: ['convex-test'] } },
    fileParallelism: false,
    sequence: { sequencer: WiringFirst },
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
