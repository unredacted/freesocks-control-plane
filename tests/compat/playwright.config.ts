import { resolve } from 'node:path';
import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './browser',
  testMatch: '**/*.spec.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // Absolute: Playwright resolves a relative reporter outputFile against this
  // config's directory, not the repo root that scripts/compat/report.ts reads.
  reporter: [['list'], ['junit', { outputFile: resolve('test-results/compat/browser.xml') }]],
  use: {
    baseURL: 'http://127.0.0.1:4178',
    locale: 'en-US',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  outputDir: resolve('test-results/compat/browser'),
  webServer: {
    cwd: resolve('.'),
    command: 'bun run i18n:compile && bunx vite --config tests/compat/browser/vite.config.ts',
    url: 'http://127.0.0.1:4178',
    reuseExistingServer: false,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
  ],
});
