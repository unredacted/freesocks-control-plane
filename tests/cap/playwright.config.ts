import { defineConfig } from '@playwright/test';
import compatibility from '../compat/playwright.config';

export default defineConfig({
  testDir: '.',
  testMatch: 'captcha.spec.ts',
  timeout: 90_000,
  workers: 1,
  forbidOnly: !!process.env.CI,
  use: {
    baseURL: process.env.FCP_CAP_TEST_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: compatibility.projects,
  outputDir: '../../test-results/cap',
});
