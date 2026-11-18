import { defineConfig } from '@playwright/test';
import compatibility from '../compat/playwright.config';

export default defineConfig({
  testDir: '.',
  testMatch: 'import-map.spec.ts',
  use: { baseURL: 'http://127.0.0.1:18341' },
  projects: compatibility.projects,
});
