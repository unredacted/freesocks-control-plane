import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import path from 'node:path';

const d1Migrations = await readD1Migrations(path.resolve(__dirname, 'src/server/db/migrations'));

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/unit/**/*.test.ts'],
          environment: 'node',
        },
        resolve: {
          alias: {
            '@server': path.resolve(__dirname, './src/server'),
            '@shared': path.resolve(__dirname, './src/shared'),
          },
        },
      },
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: './wrangler.dev.toml' },
            miniflare: {
              d1Databases: ['DB'],
              kvNamespaces: ['FS_SESSIONS_KV', 'FS_CACHE_KV', 'FS_RATELIMIT_KV'],
              bindings: {
                __D1_MIGRATIONS: d1Migrations,
                // Enable the CiviCRM webhook with a known secret so the webhook
                // integration test can exercise the HMAC + dedupe path. Only
                // that test POSTs to /api/webhooks/civicrm, so this is inert
                // elsewhere.
                WEBHOOKS_CIVICRM_ENABLED: 'true',
                WEBHOOK_CIVICRM_HMAC_SECRET: 'test-webhook-secret',
              },
            },
          }),
        ],
        test: {
          name: 'integration',
          include: ['test/integration/**/*.test.ts'],
          setupFiles: ['./test/integration/setup.ts'],
        },
      },
    ],
  },
});
