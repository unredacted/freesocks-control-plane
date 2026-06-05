import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/server/db/schema.ts',
  out: './src/server/db/migrations',
  dialect: 'sqlite',
  driver: 'd1-http',
  verbose: true,
  strict: true,
});
