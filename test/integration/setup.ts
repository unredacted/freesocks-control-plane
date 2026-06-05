import { applyD1Migrations, env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

declare module 'cloudflare:test' {
  interface ProvidedEnv extends Env {
    __D1_MIGRATIONS: D1Migration[];
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.__D1_MIGRATIONS);
});
