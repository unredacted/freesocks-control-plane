/// <reference types="bun-types" />
import { createApp } from '../src/server/app';
import { buildNodeAdapter, flushPendingTasks } from '../src/server/platform/node';
import { runCronTask } from '../src/server/jobs/dispatcher';

const sqlitePath = process.env.SQLITE_PATH ?? './data/freesocks.sqlite';
const port = parseInt(process.env.PORT ?? '3000', 10);

const platform = buildNodeAdapter({ sqlitePath, env: process.env });
const app = createApp(platform);

const server = Bun.serve({
  port,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return app.fetch(request);
    }
    // SPA static asset serving
    const filePath = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\//, '');
    const file = Bun.file(`./dist/client/${filePath}`);
    if (await file.exists()) {
      return new Response(file);
    }
    // SPA fallback
    return new Response(Bun.file('./dist/client/index.html'));
  },
});
platform.logger.info('bun_server_started', { port: server.port });

// Bun-native cron (simple intervals) with an in-process overlap guard so a
// long-running task can't double-fire if it exceeds its interval.
type CronTaskName = Parameters<typeof runCronTask>[0];
const runningTasks = new Set<CronTaskName>();
const runGuarded = async (task: CronTaskName) => {
  if (runningTasks.has(task)) {
    platform.logger.warn('cron_skip_overlap', { task });
    return;
  }
  runningTasks.add(task);
  try {
    await runCronTask(task, platform);
  } finally {
    runningTasks.delete(task);
  }
};
setInterval(() => runGuarded('propagate-tier-changes'), 5 * 60_000);
setInterval(() => runGuarded('grace-sweep'), 10 * 60_000);
setInterval(() => runGuarded('cleanup-expired-free'), 24 * 3600_000);

const shutdown = async () => {
  platform.logger.info('bun_server_shutting_down');
  await flushPendingTasks();
  server.stop();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
